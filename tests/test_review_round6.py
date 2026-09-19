"""P3a-2 adversarial review, round 6: reproductions of the findings that were fixed.

Each test names its finding (R6-nn). Real temp SQLite where the state matters.
"""
from __future__ import annotations

import sqlite3
import time

import pytest

import app.core.db as dbmod
import app.core.ultra_engine as ue
from tests.test_review_round5 import _link_worker, _removed_in_a_failed_pass
from tests.test_standalone_finger_removal_state import fstate  # noqa: F401  (fixture)
from tests.test_standalone_incremental_sync import _user, _worker
from tests.test_standalone_revoked_pin_removal import RevokeDriver
from tests.test_zk_standalone_driver import FakeZkem, _make_driver


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "r6.db"), raising=False)
    dbmod.init_db()
    yield dbmod
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


# ---------------------------------------------------------------------------- R6-01
class _LastPumpZkem(FakeZkem):
    """A healthy terminal whose scan arrives in the STA thread's LAST pump: once armed,
    ReadRTLog waits (bounded) until the driver is being stopped, then hands one punch
    over -- the pump the thread still runs after disconnect() set its stop event."""

    def __init__(self):
        super().__init__()
        self.stop_evt = None
        self.fired = False

    def ReadRTLog(self, machine):
        if self.stop_evt is not None and not self.fired:
            self.stop_evt.wait(5.0)
            if self.stop_evt.is_set():
                self.pending_punches.append(("117", 0, 0, 1, 2026, 9, 19, 11, 0, 0, 0))
                self.fired = True
        return super().ReadRTLog(machine)


def test_r6_01_a_scan_from_the_sta_threads_last_pump_is_decided(db, monkeypatch):
    drv, zk = _make_driver(fake=_LastPumpZkem())
    assert drv.connect() is True
    zk.stop_evt = drv._stop_evt
    try:
        w = _link_worker(monkeypatch, drv)
        w._connected = True
        w._connected_since_mono = time.monotonic() - 5000.0     # past the 30-min refresh
        seen = []
        w._process_event = lambda e: seen.append(e)
        assert w._maybe_refresh_connection() is True
        assert zk.fired, "the test did not exercise the last pump"
        assert len(seen) == 1, "a scan queued by the STA thread's last pump was never decided"
    finally:
        drv.disconnect()


# ---------------------------------------------------------------------------- R6-05
def test_r6_05_a_targeted_revoke_keeps_a_stale_snapshot_from_re_enrolling(monkeypatch, fstate):
    drv = RevokeDriver()
    w, cache = _worker(monkeypatch, driver=drv, users=[_user(30001, "A", "1")])
    fstate.rows["34439"] = ("old-hash", True, {0})            # owned, on the terminal
    assert w.request_member_revoke(34439) is True
    assert w._drain_member_sync_commands(limit=1) == 1
    assert drv.delete_calls == [["34439"]]
    # A capped continuation built from a snapshot loaded before the revocation committed;
    # the database no longer has the member (fstate: no sync_users row).
    cache.users.append(_user(34439, "Gone", "9"))
    drv.push_calls.clear()
    w.request_full_sync(reason="push-capped", fingerprint_hash="h2")
    assert w._drain_full_sync_commands(limit=1) == 1
    pushed = {str(u["pin"]) for c in drv.push_calls for u in c["users"]}
    assert "34439" not in pushed, "a departed member re-enrolled from a stale cache"


# ---------------------------------------------------------------------------- R6-06
def test_r6_06_an_unreadable_guard_read_neither_deletes_nor_reports_in_sync(monkeypatch, fstate):
    drv, w, cache = _removed_in_a_failed_pass(monkeypatch, fstate)     # guard armed: 34439
    # The membership was restored and an earlier full pass pushed the member back.
    fstate.rows["34439"] = ("back-hash", True, {0})
    cache.users.append(_user(34439, "Back", "9"))

    def _unreadable(ids):
        raise sqlite3.OperationalError("database is locked")
    monkeypatch.setattr(dbmod, "list_sync_users_by_active_membership_ids", _unreadable)
    drv.fail_push = False
    drv.delete_calls.clear()
    w.request_full_sync(reason="timer", fingerprint_hash="h3")
    assert w._drain_full_sync_commands(limit=1) == 1
    assert drv.delete_calls == [], "a paying member deleted because one read failed"
    assert w._on_full_sync_finished.call_args.kwargs["fingerprint_hash"] is None, (
        "the roster was reported in sync without the member")


# ---------------------------------------------------------------------------- R6-07
def test_r6_07_the_guard_reads_the_database_once_per_pass(monkeypatch, fstate):
    w, _c = _worker(monkeypatch, driver=RevokeDriver(), users=[])
    now = time.monotonic()
    w._recent_removed_members = {34439: now, 34440: now, 34441: now}
    calls = []

    def _read(ids):
        calls.append(sorted(ids))
        return []
    monkeypatch.setattr(dbmod, "list_sync_users_by_active_membership_ids", _read)
    assert w._recently_removed_still_gone() == {34439, 34440, 34441}
    assert calls == [[34439, 34440, 34441]], "one table scan per guarded member"


def test_r6_07_a_member_back_in_the_database_leaves_the_guard(db, monkeypatch):
    """The real coerced payload, not a stub: a wrong key would keep a restored member
    excluded (R5-03 again) without any error."""
    from tests.test_account_pin_sqlite_roundtrip import _ali, _write_delta_mode
    _write_delta_mode(db, [_ali()])                          # membership 31000 is present
    w, _c = _worker(monkeypatch, driver=RevokeDriver(), users=[])
    now = time.monotonic()
    w._recent_removed_members = {31000: now, 424242: now}
    assert w._recently_removed_still_gone() == {424242}
    assert set(w._recent_removed_members) == {424242}


# ---------------------------------------------------------- R6-02 / R6-03 / R6-04
def test_r6_02_a_listing_missing_owned_pins_changes_no_state_and_requests_no_pass(
        db, monkeypatch):
    """The R5-01 flag is withdrawn: flagging owned pins absent from the listing re-pushed
    most of the roster after a cut-short listing (R6-02), reset the retry clock of pins in
    backoff (R6-03) and never requested the pass it promised (R6-04). Re-adding members
    another system removed is loss detection (out of scope): it is only reported."""
    from tests.fake_terminal import TerminalZkem
    from tests.test_standalone_incremental_sync import _make_driver as _live_driver
    drv = _live_driver(TerminalZkem())
    w, _c = _worker(monkeypatch, driver=drv, users=[])
    monkeypatch.setattr(drv, "list_device_users", lambda **kw: {"ok": True, "users": [
        {"pin": "30001", "name": "M1", "card": "1"}]})
    db.save_device_sync_state_batch(device_id=9, rows=[("30001", "h1", True, None, ""),
                                                       ("30002", "h2", True, None, "")])
    db.record_push_intents(device_id=9, rows=[("30099", "Gone", "1", "h")],
                           protocol="ZK_STANDALONE")
    before = db.list_device_sync_hashes_and_status(device_id=9)
    requested = []
    monkeypatch.setattr(w, "request_full_sync", lambda **kw: requested.append(kw))
    try:
        w._promote_intents_by_readback(desired_pins={"30001", "30002"})
    finally:
        drv.disconnect()
    assert db.list_device_sync_hashes_and_status(device_id=9) == before
    assert requested == []
    assert set(db.list_push_intents(device_id=9)) == {"30099"}, (
        "an incomplete listing still drops no intent (R4-06)")

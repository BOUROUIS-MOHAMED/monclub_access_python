"""P3a-2 adversarial review, round 4: reproductions of the findings that were fixed.

Each test names its finding (R4-nn). Real temp SQLite; the real driver over the fake
terminal where the terminal matters.
"""
from __future__ import annotations

import queue

import pytest

import app.core.db as dbmod
import app.core.ultra_engine as ue
from tests.fake_terminal import TerminalZkem
from tests.test_standalone_finger_removal_state import fstate  # noqa: F401  (fixture)
from tests.test_standalone_incremental_sync import _make_driver, _user, _worker


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "r4.db"), raising=False)
    dbmod.init_db()
    yield dbmod
    dbmod._shutdown_db_writer_for_tests()


def test_r4_11_a_removed_revocation_is_fully_released_and_guarded_from_the_database(
        monkeypatch, fstate):
    """R4-11 (a capped continuation built from a stale cache could push a removed member
    back) was first fixed by KEEPING the roster exclusion; round 5 (R5-03) showed that
    refused a membership restored meanwhile. Now both markers are released and the stale
    cache is guarded from the database: test_review_round5.py covers both outcomes."""
    from tests.test_removals_first_and_retry import OrderDriver
    from tests.test_standalone_revoked_pin_removal import _authoritative_full_sync
    drv = OrderDriver(fail_push=True)
    w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "new", "1")])
    fstate.rows["34439"] = ("old-hash", True, {0})
    _authoritative_full_sync(w, 34439)
    with w._full_sync_lock:
        assert 34439 not in w._full_sync_revocation_phases_locked()
        assert 34439 not in w._full_sync_exclusion_phases_locked()
    assert 34439 in w._recent_removed_members


class _DeadLink:
    owns_event_source = True
    is_connected = False

    def disconnect(self):
        pass


def test_r4_10_no_full_sync_pass_runs_on_a_link_the_driver_reports_dead(monkeypatch):
    w, _c = _worker(monkeypatch, driver=_DeadLink(), users=[_user(30001, "A", "1")])
    ran = []
    monkeypatch.setattr(w, "_run_standalone_full_sync", lambda **kw: ran.append(kw))
    w.request_full_sync(reason="removal-retry")
    w._drain_full_sync_commands(limit=1)
    assert ran == [], "a removal pass spent on a dead link escalates the retry for nothing"
    assert w._pending_full_sync_request is not None, "kept for the reconnected link"


def _readback_worker(db, monkeypatch, listing):
    term = TerminalZkem()
    drv = _make_driver(term)
    w, _c = _worker(monkeypatch, driver=drv, users=[])
    monkeypatch.setattr(drv, "list_device_users", lambda **kw: listing)
    return drv, w


def test_r4_04_an_unreadable_ownership_state_does_not_disable_the_sanity_check(db, monkeypatch):
    drv, w = _readback_worker(db, monkeypatch, {"ok": True, "users": [
        {"pin": "Ali", "name": "30001", "card": "1"}]})
    db.save_device_sync_state_batch(device_id=9, rows=[("30001", "h", True, None, "")])
    db.record_push_intents(device_id=9, rows=[("30099", "Gone", "1", "h")],
                           protocol="ZK_STANDALONE")
    real = dbmod.list_confirmed_device_sync_pins

    def flaky(**kw):                                     # the push-intent read works; this fails
        raise RuntimeError("database is locked")
    monkeypatch.setattr(dbmod, "list_confirmed_device_sync_pins", flaky)
    try:
        w._promote_intents_by_readback(desired_pins={"30001"})
    finally:
        monkeypatch.setattr(dbmod, "list_confirmed_device_sync_pins", real)
        drv.disconnect()
    assert "30099" in db.list_push_intents(device_id=9)


def test_r4_06_a_listing_missing_an_owned_pin_drops_no_intent(db, monkeypatch):
    # a listing cut short after the first user: owned 30002 is missing from it
    drv, w = _readback_worker(db, monkeypatch, {"ok": True, "users": [
        {"pin": "30001", "name": "M1", "card": "1"}]})
    db.save_device_sync_state_batch(device_id=9, rows=[("30001", "h", True, None, ""),
                                                       ("30002", "h", True, None, "")])
    db.record_push_intents(device_id=9, rows=[("30099", "Gone", "1", "h")],
                           protocol="ZK_STANDALONE")
    try:
        w._promote_intents_by_readback(desired_pins={"30001", "30002"})
    finally:
        drv.disconnect()
    assert "30099" in db.list_push_intents(device_id=9), (
        "absent from an incomplete listing is not proof the write never landed")


def test_r4_05_a_targeted_push_reads_only_its_own_pins_finger_state(db, monkeypatch):
    term = TerminalZkem()
    drv = _make_driver(term)
    w, _c = _worker(monkeypatch, driver=drv, users=[])
    monkeypatch.setattr(w, "_member_row_in_db", lambda m: [_user(30001, "A", "1")])
    whole = []
    real = dbmod.list_device_pushed_fingers

    def spy(*a, **k):
        if not k.get("pins"):
            whole.append(1)
        return real(*a, **k)
    monkeypatch.setattr(dbmod, "list_device_pushed_fingers", spy)
    try:
        w._run_standalone_member_sync(30001)
    finally:
        drv.disconnect()
    assert "30001" in term.users
    assert whole == [], "a whole-device read on the door path, for one member"

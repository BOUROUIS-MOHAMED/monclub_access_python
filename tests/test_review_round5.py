"""P3a-2 adversarial review, round 5: reproductions of the findings that were fixed.

Each test names its finding (R5-nn). Real temp SQLite where the state matters.
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
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "r5.db"), raising=False)
    dbmod.init_db()
    yield dbmod
    dbmod._shutdown_db_writer_for_tests()


def _removed_in_a_failed_pass(monkeypatch, fstate):
    from tests.test_removals_first_and_retry import OrderDriver
    from tests.test_standalone_revoked_pin_removal import _authoritative_full_sync
    drv = OrderDriver(fail_push=True)
    w, cache = _worker(monkeypatch, driver=drv, users=[_user(30001, "new", "1")])
    fstate.rows["34439"] = ("old-hash", True, {0})
    _authoritative_full_sync(w, 34439)
    assert drv.delete_calls == [["34439"]]
    return drv, w, cache


def test_r5_03_a_restored_member_is_accepted_at_once(monkeypatch, fstate):
    """R4-11 kept the removed member's roster exclusion after a failed pass; a membership
    restored meanwhile was then refused and could stay off the terminal."""
    drv, w, cache = _removed_in_a_failed_pass(monkeypatch, fstate)
    # The restored membership is back in the database (the targeted read and, since
    # round 6, the guard's one-query read both go through this function).
    monkeypatch.setattr(dbmod, "list_sync_users_by_active_membership_ids",
                        lambda ids: [_user(34439, "Back", "9")] if 34439 in set(ids) else [])
    monkeypatch.setattr(w, "_member_row_in_db", lambda m: [_user(34439, "Back", "9")])
    assert w.request_member_sync(34439) is True
    cache.users.append(_user(34439, "Back", "9"))       # the cache has caught up
    drv.fail_push = False
    w.request_full_sync(reason="timer", fingerprint_hash="h2")
    assert w._drain_full_sync_commands(limit=1) == 1
    pushed = {str(u["pin"]) for c in drv.push_calls for u in c["users"]}
    assert "34439" in pushed, "a paying member left off the terminal"


def test_r4_11_a_stale_cache_still_cannot_push_back_a_removed_member(monkeypatch, fstate):
    drv, w, cache = _removed_in_a_failed_pass(monkeypatch, fstate)
    monkeypatch.setattr(w, "_member_row_in_db", lambda m: [])  # gone from the database
    cache.users.append(_user(34439, "Gone", "9"))             # ... but a stale snapshot lists it
    drv.fail_push = False
    drv.push_calls.clear()
    w.request_full_sync(reason="push-capped", fingerprint_hash="h2")
    assert w._drain_full_sync_commands(limit=1) == 1
    pushed = {str(u["pin"]) for c in drv.push_calls for u in c["users"]}
    assert "34439" not in pushed, "a departed member re-enrolled from a stale cache"


class _DeadLink:
    owns_event_source = True
    is_connected = False

    def __init__(self, events=()):
        self._events = list(events)

    def poll_rtlog_once(self, max_events: int = 64):
        out, self._events = self._events[:max_events], self._events[max_events:]
        return out

    def disconnect(self):
        pass


def test_r5_04_a_pass_requeued_for_a_dead_link_does_not_escalate_the_retry(monkeypatch):
    w, _c = _worker(monkeypatch, driver=_DeadLink(), users=[_user(30001, "A", "1")])
    w._removal_retry_streak = 1
    w.request_full_sync(reason="removal-retry")
    w._drain_full_sync_commands(limit=1)
    assert w._removal_retry_streak == 1, "a pass that attempted nothing doubled the delay"
    assert w._pending_full_sync_request is not None


def _link_worker(monkeypatch, sdk):
    w, _c = _worker(monkeypatch, driver=sdk, users=[])
    w._cmd_queue = queue.Queue()
    w._connect_retry_base_sec = 2.0
    w._connect_retry_max_sec = 120.0
    w._next_connect_at_mono = 0.0
    w._connected_since_mono = 0.0
    w._connect_down_since_mono = 0.0
    w._connect_down_since_iso = ""
    return w


def test_r5_06_every_queued_scan_is_decided_before_the_teardown(db, monkeypatch):
    events = [{"eventId": f"e{i}", "cardNo": str(i)} for i in range(150)]
    w = _link_worker(monkeypatch, _DeadLink(events=events))
    w._connected = True
    seen = []
    w._process_event = lambda e: seen.append(e["eventId"])
    w._push_link_lost()
    assert len(seen) == 150, "only the first 64 were decided; the rest died with the driver"


def test_r5_07_the_connection_refresh_decides_queued_scans_first(db, monkeypatch):
    class _Live(_DeadLink):
        is_connected = True
    evt = {"eventId": "e1", "cardNo": "1"}
    w = _link_worker(monkeypatch, _Live(events=[evt]))
    w._connected = True
    w._connected_since_mono = 1.0
    seen = []
    w._process_event = lambda e: seen.append(e)
    monkeypatch.setattr(ue.time, "monotonic", lambda: 10_000.0)
    assert w._maybe_refresh_connection() is True
    assert seen == [evt], "the 30-min refresh dropped a queued scan undecided"


def test_r5_01_an_owned_pin_missing_from_the_terminal_is_reported(db, monkeypatch):
    """One owned pin absent from the listing blocks every intent drop (R4-06 gate). Round 5
    flagged it for a re-push; round 6 withdrew that (R6-02/03/04, loss detection is out of
    scope): it is REPORTED, and changes nothing -- see test_review_round6."""
    events = []
    monkeypatch.setattr(ue._tel, "event", lambda name, **kw: events.append((name, kw)))
    term = TerminalZkem()
    drv = _make_driver(term)
    w, _c = _worker(monkeypatch, driver=drv, users=[])
    monkeypatch.setattr(drv, "list_device_users", lambda **kw: {"ok": True, "users": [
        {"pin": "30001", "name": "M1", "card": "1"}]})
    db.save_device_sync_state_batch(device_id=9, rows=[("30001", "h1", True, None, ""),
                                                       ("30002", "h2", True, None, "")])
    db.record_push_intents(device_id=9, rows=[("30099", "Gone", "1", "h")],
                           protocol="ZK_STANDALONE")
    try:
        w._promote_intents_by_readback(desired_pins={"30001", "30002"})
    finally:
        drv.disconnect()
    state = db.list_device_sync_hashes_and_status(device_id=9)
    assert state["30002"][1] is True, "reported only: no state change"
    [readback] = [kw for name, kw in events if name == "PUSH_INTENT_READBACK"]
    assert readback["missing_owned"] == 1 and readback["dropped"] == 0
    assert "30099" in db.list_push_intents(device_id=9), "still no drop on an incomplete listing"

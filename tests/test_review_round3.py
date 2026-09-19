"""P3a-2 adversarial review, round 3: reproductions of the findings that were fixed.

Each test names its finding (R3-nn). Real temp SQLite throughout; the real driver over the
stateful fake terminal where the terminal matters.
"""
from __future__ import annotations

import queue
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import app.core.db as dbmod
import app.core.ultra_engine as ue
from tests.fake_terminal import TerminalZkem
from tests.test_standalone_finger_removal_state import fstate  # noqa: F401  (fixture)
from tests.test_standalone_incremental_sync import _make_driver, _tpl, _user, _worker


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "r3.db"), raising=False)
    dbmod.init_db()
    yield dbmod
    dbmod._shutdown_db_writer_for_tests()


class _DeadLink:
    owns_event_source = True
    is_connected = False

    def __init__(self, events=()):
        self._events = list(events)

    def poll_rtlog_once(self, max_events: int = 64):
        out, self._events = self._events, []
        return out

    def disconnect(self):
        pass


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


# ═══════════════ link loss (R3-01/18/22, R3-02, R3-03, R3-19) ═══════════════

def test_r3_01_the_flap_streak_decays_once_the_link_was_stable(db, monkeypatch):
    clock = {"t": 1000.0}
    monkeypatch.setattr(ue.time, "monotonic", lambda: clock["t"])
    w = _link_worker(monkeypatch, _DeadLink())
    for _ in range(5):                                   # a flapping boot: streak climbs
        w._sdk, w._connected, w._connected_since_mono = _DeadLink(), True, clock["t"]
        clock["t"] += 3.0
        w._push_link_lost()
        clock["t"] = max(clock["t"], w._next_connect_at_mono)
    clock["t"] += 3 * 3600                               # hours of a stable link ...
    w._sdk, w._connected, w._connected_since_mono = _DeadLink(), True, clock["t"]  # a CONN_REFRESH
    clock["t"] += 20.0                                   # ... then ONE loss 20 s after it
    w._push_link_lost()
    assert max(0.0, w._next_connect_at_mono - clock["t"]) == 0.0, (
        "a stale streak made an isolated loss wait up to 120 s")


def test_r3_02_a_backoff_starts_the_outage_clock(db, monkeypatch):
    clock = {"t": 1000.0}
    monkeypatch.setattr(ue.time, "monotonic", lambda: clock["t"])
    w = _link_worker(monkeypatch, _DeadLink())
    for _ in range(2):
        w._sdk, w._connected, w._connected_since_mono = _DeadLink(), True, clock["t"]
        clock["t"] += 3.0
        w._push_link_lost()
        clock["t"] = max(clock["t"], w._next_connect_at_mono)
    assert w._next_connect_at_mono > 0.0
    assert w._connect_down_since_mono > 0.0, (
        "the desk's Open short-circuit (device unreachable) never sees the outage")


def test_r3_03_the_run_loop_spends_no_member_update_on_a_dead_link(db, monkeypatch):
    w = _link_worker(monkeypatch, _DeadLink())
    w._connected = True
    w._pending_member_syncs.append(30005)
    w._pending_member_sync_ids.add(30005)
    w._drain_member_sync_commands(limit=1)
    assert list(w._pending_member_syncs) == [30005]


def test_r3_19_scans_queued_on_a_dead_link_are_decided_after_the_reconnect(db, monkeypatch):
    evt = {"eventId": "e1", "cardNo": "123"}
    w = _link_worker(monkeypatch, _DeadLink(events=[evt]))
    w._connected = True
    seen = []
    w._process_event = lambda e: seen.append(e)
    assert w._push_link_lost() is True
    assert seen == [], "decided on a link that cannot open the door"
    assert w._take_carried_events() == [evt]
    assert w._take_carried_events() == []


# ═══════════════ removal retry (R3-04/17/27, R3-16, R3-14) ═══════════════

def test_r3_04_a_pullsdk_pass_with_no_removal_report_keeps_the_retry(monkeypatch):
    class _Engine:
        def __init__(self, cfg, logger):
            self._last_single_device_error = "no device reached"

        def sync_member_on_connected_sdk(self, **kw):
            return True

        def run_one_device_on_connected_sdk(self, **kw):
            return False                              # returned before _sync_one_device

    w = ue.UltraDeviceWorker(
        device={"id": 5, "name": "Door", "ipAddress": "10.0.0.5", "portNumber": 4370},
        settings={}, popup_q=queue.Queue(), history_q=queue.Queue(),
        stop_event=threading.Event(),
    )
    w._connected = True
    w._sdk = SimpleNamespace(owns_event_source=False, _sdk="raw")
    w._on_full_sync_finished = MagicMock()
    w._removal_retry_streak = 1
    monkeypatch.setattr(ue, "load_sync_cache",
                        lambda: SimpleNamespace(users=[{"activeMembershipId": 1}], devices=[]))
    monkeypatch.setattr("app.core.device_sync.DeviceSyncEngine", _Engine)
    w.request_full_sync(reason="removal-retry")
    assert w._drain_full_sync_commands(limit=1) == 1
    assert getattr(w, "_removal_retry_at_mono", None) is not None, (
        "a missing report read as a completed pass and cleared the retry")


def test_r3_16_parking_never_postpones_a_sooner_retry(monkeypatch):
    clock = {"t": 1000.0}
    monkeypatch.setattr(ue.time, "monotonic", lambda: clock["t"])
    w, _c = _worker(monkeypatch, driver=SimpleNamespace(), users=[])
    w._removal_retry_streak = 2
    w._removal_retry_at_mono = 1060.0                   # due in 60 s
    w._update_removal_retry(failed=[], skipped=True)
    assert w._removal_retry_at_mono == 1060.0


def test_r3_14_a_removed_revocation_is_released_when_its_pass_fails(monkeypatch, fstate):
    from tests.test_removals_first_and_retry import OrderDriver
    from tests.test_standalone_revoked_pin_removal import _authoritative_full_sync
    drv = OrderDriver(fail_push=True)
    w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "new", "1")])
    fstate.rows["34439"] = ("old-hash", True, {0})
    _authoritative_full_sync(w, 34439)
    assert drv.delete_calls == [["34439"]]
    with w._full_sync_lock:
        assert 34439 not in w._full_sync_revocation_phases_locked(), (
            "left ACTIVE: excluded from every later roster until a restart")
    assert w.request_member_sync(34439) is True


# ═══════════════ ownership, grace, capacity, read-back (R3-06, R3-11, R3-12, R3-20, R3-24) ═════

def test_r3_11_the_prune_keeps_the_grace_the_removal_step_used(db, monkeypatch):
    term = TerminalZkem()
    drv = _make_driver(term)
    w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "A", "1")])
    db.save_device_sync_state_batch(device_id=9, rows=[("30077", "h", True, None, "")])
    calls = {"n": 0}

    def grace():                                        # expires between the two checks
        calls["n"] += 1
        return {"30077"} if calls["n"] == 1 else set()
    monkeypatch.setattr(w, "_mirror_grace_pins", grace)
    try:
        w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
    finally:
        drv.disconnect()
    assert "30077" in set(db.list_confirmed_device_sync_pins(device_id=9)), (
        "neither removed nor kept: its ownership row was pruned")


def test_r3_12_a_withheld_pins_resident_fingers_are_recorded_truthfully(db, monkeypatch):
    term = TerminalZkem()
    term.status = {11: 500, 10: 0}
    term.add_user("30002", "B", "2", fingers=(0, 3))
    db.save_device_sync_state_batch(device_id=9, rows=[("30002", "h-old", True, None, "0,3")])
    drv = _make_driver(term)
    w, _c = _worker(monkeypatch, driver=drv, users=[
        _user(30002, "B", "2", fps=[_tpl(0, "AAAA"), _tpl(5, "FFFF"), _tpl(6, "GGGG")])])
    try:
        w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
    finally:
        drv.disconnect()
    assert term.fingers_of("30002") == {0, 5}, "slot 3 cleared, finger 5 written, 6 withheld"
    assert db.list_device_pushed_fingers(device_id=9)["30002"] == {0, 5}, (
        "the stale '0,3' makes every retry clear the empty slot 3 and fail for good")


def test_r3_20_a_listing_that_shows_none_of_monclubs_pins_changes_nothing(db, monkeypatch):
    term = TerminalZkem()
    drv = _make_driver(term)
    w, _c = _worker(monkeypatch, driver=drv, users=[])
    db.save_device_sync_state_batch(device_id=9, rows=[("30001", "h", True, None, "")])
    db.record_push_intents(device_id=9, rows=[("30099", "Gone", "1", "h")],
                           protocol="ZK_STANDALONE")
    # a wrong out-param order: the "pin" field carries the name
    monkeypatch.setattr(drv, "list_device_users", lambda **kw: {
        "ok": True, "users": [{"pin": "Ali", "name": "30001", "card": "1"}]})
    try:
        w._promote_intents_by_readback(desired_pins={"30001"})
    finally:
        drv.disconnect()
    assert "30099" in db.list_push_intents(device_id=9)


def test_r3_24_a_targeted_push_reads_no_whole_device_table_for_capacity(db, monkeypatch):
    term = TerminalZkem()
    term.status = {11: 500, 10: 50}
    drv = _make_driver(term)
    w, _c = _worker(monkeypatch, driver=drv, users=[])
    monkeypatch.setattr(w, "_member_row_in_db", lambda m: [_user(30001, "A", "1")])
    whole = []
    for name in ("list_confirmed_device_sync_pins", "list_device_sync_hashes_and_status",
                 "list_push_intents"):
        real = getattr(dbmod, name)
        monkeypatch.setattr(dbmod, name, lambda *a, _n=name, _r=real, **k: (whole.append(_n), _r(*a, **k))[1])
    try:
        w._run_standalone_member_sync(30001)
    finally:
        drv.disconnect()
    assert "30001" in term.users
    assert whole == [], "door-blind whole-table reads for one member: " + ",".join(whole)


# ═══════════════ PullSDK prune (R3-06) ═══════════════

from tests.test_account_pin_device_sites import (  # noqa: E402,F401  (fixture)
    _engine, _member, _pullsdk_device, _sdk, sqlite_db,
)


def test_r3_06_the_prune_keeps_the_row_of_a_pin_still_on_the_panel(sqlite_db):
    sqlite_db.save_device_sync_state(device_id=1, pin="40001", desired_hash="h", ok=True, error=None)
    sdk = _sdk(["40001", "101"])
    device = _pullsdk_device(pinScheme="", pushingToDevicePolicy="PUSH_WITHOUT_DELETING")
    users = [_member(101, 9101, None, "M101", card="100101")]
    with patch("app.core.device_sync.PullSDK", MagicMock(return_value=sdk)):
        _engine()._sync_one_device(device=device, users=users, local_fp_index={},
                                   default_door_id=1, changed_ids=None)
    assert sqlite_db.get_device_sync_ownership_for_pin(device_id=1, pin="40001") is True, (
        "the pin is still on the panel; without its row a later revocation is final-skipped")


# ═══════════════ follow-ups (advisor, after round 3) ═══════════════

def test_r3_12_the_targeted_push_records_a_withheld_pins_resident_fingers(db, monkeypatch):
    term = TerminalZkem()
    term.status = {11: 500, 10: 0}
    term.add_user("30002", "B", "2", fingers=(0, 3))
    db.save_device_sync_state_batch(device_id=9, rows=[("30002", "h-old", True, None, "0,3")])
    drv = _make_driver(term)
    w, _c = _worker(monkeypatch, driver=drv, users=[])
    monkeypatch.setattr(w, "_member_row_in_db", lambda m: [
        _user(30002, "B", "2", fps=[_tpl(0, "AAAA"), _tpl(5, "FFFF"), _tpl(6, "GGGG")])])
    try:
        w._run_standalone_member_sync(30002)
    finally:
        drv.disconnect()
    assert term.fingers_of("30002") == {0, 5}
    assert db.list_device_pushed_fingers(device_id=9)["30002"] == {0, 5}


def test_a_scan_carried_over_a_long_outage_is_not_decided_late(db, monkeypatch):
    """A rescue decided minutes after the member scanned would open the door for nobody."""
    clock = {"t": 1000.0}
    monkeypatch.setattr(ue.time, "monotonic", lambda: clock["t"])
    evt = {"eventId": "e1", "cardNo": "123"}
    w = _link_worker(monkeypatch, _DeadLink(events=[evt]))
    w._connected = True
    w._push_link_lost()
    clock["t"] += ue._CARRY_MAX_AGE_SEC + 1.0
    assert w._take_carried_events() == []
    w._sdk, w._connected = _DeadLink(events=[evt]), True
    w._push_link_lost()
    clock["t"] += 1.0
    assert w._take_carried_events() == [evt], "a quick reconnect still decides it"

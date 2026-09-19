"""P3a-2 adversarial review, round 2: reproductions of the findings that were fixed.

Each test names its finding (R2-nn). Most are defects introduced by round-1 fixes.
Real driver + real STA thread over the stateful fake terminal where the terminal matters;
real temp SQLite throughout.
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
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "r2.db"), raising=False)
    dbmod.init_db()
    yield dbmod
    dbmod._shutdown_db_writer_for_tests()


# ═══════════════ capacity + ownership (R2-01/22, R2-02/04/07/25, R2-24) ═══════════════

def test_r2_01_a_wedged_chunk_with_a_withheld_pin_confirms_none_of_its_members(db, monkeypatch):
    term = TerminalZkem()
    term.status = {11: 500, 10: 0}                      # no fingerprint slot: A's finger withheld
    users = [_user(30001, "A", "1", fps=[_tpl(0, "AAAA")]), _user(30002, "B", "2"),
             _user(30003, "C", "3")]
    drv = _make_driver(term)
    real_call = drv._call

    def call(op, args=None, timeout=10.0):
        if op == "push_roster":
            raise TimeoutError("zkemkeeper command 'push_roster' timed out")
        return real_call(op, args, timeout)
    drv._call = call
    w, _c = _worker(monkeypatch, driver=drv, users=users)
    try:
        w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
    finally:
        drv.disconnect()
    owned = set(db.list_confirmed_device_sync_pins(device_id=9))
    state = db.list_device_sync_hashes_and_status(device_id=9)
    assert not ({"30002", "30003"} & owned), "never written, recorded as MonClub's"
    assert state["30002"][1] is False and state["30003"][1] is False


def test_r2_02_a_targeted_push_never_records_a_withheld_finger_as_resident(db, monkeypatch):
    term = TerminalZkem()
    term.status = {11: 500, 10: 0}
    term.add_user("30001", "A", "1", fingers=(0,))
    db.save_device_sync_state_batch(device_id=9, rows=[("30001", "h-old", True, None, "0")])
    drv = _make_driver(term)
    w, _c = _worker(monkeypatch, driver=drv, users=[])
    monkeypatch.setattr(w, "_member_row_in_db", lambda m: [
        _user(30001, "A", "1", fps=[_tpl(0, "AAAA"), _tpl(1, "BBBB")])])
    try:
        w._run_standalone_member_sync(30001)
    finally:
        drv.disconnect()
    assert 1 not in term.fingers_of("30001")
    _owned, _swept, fingers = db.get_finger_sweep_state(device_id=9, pin="30001")
    assert 1 not in (fingers or set()), "a finger never written, recorded as on the terminal"


def test_r2_24_a_partly_failed_targeted_push_gets_the_enrolment_grace(db, monkeypatch):
    term = TerminalZkem()
    term.settmp_ok = False                              # the finger is refused, the card lands
    drv = _make_driver(term)
    w, _c = _worker(monkeypatch, driver=drv, users=[])
    monkeypatch.setattr(w, "_member_row_in_db", lambda m: [
        _user(30001, "New", "1", fps=[_tpl(0, "AAAA")])])
    try:
        w._run_standalone_member_sync(30001)
    finally:
        drv.disconnect()
    assert "30001" in set(db.list_confirmed_device_sync_pins(device_id=9))
    assert "30001" in w._mirror_grace_pins(), (
        "owned but not in grace: a removals-first pass from a stale cache deletes the new member")


def test_r2_09_the_prune_keeps_a_member_pushed_moments_ago(db, monkeypatch):
    term = TerminalZkem()
    drv = _make_driver(term)
    w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "A", "1")])
    db.save_device_sync_state_batch(device_id=9, rows=[("30077", "h", True, None, "")])
    w._note_recent_pushes(["30077"])                    # enrolled seconds ago, cache not yet updated
    try:
        w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
    finally:
        drv.disconnect()
    assert "30077" in set(db.list_confirmed_device_sync_pins(device_id=9))


# ═══════════════ MB2000 read-back (R2-06/29) ═══════════════

def test_r2_06_an_empty_terminal_listing_drops_no_intent(db, monkeypatch):
    term = TerminalZkem()                               # lists OK, with no user at all
    drv = _make_driver(term)
    w, _c = _worker(monkeypatch, driver=drv, users=[])
    db.record_push_intents(device_id=9, rows=[("30099", "Gone", "1", "h")],
                           protocol="ZK_STANDALONE")
    try:
        w._promote_intents_by_readback(desired_pins=set())
    finally:
        drv.disconnect()
    assert "30099" in db.list_push_intents(device_id=9)


# ═══════════════ link loss (R2-11/15/27, R2-12/28, R2-13, R2-14, R2-16) ═══════════════

class _DeadLink:
    owns_event_source = True
    is_connected = False

    def __init__(self, events=()):
        self._events = list(events)
        self.disconnected = False

    def poll_rtlog_once(self, max_events: int = 64):
        out, self._events = self._events, []
        return out

    def disconnect(self):
        self.disconnected = True


def _link_worker(monkeypatch, sdk):
    w, _c = _worker(monkeypatch, driver=sdk, users=[])
    w._cmd_queue = queue.Queue()
    w._connect_retry_base_sec = 2.0
    w._connect_retry_max_sec = 120.0
    w._next_connect_at_mono = 0.0
    w._connected_since_mono = 0.0
    return w


def test_r2_11_disconnect_is_still_the_timed_function():
    assert hasattr(ue.UltraDeviceWorker._disconnect, "__wrapped__"), (
        "the CONN_DISCONNECT timer moved onto the link check")
    assert not hasattr(ue.UltraDeviceWorker._push_link_lost, "__wrapped__")


def test_r2_12_a_link_that_keeps_dying_backs_off(db, monkeypatch):
    clock = {"t": 1000.0}
    monkeypatch.setattr(ue.time, "monotonic", lambda: clock["t"])
    w = _link_worker(monkeypatch, _DeadLink())
    delays = []
    for _ in range(4):
        w._sdk, w._connected, w._connected_since_mono = _DeadLink(), True, clock["t"]
        clock["t"] += 3.0                               # dies 3 s after each reconnect
        assert w._push_link_lost() is True
        delays.append(max(0, round(w._next_connect_at_mono - clock["t"])))
        clock["t"] = max(clock["t"], w._next_connect_at_mono)
    assert delays[0] == 0, "the first loss reconnects at once"
    assert delays[1:] == [2, 4, 8], "a link dying right after each connect must back off"
    w._sdk, w._connected, w._connected_since_mono = _DeadLink(), True, clock["t"]
    clock["t"] += 600.0                                 # stable for 10 min, then dies
    w._push_link_lost()
    assert max(0, round(w._next_connect_at_mono - clock["t"])) == 0


def test_r2_13_scans_queued_before_the_link_died_are_still_decided(db, monkeypatch):
    evt = {"eventId": "e1", "cardNo": "123"}
    w = _link_worker(monkeypatch, _DeadLink(events=[evt]))
    w._connected = True
    seen = []
    w._process_event = lambda e: seen.append(e)
    assert w._push_link_lost() is True
    assert seen == [evt]


def test_r2_14_the_push_yield_serves_no_member_update_on_a_dead_link(db, monkeypatch):
    w = _link_worker(monkeypatch, _DeadLink())
    w._connected = True
    w._pending_member_syncs.append(30005)
    w._pending_member_sync_ids.add(30005)
    w._standalone_push_yield()
    assert list(w._pending_member_syncs) == [30005], "used up on a link that cannot deliver it"


def test_r2_16_daily_maintenance_waits_for_a_live_link(db, monkeypatch):
    w = _link_worker(monkeypatch, _DeadLink())
    w._connected = True
    w._maintenance_ready_day = ue._local_day()
    w._last_desired_pins = set()
    w._drain_daily_maintenance()
    assert getattr(w, "_readback_done_day", None) is None, "the day's only read-back used up"


# ═══════════════ removal retry (R2-17, R2-20, R2-23) ═══════════════

def test_r2_20_a_guard_bail_out_parks_the_retry_instead_of_clearing_it(monkeypatch, fstate):
    from tests.test_standalone_revoked_pin_removal import RevokeDriver
    fstate.rows["30055"] = ("h", True, {0})
    w, _c = _worker(monkeypatch, driver=RevokeDriver(), users=[])
    w._note_recent_pushes(["30055"])                    # pushed moments ago
    w._neutralise_revoked_pins(desired_pins=["30001"], roster_count=1,
                               required_pins={"30055"})
    assert w._last_revoke_step == "skipped"


def test_r2_23_a_deferred_pullsdk_revocation_does_not_rearm_the_fast_retry(monkeypatch):
    class _Engine:
        def __init__(self, cfg, logger):
            self._last_single_device_error = ""
            self._last_removal_report = {"aborted": 0, "failed": [], "complete": True}
            self._last_member_sync_outcome = None

        def sync_member_on_connected_sdk(self, **kw):
            self._last_member_sync_outcome = "DEFERRED"   # roster incomplete: not deletable now
            return False

        def run_one_device_on_connected_sdk(self, **kw):
            return True

    w = ue.UltraDeviceWorker(
        device={"id": 5, "name": "Door", "ipAddress": "10.0.0.5", "portNumber": 4370},
        settings={}, popup_q=queue.Queue(), history_q=queue.Queue(),
        stop_event=threading.Event(),
    )
    w._connected = True
    w._sdk = SimpleNamespace(owns_event_source=False, _sdk="raw")
    w._on_full_sync_finished = MagicMock()
    monkeypatch.setattr(ue, "load_sync_cache",
                        lambda: SimpleNamespace(users=[{"activeMembershipId": 1}], devices=[]))
    monkeypatch.setattr("app.core.device_sync.DeviceSyncEngine", _Engine)
    w.request_full_sync(reason="revoke-failed", revoked_ids={41})
    assert w._drain_full_sync_commands(limit=1) == 1
    assert getattr(w, "_removal_retry_at_mono", None) is None, (
        "nothing a 30-300 s retry can change: a C3 pass every 300 s for nothing")


# ═══════════════ PullSDK (R2-21, R2-18/26) ═══════════════

from tests.test_account_pin_device_sites import (  # noqa: E402,F401  (fixture)
    _engine, _member, _pullsdk_device, _sdk, sqlite_db,
)


def test_r2_21_a_failed_stale_delete_is_reported_even_if_the_pass_then_fails(sqlite_db):
    for pin in ("40001", "40002"):
        sqlite_db.save_device_sync_state(device_id=1, pin=pin, desired_hash="h", ok=True, error=None)
    sdk = _sdk(["40001", "40002"])
    sdk.delete_device_data_batch.side_effect = lambda *, table, pins, chunk_size: (
        (1, ["40002"]) if table == "user" else (len(pins), []))
    eng = _engine()
    device = _pullsdk_device(pinScheme="", pushingToDevicePolicy="1")
    users = [_member(am, 9000 + am, None, f"M{am}", card=str(100000 + am)) for am in (101,)]
    with patch("app.core.device_sync.PullSDK", MagicMock(return_value=sdk)), \
            patch("app.core.device_sync.record_push_intents", side_effect=RuntimeError("locked")):
        with pytest.raises(Exception):
            eng._sync_one_device(device=device, users=users, local_fp_index={},
                                 default_door_id=1, changed_ids=None)
    assert eng._last_removal_report["failed"] == ["40002"], (
        "the stale step's failure is lost when a later step of the same pass raises")


def test_r2_18_a_failed_promotion_write_is_a_retry_not_final(sqlite_db):
    from tests.test_account_pin_device_sites import _cache, _sonia, _ali_gym
    from tests.test_push_write_ahead import _panel_sdk
    _cache(sqlite_db, [_ali_gym(), _sonia()])
    _cache(sqlite_db, [], valid_ids=[31000])            # Sonia (pin 5) revoked
    sqlite_db.record_push_intents(device_id=1, protocol="ZK_PULLSDK",
                                  rows=[("5", "Sonia", "1901", "h")])
    sdk = _panel_sdk({"5": "1901"})                     # her card IS on the panel
    eng = _engine()
    with patch("app.core.device_sync.promote_push_intents", side_effect=RuntimeError("locked")):
        assert eng.sync_member_on_connected_sdk(
            sdk=sdk, device=_pullsdk_device(), member_id=5, revocation=True) is False
    assert eng._last_member_sync_outcome == "OWNERSHIP_UNREADABLE"


# ═══════════════ daily maintenance on an always-incomplete roster (R2-05) ═══════════════

def _withheld_roster(w, monkeypatch):
    orig = w._build_standalone_roster

    def withheld(*a, **k):
        out = orig(*a, **k)
        w._last_standalone_roster_stats = {"withheld_missing_account": 1}
        return out
    monkeypatch.setattr(w, "_build_standalone_roster", withheld)


def test_r2_05_the_slot_opens_with_the_last_complete_snapshot(db, monkeypatch):
    term = TerminalZkem()
    drv = _make_driver(term)
    w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "A", "1")])
    w._cmd_queue = queue.Queue()
    try:
        w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")   # complete
        w._maintenance_ready_day = None                                      # a new day
        _withheld_roster(w, monkeypatch)
        w._run_standalone_full_sync(reason="timer", fingerprint_hash="h2")  # incomplete
        w._drain_daily_maintenance()
    finally:
        drv.disconnect()
    assert getattr(w, "_readback_done_day", None) == ue._local_day(), (
        "an incomplete pass suspended the whole daily maintenance slot, silently")


def test_r2_05_no_complete_roster_yet_is_reported_once_a_day(db, monkeypatch):
    import app.core.telemetry as tel
    seen = []
    monkeypatch.setattr(tel, "warn", lambda name, **f: seen.append(name))
    term = TerminalZkem()
    drv = _make_driver(term)
    w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "A", "1")])
    w._cmd_queue = queue.Queue()
    _withheld_roster(w, monkeypatch)
    try:
        w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
        for _ in range(3):
            w._drain_daily_maintenance()
    finally:
        drv.disconnect()
    assert seen.count("MAINTENANCE_SKIPPED") == 1

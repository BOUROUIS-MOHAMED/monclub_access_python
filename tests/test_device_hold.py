"""Lane 1 item 3: a turnstile on hold gets NO write from MonClub (guide §3.2h).

The Erase-content wizard holds a turnstile from before its backup to the refill -- and, with
"Hold until I press Refill", across a restart (the cutover restarts Access between the erase and
the refill). The hold closes the gates a handover's write freeze closes: the ULTRA worker's member
drain, full-sync drain, mid-push chunks and maintenance slot, the PullSDK engine's pass, batch and
targeted member sync, and the remote DEVICE_RECONCILE. The door and the scans are untouched.
Also here: the driver surfaces the wizard added (strict PullSDK reads, the MB2000 template read and
privilege).
"""
from __future__ import annotations

import queue
import threading
import time
from types import SimpleNamespace
from typing import List
from unittest.mock import MagicMock, patch

import pytest

import app.core.db as dbmod
import app.core.ultra_engine as ue
from app.core import device_hold
from app.core.v2 import lease_gate as lg
from tests.test_account_pin_device_sites import _member, _pullsdk_device, _sdk, _written_pins


@pytest.fixture
def sqlite_db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "hold.db"), raising=False)
    dbmod.init_db()
    device_hold.reset_for_tests()
    lg.reset_for_tests()
    yield dbmod
    device_hold.reset_for_tests()
    lg.reset_for_tests()
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


def _users(*ams):
    return [_member(am, 9000 + am, None, f"M{am}", card=str(100000 + am)) for am in ams]


# ─────────────────────────── the hold itself ───────────────────────────

def test_a_hold_is_durable_and_reloaded_at_start(sqlite_db):
    device_hold.hold(5, reason="erase", run_id="r1")
    assert device_hold.is_held(5) and not device_hold.is_held(6)
    assert sqlite_db.list_device_write_holds()[5]["runId"] == "r1"
    device_hold.reset_for_tests()                       # the process ends
    assert not device_hold.is_held(5)
    assert device_hold.load() == frozenset({5})         # the next start
    assert device_hold.is_held("5")
    assert device_hold.release(5) is True
    assert not device_hold.is_held(5) and sqlite_db.list_device_write_holds() == {}


def test_the_app_loads_the_holds_before_the_first_sync_tick(tmp_path, monkeypatch):
    import app.ui.app as app_module
    from tests.test_p3b1_app_wiring import _stub_heavy_init

    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "init.db"), raising=False)
    _stub_heavy_init(monkeypatch)
    order: List[str] = []

    class StopInit(Exception):
        pass

    monkeypatch.setattr(app_module.MainApp, "_apply_date_flips", lambda self, source, **k: None)
    # Lane 1b: the start-up load also releases the holds of runs that stopped before any delete.
    monkeypatch.setattr(device_hold, "load", lambda **kw: order.append(
        "holds" if kw == {"release_unstarted": True} else f"holds{kw}") or frozenset())

    def recording_after(self, delay_ms, callback):
        if getattr(callback, "__name__", "") == "_sync_tick":
            order.append("first_sync_tick")
            raise StopInit
        return 1

    monkeypatch.setattr(app_module.MainApp, "after", recording_after)
    with pytest.raises(StopInit):
        app_module.MainApp()
    assert order == ["holds", "first_sync_tick"]


# ─────────────────────── a failed start-up load fails CLOSED (review round 1, finding 10) ───────────────────────

def _unreadable():
    raise RuntimeError("database is locked")


def test_a_failed_load_holds_every_turnstile_until_a_retry_reads(sqlite_db, monkeypatch):
    device_hold.hold(5, reason="erase", run_id="r")
    device_hold.reset_for_tests()                         # the next start ...
    real = dbmod.list_device_write_holds
    monkeypatch.setattr(dbmod, "list_device_write_holds", _unreadable)
    with pytest.raises(RuntimeError):
        device_hold.load()                                # ... cannot read the holds
    assert device_hold.load_failed() is True
    assert device_hold.is_held(5) and device_hold.is_held(6), "unknown: every turnstile is held"
    assert ue._v2_writes_blocked(6) is True
    assert device_hold.ensure_loaded() is False           # still unreadable: stays closed
    assert device_hold.is_held(6)
    monkeypatch.setattr(dbmod, "list_device_write_holds", real)
    assert device_hold.ensure_loaded() is True
    assert device_hold.is_held(5) and not device_hold.is_held(6)
    assert device_hold.load_failed() is False


def test_ensure_loaded_reads_nothing_once_the_holds_are_loaded(sqlite_db, monkeypatch):
    device_hold.load()
    monkeypatch.setattr(dbmod, "list_device_write_holds", _unreadable)
    assert device_hold.ensure_loaded() is True            # the flag is clear: no read


def test_reset_for_tests_clears_the_failed_flag(sqlite_db, monkeypatch):
    monkeypatch.setattr(dbmod, "list_device_write_holds", _unreadable)
    with pytest.raises(RuntimeError):
        device_hold.load()
    device_hold.reset_for_tests()
    assert device_hold.load_failed() is False and not device_hold.is_held(5)


def test_a_load_racing_a_hold_keeps_the_in_memory_gate(sqlite_db, monkeypatch):
    """Review round 2 (R2-5): load() read the database, then replaced the in-memory set -- a
    hold() whose row landed in between lost its gate although its row was durable."""
    real = dbmod.list_device_write_holds
    raced = []

    def _read_then_a_hold_lands():
        out = real()
        if not raced:
            raced.append(1)
            threading.Thread(target=lambda: device_hold.hold(5, reason="erase", run_id="r"),
                             daemon=True).start()
            time.sleep(0.2)                     # the hold waits for the load to finish
        return out

    monkeypatch.setattr(device_hold, "_load_failed", True)
    monkeypatch.setattr(dbmod, "list_device_write_holds", _read_then_a_hold_lands)
    assert device_hold.ensure_loaded() is True
    deadline = time.monotonic() + 5
    while 5 not in real() and time.monotonic() < deadline:
        time.sleep(0.02)
    monkeypatch.setattr(dbmod, "list_device_write_holds", real)
    assert 5 in real() and device_hold.is_held(5), "the row and the gate agree"


def test_every_sync_tick_retries_a_failed_hold_load(monkeypatch):
    import app.ui.app as app_module
    calls: List[int] = []
    monkeypatch.setattr(device_hold, "ensure_loaded", lambda: calls.append(1) or True)
    fake = SimpleNamespace(reschedule_sync_timer=lambda: None, _sync_work_running=True,
                           _pending_sync_context=None, logger=MagicMock())
    app_module.MainApp._sync_tick(fake)
    assert calls == [1], "retried even when the tick itself is skipped"


# ─────────────────────────── the ULTRA worker ───────────────────────────

def test_the_worker_gate_includes_the_hold(sqlite_db):
    assert ue._v2_writes_blocked(5) is False
    device_hold.hold(5)
    assert ue._v2_writes_blocked(5) is True and ue._v2_writes_blocked(6) is False


def _panel_worker(monkeypatch, users, raw):
    device = _pullsdk_device(pinScheme="", pushingToDevicePolicy="1")
    w = ue.UltraDeviceWorker(device=device, settings={}, popup_q=queue.Queue(),
                             history_q=queue.Queue(), stop_event=threading.Event())
    w._connected = True
    w._on_full_sync_finished = MagicMock()
    monkeypatch.setattr(ue, "load_sync_cache",
                        lambda: SimpleNamespace(users=list(users), devices=[]))
    w._sdk = SimpleNamespace(owns_event_source=False, _sdk=raw)
    return w


def test_a_held_panel_runs_no_pass_until_it_is_released(sqlite_db, monkeypatch):
    raw = _sdk([])
    w = _panel_worker(monkeypatch, _users(101, 102), raw)
    device_hold.hold(1)
    w.request_full_sync(reason="timer", fingerprint_hash="h")
    assert w._drain_full_sync_commands(limit=1) == 0
    assert w._pending_full_sync_request is not None, "the pass waits, it is not dropped"
    assert _written_pins(raw) == []
    device_hold.release(1)
    assert w._drain_full_sync_commands(limit=1) == 1
    assert {"101", "102"} <= set(_written_pins(raw))


def test_a_held_panel_serves_no_member_update(sqlite_db, monkeypatch):
    w = _panel_worker(monkeypatch, _users(101), _sdk([]))
    device_hold.hold(1)
    w.request_member_sync(101)
    assert w._drain_member_sync_commands(limit=1) == 0
    assert list(w._pending_member_syncs) == [101], "still queued for after the refill"


def test_a_hold_set_mid_push_stops_the_rest_of_an_mb2000_push(sqlite_db, monkeypatch):
    from tests.test_push_yield_and_cap import HookedTerminal, _members, _setup

    term = HookedTerminal()
    drv, w = _setup(monkeypatch, term, _members(40))
    term.on_user["30005"] = lambda: device_hold.hold(9)       # during chunk 1
    try:
        w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
    finally:
        drv.disconnect()
    assert len(term.users) == 10, "chunk 1 was already on the wire; nothing after it"


# ─────────────────────────── the PullSDK engine ───────────────────────────

def test_the_pullsdk_pass_opens_no_session_on_a_held_panel(sqlite_db):
    from tests.test_account_pin_device_sites import _engine

    device_hold.hold(1)
    factory = MagicMock()
    with patch("app.core.device_sync.PullSDK", factory):
        _engine()._sync_one_device(device=_pullsdk_device(), users=_users(101), local_fp_index={},
                                   default_door_id=1)
    factory.assert_not_called()


def test_a_targeted_member_sync_on_a_held_panel_is_deferred(sqlite_db):
    from app.core.device_sync import MEMBER_SYNC_DEFERRED
    from tests.test_account_pin_device_sites import _cache, _engine

    _cache(sqlite_db, _users(101))
    device_hold.hold(1)
    sdk = _sdk()
    engine = _engine()
    assert engine.sync_member_on_connected_sdk(sdk=sdk, device=_pullsdk_device(),
                                               member_id=101) is False
    assert engine._last_member_sync_outcome == MEMBER_SYNC_DEFERRED
    assert _written_pins(sdk) == []


def test_a_remote_reconcile_of_a_held_turnstile_is_refused(sqlite_db):
    from app.core.v2.commands import CommandRun
    from app.core.v2.handlers import CommandHandlers

    device_hold.hold(8)
    run = CommandRun(id="c1", type="DEVICE_RECONCILE", gym_device_id=8, payload=None,
                     deadline_mono=time.monotonic() + 20, claim_token="t" * 16)
    app = SimpleNamespace(_request_running_ultra_sync=MagicMock(), after=MagicMock())
    out = CommandHandlers(app).device_reconcile(run)
    assert out[:2] == ("FAILED", "DEVICE_ON_HOLD")
    app._request_running_ultra_sync.assert_not_called()


# ─────────────────────────── the driver surfaces ───────────────────────────

class _LowLevel:
    def __init__(self):
        self.count = 3
        self.rows = [{"Pin": "1"}]
        self.cleared: List[str] = []

    def get_device_data_count(self, *, table, filter_expr="", options=""):
        return self.count

    def get_device_data_rows(self, *, table, fields="*", **kw):
        if self.rows is None:
            from app.sdk.pullsdk import PullSDKError
            raise PullSDKError("GetDeviceData FAILED table=user rc=-2")
        return self.rows

    def clear_device_table(self, *, table):
        self.cleared.append(table)
        return 0


def _pullsdk_driver(low):
    from app.sdk.pullsdk import PullSDKDevice

    drv = PullSDKDevice({"id": 5, "ipAddress": "10.0.0.1"})
    drv._sdk = low
    drv._connected = True
    drv.ensure_connected = lambda: True
    return drv


def test_the_strict_panel_calls_raise_instead_of_reading_empty():
    from app.sdk.pullsdk import PullSDKError

    low = _LowLevel()
    drv = _pullsdk_driver(low)
    assert drv.count_table_strict(table="user") == 3
    low.count = -1
    with pytest.raises(PullSDKError):
        drv.count_table_strict(table="user")
    assert drv.read_table_strict(table="user") == [{"Pin": "1"}]
    low.rows = None
    with pytest.raises(PullSDKError):
        drv.read_table_strict(table="user")
    assert drv.read_table_rows(table="user") == [], "the old call still swallows it"
    drv.erase_table(table="userauthorize")
    assert low.cleared == ["userauthorize"]


def test_the_mb2000_listing_carries_the_privilege_and_templates_read_by_slot():
    from tests.test_erase_wizard import WizardTerminal
    from tests.test_standalone_incremental_sync import _make_driver

    term = WizardTerminal()
    term.add("1", "Admin", "", fingers=(0,), privilege=14)
    term.add("30001", "Ali", "111", fingers=(0, 3))
    drv = _make_driver(term)
    try:
        users = drv.list_device_users()
        got = drv.read_user_templates(["30001", "1"])
        bad = drv.read_user_templates(["30001", "abc"])
        status = drv.read_device_status()
    finally:
        drv.disconnect()
    assert {u["pin"]: u["privilege"] for u in users["users"]} == {"1": 14, "30001": 0}
    assert got["ok"] and [s["fingerId"] for s in got["templates"]["30001"]] == [0, 3]
    assert got["templates"]["1"] == [{"fingerId": 0, "template": "TPL1F0", "size": 8}]
    assert bad["ok"] is False
    assert status["ok"] and status["status"]["users"] == 2 and status["status"]["admins"] == 1


def test_an_unexpected_template_shape_fails_the_whole_read():
    from tests.test_erase_wizard import WizardTerminal
    from tests.test_standalone_incremental_sync import _make_driver

    term = WizardTerminal()
    term.add("30001", "Ali", "111", fingers=(0,))
    term.SSR_GetUserTmpStr = lambda *a: 42
    drv = _make_driver(term)
    try:
        got = drv.read_user_templates(["30001"])
    finally:
        drv.disconnect()
    assert got["ok"] is False and "unexpected shape" in got["error"]


def test_the_must_not_call_grep_still_counts_three():
    """zkemkeeper_guide §11: the wizard added no new delete call site to the driver."""
    import re
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "app" / "sdk" / "zk_standalone.py").read_text(
        encoding="utf-8")
    hits = re.findall(r"zk\.SSR_DeleteEnrollData|zk\.SSR_DelUserTmpExt", src)
    assert len(hits) == 3

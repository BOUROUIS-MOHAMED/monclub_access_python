"""Lane 1 item 1: the heartbeat's ``failedPins`` ("N waiting") is filled.

Before: ``access/pc_identity.py::build_heartbeat_payload`` forwarded ``failedPins`` from the
ULTRA worker snapshot (``failedPins`` / ``failed_pins``) and from the AGENT snapshot, but no
engine ever put the key there, so every turnstile reported 0 and the dashboard's
"not reachable since 14:02, 3 waiting" could never appear.

Now each ULTRA full pass counts, at its end, the pins of ITS desired roster that the
per-pin state does not show confirmed on the device with the desired content -- no row,
``last_ok=0``, or a stored hash that differs. That is exactly what the next pass will try
to write again: pins the terminal refused, pins in retry backoff, pins the per-pass cap or
a full terminal left for later. Rows of pins that are NOT in the roster (an old pin scheme's
rows after a switch, a departed member kept by a ceiling refusal) are not counted: nothing
will ever write them.

Real temp SQLite; the MB2000 through the real driver over the stateful fake terminal, the
C3 through the real DeviceSyncEngine over a MagicMock PullSDK. Nothing reaches a device.
"""
from __future__ import annotations

import queue
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import app.core.db as dbmod
import app.core.ultra_engine as ue
from app.sdk.pullsdk import PullSDKError
from tests.fake_terminal import TerminalZkem
from tests.test_account_pin_device_sites import (  # noqa: F401  (fixture)
    _engine, _member, _pullsdk_device, _sdk, sqlite_db,
)
from tests.test_standalone_incremental_sync import _make_driver, _user


class RefusingTerminal(TerminalZkem):
    """The fake MB2000, refusing ``SSR_SetUserInfo`` for the pins in ``refuse``."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.refuse: set = set()

    def SSR_SetUserInfo(self, machine, pin, name, pw, priv, enabled):
        if str(pin) in self.refuse:
            self._rec("SSR_SetUserInfo", machine, pin, name, pw, priv, enabled)
            return False
        return super().SSR_SetUserInfo(machine, pin, name, pw, priv, enabled)


def _members(n, first=30001):
    return [_user(first + i, f"M{i}", str(100 + i)) for i in range(n)]


def _standalone_worker(monkeypatch, drv, users):
    """A REAL UltraDeviceWorker (its own __init__), driving the fake MB2000."""
    w = ue.UltraDeviceWorker(device={"id": 9, "name": "Entree 1"}, settings={},
                             popup_q=queue.Queue(), history_q=queue.Queue(),
                             stop_event=threading.Event())
    w._sdk = drv
    w._connected = True
    w._on_full_sync_started = MagicMock()
    w._on_full_sync_finished = MagicMock()
    cache = SimpleNamespace(users=list(users), devices=[])
    monkeypatch.setattr(ue, "load_sync_cache", lambda: cache)
    monkeypatch.setattr(ue, "insert_push_batch", MagicMock(return_value=1))
    monkeypatch.setattr(ue, "update_push_batch", lambda **kw: None)
    import app.core.device_sync as ds
    monkeypatch.setattr(ds.DeviceSyncEngine, "_build_local_fp_index_for_pins",
                        lambda self, *, pins, fingerprint_enabled: {}, raising=True)
    return w, cache


def _pass(w):
    w.request_full_sync(reason="timer", fingerprint_hash="h")
    assert w._drain_full_sync_commands(limit=1) == 1


def _waiting(w):
    return w.get_snapshot()["failed_pins"]


# ═════════════════════════ MB2000 (ZK_STANDALONE) ═════════════════════════

class TestStandaloneWorker:

    def test_before_any_pass_the_count_is_unknown_not_zero(self, sqlite_db, monkeypatch):
        term = RefusingTerminal()
        drv = _make_driver(term)
        try:
            w, _ = _standalone_worker(monkeypatch, drv, _members(3))
            assert _waiting(w) is None
        finally:
            drv.disconnect()

    def test_pins_the_terminal_refused_are_waiting(self, sqlite_db, monkeypatch):
        term = RefusingTerminal()
        term.refuse = {"30002", "30004"}
        drv = _make_driver(term)
        try:
            w, _ = _standalone_worker(monkeypatch, drv, _members(5))
            _pass(w)
        finally:
            drv.disconnect()
        assert set(term.users) == {"30001", "30003", "30005"}
        assert _waiting(w) == 2

    def test_a_pass_that_confirms_every_pin_reports_zero(self, sqlite_db, monkeypatch):
        term = RefusingTerminal()
        drv = _make_driver(term)
        try:
            w, _ = _standalone_worker(monkeypatch, drv, _members(4))
            _pass(w)
        finally:
            drv.disconnect()
        assert _waiting(w) == 0

    def test_the_count_follows_the_next_pass(self, sqlite_db, monkeypatch):
        term = RefusingTerminal()
        term.refuse = {"30002"}
        drv = _make_driver(term)
        try:
            w, _ = _standalone_worker(monkeypatch, drv, _members(3))
            _pass(w)
            assert _waiting(w) == 1
            term.refuse = set()
            # The refused pin is in retry backoff after its first failure only when its
            # content was refused repeatedly; one failure is retried at once.
            _pass(w)
        finally:
            drv.disconnect()
        assert "30002" in term.users
        assert _waiting(w) == 0

    def test_pins_left_by_the_per_pass_cap_are_waiting(self, sqlite_db, monkeypatch):
        monkeypatch.setattr(ue, "_FULL_SYNC_MAX_PINS_PER_PASS", 3)
        term = RefusingTerminal()
        drv = _make_driver(term)
        try:
            w, _ = _standalone_worker(monkeypatch, drv, _members(5))
            _pass(w)
        finally:
            drv.disconnect()
        assert len(term.users) == 3
        assert _waiting(w) == 2, "the capped-out pins have no state row: still waiting"

    def test_a_pin_held_by_the_retry_backoff_is_waiting(self, sqlite_db, monkeypatch):
        term = RefusingTerminal()
        term.refuse = {"30002"}
        drv = _make_driver(term)
        import app.core.device_sync as ds
        try:
            w, _ = _standalone_worker(monkeypatch, drv, _members(3))
            _pass(w)
            # Same content, refused, not yet due: the next pass skips it (SYNC_RETRY_BACKOFF).
            monkeypatch.setattr(ds.DeviceSyncEngine, "_retry_due",
                                staticmethod(lambda **kw: False))
            _pass(w)
        finally:
            drv.disconnect()
        assert "30002" in getattr(w, "_last_backoff_pins", set()), "precondition: held back"
        assert _waiting(w) == 1

    def test_rows_outside_the_roster_are_never_counted(self, sqlite_db, monkeypatch):
        """After a pinScheme switch the old scheme's rows stay ``last_ok=0`` for good (the
        revoke pass aborts on the ceiling, so no prune). A raw ``last_ok=0`` count would
        read ~1,000 waiting at gym 45 forever; none of them will ever be written."""
        old = [str(40000 + i) for i in range(12)]
        for pin in old:
            sqlite_db.save_device_sync_state(device_id=9, pin=pin, desired_hash="h-old",
                                             ok=True, error=None)
        sqlite_db.clear_device_sync_hashes(device_id=9)          # what a switch does
        term = RefusingTerminal()
        for pin in old:
            term.add_user(pin, "Old", "1")
        drv = _make_driver(term)
        try:
            w, _ = _standalone_worker(monkeypatch, drv, _members(3))
            _pass(w)
        finally:
            drv.disconnect()
        state = sqlite_db.list_device_sync_hashes_and_status(device_id=9)
        assert all(pin in state and state[pin][1] is False for pin in old), (
            "precondition: the 12 old rows are still there, last_ok=0 (ceiling refused)")
        assert _waiting(w) == 0

    def test_a_pass_that_stops_before_its_roster_keeps_the_previous_count(
            self, sqlite_db, monkeypatch):
        term = RefusingTerminal()
        term.refuse = {"30002"}
        drv = _make_driver(term)
        try:
            w, _ = _standalone_worker(monkeypatch, drv, _members(3))
            _pass(w)
            assert _waiting(w) == 1
            monkeypatch.setattr(ue, "load_sync_cache", lambda: None)   # "no sync cache"
            _pass(w)
        finally:
            drv.disconnect()
        assert _waiting(w) == 1, "an early return is not a pass that found nothing waiting"


# ═════════════════════════ C3 (PullSDK, ULTRA) ═════════════════════════

def _users(*ams):
    return [_member(am, 9000 + am, None, f"M{am}", card=str(100000 + am)) for am in ams]


def _refusing_sdk(refuse_pins):
    sdk = _sdk()

    def _set(*, table, data, options=""):
        if table == "user" and any(f"Pin={p}\t" in data or data.startswith(f"Pin={p}")
                                   for p in refuse_pins):
            raise PullSDKError(f"SetDeviceData failed rc=-1 table={table}")
        return 0

    sdk.set_device_data.side_effect = _set
    return sdk


def _run_engine(users, device, sdk):
    engine = _engine()
    with patch("app.core.device_sync.PullSDK", MagicMock(return_value=sdk)):
        engine._sync_one_device(device=device, users=users, local_fp_index={},
                                default_door_id=1, changed_ids=None)
    return engine


class TestPullSdkPass:

    def test_a_pin_the_panel_refused_is_waiting(self, sqlite_db):
        engine = _run_engine(_users(101, 102, 103), _pullsdk_device(), _refusing_sdk({"102"}))
        assert engine._last_waiting_pins == 1

    def test_a_clean_pass_reports_zero(self, sqlite_db):
        engine = _run_engine(_users(101, 102, 103), _pullsdk_device(), _refusing_sdk(set()))
        assert engine._last_waiting_pins == 0

    def test_rows_outside_the_roster_are_never_counted(self, sqlite_db):
        old = [str(40000 + i) for i in range(12)]
        for pin in old:
            sqlite_db.save_device_sync_state(device_id=1, pin=pin, desired_hash="h-old",
                                             ok=True, error=None)
        sqlite_db.clear_device_sync_hashes(device_id=1)
        engine = _run_engine(_users(101, 102), _pullsdk_device(pinScheme="", pushingToDevicePolicy="1"),
                             _sdk(old + ["101"]))
        assert engine._last_waiting_pins == 0

    def test_a_pass_refused_before_its_roster_leaves_no_count(self, sqlite_db, monkeypatch):
        from app.core.v2 import lease_gate
        monkeypatch.setattr(lease_gate, "writes_frozen", lambda did: True)
        engine = _run_engine(_users(101), _pullsdk_device(), _sdk())
        assert engine._last_waiting_pins is None

    def test_the_worker_reports_what_its_pass_counted(self, sqlite_db, monkeypatch):
        device = _pullsdk_device(pinScheme="", pushingToDevicePolicy="1")
        w = ue.UltraDeviceWorker(device=device, settings={}, popup_q=queue.Queue(),
                                 history_q=queue.Queue(), stop_event=threading.Event())
        w._connected = True
        w._on_full_sync_finished = MagicMock()
        monkeypatch.setattr(ue, "load_sync_cache",
                            lambda: SimpleNamespace(users=_users(101, 102, 103), devices=[]))
        w._sdk = SimpleNamespace(owns_event_source=False, _sdk=_refusing_sdk({"102", "103"}))
        assert _waiting(w) is None
        _pass(w)
        assert _waiting(w) == 2


# ═════════════════════════ AGENT, and the heartbeat ═════════════════════════

def test_an_agent_device_has_nothing_waiting_by_construction():
    """No engine writes a PIN to an AGENT device: DeviceSyncEngine syncs DEVICE devices
    only and ULTRA drives ULTRA devices only (guide §3). So its count is a true 0."""
    from app.core.realtime_agent import AgentRealtimeEngine, DeviceStatus

    engine = AgentRealtimeEngine.__new__(AgentRealtimeEngine)
    engine._lock = threading.Lock()
    engine._statuses = {7: DeviceStatus(device_id=7, name="Agent door", enabled=True, connected=True)}
    assert engine.get_status_snapshot()[7]["failedPins"] == 0


def test_the_heartbeat_forwards_the_ultra_count(sqlite_db, monkeypatch):
    from access.pc_identity import build_heartbeat_payload

    class _Ultra:
        def get_status(self):
            return {"running": True, "devices": {"9": {"connected": False, "failed_pins": 3}}}

    app = SimpleNamespace(_ultra_engine=_Ultra(),
                          _agent_engine=SimpleNamespace(get_status_snapshot=lambda: {}))
    monkeypatch.setattr(dbmod, "peek_sync_cache", lambda: None, raising=False)
    payload = build_heartbeat_payload(app)
    [line] = [t for t in payload["turnstiles"] if t["gymDeviceId"] == 9]
    assert line["failedPins"] == 3 and line["reachable"] is False

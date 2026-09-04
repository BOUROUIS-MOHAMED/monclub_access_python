"""Session B (2026-09-04): the door command on the ZK_STANDALONE family.

Proves the whole chain with a fake COM object -- nothing here talks to an MB2000:

    POST /api/v2/devices/{id}/door/open
      -> _handle_device_door_open (local_access_api_v2)
      -> UltraDeviceWorker.request_door_open / _drain_commands  (command queue)
      -> ZKStandaloneDevice.open_door                            (STA command)
      -> _do_open_door -> zk.ACUnlock(1, delay_ds)

plus the persisted per-device switch (env > local > family default), the
decisecond clamp, DOOR_OPEN telemetry results, the STA generation fence, and a
regression pin on the PullSDK door path (which this session must not touch).

Every test that can reach app.core.db patches _DB_PATH to a temp file (hard rule:
otherwise tests hit the real C:\\ProgramData\\MonClub Access\\access\\access.db).
"""
from __future__ import annotations

import inspect
import queue
import threading
import time
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

from app.sdk import zk_standalone as zs
from app.sdk.zk_standalone import ZKStandaloneDevice


# --------------------------------------------------------------------------- #
# Fake zkemkeeper COM object (door-focused; same shape as test_zk_standalone_driver)
# --------------------------------------------------------------------------- #

class FakeZkem:
    def __init__(self):
        self.calls: List[tuple] = []
        self.connect_ok = True
        self.unlock_ok = True
        self.unlock_raise: Optional[BaseException] = None
        # When set, ACUnlock blocks until the event is set -- simulates the
        # zkemkeeper "call never returns" wedge on the STA thread.
        self.unlock_block: Optional[threading.Event] = None
        self.unlock_started = threading.Event()

    def _rec(self, name, *args):
        self.calls.append((name, *args))

    def SetCommPassword(self, key):
        self._rec("SetCommPassword", key); return True

    def Connect_Net(self, ip, port):
        self._rec("Connect_Net", ip, port); return self.connect_ok

    def RegEvent(self, machine, mask):
        self._rec("RegEvent", machine, mask); return True

    def Disconnect(self):
        self._rec("Disconnect")

    def ReadRTLog(self, machine):
        return False

    def GetRTLog(self, machine):
        return False

    def ACUnlock(self, machine, delay):
        self._rec("ACUnlock", machine, delay)
        self.unlock_started.set()
        if self.unlock_block is not None:
            self.unlock_block.wait()
        if self.unlock_raise is not None:
            raise self.unlock_raise
        return self.unlock_ok

    def unlocks(self) -> List[tuple]:
        return [c for c in self.calls if c[0] == "ACUnlock"]


def _make_driver(payload_extra: Dict[str, Any] | None = None,
                 fake: FakeZkem | None = None) -> tuple[ZKStandaloneDevice, FakeZkem]:
    payload = {
        "id": 8, "name": "Sortie", "ipAddress": "192.168.1.247", "portNumber": 4370,
        "deviceProtocol": "ZK_STANDALONE",
        "doorPresets": [{"doorNumber": 1, "direction": "OUT"}],
    }
    payload.update(payload_extra or {})
    drv = ZKStandaloneDevice(payload, logger=MagicMock())
    zk = fake or FakeZkem()
    drv._com_factory = lambda: zk
    drv._co_init = lambda: None
    drv._co_uninit = lambda: None
    drv._pump = lambda: None
    drv._refresh_pin_card_map = lambda: None  # type: ignore[method-assign]  # no sqlite in unit tests
    return drv, zk


def _tel_calls(tel: MagicMock, name: str) -> List[Dict[str, Any]]:
    """Telemetry lines named *name*, in chronological order across event()/warn()."""
    out: List[Dict[str, Any]] = []
    for meth, args, kwargs in tel.mock_calls:
        if meth in ("event", "warn") and args and args[0] == name:
            out.append(dict(kwargs))
    return out


@pytest.fixture(autouse=True)
def _no_env_override(monkeypatch):
    monkeypatch.delenv(zs._OPEN_DOOR_ENV_VAR, raising=False)


@pytest.fixture
def tel(monkeypatch):
    fake = MagicMock()
    monkeypatch.setattr(zs, "_tel", fake)
    return fake


# --------------------------------------------------------------------------- #
# 1. Switch resolution: env override > persisted local switch > family default
# --------------------------------------------------------------------------- #

class TestOpenDoorSwitchResolution:
    def test_family_default_is_on_by_operator_decision(self):
        assert zs._OPEN_DOOR_FAMILY_DEFAULT is True
        assert zs.resolve_open_door_switch(8, {}) == (True, "default")
        assert zs.resolve_open_door_switch(8, {"openDoorEnabled": None}) == (True, "default")

    def test_local_switch_off_and_on(self):
        assert zs.resolve_open_door_switch(8, {"openDoorEnabled": False}) == (False, "local")
        assert zs.resolve_open_door_switch(8, {"openDoorEnabled": True}) == (True, "local")
        # stored as 0/1 integers or strings by SQLite / JSON, still understood
        assert zs.resolve_open_door_switch(8, {"openDoorEnabled": 0}) == (False, "local")
        assert zs.resolve_open_door_switch(8, {"openDoorEnabled": "false"}) == (False, "local")

    def test_env_forces_off_over_local_on(self, monkeypatch):
        for val in ("0", "false", "no", "off", "none"):
            monkeypatch.setenv(zs._OPEN_DOOR_ENV_VAR, val)
            assert zs._open_door_env_override(8) is False, val
            assert zs.resolve_open_door_switch(8, {"openDoorEnabled": True}) == (False, "env"), val

    def test_env_forces_on_over_local_off(self, monkeypatch):
        for val in ("1", "true", "yes", "on", "all"):
            monkeypatch.setenv(zs._OPEN_DOOR_ENV_VAR, val)
            assert zs._open_door_env_override(8) is True, val
            assert zs.resolve_open_door_switch(8, {"openDoorEnabled": False}) == (True, "env"), val

    def test_env_id_list_is_an_allowlist(self, monkeypatch):
        monkeypatch.setenv(zs._OPEN_DOOR_ENV_VAR, "8,12")
        assert zs.resolve_open_door_switch(8, {"openDoorEnabled": False}) == (True, "env")
        assert zs.resolve_open_door_switch(12, {}) == (True, "env")
        assert zs.resolve_open_door_switch(9, {"openDoorEnabled": True}) == (False, "env")

    def test_unset_or_blank_env_is_no_override(self, monkeypatch):
        assert zs._open_door_env_override(8) is None
        monkeypatch.setenv(zs._OPEN_DOOR_ENV_VAR, "   ")
        assert zs._open_door_env_override(8) is None

    def test_garbage_env_is_ignored_not_interpreted(self, monkeypatch):
        monkeypatch.setenv(zs._OPEN_DOOR_ENV_VAR, "nope")
        assert zs._open_door_env_override(8) is None
        assert zs.resolve_open_door_switch(8, {"openDoorEnabled": False}) == (False, "local")
        assert zs.resolve_open_door_switch(8, {}) == (True, "default")

    def test_driver_reads_switch_from_payload_and_logs_it(self, tel):
        drv, _ = _make_driver()
        assert drv.supports_open_door is True
        assert drv._open_door_source == "default"
        drv2, _ = _make_driver({"openDoorEnabled": False})
        assert drv2.supports_open_door is False
        assert drv2._open_door_source == "local"
        # effective value is announced at construction (= worker connect) as telemetry
        sw = _tel_calls(tel, "DOOR_OPEN_SWITCH")
        assert [(s["enabled"], s["source"]) for s in sw] == [(True, "default"), (False, "local")]
        assert all(s["worker"] == "ZKEM:8" for s in sw)

    def test_env_beats_payload_at_construction(self, monkeypatch):
        monkeypatch.setenv(zs._OPEN_DOOR_ENV_VAR, "off")
        drv, _ = _make_driver({"openDoorEnabled": True})
        assert drv.supports_open_door is False and drv._open_door_source == "env"

    def test_live_apply_flips_without_reconnect(self, tel):
        drv, zk = _make_driver()
        assert drv.connect() is True
        try:
            assert drv.apply_open_door_switch(False) == (False, "local")
            assert drv.open_door(door_id=1, pulse_time_ms=3000) is False
            assert zk.unlocks() == []
            assert drv.apply_open_door_switch(None) == (True, "default")
            assert drv.open_door(door_id=1, pulse_time_ms=3000) is True
            assert zk.unlocks() == [("ACUnlock", 1, 30)]
        finally:
            drv.disconnect()


# --------------------------------------------------------------------------- #
# 2. Driver: STA -> ACUnlock(machine=1, deciseconds), results, clamp, fence
# --------------------------------------------------------------------------- #

class TestDriverDoorCommand:
    def test_open_issues_acunlock_with_machine_1_and_deciseconds(self, tel):
        drv, zk = _make_driver()
        drv.connect()
        try:
            assert drv.open_door(door_id=1, pulse_time_ms=3000) is True
            assert zk.unlocks() == [("ACUnlock", 1, 30)]
            ev = _tel_calls(tel, "DOOR_OPEN")
            assert len(ev) == 1
            assert ev[0]["result"] == "ok"
            assert ev[0]["delay_ds"] == 30
            assert ev[0]["worker"] == "ZKEM:8"
            assert isinstance(ev[0]["dur_ms"], (int, float)) and ev[0]["dur_ms"] >= 0
            assert ev[0].get("clamped") in (None, False)
        finally:
            drv.disconnect()

    def test_false_return_is_reported_not_swallowed(self, tel):
        zk = FakeZkem(); zk.unlock_ok = False
        drv, _ = _make_driver(fake=zk)
        drv.connect()
        try:
            assert drv.open_door(door_id=1, pulse_time_ms=1000) is False
            assert zk.unlocks() == [("ACUnlock", 1, 10)]
            ev = _tel_calls(tel, "DOOR_OPEN")
            assert [e["result"] for e in ev] == ["false"]
            assert ev[0]["delay_ds"] == 10 and "dur_ms" in ev[0]
            # loud: a WARNING naming ACUnlock, not a silent False
            assert any("ACUnlock" in str(c.args[0]) for c in drv.logger.warning.call_args_list)
        finally:
            drv.disconnect()

    def test_com_exception_is_reported_as_exception(self, tel):
        zk = FakeZkem(); zk.unlock_raise = RuntimeError("COM boom")
        drv, _ = _make_driver(fake=zk)
        drv.connect()
        try:
            assert drv.open_door(door_id=1, pulse_time_ms=1000) is False
            ev = _tel_calls(tel, "DOOR_OPEN")
            assert [e["result"] for e in ev] == ["exception"]
            assert ev[0]["err"] == "RuntimeError"
        finally:
            drv.disconnect()

    def test_switch_off_is_unsupported_and_never_touches_com(self, tel):
        drv, zk = _make_driver({"openDoorEnabled": False})
        drv.connect()
        try:
            assert drv.open_door(door_id=1, pulse_time_ms=3000) is False
            assert zk.unlocks() == []
            ev = _tel_calls(tel, "DOOR_OPEN")
            assert [e["result"] for e in ev] == ["unsupported"]
            assert ev[0]["delay_ds"] == 30 and ev[0]["source"] == "local"
        finally:
            drv.disconnect()

    def test_results_vocabulary_is_closed(self):
        assert zs._DOOR_OPEN_RESULTS == frozenset({"ok", "false", "exception", "timeout", "unsupported"})

    @pytest.mark.parametrize("pulse_ms,expect_ds,clamped", [
        (3000, 30, False),
        (3500, 35, False),
        (1000, 10, False),
        (60000, 600, False),   # the local API's 60 s ceiling == 600 ds, unclamped
        (90000, 600, True),    # above the ceiling -> clamped + logged
        (0, 1, True),          # below 1 ds -> 1 ds (ACUnlock(..., 0) is not a pulse)
        (40, 1, True),
    ])
    def test_decisecond_conversion_and_clamp(self, tel, pulse_ms, expect_ds, clamped):
        assert zs._pulse_ms_to_delay_ds(pulse_ms) == (expect_ds, clamped)
        drv, zk = _make_driver()
        drv.connect()
        try:
            assert drv.open_door(door_id=1, pulse_time_ms=pulse_ms) is True
            assert zk.unlocks() == [("ACUnlock", 1, expect_ds)]
            ev = _tel_calls(tel, "DOOR_OPEN")[0]
            assert ev["delay_ds"] == expect_ds
            assert bool(ev.get("clamped")) is clamped
            warned = any("clamp" in str(c.args[0]).lower() for c in drv.logger.warning.call_args_list)
            assert warned is clamped
        finally:
            drv.disconnect()

    def test_clamp_bounds_are_the_app_ceiling_not_an_invented_sdk_max(self):
        # 1..600 ds == 0.1..60 s: the same 1-60 s ceiling the local API applies to
        # pulseSeconds and PullSDKDevice applies to seconds. The firmware's own
        # maximum is UNKNOWN -- see zkemkeeper_guide.md section 4 Door.
        assert (zs._ACUNLOCK_DELAY_DS_MIN, zs._ACUNLOCK_DELAY_DS_MAX) == (1, 600)

    def test_wedged_acunlock_times_out_abandons_sta_and_reports_timeout(self, tel):
        """The door command must NOT bypass the generation fence: a COM call that
        never returns is abandoned exactly like any other STA command."""
        zk = FakeZkem(); zk.unlock_block = threading.Event()
        drv, _ = _make_driver(fake=zk)
        assert drv.connect() is True
        old_thread = drv._sta_thread
        gen0 = drv._sta_gen
        try:
            t0 = time.monotonic()
            assert drv.open_door(door_id=1, pulse_time_ms=1000, timeout_ms=2000) is False
            assert 1.5 <= (time.monotonic() - t0) < 6.0
            assert zk.unlock_started.is_set(), "ACUnlock was actually entered on the STA thread"
            # fence: generation bumped, thread reference dropped, flag cleared
            assert drv._sta_gen == gen0 + 1
            assert drv._sta_thread is None
            assert drv.is_connected is False
            ev = _tel_calls(tel, "DOOR_OPEN")
            assert [e["result"] for e in ev] == ["timeout"]
            assert ev[0]["delay_ds"] == 10 and ev[0]["dur_ms"] >= 1500
            wedged = _tel_calls(tel, "ZKEM_STA_WEDGED")
            assert len(wedged) == 1 and "open_door" in wedged[0]["reason"]
        finally:
            zk.unlock_block.set()
            deadline = time.monotonic() + 3.0
            while old_thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.02)
            drv.disconnect()
        assert not old_thread.is_alive(), "the superseded thread exits once the call returns"

    def test_recovery_after_wedge_is_serviced_by_the_new_thread(self, tel):
        zk = FakeZkem(); zk.unlock_block = threading.Event()
        drv, _ = _make_driver(fake=zk)
        assert drv.connect() is True
        try:
            assert drv.open_door(door_id=1, pulse_time_ms=1000, timeout_ms=2000) is False  # wedge
            blocked = zk.unlock_block
            zk.unlock_block = None          # terminal answers again
            blocked.set()                   # let the zombie thread finish and exit
            assert drv.connect() is True     # rebuild behind the fence
            assert drv.is_connected is True
            assert drv.open_door(door_id=1, pulse_time_ms=1000) is True
            assert [e["result"] for e in _tel_calls(tel, "DOOR_OPEN")] == ["timeout", "ok"]
        finally:
            zk.unlock_block = None
            drv.disconnect()

    def test_not_connected_returns_false_without_com(self, tel):
        zk = FakeZkem(); zk.connect_ok = False
        drv, _ = _make_driver(fake=zk)
        assert drv.connect() is False
        try:
            assert drv.open_door(door_id=1, pulse_time_ms=1000) is False
            assert zk.unlocks() == []
            assert [e["result"] for e in _tel_calls(tel, "DOOR_OPEN")] == ["false"]
        finally:
            drv.disconnect()


# --------------------------------------------------------------------------- #
# 3. Worker: command queue + _open_door_with_retry on a standalone driver
# --------------------------------------------------------------------------- #

def _make_worker(driver, settings: Dict[str, Any] | None = None):
    import app.core.ultra_engine as ue

    w = ue.UltraDeviceWorker.__new__(ue.UltraDeviceWorker)
    w._device = {"id": 8, "name": "Sortie", "ipAddress": "192.168.1.247", "portNumber": 4370,
                 "deviceProtocol": "ZK_STANDALONE", "accessDataMode": "ULTRA"}
    w._device_id = 8
    w._device_name = "Sortie"
    w._settings = settings if settings is not None else {"door_entry_id": 1, "pulse_time_ms": 3000}
    w._cfg = None
    w._prefix = "[ULTRA:8]"
    w._tel_wid = "ULTRA:8"
    w._sdk = driver
    w._connected = True
    w._cmd_queue = queue.Queue(maxsize=10)
    w._sdk_cmd_queue = queue.Queue(maxsize=8)
    w._wake_evt = threading.Event()
    w._door_cmd_failures = 0
    w._down_for_seconds = lambda: 0.0  # type: ignore[method-assign]
    w._last_connect_error = ""
    return w


def _drain_in_background(worker) -> threading.Thread:
    def _run():
        worker._wake_evt.wait(timeout=3.0)
        worker._drain_commands()
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


class TestWorkerChain:
    def test_open_door_with_retry_issues_one_acunlock_on_success(self):
        drv, zk = _make_driver()
        drv.connect()
        w = _make_worker(drv)
        try:
            assert w._open_door_with_retry(door_id=1) is True
            assert zk.unlocks() == [("ACUnlock", 1, 30)]   # pulse_time_ms=3000 -> 30 ds
        finally:
            drv.disconnect()

    def test_open_door_with_retry_uses_door_preset_pulse(self):
        drv, zk = _make_driver()
        drv.connect()
        w = _make_worker(drv, settings={
            "door_entry_id": 1, "pulse_time_ms": 3000,
            "door_presets": [{"doorNumber": 1, "pulseSeconds": 5}],
        })
        try:
            assert w._open_door_with_retry(door_id=1) is True
            assert zk.unlocks() == [("ACUnlock", 1, 50)]
        finally:
            drv.disconnect()

    def test_open_door_with_retry_retries_once_on_false(self):
        zk = FakeZkem(); zk.unlock_ok = False
        drv, _ = _make_driver(fake=zk)
        drv.connect()
        w = _make_worker(drv)
        try:
            assert w._open_door_with_retry(door_id=1) is False
            assert zk.unlocks() == [("ACUnlock", 1, 30), ("ACUnlock", 1, 30)]
        finally:
            drv.disconnect()

    def test_open_door_with_retry_refused_by_switch_never_touches_com(self):
        drv, zk = _make_driver({"openDoorEnabled": False})
        drv.connect()
        w = _make_worker(drv)
        try:
            assert w._open_door_with_retry(door_id=1) is False
            assert zk.unlocks() == []
        finally:
            drv.disconnect()

    def test_command_queue_drains_to_acunlock(self):
        drv, zk = _make_driver()
        drv.connect()
        w = _make_worker(drv)
        try:
            _drain_in_background(w)
            res = w.request_door_open(door_id=1, pulse_ms=1500, timeout=3.0)
            assert res == {"ok": True, "error": ""}
            assert zk.unlocks() == [("ACUnlock", 1, 15)]
        finally:
            drv.disconnect()

    def test_command_queue_reports_false(self):
        zk = FakeZkem(); zk.unlock_ok = False
        drv, _ = _make_driver(fake=zk)
        drv.connect()
        w = _make_worker(drv)
        try:
            _drain_in_background(w)
            res = w.request_door_open(door_id=1, pulse_ms=3000, timeout=3.0)
            assert res == {"ok": False, "error": "open_door returned False"}
        finally:
            drv.disconnect()


# --------------------------------------------------------------------------- #
# 4. Local API: /door/open end to end + the switch endpoints
# --------------------------------------------------------------------------- #

class _FakeCtx:
    def __init__(self, params: Dict[str, str] | None = None, body: Dict[str, Any] | None = None, app=None):
        self.params = params or {}
        self._body = body or {}
        self.app = app
        self.sent: Optional[tuple] = None

    def param_int(self, name: str, default: int = 0) -> int:
        try:
            return int(self.params.get(name, default))
        except Exception:
            return default

    def body(self) -> Dict[str, Any]:
        return self._body

    def send_json(self, status: int, payload: Any) -> None:
        self.sent = (status, payload)


class _FakeApp:
    def __init__(self, ultra=None, agent=None):
        self._ultra_engine = ultra
        self._agent_engine = agent


class _FakeUltra:
    def __init__(self, workers: Dict[int, Any]):
        self.running = True
        self._workers = workers


@pytest.fixture
def v2(monkeypatch):
    from app.api import local_access_api_v2 as mod
    monkeypatch.setattr(mod, "_tel", MagicMock())
    mod._door_open_last.clear()
    return mod


def _post_door_open(v2, worker, did=8, body=None):
    ctx = _FakeCtx(params={"deviceId": str(did)}, body=body or {"doorNumber": 1, "pulseSeconds": 3},
                   app=_FakeApp(ultra=_FakeUltra({did: worker})))
    v2._handle_device_door_open(ctx)
    return ctx.sent


class TestLocalApiDoorOpenChain:
    def test_http_to_acunlock(self, v2):
        drv, zk = _make_driver()
        drv.connect()
        w = _make_worker(drv)
        try:
            _drain_in_background(w)
            status, payload = _post_door_open(v2, w)
            assert status == 200 and payload["ok"] is True and payload["source"] == "ultra"
            assert zk.unlocks() == [("ACUnlock", 1, 30)]
            api_ev = _tel_calls(v2._tel, "DOOR_OPEN")
            assert [e["result"] for e in api_ev] == ["200_ok"]
            assert api_ev[0]["device_id"] == 8
        finally:
            drv.disconnect()

    def test_pulse_seconds_clamped_to_60_reaches_600_ds(self, v2):
        drv, zk = _make_driver()
        drv.connect()
        w = _make_worker(drv)
        try:
            _drain_in_background(w)
            status, _ = _post_door_open(v2, w, body={"doorNumber": 1, "pulseSeconds": 120})
            assert status == 200
            assert zk.unlocks() == [("ACUnlock", 1, 600)]
        finally:
            drv.disconnect()

    def test_409_only_when_switch_is_off(self, v2):
        drv, zk = _make_driver({"openDoorEnabled": False})
        drv.connect()
        w = _make_worker(drv)
        try:
            status, payload = _post_door_open(v2, w)
            assert status == 409
            assert payload["unsupported"] is True
            assert "désactivée" in payload["error"]
            assert payload["source"] == "local"
            assert zk.unlocks() == []
            assert [e["result"] for e in _tel_calls(v2._tel, "DOOR_OPEN")] == ["409_unsupported"]
        finally:
            drv.disconnect()

    def test_false_return_is_a_french_500_with_the_raw_detail(self, v2):
        zk = FakeZkem(); zk.unlock_ok = False
        drv, _ = _make_driver(fake=zk)
        drv.connect()
        w = _make_worker(drv)
        try:
            _drain_in_background(w)
            status, payload = _post_door_open(v2, w)
            assert status == 500 and payload["ok"] is False
            assert "refusé" in payload["error"] and "FALSE" in payload["error"]
            assert payload["detail"] == "open_door returned False"
            assert zk.unlocks() == [("ACUnlock", 1, 30)]
            ev = _tel_calls(v2._tel, "DOOR_OPEN")
            assert [e["result"] for e in ev] == ["500_failed"]
        finally:
            drv.disconnect()

    def test_cooldown_429(self, v2):
        drv, zk = _make_driver()
        drv.connect()
        w = _make_worker(drv)
        try:
            _drain_in_background(w)
            assert _post_door_open(v2, w)[0] == 200
            status, payload = _post_door_open(v2, w)
            assert status == 429 and payload["ok"] is False
            assert zk.unlocks() == [("ACUnlock", 1, 30)]  # second press never reached COM
            assert [e["result"] for e in _tel_calls(v2._tel, "DOOR_OPEN")] == ["200_ok", "429_cooldown"]
        finally:
            drv.disconnect()

    def test_worker_timeout_is_503(self, v2):
        drv, zk = _make_driver()
        drv.connect()
        w = _make_worker(drv)
        try:
            # nobody drains -> request_door_open times out (2 s) -> 503, no COM call
            status, payload = _post_door_open(v2, w)
            assert status == 503 and payload["ok"] is False
            assert zk.unlocks() == []
            assert [e["result"] for e in _tel_calls(v2._tel, "DOOR_OPEN")] == ["503_timeout"]
        finally:
            drv.disconnect()

    def test_french_error_mapping(self, v2):
        assert "FALSE" in v2._door_open_error_fr("open_door returned False")
        assert "connecté" in v2._door_open_error_fr("not connected")
        assert v2._door_open_error_fr("weird").startswith("échec de l'ouverture de porte")


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "force_open.db"), raising=False)
    db_module.init_db()
    return db_module


def _ingest(db, device):
    with db.get_conn() as conn:
        cur = conn.cursor()
        db._insert_device_row(cur, device)
        conn.commit()


class TestLocalApiOpenDoorSwitch:
    def _ctx(self, did=8, body=None, workers=None):
        return _FakeCtx(params={"deviceId": str(did)}, body=body or {},
                        app=_FakeApp(ultra=_FakeUltra(workers or {})))

    def test_get_default_state_standalone(self, v2, db, monkeypatch):
        monkeypatch.setattr(v2, "_device_protocol_of", lambda did: "ZK_STANDALONE")
        ctx = self._ctx()
        v2._handle_device_open_door_switch_get(ctx)
        status, p = ctx.sent
        assert status == 200
        assert p["enabled"] is True and p["source"] == "default"
        assert p["local"] is None and p["envOverride"] is None
        assert p["hardwareVerified"] is False
        assert p["live"] is None  # no worker/driver yet

    def test_get_refuses_pullsdk_family(self, v2, db, monkeypatch):
        monkeypatch.setattr(v2, "_device_protocol_of", lambda did: "ZK_PULLSDK")
        ctx = self._ctx()
        v2._handle_device_open_door_switch_get(ctx)
        status, p = ctx.sent
        assert status == 409 and p["unsupported"] is True and p["protocol"] == "ZK_PULLSDK"
        ctx2 = self._ctx(body={"enabled": False})
        v2._handle_device_open_door_switch_set(ctx2)
        assert ctx2.sent[0] == 409

    def test_set_persists_and_applies_live(self, v2, db, monkeypatch):
        monkeypatch.setattr(v2, "_device_protocol_of", lambda did: "ZK_STANDALONE")
        drv, zk = _make_driver()
        drv.connect()
        w = _make_worker(drv)
        try:
            ctx = self._ctx(body={"enabled": False}, workers={8: w})
            v2._handle_device_open_door_switch_set(ctx)
            status, p = ctx.sent
            assert status == 200 and p["applied"] is True
            assert p["enabled"] is False and p["source"] == "local" and p["local"] is False
            assert p["live"] is False
            # persisted
            assert db.get_device_open_door_switch(8) is False
            # live driver refuses, worker snapshot carries it for the next reconnect
            assert drv.supports_open_door is False
            assert w._device["openDoorEnabled"] is False
            status, dp = _post_door_open(v2, w)
            assert status == 409 and zk.unlocks() == []
            # back to family default
            ctx = self._ctx(body={"enabled": None}, workers={8: w})
            v2._handle_device_open_door_switch_set(ctx)
            assert ctx.sent[1]["enabled"] is True and ctx.sent[1]["source"] == "default"
            assert db.get_device_open_door_switch(8) is None
            assert drv.supports_open_door is True
            sw = _tel_calls(v2._tel, "DOOR_OPEN_SWITCH")
            assert [(s["enabled"], s["by"]) for s in sw] == [(False, "operator"), (True, "operator")]
        finally:
            drv.disconnect()

    def test_env_override_wins_and_is_reported(self, v2, db, monkeypatch):
        monkeypatch.setattr(v2, "_device_protocol_of", lambda did: "ZK_STANDALONE")
        monkeypatch.setenv(zs._OPEN_DOOR_ENV_VAR, "off")
        ctx = self._ctx(body={"enabled": True})
        v2._handle_device_open_door_switch_set(ctx)
        status, p = ctx.sent
        assert status == 200
        assert p["local"] is True and db.get_device_open_door_switch(8) is True
        assert p["enabled"] is False and p["source"] == "env" and p["envOverride"] is False

    def test_invalid_device_id(self, v2, db):
        ctx = self._ctx(did=0)
        v2._handle_device_open_door_switch_get(ctx)
        assert ctx.sent[0] == 400


# --------------------------------------------------------------------------- #
# 5. Persistence + projection into the device payload
# --------------------------------------------------------------------------- #

class TestDeviceLocalSwitchStorage:
    def test_round_trip(self, db):
        assert db.get_device_open_door_switch(8) is None
        db.set_device_open_door_switch(8, False)
        assert db.get_device_open_door_switch(8) is False
        db.set_device_open_door_switch(8, True)
        assert db.get_device_open_door_switch(8) is True
        db.set_device_open_door_switch(8, None)
        assert db.get_device_open_door_switch(8) is None

    def test_projection_carries_open_door_enabled(self, db):
        _ingest(db, {"id": 8, "name": "Sortie", "ipAddress": "192.168.1.247", "portNumber": 4370,
                     "accessDataMode": "ULTRA", "deviceProtocol": "ZK_STANDALONE"})
        payload = db.list_sync_devices_payload()
        assert len(payload) == 1 and payload[0]["openDoorEnabled"] is None
        db.set_device_open_door_switch(8, False)
        assert db.list_sync_devices_payload()[0]["openDoorEnabled"] is False
        assert db.get_sync_device_payload(8)["openDoorEnabled"] is False
        # the driver built from that projection is switched off
        drv, zk = _make_driver(db.get_sync_device_payload(8))
        assert drv.supports_open_door is False and drv._open_door_source == "local"

    def test_local_switch_survives_a_sync_cache_replace(self, db):
        """sync_* tables are replaced on every full sync/logout; the operator's
        local switch lives in device_local_settings and must not be wiped."""
        _ingest(db, {"id": 8, "name": "Sortie", "ipAddress": "192.168.1.247", "portNumber": 4370,
                     "accessDataMode": "ULTRA", "deviceProtocol": "ZK_STANDALONE"})
        db.set_device_open_door_switch(8, False)
        with db.get_conn() as conn:
            conn.execute("DELETE FROM sync_devices")
            conn.commit()
        assert db.get_device_open_door_switch(8) is False


# --------------------------------------------------------------------------- #
# 6. Regression: the PullSDK door path is untouched
# --------------------------------------------------------------------------- #

class _FakeLowLevelPullSDK:
    def __init__(self):
        self.calls: List[tuple] = []

    def supports_set_device_param(self):
        return True

    def set_device_param(self, *, items):
        self.calls.append(("set_device_param", items))

    def door_pulse_open(self, *, door, seconds):
        self.calls.append(("door_pulse_open", door, seconds))
        return 0

    def disconnect(self):
        self.calls.append(("disconnect",))


def _pull_device():
    from app.sdk.pullsdk import PullSDKDevice
    dev = PullSDKDevice({"id": 3, "name": "Entree", "ipAddress": "192.168.1.201", "portNumber": 4370},
                        logger=MagicMock())
    dev._sdk = _FakeLowLevelPullSDK()
    dev._connected = True
    return dev


class TestPullSdkDoorPathUnchanged:
    def test_pullsdk_device_open_door_sequence(self):
        dev = _pull_device()
        assert dev.open_door(door_id=2, pulse_time_ms=3000) is True
        assert dev._sdk.calls == [("set_device_param", "Door2Drivertime=3"), ("door_pulse_open", 2, 3)]
        # drive-time is set once per connection; ceil(ms/1000) clamped 1..60
        assert dev.open_door(door_id=2, pulse_time_ms=3000) is True
        assert dev._sdk.calls[2:] == [("door_pulse_open", 2, 3)]
        assert dev.open_door(door_id=1, pulse_time_ms=3500) is True
        assert dev._sdk.calls[3:] == [("set_device_param", "Door1Drivertime=4"), ("door_pulse_open", 1, 4)]

    def test_pullsdk_device_not_connected_is_false_without_calls(self, monkeypatch):
        dev = _pull_device()
        dev._connected = False
        monkeypatch.setattr(dev, "connect", lambda: False)
        assert dev.open_door(door_id=1, pulse_time_ms=3000) is False
        assert dev._sdk.calls == []

    def test_pullsdk_has_no_open_door_flag_and_no_acunlock(self):
        import app.sdk.pullsdk as pullsdk
        from app.sdk.pullsdk import PullSDKDevice
        assert not hasattr(PullSDKDevice, "supports_open_door")  # callers default True
        src = inspect.getsource(pullsdk)
        # (pullsdk.py mentions zk_standalone.py in a capability-flag comment; the
        # pin is on the door mechanism itself, not on that cross-reference.)
        assert "ACUnlock" not in src and "openDoorEnabled" not in src
        assert "resolve_open_door_switch" not in src

    def test_local_api_ultra_path_with_pullsdk_driver_still_pulses(self, v2):
        dev = _pull_device()
        w = _make_worker(dev)
        _drain_in_background(w)
        status, payload = _post_door_open(v2, w, did=3)
        assert status == 200 and payload["source"] == "ultra"
        assert ("door_pulse_open", 1, 3) in dev._sdk.calls

    def test_local_api_fallback_direct_pullsdk_pulse(self, v2, monkeypatch):
        sdk = _FakeLowLevelPullSDK()
        monkeypatch.setattr(v2, "_connect_device", lambda ctx, did: (sdk, None))
        ctx = _FakeCtx(params={"deviceId": "3"}, body={"doorNumber": 2, "pulseSeconds": 4},
                       app=_FakeApp(ultra=None, agent=None))
        v2._handle_device_door_open(ctx)
        status, payload = ctx.sent
        assert status == 200 and payload["ok"] is True
        assert sdk.calls == [("door_pulse_open", 2, 4), ("disconnect",)]

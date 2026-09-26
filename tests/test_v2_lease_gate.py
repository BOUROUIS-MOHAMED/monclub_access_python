"""P3b-2 step 2: the lease gate, and the guard that a READER never touches a turnstile.

Owner decision 1: one driver PC per turnstile; readers NEVER connect to any turnstile.
Owner decision 4: a gym with no lease keeps today's behaviour (every PC drives every turnstile).

The guard tests make every way of building a device driver raise, install a READER snapshot,
and drive every place that selects devices or connects to one: the ULTRA list the app starts,
UltraEngine.start/refresh_devices, the ULTRA worker's connect, the AGENT engine, the DEVICE-mode
push engine, the DEVICE-mode attendance reader, and every local API handler that opens a device
session. Nothing may construct a driver.
"""
from __future__ import annotations

import logging
import queue
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.core.v2 import lease_gate as lg


@pytest.fixture(autouse=True)
def _reset_gate():
    lg.reset_for_tests()
    yield
    lg.reset_for_tests()


def _reader_body():
    return {"serverTime": "2026-09-26T10:00:00", "gymUsesAssignments": True, "role": "READER",
            "drive": [], "release": [], "alsoReadEnabled": False,
            "readerOf": [{"pcId": 3, "name": "Accueil"}]}


def _driver_body():
    return {"gymUsesAssignments": True, "role": "DRIVER", "readerOf": [],
            "drive": [
                {"gymDeviceId": 8, "name": "Sortie", "generation": 4, "state": "DRIVE",
                 "handoverForced": False, "forcedReason": None, "previousPcId": None},
                {"gymDeviceId": 10, "name": "Entree", "generation": 2, "state": "DRIVE",
                 "handoverForced": True, "forcedReason": "OWNER_FORCED", "previousPcId": 5},
                {"gymDeviceId": 12, "name": "Porte", "generation": 7, "state": "WAIT_FOR_RELEASE",
                 "handoverForced": False, "forcedReason": None, "previousPcId": 6},
            ],
            "release": [{"gymDeviceId": 14, "name": "Salle", "generation": 9, "newDriverPcId": 6}]}


# --------------------------------------------------------------------------- the snapshot

def test_no_information_allows_every_turnstile_as_before():
    snap = lg.current()
    assert snap.mode == lg.MODE_ALL
    assert all(snap.allows(d) for d in (1, 8, 999))
    assert snap.removals_blocked(8) is None and not snap.writes_frozen(8)


def test_a_gym_without_assignments_keeps_every_turnstile():
    snap = lg.snapshot_from_assignment({"gymUsesAssignments": False, "role": "ALL_TURNSTILES",
                                        "drive": [], "release": [], "readerOf": []}, source="server")
    assert snap.mode == lg.MODE_ALL and snap.allows(8)


def test_a_reader_drives_nothing():
    snap = lg.snapshot_from_assignment(_reader_body(), source="server")
    assert snap.mode == lg.MODE_LEASED and snap.role == "READER"
    assert not any(snap.allows(d) for d in (1, 8, 10))
    assert snap.reader_of == ((3, "Accueil"),)


def test_a_driver_drives_its_drive_entries_only():
    snap = lg.snapshot_from_assignment(_driver_body(), source="server")
    assert snap.allows(8) and snap.allows(10)
    assert not snap.allows(12), "WAIT_FOR_RELEASE: the outgoing PC still drives it"
    assert snap.allows(14), "release[]: keep serving the door until the release is acknowledged"
    assert not snap.allows(99)


def test_a_turnstile_being_released_is_frozen_for_writes():
    snap = lg.snapshot_from_assignment(_driver_body(), source="server")
    assert snap.writes_frozen(14) and not snap.writes_frozen(8)
    assert snap.removals_blocked(14) == "handover_release"


def test_a_forced_handover_is_add_only_until_read_back():
    snap = lg.snapshot_from_assignment(_driver_body(), source="server")
    assert snap.removals_blocked(10) == "add_only"
    assert snap.removals_blocked(8) is None
    extra = lg.snapshot_from_assignment(_driver_body(), source="server", add_only=[8])
    assert extra.removals_blocked(8) == "add_only", "not yet restored -> add-only too"


def test_filter_devices_keeps_payloads_by_id():
    lg.install(lg.snapshot_from_assignment(_driver_body(), source="server"))
    got = lg.filter_devices([{"id": 8}, {"id": 12}, {"id": "10"}, {"id": None}, "junk"])
    assert [d["id"] for d in got] == [8, "10"]


# --------------------------------------------------------------------------- the guard

class _Boom(AssertionError):
    pass


@pytest.fixture
def no_driver(monkeypatch):
    """Every way of constructing a device driver raises."""
    def boom(*a, **k):
        raise _Boom("a device driver was constructed for a READER")

    import app.core.ultra_engine as ue
    import app.core.realtime_agent as ra
    import app.core.device_attendance as da
    import app.core.device_sync as ds
    import app.sdk.device_driver as dd
    import app.sdk.pullsdk as ps
    import app.sdk.zk_standalone as zs

    for mod in (ue, ra, da, dd):
        monkeypatch.setattr(mod, "get_driver", boom, raising=False)
    monkeypatch.setattr(ds, "PullSDK", boom, raising=False)
    monkeypatch.setattr(ps.PullSDK, "__init__", boom)
    monkeypatch.setattr(ps.PullSDKDevice, "__init__", boom)
    monkeypatch.setattr(zs.ZKStandaloneDevice, "__init__", boom)
    lg.install(lg.snapshot_from_assignment(_reader_body(), source="server"))
    return boom


def _dev(did, mode, proto="ZK_PULLSDK"):
    return {"id": did, "name": f"dev{did}", "ipAddress": "192.168.1.%d" % did, "portNumber": 4370,
            "accessDataMode": mode, "deviceProtocol": proto, "active": True, "accessDevice": True}


def test_the_app_starts_no_ultra_worker_on_a_reader(no_driver):
    from app.ui.app import ultra_devices_for_this_pc
    assert ultra_devices_for_this_pc([_dev(8, "ULTRA"), _dev(9, "AGENT")]) == []
    lg.reset_for_tests()
    assert [d["id"] for d in ultra_devices_for_this_pc([_dev(8, "ULTRA"), _dev(9, "AGENT")])] == [8]


def test_ultra_engine_start_and_refresh_build_nothing_on_a_reader(no_driver, monkeypatch):
    import app.core.ultra_engine as ue
    eng = ue.UltraEngine.__new__(ue.UltraEngine)
    eng._running = False
    eng._stop_event = threading.Event()
    eng._logger = logging.getLogger("t")
    eng._workers = {}
    eng._sync_scheduler = None
    eng.start([_dev(8, "ULTRA", "ZK_STANDALONE")])
    assert eng._workers == {} and not eng._running


def test_an_ultra_worker_does_not_connect_to_a_turnstile_it_does_not_drive(no_driver):
    import app.core.ultra_engine as ue
    w = ue.UltraDeviceWorker(_dev(8, "ULTRA", "ZK_STANDALONE"), {}, queue.Queue(), queue.Queue(),
                             threading.Event())
    w._connect()                     # raising would fail the test through _Boom
    assert not w._connected and w._sdk is None


def test_the_agent_engine_starts_no_worker_on_a_reader(no_driver, monkeypatch):
    import app.core.realtime_agent as ra
    eng = ra.AgentRealtimeEngine.__new__(ra.AgentRealtimeEngine)
    eng.logger = logging.getLogger("t")
    eng._lock = threading.Lock()
    eng._workers = {}
    eng._devices_by_id = {}
    eng._check_thread_health = lambda: None
    eng._load_devices_cached = lambda: [_dev(8, "AGENT")]
    monkeypatch.setattr(ra, "DeviceWorker", no_driver)
    eng.refresh_devices()
    assert eng._workers == {}


def test_the_device_mode_push_engine_syncs_nothing_on_a_reader(no_driver, monkeypatch):
    from app.core.device_sync import DeviceSyncEngine
    eng = DeviceSyncEngine(cfg=MagicMock(), logger=logging.getLogger("t"))
    reg = SimpleNamespace(update_devices=MagicMock(), enqueue_full_reconcile=MagicMock(return_value=0),
                          enqueue_targeted_sync=MagicMock(return_value=0), stop_all=MagicMock())
    monkeypatch.setattr(eng, "_actor_registry", reg)
    monkeypatch.setattr("app.core.device_sync.list_fingerprints", lambda: [])
    monkeypatch.setattr(eng, "_set_progress", lambda **kw: None)
    eng._sync_all_devices(cache=SimpleNamespace(users=[], devices=[_dev(8, "DEVICE")]),
                          changed_ids=None, sync_run_id=1)
    for call in reg.update_devices.call_args_list:
        assert not list(call.args[0] if call.args else call.kwargs.get("devices") or [])
    for call in reg.enqueue_full_reconcile.call_args_list:
        assert not set(call.kwargs.get("device_ids") or ())


def test_the_device_mode_one_shot_sync_refuses_a_turnstile_it_does_not_drive(no_driver):
    from app.core.device_sync import DeviceSyncEngine
    eng = DeviceSyncEngine(cfg=MagicMock(), logger=logging.getLogger("t"))
    cache = SimpleNamespace(users=[], devices=[_dev(8, "DEVICE")])
    # The ULTRA scheduler's fallback path for a PullSDK turnstile.
    assert eng.run_one_device_blocking(cache=cache, device=_dev(8, "DEVICE")) is False
    # The DEVICE-mode actor path.
    assert eng._sync_one_device(device=_dev(8, "DEVICE"), users=[], local_fp_index={},
                                default_door_id=1) is None


def test_the_attendance_reader_reads_nothing_on_a_reader(no_driver, monkeypatch):
    import app.core.device_attendance as da
    eng = da.DeviceAttendanceMaintenanceEngine(cfg=SimpleNamespace(), logger=MagicMock())
    monkeypatch.setattr(da, "list_sync_devices_payload", lambda: [_dev(8, "DEVICE")])
    monkeypatch.setattr(da, "normalize_device_settings", lambda d, g=None: {"access_data_mode": "DEVICE"})
    assert eng._list_device_candidates({}) == []


GATED = ("_handle_device_connect", "_handle_device_info", "_handle_device_settings_get",
         "_handle_device_reentry_set", "_handle_device_clock_get", "_handle_device_clock_sync",
         "_handle_device_table", "_handle_device_door_open", "_handle_device_users_push",
         "_handle_device_users_list", "_handle_device_users_delete")


class _Ctx:
    def __init__(self, did):
        self.app = SimpleNamespace(cfg=SimpleNamespace(plcomm_dll_path="x"), logger=logging.getLogger("t"),
                                   _ultra_engine=None, _agent_engine=None)
        self._did = did
        self.sent = None

    def param_int(self, name, default=0):
        return self._did

    def param(self, name, default=""):
        return "user" if name == "tableName" else str(self._did)

    def body(self):
        return {"pin": "1", "doorNumber": 1, "pulseSeconds": 3}

    def q(self, *a, **k):
        return None

    def send_json(self, status, payload):
        self.sent = (status, payload)


@pytest.mark.parametrize("handler_name", GATED)
def test_every_device_session_handler_refuses_a_reader(no_driver, handler_name):
    from access.local_api_routes import gated_handler
    import app.api.local_access_api_v2 as la2
    ctx = _Ctx(8)
    gated_handler(getattr(la2, handler_name))(ctx)
    status, payload = ctx.sent
    assert status == 409 and payload.get("notDriver") is True


def test_the_route_table_wraps_exactly_the_device_session_handlers():
    from access.local_api_routes import LEASE_GATED_HANDLERS
    assert set(LEASE_GATED_HANDLERS) == set(GATED)


def test_a_gated_handler_runs_normally_when_the_pc_drives_the_turnstile(monkeypatch):
    from access.local_api_routes import gated_handler
    calls = []
    gated_handler(lambda ctx: calls.append(ctx))(_Ctx(8))
    assert len(calls) == 1

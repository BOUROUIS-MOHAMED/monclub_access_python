from __future__ import annotations

import threading
import time
import types
import queue
from types import SimpleNamespace
from unittest.mock import MagicMock


def test_ultra_sync_scheduler_request_sync_now_wakes_without_waiting_interval(monkeypatch):
    import app.core.ultra_engine as ultra_module

    scheduler = ultra_module.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())
    device = {"id": 5, "_settings": {"ultra_sync_interval_minutes": 999}}
    calls: list[tuple[str, set[int] | None]] = []

    def fake_sync_all(self, *, changed_ids=None, device_ids=None, reason="timer"):
        normalized = None if changed_ids is None else set(changed_ids)
        calls.append((reason, normalized))
        if len(calls) >= 2:
            self._stop.set()

    monkeypatch.setattr(
        scheduler,
        "_sync_all",
        types.MethodType(fake_sync_all, scheduler),
    )

    scheduler.start([device])

    deadline = time.time() + 1.0
    while len(calls) < 1 and time.time() < deadline:
        time.sleep(0.01)

    scheduler.request_sync_now(changed_ids={11}, reason="member_delta")

    deadline = time.time() + 1.0
    while len(calls) < 2 and time.time() < deadline:
        time.sleep(0.01)

    scheduler.stop()

    assert calls[0] == ("startup", None)
    assert calls[1] == ("member_delta", {11})


def test_ultra_sync_scheduler_sync_device_passes_changed_ids(monkeypatch):
    import app.core.ultra_engine as ultra_module

    run_one_device_calls: list[set[int] | None] = []

    class _FakeDeviceSyncEngine:
        def __init__(self, cfg, logger):
            self.cfg = cfg
            self.logger = logger

        def build_device_sync_fingerprint(self, *, device, users):
            return ("hash-1", 1)

        def run_one_device_blocking(
            self,
            *,
            cache,
            device,
            source="timer",
            changed_ids=None,
            sync_run_id=None,
        ):
            run_one_device_calls.append(None if changed_ids is None else set(changed_ids))
            return True

    worker = SimpleNamespace(
        pause_for_sync=lambda timeout=20.0: True,
        resume_from_sync=MagicMock(),
    )

    scheduler = ultra_module.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())
    scheduler.set_workers({5: worker})

    monkeypatch.setattr(
        ultra_module,
        "load_sync_cache",
        lambda: SimpleNamespace(users=[{"activeMembershipId": 11}], devices=[]),
    )
    monkeypatch.setattr("app.core.device_sync.DeviceSyncEngine", _FakeDeviceSyncEngine)

    did_sync = scheduler._sync_device(
        {"id": 5, "name": "Door 1", "accessDataMode": "ULTRA"},
        changed_ids={11},
    )

    assert did_sync is True
    assert run_one_device_calls == [{11}]
    worker.resume_from_sync.assert_called_once()


def test_ultra_sync_scheduler_sync_all_limits_to_targeted_devices(monkeypatch):
    import app.core.ultra_engine as ultra_module

    scheduler = ultra_module.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())
    scheduler._devices = [
        {"id": 5, "name": "Door 1", "accessDataMode": "ULTRA"},
        {"id": 6, "name": "Door 2", "accessDataMode": "ULTRA"},
    ]

    synced_device_ids: list[int] = []

    def fake_sync_device(self, device, *, changed_ids=None):
        synced_device_ids.append(int(device["id"]))
        return True

    monkeypatch.setattr(
        scheduler,
        "_sync_device",
        types.MethodType(fake_sync_device, scheduler),
    )

    scheduler._sync_all(changed_ids={11}, device_ids={6}, reason="member_delta")

    assert synced_device_ids == [6]


def test_ultra_engine_request_sync_now_routes_member_delta_to_live_workers():
    import app.core.ultra_engine as ultra_module

    worker = SimpleNamespace(request_member_sync=MagicMock())
    scheduler = SimpleNamespace(request_sync_now=MagicMock())
    engine = SimpleNamespace(
        _running=True,
        _sync_scheduler=scheduler,
        _workers={5: worker},
        _logger=MagicMock(),
    )

    started = ultra_module.UltraEngine.request_sync_now(
        engine,
        changed_ids={13, 11},
        device_ids={5},
        reason="fast_patch_bundle",
    )

    assert started is True
    assert [call.args[0] for call in worker.request_member_sync.call_args_list] == [11, 13]
    scheduler.request_sync_now.assert_not_called()


def test_ultra_engine_request_sync_now_skips_empty_member_delta():
    import app.core.ultra_engine as ultra_module

    worker = SimpleNamespace(request_member_sync=MagicMock(), request_full_sync=MagicMock())
    scheduler = SimpleNamespace(request_sync_now=MagicMock())
    engine = SimpleNamespace(
        _running=True,
        _sync_scheduler=scheduler,
        _workers={5: worker},
        _logger=MagicMock(),
    )

    started = ultra_module.UltraEngine.request_sync_now(
        engine,
        changed_ids=set(),
        device_ids={5},
        reason="change_detector",
    )

    assert started is False
    worker.request_member_sync.assert_not_called()
    worker.request_full_sync.assert_not_called()
    scheduler.request_sync_now.assert_not_called()


def test_ultra_engine_request_sync_now_routes_full_refresh_to_live_workers():
    import app.core.ultra_engine as ultra_module

    worker = SimpleNamespace(
        request_member_sync=MagicMock(),
        request_full_sync=MagicMock(return_value=True),
    )
    scheduler = SimpleNamespace(request_sync_now=MagicMock())
    engine = SimpleNamespace(
        _running=True,
        _sync_scheduler=scheduler,
        _workers={5: worker},
        _logger=MagicMock(),
    )

    started = ultra_module.UltraEngine.request_sync_now(
        engine,
        changed_ids=None,
        device_ids={5},
        reason="device_refresh",
    )

    assert started is True
    worker.request_full_sync.assert_called_once_with(reason="device_refresh")
    scheduler.request_sync_now.assert_not_called()


def test_ultra_engine_request_sync_now_uses_scheduler_for_full_refresh_without_live_worker():
    import app.core.ultra_engine as ultra_module

    scheduler = SimpleNamespace(request_sync_now=MagicMock())
    engine = SimpleNamespace(
        _running=True,
        _sync_scheduler=scheduler,
        _workers={},
        _logger=MagicMock(),
    )

    started = ultra_module.UltraEngine.request_sync_now(
        engine,
        changed_ids=None,
        device_ids={5},
        reason="device_refresh",
    )

    assert started is True
    scheduler.request_sync_now.assert_called_once_with(
        changed_ids=None,
        device_ids={5},
        reason="device_refresh",
    )


def test_ultra_sync_scheduler_sync_all_routes_targeted_delta_to_live_worker(monkeypatch):
    import app.core.ultra_engine as ultra_module

    worker = SimpleNamespace(
        request_member_sync=MagicMock(return_value=True),
        request_full_sync=MagicMock(return_value=True),
    )
    scheduler = ultra_module.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())
    scheduler.set_workers({5: worker})
    scheduler._devices = [
        {"id": 5, "name": "Door 1", "accessDataMode": "ULTRA", "_settings": {}},
    ]

    sync_device_calls: list[int] = []

    def fake_sync_device(self, device, *, changed_ids=None):
        sync_device_calls.append(int(device["id"]))
        return True

    monkeypatch.setattr(
        scheduler,
        "_sync_device",
        types.MethodType(fake_sync_device, scheduler),
    )

    scheduler._sync_all(changed_ids={11, 13}, reason="member_delta")

    assert [call.args[0] for call in worker.request_member_sync.call_args_list] == [11, 13]
    worker.request_full_sync.assert_not_called()
    assert sync_device_calls == []


def test_ultra_sync_scheduler_sync_all_routes_full_sync_to_live_worker(monkeypatch):
    import app.core.ultra_engine as ultra_module

    worker = SimpleNamespace(
        request_member_sync=MagicMock(return_value=True),
        request_full_sync=MagicMock(return_value=True),
    )
    scheduler = ultra_module.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())
    scheduler.set_workers({5: worker})
    scheduler._devices = [
        {"id": 5, "name": "Door 1", "accessDataMode": "ULTRA", "_settings": {}},
    ]
    scheduler._last_hash = {}

    class _FakeDeviceSyncEngine:
        def __init__(self, cfg, logger):
            self.cfg = cfg
            self.logger = logger

        def build_device_sync_fingerprint(self, *, device, users):
            return ("hash-live-worker", 1)

    sync_device_calls: list[int] = []

    def fake_sync_device(self, device, *, changed_ids=None):
        sync_device_calls.append(int(device["id"]))
        return True

    monkeypatch.setattr(
        scheduler,
        "_sync_device",
        types.MethodType(fake_sync_device, scheduler),
    )
    monkeypatch.setattr(
        ultra_module,
        "load_sync_cache",
        lambda: SimpleNamespace(users=[{"activeMembershipId": 11}], devices=[]),
    )
    monkeypatch.setattr("app.core.device_sync.DeviceSyncEngine", _FakeDeviceSyncEngine)

    scheduler._sync_all(changed_ids=None, reason="startup")

    worker.request_full_sync.assert_called_once_with(
        reason="startup",
        fingerprint_hash="hash-live-worker",
    )
    worker.request_member_sync.assert_not_called()
    assert sync_device_calls == []


def test_ultra_worker_drains_targeted_member_sync_commands_one_member_at_a_time(monkeypatch):
    import app.core.ultra_engine as ultra_module

    synced_members: list[tuple[object, int, str]] = []

    class _FakeDeviceSyncEngine:
        def __init__(self, cfg, logger):
            self.cfg = cfg
            self.logger = logger

        def sync_member_on_connected_sdk(self, *, sdk, device, member_id, source):
            synced_members.append((sdk, member_id, source))
            return True

    monkeypatch.setattr("app.core.device_sync.DeviceSyncEngine", _FakeDeviceSyncEngine)

    worker = ultra_module.UltraDeviceWorker(
        device={"id": 5, "name": "Door 1", "ipAddress": "10.0.0.5", "portNumber": 4370},
        settings={},
        popup_q=queue.Queue(),
        history_q=queue.Queue(),
        stop_event=threading.Event(),
    )
    worker._connected = True
    worker._sdk = SimpleNamespace(_sdk="raw-sdk")

    worker.request_member_sync(11)
    worker.request_member_sync(11)
    worker.request_member_sync(13)

    drained = worker._drain_member_sync_commands(limit=1)
    drained_rest = worker._drain_member_sync_commands(limit=10)

    assert drained == 1
    assert drained_rest == 1
    assert synced_members == [
        ("raw-sdk", 11, "ultra_targeted_member_sync"),
        ("raw-sdk", 13, "ultra_targeted_member_sync"),
    ]


def test_ultra_worker_drains_full_sync_commands_using_live_connection(monkeypatch):
    import app.core.ultra_engine as ultra_module

    full_sync_calls: list[tuple[object, str, list[dict[str, object]]]] = []

    class _FakeDeviceSyncEngine:
        def __init__(self, cfg, logger):
            self.cfg = cfg
            self.logger = logger

        def run_one_device_on_connected_sdk(
            self,
            *,
            sdk,
            cache,
            device,
            source="timer",
            changed_ids=None,
            sync_run_id=None,
        ):
            assert changed_ids is None
            assert sync_run_id is None
            full_sync_calls.append((sdk, source, list(getattr(cache, "users", []) or [])))
            return True

    monkeypatch.setattr("app.core.device_sync.DeviceSyncEngine", _FakeDeviceSyncEngine)
    monkeypatch.setattr(
        ultra_module,
        "load_sync_cache",
        lambda: SimpleNamespace(users=[{"activeMembershipId": 11}], devices=[]),
    )

    worker = ultra_module.UltraDeviceWorker(
        device={"id": 5, "name": "Door 1", "ipAddress": "10.0.0.5", "portNumber": 4370},
        settings={},
        popup_q=queue.Queue(),
        history_q=queue.Queue(),
        stop_event=threading.Event(),
    )
    worker._connected = True
    worker._sdk = SimpleNamespace(_sdk="raw-sdk")

    assert worker.request_full_sync(reason="device_refresh") is True
    assert worker.request_full_sync(reason="device_refresh") is False

    drained = worker._drain_full_sync_commands(limit=1)

    assert drained == 1
    assert full_sync_calls == [
        ("raw-sdk", "device_refresh", [{"activeMembershipId": 11}]),
    ]


def test_ultra_device_worker_update_device_swaps_dict_in_place():
    """update_device must replace the cached device, settings, and name so that
    a delta-sync triggered after the dashboard adds a membership to
    allowedMemberships does NOT filter the new member out and pin-delete them."""
    import app.core.ultra_engine as ultra_module

    worker = SimpleNamespace(
        _device={"id": 5, "name": "Door 1", "allowedMemberships": [1, 2]},
        _settings={"ultra_sync_interval_minutes": 15},
        _device_name="Door 1",
    )

    new_device = {
        "id": 5,
        "name": "Door 1 Renamed",
        "allowedMemberships": [1, 2, 265],
    }
    new_settings = {"ultra_sync_interval_minutes": 30}

    ultra_module.UltraDeviceWorker.update_device(worker, new_device, new_settings)

    assert worker._device is new_device
    assert worker._device["allowedMemberships"] == [1, 2, 265]
    assert worker._settings is new_settings
    assert worker._device_name == "Door 1 Renamed"


def test_ultra_sync_scheduler_update_devices_replaces_list():
    import app.core.ultra_engine as ultra_module

    scheduler = ultra_module.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())
    scheduler._devices = [{"id": 5, "allowedMemberships": [1]}]

    new_devices = [
        {"id": 5, "allowedMemberships": [1, 265]},
        {"id": 6, "allowedMemberships": [1, 265]},
    ]
    scheduler.update_devices(new_devices)

    assert scheduler._devices == new_devices
    # Defensive copy: mutating the caller's list must not affect the scheduler.
    new_devices.append({"id": 99})
    assert len(scheduler._devices) == 2


def test_ultra_engine_refresh_devices_updates_workers_in_place(monkeypatch):
    """When the dashboard adds a membership to a device, refresh_devices must
    push the new device dict into each running ULTRA worker so subsequent
    delta-sync calls see the fresh allowedMemberships list."""
    import app.core.ultra_engine as ultra_module

    worker_a = MagicMock()
    worker_b = MagicMock()
    scheduler = SimpleNamespace(update_devices=MagicMock())

    engine = SimpleNamespace(
        _running=True,
        _workers={5: worker_a, 6: worker_b},
        _sync_scheduler=scheduler,
        _logger=MagicMock(),
    )

    monkeypatch.setattr(
        "app.core.settings_reader.normalize_device_settings",
        lambda d: {"ultra_sync_interval_minutes": 15, "_normalized_for": d.get("id")},
    )

    devices = [
        {"id": 5, "name": "Door 1", "accessDataMode": "ULTRA",
         "allowedMemberships": [1, 2, 265]},
        {"id": 6, "name": "Door 2", "accessDataMode": "ULTRA",
         "allowedMemberships": [1, 2, 265]},
        {"id": 9, "name": "Agent door", "accessDataMode": "AGENT"},  # filtered out
        {"id": 99, "name": "Stray", "accessDataMode": "ULTRA"},      # no worker
    ]

    refreshed = ultra_module.UltraEngine.refresh_devices(engine, devices)

    assert refreshed == 2
    worker_a.update_device.assert_called_once()
    worker_b.update_device.assert_called_once()

    a_args = worker_a.update_device.call_args
    assert a_args.args[0]["id"] == 5
    assert a_args.args[0]["allowedMemberships"] == [1, 2, 265]
    assert a_args.args[1]["_normalized_for"] == 5

    b_args = worker_b.update_device.call_args
    assert b_args.args[0]["id"] == 6

    # Scheduler is updated with ULTRA-only devices (AGENT and unmanaged ULTRA
    # are still passed through — only the engine's workers gate what gets
    # update_device-ed).
    scheduler.update_devices.assert_called_once()
    sched_devices = scheduler.update_devices.call_args.args[0]
    sched_ids = sorted(d["id"] for d in sched_devices)
    assert sched_ids == [5, 6, 99]  # 9 (AGENT) is filtered out


def test_ultra_engine_refresh_devices_skips_when_not_running():
    import app.core.ultra_engine as ultra_module

    worker = MagicMock()
    scheduler = SimpleNamespace(update_devices=MagicMock())
    engine = SimpleNamespace(
        _running=False,
        _workers={5: worker},
        _sync_scheduler=scheduler,
        _logger=MagicMock(),
    )

    refreshed = ultra_module.UltraEngine.refresh_devices(
        engine, [{"id": 5, "accessDataMode": "ULTRA"}]
    )

    assert refreshed == 0
    worker.update_device.assert_not_called()
    scheduler.update_devices.assert_not_called()

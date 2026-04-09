from __future__ import annotations

import queue
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.core.access_types import AccessEvent
from app.core.db import normalize_access_history_source
from app.core.device_sync import DeviceSyncEngine
from app.core.realtime_agent import CommandResult, DecisionService, EMA, NotificationGate
from app.core.ultra_engine import UltraDeviceWorker, UltraSyncScheduler


class _DummyLogger:
    def info(self, *args, **kwargs) -> None:
        pass

    def warning(self, *args, **kwargs) -> None:
        pass

    def error(self, *args, **kwargs) -> None:
        pass

    def exception(self, *args, **kwargs) -> None:
        pass

    def debug(self, *args, **kwargs) -> None:
        pass


def _make_ultra_worker(*, door_entry_id: int = 1) -> UltraDeviceWorker:
    return UltraDeviceWorker(
        device={
            "id": 1,
            "name": "ultra-1",
            "ipAddress": "192.168.1.20",
            "portNumber": 4370,
            "accessDataMode": "ULTRA",
        },
        settings={
            "totp_enabled": True,
            "ultra_totp_rescue_enabled": True,
            "totp_prefix": "9",
            "totp_digits": 7,
            "popup_enabled": False,
            "popup_show_image": False,
            "popup_duration_sec": 3,
            "win_notify_enabled": False,
            "door_entry_id": door_entry_id,
            "pulse_time_ms": 3000,
            "busy_sleep_min_ms": 0,
            "busy_sleep_max_ms": 50,
            "empty_sleep_min_ms": 200,
            "empty_sleep_max_ms": 500,
            "empty_backoff_factor": 1.35,
            "empty_backoff_max_ms": 2000,
        },
        popup_q=queue.Queue(),
        history_q=queue.Queue(),
        stop_event=threading.Event(),
    )


def _make_decision_service(command_bus: MagicMock) -> DecisionService:
    return DecisionService(
        logger=_DummyLogger(),
        event_queue=queue.Queue(),
        command_bus=command_bus,
        notify_q=queue.Queue(),
        popup_q=queue.Queue(),
        history_q=queue.Queue(),
        settings_provider=lambda _device_id: {
            "save_history": True,
            "door_entry_id": 1,
            "pulse_time_ms": 3000,
            "cmd_timeout_ms": 4000,
            "show_notifications": False,
        },
        global_settings=lambda: {},
        notify_gate=NotificationGate(global_settings=lambda: {}),
        decision_ema=EMA(0.2),
    )


def test_decision_service_does_not_open_door_when_history_insert_fails() -> None:
    command_bus = MagicMock()
    command_bus.open_door.return_value = CommandResult(ok=True, error="", cmd_ms=0.0)
    service = _make_decision_service(command_bus)
    service.event_queue.put(
        AccessEvent(
            event_id="evt-history-fail",
            device_id=10,
            door_id=2,
            event_type="RTLOG",
            card_no="91234567",
            event_time="2026-04-01T10:00:00",
            raw={},
            poll_ms=12.0,
        )
    )

    with (
        patch("app.core.realtime_agent.access_history_exists", return_value=False),
        patch.object(service, "_load_local_state", return_value=([], {}, {})),
        patch.object(
            service,
            "_verify_totp",
            return_value={"allowed": True, "reason": "ALLOW_TOTP", "scanMode": "QR_TOTP", "user": None},
        ),
        patch("app.core.realtime_agent.insert_access_history", side_effect=RuntimeError("sqlite write failed")),
    ):
        service.start()
        time.sleep(0.2)
        service.stop()
        service.join(timeout=1.0)

    command_bus.open_door.assert_not_called()


def test_normalize_access_history_source_preserves_ultra() -> None:
    assert normalize_access_history_source("ULTRA") == "ULTRA"


def test_ultra_open_door_prefers_event_door_id() -> None:
    worker = _make_ultra_worker(door_entry_id=7)
    worker._sdk = MagicMock()
    worker._sdk.open_door.return_value = True

    assert worker._open_door_with_retry(door_id=3) is True
    worker._sdk.open_door.assert_called_once_with(door_id=3, pulse_time_ms=3000, timeout_ms=4000)


def test_ultra_open_door_falls_back_to_configured_entry_door() -> None:
    worker = _make_ultra_worker(door_entry_id=7)
    worker._sdk = MagicMock()
    worker._sdk.open_door.return_value = True

    assert worker._open_door_with_retry(door_id=0) is True
    worker._sdk.open_door.assert_called_once_with(door_id=7, pulse_time_ms=3000, timeout_ms=4000)


def test_ultra_sync_scheduler_syncs_only_target_device_with_device_mode_copy() -> None:
    scheduler = UltraSyncScheduler(cfg=object(), logger_inst=_DummyLogger())
    target_device = {
        "id": 42,
        "name": "ultra-target",
        "accessDataMode": "ULTRA",
        "_settings": {"ultra_sync_interval_minutes": 15},
    }
    cache = SimpleNamespace(
        users=[{"activeMembershipId": 101, "firstCardId": "555"}],
        devices=[
            target_device,
            {"id": 99, "name": "other-device", "accessDataMode": "DEVICE"},
        ],
    )
    engine_instance = MagicMock()
    engine_instance.build_device_sync_fingerprint.return_value = ("hash-1", 1)

    with (
        patch("app.core.ultra_engine.load_sync_cache", return_value=cache),
        patch("app.core.device_sync.DeviceSyncEngine", return_value=engine_instance),
    ):
        scheduler._sync_device(target_device)

    _, kwargs = engine_instance.run_blocking.call_args
    filtered_cache = kwargs["cache"]
    assert len(filtered_cache.devices) == 1
    assert filtered_cache.devices[0]["id"] == 42
    assert filtered_cache.devices[0]["accessDataMode"] == "DEVICE"


def test_device_sync_fingerprint_changes_when_allowed_memberships_change() -> None:
    engine = DeviceSyncEngine(cfg=SimpleNamespace(), logger=_DummyLogger())
    device = {
        "id": 42,
        "name": "ultra-target",
        "ipAddress": "192.168.1.50",
        "portNumber": 4370,
        "accessDataMode": "DEVICE",
        "doorIds": [1],
        "allowedMemberships": [7],
        "authorizeTimezoneId": 1,
        "pushingToDevicePolicy": "ALL",
    }
    users = [{
        "userId": 1,
        "activeMembershipId": 101,
        "membershipId": 7,
        "fullName": "Alice Doe",
        "firstCardId": "555",
        "fingerprints": [],
    }]

    with patch("app.core.device_sync.get_backend_global_settings", return_value={}):
        hash_with_membership, desired_with_membership = engine.build_device_sync_fingerprint(
            device=device,
            users=users,
            local_fp_index={},
        )
        hash_without_membership, desired_without_membership = engine.build_device_sync_fingerprint(
            device={**device, "allowedMemberships": [8]},
            users=users,
            local_fp_index={},
        )

    assert desired_with_membership == 1
    assert desired_without_membership == 0
    assert hash_with_membership != hash_without_membership


def test_ultra_sync_scheduler_resyncs_when_device_fingerprint_changes() -> None:
    scheduler = UltraSyncScheduler(cfg=object(), logger_inst=_DummyLogger())
    device = {
        "id": 42,
        "name": "ultra-target",
        "ipAddress": "192.168.1.50",
        "portNumber": 4370,
        "accessDataMode": "ULTRA",
        "allowedMemberships": [7],
        "_settings": {"ultra_sync_interval_minutes": 15},
    }
    cache = SimpleNamespace(
        users=[{
            "userId": 1,
            "activeMembershipId": 101,
            "membershipId": 7,
            "fullName": "Alice Doe",
        }],
        devices=[device],
    )
    first_engine = MagicMock()
    first_engine.build_device_sync_fingerprint.return_value = ("hash-1", 1)
    second_engine = MagicMock()
    second_engine.build_device_sync_fingerprint.return_value = ("hash-2", 0)

    with (
        patch("app.core.ultra_engine.load_sync_cache", return_value=cache),
        patch("app.core.device_sync.DeviceSyncEngine", side_effect=[first_engine, second_engine]),
    ):
        assert scheduler._sync_device(device) is True
        assert scheduler._sync_device({**device, "allowedMemberships": [8]}) is True

    assert first_engine.run_blocking.call_count == 1
    assert second_engine.run_blocking.call_count == 1

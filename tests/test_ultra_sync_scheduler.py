from __future__ import annotations

import threading
import time
import types
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

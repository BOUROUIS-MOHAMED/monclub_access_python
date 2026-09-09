from __future__ import annotations

from collections import deque
import threading
import time
import types
import queue
from types import SimpleNamespace
from unittest.mock import MagicMock


def _member_command_worker(ultra_module):
    worker = object.__new__(ultra_module.UltraDeviceWorker)
    worker._member_sync_lock = threading.Lock()
    worker._pending_member_syncs = deque()
    worker._pending_member_sync_ids = set()
    worker._pending_member_revoke_ids = set()
    worker._active_member_revoke_ids = set()
    worker._confirmed_member_revoke_ids = set()
    worker._full_sync_lock = threading.Lock()
    worker._pending_full_sync_request = None
    worker._full_sync_revocation_phase = {}
    worker._wake_evt = threading.Event()
    return worker


def test_ultra_sync_scheduler_request_sync_now_wakes_without_waiting_interval(monkeypatch):
    import app.core.ultra_engine as ultra_module

    scheduler = ultra_module.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())
    device = {"id": 5, "_settings": {"ultra_sync_interval_minutes": 999}}
    calls: list[tuple[str, set[int] | None]] = []

    def fake_sync_all(self, *, changed_ids=None, revoked_ids=None, device_ids=None, reason="timer"):
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

        def build_device_sync_fingerprint(self, *, device, users, local_fp_index=None, detail_out=None):
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


def test_ultra_engine_request_sync_now_routes_revocations_first_with_precedence():
    import app.core.ultra_engine as ultra_module

    routed: list[tuple[str, int]] = []
    worker = SimpleNamespace(
        request_member_sync=MagicMock(
            side_effect=lambda member_id: routed.append(("sync", member_id)) or True
        ),
        request_member_revoke=MagicMock(
            side_effect=lambda member_id: routed.append(("revoke", member_id)) or True
        ),
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
        changed_ids={11, 13},
        revoked_ids={13, 17},
        device_ids={5},
        reason="fast_patch_bundle",
    )

    assert started is True
    assert routed == [("revoke", 13), ("revoke", 17), ("sync", 11)]
    scheduler.request_sync_now.assert_not_called()


def test_ultra_engine_request_sync_now_falls_back_for_registered_dead_worker():
    import app.core.ultra_engine as ultra_module

    worker = SimpleNamespace(
        is_alive=lambda: False,
        request_member_sync=MagicMock(return_value=True),
        request_member_revoke=MagicMock(return_value=True),
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
        changed_ids={11},
        revoked_ids={17},
        device_ids={5},
        reason="fast_patch_bundle",
    )

    assert started is True
    worker.request_member_revoke.assert_not_called()
    worker.request_member_sync.assert_not_called()
    scheduler.request_sync_now.assert_called_once_with(
        changed_ids={11},
        revoked_ids={17},
        device_ids={5},
        reason="fast_patch_bundle",
    )


def test_ultra_engine_request_sync_now_falls_back_only_for_unmatched_device_ids():
    import app.core.ultra_engine as ultra_module

    worker = SimpleNamespace(
        request_member_sync=MagicMock(return_value=True),
        request_member_revoke=MagicMock(return_value=True),
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
        changed_ids={11},
        revoked_ids={17},
        device_ids={5, 6},
        reason="fast_patch_bundle",
    )

    assert started is True
    worker.request_member_revoke.assert_called_once_with(17)
    worker.request_member_sync.assert_called_once_with(11)
    scheduler.request_sync_now.assert_called_once_with(
        changed_ids={11},
        revoked_ids={17},
        device_ids={6},
        reason="fast_patch_bundle",
    )


def test_ultra_engine_request_sync_now_preserves_broadcast_fallback_without_workers():
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
        changed_ids=set(),
        revoked_ids={17},
        device_ids=None,
        reason="fast_patch_bundle",
    )

    assert started is True
    scheduler.request_sync_now.assert_called_once_with(
        changed_ids=set(),
        revoked_ids={17},
        device_ids=None,
        reason="fast_patch_bundle",
    )


def test_ultra_engine_request_sync_now_preserves_broadcast_for_partial_workers():
    import app.core.ultra_engine as ultra_module

    worker = SimpleNamespace(request_member_revoke=MagicMock(return_value=True))
    scheduler = SimpleNamespace(
        _devices=[{"id": 5}, {"id": 6}],
        request_sync_now=MagicMock(),
    )
    engine = SimpleNamespace(
        _running=True,
        _sync_scheduler=scheduler,
        _workers={5: worker},
        _logger=MagicMock(),
    )

    assert ultra_module.UltraEngine.request_sync_now(
        engine,
        changed_ids=set(),
        revoked_ids={17},
        device_ids=None,
        reason="fast_patch_bundle",
    ) is True

    worker.request_member_revoke.assert_called_once_with(17)
    scheduler.request_sync_now.assert_called_once_with(
        changed_ids=set(),
        revoked_ids={17},
        device_ids=None,
        reason="fast_patch_bundle",
    )


def test_ultra_engine_request_sync_now_falls_back_when_revoke_enqueue_raises():
    import app.core.ultra_engine as ultra_module

    worker = SimpleNamespace(
        request_member_sync=MagicMock(return_value=True),
        request_member_revoke=MagicMock(side_effect=RuntimeError("queue unavailable")),
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
        changed_ids={11},
        revoked_ids={17},
        device_ids={5},
        reason="fast_patch_bundle",
    )

    assert started is True
    scheduler.request_sync_now.assert_called_once_with(
        changed_ids={11},
        revoked_ids={17},
        device_ids={5},
        reason="fast_patch_bundle",
    )
    engine._logger.warning.assert_called()


def test_ultra_engine_request_sync_now_accepts_revocation_already_safely_pending():
    import app.core.ultra_engine as ultra_module

    worker = _member_command_worker(ultra_module)
    worker.is_alive = lambda: True
    assert worker.request_member_revoke(17) is True
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
        revoked_ids={17},
        device_ids={5},
        reason="fast_patch_bundle",
    )

    assert started is True
    scheduler.request_sync_now.assert_not_called()


def test_ultra_engine_request_sync_now_passes_changes_and_revocations_to_scheduler_without_matching_worker():
    import app.core.ultra_engine as ultra_module

    worker = SimpleNamespace(
        request_member_sync=MagicMock(),
        request_member_revoke=MagicMock(),
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
        changed_ids={"11", 13},
        revoked_ids={"13", 17},
        device_ids={6},
        reason="fast_patch_bundle",
    )

    assert started is True
    worker.request_member_revoke.assert_not_called()
    worker.request_member_sync.assert_not_called()
    scheduler.request_sync_now.assert_called_once_with(
        changed_ids={11},
        revoked_ids={13, 17},
        device_ids={6},
        reason="fast_patch_bundle",
    )


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
    worker.request_full_sync.assert_called_once_with(
        reason="device_refresh",
        require_full_refresh=True,
    )
    scheduler.request_sync_now.assert_not_called()


def test_ultra_engine_full_refresh_routes_revocation_before_filtered_full_sync():
    import app.core.ultra_engine as ultra_module

    routed: list[tuple[str, object]] = []
    worker = SimpleNamespace(
        request_member_revoke=MagicMock(
            side_effect=lambda member_id: routed.append(("revoke", member_id)) or True
        ),
        request_full_sync=MagicMock(
            side_effect=lambda **kwargs: routed.append(("full", kwargs)) or True
        ),
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
        revoked_ids={17},
        device_ids={5},
        reason="device_refresh",
    )

    assert started is True
    assert routed == [
        ("revoke", 17),
        (
            "full",
            {
                "reason": "device_refresh",
                "revoked_ids": {17},
                "require_full_refresh": True,
            },
        ),
    ]
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
        revoked_ids=set(),
        device_ids={5},
        reason="device_refresh",
    )


def test_ultra_sync_scheduler_accumulates_and_drains_revocations_separately():
    import app.core.ultra_engine as ultra_module

    scheduler = ultra_module.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())

    scheduler.request_sync_now(
        changed_ids={11},
        revoked_ids={17},
        device_ids={5},
        reason="fast_patch_bundle",
    )

    assert scheduler._drain_pending_sync_request() == (
        {11},
        {17},
        {5},
        "fast_patch_bundle",
    )


def test_ultra_sync_scheduler_revocation_wins_across_coalesced_requests():
    import app.core.ultra_engine as ultra_module

    scheduler = ultra_module.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())

    scheduler.request_sync_now(
        changed_ids={11, 13},
        revoked_ids={17},
        device_ids={5},
        reason="first",
    )
    scheduler.request_sync_now(
        changed_ids={17, 19},
        revoked_ids={13},
        device_ids={6},
        reason="second",
    )

    assert scheduler._drain_pending_sync_request() == (
        {11, 19},
        {13, 17},
        {5, 6},
        "second",
    )


def test_ultra_sync_scheduler_accepts_revoke_only_request():
    import app.core.ultra_engine as ultra_module

    scheduler = ultra_module.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())

    scheduler.request_sync_now(
        changed_ids=set(),
        revoked_ids={17},
        device_ids={5},
        reason="revoked_only",
    )

    assert scheduler._drain_pending_sync_request() == (
        set(),
        {17},
        {5},
        "revoked_only",
    )


def test_ultra_sync_scheduler_keeps_none_changed_ids_as_full_refresh_signal():
    import app.core.ultra_engine as ultra_module

    scheduler = ultra_module.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())

    scheduler.request_sync_now(
        changed_ids=None,
        revoked_ids={17},
        device_ids={5},
        reason="device_refresh",
    )

    assert scheduler._drain_pending_sync_request() == (
        None,
        {17},
        {5},
        "device_refresh",
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


def test_ultra_sync_scheduler_sync_all_routes_revocations_before_ordinary_syncs(monkeypatch):
    import app.core.ultra_engine as ultra_module

    routed: list[tuple[str, int]] = []
    worker = SimpleNamespace(
        request_member_sync=MagicMock(
            side_effect=lambda member_id: routed.append(("sync", member_id)) or True
        ),
        request_member_revoke=MagicMock(
            side_effect=lambda member_id: routed.append(("revoke", member_id)) or True
        ),
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

    scheduler._sync_all(
        changed_ids={11, 13},
        revoked_ids={13, 17},
        reason="fast_patch_bundle",
    )

    assert routed == [("revoke", 13), ("revoke", 17), ("sync", 11)]
    worker.request_full_sync.assert_not_called()
    assert sync_device_calls == []


def test_ultra_sync_scheduler_no_worker_additive_pull_device_keeps_revocation_pending(monkeypatch):
    import app.core.ultra_engine as ultra_module

    scheduler = ultra_module.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())
    scheduler._devices = [
        {
            "id": 5,
            "name": "Door 1",
            "accessDataMode": "ULTRA",
            "rosterPushingPolicy": "PUSH_WITHOUT_DELETING",
            "_settings": {},
        },
    ]
    sync_device = MagicMock(return_value=True)
    monkeypatch.setattr(scheduler, "_sync_device", sync_device)

    scheduler._sync_all(
        changed_ids=set(),
        revoked_ids={17},
        device_ids={5},
        reason="fast_patch_bundle",
    )

    sync_device.assert_not_called()
    assert scheduler._drain_pending_sync_request() == (
        set(),
        {17},
        {5},
        "fast_patch_bundle",
    )


def test_ultra_sync_scheduler_no_worker_untracked_pull_pin_keeps_revocation_pending(monkeypatch):
    import app.core.ultra_engine as ultra_module

    scheduler = ultra_module.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())
    scheduler._devices = [
        {
            "id": 5,
            "name": "Door 1",
            "accessDataMode": "ULTRA",
            "rosterPushingPolicy": "ADDITIVE_ONLY",
            "_settings": {},
        },
    ]
    sync_device = MagicMock(return_value=True)
    monkeypatch.setattr(scheduler, "_sync_device", sync_device)

    scheduler._sync_all(
        changed_ids=None,
        revoked_ids={99117},
        device_ids={5},
        reason="fast_patch_bundle",
    )

    sync_device.assert_not_called()
    assert scheduler._drain_pending_sync_request() == (
        None,
        {99117},
        {5},
        "fast_patch_bundle",
    )


def test_ultra_sync_scheduler_failed_full_sync_requeues_authoritative_revocation_once():
    import app.core.ultra_engine as ultra_module

    scheduler = ultra_module.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())

    scheduler._handle_worker_full_sync_finished(
        device_id=5,
        reason="fast_patch_bundle",
        ok=False,
        fingerprint_hash=None,
        duration_ms=2.0,
        error="authoritative revocation unconfirmed",
        revoked_ids={17},
    )

    assert scheduler._drain_pending_sync_request() == (
        None,
        {17},
        {5},
        "fast_patch_bundle",
    )
    assert scheduler._drain_pending_sync_request() is None


def test_ultra_sync_scheduler_preserves_standalone_revocation_until_worker_replacement(monkeypatch):
    import app.core.ultra_engine as ultra_module

    scheduler = ultra_module.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())
    scheduler._devices = [
        {
            "id": 5,
            "name": "Standalone Door",
            "accessDataMode": "ULTRA",
            "deviceProtocol": "ZK_STANDALONE",
            "_settings": {},
        },
    ]
    sync_device = MagicMock()
    monkeypatch.setattr(scheduler, "_sync_device", sync_device)

    scheduler._sync_all(
        changed_ids=set(),
        revoked_ids={17},
        device_ids={5},
        reason="fast_patch_bundle",
    )

    sync_device.assert_not_called()
    assert scheduler._drain_pending_sync_request() == (
        set(),
        {17},
        {5},
        "fast_patch_bundle",
    )


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

        def build_device_sync_fingerprint(self, *, device, users, local_fp_index=None, detail_out=None):
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
        require_full_refresh=True,
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


def test_member_revoke_upgrades_queued_member_sync_without_duplicate():
    import app.core.ultra_engine as ultra_module

    worker = _member_command_worker(ultra_module)

    assert worker.request_member_sync(41) is True
    worker._wake_evt.clear()
    assert worker.request_member_revoke(41) is True
    assert list(worker._pending_member_syncs) == [41]
    assert worker._pending_member_sync_ids == {41}
    assert worker._pending_member_revoke_ids == {41}
    assert worker._wake_evt.is_set()


def test_member_sync_cannot_downgrade_queued_member_revoke():
    import app.core.ultra_engine as ultra_module

    worker = _member_command_worker(ultra_module)

    assert worker.request_member_revoke(41) is True
    worker._wake_evt.clear()
    assert worker.request_member_sync(41) is False
    assert list(worker._pending_member_syncs) == [41]
    assert worker._pending_member_sync_ids == {41}
    assert worker._pending_member_revoke_ids == {41}
    assert not worker._wake_evt.is_set()


def test_member_sync_cannot_downgrade_confirmed_revoke_while_filtered_full_sync_is_pending():
    import app.core.ultra_engine as ultra_module

    worker = _member_command_worker(ultra_module)
    worker._confirmed_member_revoke_ids.add(41)
    worker._pending_full_sync_request = {"revoked_ids": {41}}

    assert worker.request_member_sync(41) is False
    assert worker.has_pending_member_revoke(41) is True
    assert list(worker._pending_member_syncs) == []


def test_member_sync_cannot_downgrade_revoke_after_full_sync_request_is_popped():
    import app.core.ultra_engine as ultra_module

    worker = _member_command_worker(ultra_module)
    worker._sdk = SimpleNamespace(owns_event_source=True)
    worker._connected = True
    worker._confirmed_member_revoke_ids.add(41)
    observed: dict[str, object] = {}

    def active_full_sync(**kwargs):
        observed["pending_request"] = worker._pending_full_sync_request
        observed["active_revokes"] = {
            member_id
            for member_id, phase in worker._full_sync_revocation_phase.items()
            if phase == ultra_module._FULL_REVOKE_ACTIVE
        }
        observed["ordinary_accepted"] = worker.request_member_sync(41)
        observed["revoke_pending"] = worker.has_pending_member_revoke(41)
        observed["confirmed_revokes"] = set(worker._confirmed_member_revoke_ids)
        observed["ordinary_queue"] = list(worker._pending_member_syncs)
        worker._finalize_full_sync_revokes({41}, ok=True)

    worker._run_standalone_full_sync = active_full_sync
    assert worker.request_full_sync(
        reason="fast_patch_bundle",
        revoked_ids={41},
    ) is True

    assert worker._drain_full_sync_commands(limit=1) == 1

    assert observed == {
        "pending_request": None,
        "active_revokes": {41},
        "ordinary_accepted": False,
        "revoke_pending": True,
        "confirmed_revokes": {41},
        "ordinary_queue": [],
    }


def _block_active_full_sync(worker, revoked_ids: set[int]):
    entered = threading.Event()
    release = threading.Event()

    def blocked_full_sync(**kwargs):
        entered.set()
        assert release.wait(1.0)

    worker._sdk = SimpleNamespace(owns_event_source=True)
    worker._connected = True
    worker._run_standalone_full_sync = blocked_full_sync
    assert worker.request_full_sync(
        reason="fast_patch_bundle",
        revoked_ids=revoked_ids,
    ) is True
    thread = threading.Thread(target=worker._drain_full_sync_commands, kwargs={"limit": 1})
    thread.start()
    assert entered.wait(1.0)
    return release, thread


def test_active_full_sync_handles_exact_duplicate_without_new_work():
    import app.core.ultra_engine as ultra_module

    worker = _member_command_worker(ultra_module)
    release, thread = _block_active_full_sync(worker, {41})
    try:
        assert worker.request_full_sync(
            reason="fast_patch_bundle",
            revoked_ids={41},
        ) is True
        assert worker._pending_full_sync_request is None
        assert worker.has_pending_full_sync(revoked_ids={41}) is True
    finally:
        release.set()
        thread.join(timeout=1.0)
    assert not thread.is_alive()


def test_active_full_sync_queues_only_new_ids_from_overlapping_request():
    import app.core.ultra_engine as ultra_module

    worker = _member_command_worker(ultra_module)
    release, thread = _block_active_full_sync(worker, {41})
    try:
        assert worker.request_full_sync(
            reason="fast_patch_bundle",
            revoked_ids={41, 43},
        ) is True
        assert worker._pending_full_sync_request["revoked_ids"] == {43}
        assert worker.has_pending_full_sync(revoked_ids={41, 43}) is True
    finally:
        release.set()
        thread.join(timeout=1.0)
    assert not thread.is_alive()


def test_later_full_sync_adopts_callback_free_retry_revocation():
    import app.core.ultra_engine as ultra_module

    worker = _member_command_worker(ultra_module)
    worker._full_sync_revocation_phase[41] = ultra_module._FULL_REVOKE_RETRY

    assert worker.request_full_sync(reason="timer") is True

    assert worker._pending_full_sync_request["revoked_ids"] == {41}
    assert worker._full_sync_revocation_phase == {}


def test_full_sync_atomically_adopts_equivalent_targeted_revoke_without_touching_other_work():
    import app.core.ultra_engine as ultra_module

    worker = _member_command_worker(ultra_module)
    worker._sdk = SimpleNamespace(owns_event_source=True)
    worker._connected = True
    observed: dict[str, object] = {}

    assert worker.request_member_sync(99) is True
    assert worker.request_member_revoke(41) is True
    worker._confirmed_member_revoke_ids.add(41)
    assert worker.request_full_sync(
        reason="fast_patch_bundle",
        revoked_ids={41},
    ) is True

    def adopted_full_sync(**kwargs):
        observed["queue"] = list(worker._pending_member_syncs)
        observed["sync_ids"] = set(worker._pending_member_sync_ids)
        observed["revoke_ids"] = set(worker._pending_member_revoke_ids)
        observed["confirmed_ids"] = set(worker._confirmed_member_revoke_ids)

    worker._run_standalone_full_sync = adopted_full_sync

    assert worker._drain_full_sync_commands(limit=1) == 1
    assert observed == {
        "queue": [99],
        "sync_ids": {99},
        "revoke_ids": set(),
        "confirmed_ids": {41},
    }


def test_pullsdk_full_sync_executes_adopted_revoke_before_filtered_roster(monkeypatch):
    import app.core.ultra_engine as ultra_module

    events: list[tuple[str, object]] = []

    class _FakeDeviceSyncEngine:
        def __init__(self, cfg, logger):
            self._last_single_device_error = ""

        def sync_member_on_connected_sdk(self, *, sdk, device, member_id, source):
            events.append(("targeted", member_id))
            return True

        def run_one_device_on_connected_sdk(
            self, *, sdk, cache, device, source, changed_ids,
        ):
            events.append((
                "full",
                {int(user["activeMembershipId"]) for user in cache.users},
            ))
            return True

    worker = ultra_module.UltraDeviceWorker(
        device={"id": 5, "name": "Door 1", "ipAddress": "10.0.0.5", "portNumber": 4370},
        settings={},
        popup_q=queue.Queue(),
        history_q=queue.Queue(),
        stop_event=threading.Event(),
    )
    worker._connected = True
    worker._sdk = SimpleNamespace(owns_event_source=False, _sdk="raw-sdk")
    worker._on_full_sync_finished = MagicMock()
    monkeypatch.setattr(
        ultra_module,
        "load_sync_cache",
        lambda: SimpleNamespace(
            users=[{"activeMembershipId": 41}, {"activeMembershipId": 99}],
            devices=[],
        ),
    )
    monkeypatch.setattr("app.core.device_sync.DeviceSyncEngine", _FakeDeviceSyncEngine)

    assert worker.request_member_revoke(41) is True
    assert worker.request_full_sync(
        reason="fast_patch_bundle",
        fingerprint_hash="filtered-hash",
        revoked_ids={41},
    ) is True

    assert worker._drain_full_sync_commands(limit=1) == 1
    assert events == [("targeted", 41), ("full", {99})]
    assert list(worker._pending_member_syncs) == []
    assert worker._pending_member_revoke_ids == set()
    assert worker._confirmed_member_revoke_ids == set()
    assert worker._on_full_sync_finished.call_args.kwargs["ok"] is True


def _blocked_pull_full_sync_worker(
    monkeypatch,
    outcomes: list[bool],
    *,
    block_first: bool = True,
):
    import app.core.ultra_engine as ultra_module

    events: list[tuple[str, object]] = []
    entered = threading.Event()
    release = threading.Event()
    full_index = 0

    class _FakeDeviceSyncEngine:
        def __init__(self, cfg, logger):
            self._last_single_device_error = "planned failure"

        def sync_member_on_connected_sdk(self, *, sdk, device, member_id, source):
            events.append(("targeted", member_id))
            return True

        def run_one_device_on_connected_sdk(
            self, *, sdk, cache, device, source, changed_ids,
        ):
            nonlocal full_index
            full_index += 1
            events.append((
                "full",
                {int(user["activeMembershipId"]) for user in cache.users},
            ))
            if block_first and full_index == 1:
                entered.set()
                assert release.wait(1.0)
            return outcomes[full_index - 1]

    worker = ultra_module.UltraDeviceWorker(
        device={"id": 5, "name": "Door 1", "ipAddress": "10.0.0.5", "portNumber": 4370},
        settings={},
        popup_q=queue.Queue(),
        history_q=queue.Queue(),
        stop_event=threading.Event(),
    )
    worker._connected = True
    worker._sdk = SimpleNamespace(owns_event_source=False, _sdk="raw-sdk")
    worker._on_full_sync_finished = MagicMock()
    monkeypatch.setattr(
        ultra_module,
        "load_sync_cache",
        lambda: SimpleNamespace(
            users=[
                {"activeMembershipId": 41},
                {"activeMembershipId": 43},
                {"activeMembershipId": 99},
            ],
            devices=[],
        ),
    )
    monkeypatch.setattr("app.core.device_sync.DeviceSyncEngine", _FakeDeviceSyncEngine)
    return worker, events, entered, release


def _start_active_pull_revoke(worker, entered):
    assert worker.request_member_revoke(41) is True
    assert worker.request_full_sync(
        reason="fast_patch_bundle",
        fingerprint_hash="first-hash",
        revoked_ids={41},
    ) is True
    thread = threading.Thread(target=worker._drain_full_sync_commands, kwargs={"limit": 1})
    thread.start()
    assert entered.wait(1.0)
    return thread


def test_overlapping_fulls_keep_active_revoke_out_of_every_stale_roster(monkeypatch):
    worker, events, entered, release = _blocked_pull_full_sync_worker(
        monkeypatch, [True, True],
    )
    thread = _start_active_pull_revoke(worker, entered)
    try:
        assert worker.request_member_revoke(43) is True
        assert worker.request_full_sync(
            reason="fast_patch_bundle",
            fingerprint_hash="second-hash",
            revoked_ids={41, 43},
        ) is True
        assert worker._pending_full_sync_request["revoked_ids"] == {43}
        assert worker._pending_full_sync_request["excluded_ids"] == {41, 43}
    finally:
        release.set()
        thread.join(timeout=1.0)
    assert not thread.is_alive()
    assert worker._confirmed_member_revoke_ids == {41}
    assert worker.request_member_sync(41) is False

    assert worker._drain_full_sync_commands(limit=1) == 1

    assert events == [
        ("targeted", 41),
        ("full", {43, 99}),
        ("targeted", 43),
        ("full", {99}),
    ]
    assert worker._confirmed_member_revoke_ids == set()
    assert worker._full_sync_revocation_phase == {}
    assert worker._full_sync_exclusion_phase == {}


def test_ordinary_full_queued_during_active_revoke_keeps_it_out_of_stale_roster(
        monkeypatch):
    worker, events, entered, release = _blocked_pull_full_sync_worker(
        monkeypatch, [True, True],
    )
    thread = _start_active_pull_revoke(worker, entered)
    try:
        assert worker.request_full_sync(reason="timer") is True
        assert worker._pending_full_sync_request["revoked_ids"] == set()
        assert worker._pending_full_sync_request["excluded_ids"] == {41}
    finally:
        release.set()
        thread.join(timeout=1.0)
    assert not thread.is_alive()

    assert worker._drain_full_sync_commands(limit=1) == 1

    assert events == [
        ("targeted", 41),
        ("full", {43, 99}),
        ("full", {43, 99}),
    ]


def test_failed_dependent_full_retains_exclusion_until_eventual_success(monkeypatch):
    import app.core.ultra_engine as ultra_module

    worker, events, entered, release = _blocked_pull_full_sync_worker(
        monkeypatch, [True, False, True],
    )
    thread = _start_active_pull_revoke(worker, entered)
    try:
        assert worker.request_full_sync(reason="timer") is True
    finally:
        release.set()
        thread.join(timeout=1.0)
    assert not thread.is_alive()

    assert worker._drain_full_sync_commands(limit=1) == 1
    assert worker.request_member_sync(41) is False
    assert worker._confirmed_member_revoke_ids == {41}
    assert worker._full_sync_exclusion_phase == {
        41: ultra_module._FULL_REVOKE_RETRY,
    }

    assert worker.request_full_sync(reason="timer") is True
    assert worker._pending_full_sync_request["revoked_ids"] == set()
    assert worker._pending_full_sync_request["excluded_ids"] == {41}
    assert worker._drain_full_sync_commands(limit=1) == 1

    assert [event for event in events if event[0] == "targeted"] == [
        ("targeted", 41),
    ]
    assert all(41 not in roster for kind, roster in events if kind == "full")
    assert worker._confirmed_member_revoke_ids == set()
    assert worker._full_sync_exclusion_phase == {}
    assert worker.request_member_sync(41) is True


def test_targeted_revoke_updates_older_full_before_normal_member_first_drain(monkeypatch):
    worker, events, _entered, _release = _blocked_pull_full_sync_worker(
        monkeypatch, [True], block_first=False,
    )
    assert worker.request_full_sync(reason="timer") is True

    assert worker.request_member_revoke(41) is True

    assert worker._pending_full_sync_request["revoked_ids"] == set()
    assert worker._pending_full_sync_request["excluded_ids"] == {41}
    assert worker._drain_member_sync_commands(limit=1) == 1
    assert worker._drain_full_sync_commands(limit=1) == 1
    assert events == [
        ("targeted", 41),
        ("full", {43, 99}),
    ]


def test_older_full_adopts_queued_targeted_revoke_when_full_drains_first(monkeypatch):
    worker, events, _entered, _release = _blocked_pull_full_sync_worker(
        monkeypatch, [True], block_first=False,
    )
    assert worker.request_full_sync(reason="timer") is True
    assert worker.request_member_revoke(41) is True

    assert worker._drain_full_sync_commands(limit=1) == 1

    assert events == [
        ("targeted", 41),
        ("full", {43, 99}),
    ]
    assert worker._drain_member_sync_commands(limit=1) == 0
    assert worker._pending_member_revoke_ids == set()


def _blocked_pull_targeted_revoke_worker(monkeypatch):
    import app.core.ultra_engine as ultra_module

    events: list[tuple[str, object]] = []
    entered = threading.Event()
    release = threading.Event()

    class _FakeDeviceSyncEngine:
        def __init__(self, cfg, logger):
            pass

        def sync_member_on_connected_sdk(self, *, sdk, device, member_id, source):
            events.append(("targeted", member_id))
            entered.set()
            assert release.wait(1.0)
            return True

        def run_one_device_on_connected_sdk(
            self, *, sdk, cache, device, source, changed_ids,
        ):
            events.append((
                "full",
                {int(user["activeMembershipId"]) for user in cache.users},
            ))
            return True

    worker = ultra_module.UltraDeviceWorker(
        device={"id": 5, "name": "Door 1", "ipAddress": "10.0.0.5", "portNumber": 4370},
        settings={},
        popup_q=queue.Queue(),
        history_q=queue.Queue(),
        stop_event=threading.Event(),
    )
    worker._connected = True
    worker._sdk = SimpleNamespace(owns_event_source=False, _sdk="raw-sdk")
    monkeypatch.setattr(
        ultra_module,
        "load_sync_cache",
        lambda: SimpleNamespace(
            users=[
                {"activeMembershipId": 41},
                {"activeMembershipId": 43},
            ],
            devices=[],
        ),
    )
    monkeypatch.setattr("app.core.device_sync.DeviceSyncEngine", _FakeDeviceSyncEngine)
    return worker, events, entered, release


def test_required_full_refresh_during_active_targeted_revoke_is_exclusion_only(
        monkeypatch):
    worker, events, entered, release = _blocked_pull_targeted_revoke_worker(monkeypatch)

    assert worker.request_member_revoke(41) is True
    thread = threading.Thread(target=worker._drain_member_sync_commands, kwargs={"limit": 1})
    thread.start()
    assert entered.wait(1.0)
    try:
        assert worker.request_member_sync(41) is False
        assert worker.request_member_revoke(41) is False
        assert worker.has_pending_member_revoke(41) is True
        assert worker._active_member_revoke_ids == {41}
        assert list(worker._pending_member_syncs) == []
        assert worker.request_full_sync(
            reason="retry",
            revoked_ids={41},
        ) is True
        assert worker._pending_full_sync_request is None
        assert worker.request_full_sync(
            reason="device_refresh",
            revoked_ids={41},
            require_full_refresh=True,
        ) is True
        assert worker._pending_full_sync_request["revoked_ids"] == set()
        assert worker._pending_full_sync_request["excluded_ids"] == {41}
        assert worker._pending_full_sync_request["require_full_refresh"] is True
    finally:
        release.set()
        thread.join(timeout=1.0)
    assert not thread.is_alive()
    assert worker._active_member_revoke_ids == set()
    assert worker.has_pending_member_revoke(41) is True
    assert worker._drain_full_sync_commands(limit=1) == 1
    assert worker.has_pending_member_revoke(41) is False
    assert events == [
        ("targeted", 41),
        ("full", {43}),
    ]


def test_engine_preserves_full_refresh_when_targeted_revoke_becomes_active(monkeypatch):
    import app.core.ultra_engine as ultra_module

    worker, events, entered, release = _blocked_pull_targeted_revoke_worker(monkeypatch)
    request_member_revoke = worker.request_member_revoke
    drain_threads: list[threading.Thread] = []

    def request_and_activate(member_id):
        accepted = request_member_revoke(member_id)
        thread = threading.Thread(
            target=worker._drain_member_sync_commands,
            kwargs={"limit": 1},
        )
        drain_threads.append(thread)
        thread.start()
        assert entered.wait(1.0)
        return accepted

    worker.request_member_revoke = request_and_activate
    worker.is_alive = lambda: True
    scheduler = SimpleNamespace(
        _devices=[worker._device],
        request_sync_now=MagicMock(),
    )
    engine = SimpleNamespace(
        _running=True,
        _sync_scheduler=scheduler,
        _workers={5: worker},
        _logger=MagicMock(),
    )

    try:
        assert ultra_module.UltraEngine.request_sync_now(
            engine,
            changed_ids=None,
            revoked_ids={41},
            device_ids={5},
            reason="device_refresh",
        ) is True
        assert worker._active_member_revoke_ids == {41}
        assert worker._pending_full_sync_request["revoked_ids"] == set()
        assert worker._pending_full_sync_request["excluded_ids"] == {41}
        assert worker._pending_full_sync_request["require_full_refresh"] is True
        scheduler.request_sync_now.assert_not_called()
    finally:
        release.set()
        for thread in drain_threads:
            thread.join(timeout=1.0)
            assert not thread.is_alive()

    assert worker._drain_full_sync_commands(limit=1) == 1
    assert events == [
        ("targeted", 41),
        ("full", {43}),
    ]
    assert worker.has_pending_member_revoke(41) is False
    assert worker._confirmed_member_revoke_ids == set()


def test_engine_full_merge_remains_handled_when_worker_drains_before_return_check(
        monkeypatch):
    import app.core.ultra_engine as ultra_module

    worker, events, _entered, _release = _blocked_pull_full_sync_worker(
        monkeypatch,
        [True],
        block_first=False,
    )
    assert worker.request_full_sync(
        reason="initial_refresh",
        revoked_ids={41},
        require_full_refresh=True,
    ) is True
    request_full_sync = worker.request_full_sync
    has_pending_full_sync = worker.has_pending_full_sync
    worker.has_pending_full_sync = MagicMock(wraps=has_pending_full_sync)

    def merge_then_complete(**kwargs):
        handled = request_full_sync(**kwargs)
        assert worker._drain_full_sync_commands(limit=1) == 1
        return handled

    worker.request_full_sync = merge_then_complete
    worker.is_alive = lambda: True
    scheduler = SimpleNamespace(
        _devices=[worker._device],
        request_sync_now=MagicMock(),
    )
    engine = SimpleNamespace(
        _running=True,
        _sync_scheduler=scheduler,
        _workers={5: worker},
        _logger=MagicMock(),
    )

    assert ultra_module.UltraEngine.request_sync_now(
        engine,
        changed_ids=None,
        revoked_ids={41},
        device_ids={5},
        reason="device_refresh",
    ) is True

    scheduler.request_sync_now.assert_not_called()
    worker.has_pending_full_sync.assert_not_called()
    assert events == [
        ("targeted", 41),
        ("full", {43, 99}),
    ]
    assert worker.has_pending_member_revoke(41) is False


def test_revoke_first_full_second_adopts_targeted_before_member_drain(monkeypatch):
    worker, events, _entered, _release = _blocked_pull_full_sync_worker(
        monkeypatch, [True], block_first=False,
    )
    assert worker.request_member_revoke(41) is True

    assert worker.request_full_sync(reason="timer") is True

    assert worker._pending_full_sync_request["revoked_ids"] == {41}
    assert worker._pending_full_sync_request["excluded_ids"] == {41}
    assert worker._drain_member_sync_commands(limit=1) == 0
    assert worker._drain_full_sync_commands(limit=1) == 1
    assert events == [
        ("targeted", 41),
        ("full", {43, 99}),
    ]


def test_revoke_first_full_second_adopts_targeted_before_full_drain(monkeypatch):
    worker, events, _entered, _release = _blocked_pull_full_sync_worker(
        monkeypatch, [True], block_first=False,
    )
    assert worker.request_member_revoke(41) is True
    assert worker.request_full_sync(reason="timer") is True

    assert worker._drain_full_sync_commands(limit=1) == 1

    assert events == [
        ("targeted", 41),
        ("full", {43, 99}),
    ]
    assert worker._drain_member_sync_commands(limit=1) == 0
    assert worker._pending_member_revoke_ids == set()


def test_targeted_only_success_allows_later_full_reenrolment_and_new_revoke(
        monkeypatch):
    worker, events, _entered, _release = _blocked_pull_full_sync_worker(
        monkeypatch, [True], block_first=False,
    )
    assert worker.request_member_revoke(41) is True
    assert worker._drain_member_sync_commands(limit=1) == 1
    assert worker.has_pending_member_revoke(41) is False
    assert worker._confirmed_member_revoke_ids == set()

    assert worker.request_full_sync(reason="timer") is True
    assert worker._drain_full_sync_commands(limit=1) == 1
    assert worker.request_member_revoke(41) is True
    assert worker._drain_member_sync_commands(limit=1) == 1

    assert events == [
        ("targeted", 41),
        ("full", {41, 43, 99}),
        ("targeted", 41),
    ]


def test_standalone_member_command_drain_routes_captured_action():
    import app.core.ultra_engine as ultra_module

    worker = _member_command_worker(ultra_module)
    worker._sdk = SimpleNamespace(owns_event_source=True)
    worker._connected = True
    worker._run_standalone_member_sync = MagicMock()
    worker._run_standalone_member_revoke = MagicMock()

    worker.request_member_sync(41)
    worker.request_member_revoke(42)

    assert worker._drain_member_sync_commands(limit=2) == 2
    worker._run_standalone_member_sync.assert_called_once_with(41)
    worker._run_standalone_member_revoke.assert_called_once_with(42)
    assert worker._pending_member_sync_ids == set()
    assert worker._pending_member_revoke_ids == set()


def test_failed_standalone_revoke_requests_full_reconcile():
    import app.core.ultra_engine as ultra_module

    worker = _member_command_worker(ultra_module)
    worker._sdk = SimpleNamespace(owns_event_source=True)
    worker._connected = True
    worker._prefix = "[ULTRA:5]"
    worker._tel_wid = "ULTRA:5"
    worker._run_standalone_member_revoke = MagicMock(side_effect=RuntimeError("boom"))
    worker.request_full_sync = MagicMock(return_value=True)

    worker.request_member_revoke(41)

    assert worker._drain_member_sync_commands(limit=1) == 1
    worker.request_full_sync.assert_called_once_with(
        reason="revoke-handler-failed",
        revoked_ids={41},
    )
    assert list(worker._pending_member_syncs) == [41]
    assert worker._pending_member_revoke_ids == {41}
    assert worker._active_member_revoke_ids == set()


def test_disconnected_standalone_revoke_is_requeued_with_revoke_intent():
    import app.core.ultra_engine as ultra_module

    worker = _member_command_worker(ultra_module)
    worker._sdk = SimpleNamespace(owns_event_source=True)
    worker._connected = False

    worker.request_member_revoke(41)
    worker._wake_evt.clear()

    assert worker._drain_member_sync_commands(limit=1) == 0
    assert list(worker._pending_member_syncs) == [41]
    assert worker._pending_member_sync_ids == {41}
    assert worker._pending_member_revoke_ids == {41}
    assert worker._wake_evt.is_set()


def test_pullsdk_member_revoke_uses_targeted_member_sync(monkeypatch):
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

    worker.request_member_revoke(41)

    assert worker._drain_member_sync_commands(limit=1) == 1
    assert synced_members == [("raw-sdk", 41, "ultra_targeted_member_sync")]


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
    assert worker.request_full_sync(reason="device_refresh") is True

    drained = worker._drain_full_sync_commands(limit=1)

    assert drained == 1
    assert full_sync_calls == [
        ("raw-sdk", "device_refresh", [{"activeMembershipId": 11}]),
    ]


def test_pending_full_sync_is_upgraded_with_revocation_without_stale_fingerprint():
    import app.core.ultra_engine as ultra_module

    worker = ultra_module.UltraDeviceWorker(
        device={"id": 5, "name": "Door 1"},
        settings={},
        popup_q=queue.Queue(),
        history_q=queue.Queue(),
        stop_event=threading.Event(),
    )

    assert worker.request_full_sync(
        reason="timer",
        fingerprint_hash="stale-roster-hash",
    ) is True
    assert worker.request_full_sync(
        reason="fast_patch_bundle",
        revoked_ids={17},
    ) is True

    assert worker.has_pending_full_sync(revoked_ids={17}) is True
    assert worker._pending_full_sync_request["fingerprint_hash"] is None


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

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock


def make_device(dev_id=1, *, fingerprint_enabled=False):
    return {
        "id": dev_id,
        "name": f"Device {dev_id}",
        "ipAddress": f"10.0.0.{dev_id}",
        "portNumber": 4370,
        "password": "",
        "active": True,
        "accessDevice": True,
        "accessDataMode": "DEVICE",
        "fingerprintEnabled": fingerprint_enabled,
        "authorizeTimezoneId": 1,
        "doorIds": [15],
        "doorPresets": [],
        "pushingToDevicePolicy": "ALL",
    }


def make_user(am_id):
    return {
        "activeMembershipId": am_id,
        "membershipId": am_id,
        "fullName": f"User {am_id}",
        "validFrom": "2026-01-01",
        "validTo": "2026-12-31",
        "firstCardId": str(am_id * 100),
        "fingerprints": [],
    }


def test_sync_all_devices_routes_full_reconcile_to_actor_registry(monkeypatch):
    from app.core.device_sync import DeviceSyncEngine

    engine = DeviceSyncEngine(cfg=MagicMock(), logger=logging.getLogger("test"))
    fake_registry = SimpleNamespace(
        update_devices=MagicMock(),
        enqueue_full_reconcile=MagicMock(return_value=2),
        enqueue_targeted_sync=MagicMock(return_value=0),
        stop_all=MagicMock(),
    )
    progress_calls = []

    monkeypatch.setattr(engine, "_actor_registry", fake_registry)
    monkeypatch.setattr("app.core.device_sync.list_fingerprints", lambda: [])
    monkeypatch.setattr(engine, "_set_progress", lambda **kwargs: progress_calls.append(kwargs))

    engine._sync_all_devices(
        cache=SimpleNamespace(
            users=[make_user(1), make_user(2)],
            devices=[make_device(7), make_device(8)],
        ),
        changed_ids=None,
        sync_run_id=501,
    )

    fake_registry.update_devices.assert_called_once()
    fake_registry.enqueue_full_reconcile.assert_called_once_with(device_ids={7, 8})
    fake_registry.enqueue_targeted_sync.assert_not_called()
    assert progress_calls[-1]["total"] == 2


def test_sync_all_devices_skips_actor_dispatch_for_empty_delta(monkeypatch):
    from app.core.device_sync import DeviceSyncEngine

    engine = DeviceSyncEngine(cfg=MagicMock(), logger=logging.getLogger("test"))
    fake_registry = SimpleNamespace(
        update_devices=MagicMock(),
        enqueue_full_reconcile=MagicMock(return_value=0),
        enqueue_targeted_sync=MagicMock(return_value=1),
        stop_all=MagicMock(),
    )

    monkeypatch.setattr(engine, "_actor_registry", fake_registry)
    monkeypatch.setattr("app.core.device_sync.list_fingerprints", lambda: [])
    monkeypatch.setattr(engine, "_set_progress", lambda **kwargs: None)

    cache = SimpleNamespace(users=[make_user(11)], devices=[make_device(7)])

    engine._sync_all_devices(cache=cache, changed_ids={11}, sync_run_id=601)
    engine._sync_all_devices(cache=cache, changed_ids=set(), sync_run_id=602)

    assert fake_registry.enqueue_targeted_sync.call_args_list[0].kwargs == {
        "device_ids": {7},
        "member_ids": {11},
    }
    assert len(fake_registry.enqueue_targeted_sync.call_args_list) == 1
    fake_registry.enqueue_full_reconcile.assert_not_called()


def test_sync_all_devices_skips_global_fingerprint_scan_when_no_device_uses_fingerprints(monkeypatch):
    from app.core.device_sync import DeviceSyncEngine

    engine = DeviceSyncEngine(cfg=MagicMock(), logger=logging.getLogger("test"))
    fake_registry = SimpleNamespace(
        update_devices=MagicMock(),
        enqueue_full_reconcile=MagicMock(return_value=1),
        enqueue_targeted_sync=MagicMock(return_value=0),
        stop_all=MagicMock(),
    )
    fingerprint_calls = {"count": 0}

    def fake_list_fingerprints():
        fingerprint_calls["count"] += 1
        return []

    monkeypatch.setattr(engine, "_actor_registry", fake_registry)
    monkeypatch.setattr("app.core.device_sync.list_fingerprints", fake_list_fingerprints)
    monkeypatch.setattr(engine, "_set_progress", lambda **kwargs: None)

    engine._sync_all_devices(
        cache=SimpleNamespace(
            users=[make_user(1)],
            devices=[make_device(7, fingerprint_enabled=False)],
        ),
        changed_ids=None,
    )

    assert fingerprint_calls["count"] == 0

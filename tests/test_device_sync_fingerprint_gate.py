from __future__ import annotations

import types
from types import SimpleNamespace
from unittest.mock import MagicMock


def test_run_one_device_blocking_skips_local_fingerprint_scan_when_device_fingerprint_disabled(monkeypatch):
    import app.core.device_sync as device_sync_module

    engine = device_sync_module.DeviceSyncEngine(cfg=SimpleNamespace(), logger=MagicMock())
    captured: dict[str, object] = {}
    calls = {"list_fingerprints": 0}

    def fake_list_fingerprints():
        calls["list_fingerprints"] += 1
        return []

    monkeypatch.setattr(device_sync_module, "list_fingerprints", fake_list_fingerprints)
    monkeypatch.setattr(engine, "_default_authorize_door_id", lambda: None)
    monkeypatch.setattr(engine, "_set_progress", lambda **kwargs: None)

    def fake_sync_one_device(self, *, device, users, local_fp_index, default_door_id, changed_ids=None, sync_run_id=None):
        captured["local_fp_index"] = local_fp_index

    monkeypatch.setattr(
        engine,
        "_sync_one_device",
        types.MethodType(fake_sync_one_device, engine),
    )

    did_run = engine.run_one_device_blocking(
        cache=SimpleNamespace(users=[]),
        device={
            "id": 5,
            "name": "Door 1",
            "active": True,
            "accessDevice": True,
            "fingerprintEnabled": False,
        },
        source="test",
    )

    assert did_run is True
    assert calls["list_fingerprints"] == 0
    assert captured["local_fp_index"] == {}

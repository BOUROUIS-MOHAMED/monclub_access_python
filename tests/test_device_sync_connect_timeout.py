from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


def _make_engine(tmp_path, monkeypatch, *, cfg_timeout_ms=0):
    import app.core.db as db_module

    db_path = str(tmp_path / "connect_timeout.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()

    from app.core.device_sync import DeviceSyncEngine

    cfg = SimpleNamespace(plcomm_dll_path="C:\\fake\\plcommpro.dll")
    if cfg_timeout_ms:
        cfg.timeout_ms = cfg_timeout_ms
    return DeviceSyncEngine(cfg=cfg, logger=logging.getLogger("test"))


def _make_device(dev_id=1, *, timeout_ms=None, connect_timeout_ms=None):
    device = {
        "id": dev_id,
        "name": "Timeout Device",
        "ipAddress": "10.0.0.1",
        "portNumber": 4370,
        "password": "",
        "active": True,
        "accessDevice": True,
        "accessDataMode": "DEVICE",
        "fingerprintEnabled": False,
        "authorizeTimezoneId": 1,
        "doorIds": [15],
        "doorPresets": [],
        "pushingToDevicePolicy": "ALL",
    }
    if timeout_ms is not None:
        device["timeoutMs"] = timeout_ms
    if connect_timeout_ms is not None:
        device["connectTimeoutMs"] = connect_timeout_ms
    return device


def _patch_sdk():
    sdk_cls = MagicMock()
    sdk_inst = MagicMock()
    sdk_cls.return_value = sdk_inst
    sdk_inst.get_device_data_rows.return_value = []
    sdk_inst.supports_delete_device_data.return_value = True
    sdk_inst.set_device_data.return_value = None
    sdk_inst.delete_device_data.return_value = None
    sdk_inst.disconnect.return_value = None
    return sdk_cls, sdk_inst


def test_sync_one_device_prefers_device_timeout_ms_over_global_default(tmp_path, monkeypatch) -> None:
    engine = _make_engine(tmp_path, monkeypatch, cfg_timeout_ms=5000)
    sdk_cls, sdk_inst = _patch_sdk()

    with patch("app.core.device_sync.PullSDK", sdk_cls):
        engine._sync_one_device(
            device=_make_device(timeout_ms=1200),
            users=[],
            local_fp_index={},
            default_door_id=15,
        )

    assert sdk_inst.connect.call_args.kwargs["timeout_ms"] == 1200


def test_sync_one_device_defaults_connect_timeout_to_pullsdk_device_default(tmp_path, monkeypatch) -> None:
    engine = _make_engine(tmp_path, monkeypatch)
    sdk_cls, sdk_inst = _patch_sdk()

    with patch("app.core.device_sync.PullSDK", sdk_cls):
        engine._sync_one_device(
            device=_make_device(),
            users=[],
            local_fp_index={},
            default_door_id=15,
        )

    assert sdk_inst.connect.call_args.kwargs["timeout_ms"] == 3000

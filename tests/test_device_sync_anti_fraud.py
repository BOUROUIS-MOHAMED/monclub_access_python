"""
Verify _normalize_device reads anti-fraud columns.
The SetDeviceParam push is tested via the full sync pathway through
integration tests; here we focus on _normalize_device field extraction.
"""
from __future__ import annotations

import pytest
from app.core.device_sync import DeviceSyncEngine


def _make_sync() -> DeviceSyncEngine:
    import logging
    return DeviceSyncEngine(cfg=None, logger=logging.getLogger("test"))


def _make_row(overrides=None) -> dict:
    base = {
        "id": 1,
        "name": "Door 1",
        "active": 1,
        "access_device": 1,
        "ip_address": "192.168.1.5",
        "port_number": "4370",
        "password": "",
        "access_data_mode": "DEVICE",
        "door_ids_json": "[1]",
        "doorIds": [1],
        "allowed_memberships_json": "[]",
        "authorize_timezone_id": 1,
        "pushing_to_device_policy": "MERGE",
        "door_presets": [],
        "anti_fraude_card": 1,
        "anti_fraude_qr_code": 1,
        "anti_fraude_duration": 30,
    }
    return {**base, **(overrides or {})}


class TestNormalizeDevice:
    def test_anti_fraude_card_true_when_one(self):
        svc = _make_sync()
        result = svc._normalize_device(_make_row())
        assert result["anti_fraude_card"] is True

    def test_anti_fraude_card_false_when_zero(self):
        svc = _make_sync()
        result = svc._normalize_device(_make_row({"anti_fraude_card": 0}))
        assert result["anti_fraude_card"] is False

    def test_anti_fraude_qr_true_by_default(self):
        svc = _make_sync()
        result = svc._normalize_device(_make_row())
        assert result["anti_fraude_qr_code"] is True

    def test_anti_fraude_qr_false_when_zero(self):
        svc = _make_sync()
        result = svc._normalize_device(_make_row({"anti_fraude_qr_code": 0}))
        assert result["anti_fraude_qr_code"] is False

    def test_anti_fraude_duration_default_30(self):
        svc = _make_sync()
        result = svc._normalize_device(_make_row())
        assert result["anti_fraude_duration"] == 30

    def test_anti_fraude_duration_custom(self):
        svc = _make_sync()
        result = svc._normalize_device(_make_row({"anti_fraude_duration": 60}))
        assert result["anti_fraude_duration"] == 60

    def test_anti_fraude_duration_none_falls_back_to_30(self):
        svc = _make_sync()
        result = svc._normalize_device(_make_row({"anti_fraude_duration": None}))
        assert result["anti_fraude_duration"] == 30

    def test_camelcase_keys_also_work(self):
        """_normalize_device accepts both snake_case and camelCase input."""
        svc = _make_sync()
        row = {
            "id": 2, "name": "test",
            "antiFraudeCard": False,
            "antiFraudeQrCode": False,
            "antiFraudeDuration": 120,
        }
        result = svc._normalize_device(row)
        assert result["anti_fraude_card"] is False
        assert result["anti_fraude_qr_code"] is False
        assert result["anti_fraude_duration"] == 120

"""Verify anti-fraud keys are returned by normalize_device_settings."""
from app.core.settings_reader import normalize_device_settings


def _norm(overrides: dict) -> dict:
    base = {
        "id": 1,
        "name": "test",
        "active": True,
        "accessDevice": True,
        "accessDataMode": "AGENT",
        "ipAddress": "192.168.1.1",
        "portNumber": "4370",
        "totpEnabled": True,
        "rfidEnabled": True,
    }
    return normalize_device_settings({**base, **overrides})


class TestAntiFraudDefaults:
    def test_default_card_enabled(self):
        s = _norm({})
        assert s["anti_fraude_card"] is True

    def test_default_qr_enabled(self):
        s = _norm({})
        assert s["anti_fraude_qr_code"] is True

    def test_default_duration(self):
        s = _norm({})
        assert s["anti_fraude_duration"] == 30


class TestAntiFraudOverrides:
    def test_card_disabled(self):
        s = _norm({"antiFraudeCard": False})
        assert s["anti_fraude_card"] is False

    def test_card_disabled_integer_zero(self):
        s = _norm({"antiFraudeCard": 0})
        assert s["anti_fraude_card"] is False

    def test_qr_disabled(self):
        s = _norm({"antiFraudeQrCode": False})
        assert s["anti_fraude_qr_code"] is False

    def test_custom_duration(self):
        s = _norm({"antiFraudeDuration": 60})
        assert s["anti_fraude_duration"] == 60

    def test_duration_clamped_low(self):
        s = _norm({"antiFraudeDuration": 1})
        assert s["anti_fraude_duration"] == 5  # lo=5

    def test_duration_clamped_high(self):
        s = _norm({"antiFraudeDuration": 9999})
        assert s["anti_fraude_duration"] == 300  # hi=300

    def test_duration_none_uses_default(self):
        s = _norm({"antiFraudeDuration": None})
        assert s["anti_fraude_duration"] == 30


class TestAntiFraudDailyPassLimit:
    def test_default_daily_pass_limit_is_zero(self):
        s = _norm({})
        assert s["anti_fraude_daily_pass_limit"] == 0

    def test_custom_daily_pass_limit(self):
        s = _norm({"antiFraudeDailyPassLimit": 7})
        assert s["anti_fraude_daily_pass_limit"] == 7

    def test_daily_pass_limit_clamped_low(self):
        s = _norm({"antiFraudeDailyPassLimit": -5})
        assert s["anti_fraude_daily_pass_limit"] == 0  # lo=0

    def test_daily_pass_limit_clamped_high(self):
        s = _norm({"antiFraudeDailyPassLimit": 500})
        assert s["anti_fraude_daily_pass_limit"] == 100  # hi=100

    def test_daily_pass_limit_none_uses_default(self):
        s = _norm({"antiFraudeDailyPassLimit": None})
        assert s["anti_fraude_daily_pass_limit"] == 0

    def test_coerce_device_row_exposes_daily_pass_limit(self):
        """Verify the db.py round-trip from SQLite row to payload dict."""
        from app.core.db import _coerce_device_row_to_payload
        row = {
            "id": 1,
            "name": "test",
            "anti_fraude_daily_pass_limit": 12,
        }
        payload = _coerce_device_row_to_payload(row)
        assert payload["antiFraudeDailyPassLimit"] == 12

    def test_device_sync_normalize_exposes_daily_pass_limit(self):
        """Verify device_sync.py _normalize_device includes the new key."""
        from app.core.device_sync import DeviceSyncEngine
        engine = DeviceSyncEngine.__new__(DeviceSyncEngine)
        # Smoke call the unbound method directly (no engine init needed)
        out = DeviceSyncEngine._normalize_device(engine, {
            "antiFraudeDailyPassLimit": 15,
        })
        assert out["anti_fraude_daily_pass_limit"] == 15

    def test_device_sync_normalize_defaults_daily_pass_limit_to_zero(self):
        from app.core.device_sync import DeviceSyncEngine
        engine = DeviceSyncEngine.__new__(DeviceSyncEngine)
        out = DeviceSyncEngine._normalize_device(engine, {})
        assert out["anti_fraude_daily_pass_limit"] == 0

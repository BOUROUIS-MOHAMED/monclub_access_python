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

from app.core.config import AppConfig
from shared.config import ACCESS_CONFIG_FIELDS


def test_scanner_fields_are_part_of_access_config_fields() -> None:
    expected = {
        "scanner_mode",
        "scanner_network_ip",
        "scanner_network_port",
        "scanner_network_timeout_ms",
        "scanner_usb_device_path",
    }
    missing = expected.difference(set(ACCESS_CONFIG_FIELDS))
    assert not missing


def test_scanner_mode_accepts_zkemkeeper() -> None:
    cfg = AppConfig.from_dict({"scanner_mode": "zkemkeeper"})
    assert cfg.scanner_mode == "zkemkeeper"


def test_scanner_mode_defaults_to_zkemkeeper_when_missing() -> None:
    cfg = AppConfig.from_dict({})
    assert cfg.scanner_mode == "zkemkeeper"

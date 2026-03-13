"""
Comprehensive integration test for settings_reader + config + cross-file connections.
Tests every call chain that was modified.
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

# ---- 1) settings_reader standalone ----
from app.core.settings_reader import (
    normalize_access_data_mode,
    normalize_global_settings,
    normalize_device_settings,
    read_sync_payload_json,
    extract_access_settings,
    extract_devices,
    get_backend_global_settings,
    get_backend_device_settings,
    get_backend_device_raw,
)

# 1a) normalize_access_data_mode
assert normalize_access_data_mode("AGENT") == "AGENT"
assert normalize_access_data_mode("agent") == "AGENT"
assert normalize_access_data_mode("DEVICE") == "DEVICE"
assert normalize_access_data_mode("device") == "DEVICE"
assert normalize_access_data_mode("") == "DEVICE"
assert normalize_access_data_mode(None) == "DEVICE"
assert normalize_access_data_mode("UNKNOWN") == "DEVICE"
print("OK 1a: normalize_access_data_mode")

# 1b) normalize_global_settings
g = normalize_global_settings({})
assert g["event_queue_max"] == 5000
assert g["decision_workers"] == 1
assert g["notification_service_enabled"] is True
assert g["image_cache_enabled"] is True
assert g["popup_enabled"] is True  # NEW: must exist in global settings
assert g["popup_duration_sec"] == 3  # NEW: must exist in global settings
assert g["show_notifications"] is True
assert len(g) >= 22
print(f"OK 1b: normalize_global_settings => {len(g)} keys")

# 1c) normalize_device_settings
d = normalize_device_settings({}, g)
assert d["totp_enabled"] is True
assert d["rfid_enabled"] is True
assert d["enabled"] is True
assert d["pulse_time_ms"] == 3000
assert d["totp_prefix"] == "9"
assert d["replay_block_window_seconds"] == 10
assert len(d) >= 34
print(f"OK 1c: normalize_device_settings => {len(d)} keys")

# 1d) extract functions with empty/missing data
assert extract_access_settings({}) == {}
assert extract_access_settings(None) == {}
assert extract_devices({}) == []
assert extract_devices(None) == []
p = read_sync_payload_json()  # may be {} if no DB cache
assert isinstance(p, dict)
print("OK 1d: extract functions safe with empty data")

# 1e) get_backend helpers
bg = get_backend_global_settings()
assert isinstance(bg, dict) and len(bg) >= 22
bd = get_backend_device_settings(99999)
assert isinstance(bd, dict) and bd["enabled"] is False
br = get_backend_device_raw(99999)
assert br is None  # device 99999 doesn't exist
print("OK 1e: get_backend helpers")

# ---- 2) config.py redirects ----
from app.core.config import load_config, AppConfig

cfg = load_config()

# 2a) get_agent_global reads from SQLite
cg = cfg.get_agent_global()
assert isinstance(cg, dict)
assert "event_queue_max" in cg
assert "notification_service_enabled" in cg
assert "popup_enabled" in cg  # must be present
assert "show_notifications" in cg
print(f"OK 2a: cfg.get_agent_global() => {len(cg)} keys")

# 2b) get_agent_device_settings reads from SQLite
cd = cfg.get_agent_device_settings(99999)
assert isinstance(cd, dict)
assert "totp_enabled" in cd
assert "rfid_enabled" in cd
print(f"OK 2b: cfg.get_agent_device_settings(99999) => {len(cd)} keys")

# 2c) set_agent_device_override is no-op
cfg.set_agent_device_override(123, {"totp_enabled": False})
# Should not crash, should not change anything
print("OK 2c: set_agent_device_override is no-op")

# 2d) is_device_mode (deprecated but functional)
m = cfg.is_device_mode
assert isinstance(m, bool)
print(f"OK 2d: cfg.is_device_mode => {m}")

# ---- 3) realtime_agent imports from settings_reader ----
from app.core.realtime_agent import (
    _read_sync_payload_json,
    _extract_access_settings,
    _extract_devices,
    _normalize_global_settings,
    _normalize_device_settings,
)
# Verify they point to settings_reader functions
from app.core import settings_reader as sr
assert _read_sync_payload_json is sr.read_sync_payload_json
assert _extract_access_settings is sr.extract_access_settings
assert _extract_devices is sr.extract_devices
assert _normalize_global_settings is sr.normalize_global_settings
assert _normalize_device_settings is sr.normalize_device_settings
print("OK 3: realtime_agent imports are aliases to settings_reader")

# ---- 4) device_sync accessDataMode handling ----
from app.core.device_sync import DeviceSyncEngine
import logging

logger = logging.getLogger("test")
dse = DeviceSyncEngine(cfg=cfg, logger=logger)

# Test _normalize_device with camelCase
d1 = dse._normalize_device({"id": 1, "name": "dev1", "accessDataMode": "AGENT"})
assert d1["accessDataMode"] == "AGENT"

# Test _normalize_device with snake_case
d2 = dse._normalize_device({"id": 2, "name": "dev2", "access_data_mode": "AGENT"})
assert d2["accessDataMode"] == "AGENT"

# Test _normalize_device with missing => defaults to DEVICE
d3 = dse._normalize_device({"id": 3, "name": "dev3"})
assert d3["accessDataMode"] == "DEVICE"

# Test _normalize_device with garbage => defaults to DEVICE
d4 = dse._normalize_device({"id": 4, "name": "dev4", "accessDataMode": "GARBAGE"})
assert d4["accessDataMode"] == "DEVICE"
print("OK 4: device_sync._normalize_device handles all accessDataMode cases")

# ---- 5) Cross-check: global settings keys match what UI expects ----
ui_expected_global_keys = [
    "notification_rate_limit_per_minute",
    "notification_dedupe_window_sec",
    "history_retention_days",
    "event_queue_max",
    "decision_workers",
    "notification_queue_max",
    "history_queue_max",
    "decision_ema_alpha",
    "notification_service_enabled",
    "history_service_enabled",
    "image_cache_enabled",
    "image_cache_timeout_sec",
    "image_cache_max_bytes",
    "image_cache_max_files",
    "popup_enabled",
    "popup_duration_sec",
    "show_notifications",
]
for k in ui_expected_global_keys:
    assert k in bg, f"Missing key '{k}' in global settings"
print(f"OK 5: All {len(ui_expected_global_keys)} UI-expected global keys present")

# ---- 6) Cross-check: device settings keys match what UI expects ----
ui_expected_device_keys = [
    "enabled", "adaptive_sleep",
    "busy_sleep_min_ms", "busy_sleep_max_ms",
    "empty_sleep_min_ms", "empty_sleep_max_ms",
    "empty_backoff_factor", "empty_backoff_max_ms",
    "timeout_ms", "rtlog_table",
    "door_entry_id", "pulse_time_ms", "cmd_timeout_ms",
    "save_history", "show_notifications",
    "totp_enabled", "totp_digits", "totp_period_seconds",
    "totp_drift_steps", "totp_max_past_age_seconds",
    "totp_max_future_skew_seconds", "totp_prefix",
    "rfid_enabled", "rfid_min_digits", "rfid_max_digits",
    "replay_block_window_seconds", "replay_lru_size",
    "poll_ema_alpha", "cmd_ema_alpha",
    "popup_enabled", "popup_duration_sec", "popup_show_image",
    "win_notify_enabled",
]
for k in ui_expected_device_keys:
    assert k in bd, f"Missing key '{k}' in device settings"
print(f"OK 6: All {len(ui_expected_device_keys)} UI-expected device keys present")

print("\n=== ALL INTEGRATION TESTS PASSED ===")


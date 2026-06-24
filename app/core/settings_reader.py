# app/core/settings_reader.py
"""
Shared helpers to read backend-driven settings from SQLite.

Source of truth:
- Global settings come from GymAccessSoftwareSettingsDto stored in SQLite table:
  `sync_access_software_settings` (single row, id=1).
- Per-device settings come from GymDeviceDto stored in SQLite table:
  `sync_devices`.

These settings are READ-ONLY from the desktop app perspective:
only the backend can modify them; the desktop app only consumes them.

This module provides normalization/clamping so config.py, app.py, realtime_agent.py,
device_sync.py, and UI pages can consume consistent snake_case settings without
circular imports.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# In-memory cache for get_backend_global_settings().
#
# Measured in production (gym PC, 2026-06-22): this helper was called 229 times
# in 27 minutes and EACH call hit SQLite (load_sync_access_software_settings or
# the giant payload_json fallback) costing ~1s on that machine — ~226s of pure
# waste that also contends with the worker's reads/writes. Global settings change
# rarely (only on a settings sync), so a short TTL cache is safe and removes the
# repeated DB hits. invalidate_global_settings_cache() is called after a settings
# refresh so a real change applies immediately.
# ---------------------------------------------------------------------------
_GLOBAL_SETTINGS_CACHE: Dict[str, Any] = {"value": None, "ts": 0.0}
_GLOBAL_SETTINGS_LOCK = threading.Lock()
_GLOBAL_SETTINGS_TTL_SEC = 30.0


def invalidate_global_settings_cache() -> None:
    """Drop the cached global settings so the next read reloads from DB.

    Call after a settings sync so a dashboard change applies without waiting for
    the TTL. Never raises.
    """
    try:
        with _GLOBAL_SETTINGS_LOCK:
            _GLOBAL_SETTINGS_CACHE["value"] = None
            _GLOBAL_SETTINGS_CACHE["ts"] = 0.0
    except Exception:
        pass


# --------------- generic helpers (local to avoid circular imports) ---------------

def _safe_int(v: Any, default: int = 0) -> int:
    try:
        if v is None:
            return default
        if isinstance(v, bool):
            return int(v)
        return int(float(str(v).strip()))
    except Exception:
        return default


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None:
            return default
        return float(str(v).strip())
    except Exception:
        return default


def _safe_str(v: Any, default: str = "") -> str:
    if v is None:
        return default
    try:
        return str(v)
    except Exception:
        return default


def _boolish(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return int(v) != 0
    s = _safe_str(v, "").strip().lower()
    if s in ("1", "true", "yes", "y", "on"):
        return True
    if s in ("0", "false", "no", "n", "off"):
        return False
    return default


def _clamp_int(v: Any, default: int, lo: int, hi: int) -> int:
    x = _safe_int(v, default)
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x


def _clamp_float(v: Any, default: float, lo: float, hi: float) -> float:
    x = _safe_float(v, default)
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x


def _parse_duration_minutes(v: Any, default_minutes: int = 30, *, min_minutes: int = 1, max_minutes: int = 1440) -> int:
    if v is None:
        return default_minutes
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return _clamp_int(v, default_minutes, min_minutes, max_minutes)

    s = _safe_str(v, "").strip().lower()
    if not s:
        return default_minutes

    try:
        if s.endswith("ms"):
            return _clamp_int(float(s[:-2]) / 60000.0, default_minutes, min_minutes, max_minutes)
        if s.endswith("s"):
            return _clamp_int(float(s[:-1]) / 60.0, default_minutes, min_minutes, max_minutes)
        if s.endswith("m"):
            return _clamp_int(float(s[:-1]), default_minutes, min_minutes, max_minutes)
        if s.endswith("h"):
            return _clamp_int(float(s[:-1]) * 60.0, default_minutes, min_minutes, max_minutes)
        return _clamp_int(float(s), default_minutes, min_minutes, max_minutes)
    except Exception:
        return default_minutes


# --------------- raw payload fallback (ONLY as a fallback) ---------------

def _read_sync_payload_json_fallback() -> Dict[str, Any]:
    """
    Fallback reader: raw ActiveMemberResponse payload_json from sync_cache.

    NOTE: This is NOT the primary source of truth anymore. We only use it if the
    normalized tables aren't populated (older DBs / before first sync).
    """
    try:
        from app.core.db import get_conn
        with get_conn() as conn:
            r = conn.execute("SELECT payload_json FROM sync_cache WHERE id=1").fetchone()
            if not r:
                return {}
            raw = r["payload_json"]  # type: ignore[index]
            if not raw:
                return {}
            data = json.loads(raw)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _extract_access_settings_from_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    v = payload.get("accessSoftwareSettings") or payload.get("access_software_settings") or payload.get("settings")
    return v if isinstance(v, dict) else {}


def _extract_devices_from_payload(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    devs = payload.get("devices") or payload.get("device") or []
    if isinstance(devs, list):
        return [d for d in devs if isinstance(d, dict)]
    return []


# --------------- normalization ---------------

def normalize_access_data_mode(v: Any) -> str:
    """Normalize accessDataMode to 'DEVICE', 'AGENT', or 'ULTRA'."""
    s = _safe_str(v, "DEVICE").strip().upper()
    if s == "AGENT":
        return "AGENT"
    if s == "ULTRA":
        return "ULTRA"
    return "DEVICE"


def normalize_global_settings(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize GymAccessSoftwareSettingsDto (camelCase) into internal snake_case keys.

    Safe to call with an empty dict — returns reasonable defaults.
    """
    return {
        "access_server_host": _safe_str(raw.get("accessServerHost"), ""),
        "access_server_port": _safe_int(raw.get("accessServerPort"), 8788),
        "access_server_enabled": _boolish(raw.get("accessServerEnabled"), True),
        "totp_validation": _boolish(raw.get("totpValidation", raw.get("totp_validation")), True),

        "image_cache_enabled": _boolish(raw.get("imageCacheEnabled"), True),
        # 8s default — slow Tunisian links routinely exceeded the old 2s and
        # turned popup avatars into blanks. Clamp top stays generous.
        "image_cache_timeout_sec": _clamp_int(raw.get("imageCacheTimeoutSec"), 8, 1, 60),
        # 50MB default keeps a full season roster of avatars warm. Cap raised
        # so a backend override can grow further if the gym wants it.
        # Sized to hold ALL members' avatars + face captures (≈1800 members × 2
        # images) so a once-seen image is never evicted (was 50MB → the cache
        # filled in 1-2h and members went black again on their next scan).
        "image_cache_max_bytes": _clamp_int(raw.get("imageCacheMaxBytes"), 256 * 1024 * 1024, 1024, 1024 * 1024 * 1024),
        "image_cache_max_files": _clamp_int(raw.get("imageCacheMaxFiles"), 8000, 1, 50000),

        "event_queue_max": _clamp_int(raw.get("eventQueueMax"), 5000, 100, 200000),
        "notification_queue_max": _clamp_int(raw.get("notificationQueueMax"), 5000, 100, 200000),
        "popup_queue_max": _clamp_int(raw.get("popupQueueMax"), 5000, 100, 200000),
        "history_queue_max": _clamp_int(raw.get("historyQueueMax"), 5000, 100, 200000),

        "decision_workers": _clamp_int(raw.get("decisionWorkers"), 1, 1, 16),
        "decision_ema_alpha": _clamp_float(raw.get("decisionEmaAlpha"), 0.2, 0.01, 1.0),

        "history_retention_days": _clamp_int(raw.get("historyRetentionDays"), 30, 1, 3650),
        "notification_rate_limit_per_minute": _clamp_int(raw.get("notificationRateLimitPerMinute"), 30, 0, 600),
        "notification_dedupe_window_sec": _clamp_int(raw.get("notificationDedupeWindowSec"), 30, 0, 600),

        "notification_service_enabled": _boolish(raw.get("notificationServiceEnabled"), True),
        "history_service_enabled": _boolish(raw.get("historyServiceEnabled"), True),

        "agent_sync_backend_refresh_min": _clamp_int(raw.get("agentSyncBackendRefreshMin"), 30, 1, 1440),

        # When True, dashboard edits do NOT auto-push to the turnstiles. Auto sync ticks
        # (timer / change-detector) still pull+cache but skip the device push; only an explicit
        # push — the "Sync data" button ({"reason":"user-sync"}) or a HARD_RESET — reconciles.
        "manual_sync_mode": _boolish(raw.get("manualSyncMode", raw.get("manual_sync_mode")), False),

        "optional_data_sync_delay_minutes": _clamp_int(raw.get("optionalDataSyncDelayMinutes"), 60, 60, 1440),

        "default_authorize_door_id": _clamp_int(raw.get("defaultAuthorizeDoorId"), 15, 1, 64),

        "sdk_read_initial_bytes": _clamp_int(raw.get("sdkReadInitialBytes"), 1_048_576, 64 * 1024, 16 * 1024 * 1024),

        # compat keys used by UI/config patterns
        "show_notifications": _boolish(raw.get("showNotifications", raw.get("notificationServiceEnabled")), True),

        # global popup defaults (per-device override exists)
        "popup_enabled": _boolish(raw.get("popupEnabled"), True),
        "popup_duration_sec": _clamp_int(raw.get("popupDurationSec"), 3, 1, 60),
        # Number of simultaneous member cards the TV popup can display.
        # Default 3 matches the "3 turnstiles firing at once" case in the gym.
        "popup_lanes": _clamp_int(raw.get("popupLanes"), 3, 1, 5),
    }


def normalize_device_settings(dev: Dict[str, Any], gs: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Normalize a GymDeviceDto dict (camelCase) into internal snake_case keys used by engines.

    ``gs`` is the global settings dict (fallback defaults like default_authorize_door_id).
    Safe to call with an empty dict — returns safe defaults.
    """
    if gs is None:
        gs = {}

    # door ids list
    door_ids_raw = dev.get("doorIds") or dev.get("door_ids") or []
    door_ids: List[int] = []
    if isinstance(door_ids_raw, list):
        for x in door_ids_raw:
            xi = _safe_int(x, 0)
            if xi > 0:
                door_ids.append(int(xi))

    default_door = _safe_int(gs.get("default_authorize_door_id"), 15)
    door_entry_id = door_ids[0] if door_ids else default_door

    # per-device data mode (CRITICAL)
    access_data_mode = normalize_access_data_mode(dev.get("accessDataMode") or dev.get("access_data_mode"))

    # per-device toggles
    active = _boolish(dev.get("active"), True)
    access_device = _boolish(dev.get("accessDevice"), True)
    enabled = bool(active and access_device)

    show_notifications = _boolish(dev.get("showNotifications"), True)
    win_notify_enabled = _boolish(dev.get("winNotifyEnabled"), True)
    popup_enabled = _boolish(dev.get("popupEnabled"), True)
    popup_duration_sec = _clamp_int(dev.get("popupDurationSec"), 3, 1, 60)
    popup_show_image = _boolish(dev.get("popupShowImage"), True)

    # sleep/backoff
    adaptive_sleep = _boolish(dev.get("adaptiveSleep"), True)
    busy_min = _clamp_int(dev.get("busySleepMinMs"), 0, 0, 60000)
    busy_max = _clamp_int(dev.get("busySleepMaxMs"), 50, 0, 60000)
    if busy_max < busy_min:
        busy_max = busy_min

    empty_min = _clamp_int(dev.get("emptySleepMinMs"), 50, 0, 60000)
    empty_max = _clamp_int(dev.get("emptySleepMaxMs"), 150, 0, 60000)
    if empty_max < empty_min:
        empty_max = empty_min

    empty_factor = _clamp_float(dev.get("emptyBackoffFactor"), 1.35, 1.0, 3.0)
    empty_backoff_max = _clamp_int(dev.get("emptyBackoffMaxMs"), 300, 0, 120000)

    # TOTP/RFID
    totp_enabled = _boolish(dev.get("totpEnabled"), True)
    rfid_enabled = _boolish(dev.get("rfidEnabled"), True)

    totp_prefix = _safe_str(dev.get("totpPrefix"), "9").strip()
    if len(totp_prefix) != 1 or not totp_prefix.isdigit():
        totp_prefix = "9"

    totp_digits = _clamp_int(dev.get("totpDigits"), 7, 4, 10)
    totp_period_seconds = _clamp_int(dev.get("totpPeriodSeconds"), 30, 10, 120)
    # Default validation window widened from the original (1 step / 32s / 3s).
    # Field gym PCs and turnstile RTCs are frequently NOT NTP-synced and drift
    # tens of seconds apart; the old window rejected valid QR codes as
    # DENY_NO_MATCH the moment combined skew + pipeline latency passed ~45s
    # (real incident). These defaults only apply when the backend omits a value
    # (the dashboard normally sends explicit ones); they absorb ~75s of skew
    # while keeping the QR replay window short. Engines also now validate at the
    # scan timestamp, so this is purely a safety margin for clock skew.
    totp_drift_steps = _clamp_int(dev.get("totpDriftSteps"), 2, 0, 10)
    totp_max_past_age_seconds = _clamp_int(dev.get("totpMaxPastAgeSeconds"), 75, 1, 600)
    totp_max_future_skew_seconds = _clamp_int(dev.get("totpMaxFutureSkewSeconds"), 15, 0, 120)

    rfid_min_digits = _clamp_int(dev.get("rfidMinDigits"), 1, 1, 16)
    rfid_max_digits = _clamp_int(dev.get("rfidMaxDigits"), 16, 1, 16)
    if rfid_max_digits < rfid_min_digits:
        rfid_max_digits = rfid_min_digits

    # timings
    pulse_time_ms = _clamp_int(dev.get("pulseTimeMs"), 3000, 100, 60000)
    cmd_timeout_ms = _clamp_int(dev.get("cmdTimeoutMs"), 4000, 200, 60000)
    timeout_ms = _clamp_int(dev.get("timeoutMs"), 5000, 500, 60000)

    # misc
    rtlog_table = _safe_str(dev.get("rtlogTable"), "rtlog").strip() or "rtlog"
    platform = _safe_str(dev.get("platform"), "").strip()
    save_history = _boolish(dev.get("saveHistory"), True)
    device_attendance_history_reading_delay_minutes = _parse_duration_minutes(
        dev.get(
            "deviceAttendanceHistoryReadingDelay",
            dev.get(
                "device_attendance_history_reading_delay",
                dev.get("device_attendance_history_reading_delay_minutes"),
            ),
        ),
        30,
    )

    # device capability flags
    fingerprint_enabled = _boolish(dev.get("fingerprintEnabled"), False)
    face_id_enabled = _boolish(dev.get("faceIdEnabled"), False)

    # policy/timezone
    authorize_timezone_id = _safe_int(dev.get("authorizeTimezoneId"), 1)
    pushing_to_device_policy = _safe_str(dev.get("pushingToDevicePolicy"), "").strip()

    return {
        "enabled": enabled,

        # NEW: per-device mode from backend
        "access_data_mode": access_data_mode,

        # NEW: policy/timezone/capabilities
        "authorize_timezone_id": int(authorize_timezone_id),
        "pushing_to_device_policy": pushing_to_device_policy,
        "fingerprint_enabled": bool(fingerprint_enabled),
        "face_id_enabled": bool(face_id_enabled),

        # ids
        "door_ids": list(door_ids),
        "door_entry_id": int(door_entry_id),

        # sleep/backoff
        "adaptive_sleep": bool(adaptive_sleep),
        "busy_sleep_min_ms": int(busy_min),
        "busy_sleep_max_ms": int(busy_max),
        "empty_sleep_min_ms": int(empty_min),
        "empty_sleep_max_ms": int(empty_max),
        "empty_backoff_factor": float(empty_factor),
        "empty_backoff_max_ms": int(empty_backoff_max),

        # timing/platform
        "platform": platform,
        "timeout_ms": int(timeout_ms),
        "rtlog_table": rtlog_table,
        "pulse_time_ms": int(pulse_time_ms),
        "cmd_timeout_ms": int(cmd_timeout_ms),

        # notifications
        "save_history": bool(save_history),
        "device_attendance_history_reading_delay_minutes": int(device_attendance_history_reading_delay_minutes),
        "device_attendance_history_reading_delay_seconds": int(device_attendance_history_reading_delay_minutes * 60),
        "show_notifications": bool(show_notifications),
        "win_notify_enabled": bool(win_notify_enabled),
        "popup_enabled": bool(popup_enabled),
        "popup_duration_sec": int(popup_duration_sec),
        "popup_show_image": bool(popup_show_image),

        # totp/rfid
        "totp_enabled": bool(totp_enabled),
        "totp_digits": int(totp_digits),
        "totp_period_seconds": int(totp_period_seconds),
        "totp_drift_steps": int(totp_drift_steps),
        "totp_max_past_age_seconds": int(totp_max_past_age_seconds),
        "totp_max_future_skew_seconds": int(totp_max_future_skew_seconds),
        "totp_prefix": totp_prefix,

        "rfid_enabled": bool(rfid_enabled),
        "rfid_min_digits": int(rfid_min_digits),
        "rfid_max_digits": int(rfid_max_digits),

        "anti_fraude_card":             _boolish(dev.get("antiFraudeCard"), True),
        "anti_fraude_qr_code":          _boolish(dev.get("antiFraudeQrCode"), True),
        "anti_fraude_duration":         _clamp_int(dev.get("antiFraudeDuration"), default=30, lo=5, hi=300),
        "anti_fraude_daily_pass_limit": _clamp_int(dev.get("antiFraudeDailyPassLimit"), default=0, lo=0, hi=100),

        # internal defaults (not in backend models yet)
        "replay_block_window_seconds": 10,
        "replay_lru_size": 2000,
        "poll_ema_alpha": 0.2,
        "cmd_ema_alpha": 0.2,

        # ULTRA mode fields
        # Periodic full-reconciliation interval. The full sync runs inline on the
        # worker's single SDK socket and blocks RTLog polling for its duration
        # (~15-25s on a 1700-user device), during which new scans buffer on the
        # device and the door opens late. Raised 15->30 to halve these timer-driven
        # blackouts; real-time member changes still propagate via the fast targeted
        # member-sync path (change_detector), so data freshness is unaffected.
        # (Scan-time TOTP validation already ensures buffered codes stay valid.)
        "ultra_sync_interval_minutes": int(dev.get("ultraSyncIntervalMinutes") or 30),
        "ultra_totp_rescue_enabled": bool(dev.get("ultraTotpRescueEnabled", True)),
        "ultra_rtlog_enabled": bool(dev.get("ultraRtlogEnabled", True)),
        # Precompute a {code -> credential} index off the hot path so QR/TOTP
        # verification is O(1) instead of HMAC-ing every credential (~350ms on a
        # ~1800-member roster). Pure speed: a stale/missing index transparently
        # falls back to the full verify loop, so the decision is unchanged. ON by
        # default; backend can disable per-device with ultraTotpIndexEnabled=false.
        "ultra_totp_index_enabled": _boolish(dev.get("ultraTotpIndexEnabled"), True),
        # Device RTC discipline (fix #2b). When enabled, the ULTRA worker nudges
        # the turnstile clock toward the PC clock when they drift apart by more
        # than ultra_device_clock_max_drift_sec. Default ON: prod evidence showed
        # C3-200 RTCs drifting 38-74s behind the PC, which makes scan-time TOTP
        # verification always fail (forcing the slow 2-pass fallback ~+400ms) and
        # causes ~50% DENY_NO_MATCH whenever processing lags even slightly. The
        # resilient verifier already trusts the PC clock for its wall-clock pass,
        # so aligning the device to the (NTP-synced) PC can only help; a backend
        # value of false still disables it per-device. The read-only device↔PC
        # skew check/log runs regardless.
        "ultra_discipline_device_clock": _boolish(dev.get("ultraDisciplineDeviceClock"), True),
        "ultra_device_clock_max_drift_sec": _clamp_int(dev.get("ultraDeviceClockMaxDriftSec"), 10, 2, 600),
        # Connect-per-cycle hot window: how many consecutive empty polls the
        # worker holds the TCP connection before disconnecting. C2-400 /
        # C3-200 firmware drops idle sockets unpredictably, so we close
        # proactively after a burst window. 0 disables the hot window entirely
        # (pure connect-per-poll).
        #
        # Raised 3 -> 20: with 3 (~1.5s grace) the socket dropped between scans,
        # so a re-entry/next member arrived to a disconnected worker and ate a
        # 0.6-2.2s reconnect before its scan was even polled — the cause of the
        # variable 2s/5-10s door-open latency. 20 holds the connection ~5-7s
        # after activity so back-to-back scans hit a live socket and open fast.
        # If the firmware silently drops the held socket the next poll just
        # reconnects (self-healing); no events are lost. Backend can override
        # per-device via ultraHotWindowEmptyPolls.
        "ultra_hot_window_empty_polls": _clamp_int(
            dev.get("ultraHotWindowEmptyPolls"), 20, 0, 50
        ),

        # Per-door presets (from dashboard doorPresets config).
        # List of dicts: [{"doorNumber": 1, "pulseSeconds": 3, "doorName": "..."}, ...]
        "door_presets": list(dev.get("door_presets") or dev.get("doorPresets") or []),
    }


# --------------- Convenience: full reads (normalized tables first) ---------------

def get_backend_global_settings() -> Dict[str, Any]:
    """One-call helper, with a short in-memory TTL cache (see top of module).

    - Primary: read from normalized table sync_access_software_settings (via db.py)
    - Fallback: read from sync_cache.payload_json (older DB / before first sync)

    Returns a shallow COPY of the cached dict so callers may freely mutate their
    result without corrupting the shared cache.
    """
    now = time.monotonic()
    try:
        with _GLOBAL_SETTINGS_LOCK:
            cached = _GLOBAL_SETTINGS_CACHE["value"]
            if cached is not None and (now - float(_GLOBAL_SETTINGS_CACHE["ts"])) < _GLOBAL_SETTINGS_TTL_SEC:
                return dict(cached)
    except Exception:
        pass

    result = _load_backend_global_settings_uncached()

    try:
        with _GLOBAL_SETTINGS_LOCK:
            _GLOBAL_SETTINGS_CACHE["value"] = result
            _GLOBAL_SETTINGS_CACHE["ts"] = time.monotonic()
    except Exception:
        pass
    return dict(result)


def _load_backend_global_settings_uncached() -> Dict[str, Any]:
    """Uncached DB read + normalize (the original get_backend_global_settings body)."""
    raw: Dict[str, Any] = {}
    try:
        from app.core.db import load_sync_access_software_settings
        v = load_sync_access_software_settings()
        if isinstance(v, dict):
            raw = v
    except Exception as _sr_err:
        import logging
        logging.getLogger("settings_reader").error(
            f"[settings_reader] Failed to read global settings from DB: {_sr_err}. Using defaults."
        )
        raw = {}

    if not raw:
        payload = _read_sync_payload_json_fallback()
        raw = _extract_access_settings_from_payload(payload)

    return normalize_global_settings(raw)


def get_backend_device_raw(device_id: int) -> Optional[Dict[str, Any]]:
    """
    One-call helper:
    - Primary: read from normalized table sync_devices (via db.py payload coercion)
    - Fallback: find device in sync_cache.payload_json
    """
    did = int(device_id)

    # primary
    try:
        from app.core.db import get_sync_device_payload
        v = get_sync_device_payload(did)
        if isinstance(v, dict):
            return v
    except Exception:
        pass

    # fallback
    payload = _read_sync_payload_json_fallback()
    for dev in _extract_devices_from_payload(payload):
        if _safe_int(dev.get("id"), 0) == did:
            return dev

    return None


def get_backend_device_settings(device_id: int) -> Dict[str, Any]:
    """
    One-call helper:
    - reads global settings (normalized)
    - reads device raw (normalized table first)
    - normalizes/clamps device settings
    """
    gs = get_backend_global_settings()
    dev = get_backend_device_raw(device_id)
    if dev:
        return normalize_device_settings(dev, gs)

    # device not found -> safe disabled defaults
    return normalize_device_settings({"id": int(device_id), "active": False, "accessDevice": False}, gs)

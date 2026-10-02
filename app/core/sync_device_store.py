"""Local store of the device list (``sync_devices``): one device row in, one device payload out.

Moved out of ``db.py`` unchanged (ULTRA merge plan 2, Task 1) so that the columns the ULTRA merge
adds do not grow ``db.py`` (spec 2026-10-02 section 9, D9). ``db.py`` re-imports every name used
elsewhere, so ``db._insert_device_row`` and ``db._coerce_device_row_to_payload`` keep working.
The pinScheme switch record stays in ``db.py``; ``_insert_device_row`` reaches it through the
three wrappers at the end of this file, resolved at call time (``db`` imports this module).
"""
from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any, Dict, Optional

from app.core.db_values import _bool_to_i, _safe_str, _to_float_or_none, _to_int_or_none


def _device_capabilities_to_text(v: Any) -> Optional[str]:
    """Serialize the opaque deviceCapabilities payload for storage.

    The backend treats deviceCapabilities as an opaque JSON TEXT column; we store
    the raw JSON string unchanged. Accepts a dict (json.dumps) or a non-empty
    string (stored as-is); anything else -> None. Never raises.
    """
    if isinstance(v, dict):
        try:
            return json.dumps(v, ensure_ascii=False)
        except Exception:
            return None
    if isinstance(v, str):
        s = v.strip()
        return s or None
    return None


def _device_capabilities_from_stored(v: Any) -> Optional[Dict[str, Any]]:
    """Parse the stored deviceCapabilities TEXT back into a dict.

    Returns the parsed dict when the stored string is valid JSON (or when the
    value is already a dict, e.g. from the in-memory cache path); None on
    absent/malformed/non-dict values. Never raises.
    """
    if isinstance(v, dict):
        return v
    if isinstance(v, str) and v.strip():
        try:
            parsed = json.loads(v)
        except Exception:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _insert_device_row(cur: sqlite3.Cursor, d: dict) -> None:
    """Insert a single device (presets + device row) into sync tables. Helper shared by save_sync_cache and save_sync_cache_delta."""
    if not isinstance(d, dict):
        return

    # save synced door presets
    presets = d.get("doorPresets") or []
    if isinstance(presets, list):
        for p in presets:
            if not isinstance(p, dict):
                continue
            cur.execute(
                """
                INSERT OR REPLACE INTO sync_device_door_presets (
                    remote_id, device_id, door_number, pulse_seconds, door_name, created_at, updated_at,
                    favorite_enabled, favorite_order, favorite_shortcut, direction
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _to_int_or_none(p.get("id")),
                    _to_int_or_none(p.get("deviceId") or d.get("id")),
                    _to_int_or_none(p.get("doorNumber")),
                    _to_int_or_none(p.get("pulseSeconds")),
                    _safe_str(p.get("doorName"), ""),
                    _safe_str(p.get("createdAt"), None),
                    _safe_str(p.get("updatedAt"), None),
                    1 if p.get("favoriteEnabled") else 0,
                    _to_int_or_none(p.get("favoriteOrder")),
                    _safe_str(p.get("favoriteShortcut"), None),
                    _safe_str(p.get("direction"), None),
                ),
            )

    # normalize accessDataMode
    adm_raw = d.get("accessDataMode") or d.get("access_data_mode") or "DEVICE"
    adm = str(adm_raw or "").strip().upper()
    if adm not in ("DEVICE", "AGENT", "ULTRA"):
        adm = "DEVICE"

    # pinScheme: only an explicit, recognised value is stored as given. An absent key, null,
    # "" or an unknown token keeps the LAST KNOWN scheme (the switch history -- sync_devices
    # itself is deleted and re-inserted on every device refresh), so a partial payload never
    # turns an ACCOUNT terminal back into a MEMBERSHIP one. Review #6, guide §3.2e.
    explicit_pin_scheme = _explicit_device_pin_scheme(d)
    stored_pin_scheme = explicit_pin_scheme
    if stored_pin_scheme is None:
        stored_pin_scheme = _last_known_device_pin_scheme(cur, _to_int_or_none(d.get("id")))
        if stored_pin_scheme is not None:
            logging.getLogger(__name__).warning(
                "[DB] device id=%s payload carries no recognised pinScheme (%r); keeping the last "
                "known scheme %s -- only an explicit value switches a device (guide §3.2e).",
                d.get("id"), d.get("pinScheme", d.get("pin_scheme")), stored_pin_scheme,
            )

    cur.execute(
        """
        INSERT INTO sync_devices (
            id, name, description, allowed_memberships_json,

            active, access_device,

            ip_address, mac_address, password, port_number,

            access_data_mode,

            model, installed_models_json, door_ids_json, zone,

            show_notifications, win_notify_enabled, popup_enabled, popup_duration_sec, popup_show_image,

            totp_prefix, totp_digits, totp_period_seconds, totp_drift_steps,
            totp_max_past_age_seconds, totp_max_future_skew_seconds,

            rfid_min_digits, rfid_max_digits,

            pulse_time_ms, cmd_timeout_ms, timeout_ms,

            rtlog_table, save_history, device_attendance_history_reading_delay_minutes, platform,

            totp_enabled, rfid_enabled, fingerprint_enabled, face_id_enabled,

            adaptive_sleep, busy_sleep_min_ms, busy_sleep_max_ms,
            empty_sleep_min_ms, empty_sleep_max_ms,
            empty_backoff_factor, empty_backoff_max_ms,

            authorize_timezone_id, pushing_to_device_policy,

            created_at, updated_at,

            anti_fraude_card, anti_fraude_qr_code, anti_fraude_duration,
            anti_fraude_daily_pass_limit,
            frequent_pass_limit, frequent_pass_window_minutes,

            device_protocol,

            roster_pushing_policy,

            pin_scheme,

            device_capabilities
        )
        VALUES (
            ?, ?, ?, ?,
            ?, ?,
            ?, ?, ?, ?,
            ?,
            ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?,
            ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?,
            ?, ?,
            ?, ?,
            ?, ?,
            ?, ?, ?,
            ?,
            ?, ?,
            ?,
            ?,
            ?,
            ?
        )
        """,
        (
            d.get("id"),
            d.get("name"),
            d.get("description"),
            json.dumps(d.get("allowedMemberships") or [], ensure_ascii=False),

            _bool_to_i(d.get("active", True), default=1),
            _bool_to_i(d.get("accessDevice", True), default=1),

            d.get("ipAddress"),
            d.get("macAddress"),
            d.get("password"),
            d.get("portNumber"),

            adm,

            d.get("model"),
            json.dumps(d.get("installedModels") or [], ensure_ascii=False),
            json.dumps(d.get("doorIds") or [], ensure_ascii=False),
            d.get("zone"),

            _bool_to_i(d.get("showNotifications", True), default=1),
            _bool_to_i(d.get("winNotifyEnabled", True), default=1),
            _bool_to_i(d.get("popupEnabled", True), default=1),
            _to_int_or_none(d.get("popupDurationSec", 3)),
            _bool_to_i(d.get("popupShowImage", True), default=1),

            _safe_str(d.get("totpPrefix", "9"), "9"),
            _to_int_or_none(d.get("totpDigits", 7)),
            _to_int_or_none(d.get("totpPeriodSeconds", 30)),
            _to_int_or_none(d.get("totpDriftSteps", 1)),
            _to_int_or_none(d.get("totpMaxPastAgeSeconds", 32)),
            _to_int_or_none(d.get("totpMaxFutureSkewSeconds", 3)),

            _to_int_or_none(d.get("rfidMinDigits", 1)),
            _to_int_or_none(d.get("rfidMaxDigits", 16)),

            _to_int_or_none(d.get("pulseTimeMs", 3000)),
            _to_int_or_none(d.get("cmdTimeoutMs", 4000)),
            _to_int_or_none(d.get("timeoutMs", 5000)),

            _safe_str(d.get("rtlogTable", "rtlog"), "rtlog"),
            _bool_to_i(d.get("saveHistory", True), default=1),
            _to_int_or_none(
                d.get("deviceAttendanceHistoryReadingDelay", d.get("device_attendance_history_reading_delay"))
            ),
            d.get("platform"),

            _bool_to_i(d.get("totpEnabled", True), default=1),
            _bool_to_i(d.get("rfidEnabled", True), default=1),
            _bool_to_i(d.get("fingerprintEnabled", False), default=0),
            _bool_to_i(d.get("faceIdEnabled", False), default=0),

            _bool_to_i(d.get("adaptiveSleep", True), default=1),
            _to_int_or_none(d.get("busySleepMinMs", 0)),
            _to_int_or_none(d.get("busySleepMaxMs", 500)),
            _to_int_or_none(d.get("emptySleepMinMs", 200)),
            _to_int_or_none(d.get("emptySleepMaxMs", 500)),
            _to_float_or_none(d.get("emptyBackoffFactor", 1.35)),
            _to_int_or_none(d.get("emptyBackoffMaxMs", 2000)),

            _to_int_or_none(d.get("authorizeTimezoneId", 1)),
            d.get("pushingToDevicePolicy") or d.get("pushing_to_device_policy"),

            _safe_str(d.get("createdAt"), ""),
            _safe_str(d.get("updatedAt"), ""),

            _bool_to_i(d.get("antiFraudeCard", True), default=1),
            _bool_to_i(d.get("antiFraudeQrCode", True), default=1),
            _to_int_or_none(d.get("antiFraudeDuration", 30)) or 30,
            _to_int_or_none(d.get("antiFraudeDailyPassLimit", 0)) or 0,
            _to_int_or_none(d.get("frequentPassLimit", 0)) or 0,
            _to_int_or_none(d.get("frequentPassWindowMinutes", 0)) or 0,

            (_safe_str(d.get("deviceProtocol") or d.get("device_protocol"), "").strip().upper() or None),

            (_safe_str(d.get("rosterPushingPolicy") or d.get("roster_pushing_policy"), "").strip().upper() or None),

            stored_pin_scheme,

            _device_capabilities_to_text(d.get("deviceCapabilities") or d.get("device_capabilities")),
        ),
    )

    # Same transaction as the device row: every device write path (full, delta, fast patch)
    # comes through here, so a pinScheme change is detected exactly once, wherever it arrives.
    _record_device_pin_scheme_switch(cur, d)


def _coerce_device_row_to_payload(d: Dict[str, Any]) -> Dict[str, Any]:
    """
    Converts a DB row (snake_case columns + *_json) into a dict aligned with GymDeviceDto (camelCase).
    """
    def g(*keys, default=None):
        for k in keys:
            if k in d:
                return d.get(k)
        return default

    allowed = g("allowedMemberships", "allowed_memberships", default=None) or []
    installed = g("installedModels", "installed_models", default=None) or []
    doors = g("doorIds", "door_ids", default=None) or []

    def _boolish(v: Any, default: bool) -> bool:
        if isinstance(v, str):
            s = v.strip().lower()
            if s in ("1", "true", "yes", "y", "on"):
                return True
            if s in ("0", "false", "no", "n", "off"):
                return False
            return default
        if isinstance(v, (int, float)):
            return int(v) != 0
        if isinstance(v, bool):
            return v
        return default

    adm_raw = g("accessDataMode", "access_data_mode", default="DEVICE") or "DEVICE"
    adm = str(adm_raw).strip().upper()
    if adm not in ("DEVICE", "AGENT", "ULTRA"):
        adm = "DEVICE"

    return {
        "id": g("id"),
        "name": g("name"),
        "description": g("description"),
        "allowedMemberships": allowed,

        "active": _boolish(g("active", default=1), True),
        "accessDevice": _boolish(g("access_device", "accessDevice", default=1), True),

        "ipAddress": g("ipAddress", "ip_address"),
        "macAddress": g("macAddress", "mac_address"),
        "password": g("password"),
        "portNumber": g("portNumber", "port_number"),

        "accessDataMode": adm,

        # SDK-family routing (device-driver factory). None/absent -> the factory's
        # ZK_PULLSDK default, so pre-protocol rows keep working unchanged.
        "deviceProtocol": g("deviceProtocol", "device_protocol"),

        # Roster pushing policy (PRESERVE default / MIRROR). None -> engine treats as
        # PRESERVE, so pre-migration rows keep the additive behavior.
        "rosterPushingPolicy": g("rosterPushingPolicy", "roster_pushing_policy"),

        # PIN scheme (MEMBERSHIP default / ACCOUNT). None -> device_sync.device_pin_scheme
        # answers MEMBERSHIP, so pre-migration rows keep membership pins.
        "pinScheme": g("pinScheme", "pin_scheme"),

        # Opaque capability descriptor (e.g. {"fingerprintTemplateVersion": 9}).
        # Parsed dict when the stored JSON is valid, else None.
        "deviceCapabilities": _device_capabilities_from_stored(
            g("deviceCapabilities", "device_capabilities")
        ),

        "model": g("model"),
        "installedModels": installed,
        "doorIds": doors,
        "zone": g("zone"),

        "showNotifications": _boolish(g("showNotifications", "show_notifications", default=1), True),
        "winNotifyEnabled": _boolish(g("winNotifyEnabled", "win_notify_enabled", default=1), True),
        "popupEnabled": _boolish(g("popupEnabled", "popup_enabled", default=1), True),
        "popupDurationSec": _to_int_or_none(g("popupDurationSec", "popup_duration_sec", default=3)) or 3,
        "popupShowImage": _boolish(g("popupShowImage", "popup_show_image", default=1), True),

        "totpPrefix": _safe_str(g("totpPrefix", "totp_prefix", default="9"), "9"),
        "totpDigits": _to_int_or_none(g("totpDigits", "totp_digits", default=7)) or 7,
        "totpPeriodSeconds": _to_int_or_none(g("totpPeriodSeconds", "totp_period_seconds", default=30)) or 30,
        "totpDriftSteps": _to_int_or_none(g("totpDriftSteps", "totp_drift_steps", default=1)) or 1,
        "totpMaxPastAgeSeconds": _to_int_or_none(g("totpMaxPastAgeSeconds", "totp_max_past_age_seconds", default=32)) or 32,
        "totpMaxFutureSkewSeconds": _to_int_or_none(g("totpMaxFutureSkewSeconds", "totp_max_future_skew_seconds", default=3)) or 3,

        "rfidMinDigits": _to_int_or_none(g("rfidMinDigits", "rfid_min_digits", default=1)) or 1,
        "rfidMaxDigits": _to_int_or_none(g("rfidMaxDigits", "rfid_max_digits", default=16)) or 16,

        "pulseTimeMs": _to_int_or_none(g("pulseTimeMs", "pulse_time_ms", default=3000)) or 3000,
        "cmdTimeoutMs": _to_int_or_none(g("cmdTimeoutMs", "cmd_timeout_ms", default=4000)) or 4000,
        "timeoutMs": _to_int_or_none(g("timeoutMs", "timeout_ms", default=5000)) or 5000,

        "rtlogTable": _safe_str(g("rtlogTable", "rtlog_table", default="rtlog"), "rtlog") or "rtlog",
        "saveHistory": _boolish(g("saveHistory", "save_history", default=1), True),
        "deviceAttendanceHistoryReadingDelay": (
            _to_int_or_none(
                g(
                    "deviceAttendanceHistoryReadingDelay",
                    "device_attendance_history_reading_delay",
                    "device_attendance_history_reading_delay_minutes",
                    default=30,
                )
            )
            or 30
        ),
        "platform": g("platform"),

        "totpEnabled": _boolish(g("totpEnabled", "totp_enabled", default=1), True),
        "rfidEnabled": _boolish(g("rfidEnabled", "rfid_enabled", default=1), True),
        "fingerprintEnabled": _boolish(g("fingerprintEnabled", "fingerprint_enabled", default=0), False),
        "faceIdEnabled": _boolish(g("faceIdEnabled", "face_id_enabled", default=0), False),

        "adaptiveSleep": _boolish(g("adaptiveSleep", "adaptive_sleep", default=1), True),
        "busySleepMinMs": _to_int_or_none(g("busySleepMinMs", "busy_sleep_min_ms", default=0)) or 0,
        "busySleepMaxMs": _to_int_or_none(g("busySleepMaxMs", "busy_sleep_max_ms", default=500)) or 500,
        "emptySleepMinMs": _to_int_or_none(g("emptySleepMinMs", "empty_sleep_min_ms", default=200)) or 200,
        "emptySleepMaxMs": _to_int_or_none(g("emptySleepMaxMs", "empty_sleep_max_ms", default=500)) or 500,
        "emptyBackoffFactor": _to_float_or_none(g("emptyBackoffFactor", "empty_backoff_factor", default=1.35)) or 1.35,
        "emptyBackoffMaxMs": _to_int_or_none(g("emptyBackoffMaxMs", "empty_backoff_max_ms", default=2000)) or 2000,

        "authorizeTimezoneId": _to_int_or_none(g("authorizeTimezoneId", "authorize_timezone_id", default=1)) or 1,
        "pushingToDevicePolicy": g("pushingToDevicePolicy", "pushing_to_device_policy"),

        "createdAt": g("createdAt", "created_at"),
        "updatedAt": g("updatedAt", "updated_at"),

        "antiFraudeCard":             _boolish(g("anti_fraude_card",    default=1), True),
        "antiFraudeQrCode":           _boolish(g("anti_fraude_qr_code", default=1), True),
        "antiFraudeDuration":         _to_int_or_none(g("anti_fraude_duration", default=30)) or 30,
        "antiFraudeDailyPassLimit":   int(g("anti_fraude_daily_pass_limit", default=0) or 0),
        "frequentPassLimit":          int(g("frequent_pass_limit", default=0) or 0),
        "frequentPassWindowMinutes":  int(g("frequent_pass_window_minutes", default=0) or 0),

        # attached later by list_sync_devices_payload (synced presets)
        "doorPresets": g("doorPresets", "door_presets", default=None) or [],
    }


def _explicit_device_pin_scheme(d: dict) -> Optional[str]:
    from app.core import db as _db  # call time: db imports this module while it loads

    return _db._explicit_device_pin_scheme(d)


def _last_known_device_pin_scheme(cur: sqlite3.Cursor, device_id: Optional[int]) -> Optional[str]:
    from app.core import db as _db

    return _db._last_known_device_pin_scheme(cur, device_id)


def _record_device_pin_scheme_switch(cur: sqlite3.Cursor, d: dict) -> bool:
    from app.core import db as _db

    return _db._record_device_pin_scheme_switch(cur, d)

# app/core/db.py
from __future__ import annotations

import base64
import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from app.core.utils import DB_PATH, ensure_dirs, now_iso

# -----------------------------
# SQLite connection helpers
# -----------------------------
def get_conn() -> sqlite3.Connection:
    ensure_dirs()
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


# -----------------------------
# Optional DPAPI protection (Windows)
# -----------------------------
def _dpapi_encrypt(plain: str) -> str:
    """
    Best-effort encryption for auth tokens on Windows using DPAPI.
    Falls back to raw: prefix if DPAPI is unavailable.
    """
    try:
        import ctypes
        from ctypes import wintypes

        crypt32 = ctypes.WinDLL("crypt32.dll")
        kernel32 = ctypes.WinDLL("kernel32.dll")

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

        def _bytes_to_blob(b: bytes) -> DATA_BLOB:
            buf = (ctypes.c_byte * len(b))(*b)
            return DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))

        def _blob_to_bytes(blob: DATA_BLOB) -> bytes:
            cb = int(blob.cbData)
            if cb <= 0:
                return b""
            data = ctypes.string_at(blob.pbData, cb)
            kernel32.LocalFree(blob.pbData)
            return data

        crypt32.CryptProtectData.argtypes = [
            ctypes.POINTER(DATA_BLOB),
            wintypes.LPCWSTR,
            ctypes.POINTER(DATA_BLOB),
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(DATA_BLOB),
        ]
        crypt32.CryptProtectData.restype = wintypes.BOOL

        plain_bytes = plain.encode("utf-8")
        in_blob = _bytes_to_blob(plain_bytes)
        out_blob = DATA_BLOB()

        ok = crypt32.CryptProtectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob))
        if not ok:
            return "raw:" + plain

        enc = _blob_to_bytes(out_blob)
        return "dpapi:" + base64.b64encode(enc).decode("ascii")
    except Exception:
        return "raw:" + plain


def _dpapi_decrypt(stored: str) -> str:
    if not stored:
        return ""
    if stored.startswith("raw:"):
        return stored[len("raw:") :]
    if not stored.startswith("dpapi:"):
        return stored

    try:
        import ctypes
        from ctypes import wintypes

        crypt32 = ctypes.WinDLL("crypt32.dll")
        kernel32 = ctypes.WinDLL("kernel32.dll")

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

        def _bytes_to_blob_alloc(b: bytes) -> DATA_BLOB:
            buf = (ctypes.c_byte * len(b))(*b)
            return DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))

        def _blob_to_bytes(blob: DATA_BLOB) -> bytes:
            cb = int(blob.cbData)
            if cb <= 0:
                return b""
            data = ctypes.string_at(blob.pbData, cb)
            kernel32.LocalFree(blob.pbData)
            return data

        crypt32.CryptUnprotectData.argtypes = [
            ctypes.POINTER(DATA_BLOB),
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(DATA_BLOB),
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(DATA_BLOB),
        ]
        crypt32.CryptUnprotectData.restype = wintypes.BOOL

        enc = base64.b64decode(stored[len("dpapi:") :].encode("ascii"))
        in_blob = _bytes_to_blob_alloc(enc)
        out_blob = DATA_BLOB()

        ok = crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob))
        if not ok:
            return ""

        dec = _blob_to_bytes(out_blob)
        return dec.decode("utf-8", errors="replace")
    except Exception:
        return ""


# -----------------------------
# DB schema helpers / migrations
# -----------------------------
def _table_columns(conn: sqlite3.Connection, table: str) -> List[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        return [r["name"] for r in rows]  # type: ignore[index]
    except Exception:
        return []


def _ensure_column(conn: sqlite3.Connection, table: str, col_name: str, col_def_sql: str) -> None:
    cols = set(_table_columns(conn, table))
    if col_name in cols:
        return
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_def_sql}")
    except Exception:
        pass


def _sync_users_has_legacy_fingerprint(conn: sqlite3.Connection) -> bool:
    cols = _table_columns(conn, "sync_users")
    return "fingerprint" in cols


def _rebuild_sync_users_without_legacy_fingerprint(conn: sqlite3.Connection) -> None:
    """
    Older DBs had a single 'fingerprint' column. We rebuild into the new shape.
    """
    if not _sync_users_has_legacy_fingerprint(conn):
        return

    cols_old = set(_table_columns(conn, "sync_users"))

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sync_users_new (
            user_id INTEGER,
            active_membership_id INTEGER,
            membership_id INTEGER,
            full_name TEXT,
            phone TEXT,
            email TEXT,
            valid_from TEXT,
            valid_to TEXT,
            first_card_id TEXT,
            second_card_id TEXT,
            image TEXT,
            fingerprints_json TEXT,
            face_id TEXT,
            qr_code_payload TEXT
        );
        """
    )

    def sel(col: str, default_sql: str = "NULL") -> str:
        return col if col in cols_old else default_sql

    fps_expr = sel("fingerprints_json", "'[]'")

    conn.execute(
        f"""
        INSERT INTO sync_users_new (
            user_id, active_membership_id, membership_id,
            full_name, phone, email, valid_from, valid_to,
            first_card_id, second_card_id, image,
            fingerprints_json,
            face_id, qr_code_payload
        )
        SELECT
            {sel("user_id")},
            {sel("active_membership_id")},
            {sel("membership_id")},
            {sel("full_name")},
            {sel("phone")},
            {sel("email")},
            {sel("valid_from")},
            {sel("valid_to")},
            {sel("first_card_id")},
            {sel("second_card_id")},
            {sel("image")},
            {fps_expr},
            {sel("face_id")},
            {sel("qr_code_payload")}
        FROM sync_users;
        """
    )

    conn.execute("DROP TABLE sync_users;")
    conn.execute("ALTER TABLE sync_users_new RENAME TO sync_users;")


# -----------------------------
# DB init
# -----------------------------
def init_db() -> None:
    with get_conn() as conn:
        # -----------------------------
        # local fingerprints enroll cache (unchanged)
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                label TEXT,
                pin TEXT,
                card_no TEXT,
                finger_id INTEGER NOT NULL,
                template_version INTEGER NOT NULL,
                template_encoding TEXT NOT NULL,
                template_data TEXT NOT NULL,
                template_size INTEGER NOT NULL
            );
            """
        )

        # -----------------------------
        # auth token
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_state (
                id INTEGER PRIMARY KEY CHECK (id=1),
                email TEXT,
                token_protected TEXT,
                last_login_at TEXT
            );
            """
        )

        # -----------------------------
        # raw payload cache
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_cache (
                id INTEGER PRIMARY KEY CHECK (id=1),
                updated_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            """
        )

        # -----------------------------
        # contract meta
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_meta (
                id INTEGER PRIMARY KEY CHECK (id=1),
                contract_status INTEGER NOT NULL,
                contract_end_date TEXT,
                updated_at TEXT NOT NULL
            );
            """
        )

        # -----------------------------
        # users (fixed - no duplicated tokens)
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_users (
                user_id INTEGER,
                active_membership_id INTEGER,
                membership_id INTEGER,
                full_name TEXT,
                phone TEXT,
                email TEXT,
                valid_from TEXT,
                valid_to TEXT,
                first_card_id TEXT,
                second_card_id TEXT,
                image TEXT,
                fingerprints_json TEXT,
                face_id TEXT,
                qr_code_payload TEXT
            );
            """
        )

        _ensure_column(conn, "sync_users", "fingerprints_json", "fingerprints_json TEXT")
        _ensure_column(conn, "sync_users", "active_membership_id", "active_membership_id INTEGER")
        try:
            _rebuild_sync_users_without_legacy_fingerprint(conn)
        except Exception:
            pass

        # -----------------------------
        # memberships
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_memberships (
                id INTEGER,
                title TEXT,
                description TEXT,
                price TEXT,
                duration_in_days INTEGER
            );
            """
        )

        # -----------------------------
        # GymAccessSoftwareSettingsDto (single row)
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_access_software_settings (
                id INTEGER PRIMARY KEY CHECK (id=1),
                gym_id INTEGER,
                access_server_host TEXT,
                access_server_port INTEGER,
                access_server_enabled INTEGER,

                image_cache_enabled INTEGER,
                image_cache_timeout_sec INTEGER,
                image_cache_max_bytes INTEGER,
                image_cache_max_files INTEGER,

                event_queue_max INTEGER,
                notification_queue_max INTEGER,
                history_queue_max INTEGER,
                popup_queue_max INTEGER,

                decision_workers INTEGER,
                decision_ema_alpha REAL,

                history_retention_days INTEGER,
                notification_rate_limit_per_minute INTEGER,
                notification_dedupe_window_sec INTEGER,

                notification_service_enabled INTEGER,
                history_service_enabled INTEGER,

                agent_sync_backend_refresh_min INTEGER,

                default_authorize_door_id INTEGER,
                sdk_read_initial_bytes INTEGER,

                created_at TEXT,
                updated_at TEXT
            );
            """
        )

        # Best-effort ensure columns for older DBs
        _ensure_column(conn, "sync_access_software_settings", "gym_id", "gym_id INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "access_server_host", "access_server_host TEXT")
        _ensure_column(conn, "sync_access_software_settings", "access_server_port", "access_server_port INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "access_server_enabled", "access_server_enabled INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "image_cache_enabled", "image_cache_enabled INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "image_cache_timeout_sec", "image_cache_timeout_sec INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "image_cache_max_bytes", "image_cache_max_bytes INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "image_cache_max_files", "image_cache_max_files INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "event_queue_max", "event_queue_max INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "notification_queue_max", "notification_queue_max INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "history_queue_max", "history_queue_max INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "popup_queue_max", "popup_queue_max INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "decision_workers", "decision_workers INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "decision_ema_alpha", "decision_ema_alpha REAL")
        _ensure_column(conn, "sync_access_software_settings", "history_retention_days", "history_retention_days INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "notification_rate_limit_per_minute", "notification_rate_limit_per_minute INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "notification_dedupe_window_sec", "notification_dedupe_window_sec INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "notification_service_enabled", "notification_service_enabled INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "history_service_enabled", "history_service_enabled INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "agent_sync_backend_refresh_min", "agent_sync_backend_refresh_min INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "default_authorize_door_id", "default_authorize_door_id INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "sdk_read_initial_bytes", "sdk_read_initial_bytes INTEGER")
        _ensure_column(conn, "sync_access_software_settings", "created_at", "created_at TEXT")
        _ensure_column(conn, "sync_access_software_settings", "updated_at", "updated_at TEXT")

        # -----------------------------
        # devices (matches GymDeviceDto)
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_devices (
                id INTEGER,
                name TEXT,
                description TEXT,
                allowed_memberships_json TEXT,

                active INTEGER,
                access_device INTEGER,

                ip_address TEXT,
                mac_address TEXT,
                password TEXT,
                port_number TEXT,

                access_data_mode TEXT,

                model TEXT,
                installed_models_json TEXT,
                door_ids_json TEXT,
                zone TEXT,

                show_notifications INTEGER,
                win_notify_enabled INTEGER,
                popup_enabled INTEGER,
                popup_duration_sec INTEGER,
                popup_show_image INTEGER,

                totp_prefix TEXT,
                totp_digits INTEGER,
                totp_period_seconds INTEGER,
                totp_drift_steps INTEGER,
                totp_max_past_age_seconds INTEGER,
                totp_max_future_skew_seconds INTEGER,

                rfid_min_digits INTEGER,
                rfid_max_digits INTEGER,

                pulse_time_ms INTEGER,
                cmd_timeout_ms INTEGER,
                timeout_ms INTEGER,

                rtlog_table TEXT,
                save_history INTEGER,
                platform TEXT,

                totp_enabled INTEGER,
                rfid_enabled INTEGER,
                fingerprint_enabled INTEGER,
                face_id_enabled INTEGER,

                adaptive_sleep INTEGER,
                busy_sleep_min_ms INTEGER,
                busy_sleep_max_ms INTEGER,
                empty_sleep_min_ms INTEGER,
                empty_sleep_max_ms INTEGER,
                empty_backoff_factor REAL,
                empty_backoff_max_ms INTEGER,

                authorize_timezone_id INTEGER,
                pushing_to_device_policy TEXT,

                created_at TEXT,
                updated_at TEXT
            );
            """
        )

        # Ensure columns for older DBs (best-effort)
        _ensure_column(conn, "sync_devices", "access_data_mode", "access_data_mode TEXT")

        _ensure_column(conn, "sync_devices", "show_notifications", "show_notifications INTEGER")
        _ensure_column(conn, "sync_devices", "win_notify_enabled", "win_notify_enabled INTEGER")
        _ensure_column(conn, "sync_devices", "popup_enabled", "popup_enabled INTEGER")
        _ensure_column(conn, "sync_devices", "popup_duration_sec", "popup_duration_sec INTEGER")
        _ensure_column(conn, "sync_devices", "popup_show_image", "popup_show_image INTEGER")

        _ensure_column(conn, "sync_devices", "totp_enabled", "totp_enabled INTEGER")
        _ensure_column(conn, "sync_devices", "totp_prefix", "totp_prefix TEXT")
        _ensure_column(conn, "sync_devices", "totp_digits", "totp_digits INTEGER")
        _ensure_column(conn, "sync_devices", "totp_period_seconds", "totp_period_seconds INTEGER")
        _ensure_column(conn, "sync_devices", "totp_drift_steps", "totp_drift_steps INTEGER")
        _ensure_column(conn, "sync_devices", "totp_max_past_age_seconds", "totp_max_past_age_seconds INTEGER")
        _ensure_column(conn, "sync_devices", "totp_max_future_skew_seconds", "totp_max_future_skew_seconds INTEGER")

        _ensure_column(conn, "sync_devices", "rfid_enabled", "rfid_enabled INTEGER")
        _ensure_column(conn, "sync_devices", "rfid_min_digits", "rfid_min_digits INTEGER")
        _ensure_column(conn, "sync_devices", "rfid_max_digits", "rfid_max_digits INTEGER")

        _ensure_column(conn, "sync_devices", "fingerprint_enabled", "fingerprint_enabled INTEGER")
        _ensure_column(conn, "sync_devices", "face_id_enabled", "face_id_enabled INTEGER")

        _ensure_column(conn, "sync_devices", "pulse_time_ms", "pulse_time_ms INTEGER")
        _ensure_column(conn, "sync_devices", "cmd_timeout_ms", "cmd_timeout_ms INTEGER")
        _ensure_column(conn, "sync_devices", "timeout_ms", "timeout_ms INTEGER")

        _ensure_column(conn, "sync_devices", "rtlog_table", "rtlog_table TEXT")
        _ensure_column(conn, "sync_devices", "save_history", "save_history INTEGER")
        _ensure_column(conn, "sync_devices", "platform", "platform TEXT")

        _ensure_column(conn, "sync_devices", "adaptive_sleep", "adaptive_sleep INTEGER")
        _ensure_column(conn, "sync_devices", "busy_sleep_min_ms", "busy_sleep_min_ms INTEGER")
        _ensure_column(conn, "sync_devices", "busy_sleep_max_ms", "busy_sleep_max_ms INTEGER")
        _ensure_column(conn, "sync_devices", "empty_sleep_min_ms", "empty_sleep_min_ms INTEGER")
        _ensure_column(conn, "sync_devices", "empty_sleep_max_ms", "empty_sleep_max_ms INTEGER")
        _ensure_column(conn, "sync_devices", "empty_backoff_factor", "empty_backoff_factor REAL")
        _ensure_column(conn, "sync_devices", "empty_backoff_max_ms", "empty_backoff_max_ms INTEGER")

        _ensure_column(conn, "sync_devices", "authorize_timezone_id", "authorize_timezone_id INTEGER")
        _ensure_column(conn, "sync_devices", "pushing_to_device_policy", "pushing_to_device_policy TEXT")

        # -----------------------------
        # door presets synced from backend (GymDeviceDoorPresetDto)
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_device_door_presets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                remote_id INTEGER,
                device_id INTEGER NOT NULL,
                door_number INTEGER NOT NULL,
                pulse_seconds INTEGER NOT NULL,
                door_name TEXT NOT NULL,
                created_at TEXT,
                updated_at TEXT
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sync_ddp_device_id ON sync_device_door_presets(device_id);")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_sync_ddp_remote_id ON sync_device_door_presets(remote_id);")

        # -----------------------------
        # infrastructures
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_infrastructures (
                id INTEGER,
                name TEXT,
                gym_agent_json TEXT,
                created_at TEXT,
                updated_at TEXT
            );
            """
        )

        # -----------------------------
        # gym access credentials (TOTP secret grants)
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_gym_access_credentials (
                id INTEGER,
                gym_id INTEGER,
                account_id INTEGER,
                secret_hex TEXT,
                enabled INTEGER,
                rotated_at TEXT,
                created_at TEXT,
                updated_at TEXT,
                granted_active_membership_ids_json TEXT
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sync_gac_gym_id ON sync_gym_access_credentials(gym_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sync_gac_account_id ON sync_gym_access_credentials(account_id);")

        # -----------------------------
        # local door presets per device (legacy/local UI editable)
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_door_presets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                door_number INTEGER NOT NULL,
                pulse_seconds INTEGER NOT NULL,
                door_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(device_id, door_number, door_name)
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_device_door_presets_device_id ON device_door_presets(device_id);")

        # -----------------------------
        # realtime rtlog cursor
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_rtlog_state (
                device_id INTEGER PRIMARY KEY,
                last_event_at TEXT,
                last_event_id TEXT,
                updated_at TEXT NOT NULL
            );
            """
        )

        # -----------------------------
        # realtime access history
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS access_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                event_id TEXT NOT NULL,
                device_id INTEGER,
                door_id INTEGER,
                card_no TEXT,
                event_time TEXT,
                event_type TEXT,
                allowed INTEGER,
                reason TEXT,
                poll_ms REAL,
                decision_ms REAL,
                cmd_ms REAL,
                cmd_ok INTEGER,
                cmd_error TEXT,
                raw_json TEXT,
                UNIQUE(event_id)
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_access_history_device_time ON access_history(device_id, event_time);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_access_history_created_at ON access_history(created_at);")

        # -----------------------------
        # device sync incremental state (per-device+pin)
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_sync_state (
                device_id INTEGER NOT NULL,
                pin TEXT NOT NULL,
                desired_hash TEXT,
                last_ok INTEGER NOT NULL DEFAULT 1,
                last_error TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (device_id, pin)
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_device_sync_state_device ON device_sync_state(device_id);")

        conn.commit()


# -----------------------------
# Fingerprints (local enroll cache)
# -----------------------------
@dataclass
class FingerprintRecord:
    id: int
    created_at: str
    label: str
    pin: str
    card_no: str
    finger_id: int
    template_version: int
    template_encoding: str
    template_data: str
    template_size: int


def insert_fingerprint(
    *,
    label: str,
    pin: str,
    card_no: str,
    finger_id: int,
    template_version: int,
    template_encoding: str,
    template_data: str,
    template_size: int,
) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO fingerprints
            (created_at, label, pin, card_no, finger_id, template_version, template_encoding, template_data, template_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (now_iso(), label, pin, card_no, finger_id, template_version, template_encoding, template_data, template_size),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_fingerprints() -> List[FingerprintRecord]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM fingerprints ORDER BY id DESC").fetchall()
        return [FingerprintRecord(**dict(r)) for r in rows]


def get_fingerprint(fp_id: int) -> Optional[FingerprintRecord]:
    with get_conn() as conn:
        r = conn.execute("SELECT * FROM fingerprints WHERE id=?", (int(fp_id),)).fetchone()
        return FingerprintRecord(**dict(r)) if r else None


def delete_fingerprint(fp_id: int) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM fingerprints WHERE id=?", (int(fp_id),))
        conn.commit()


# -----------------------------
# Door presets per device (local editable)
# -----------------------------
@dataclass
class DeviceDoorPreset:
    id: int
    device_id: int
    door_number: int
    pulse_seconds: int
    door_name: str
    created_at: str
    updated_at: str


def _clamp_int(v: Any, default: int, min_v: int, max_v: int) -> int:
    try:
        x = int(str(v).strip())
    except Exception:
        x = default
    if x < min_v:
        x = min_v
    if x > max_v:
        x = max_v
    return x


def list_device_door_presets(device_id: int) -> List[DeviceDoorPreset]:
    did = int(device_id)
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT * FROM device_door_presets
            WHERE device_id=?
            ORDER BY door_number ASC, id ASC
            """,
            (did,),
        ).fetchall()
        return [DeviceDoorPreset(**dict(r)) for r in rows]


def create_device_door_preset(
    *,
    device_id: int,
    door_number: int,
    pulse_seconds: int,
    door_name: str,
    max_per_device: int = 10,
) -> int:
    did = int(device_id)
    dn = _clamp_int(door_number, 1, 1, 64)
    ps = _clamp_int(pulse_seconds, 3, 1, 60)
    name = (door_name or "").strip()
    if not name:
        raise ValueError("Door name is required.")

    with get_conn() as conn:
        cur = conn.execute("SELECT COUNT(*) AS c FROM device_door_presets WHERE device_id=?", (did,))
        c = int(cur.fetchone()["c"])  # type: ignore[index]
        if c >= int(max_per_device):
            raise ValueError(f"Max presets per device is {max_per_device}.")

        now = now_iso()
        cur2 = conn.execute(
            """
            INSERT INTO device_door_presets
            (device_id, door_number, pulse_seconds, door_name, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (did, dn, ps, name, now, now),
        )
        conn.commit()
        return int(cur2.lastrowid)


def update_device_door_preset(
    *,
    preset_id: int,
    device_id: int,
    door_number: int,
    pulse_seconds: int,
    door_name: str,
    max_per_device: int = 10,
) -> None:
    pid = int(preset_id)
    did = int(device_id)
    dn = _clamp_int(door_number, 1, 1, 64)
    ps = _clamp_int(pulse_seconds, 3, 1, 60)
    name = (door_name or "").strip()
    if not name:
        raise ValueError("Door name is required.")

    with get_conn() as conn:
        r = conn.execute("SELECT id, device_id FROM device_door_presets WHERE id=?", (pid,)).fetchone()
        if not r:
            raise ValueError("Preset not found.")

        old_did = int(r["device_id"])  # type: ignore[index]
        if old_did != did:
            cur = conn.execute("SELECT COUNT(*) AS c FROM device_door_presets WHERE device_id=?", (did,))
            c = int(cur.fetchone()["c"])  # type: ignore[index]
            if c >= int(max_per_device):
                raise ValueError(f"Max presets per device is {max_per_device}.")

        conn.execute(
            """
            UPDATE device_door_presets
            SET device_id=?, door_number=?, pulse_seconds=?, door_name=?, updated_at=?
            WHERE id=?
            """,
            (did, dn, ps, name, now_iso(), pid),
        )
        conn.commit()


def delete_device_door_preset(preset_id: int) -> None:
    pid = int(preset_id)
    with get_conn() as conn:
        conn.execute("DELETE FROM device_door_presets WHERE id=?", (pid,))
        conn.commit()


# -----------------------------
# Auth token state
# -----------------------------
@dataclass
class AuthTokenState:
    email: str
    token: str
    last_login_at: str


def save_auth_token(*, email: str, token: str, last_login_at: str | None = None) -> None:
    last_login_at = last_login_at or now_iso()
    protected = _dpapi_encrypt(token)

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO auth_state (id, email, token_protected, last_login_at)
            VALUES (1, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                email=excluded.email,
                token_protected=excluded.token_protected,
                last_login_at=excluded.last_login_at
            """,
            (email, protected, last_login_at),
        )
        conn.commit()


def load_auth_token() -> AuthTokenState | None:
    with get_conn() as conn:
        r = conn.execute("SELECT email, token_protected, last_login_at FROM auth_state WHERE id=1").fetchone()
        if not r:
            return None
        email = (r["email"] or "").strip()
        token = _dpapi_decrypt(r["token_protected"] or "")
        last_login_at = r["last_login_at"] or ""
        if not token:
            return None
        return AuthTokenState(email=email, token=token, last_login_at=last_login_at)


def clear_auth_token() -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM auth_state WHERE id=1")
        conn.commit()


# -----------------------------
# Sync cache (ActiveMemberResponse)
# -----------------------------
@dataclass
class SyncCacheState:
    contract_status: bool
    contract_end_date: str
    access_software_settings: Optional[Dict[str, Any]]
    users: List[Dict[str, Any]]
    membership: List[Dict[str, Any]]
    devices: List[Dict[str, Any]]
    infrastructures: List[Dict[str, Any]]
    gym_access_credentials: List[Dict[str, Any]] = field(default_factory=list)
    updated_at: str = ""


def _bool_to_i(v: Any, default: int = 0) -> int:
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, (int, float)):
        return 1 if int(v) != 0 else 0
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("1", "true", "yes", "y", "on"):
            return 1
        if s in ("0", "false", "no", "n", "off"):
            return 0
    return int(default)


def _to_int_or_none(v: Any) -> int | None:
    try:
        if v is None:
            return None
        s = str(v).strip()
        if not s:
            return None
        return int(s)
    except Exception:
        return None


def _to_float_or_none(v: Any) -> float | None:
    try:
        if v is None:
            return None
        s = str(v).strip()
        if not s:
            return None
        return float(s)
    except Exception:
        return None


def _safe_str(v: Any, default: str = "") -> str:
    if v is None:
        return default
    try:
        return str(v)
    except Exception:
        return default


def save_sync_cache(data: Optional[Dict[str, Any]]) -> None:
    """
    Persist ActiveMemberResponse payload and normalized tables.
    If data is None/empty, clears cached sync tables (best-effort).
    """
    if not data:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM sync_cache WHERE id=1")
            cur.execute("DELETE FROM sync_meta WHERE id=1")
            cur.execute("DELETE FROM sync_users")
            cur.execute("DELETE FROM sync_memberships")
            cur.execute("DELETE FROM sync_devices")
            cur.execute("DELETE FROM sync_infrastructures")
            cur.execute("DELETE FROM sync_gym_access_credentials")
            cur.execute("DELETE FROM sync_device_door_presets")
            # keep sync_access_software_settings row (it is "settings", not "cache json")
            conn.commit()
        return

    payload_json = json.dumps(data or {}, ensure_ascii=False)
    updated_at = now_iso()

    contract_status = bool(data.get("contractStatus", False))
    contract_end_date = (data.get("contractEndDate") or "").strip()

    access_settings = data.get("accessSoftwareSettings") or data.get("access_software_settings") or None

    users = data.get("users") or []
    memberships = data.get("membership") or data.get("memberships") or []
    devices = data.get("devices") or []
    infrastructures = data.get("infrastructures") or data.get("infrastructure") or []
    gym_access_credentials = data.get("gymAccessCredentials") or data.get("gym_access_credentials") or []

    with get_conn() as conn:
        cur = conn.cursor()

        # cache payload json (debug / fallback)
        cur.execute(
            """
            INSERT INTO sync_cache (id, updated_at, payload_json)
            VALUES (1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                updated_at=excluded.updated_at,
                payload_json=excluded.payload_json
            """,
            (updated_at, payload_json),
        )

        # meta
        cur.execute(
            """
            INSERT INTO sync_meta (id, contract_status, contract_end_date, updated_at)
            VALUES (1, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                contract_status=excluded.contract_status,
                contract_end_date=excluded.contract_end_date,
                updated_at=excluded.updated_at
            """,
            (1 if contract_status else 0, contract_end_date, updated_at),
        )

        # clear normalized tables
        cur.execute("DELETE FROM sync_users")
        cur.execute("DELETE FROM sync_memberships")
        cur.execute("DELETE FROM sync_devices")
        cur.execute("DELETE FROM sync_infrastructures")
        cur.execute("DELETE FROM sync_gym_access_credentials")
        cur.execute("DELETE FROM sync_device_door_presets")

        # access settings (single row)
        if isinstance(access_settings, dict):
            s = access_settings
            try:
                cur.execute(
                    """
                    INSERT INTO sync_access_software_settings (
                        id,
                        gym_id,
                        access_server_host,
                        access_server_port,
                        access_server_enabled,

                        image_cache_enabled,
                        image_cache_timeout_sec,
                        image_cache_max_bytes,
                        image_cache_max_files,

                        event_queue_max,
                        notification_queue_max,
                        history_queue_max,
                        popup_queue_max,

                        decision_workers,
                        decision_ema_alpha,

                        history_retention_days,
                        notification_rate_limit_per_minute,
                        notification_dedupe_window_sec,

                        notification_service_enabled,
                        history_service_enabled,

                        agent_sync_backend_refresh_min,

                        default_authorize_door_id,
                        sdk_read_initial_bytes,

                        created_at,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        gym_id=excluded.gym_id,
                        access_server_host=excluded.access_server_host,
                        access_server_port=excluded.access_server_port,
                        access_server_enabled=excluded.access_server_enabled,

                        image_cache_enabled=excluded.image_cache_enabled,
                        image_cache_timeout_sec=excluded.image_cache_timeout_sec,
                        image_cache_max_bytes=excluded.image_cache_max_bytes,
                        image_cache_max_files=excluded.image_cache_max_files,

                        event_queue_max=excluded.event_queue_max,
                        notification_queue_max=excluded.notification_queue_max,
                        history_queue_max=excluded.history_queue_max,
                        popup_queue_max=excluded.popup_queue_max,

                        decision_workers=excluded.decision_workers,
                        decision_ema_alpha=excluded.decision_ema_alpha,

                        history_retention_days=excluded.history_retention_days,
                        notification_rate_limit_per_minute=excluded.notification_rate_limit_per_minute,
                        notification_dedupe_window_sec=excluded.notification_dedupe_window_sec,

                        notification_service_enabled=excluded.notification_service_enabled,
                        history_service_enabled=excluded.history_service_enabled,

                        agent_sync_backend_refresh_min=excluded.agent_sync_backend_refresh_min,

                        default_authorize_door_id=excluded.default_authorize_door_id,
                        sdk_read_initial_bytes=excluded.sdk_read_initial_bytes,

                        created_at=excluded.created_at,
                        updated_at=excluded.updated_at
                    """,
                    (
                        1,
                        _to_int_or_none(s.get("gymId") if "gymId" in s else s.get("gym_id")),
                        _safe_str(s.get("accessServerHost") if "accessServerHost" in s else s.get("access_server_host"), ""),
                        _to_int_or_none(s.get("accessServerPort") if "accessServerPort" in s else s.get("access_server_port")),
                        _bool_to_i(s.get("accessServerEnabled", True), default=1),

                        _bool_to_i(s.get("imageCacheEnabled", True), default=1),
                        _to_int_or_none(s.get("imageCacheTimeoutSec", 2)),
                        _to_int_or_none(s.get("imageCacheMaxBytes", 5242880)),
                        _to_int_or_none(s.get("imageCacheMaxFiles", 1000)),

                        _to_int_or_none(s.get("eventQueueMax", 5000)),
                        _to_int_or_none(s.get("notificationQueueMax", 5000)),
                        _to_int_or_none(s.get("historyQueueMax", 5000)),
                        _to_int_or_none(s.get("popupQueueMax", 5000)),

                        _to_int_or_none(s.get("decisionWorkers", 1)),
                        _to_float_or_none(s.get("decisionEmaAlpha", 0.2)),

                        _to_int_or_none(s.get("historyRetentionDays", 30)),
                        _to_int_or_none(s.get("notificationRateLimitPerMinute", 30)),
                        _to_int_or_none(s.get("notificationDedupeWindowSec", 30)),

                        _bool_to_i(s.get("notificationServiceEnabled", True), default=1),
                        _bool_to_i(s.get("historyServiceEnabled", True), default=1),

                        _to_int_or_none(s.get("agentSyncBackendRefreshMin", 30)),

                        _to_int_or_none(s.get("defaultAuthorizeDoorId", 15)),
                        _to_int_or_none(s.get("sdkReadInitialBytes", 1048576)),

                        _safe_str(s.get("createdAt"), ""),
                        _safe_str(s.get("updatedAt"), updated_at) or updated_at,
                    ),
                )
            except Exception:
                # never break sync
                pass

        # users
        for u in users:
            if not isinstance(u, dict):
                continue

            fps = u.get("fingerprints") or []
            if not isinstance(fps, list):
                fps = []

            am_id = u.get("activeMembershipId")
            m_id = u.get("membershipId")
            if am_id is None or str(am_id).strip() == "":
                am_id = m_id

            cur.execute(
                """
                INSERT INTO sync_users (
                    user_id,
                    active_membership_id,
                    membership_id,
                    full_name, phone, email, valid_from, valid_to,
                    first_card_id, second_card_id, image,
                    fingerprints_json,
                    face_id, qr_code_payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    u.get("userId"),
                    am_id,
                    m_id,
                    u.get("fullName"),
                    u.get("phone"),
                    u.get("email"),
                    u.get("validFrom"),
                    u.get("validTo"),
                    u.get("firstCardId"),
                    u.get("secondCardId"),
                    u.get("image"),
                    json.dumps(fps, ensure_ascii=False),
                    u.get("faceId"),
                    u.get("qrCodePayload"),
                ),
            )

        # memberships
        for m in memberships:
            if not isinstance(m, dict):
                continue
            cur.execute(
                """
                INSERT INTO sync_memberships (id, title, description, price, duration_in_days)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    m.get("id"),
                    m.get("title"),
                    m.get("description"),
                    m.get("price"),
                    m.get("durationInDays"),
                ),
            )

        # devices + synced door presets
        for d in devices:
            if not isinstance(d, dict):
                continue

            # save presets (synced)
            presets = d.get("doorPresets") or []
            if isinstance(presets, list):
                for p in presets:
                    if not isinstance(p, dict):
                        continue
                    cur.execute(
                        """
                        INSERT INTO sync_device_door_presets (
                            remote_id, device_id, door_number, pulse_seconds, door_name, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            _to_int_or_none(p.get("id")),
                            _to_int_or_none(p.get("deviceId") or d.get("id")),
                            _to_int_or_none(p.get("doorNumber")),
                            _to_int_or_none(p.get("pulseSeconds")),
                            _safe_str(p.get("doorName"), ""),
                            _safe_str(p.get("createdAt"), None),
                            _safe_str(p.get("updatedAt"), None),
                        ),
                    )

            # normalize accessDataMode
            adm_raw = d.get("accessDataMode") or d.get("access_data_mode") or "DEVICE"
            adm = str(adm_raw or "").strip().upper()
            if adm not in ("DEVICE", "AGENT"):
                adm = "DEVICE"

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

                    rtlog_table, save_history, platform,

                    totp_enabled, rfid_enabled, fingerprint_enabled, face_id_enabled,

                    adaptive_sleep, busy_sleep_min_ms, busy_sleep_max_ms,
                    empty_sleep_min_ms, empty_sleep_max_ms,
                    empty_backoff_factor, empty_backoff_max_ms,

                    authorize_timezone_id, pushing_to_device_policy,

                    created_at, updated_at
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
                    ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?,
                    ?, ?
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
                ),
            )

        # infrastructures
        for inf in infrastructures:
            if not isinstance(inf, dict):
                continue
            cur.execute(
                """
                INSERT INTO sync_infrastructures (id, name, gym_agent_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    inf.get("id"),
                    inf.get("name"),
                    json.dumps(inf.get("gymAgent") or {}, ensure_ascii=False),
                    inf.get("createdAt"),
                    inf.get("updatedAt"),
                ),
            )

        # gym access credentials
        for c in gym_access_credentials:
            if not isinstance(c, dict):
                continue

            granted_ids = c.get("grantedActiveMembershipIds")
            if not isinstance(granted_ids, list):
                granted_ids = []

            cid = _to_int_or_none(c.get("id"))
            gym_id = _to_int_or_none(c.get("gymId") if "gymId" in c else c.get("gym_id"))
            account_id = _to_int_or_none(c.get("accountId") if "accountId" in c else c.get("account_id"))
            secret_hex = (c.get("secretHex") if "secretHex" in c else c.get("secret_hex")) or ""
            enabled = 1 if bool(c.get("enabled", False)) else 0

            cur.execute(
                """
                INSERT INTO sync_gym_access_credentials (
                    id, gym_id, account_id, secret_hex, enabled,
                    rotated_at, created_at, updated_at,
                    granted_active_membership_ids_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cid,
                    gym_id,
                    account_id,
                    str(secret_hex or ""),
                    enabled,
                    c.get("rotatedAt") or c.get("rotated_at"),
                    c.get("createdAt") or c.get("created_at"),
                    c.get("updatedAt") or c.get("updated_at"),
                    json.dumps(granted_ids, ensure_ascii=False),
                ),
            )

        conn.commit()


def _coerce_user_row_to_payload(u: Dict[str, Any]) -> Dict[str, Any]:
    def g(*keys, default=None):
        for k in keys:
            if k in u:
                return u.get(k)
        return default

    fps_raw = g("fingerprints", "fingerprints_json", default=None)
    fps: List[Dict[str, Any]] = []
    if isinstance(fps_raw, list):
        fps = fps_raw  # type: ignore[assignment]
    elif isinstance(fps_raw, str) and fps_raw.strip():
        try:
            x = json.loads(fps_raw)
            if isinstance(x, list):
                fps = x  # type: ignore[assignment]
        except Exception:
            fps = []
    else:
        fps = []

    active_membership_id = g("activeMembershipId", "active_membership_id", default=None)
    membership_id = g("membershipId", "membership_id", default=None)

    return {
        "userId": g("userId", "userid", "user_id", "id"),
        "activeMembershipId": active_membership_id,
        "membershipId": membership_id,
        "fullName": g("fullName", "full_name", "name"),
        "phone": g("phone"),
        "email": g("email"),
        "validFrom": g("validFrom", "valid_from"),
        "validTo": g("validTo", "valid_to"),
        "firstCardId": g("firstCardId", "first_card_id"),
        "secondCardId": g("secondCardId", "second_card_id"),
        "image": g("image"),
        "fingerprints": fps,
        "faceId": g("faceId", "face_id"),
        "qrCodePayload": g("qrCodePayload", "qr_code_payload"),
    }


def _expand_device_json_fields(d: Dict[str, Any]) -> Dict[str, Any]:
    dd = dict(d or {})
    try:
        dd["allowed_memberships"] = json.loads(dd.get("allowed_memberships_json") or "[]")
    except Exception:
        dd["allowed_memberships"] = []
    try:
        dd["installed_models"] = json.loads(dd.get("installed_models_json") or "[]")
    except Exception:
        dd["installed_models"] = []
    try:
        dd["door_ids"] = json.loads(dd.get("door_ids_json") or "[]")
    except Exception:
        dd["door_ids"] = []
    return dd


def _load_synced_door_presets_index() -> Dict[int, List[Dict[str, Any]]]:
    """
    Returns {device_id: [ {id, deviceId, doorNumber, pulseSeconds, doorName}, ... ] }
    """
    idx: Dict[int, List[Dict[str, Any]]] = {}
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT remote_id, device_id, door_number, pulse_seconds, door_name, created_at, updated_at
            FROM sync_device_door_presets
            ORDER BY device_id ASC, door_number ASC, remote_id ASC, id ASC
            """
        ).fetchall()

        for r in rows:
            did = _to_int_or_none(r["device_id"])  # type: ignore[index]
            if did is None:
                continue
            rid = _to_int_or_none(r["remote_id"])  # type: ignore[index]
            idx.setdefault(int(did), []).append(
                {
                    "id": rid,
                    "deviceId": int(did),
                    "doorNumber": _to_int_or_none(r["door_number"]),  # type: ignore[index]
                    "pulseSeconds": _to_int_or_none(r["pulse_seconds"]),  # type: ignore[index]
                    "doorName": _safe_str(r["door_name"], ""),  # type: ignore[index]
                    "createdAt": _safe_str(r["created_at"], ""),  # type: ignore[index]
                    "updatedAt": _safe_str(r["updated_at"], ""),  # type: ignore[index]
                }
            )
    return idx


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
    if adm not in ("DEVICE", "AGENT"):
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

        # attached later by list_sync_devices_payload (synced presets)
        "doorPresets": g("doorPresets", "door_presets", default=None) or [],
    }


def _expand_gym_access_credential_json_fields(c: Dict[str, Any]) -> Dict[str, Any]:
    cc = dict(c or {})
    raw = cc.get("granted_active_membership_ids_json")
    if raw is None:
        raw = cc.get("grantedActiveMembershipIds")
    try:
        cc["granted_active_membership_ids"] = json.loads(raw or "[]") if isinstance(raw, str) else (raw or [])
        if not isinstance(cc["granted_active_membership_ids"], list):
            cc["granted_active_membership_ids"] = []
    except Exception:
        cc["granted_active_membership_ids"] = []
    return cc


def _coerce_gym_access_credential_row_to_payload(c: Dict[str, Any]) -> Dict[str, Any]:
    def g(*keys, default=None):
        for k in keys:
            if k in c:
                return c.get(k)
        return default

    enabled_raw = g("enabled", default=False)
    if isinstance(enabled_raw, str):
        enabled = enabled_raw.strip().lower() in ("1", "true", "yes", "y", "on")
    elif isinstance(enabled_raw, (int, float)):
        enabled = int(enabled_raw) != 0
    else:
        enabled = bool(enabled_raw)

    granted = g("grantedActiveMembershipIds", "granted_active_membership_ids", default=None)
    if not isinstance(granted, list):
        granted = []

    return {
        "id": g("id"),
        "gymId": g("gymId", "gym_id"),
        "accountId": g("accountId", "account_id"),
        "secretHex": g("secretHex", "secret_hex"),
        "enabled": enabled,
        "rotatedAt": g("rotatedAt", "rotated_at"),
        "createdAt": g("createdAt", "created_at"),
        "updatedAt": g("updatedAt", "updated_at"),
        "grantedActiveMembershipIds": granted,
    }


def load_sync_access_software_settings() -> Optional[Dict[str, Any]]:
    """
    Returns a dict matching GymAccessSoftwareSettingsDto field names (camelCase),
    or None if not present.
    """
    with get_conn() as conn:
        r = conn.execute(
            """
            SELECT
                gym_id,
                access_server_host, access_server_port, access_server_enabled,
                image_cache_enabled, image_cache_timeout_sec, image_cache_max_bytes, image_cache_max_files,
                event_queue_max, notification_queue_max, history_queue_max, popup_queue_max,
                decision_workers, decision_ema_alpha,
                history_retention_days, notification_rate_limit_per_minute, notification_dedupe_window_sec,
                notification_service_enabled, history_service_enabled,
                agent_sync_backend_refresh_min,
                default_authorize_door_id,
                sdk_read_initial_bytes,
                created_at, updated_at
            FROM sync_access_software_settings
            WHERE id=1
            """
        ).fetchone()
        if not r:
            return None

        d = dict(r)
        return {
            "gymId": d.get("gym_id"),
            "accessServerHost": d.get("access_server_host"),
            "accessServerPort": d.get("access_server_port"),
            "accessServerEnabled": bool(int(d.get("access_server_enabled") or 0)),

            "imageCacheEnabled": bool(int(d.get("image_cache_enabled") or 0)),
            "imageCacheTimeoutSec": d.get("image_cache_timeout_sec"),
            "imageCacheMaxBytes": d.get("image_cache_max_bytes"),
            "imageCacheMaxFiles": d.get("image_cache_max_files"),

            "eventQueueMax": d.get("event_queue_max"),
            "notificationQueueMax": d.get("notification_queue_max"),
            "historyQueueMax": d.get("history_queue_max"),
            "popupQueueMax": d.get("popup_queue_max"),

            "decisionWorkers": d.get("decision_workers"),
            "decisionEmaAlpha": d.get("decision_ema_alpha"),

            "historyRetentionDays": d.get("history_retention_days"),
            "notificationRateLimitPerMinute": d.get("notification_rate_limit_per_minute"),
            "notificationDedupeWindowSec": d.get("notification_dedupe_window_sec"),

            "notificationServiceEnabled": bool(int(d.get("notification_service_enabled") or 0)),
            "historyServiceEnabled": bool(int(d.get("history_service_enabled") or 0)),

            "agentSyncBackendRefreshMin": d.get("agent_sync_backend_refresh_min"),

            "defaultAuthorizeDoorId": d.get("default_authorize_door_id"),
            "sdkReadInitialBytes": d.get("sdk_read_initial_bytes"),

            "createdAt": d.get("created_at"),
            "updatedAt": d.get("updated_at"),
        }


def load_sync_cache() -> SyncCacheState | None:
    with get_conn() as conn:
        meta = conn.execute("SELECT contract_status, contract_end_date, updated_at FROM sync_meta WHERE id=1").fetchone()
        if not meta:
            raw = conn.execute("SELECT updated_at, payload_json FROM sync_cache WHERE id=1").fetchone()
            if not raw:
                return None
            try:
                data = json.loads(raw["payload_json"] or "{}")
            except Exception:
                return None

            users = list(data.get("users") or [])
            norm_users: List[Dict[str, Any]] = []
            for u in users:
                if isinstance(u, dict):
                    norm_users.append(_coerce_user_row_to_payload(u))

            devs = list(data.get("devices") or [])
            creds = list(data.get("gymAccessCredentials") or data.get("gym_access_credentials") or [])

            return SyncCacheState(
                contract_status=bool(data.get("contractStatus", False)),
                contract_end_date=(data.get("contractEndDate") or ""),
                access_software_settings=(data.get("accessSoftwareSettings") if isinstance(data.get("accessSoftwareSettings"), dict) else None),
                users=norm_users,
                membership=list(data.get("membership") or data.get("memberships") or []),
                devices=devs,
                infrastructures=list(data.get("infrastructures") or data.get("infrastructure") or []),
                gym_access_credentials=[c for c in creds if isinstance(c, dict)],
                updated_at=(raw["updated_at"] or ""),
            )

        contract_status = bool(int(meta["contract_status"]))
        contract_end_date = meta["contract_end_date"] or ""
        updated_at = meta["updated_at"] or ""

        access_settings = load_sync_access_software_settings()

        users_rows = [dict(r) for r in conn.execute("SELECT * FROM sync_users").fetchall()]
        users = [_coerce_user_row_to_payload(u) for u in users_rows]

        membership = [dict(r) for r in conn.execute("SELECT * FROM sync_memberships").fetchall()]

        devices_rows = [dict(r) for r in conn.execute("SELECT * FROM sync_devices").fetchall()]
        devices_rows = [_expand_device_json_fields(d) for d in devices_rows]

        presets_idx = _load_synced_door_presets_index()
        for d in devices_rows:
            try:
                did = _to_int_or_none(d.get("id"))
                d["door_presets"] = presets_idx.get(int(did), []) if did is not None else []
            except Exception:
                d["door_presets"] = []

        infrastructures = [dict(r) for r in conn.execute("SELECT * FROM sync_infrastructures").fetchall()]
        for inf in infrastructures:
            try:
                inf["gym_agent"] = json.loads(inf.get("gym_agent_json") or "{}")
            except Exception:
                inf["gym_agent"] = {}

        creds_rows = [dict(r) for r in conn.execute("SELECT * FROM sync_gym_access_credentials").fetchall()]
        creds_rows = [_expand_gym_access_credential_json_fields(c) for c in creds_rows]
        creds_payload = [_coerce_gym_access_credential_row_to_payload(c) for c in creds_rows]

        return SyncCacheState(
            contract_status=contract_status,
            contract_end_date=contract_end_date,
            access_software_settings=access_settings,
            users=users,
            membership=membership,
            devices=devices_rows,
            infrastructures=infrastructures,
            gym_access_credentials=creds_payload,
            updated_at=updated_at,
        )


def list_sync_users() -> List[Dict[str, Any]]:
    cache = load_sync_cache()
    return list(cache.users) if cache else []


def list_sync_memberships() -> List[Dict[str, Any]]:
    with get_conn() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM sync_memberships").fetchall()]


def list_sync_devices() -> List[Dict[str, Any]]:
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM sync_devices").fetchall()]

    out: List[Dict[str, Any]] = []
    presets_idx = _load_synced_door_presets_index()

    for d in rows:
        for k in ("allowed_memberships_json", "installed_models_json", "door_ids_json"):
            if k in d and d[k] is None:
                d[k] = "[]"

        dd = _expand_device_json_fields(d)
        did = _to_int_or_none(dd.get("id"))
        dd["door_presets"] = presets_idx.get(int(did), []) if did is not None else []
        out.append(dd)

    return out


def get_sync_device(device_id: int) -> Optional[Dict[str, Any]]:
    try:
        did = int(device_id)
    except Exception:
        return None

    with get_conn() as conn:
        r = conn.execute("SELECT * FROM sync_devices WHERE id=?", (did,)).fetchone()
        if not r:
            return None
        d = dict(r)
        for k in ("allowed_memberships_json", "installed_models_json", "door_ids_json"):
            if k in d and d[k] is None:
                d[k] = "[]"
        dd = _expand_device_json_fields(d)

    presets_idx = _load_synced_door_presets_index()
    dd["door_presets"] = presets_idx.get(int(did), [])
    return dd


def list_sync_devices_payload() -> List[Dict[str, Any]]:
    rows = list_sync_devices()
    payload: List[Dict[str, Any]] = []
    for d in rows:
        p = _coerce_device_row_to_payload(d)
        presets = d.get("door_presets") or []
        if isinstance(presets, list):
            p["doorPresets"] = presets
        payload.append(p)
    return payload


def get_sync_device_payload(device_id: int) -> Optional[Dict[str, Any]]:
    d = get_sync_device(device_id)
    if not d:
        return None
    p = _coerce_device_row_to_payload(d)
    presets = d.get("door_presets") or []
    if isinstance(presets, list):
        p["doorPresets"] = presets
    return p


def list_sync_infrastructures() -> List[Dict[str, Any]]:
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM sync_infrastructures").fetchall()]
        for inf in rows:
            try:
                inf["gym_agent"] = json.loads(inf.get("gym_agent_json") or "{}")
            except Exception:
                inf["gym_agent"] = {}
        return rows


def get_sync_access_software_settings_payload() -> Optional[Dict[str, Any]]:
    return load_sync_access_software_settings()


def list_sync_gym_access_credentials() -> List[Dict[str, Any]]:
    cache = load_sync_cache()
    return list(cache.gym_access_credentials) if cache else []


# -----------------------------
# DeviceSync per-device+pin state (hash-based incremental sync)
# -----------------------------
def list_device_sync_hashes(*, device_id: int) -> Dict[str, str]:
    did = int(device_id)
    with get_conn() as conn:
        rows = conn.execute("SELECT pin, desired_hash FROM device_sync_state WHERE device_id=?", (did,)).fetchall()
        out: Dict[str, str] = {}
        for r in rows:
            p = str(r["pin"] or "")
            h = str(r["desired_hash"] or "")
            if p:
                out[p] = h
        return out


def list_device_sync_pins(*, device_id: int) -> List[str]:
    did = int(device_id)
    with get_conn() as conn:
        rows = conn.execute("SELECT pin FROM device_sync_state WHERE device_id=?", (did,)).fetchall()
        return [str(r["pin"] or "") for r in rows if str(r["pin"] or "").strip()]


def save_device_sync_state(*, device_id: int, pin: str, desired_hash: str | None, ok: bool, error: str | None) -> None:
    did = int(device_id)
    p = str(pin or "").strip()
    if not p:
        return

    err = (str(error or "")[:1000]) if error else None
    ok_i = 1 if bool(ok) else 0
    dh = str(desired_hash or "").strip() if desired_hash else ""

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO device_sync_state (device_id, pin, desired_hash, last_ok, last_error, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id, pin) DO UPDATE SET
                desired_hash = CASE
                    WHEN excluded.last_ok = 1 THEN excluded.desired_hash
                    ELSE device_sync_state.desired_hash
                END,
                last_ok = excluded.last_ok,
                last_error = excluded.last_error,
                updated_at = excluded.updated_at
            """,
            (did, p, dh, ok_i, err, now_iso()),
        )
        conn.commit()


def delete_device_sync_state(*, device_id: int, pin: str) -> None:
    did = int(device_id)
    p = str(pin or "").strip()
    if not p:
        return
    with get_conn() as conn:
        conn.execute("DELETE FROM device_sync_state WHERE device_id=? AND pin=?", (did, p))
        conn.commit()


def prune_device_sync_state(*, device_id: int, keep_pins: Iterable[str]) -> int:
    did = int(device_id)
    keep = {str(x).strip() for x in (keep_pins or []) if str(x).strip()}
    existing = set(list_device_sync_pins(device_id=did))
    to_remove = sorted([p for p in existing if p not in keep])
    if not to_remove:
        return 0

    deleted = 0
    with get_conn() as conn:
        CHUNK = 300
        for i in range(0, len(to_remove), CHUNK):
            chunk = to_remove[i : i + CHUNK]
            q = ",".join(["?"] * len(chunk))
            cur = conn.execute(
                f"DELETE FROM device_sync_state WHERE device_id=? AND pin IN ({q})",
                (did, *chunk),
            )
            deleted += int(cur.rowcount or 0)
        conn.commit()
    return deleted


# -----------------------------
# Realtime RTLog cursor/state
# -----------------------------
@dataclass
class AgentRtlogState:
    device_id: int
    last_event_at: str
    last_event_id: str
    updated_at: str


def load_agent_rtlog_state(device_id: int) -> Optional[AgentRtlogState]:
    did = int(device_id)
    with get_conn() as conn:
        r = conn.execute(
            "SELECT device_id, last_event_at, last_event_id, updated_at FROM agent_rtlog_state WHERE device_id=?",
            (did,),
        ).fetchone()
        if not r:
            return None
        return AgentRtlogState(
            device_id=int(r["device_id"]),  # type: ignore[index]
            last_event_at=str(r["last_event_at"] or ""),
            last_event_id=str(r["last_event_id"] or ""),
            updated_at=str(r["updated_at"] or ""),
        )


def save_agent_rtlog_state(*, device_id: int, last_event_at: str, last_event_id: str) -> None:
    did = int(device_id)
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO agent_rtlog_state (device_id, last_event_at, last_event_id, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                last_event_at=excluded.last_event_at,
                last_event_id=excluded.last_event_id,
                updated_at=excluded.updated_at
            """,
            (did, str(last_event_at or ""), str(last_event_id or ""), now_iso()),
        )
        conn.commit()


# -----------------------------
# Access history (realtime engine)
# -----------------------------
@dataclass
class AccessHistoryRow:
    id: int
    created_at: str
    event_id: str
    device_id: Optional[int]
    door_id: Optional[int]
    card_no: str
    event_time: str
    event_type: str
    allowed: int
    reason: str
    poll_ms: Optional[float]
    decision_ms: Optional[float]
    cmd_ms: Optional[float]
    cmd_ok: Optional[int]
    cmd_error: Optional[str]
    raw_json: str


def access_history_exists(event_id: str) -> bool:
    eid = str(event_id or "").strip()
    if not eid:
        return False
    try:
        with get_conn() as conn:
            r = conn.execute("SELECT 1 FROM access_history WHERE event_id=? LIMIT 1", (eid,)).fetchone()
            return bool(r)
    except Exception:
        return False


def insert_access_history(
    *,
    event_id: str,
    device_id: int | None,
    door_id: int | None,
    card_no: str | None,
    event_time: str | None,
    event_type: str | None,
    allowed: bool,
    reason: str | None,
    poll_ms: float | None,
    decision_ms: float | None,
    cmd_ms: float | None,
    cmd_ok: bool | None,
    cmd_error: str | None,
    raw: Dict[str, Any] | None,
) -> None:
    if not str(event_id or "").strip():
        return

    with get_conn() as conn:
        try:
            conn.execute(
                """
                INSERT INTO access_history (
                    created_at, event_id, device_id, door_id, card_no,
                    event_time, event_type,
                    allowed, reason,
                    poll_ms, decision_ms, cmd_ms,
                    cmd_ok, cmd_error,
                    raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now_iso(),
                    str(event_id),
                    int(device_id) if device_id is not None else None,
                    int(door_id) if door_id is not None else None,
                    (str(card_no) if card_no is not None else None),
                    (str(event_time) if event_time is not None else None),
                    (str(event_type) if event_type is not None else None),
                    1 if bool(allowed) else 0,
                    (str(reason or "")[:500]),
                    float(poll_ms) if poll_ms is not None else None,
                    float(decision_ms) if decision_ms is not None else None,
                    float(cmd_ms) if cmd_ms is not None else None,
                    (1 if bool(cmd_ok) else 0) if cmd_ok is not None else None,
                    (str(cmd_error or "")[:1000]) if cmd_error else None,
                    json.dumps(raw or {}, ensure_ascii=False),
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return


def prune_access_history(*, retention_days: int) -> int:
    days = int(retention_days)
    if days < 1:
        days = 1
    with get_conn() as conn:
        cur = conn.execute(
            """
            DELETE FROM access_history
            WHERE julianday('now') - julianday(created_at) > ?
            """,
            (days,),
        )
        conn.commit()
        return int(cur.rowcount or 0)


def get_recent_access_history(*, limit: int = 10) -> List[AccessHistoryRow]:
    lim = int(limit)
    if lim < 1:
        lim = 1
    if lim > 500:
        lim = 500
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM access_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (lim,),
        ).fetchall()
        out: List[AccessHistoryRow] = []
        for r in rows:
            d = dict(r)
            out.append(AccessHistoryRow(**d))
        return out

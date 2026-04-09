# app/core/db.py
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, Iterator, List, Optional

from access.storage import current_access_runtime_db_path
from app.core.utils import ensure_dirs, now_iso
from shared.auth_state import AuthTokenState, protect_auth_token, unprotect_auth_token

# Test-only override: set _DB_PATH to a temp path in tests via monkeypatch.
# Production code always leaves this as None (falls through to current_access_runtime_db_path).
_DB_PATH: str | None = None

# -----------------------------
# SQLite connection helpers
# -----------------------------
@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    if _DB_PATH is not None:
        import pathlib
        db_path = pathlib.Path(_DB_PATH)
        db_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        ensure_dirs()
        db_path = current_access_runtime_db_path()
        db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA wal_autocheckpoint=1000")
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


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
            account_username_id TEXT,
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
            face_id, account_username_id, qr_code_payload
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
            {sel("account_username_id")},
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
                account_username_id TEXT,
                qr_code_payload TEXT,
                birthday TEXT
            );
            """
        )

        # F-027: Track backend upload status for fingerprints
        _ensure_column(conn, "fingerprints", "backend_confirmed", "backend_confirmed INTEGER NOT NULL DEFAULT 0")

        _ensure_column(conn, "sync_users", "fingerprints_json", "fingerprints_json TEXT")
        _ensure_column(conn, "sync_users", "active_membership_id", "active_membership_id INTEGER")
        _ensure_column(conn, "sync_users", "account_username_id", "account_username_id TEXT")
        _ensure_column(conn, "sync_users", "birthday",           "birthday TEXT")
        _ensure_column(conn, "sync_users", "image_source",       "image_source TEXT")
        _ensure_column(conn, "sync_users", "user_image_status",  "user_image_status TEXT")
        try:
            _rebuild_sync_users_without_legacy_fingerprint(conn)
        except Exception as _mig_exc:
            _logger.error("[DB] schema migration _rebuild_sync_users failed: %s", _mig_exc)

        # F-005: UNIQUE index on (user_id, active_membership_id) to prevent duplicate rows
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_sync_users_uid_amid ON sync_users(user_id, active_membership_id) WHERE user_id IS NOT NULL AND active_membership_id IS NOT NULL;")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sync_users_first_card ON sync_users(first_card_id) WHERE first_card_id IS NOT NULL;")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sync_users_second_card ON sync_users(second_card_id) WHERE second_card_id IS NOT NULL;")

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

                optional_data_sync_delay_minutes INTEGER,

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
        _ensure_column(conn, "sync_access_software_settings", "optional_data_sync_delay_minutes", "optional_data_sync_delay_minutes INTEGER")
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
                device_attendance_history_reading_delay_minutes INTEGER,
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
                updated_at TEXT,

                anti_fraude_card     INTEGER NOT NULL DEFAULT 1,
                anti_fraude_qr_code  INTEGER NOT NULL DEFAULT 1,
                anti_fraude_duration INTEGER NOT NULL DEFAULT 30
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
        _ensure_column(
            conn,
            "sync_devices",
            "device_attendance_history_reading_delay_minutes",
            "device_attendance_history_reading_delay_minutes INTEGER",
        )
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

        _ensure_column(conn, "sync_devices", "anti_fraude_card",     "anti_fraude_card INTEGER NOT NULL DEFAULT 1")
        _ensure_column(conn, "sync_devices", "anti_fraude_qr_code",  "anti_fraude_qr_code INTEGER NOT NULL DEFAULT 1")
        _ensure_column(conn, "sync_devices", "anti_fraude_duration", "anti_fraude_duration INTEGER NOT NULL DEFAULT 30")

        # F-015: Deduplicate sync_devices by id before adding unique index
        conn.execute("""
            DELETE FROM sync_devices WHERE rowid NOT IN (
                SELECT MIN(rowid) FROM sync_devices GROUP BY id
            )
        """)
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_sync_devices_id ON sync_devices(id);")

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
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_sync_gac_account_gym ON sync_gym_access_credentials(account_id, gym_id);")

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
                history_source TEXT NOT NULL DEFAULT 'AGENT',
                backend_sync_state TEXT NOT NULL DEFAULT 'PENDING',
                backend_attempt_count INTEGER NOT NULL DEFAULT 0,
                backend_failure_count INTEGER NOT NULL DEFAULT 0,
                backend_last_attempt_at TEXT,
                backend_next_retry_at TEXT,
                backend_synced_at TEXT,
                backend_last_error TEXT,
                UNIQUE(event_id)
            );
            """
        )
        _ensure_column(conn, "access_history", "history_source", "history_source TEXT NOT NULL DEFAULT 'AGENT'")
        _ensure_column(conn, "access_history", "backend_sync_state", "backend_sync_state TEXT NOT NULL DEFAULT 'PENDING'")
        _ensure_column(conn, "access_history", "backend_attempt_count", "backend_attempt_count INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "access_history", "backend_failure_count", "backend_failure_count INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "access_history", "backend_last_attempt_at", "backend_last_attempt_at TEXT")
        _ensure_column(conn, "access_history", "backend_next_retry_at", "backend_next_retry_at TEXT")
        _ensure_column(conn, "access_history", "backend_synced_at", "backend_synced_at TEXT")
        _ensure_column(conn, "access_history", "backend_last_error", "backend_last_error TEXT")
        conn.execute("UPDATE access_history SET history_source='AGENT' WHERE history_source IS NULL OR history_source=''")
        conn.execute("UPDATE access_history SET backend_sync_state='PENDING' WHERE backend_sync_state IS NULL OR backend_sync_state=''")
        conn.execute("UPDATE access_history SET backend_attempt_count=0 WHERE backend_attempt_count IS NULL")
        conn.execute("UPDATE access_history SET backend_failure_count=0 WHERE backend_failure_count IS NULL")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_access_history_device_time ON access_history(device_id, event_time);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_access_history_created_at ON access_history(created_at);")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_access_history_backend_sync "
            "ON access_history(backend_sync_state, backend_next_retry_at, id);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_access_history_source_time "
            "ON access_history(history_source, event_time);"
        )

        # -----------------------------
        # device attendance state (DEVICE-mode polling/upload/purge)
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_attendance_state (
                device_id INTEGER PRIMARY KEY,
                last_read_started_at TEXT,
                last_read_finished_at TEXT,
                last_read_event_count INTEGER NOT NULL DEFAULT 0,
                last_read_error TEXT,
                last_purge_at TEXT,
                last_purge_deleted_count INTEGER NOT NULL DEFAULT 0,
                last_purge_error TEXT,
                updated_at TEXT NOT NULL
            );
            """
        )

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

        # -----------------------------
        # offline creation queue (access-only)
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS offline_creation_queue (
                local_id TEXT PRIMARY KEY,
                client_request_id TEXT NOT NULL,
                creation_kind TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_hash TEXT,
                state TEXT NOT NULL DEFAULT 'pending',
                created INTEGER NOT NULL DEFAULT 0,
                try_to_create INTEGER NOT NULL DEFAULT 1,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                failure_count INTEGER NOT NULL DEFAULT 0,
                failure_type TEXT,
                failure_code TEXT,
                last_http_status INTEGER,
                last_error_message TEXT,
                failed_reason TEXT,
                last_attempt_at TEXT,
                next_retry_at TEXT,
                processing_started_at TEXT,
                processing_lock_token TEXT,
                processing_lock_expires_at TEXT,
                succeeded_at TEXT,
                reconciled_at TEXT,
                cancelled_at TEXT,
                archived_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )

        _ensure_column(conn, "offline_creation_queue", "payload_hash", "payload_hash TEXT")
        _ensure_column(conn, "offline_creation_queue", "state", "state TEXT NOT NULL DEFAULT 'pending'")
        _ensure_column(conn, "offline_creation_queue", "created", "created INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "offline_creation_queue", "try_to_create", "try_to_create INTEGER NOT NULL DEFAULT 1")
        _ensure_column(conn, "offline_creation_queue", "attempt_count", "attempt_count INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "offline_creation_queue", "failure_count", "failure_count INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "offline_creation_queue", "failure_type", "failure_type TEXT")
        _ensure_column(conn, "offline_creation_queue", "failure_code", "failure_code TEXT")
        _ensure_column(conn, "offline_creation_queue", "last_http_status", "last_http_status INTEGER")
        _ensure_column(conn, "offline_creation_queue", "last_error_message", "last_error_message TEXT")
        _ensure_column(conn, "offline_creation_queue", "failed_reason", "failed_reason TEXT")
        _ensure_column(conn, "offline_creation_queue", "last_attempt_at", "last_attempt_at TEXT")
        _ensure_column(conn, "offline_creation_queue", "next_retry_at", "next_retry_at TEXT")
        _ensure_column(conn, "offline_creation_queue", "processing_started_at", "processing_started_at TEXT")
        _ensure_column(conn, "offline_creation_queue", "processing_lock_token", "processing_lock_token TEXT")
        _ensure_column(conn, "offline_creation_queue", "processing_lock_expires_at", "processing_lock_expires_at TEXT")
        _ensure_column(conn, "offline_creation_queue", "succeeded_at", "succeeded_at TEXT")
        _ensure_column(conn, "offline_creation_queue", "reconciled_at", "reconciled_at TEXT")
        _ensure_column(conn, "offline_creation_queue", "cancelled_at", "cancelled_at TEXT")
        _ensure_column(conn, "offline_creation_queue", "archived_at", "archived_at TEXT")
        _ensure_column(conn, "offline_creation_queue", "created_at", "created_at TEXT")
        _ensure_column(conn, "offline_creation_queue", "updated_at", "updated_at TEXT")

        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_offline_creation_client_request_id ON offline_creation_queue(client_request_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_offline_creation_active_retry ON offline_creation_queue(state, try_to_create, next_retry_at);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_offline_creation_processing_lock ON offline_creation_queue(state, processing_lock_expires_at);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_offline_creation_history_state ON offline_creation_queue(state, updated_at);")

        # -----------------------------
        # optional content sync state (single row — version markers)
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS optional_sync_state (
                id INTEGER PRIMARY KEY CHECK (id=1),
                events_version_at TEXT,
                products_version_at TEXT,
                deals_version_at TEXT,
                last_sync_at TEXT
            );
            """
        )

        # -----------------------------
        # optional upcoming events (today's events for TV display)
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS optional_upcoming_events (
                id INTEGER PRIMARY KEY,
                title TEXT,
                sub_title TEXT,
                description TEXT,
                image TEXT,
                room TEXT,
                event_date TEXT,
                duration_in_minutes INTEGER,
                coach_name TEXT,
                price TEXT,
                category TEXT,
                available INTEGER NOT NULL DEFAULT 1,
                synced_at TEXT
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_optional_events_date ON optional_upcoming_events(event_date);")

        # -----------------------------
        # optional products cache
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS optional_products (
                id INTEGER PRIMARY KEY,
                title TEXT,
                model TEXT,
                description TEXT,
                image TEXT,
                category TEXT,
                price REAL,
                sale_price REAL,
                available_number INTEGER,
                available INTEGER NOT NULL DEFAULT 1,
                synced_at TEXT
            );
            """
        )

        # -----------------------------
        # optional deals cache (global admin deals)
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS optional_deals (
                id INTEGER PRIMARY KEY,
                title TEXT,
                description TEXT,
                header TEXT,
                image TEXT,
                deal_end_date TEXT,
                partner_name TEXT,
                available INTEGER NOT NULL DEFAULT 1,
                synced_at TEXT
            );
            """
        )

        # Backfill state defaults for legacy rows if they exist
        conn.execute("UPDATE offline_creation_queue SET created_at = COALESCE(created_at, updated_at, datetime('now')) WHERE created_at IS NULL OR created_at = '';")
        conn.execute("UPDATE offline_creation_queue SET updated_at = COALESCE(updated_at, created_at, datetime('now')) WHERE updated_at IS NULL OR updated_at = '';")
        conn.execute("UPDATE offline_creation_queue SET state = 'succeeded', succeeded_at = COALESCE(succeeded_at, updated_at, created_at) WHERE created = 1 AND (state IS NULL OR state = '' OR state IN ('pending','processing','failed_retryable','blocked_auth'));")
        conn.execute("UPDATE offline_creation_queue SET state = 'failed_terminal' WHERE created = 0 AND (try_to_create = 0 OR try_to_create = '0') AND (state IS NULL OR state = '' OR state IN ('pending','failed_retryable'));")
        conn.execute("UPDATE offline_creation_queue SET state = 'pending' WHERE state IS NULL OR state = '';")

        # -----------------------------
        # delta sync: version tokens
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_version_tokens (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )

        # Phase 2: firmware profile cache
        # Keyed by device_id (stable int) — not IP (DHCP can reassign IPs).
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_firmware_profiles (
                device_id            INTEGER PRIMARY KEY,
                template_table       TEXT    NOT NULL,
                template_body_index  INTEGER NOT NULL,
                authorize_body_index INTEGER NOT NULL,
                name_supported       INTEGER DEFAULT NULL,
                updated_at           TEXT    NOT NULL
            );
            """
        )

        conn.commit()

    # F-014: On startup, reset any stale processing locks in the offline queue
    try:
        n = reset_stale_processing_locks()
        if n > 0:
            import logging
            logging.getLogger("db").warning(f"[DB] Reset {n} stale processing lock(s) in offline_creation_queue on startup.")
    except Exception as _e:
        import logging
        logging.getLogger("db").error(f"[DB] Failed to reset stale processing locks on startup: {_e}")


# -----------------------------
# Delta sync: version tokens
# -----------------------------

def save_version_tokens(tokens: dict) -> None:
    """Upsert version tokens. keys: membersVersion, devicesVersion, credentialsVersion, settingsVersion."""
    if not tokens:
        return
    with get_conn() as conn:
        for key, value in tokens.items():
            if value is None:
                continue
            conn.execute(
                """
                INSERT INTO sync_version_tokens (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (key, str(value)),
            )
        conn.commit()


def load_version_tokens() -> dict:
    """Return all saved version tokens, or empty dict if none."""
    with get_conn() as conn:
        rows = conn.execute("SELECT key, value FROM sync_version_tokens").fetchall()
        return {r["key"]: r["value"] for r in rows}


def clear_version_tokens() -> None:
    """Delete all saved version tokens (call on logout/login/cache-clear)."""
    with get_conn() as conn:
        conn.execute("DELETE FROM sync_version_tokens")


# -----------------------------
# Phase 2: Firmware profile cache
# -----------------------------

def save_firmware_profile(
    *,
    device_id: int,
    template_table: str,
    template_body_index: int,
    authorize_body_index: int,
    name_supported: bool | None = None,
) -> None:
    """
    Upsert the firmware profile for a ZKTeco device.
    Keyed by device_id (stable integer) — not IP (DHCP can change IPs).
    """
    name_val = None if name_supported is None else (1 if name_supported else 0)
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO sync_firmware_profiles
                (device_id, template_table, template_body_index, authorize_body_index, name_supported, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                template_table       = excluded.template_table,
                template_body_index  = excluded.template_body_index,
                authorize_body_index = excluded.authorize_body_index,
                name_supported       = excluded.name_supported,
                updated_at           = excluded.updated_at
            """,
            (device_id, template_table, template_body_index, authorize_body_index, name_val, now_iso()),
        )
        conn.commit()


def load_firmware_profile(*, device_id: int) -> dict | None:
    """
    Load the cached firmware profile for a device, or None if not cached.
    Returns dict with keys: template_table, template_body_index, authorize_body_index.
    """
    with get_conn() as conn:
        row = conn.execute(
            "SELECT template_table, template_body_index, authorize_body_index, name_supported "
            "FROM sync_firmware_profiles WHERE device_id = ?",
            (device_id,),
        ).fetchone()
    if row is None:
        return None
    ns = row[3]
    return {
        "template_table": row[0],
        "template_body_index": row[1],
        "authorize_body_index": row[2],
        "name_supported": None if ns is None else bool(ns),
    }


def clear_firmware_profile(*, device_id: int) -> None:
    """Remove the cached firmware profile for a device (e.g., after firmware upgrade detected)."""
    with get_conn() as conn:
        conn.execute("DELETE FROM sync_firmware_profiles WHERE device_id = ?", (device_id,))
        conn.commit()


# -----------------------------
# Phase 3: Delta user cache
# -----------------------------

def upsert_delta_users(users: list[dict]) -> None:
    """
    Upsert (INSERT OR REPLACE) changed members into sync_users.
    Used by Phase 3 delta sync: only changed members are sent, so we upsert
    instead of DELETE-all + INSERT-all.

    H-006 guard does NOT apply here — delta mode with 0 users means only deletions,
    which are handled separately by delete_users_by_am_ids().
    """
    if not users:
        return
    with get_conn() as conn:
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
            conn.execute(
                """
                INSERT OR REPLACE INTO sync_users (
                    user_id, active_membership_id, membership_id,
                    full_name, phone, email, valid_from, valid_to,
                    first_card_id, second_card_id, image,
                    fingerprints_json, face_id, account_username_id,
                    qr_code_payload, birthday, image_source, user_image_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    u.get("userId"), am_id, m_id,
                    u.get("fullName"), u.get("phone"), u.get("email"),
                    u.get("validFrom"), u.get("validTo"),
                    u.get("firstCardId"), u.get("secondCardId"), u.get("image"),
                    json.dumps(fps, ensure_ascii=False),
                    u.get("faceId"),
                    u.get("accountUsernameId") or u.get("account_username_id"),
                    u.get("qrCodePayload"), u.get("birthday"),
                    u.get("imageSource"), u.get("userImageStatus"),
                ),
            )
        conn.commit()


def delete_users_by_am_ids(am_ids: set[int]) -> None:
    """
    Delete sync_users rows for the given active_membership_ids.
    Used by Phase 3 delta sync for client-side delete detection:
    local_ids - server_valid_ids = to_delete.
    """
    if not am_ids:
        return
    with get_conn() as conn:
        placeholders = ",".join("?" * len(am_ids))
        conn.execute(
            f"DELETE FROM sync_users WHERE active_membership_id IN ({placeholders})",
            list(am_ids),
        )
        conn.commit()


def get_all_cached_user_am_ids() -> list[int]:
    """
    Return all active_membership_id values currently in the sync_users cache.
    Used for delta delete detection: compare against server's validMemberIds.
    """
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT active_membership_id FROM sync_users WHERE active_membership_id IS NOT NULL"
        ).fetchall()
    return [r[0] for r in rows]


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
    backend_confirmed: int = 0  # F-027: 0=local-only (unconfirmed), 1=backend upload confirmed


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


def confirm_fingerprint_uploaded(fp_id: int) -> None:
    """
    F-027: Mark a fingerprint as confirmed uploaded to backend.
    Call this after a successful backend upload to clear orphan status.
    """
    with get_conn() as conn:
        conn.execute("UPDATE fingerprints SET backend_confirmed=1 WHERE id=?", (int(fp_id),))
        conn.commit()


def list_unconfirmed_fingerprints() -> List[FingerprintRecord]:
    """
    F-027: Return fingerprints with backend_confirmed=0.
    Records with backend_confirmed=0 are local-only and may be orphaned
    if backend upload never completes. Call confirm_fingerprint_uploaded()
    after successful backend upload.
    """
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM fingerprints WHERE backend_confirmed=0 ORDER BY id ASC"
        ).fetchall()
        return [FingerprintRecord(**dict(r)) for r in rows]


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


def _clamp_int_db(v: Any, default: int, min_v: int, max_v: int) -> int:
    # F-030: renamed from _clamp_int to _clamp_int_db to avoid shadowing settings_reader._clamp_int
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
    dn = _clamp_int_db(door_number, 1, 1, 64)
    ps = _clamp_int_db(pulse_seconds, 3, 1, 60)
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
    dn = _clamp_int_db(door_number, 1, 1, 64)
    ps = _clamp_int_db(pulse_seconds, 3, 1, 60)
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
def save_auth_token(*, email: str, token: str, last_login_at: str | None = None) -> None:
    last_login_at = last_login_at or now_iso()
    protected = protect_auth_token(token)

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
        token = unprotect_auth_token(r["token_protected"] or "")
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
    if adm not in ("DEVICE", "AGENT", "ULTRA"):
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

            rtlog_table, save_history, device_attendance_history_reading_delay_minutes, platform,

            totp_enabled, rfid_enabled, fingerprint_enabled, face_id_enabled,

            adaptive_sleep, busy_sleep_min_ms, busy_sleep_max_ms,
            empty_sleep_min_ms, empty_sleep_max_ms,
            empty_backoff_factor, empty_backoff_max_ms,

            authorize_timezone_id, pushing_to_device_policy,

            created_at, updated_at,

            anti_fraude_card, anti_fraude_qr_code, anti_fraude_duration
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
            ?, ?, ?, ?,
            ?, ?,
            ?, ?,
            ?, ?, ?
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
        ),
    )


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

        # H-006: Validate sync data before replacing cache.
        # If backend returns empty user list but we had >10 users before,
        # this is likely a backend error — refuse to wipe local cache.
        if not users:
            old_count = cur.execute("SELECT COUNT(*) FROM sync_users").fetchone()[0]
            if old_count > 10:
                import logging as _log
                _log.getLogger(__name__).error(
                    f"[DB] save_sync_cache: backend returned 0 users but local cache has {old_count}. "
                    "Refusing to clear — likely backend error. Skipping normalized table update."
                )
                conn.commit()
                return

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

                        optional_data_sync_delay_minutes,

                        created_at,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

                        optional_data_sync_delay_minutes=excluded.optional_data_sync_delay_minutes,

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

                        _to_int_or_none(s.get("optionalDataSyncDelayMinutes", 60)),

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
                INSERT OR REPLACE INTO sync_users (
                    user_id,
                    active_membership_id,
                    membership_id,
                    full_name, phone, email, valid_from, valid_to,
                    first_card_id, second_card_id, image,
                    fingerprints_json,
                    face_id, account_username_id, qr_code_payload, birthday,
                    image_source, user_image_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    u.get("accountUsernameId") or u.get("account_username_id"),
                    u.get("qrCodePayload"),
                    u.get("birthday"),
                    u.get("imageSource"),
                    u.get("userImageStatus"),
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
            _insert_device_row(cur, d)

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


def save_sync_cache_delta(data: dict, refresh: dict) -> None:
    """
    Delta-aware cache update. Only replaces sections where refresh[section] is True.
    Sections with refresh=False are left untouched in the local cache.

    refresh = {
        "members":     True/False,
        "devices":     True/False,
        "credentials": True/False,
        "settings":    True/False,
    }

    H-006 guard only applies when refreshMembers=True AND backend returns 0 users.
    """
    if not data:
        return

    import logging as _log
    _logger = _log.getLogger(__name__)

    updated_at = now_iso()
    contract_status = bool(data.get("contractStatus", False))
    contract_end_date = (data.get("contractEndDate") or "").strip()
    access_settings = data.get("accessSoftwareSettings") or data.get("access_software_settings") or None
    memberships = data.get("membership") or data.get("memberships") or []

    with get_conn() as conn:
        cur = conn.cursor()

        # Always: update contract meta
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

        # Always: update access software settings
        if isinstance(access_settings, dict):
            s = access_settings
            try:
                cur.execute(
                    """
                    INSERT INTO sync_access_software_settings (
                        id, gym_id, access_server_host, access_server_port, access_server_enabled,
                        image_cache_enabled, image_cache_timeout_sec, image_cache_max_bytes, image_cache_max_files,
                        event_queue_max, notification_queue_max, history_queue_max, popup_queue_max,
                        decision_workers, decision_ema_alpha,
                        history_retention_days, notification_rate_limit_per_minute, notification_dedupe_window_sec,
                        notification_service_enabled, history_service_enabled,
                        agent_sync_backend_refresh_min,
                        default_authorize_door_id, sdk_read_initial_bytes,
                        optional_data_sync_delay_minutes,
                        created_at, updated_at
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
                        optional_data_sync_delay_minutes=excluded.optional_data_sync_delay_minutes,
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
                        _to_int_or_none(s.get("optionalDataSyncDelayMinutes", 60)),
                        _safe_str(s.get("createdAt"), ""),
                        _safe_str(s.get("updatedAt"), updated_at) or updated_at,
                    ),
                )
            except Exception:
                pass  # never break sync

        # Always: update membership types
        cur.execute("DELETE FROM sync_memberships")
        for m in memberships:
            if not isinstance(m, dict):
                continue
            cur.execute(
                "INSERT INTO sync_memberships (id, title, description, price, duration_in_days) VALUES (?, ?, ?, ?, ?)",
                (m.get("id"), m.get("title"), m.get("description"), m.get("price"), m.get("durationInDays")),
            )

        # Conditional: members (users + fingerprints)
        if refresh.get("members", True):
            users = data.get("users") or []
            delta_mode = bool(data.get("membersDeltaMode", False))
            valid_ids = data.get("validMemberIds")

            if delta_mode:
                # Delta mode: upsert changed users + delete ones absent from validMemberIds
                if users:
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
                            INSERT OR REPLACE INTO sync_users (
                                user_id, active_membership_id, membership_id,
                                full_name, phone, email, valid_from, valid_to,
                                first_card_id, second_card_id, image,
                                fingerprints_json, face_id, account_username_id, qr_code_payload, birthday,
                                image_source, user_image_status
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                u.get("userId"), am_id, m_id,
                                u.get("fullName"), u.get("phone"), u.get("email"),
                                u.get("validFrom"), u.get("validTo"),
                                u.get("firstCardId"), u.get("secondCardId"), u.get("image"),
                                json.dumps(fps, ensure_ascii=False),
                                u.get("faceId"),
                                u.get("accountUsernameId") or u.get("account_username_id"),
                                u.get("qrCodePayload"), u.get("birthday"),
                                u.get("imageSource"),
                                u.get("userImageStatus"),
                            ),
                        )
                if valid_ids is not None:
                    valid_set = set(valid_ids)
                    cached_rows = cur.execute(
                        "SELECT active_membership_id FROM sync_users WHERE active_membership_id IS NOT NULL"
                    ).fetchall()
                    ids_to_remove = {r[0] for r in cached_rows} - valid_set
                    ids_list = list(ids_to_remove)
                    for i in range(0, len(ids_list), 500):
                        chunk = ids_list[i:i + 500]
                        placeholders = ",".join("?" * len(chunk))
                        cur.execute(
                            f"DELETE FROM sync_users WHERE active_membership_id IN ({placeholders})",
                            chunk,
                        )
            else:
                # Full replace mode
                old_count = cur.execute("SELECT COUNT(*) FROM sync_users").fetchone()[0]
                _logger.info(
                    "[SYNC-DEBUG] save_sync_cache_delta: refreshMembers=True, "
                    "incoming_users=%d, old_db_count=%d",
                    len(users), old_count,
                )
                if not users:
                    if old_count > 10:
                        _logger.error(
                            f"[DB] save_sync_cache_delta: backend returned 0 users (refreshMembers=True) "
                            f"but local cache has {old_count}. Refusing to clear — likely backend error."
                        )
                        conn.commit()
                        return
                    else:
                        _logger.warning(
                            "[SYNC-DEBUG] H-006 NOT triggered (old_count=%d <= 10). "
                            "Will DELETE all sync_users with 0 replacements!",
                            old_count,
                        )

                # --- Content-hash guard: skip DELETE+INSERT if user data is unchanged ---
                # This prevents unnecessary DB churn and device re-sync when backend
                # returns refreshMembers=True but user data is actually the same.
                def _users_content_hash(user_list):
                    """Compute a SHA-1 hash of the user list content for comparison."""
                    h = hashlib.sha1()
                    for u in sorted(user_list, key=lambda x: (x.get("userId") or 0, x.get("activeMembershipId") or x.get("membershipId") or 0)):
                        am_id = u.get("activeMembershipId")
                        m_id = u.get("membershipId")
                        if am_id is None or str(am_id).strip() == "":
                            am_id = m_id
                        fps = u.get("fingerprints") or []
                        row = (
                            f"{u.get('userId')}|{am_id}|{m_id}|"
                            f"{u.get('fullName')}|{u.get('phone')}|{u.get('email')}|"
                            f"{u.get('validFrom')}|{u.get('validTo')}|"
                            f"{u.get('firstCardId')}|{u.get('secondCardId')}|"
                            f"{u.get('image')}|{json.dumps(fps, ensure_ascii=False, sort_keys=True)}|"
                            f"{u.get('faceId')}|{u.get('accountUsernameId') or u.get('account_username_id')}|"
                            f"{u.get('qrCodePayload')}|{u.get('birthday')}|"
                            f"{u.get('imageSource')}|{u.get('userImageStatus')}"
                        )
                        h.update(row.encode("utf-8", errors="replace"))
                    return h.hexdigest()

                if users and old_count > 0:
                    incoming_hash = _users_content_hash(users)
                    # Build equivalent dicts from existing DB rows for comparison
                    existing_rows = cur.execute(
                        "SELECT user_id, active_membership_id, membership_id, "
                        "full_name, phone, email, valid_from, valid_to, "
                        "first_card_id, second_card_id, image, fingerprints_json, "
                        "face_id, account_username_id, qr_code_payload, birthday, "
                        "image_source, user_image_status FROM sync_users"
                    ).fetchall()
                    existing_as_dicts = []
                    for r in existing_rows:
                        fps_raw = r[11] or "[]"
                        try:
                            fps_parsed = json.loads(fps_raw)
                        except Exception:
                            fps_parsed = []
                        existing_as_dicts.append({
                            "userId": r[0], "activeMembershipId": r[1], "membershipId": r[2],
                            "fullName": r[3], "phone": r[4], "email": r[5],
                            "validFrom": r[6], "validTo": r[7],
                            "firstCardId": r[8], "secondCardId": r[9], "image": r[10],
                            "fingerprints": fps_parsed,
                            "faceId": r[12], "accountUsernameId": r[13],
                            "qrCodePayload": r[14], "birthday": r[15],
                            "imageSource": r[16], "userImageStatus": r[17],
                        })
                    existing_hash = _users_content_hash(existing_as_dicts)
                    if incoming_hash == existing_hash:
                        _logger.info(
                            "[SYNC-DEBUG] save_sync_cache_delta: users UNCHANGED (hash=%s), "
                            "skipping DELETE+INSERT for %d users",
                            incoming_hash[:12], len(users),
                        )
                        # Skip to next section — preserve device_sync_state hashes
                        users = None  # sentinel: skip the INSERT loop below

                if users is not None:
                    cur.execute("DELETE FROM sync_users")
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
                            INSERT OR REPLACE INTO sync_users (
                                user_id, active_membership_id, membership_id,
                                full_name, phone, email, valid_from, valid_to,
                                first_card_id, second_card_id, image,
                                fingerprints_json, face_id, account_username_id, qr_code_payload, birthday,
                                image_source, user_image_status
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                u.get("userId"), am_id, m_id,
                                u.get("fullName"), u.get("phone"), u.get("email"),
                                u.get("validFrom"), u.get("validTo"),
                                u.get("firstCardId"), u.get("secondCardId"), u.get("image"),
                                json.dumps(fps, ensure_ascii=False),
                                u.get("faceId"),
                                u.get("accountUsernameId") or u.get("account_username_id"),
                                u.get("qrCodePayload"), u.get("birthday"),
                                u.get("imageSource"),
                                u.get("userImageStatus"),
                            ),
                        )

                    new_count = cur.execute("SELECT COUNT(*) FROM sync_users").fetchone()[0]
                    _logger.info(
                        "[SYNC-DEBUG] save_sync_cache_delta: after members update, new_db_count=%d",
                        new_count,
                    )
        else:
            _logger.info("[SYNC-DEBUG] save_sync_cache_delta: refreshMembers=False, skipping members section")

        # Conditional: devices
        if refresh.get("devices", True):
            cur.execute("DELETE FROM sync_devices")
            cur.execute("DELETE FROM sync_device_door_presets")
            for d in (data.get("devices") or []):
                _insert_device_row(cur, d)

        # Conditional: credentials
        if refresh.get("credentials", True):
            cur.execute("DELETE FROM sync_gym_access_credentials")
            for c in (data.get("gymAccessCredentials") or data.get("gym_access_credentials") or []):
                if not isinstance(c, dict):
                    continue
                granted_ids = c.get("grantedActiveMembershipIds")
                if not isinstance(granted_ids, list):
                    granted_ids = []
                cur.execute(
                    """
                    INSERT INTO sync_gym_access_credentials (
                        id, gym_id, account_id, secret_hex, enabled,
                        rotated_at, created_at, updated_at,
                        granted_active_membership_ids_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        _to_int_or_none(c.get("id")),
                        _to_int_or_none(c.get("gymId") if "gymId" in c else c.get("gym_id")),
                        _to_int_or_none(c.get("accountId") if "accountId" in c else c.get("account_id")),
                        str((c.get("secretHex") if "secretHex" in c else c.get("secret_hex")) or ""),
                        1 if bool(c.get("enabled", False)) else 0,
                        c.get("rotatedAt") or c.get("rotated_at"),
                        c.get("createdAt") or c.get("created_at"),
                        c.get("updatedAt") or c.get("updated_at"),
                        json.dumps(granted_ids, ensure_ascii=False),
                    ),
                )

        # Conditional: settings (infrastructures)
        if refresh.get("settings", True):
            cur.execute("DELETE FROM sync_infrastructures")
            for z in (data.get("infrastructures") or data.get("infrastructure") or []):
                if not isinstance(z, dict):
                    continue
                cur.execute(
                    """
                    INSERT INTO sync_infrastructures (id, name, gym_agent_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        z.get("id"),
                        z.get("name"),
                        json.dumps(z.get("gymAgent") or {}, ensure_ascii=False),
                        z.get("createdAt"),
                        z.get("updatedAt"),
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
        "imageSource": g("imageSource", "image_source"),
        "userImageStatus": g("userImageStatus", "user_image_status"),
        "fingerprints": fps,
        "faceId": g("faceId", "face_id"),
        "accountUsernameId": g("accountUsernameId", "account_username_id", "usernameId", "username_id"),
        "qrCodePayload": g("qrCodePayload", "qr_code_payload"),
        "birthday": g("birthday"),
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

        "antiFraudeCard":     _boolish(g("anti_fraude_card",    default=1), True),
        "antiFraudeQrCode":   _boolish(g("anti_fraude_qr_code", default=1), True),
        "antiFraudeDuration": _to_int_or_none(g("anti_fraude_duration", default=30)) or 30,

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
                optional_data_sync_delay_minutes,
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

            "optionalDataSyncDelayMinutes": d.get("optional_data_sync_delay_minutes"),

            "createdAt": d.get("created_at"),
            "updatedAt": d.get("updated_at"),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Optional content sync — state, events, products, deals
# ─────────────────────────────────────────────────────────────────────────────

def get_optional_sync_state() -> Dict[str, Any]:
    """Return the current optional sync state (version markers). Never raises."""
    try:
        with get_conn() as conn:
            r = conn.execute(
                "SELECT events_version_at, products_version_at, deals_version_at, last_sync_at "
                "FROM optional_sync_state WHERE id=1"
            ).fetchone()
            return dict(r) if r else {}
    except Exception:
        return {}


def save_optional_sync_state(
    *,
    events_version_at: Optional[str],
    products_version_at: Optional[str],
    deals_version_at: Optional[str],
    last_sync_at: str,
    refresh_events: bool,
    refresh_products: bool,
    refresh_deals: bool,
) -> None:
    """
    Upsert the optional sync state row.
    Only overwrites a version marker when the corresponding refresh flag was true,
    preserving unchanged markers.
    """
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO optional_sync_state (id, events_version_at, products_version_at, deals_version_at, last_sync_at)
            VALUES (1, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                events_version_at   = CASE WHEN ? THEN excluded.events_version_at   ELSE events_version_at   END,
                products_version_at = CASE WHEN ? THEN excluded.products_version_at ELSE products_version_at END,
                deals_version_at    = CASE WHEN ? THEN excluded.deals_version_at    ELSE deals_version_at    END,
                last_sync_at        = excluded.last_sync_at
            """,
            (
                events_version_at,
                products_version_at,
                deals_version_at,
                last_sync_at,
                1 if refresh_events else 0,
                1 if refresh_products else 0,
                1 if refresh_deals else 0,
            ),
        )
        conn.commit()


def delete_passed_optional_events() -> int:
    """
    Delete events from optional_upcoming_events whose event_date is in the past.
    Returns the number of deleted rows. Called before each optional sync cycle.
    """
    now_iso = datetime.now().isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM optional_upcoming_events WHERE event_date < ?", (now_iso,)
        )
        conn.commit()
        return cur.rowcount


def replace_optional_events(events: List[Dict[str, Any]]) -> None:
    """Replace the full optional events cache."""
    now_ts = datetime.now().isoformat()
    with get_conn() as conn:
        conn.execute("DELETE FROM optional_upcoming_events")
        for ev in events:
            conn.execute(
                """
                INSERT OR REPLACE INTO optional_upcoming_events
                    (id, title, sub_title, description, image, room, event_date,
                     duration_in_minutes, coach_name, price, category, available, synced_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ev.get("id"),
                    ev.get("title"),
                    ev.get("subTitle"),
                    ev.get("description"),
                    ev.get("image"),
                    ev.get("room"),
                    ev.get("date"),
                    ev.get("durationInMinutes"),
                    ev.get("coachName"),
                    str(ev["price"]) if ev.get("price") is not None else None,
                    ev.get("category"),
                    1 if ev.get("available") else 0,
                    now_ts,
                ),
            )
        conn.commit()


def replace_optional_products(products: List[Dict[str, Any]]) -> None:
    """Replace the full optional products cache."""
    now_ts = datetime.now().isoformat()
    with get_conn() as conn:
        conn.execute("DELETE FROM optional_products")
        for p in products:
            conn.execute(
                """
                INSERT OR REPLACE INTO optional_products
                    (id, title, model, description, image, category,
                     price, sale_price, available_number, available, synced_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    p.get("id"),
                    p.get("title"),
                    p.get("model"),
                    p.get("description"),
                    p.get("image"),
                    p.get("category"),
                    p.get("price"),
                    p.get("salePrice"),
                    p.get("availableNumber"),
                    1 if p.get("available") else 0,
                    now_ts,
                ),
            )
        conn.commit()


def replace_optional_deals(deals: List[Dict[str, Any]]) -> None:
    """Replace the full optional deals cache."""
    now_ts = datetime.now().isoformat()
    with get_conn() as conn:
        conn.execute("DELETE FROM optional_deals")
        for d in deals:
            conn.execute(
                """
                INSERT OR REPLACE INTO optional_deals
                    (id, title, description, header, image, deal_end_date, partner_name, available, synced_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    d.get("id"),
                    d.get("title"),
                    d.get("description"),
                    d.get("header"),
                    d.get("image"),
                    d.get("dealEndDate"),
                    d.get("partnerName"),
                    1 if d.get("available") else 0,
                    now_ts,
                ),
            )
        conn.commit()


def list_optional_upcoming_events() -> List[Dict[str, Any]]:
    """Return cached upcoming events ordered by date. Used by TV display."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM optional_upcoming_events ORDER BY event_date ASC"
        ).fetchall()
        return [dict(r) for r in rows]


def list_optional_products() -> List[Dict[str, Any]]:
    """Return cached available products. Used by TV display."""
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM optional_products").fetchall()
        return [dict(r) for r in rows]


def list_optional_deals() -> List[Dict[str, Any]]:
    """Return cached active deals. Used by TV display."""
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM optional_deals").fetchall()
        return [dict(r) for r in rows]


_sync_cache_lock = threading.Lock()
_sync_cache_entry: tuple[float, "SyncCacheState | None"] = (0.0, None)
_sync_cache_loading: "threading.Event | None" = None  # None = no load in progress
_SYNC_CACHE_TTL = 5.0  # seconds


def invalidate_sync_cache() -> None:
    """Force the next load_sync_cache() call to read from the DB."""
    global _sync_cache_entry
    with _sync_cache_lock:
        _sync_cache_entry = (0.0, None)


def load_sync_cache() -> "SyncCacheState | None":
    global _sync_cache_entry, _sync_cache_loading
    now = time.monotonic()

    with _sync_cache_lock:
        expires, cached = _sync_cache_entry
        if now < expires and cached is not None:
            return cached

        # Cache expired. Is another thread already loading?
        if _sync_cache_loading is not None:
            evt = _sync_cache_loading  # wait for the in-flight loader
        else:
            # We are the loader thread.
            evt = threading.Event()
            _sync_cache_loading = evt
            evt = None  # signal: "we are the loader"

    if evt is not None:
        # Another thread is loading — wait for it (bounded).
        evt.wait(timeout=10.0)
        with _sync_cache_lock:
            _, cached = _sync_cache_entry
        return cached

    # We are the loader thread.
    try:
        result = _load_sync_cache_db()
        with _sync_cache_lock:
            _sync_cache_entry = (time.monotonic() + _SYNC_CACHE_TTL, result)
            loading_evt = _sync_cache_loading
            _sync_cache_loading = None
        if loading_evt is not None:
            loading_evt.set()  # wake all waiters
        return result
    except Exception:
        with _sync_cache_lock:
            loading_evt = _sync_cache_loading
            _sync_cache_loading = None
        if loading_evt is not None:
            loading_evt.set()  # wake waiters even on failure
        raise


def _load_sync_cache_db() -> "SyncCacheState | None":
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

            try:
                norm_users.extend(list_projected_offline_users(base_users=norm_users))
            except Exception:
                pass
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
        try:
            users.extend(list_projected_offline_users(base_users=users))
        except Exception:
            pass

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
    """Direct query — avoids loading memberships/devices/infra via load_sync_cache() hot path."""
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM sync_users").fetchall()]
    users = [_coerce_user_row_to_payload(r) for r in rows]
    try:
        users.extend(list_projected_offline_users(base_users=users))
    except Exception:
        pass
    return users


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
    """Direct query — avoids full load_sync_cache() on the hot verification path."""
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM sync_gym_access_credentials").fetchall()]
    rows = [_expand_gym_access_credential_json_fields(r) for r in rows]
    return [_coerce_gym_access_credential_row_to_payload(r) for r in rows]


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


def list_device_sync_hashes_and_status(*, device_id: int) -> Dict[str, tuple]:
    """Return {pin: (desired_hash, last_ok)} so callers can detect pins that need retry."""
    did = int(device_id)
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT pin, desired_hash, last_ok FROM device_sync_state WHERE device_id=?",
            (did,),
        ).fetchall()
        out: Dict[str, tuple] = {}
        for r in rows:
            p = str(r["pin"] or "")
            h = str(r["desired_hash"] or "")
            ok = bool(int(r["last_ok"] or 0))
            if p:
                out[p] = (h, ok)
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
def clear_device_sync_hashes(*, device_id: int) -> int:
    """F-015: Clear all sync hashes for a device to force full re-sync on next cycle."""
    did = int(device_id)
    with get_conn() as conn:
        cursor = conn.execute("DELETE FROM device_sync_state WHERE device_id=?", (did,))
        conn.commit()
        return cursor.rowcount


def clear_all_device_sync_hashes() -> int:
    """Hard-reset: clear sync hashes for ALL devices so next sync re-pushes every user."""
    with get_conn() as conn:
        cursor = conn.execute("DELETE FROM device_sync_state")
        conn.commit()
        return cursor.rowcount


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
    history_source: str
    backend_sync_state: str
    backend_attempt_count: int
    backend_failure_count: int
    backend_last_attempt_at: Optional[str]
    backend_next_retry_at: Optional[str]
    backend_synced_at: Optional[str]
    backend_last_error: Optional[str]


ACCESS_HISTORY_SOURCE_AGENT = "AGENT"
ACCESS_HISTORY_SOURCE_DEVICE = "DEVICE"
ACCESS_HISTORY_SOURCE_ULTRA = "ULTRA"

ACCESS_HISTORY_SYNC_PENDING = "PENDING"
ACCESS_HISTORY_SYNC_FAILED_RETRYABLE = "FAILED_RETRYABLE"
ACCESS_HISTORY_SYNC_FAILED_TERMINAL = "FAILED_TERMINAL"
ACCESS_HISTORY_SYNC_SYNCED = "SYNCED"


@dataclass
class DeviceAttendanceState:
    device_id: int
    last_read_started_at: str
    last_read_finished_at: str
    last_read_event_count: int
    last_read_error: str
    last_purge_at: str
    last_purge_deleted_count: int
    last_purge_error: str
    updated_at: str


def normalize_access_history_source(v: Any) -> str:
    s = str(v or "").strip().upper()
    if s == ACCESS_HISTORY_SOURCE_DEVICE:
        return ACCESS_HISTORY_SOURCE_DEVICE
    if s == ACCESS_HISTORY_SOURCE_ULTRA:
        return ACCESS_HISTORY_SOURCE_ULTRA
    return ACCESS_HISTORY_SOURCE_AGENT


def normalize_access_history_sync_state(v: Any) -> str:
    s = str(v or "").strip().upper()
    if s == ACCESS_HISTORY_SYNC_SYNCED:
        return ACCESS_HISTORY_SYNC_SYNCED
    if s == ACCESS_HISTORY_SYNC_FAILED_TERMINAL:
        return ACCESS_HISTORY_SYNC_FAILED_TERMINAL
    if s == ACCESS_HISTORY_SYNC_FAILED_RETRYABLE:
        return ACCESS_HISTORY_SYNC_FAILED_RETRYABLE
    return ACCESS_HISTORY_SYNC_PENDING


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


def _build_access_history_insert_params(
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
    history_source: str | None,
    backend_sync_state: str | None,
) -> tuple[Any, ...]:
    return (
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
        normalize_access_history_source(history_source),
        normalize_access_history_sync_state(backend_sync_state),
    )


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
    history_source: str | None = None,
    backend_sync_state: str | None = None,
) -> int:
    """
    Insert an access history row using INSERT OR IGNORE (UNIQUE on event_id).
    Returns rowcount: 1 if inserted (first worker to claim), 0 if already exists.
    F-013: callers should only open_door if return value is 1.
    """
    if not str(event_id or "").strip():
        return 0

    with get_conn() as conn:
        try:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO access_history (
                    created_at, event_id, device_id, door_id, card_no,
                    event_time, event_type,
                    allowed, reason,
                    poll_ms, decision_ms, cmd_ms,
                    cmd_ok, cmd_error,
                    raw_json,
                    history_source,
                    backend_sync_state
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                _build_access_history_insert_params(
                    event_id=event_id,
                    device_id=device_id,
                    door_id=door_id,
                    card_no=card_no,
                    event_time=event_time,
                    event_type=event_type,
                    allowed=allowed,
                    reason=reason,
                    poll_ms=poll_ms,
                    decision_ms=decision_ms,
                    cmd_ms=cmd_ms,
                    cmd_ok=cmd_ok,
                    cmd_error=cmd_error,
                    raw=raw,
                    history_source=history_source,
                    backend_sync_state=backend_sync_state,
                ),
            )
            conn.commit()
            return int(cur.rowcount or 0)
        except sqlite3.IntegrityError:
            return 0


def insert_access_history_batch(*, rows: Iterable[Dict[str, Any]]) -> int:
    batch: List[tuple[Any, ...]] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        event_id = str(row.get("event_id") or row.get("eventId") or "").strip()
        if not event_id:
            continue
        batch.append(
            _build_access_history_insert_params(
                event_id=event_id,
                device_id=row.get("device_id", row.get("deviceId")),
                door_id=row.get("door_id", row.get("doorId")),
                card_no=row.get("card_no", row.get("cardNo")),
                event_time=row.get("event_time", row.get("eventTime")),
                event_type=row.get("event_type", row.get("eventType")),
                allowed=bool(row.get("allowed", False)),
                reason=row.get("reason"),
                poll_ms=row.get("poll_ms", row.get("pollMs")),
                decision_ms=row.get("decision_ms", row.get("decisionMs")),
                cmd_ms=row.get("cmd_ms", row.get("cmdMs")),
                cmd_ok=row.get("cmd_ok", row.get("cmdOk")),
                cmd_error=row.get("cmd_error", row.get("cmdError")),
                raw=row.get("raw"),
                history_source=row.get("history_source", row.get("historySource")),
                backend_sync_state=row.get("backend_sync_state", row.get("backendSyncState")),
            )
        )
    if not batch:
        return 0
    with get_conn() as conn:
        cur = conn.executemany(
            """
            INSERT OR IGNORE INTO access_history (
                created_at, event_id, device_id, door_id, card_no,
                event_time, event_type,
                allowed, reason,
                poll_ms, decision_ms, cmd_ms,
                cmd_ok, cmd_error,
                raw_json,
                history_source,
                backend_sync_state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            batch,
        )
        conn.commit()
        return int(cur.rowcount or 0)


def prune_access_history(*, retention_days: int) -> int:
    days = int(retention_days)
    if days < 1:
        days = 1
    with get_conn() as conn:
        cur = conn.execute(
            """
            DELETE FROM access_history
            WHERE julianday('now') - julianday(COALESCE(backend_synced_at, created_at)) > ?
              AND backend_sync_state IN (?, ?)
            """,
            (days, ACCESS_HISTORY_SYNC_SYNCED, ACCESS_HISTORY_SYNC_FAILED_TERMINAL),
        )
        conn.commit()
        return int(cur.rowcount or 0)


def prune_offline_creation_queue(*, retention_days: int = 30) -> int:
    """M-008: Clean up succeeded/failed offline creations older than retention_days."""
    days = max(int(retention_days), 1)
    with get_conn() as conn:
        cur = conn.execute(
            """
            DELETE FROM offline_creation_queue
            WHERE state IN ('succeeded', 'failed_terminal')
              AND julianday('now') - julianday(updated_at) > ?
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


def list_pending_access_history_for_sync(*, limit: int = 200) -> List[AccessHistoryRow]:
    lim = int(limit)
    if lim < 1:
        lim = 1
    if lim > 1000:
        lim = 1000
    now = now_iso()
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM access_history
            WHERE backend_sync_state IN (?, ?)
              AND (backend_next_retry_at IS NULL OR backend_next_retry_at = '' OR backend_next_retry_at <= ?)
            ORDER BY id ASC
            LIMIT ?
            """,
            (ACCESS_HISTORY_SYNC_PENDING, ACCESS_HISTORY_SYNC_FAILED_RETRYABLE, now, lim),
        ).fetchall()
        return [AccessHistoryRow(**dict(r)) for r in rows]


def mark_access_history_synced(*, row_ids: Iterable[int], synced_at: str | None = None) -> int:
    ids = sorted({int(x) for x in row_ids if int(x) > 0})
    if not ids:
        return 0
    ts = str(synced_at or now_iso())
    placeholders = ",".join("?" for _ in ids)
    with get_conn() as conn:
        cur = conn.execute(
            f"""
            UPDATE access_history
            SET backend_sync_state=?,
                backend_attempt_count=COALESCE(backend_attempt_count, 0) + 1,
                backend_synced_at=?,
                backend_last_attempt_at=?,
                backend_next_retry_at=NULL,
                backend_last_error=NULL
            WHERE id IN ({placeholders})
            """,
            (ACCESS_HISTORY_SYNC_SYNCED, ts, ts, *ids),
        )
        conn.commit()
        return int(cur.rowcount or 0)


def mark_access_history_sync_failure(
    *,
    row_ids: Iterable[int],
    error: str,
    retry_after_seconds: int = 300,
    terminal: bool = False,
    attempted_at: str | None = None,
) -> int:
    ids = sorted({int(x) for x in row_ids if int(x) > 0})
    if not ids:
        return 0
    ts = str(attempted_at or now_iso())
    retry_after = max(30, int(retry_after_seconds or 300))
    try:
        retry_dt = datetime.fromisoformat(ts.replace("Z", "+00:00")) + timedelta(seconds=retry_after)
        retry_at = retry_dt.isoformat()
    except Exception:
        retry_at = now_iso()
    state = ACCESS_HISTORY_SYNC_FAILED_TERMINAL if terminal else ACCESS_HISTORY_SYNC_FAILED_RETRYABLE
    next_retry = None if terminal else retry_at
    placeholders = ",".join("?" for _ in ids)
    with get_conn() as conn:
        cur = conn.execute(
            f"""
            UPDATE access_history
            SET backend_sync_state=?,
                backend_attempt_count=COALESCE(backend_attempt_count, 0) + 1,
                backend_failure_count=COALESCE(backend_failure_count, 0) + 1,
                backend_last_attempt_at=?,
                backend_next_retry_at=?,
                backend_last_error=?
            WHERE id IN ({placeholders})
            """,
            (state, ts, next_retry, str(error or "")[:2000], *ids),
        )
        conn.commit()
        return int(cur.rowcount or 0)


def mark_access_history_sync_attempt(
    *,
    row_ids: Iterable[int],
    attempted_at: str | None = None,
) -> int:
    ids = sorted({int(x) for x in row_ids if int(x) > 0})
    if not ids:
        return 0
    ts = str(attempted_at or now_iso())
    placeholders = ",".join("?" for _ in ids)
    with get_conn() as conn:
        cur = conn.execute(
            f"""
            UPDATE access_history
            SET backend_attempt_count=COALESCE(backend_attempt_count, 0) + 1,
                backend_last_attempt_at=?
            WHERE id IN ({placeholders})
            """,
            (ts, *ids),
        )
        conn.commit()
        return int(cur.rowcount or 0)


def load_device_attendance_state(device_id: int) -> Optional[DeviceAttendanceState]:
    did = int(device_id)
    with get_conn() as conn:
        r = conn.execute(
            """
            SELECT
                device_id,
                last_read_started_at,
                last_read_finished_at,
                last_read_event_count,
                last_read_error,
                last_purge_at,
                last_purge_deleted_count,
                last_purge_error,
                updated_at
            FROM device_attendance_state
            WHERE device_id=?
            """,
            (did,),
        ).fetchone()
        if not r:
            return None
        return DeviceAttendanceState(
            device_id=int(r["device_id"]),  # type: ignore[index]
            last_read_started_at=str(r["last_read_started_at"] or ""),
            last_read_finished_at=str(r["last_read_finished_at"] or ""),
            last_read_event_count=int(r["last_read_event_count"] or 0),
            last_read_error=str(r["last_read_error"] or ""),
            last_purge_at=str(r["last_purge_at"] or ""),
            last_purge_deleted_count=int(r["last_purge_deleted_count"] or 0),
            last_purge_error=str(r["last_purge_error"] or ""),
            updated_at=str(r["updated_at"] or ""),
        )


def save_device_attendance_state(
    *,
    device_id: int,
    last_read_started_at: str | None = None,
    last_read_finished_at: str | None = None,
    last_read_event_count: int | None = None,
    last_read_error: str | None = None,
    last_purge_at: str | None = None,
    last_purge_deleted_count: int | None = None,
    last_purge_error: str | None = None,
) -> None:
    did = int(device_id)
    with get_conn() as conn:
        existing = conn.execute(
            """
            SELECT
                last_read_started_at,
                last_read_finished_at,
                last_read_event_count,
                last_read_error,
                last_purge_at,
                last_purge_deleted_count,
                last_purge_error
            FROM device_attendance_state
            WHERE device_id=?
            """,
            (did,),
        ).fetchone()
        base = dict(existing) if existing else {}
        conn.execute(
            """
            INSERT INTO device_attendance_state (
                device_id,
                last_read_started_at,
                last_read_finished_at,
                last_read_event_count,
                last_read_error,
                last_purge_at,
                last_purge_deleted_count,
                last_purge_error,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                last_read_started_at=excluded.last_read_started_at,
                last_read_finished_at=excluded.last_read_finished_at,
                last_read_event_count=excluded.last_read_event_count,
                last_read_error=excluded.last_read_error,
                last_purge_at=excluded.last_purge_at,
                last_purge_deleted_count=excluded.last_purge_deleted_count,
                last_purge_error=excluded.last_purge_error,
                updated_at=excluded.updated_at
            """,
            (
                did,
                str(last_read_started_at if last_read_started_at is not None else base.get("last_read_started_at") or ""),
                str(last_read_finished_at if last_read_finished_at is not None else base.get("last_read_finished_at") or ""),
                int(last_read_event_count if last_read_event_count is not None else base.get("last_read_event_count") or 0),
                str(last_read_error if last_read_error is not None else base.get("last_read_error") or ""),
                str(last_purge_at if last_purge_at is not None else base.get("last_purge_at") or ""),
                int(last_purge_deleted_count if last_purge_deleted_count is not None else base.get("last_purge_deleted_count") or 0),
                str(last_purge_error if last_purge_error is not None else base.get("last_purge_error") or ""),
                now_iso(),
            ),
        )
        conn.commit()









# -----------------------------
# Offline creation queue (access-only)
# -----------------------------

OFFLINE_QUEUE_ACTIVE_STATES = ("pending", "processing", "failed_retryable", "blocked_auth")
OFFLINE_QUEUE_FINAL_STATES = ("succeeded", "reconciled", "cancelled", "failed_terminal", "archived")

# F-009: Maximum number of active (pending/processing/failed_retryable/blocked_auth) items in the queue
_OFFLINE_QUEUE_MAX_PENDING = 500


def count_offline_queue_active() -> int:
    """Count items in pending/processing state (active items)."""
    with get_conn() as conn:
        r = conn.execute(
            "SELECT COUNT(*) AS c FROM offline_creation_queue WHERE state IN ('pending','processing','failed_retryable','blocked_auth')"
        ).fetchone()
        return int(r["c"]) if r else 0


def reset_stale_processing_locks(now_iso: Optional[str] = None) -> int:
    """
    On startup: reset any offline_creation_queue rows that are stuck in
    state='processing' with an expired lock TTL back to state='pending'.
    Returns the count of rows reset.
    """
    if now_iso is None:
        from datetime import datetime, timezone as _tz
        now_iso = datetime.now(tz=_tz.utc).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE offline_creation_queue
            SET state = 'pending',
                processing_lock_token = NULL,
                processing_lock_expires_at = NULL
            WHERE state = 'processing'
              AND (processing_lock_expires_at IS NULL OR processing_lock_expires_at < ?)
            """,
            (now_iso,),
        )
        conn.commit()
        return cur.rowcount


def _utc_now_iso() -> str:
    try:
        return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    except Exception:
        return now_iso()


def _hash_payload(payload: Dict[str, Any]) -> str:
    try:
        raw = json.dumps(payload or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except Exception:
        raw = "{}"
    return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()


def _normalize_creation_kind(kind: str) -> str:
    k = str(kind or "").strip().lower()
    if k in ("membership", "membership_only", "active_membership", "active_membership_only"):
        return "membership_only"
    if k in ("account", "account_plus_membership", "create_account"):
        return "account_plus_membership"
    return "membership_only"


def _normalize_queue_state(state: str, *, default: str = "pending") -> str:
    s = str(state or "").strip().lower()
    allowed = {
        "pending", "processing", "failed_retryable", "blocked_auth",
        "succeeded", "reconciled", "cancelled", "failed_terminal", "archived",
    }
    return s if s in allowed else default


def _failure_is_countable(failure_type: str) -> bool:
    ft = str(failure_type or "").strip().lower()
    return ft in ("validation", "conflict")


def _failure_retry_delay_minutes(failure_type: str) -> int:
    ft = str(failure_type or "").strip().lower()
    if ft == "network":
        return 5
    if ft == "server":
        return 15
    if ft == "auth":
        return 60
    return 60


def _next_retry_iso(minutes: int) -> str:
    try:
        mins = int(minutes)
    except Exception:
        mins = 60
    if mins < 1:
        mins = 1
    return (datetime.utcnow() + timedelta(minutes=mins)).replace(microsecond=0).isoformat() + "Z"


def _parse_iso_date(v: Any) -> datetime | None:
    s = str(v or "").strip()
    if not s:
        return None
    if len(s) >= 10:
        s = s[:10]
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _simple_email_ok(v: Any) -> bool:
    s = str(v or "").strip()
    return ("@" in s) and ("." in s.split("@")[-1]) and (len(s) >= 5)


def _norm_text(v: Any) -> str:
    return str(v or "").strip()


def _norm_text_l(v: Any) -> str:
    return _norm_text(v).lower()


def _synthetic_negative_id(local_id: str, salt: str) -> int:
    lid = str(local_id or "").strip() or "0"
    h = hashlib.sha1(f"{salt}:{lid}".encode("utf-8", errors="ignore")).hexdigest()
    n = int(h[:8], 16) % 2000000000
    if n <= 0:
        n = 1
    return -n


def _row_payload_dict(row: Dict[str, Any]) -> Dict[str, Any]:
    raw = row.get("payload_json")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            j = json.loads(raw)
            if isinstance(j, dict):
                return j
        except Exception:
            return {}
    return {}


def _queue_row_to_dict(row: sqlite3.Row | Dict[str, Any]) -> Dict[str, Any]:
    d = dict(row)
    payload = _row_payload_dict(d)
    d["payload"] = payload
    d["creation_kind"] = _normalize_creation_kind(d.get("creation_kind"))
    d["state"] = _normalize_queue_state(d.get("state"), default="pending")
    d["created"] = bool(int(d.get("created") or 0))
    d["try_to_create"] = bool(int(d.get("try_to_create") or 0))
    d["attempt_count"] = int(d.get("attempt_count") or 0)
    d["failure_count"] = int(d.get("failure_count") or 0)
    return d


def insert_offline_creation(
    *,
    creation_kind: str,
    payload: Dict[str, Any],
    local_id: str | None = None,
    client_request_id: str | None = None,
    state: str = "pending",
    try_to_create: bool = True,
    created: bool = False,
    failure_type: str | None = None,
    failure_code: str | None = None,
    last_http_status: int | None = None,
    last_error_message: str | None = None,
    failed_reason: str | None = None,
    next_retry_at: str | None = None,
) -> Dict[str, Any]:
    # F-009: Check queue cap before inserting
    if count_offline_queue_active() >= _OFFLINE_QUEUE_MAX_PENDING:
        raise RuntimeError(f"Offline creation queue is full (max={_OFFLINE_QUEUE_MAX_PENDING}). Cannot enqueue new item.")

    lid = str(local_id or uuid.uuid4())
    rid = str(client_request_id or uuid.uuid4())
    kind = _normalize_creation_kind(creation_kind)
    st = _normalize_queue_state(state, default="pending")
    now = _utc_now_iso()
    payload_obj = payload if isinstance(payload, dict) else {}
    payload_json = json.dumps(payload_obj, ensure_ascii=False)
    payload_hash = _hash_payload(payload_obj)

    with get_conn() as conn:
        try:
            conn.execute(
                """
                INSERT INTO offline_creation_queue (
                    local_id, client_request_id, creation_kind,
                    payload_json, payload_hash,
                    state, created, try_to_create,
                    attempt_count, failure_count,
                    failure_type, failure_code, last_http_status,
                    last_error_message, failed_reason,
                    last_attempt_at, next_retry_at,
                    processing_started_at, processing_lock_token, processing_lock_expires_at,
                    succeeded_at, reconciled_at, cancelled_at, archived_at,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    lid, rid, kind,
                    payload_json, payload_hash,
                    st,
                    1 if created else 0,
                    1 if try_to_create else 0,
                    0, 0,
                    _norm_text(failure_type) or None,
                    _norm_text(failure_code) or None,
                    int(last_http_status) if last_http_status is not None else None,
                    _norm_text(last_error_message)[:1000] or None,
                    _norm_text(failed_reason)[:1000] or None,
                    None,
                    _norm_text(next_retry_at) or None,
                    None, None, None,
                    (now if st == "succeeded" else None),
                    (now if st == "reconciled" else None),
                    (now if st == "cancelled" else None),
                    (now if st == "archived" else None),
                    now,
                    now,
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            # Stable client_request_id should return the existing logical row.
            ex = conn.execute(
                "SELECT local_id FROM offline_creation_queue WHERE client_request_id=? LIMIT 1",
                (rid,),
            ).fetchone()
            if ex:
                existing_id = str(ex["local_id"])  # type: ignore[index]
                existing = get_offline_creation(existing_id)
                if existing:
                    return existing
            raise

    row = get_offline_creation(lid)
    if not row:
        raise RuntimeError("Failed to insert offline creation row")
    return row

def get_offline_creation(local_id: str) -> Dict[str, Any] | None:
    lid = _norm_text(local_id)
    if not lid:
        return None
    with get_conn() as conn:
        r = conn.execute("SELECT * FROM offline_creation_queue WHERE local_id=? LIMIT 1", (lid,)).fetchone()
        if not r:
            return None
        return _queue_row_to_dict(r)


def list_offline_creations(
    *,
    states: List[str] | None = None,
    include_archived: bool = False,
    limit: int = 500,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    lim = max(1, min(int(limit or 500), 5000))
    off = max(0, int(offset or 0))

    where: List[str] = []
    args: List[Any] = []

    norm_states: List[str] = []
    if states:
        for s in states:
            ns = _normalize_queue_state(s, default="")
            if ns:
                norm_states.append(ns)
    if norm_states:
        q = ",".join(["?"] * len(norm_states))
        where.append(f"state IN ({q})")
        args.extend(norm_states)
    elif not include_archived:
        where.append("state <> 'archived'")

    sql = "SELECT * FROM offline_creation_queue"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY updated_at DESC, created_at DESC LIMIT ? OFFSET ?"
    args.extend([lim, off])

    with get_conn() as conn:
        rows = conn.execute(sql, tuple(args)).fetchall()
        return [_queue_row_to_dict(r) for r in rows]

def count_offline_creations(
    *,
    states: List[str] | None = None,
    include_archived: bool = False,
) -> int:
    where: List[str] = []
    args: List[Any] = []

    norm_states: List[str] = []
    if states:
        for s in states:
            ns = _normalize_queue_state(s, default="")
            if ns:
                norm_states.append(ns)
    if norm_states:
        q = ",".join(["?"] * len(norm_states))
        where.append(f"state IN ({q})")
        args.extend(norm_states)
    elif not include_archived:
        where.append("state <> 'archived'")

    sql = "SELECT COUNT(*) AS c FROM offline_creation_queue"
    if where:
        sql += " WHERE " + " AND ".join(where)

    with get_conn() as conn:
        r = conn.execute(sql, tuple(args)).fetchone()
        if not r:
            return 0
        return int(r["c"] or 0)

def list_offline_creations_due_for_retry(*, now_iso_value: str | None = None, limit: int = 100) -> List[Dict[str, Any]]:
    now_v = _norm_text(now_iso_value) or _utc_now_iso()
    lim = max(1, min(int(limit or 100), 500))
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM offline_creation_queue
            WHERE created = 0
              AND try_to_create = 1
              AND state IN ('pending','failed_retryable','blocked_auth')
              AND (next_retry_at IS NULL OR next_retry_at = '' OR next_retry_at <= ?)
              AND (processing_lock_expires_at IS NULL OR processing_lock_expires_at = '' OR processing_lock_expires_at <= ?)
            ORDER BY COALESCE(next_retry_at, ''), updated_at, created_at
            LIMIT ?
            """,
            (now_v, now_v, lim),
        ).fetchall()
        return [_queue_row_to_dict(r) for r in rows]


def update_offline_creation_payload(
    local_id: str,
    *,
    payload: Dict[str, Any],
    try_to_create: bool | None = None,
) -> Dict[str, Any] | None:
    lid = _norm_text(local_id)
    if not lid:
        return None

    row = get_offline_creation(lid)
    if not row:
        return None
    if row.get("state") in OFFLINE_QUEUE_FINAL_STATES or row.get("created"):
        return None

    payload_obj = payload if isinstance(payload, dict) else {}
    now = _utc_now_iso()
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE offline_creation_queue
            SET payload_json=?,
                payload_hash=?,
                state='pending',
                failure_type=NULL,
                failure_code=NULL,
                last_http_status=NULL,
                last_error_message=NULL,
                failed_reason=NULL,
                failure_count=0,
                next_retry_at=NULL,
                processing_started_at=NULL,
                processing_lock_token=NULL,
                processing_lock_expires_at=NULL,
                updated_at=?,
                try_to_create=COALESCE(?, try_to_create)
            WHERE local_id=?
            """,
            (
                json.dumps(payload_obj, ensure_ascii=False),
                _hash_payload(payload_obj),
                now,
                (1 if bool(try_to_create) else 0) if try_to_create is not None else None,
                lid,
            ),
        )
        conn.commit()
    return get_offline_creation(lid)


def set_offline_creation_try_to_create(local_id: str, enabled: bool) -> Dict[str, Any] | None:
    lid = _norm_text(local_id)
    if not lid:
        return None
    row = get_offline_creation(lid)
    if not row:
        return None
    if row.get("state") in ("succeeded", "reconciled", "cancelled", "archived"):
        return None

    now = _utc_now_iso()
    new_state = row.get("state") or "pending"
    if enabled and new_state == "failed_terminal":
        new_state = "failed_retryable"
    if not enabled and new_state not in OFFLINE_QUEUE_FINAL_STATES:
        if row.get("state") == "blocked_auth":
            new_state = "blocked_auth"
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE offline_creation_queue
            SET try_to_create=?, state=?,
                processing_started_at=NULL,
                processing_lock_token=NULL,
                processing_lock_expires_at=NULL,
                updated_at=?
            WHERE local_id=?
            """,
            (1 if enabled else 0, _normalize_queue_state(new_state), now, lid),
        )
        conn.commit()
    return get_offline_creation(lid)


def cancel_offline_creation(local_id: str, *, reason: str | None = None) -> Dict[str, Any] | None:
    lid = _norm_text(local_id)
    if not lid:
        return None
    row = get_offline_creation(lid)
    if not row:
        return None
    if row.get("state") in ("succeeded", "reconciled", "archived"):
        return None

    now = _utc_now_iso()
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE offline_creation_queue
            SET state='cancelled',
                created=0,
                try_to_create=0,
                cancelled_at=?,
                failed_reason=COALESCE(?, failed_reason),
                processing_started_at=NULL,
                processing_lock_token=NULL,
                processing_lock_expires_at=NULL,
                updated_at=?
            WHERE local_id=?
            """,
            (now, _norm_text(reason)[:1000] or None, now, lid),
        )
        conn.commit()
    return get_offline_creation(lid)


def archive_offline_creation(local_id: str) -> Dict[str, Any] | None:
    lid = _norm_text(local_id)
    if not lid:
        return None
    row = get_offline_creation(lid)
    if not row:
        return None

    now = _utc_now_iso()
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE offline_creation_queue
            SET state='archived',
                archived_at=?,
                try_to_create=0,
                processing_started_at=NULL,
                processing_lock_token=NULL,
                processing_lock_expires_at=NULL,
                updated_at=?
            WHERE local_id=?
            """,
            (now, now, lid),
        )
        conn.commit()
    return get_offline_creation(lid)


def duplicate_offline_creation(local_id: str) -> Dict[str, Any] | None:
    src = get_offline_creation(local_id)
    if not src:
        return None
    payload = src.get("payload") if isinstance(src.get("payload"), dict) else {}
    return insert_offline_creation(
        creation_kind=str(src.get("creation_kind") or "membership_only"),
        payload=payload,
        local_id=str(uuid.uuid4()),
        client_request_id=str(uuid.uuid4()),
        state="pending",
        try_to_create=True,
        created=False,
    )


def claim_offline_creation_for_processing(local_id: str, *, lock_ttl_sec: int = 300, force: bool = False) -> Dict[str, Any] | None:
    lid = _norm_text(local_id)
    if not lid:
        return None

    now = _utc_now_iso()
    expires = (datetime.utcnow() + timedelta(seconds=max(30, int(lock_ttl_sec or 300)))).replace(microsecond=0).isoformat() + "Z"
    token = str(uuid.uuid4())

    where = (
        "local_id=? AND created=0 AND "
        "(processing_lock_expires_at IS NULL OR processing_lock_expires_at='' OR processing_lock_expires_at<=?)"
    )
    args: List[Any] = [lid, now]
    if not force:
        where += " AND try_to_create=1 AND state IN ('pending','failed_retryable','blocked_auth')"

    with get_conn() as conn:
        cur = conn.execute(
            f"""
            UPDATE offline_creation_queue
            SET state='processing',
                attempt_count = COALESCE(attempt_count, 0) + 1,
                last_attempt_at=?,
                processing_started_at=?,
                processing_lock_token=?,
                processing_lock_expires_at=?,
                updated_at=?
            WHERE {where}
            """,
            (now, now, token, expires, now, *args),
        )
        conn.commit()
        if int(cur.rowcount or 0) <= 0:
            return None

    row = get_offline_creation(lid)
    if not row:
        return None
    row["processing_lock_token"] = token
    return row


def mark_offline_creation_success(
    local_id: str,
    *,
    reconciled: bool,
    result: Dict[str, Any] | None = None,
) -> Dict[str, Any] | None:
    lid = _norm_text(local_id)
    if not lid:
        return None

    now = _utc_now_iso()
    state = "reconciled" if bool(reconciled) else "succeeded"
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE offline_creation_queue
            SET state=?,
                created=1,
                try_to_create=0,
                failure_type=NULL,
                failure_code=NULL,
                last_http_status=NULL,
                last_error_message=NULL,
                failed_reason=NULL,
                next_retry_at=NULL,
                processing_started_at=NULL,
                processing_lock_token=NULL,
                processing_lock_expires_at=NULL,
                succeeded_at=CASE WHEN ?='succeeded' THEN ? ELSE succeeded_at END,
                reconciled_at=CASE WHEN ?='reconciled' THEN ? ELSE reconciled_at END,
                updated_at=?
            WHERE local_id=?
            """,
            (state, state, now, state, now, now, lid),
        )
        conn.commit()
    return get_offline_creation(lid)


def mark_offline_creation_failure(
    local_id: str,
    *,
    failure_type: str,
    failure_code: str | None,
    http_status: int | None,
    message: str,
    retry_delay_min: int | None = None,
    max_countable_failures: int = 5,
) -> Dict[str, Any] | None:
    lid = _norm_text(local_id)
    if not lid:
        return None

    row = get_offline_creation(lid)
    if not row:
        return None

    ft = _norm_text_l(failure_type) or "server"
    countable = _failure_is_countable(ft)
    prev_count = int(row.get("failure_count") or 0)
    new_count = prev_count + (1 if countable else 0)

    next_state = "failed_retryable"
    next_try = True
    if ft == "auth":
        next_state = "blocked_auth"
    elif countable and new_count >= max(1, int(max_countable_failures or 5)):
        next_state = "failed_terminal"
        next_try = False

    delay = int(retry_delay_min) if retry_delay_min is not None else _failure_retry_delay_minutes(ft)
    nr = _next_retry_iso(delay)
    if next_state == "failed_terminal":
        nr = None

    now = _utc_now_iso()
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE offline_creation_queue
            SET state=?,
                created=0,
                try_to_create=?,
                failure_count=?,
                failure_type=?,
                failure_code=?,
                last_http_status=?,
                last_error_message=?,
                failed_reason=?,
                next_retry_at=?,
                processing_started_at=NULL,
                processing_lock_token=NULL,
                processing_lock_expires_at=NULL,
                updated_at=?
            WHERE local_id=?
            """,
            (
                next_state,
                1 if next_try else 0,
                new_count,
                ft,
                _norm_text(failure_code)[:200] or None,
                int(http_status) if http_status is not None else None,
                _norm_text(message)[:1000] or None,
                _norm_text(message)[:1000] or None,
                nr,
                now,
                lid,
            ),
        )
        conn.commit()
    return get_offline_creation(lid)


def classify_failure(*, http_status: int | None, message: str | None) -> Dict[str, Any]:
    msg = _norm_text_l(message)
    hs = int(http_status) if http_status is not None else None

    if hs in (401, 403):
        return {
            "failure_type": "auth",
            "failure_code": "AUTH_REQUIRED",
            "recommendation": "save_later",
            "countable": False,
        }
    if hs == 409:
        return {
            "failure_type": "conflict",
            "failure_code": "BUSINESS_CONFLICT",
            "recommendation": "modify",
            "countable": True,
        }
    if hs in (400, 404, 422):
        return {
            "failure_type": "validation",
            "failure_code": "VALIDATION_ERROR",
            "recommendation": "modify",
            "countable": True,
        }
    if hs is not None and hs >= 500:
        return {
            "failure_type": "server",
            "failure_code": "SERVER_UNAVAILABLE",
            "recommendation": "save_later",
            "countable": False,
        }

    net_markers = (
        "connection", "timeout", "timed out", "dns", "name or service", "failed to establish",
        "network", "unreachable", "forcibly closed", "connection aborted", "max retries exceeded",
    )
    for m in net_markers:
        if m in msg:
            return {
                "failure_type": "network",
                "failure_code": "NETWORK_ERROR",
                "recommendation": "save_later",
                "countable": False,
            }

    return {
        "failure_type": "server",
        "failure_code": "SERVER_UNKNOWN",
        "recommendation": "save_later",
        "countable": False,
    }


def _base_sync_users_payload_only() -> List[Dict[str, Any]]:
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM sync_users").fetchall()]
    return [_coerce_user_row_to_payload(r) for r in rows]


def _payload_get(payload: Dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in payload:
            return payload.get(k)
    return None


def list_projected_offline_users(*, base_users: List[Dict[str, Any]] | None = None) -> List[Dict[str, Any]]:
    users = list(base_users or [])

    by_username: Dict[str, Dict[str, Any]] = {}
    email_set: set[str] = set()
    card_set: set[str] = set()
    membership_link_set: set[tuple[str, str]] = set()

    for u in users:
        un = _norm_text_l(u.get("accountUsernameId"))
        if un:
            by_username[un] = u
        em = _norm_text_l(u.get("email"))
        if em:
            email_set.add(em)
        c1 = _norm_text_l(u.get("firstCardId"))
        c2 = _norm_text_l(u.get("secondCardId"))
        if c1:
            card_set.add(c1)
        if c2:
            card_set.add(c2)
        mid = _norm_text(u.get("membershipId"))
        if un and mid:
            membership_link_set.add((un, mid))

    candidates = list_offline_creations(states=["pending", "processing", "failed_retryable", "blocked_auth"], include_archived=False, limit=5000)
    out: List[Dict[str, Any]] = []

    for r in candidates:
        if not bool(r.get("try_to_create")):
            continue
        if bool(r.get("created")):
            continue
        if _normalize_queue_state(r.get("state")) in OFFLINE_QUEUE_FINAL_STATES:
            continue

        kind = _normalize_creation_kind(r.get("creation_kind"))
        payload = r.get("payload") if isinstance(r.get("payload"), dict) else {}

        start_v = _payload_get(payload, "startDate", "start_date", "validFrom", "valid_from")
        end_v = _payload_get(payload, "endDate", "end_date", "validTo", "valid_to")
        dt_start = _parse_iso_date(start_v)
        dt_end = _parse_iso_date(end_v)
        if dt_start is None or dt_end is None or dt_end < dt_start:
            continue

        membership_id = _norm_text(_payload_get(payload, "membershipId", "membership_id"))
        card1 = _norm_text_l(_payload_get(payload, "cardId", "card_id", "firstCardId", "first_card_id"))
        card2 = _norm_text_l(_payload_get(payload, "secondCardId", "second_card_id"))
        if card1 and card1 in card_set:
            continue
        if card2 and card2 in card_set:
            continue

        if kind == "membership_only":
            account_username = _norm_text_l(_payload_get(payload, "accountUsernameId", "account_username_id"))
            if not account_username or not membership_id:
                continue
            user_src = by_username.get(account_username)
            if not user_src:
                continue
            if (account_username, membership_id) in membership_link_set:
                continue

            am_id = _synthetic_negative_id(str(r.get("local_id")), "am")
            proj = {
                "userId": user_src.get("userId"),
                "activeMembershipId": am_id,
                "membershipId": _to_int_or_none(membership_id) or membership_id,
                "fullName": user_src.get("fullName") or "unavailable in offline mode",
                "phone": user_src.get("phone") or "unavailable in offline mode",
                "email": user_src.get("email") or "unavailable in offline mode",
                "validFrom": _norm_text(start_v),
                "validTo": _norm_text(end_v),
                "firstCardId": _payload_get(payload, "cardId", "card_id", "firstCardId", "first_card_id") or user_src.get("firstCardId"),
                "secondCardId": _payload_get(payload, "secondCardId", "second_card_id") or user_src.get("secondCardId"),
                "image": user_src.get("image"),
                "fingerprints": user_src.get("fingerprints") or [],
                "faceId": user_src.get("faceId"),
                "qrCodePayload": user_src.get("qrCodePayload"),
                "accountUsernameId": user_src.get("accountUsernameId") or account_username,
                "offlinePending": True,
                "offlinePendingLocalId": r.get("local_id"),
                "offlinePendingState": r.get("state"),
                "offlinePendingKind": kind,
                "offlineModeNote": "unavailable in offline mode",
            }
            out.append(proj)
            if card1:
                card_set.add(card1)
            if card2:
                card_set.add(card2)
            membership_link_set.add((account_username, membership_id))
            continue

        # account_plus_membership (stricter)
        email = _norm_text_l(_payload_get(payload, "email"))
        first = _norm_text(_payload_get(payload, "firstname", "firstName", "first_name"))
        last = _norm_text(_payload_get(payload, "lastname", "lastName", "last_name"))
        phone = _norm_text(_payload_get(payload, "phone"))
        password = _norm_text(_payload_get(payload, "password"))
        if not membership_id or not email or not first or not last or not phone:
            continue
        if len(password) < 8:
            continue
        if not _simple_email_ok(email):
            continue
        if email in email_set:
            continue

        provided_username = _norm_text_l(_payload_get(payload, "accountUsernameId", "account_username_id"))
        if provided_username and provided_username in by_username:
            continue

        am_id = _synthetic_negative_id(str(r.get("local_id")), "am")
        uid = _synthetic_negative_id(str(r.get("local_id")), "user")
        acc_username = provided_username or ("pending-" + _norm_text(str(r.get("local_id")))[:8])

        proj = {
            "userId": uid,
            "activeMembershipId": am_id,
            "membershipId": _to_int_or_none(membership_id) or membership_id,
            "fullName": (first + " " + last).strip(),
            "phone": phone,
            "email": email,
            "validFrom": _norm_text(start_v),
            "validTo": _norm_text(end_v),
            "firstCardId": _payload_get(payload, "cardId", "card_id", "firstCardId", "first_card_id"),
            "secondCardId": _payload_get(payload, "secondCardId", "second_card_id"),
            "image": None,
            "fingerprints": [],
            "faceId": None,
            "qrCodePayload": None,
            "accountUsernameId": acc_username,
            "offlinePending": True,
            "offlinePendingLocalId": r.get("local_id"),
            "offlinePendingState": r.get("state"),
            "offlinePendingKind": kind,
            "offlineModeNote": "unavailable in offline mode",
        }
        out.append(proj)

        email_set.add(email)
        if acc_username:
            by_username[acc_username] = proj
        if card1:
            card_set.add(card1)
        if card2:
            card_set.add(card2)

    return out









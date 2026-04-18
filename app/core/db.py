# app/core/db.py
from __future__ import annotations

import hashlib
import json
import logging
import queue
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional

from access.storage import current_access_runtime_db_path
from app.core.utils import ensure_dirs, now_iso
from shared.auth_state import AuthTokenState, protect_auth_token, unprotect_auth_token

# Test-only override: set _DB_PATH to a temp path in tests via monkeypatch.
# Production code always leaves this as None (falls through to current_access_runtime_db_path).
_DB_PATH: str | None = None
_DB_WRITE_PROFILE_LOG_THRESHOLD_MS = 250.0
_db_write_profiles_lock = threading.Lock()
_db_write_profiles: Dict[str, Dict[str, Any]] = {}
_db_write_profiles_order: List[str] = []
_db_writer_state_lock = threading.Lock()
_db_writer_thread: threading.Thread | None = None
_db_writer_queue: "queue.Queue[_DbWriteJob | None] | None" = None
_db_writer_db_path: str | None = None
_db_writer_local = threading.local()


def _resolve_db_path():
    if _DB_PATH is not None:
        import pathlib

        db_path = pathlib.Path(_DB_PATH)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        return db_path
    ensure_dirs()
    db_path = current_access_runtime_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return db_path


def _open_sqlite_connection(
    db_path,
    *,
    timeout: float = 30.0,
    wal_autocheckpoint: int = 1000,
) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=timeout)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(f"PRAGMA wal_autocheckpoint={int(wal_autocheckpoint)}")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@dataclass
class _DbWriteJob:
    label: str
    operation: Callable[[sqlite3.Connection, Dict[str, Any]], Any]
    submitted_at: float = field(default_factory=time.perf_counter)
    done: threading.Event = field(default_factory=threading.Event)
    result: Any = None
    error: BaseException | None = None
    profile: Dict[str, Any] | None = None


def _record_db_write_profile(label: str, profile: Dict[str, Any]) -> None:
    snapshot = dict(profile or {})
    snapshot["label"] = label
    with _db_write_profiles_lock:
        _db_write_profiles[label] = snapshot
        _db_write_profiles_order.append(label)
        if len(_db_write_profiles_order) > 32:
            _db_write_profiles_order[:] = _db_write_profiles_order[-32:]


def get_last_db_write_profile(label: str | None = None) -> Dict[str, Any] | None:
    with _db_write_profiles_lock:
        if label is not None:
            profile = _db_write_profiles.get(str(label))
            return dict(profile) if profile is not None else None
        if not _db_write_profiles_order:
            return None
        last_label = _db_write_profiles_order[-1]
        profile = _db_write_profiles.get(last_label)
        return dict(profile) if profile is not None else None


def _shutdown_db_writer_for_tests() -> None:
    global _db_writer_thread, _db_writer_queue, _db_writer_db_path
    with _db_writer_state_lock:
        thread = _db_writer_thread
        work_q = _db_writer_queue
        _db_writer_thread = None
        _db_writer_queue = None
        _db_writer_db_path = None
    if work_q is not None:
        work_q.put(None)
    if thread is not None and thread.is_alive():
        thread.join(timeout=2.0)


def _ensure_db_writer() -> "queue.Queue[_DbWriteJob | None]":
    global _db_writer_thread, _db_writer_queue, _db_writer_db_path

    db_path = str(_resolve_db_path())
    with _db_writer_state_lock:
        thread = _db_writer_thread
        work_q = _db_writer_queue
        if thread is not None and thread.is_alive() and work_q is not None and _db_writer_db_path == db_path:
            return work_q

    _shutdown_db_writer_for_tests()

    work_q = queue.Queue()
    thread = threading.Thread(
        target=_db_writer_loop,
        args=(db_path, work_q),
        name="DbWriter",
        daemon=True,
    )
    with _db_writer_state_lock:
        _db_writer_queue = work_q
        _db_writer_thread = thread
        _db_writer_db_path = db_path
    thread.start()
    return work_q


def _db_writer_loop(db_path: str, work_q: "queue.Queue[_DbWriteJob | None]") -> None:
    logger = logging.getLogger(__name__)
    conn = _open_sqlite_connection(db_path)
    _db_writer_local.connection = conn
    _db_writer_local.ident = threading.get_ident()
    try:
        while True:
            job = work_q.get()
            if job is None:
                break

            total_started = time.perf_counter()
            profile: Dict[str, Any] = {
                "label": job.label,
                "queue_wait_ms": round((total_started - job.submitted_at) * 1000.0, 3),
                "writer_thread": threading.current_thread().name,
            }
            try:
                begin_started = time.perf_counter()
                conn.execute("BEGIN IMMEDIATE")
                profile["begin_wait_ms"] = round((time.perf_counter() - begin_started) * 1000.0, 3)

                tx_started = time.perf_counter()
                result = job.operation(conn, profile)
                profile["transaction_ms"] = round((time.perf_counter() - tx_started) * 1000.0, 3)

                commit_started = time.perf_counter()
                conn.commit()
                profile["commit_ms"] = round((time.perf_counter() - commit_started) * 1000.0, 3)
                profile["total_ms"] = round((time.perf_counter() - total_started) * 1000.0, 3)
                job.result = result
            except BaseException as exc:
                try:
                    conn.rollback()
                except Exception:
                    pass
                profile.setdefault("begin_wait_ms", 0.0)
                profile.setdefault("transaction_ms", 0.0)
                profile.setdefault("commit_ms", 0.0)
                profile["total_ms"] = round((time.perf_counter() - total_started) * 1000.0, 3)
                profile["error"] = repr(exc)
                job.error = exc
            finally:
                _record_db_write_profile(job.label, profile)
                # Log if processing was slow OR if the job waited long in queue.
                # queue_wait_ms is NOT included in total_ms, so we check both.
                _log_threshold = _DB_WRITE_PROFILE_LOG_THRESHOLD_MS
                if (
                    float(profile.get("total_ms") or 0.0) >= _log_threshold
                    or float(profile.get("queue_wait_ms") or 0.0) >= _log_threshold
                ):
                    logger.info("[DB-WRITE] %s profile=%s", job.label, profile)
                job.profile = profile
                job.done.set()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        _db_writer_local.connection = None
        _db_writer_local.ident = None


def _run_db_write_sync(
    label: str,
    operation: Callable[[sqlite3.Connection, Dict[str, Any]], Any],
) -> Any:
    if getattr(_db_writer_local, "ident", None) == threading.get_ident():
        conn = getattr(_db_writer_local, "connection", None)
        if conn is None:
            raise RuntimeError("DB writer thread missing active connection")
        profile: Dict[str, Any] = {
            "label": label,
            "queue_wait_ms": 0.0,
            "begin_wait_ms": 0.0,
            "writer_thread": threading.current_thread().name,
        }
        started = time.perf_counter()
        result = operation(conn, profile)
        profile["transaction_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
        profile["commit_ms"] = 0.0
        profile["total_ms"] = profile["transaction_ms"]
        _record_db_write_profile(label, profile)
        return result

    work_q = _ensure_db_writer()
    job = _DbWriteJob(label=str(label), operation=operation)
    work_q.put(job)
    if not job.done.wait(timeout=60.0):
        raise TimeoutError(f"Timed out waiting for DB writer job '{label}'")
    if job.error is not None:
        raise job.error
    return job.result


@contextmanager
def _profile_write_step(profile: Dict[str, Any], key: str) -> Iterator[None]:
    started = time.perf_counter()
    try:
        yield
    finally:
        profile[key] = round((time.perf_counter() - started) * 1000.0, 3)

# -----------------------------
# SQLite connection helpers
# -----------------------------
@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = _open_sqlite_connection(_resolve_db_path())
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


def _relax_firmware_profiles_not_null(conn: sqlite3.Connection) -> None:
    """
    P0-bulk migration: the original sync_firmware_profiles schema had NOT NULL on
    template_table / template_body_index / authorize_body_index. On devices that
    don't expose those (e.g. C3-400 with fingerprintEnabled=false, where template
    discovery never runs) we now need to cache insert_strategy / delete_strategy
    independently, so the template columns must be nullable. SQLite can't relax
    NOT NULL via ALTER — rebuild the table if the old constraints are still in
    place. Idempotent: no-op once migrated. Robust against very old schemas
    missing name_supported / insert_strategy / delete_strategy: the SELECT only
    pulls columns that actually exist.
    """
    try:
        rows = conn.execute("PRAGMA table_info(sync_firmware_profiles)").fetchall()
    except Exception:
        return
    if not rows:
        return

    existing: dict = {}
    for r in rows:
        try:
            existing[r["name"]] = bool(r["notnull"])
        except Exception:
            # Fallback for non-Row cursors
            existing[r[1]] = bool(r[3])

    must_migrate = any(
        existing.get(col) is True
        for col in ("template_table", "template_body_index", "authorize_body_index")
    )
    if not must_migrate:
        return

    # Build the SELECT list from whatever columns actually exist; default missing
    # ones to NULL so very old DBs migrate cleanly.
    def _col_or_null(name: str) -> str:
        return name if name in existing else "NULL"

    select_list = ", ".join(
        _col_or_null(c)
        for c in (
            "device_id",
            "template_table",
            "template_body_index",
            "authorize_body_index",
            "name_supported",
            "insert_strategy",
            "delete_strategy",
            "updated_at",
        )
    )

    conn.execute("DROP TABLE IF EXISTS sync_firmware_profiles__new")
    conn.execute(
        """
        CREATE TABLE sync_firmware_profiles__new (
            device_id            INTEGER PRIMARY KEY,
            template_table       TEXT,
            template_body_index  INTEGER,
            authorize_body_index INTEGER,
            name_supported       INTEGER DEFAULT NULL,
            insert_strategy      TEXT    DEFAULT NULL,
            delete_strategy      TEXT    DEFAULT NULL,
            updated_at           TEXT    NOT NULL DEFAULT ''
        );
        """
    )
    conn.execute(
        f"""
        INSERT OR IGNORE INTO sync_firmware_profiles__new
            (device_id, template_table, template_body_index, authorize_body_index,
             name_supported, insert_strategy, delete_strategy, updated_at)
        SELECT {select_list}
        FROM sync_firmware_profiles
        """
    )
    conn.execute("DROP TABLE sync_firmware_profiles")
    conn.execute("ALTER TABLE sync_firmware_profiles__new RENAME TO sync_firmware_profiles")


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

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fast_patch_bundles (
                bundle_id TEXT PRIMARY KEY,
                generated_at TEXT NOT NULL,
                applied_at TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fast_patch_revisions (
                patch_key TEXT PRIMARY KEY,
                revision TEXT NOT NULL,
                updated_at TEXT NOT NULL
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

        # P0-bulk: strategy cache on firmware profile (bulk upsert / delete cascade)
        _ensure_column(conn, "sync_firmware_profiles", "insert_strategy", "insert_strategy TEXT")
        _ensure_column(conn, "sync_firmware_profiles", "delete_strategy", "delete_strategy TEXT")
        try:
            _relax_firmware_profiles_not_null(conn)
        except Exception as _mig_exc:
            logging.getLogger(__name__).error(
                "[DB] schema migration _relax_firmware_profiles_not_null failed: %s",
                _mig_exc,
            )

        _ensure_column(conn, "sync_users", "fingerprints_json", "fingerprints_json TEXT")
        _ensure_column(conn, "sync_users", "active_membership_id", "active_membership_id INTEGER")
        _ensure_column(conn, "sync_users", "account_username_id", "account_username_id TEXT")
        _ensure_column(conn, "sync_users", "birthday",           "birthday TEXT")
        _ensure_column(conn, "sync_users", "image_source",       "image_source TEXT")
        _ensure_column(conn, "sync_users", "user_image_status",  "user_image_status TEXT")
        _ensure_column(conn, "sync_users", "user_profile_image", "user_profile_image TEXT")
        try:
            _rebuild_sync_users_without_legacy_fingerprint(conn)
        except Exception as _mig_exc:
            logging.getLogger(__name__).error(
                "[DB] schema migration _rebuild_sync_users failed: %s",
                _mig_exc,
            )

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
                totp_validation INTEGER,

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
        _ensure_column(conn, "sync_access_software_settings", "totp_validation", "totp_validation INTEGER")
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

                anti_fraude_card             INTEGER NOT NULL DEFAULT 1,
                anti_fraude_qr_code          INTEGER NOT NULL DEFAULT 1,
                anti_fraude_duration         INTEGER NOT NULL DEFAULT 30,
                anti_fraude_daily_pass_limit INTEGER NOT NULL DEFAULT 0
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

        _ensure_column(conn, "sync_devices", "anti_fraude_card",             "anti_fraude_card INTEGER NOT NULL DEFAULT 1")
        _ensure_column(conn, "sync_devices", "anti_fraude_qr_code",          "anti_fraude_qr_code INTEGER NOT NULL DEFAULT 1")
        _ensure_column(conn, "sync_devices", "anti_fraude_duration",         "anti_fraude_duration INTEGER NOT NULL DEFAULT 30")
        _ensure_column(conn, "sync_devices", "anti_fraude_daily_pass_limit", "anti_fraude_daily_pass_limit INTEGER NOT NULL DEFAULT 0")

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
                updated_at TEXT,
                favorite_enabled INTEGER NOT NULL DEFAULT 0,
                favorite_order INTEGER,
                favorite_shortcut TEXT
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sync_ddp_device_id ON sync_device_door_presets(device_id);")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_sync_ddp_remote_id ON sync_device_door_presets(remote_id);")
        _ensure_column(conn, "sync_device_door_presets", "favorite_enabled", "favorite_enabled INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "sync_device_door_presets", "favorite_order", "favorite_order INTEGER")
        _ensure_column(conn, "sync_device_door_presets", "favorite_shortcut", "favorite_shortcut TEXT")

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
        # Anti-fraud daily-limit feature: user_id resolved at insert time so
        # count_today_for_user_door() can query directly by user without joining
        # sync_users (JOIN is ambiguous for cards that get reassigned and
        # undefined for QR credentials which have no card_no).
        _ensure_column(conn, "access_history", "user_id", "user_id INTEGER")
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
        # Anti-fraud daily-pass-limit: composite index that bounds
        # count_today_for_user_door(user_id, device_id, door_id) to O(log n)
        # even as access_history grows. Partial index on allowed=1 would be
        # tighter but SQLite partial-index predicate evaluation cost isn't
        # worth it at gym-scale row counts; the full composite suffices.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_access_history_user_door_day "
            "ON access_history(user_id, device_id, door_id, allowed, created_at);"
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
                template_table       TEXT,
                template_body_index  INTEGER,
                authorize_body_index INTEGER,
                name_supported       INTEGER DEFAULT NULL,
                insert_strategy      TEXT    DEFAULT NULL,
                delete_strategy      TEXT    DEFAULT NULL,
                updated_at           TEXT    NOT NULL
            );
            """
        )

        # P7: Device content mirror — write-through copy of what was last pushed to each device.
        # Updated after every successful per-pin push; used for drift detection and dashboard visibility.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_content_mirror (
                device_id       INTEGER NOT NULL,
                pin             TEXT    NOT NULL,
                full_name       TEXT,
                card_no         TEXT,
                door_bitmask    INTEGER,
                authorize_tz_id INTEGER,
                fp_count        INTEGER NOT NULL DEFAULT 0,
                pushed_at       TEXT    NOT NULL,
                push_ok         INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (device_id, pin)
            );
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_dcm_device ON device_content_mirror(device_id);"
        )

        # P6: Member shadow — lightweight local copy of backend member state for diff detection.
        # Enables Access to classify changes as NEW/MODIFIED/DELETED and route to affected devices
        # without fetching the full roster from the backend on every sync.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS member_shadow (
                active_membership_id  INTEGER PRIMARY KEY,
                pin                   TEXT,
                full_name             TEXT,
                card_id               TEXT,
                second_card_id        TEXT,
                membership_id         INTEGER,
                valid_from            TEXT,
                valid_to              TEXT,
                fp_hash               TEXT,
                updated_at            TEXT    NOT NULL
            );
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ms_membership ON member_shadow(membership_id);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ms_card ON member_shadow(card_id) WHERE card_id IS NOT NULL;"
        )

        # -----------------------------
        # sync observability
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_run_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                run_type        TEXT NOT NULL,
                trigger_source  TEXT NOT NULL,
                trigger_hint    TEXT,
                status          TEXT NOT NULL,
                members_total   INTEGER NOT NULL DEFAULT 0,
                members_changed INTEGER NOT NULL DEFAULT 0,
                devices_synced  INTEGER NOT NULL DEFAULT 0,
                duration_ms     INTEGER NOT NULL DEFAULT 0,
                error_message   TEXT,
                raw_response    TEXT,
                created_at      TEXT NOT NULL
            );
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sync_run_history_created_at "
            "ON sync_run_history(created_at DESC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sync_run_history_status "
            "ON sync_run_history(status);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sync_run_history_trigger_source "
            "ON sync_run_history(trigger_source);"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS push_batch_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                sync_run_id     INTEGER REFERENCES sync_run_history(id) ON DELETE SET NULL,
                device_id       INTEGER NOT NULL,
                device_name     TEXT NOT NULL,
                policy          TEXT NOT NULL,
                pins_attempted  INTEGER NOT NULL DEFAULT 0,
                pins_success    INTEGER NOT NULL DEFAULT 0,
                pins_failed     INTEGER NOT NULL DEFAULT 0,
                status          TEXT NOT NULL,
                duration_ms     INTEGER NOT NULL DEFAULT 0,
                error_message   TEXT,
                created_at      TEXT NOT NULL
            );
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_push_batch_history_created_at "
            "ON push_batch_history(created_at DESC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_push_batch_history_device_id "
            "ON push_batch_history(device_id);"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS push_pin_history (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id      INTEGER NOT NULL REFERENCES push_batch_history(id) ON DELETE CASCADE,
                pin           TEXT NOT NULL,
                full_name     TEXT,
                operation     TEXT NOT NULL,
                status        TEXT NOT NULL,
                error_message TEXT,
                duration_ms   INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_push_pin_history_batch_id "
            "ON push_pin_history(batch_id);"
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

    def _write(conn: sqlite3.Connection, profile: Dict[str, Any]) -> None:
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

    _run_db_write_sync("save_version_tokens", _write)


def load_version_tokens() -> dict:
    """Return all saved version tokens, or empty dict if none."""
    with get_conn() as conn:
        rows = conn.execute("SELECT key, value FROM sync_version_tokens").fetchall()
        return {r["key"]: r["value"] for r in rows}


def clear_version_tokens() -> None:
    """Delete all saved version tokens (call on logout/login/cache-clear)."""
    def _write(conn: sqlite3.Connection, profile: Dict[str, Any]) -> None:
        conn.execute("DELETE FROM sync_version_tokens")

    _run_db_write_sync("clear_version_tokens", _write)


# -----------------------------
# Phase 2: Firmware profile cache
# -----------------------------

def save_firmware_profile(
    *,
    device_id: int,
    template_table: str | None = None,
    template_body_index: int | None = None,
    authorize_body_index: int | None = None,
    name_supported: bool | None = None,
    insert_strategy: str | None = None,
    delete_strategy: str | None = None,
) -> None:
    """
    Upsert the firmware profile for a ZKTeco device.
    Keyed by device_id (stable integer) — not IP (DHCP can change IPs).

    Template/authorize columns preserve existing values when None is passed, so
    callers can save strategy fields without clobbering earlier discoveries.
    """
    name_val = None if name_supported is None else (1 if name_supported else 0)
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO sync_firmware_profiles
                (device_id, template_table, template_body_index, authorize_body_index,
                 name_supported, insert_strategy, delete_strategy, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                template_table       = COALESCE(excluded.template_table,       sync_firmware_profiles.template_table),
                template_body_index  = COALESCE(excluded.template_body_index,  sync_firmware_profiles.template_body_index),
                authorize_body_index = COALESCE(excluded.authorize_body_index, sync_firmware_profiles.authorize_body_index),
                name_supported       = COALESCE(excluded.name_supported,       sync_firmware_profiles.name_supported),
                insert_strategy      = COALESCE(excluded.insert_strategy,      sync_firmware_profiles.insert_strategy),
                delete_strategy      = COALESCE(excluded.delete_strategy,      sync_firmware_profiles.delete_strategy),
                updated_at           = excluded.updated_at
            """,
            (
                device_id,
                template_table,
                template_body_index,
                authorize_body_index,
                name_val,
                insert_strategy,
                delete_strategy,
                now_iso(),
            ),
        )
        conn.commit()


def load_firmware_profile(*, device_id: int) -> dict | None:
    """
    Load the cached firmware profile for a device, or None if not cached.
    Returns dict with keys: template_table, template_body_index, authorize_body_index,
    name_supported, insert_strategy, delete_strategy.
    """
    with get_conn() as conn:
        row = conn.execute(
            "SELECT template_table, template_body_index, authorize_body_index, "
            "name_supported, insert_strategy, delete_strategy "
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
        "insert_strategy": row[4],
        "delete_strategy": row[5],
    }


def clear_firmware_profile(*, device_id: int) -> None:
    """Remove the cached firmware profile for a device (e.g., after firmware upgrade detected)."""
    with get_conn() as conn:
        conn.execute("DELETE FROM sync_firmware_profiles WHERE device_id = ?", (device_id,))
        conn.commit()


# -----------------------------
# P7: Device content mirror
# -----------------------------

def upsert_device_mirror_pin(
    *,
    device_id: int,
    pin: str,
    full_name: str | None,
    card_no: str | None,
    door_bitmask: int | None,
    authorize_tz_id: int | None,
    fp_count: int = 0,
    push_ok: bool = True,
) -> None:
    """Write-through update after a successful per-pin push to a ZKTeco device."""
    import time as _time
    pushed_at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO device_content_mirror
                (device_id, pin, full_name, card_no, door_bitmask, authorize_tz_id,
                 fp_count, pushed_at, push_ok)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id, pin) DO UPDATE SET
                full_name       = excluded.full_name,
                card_no         = excluded.card_no,
                door_bitmask    = excluded.door_bitmask,
                authorize_tz_id = excluded.authorize_tz_id,
                fp_count        = excluded.fp_count,
                pushed_at       = excluded.pushed_at,
                push_ok         = excluded.push_ok
            """,
            (device_id, pin, full_name, card_no, door_bitmask, authorize_tz_id,
             fp_count, pushed_at, 1 if push_ok else 0),
        )
        conn.commit()


def delete_device_mirror_pin(*, device_id: int, pin: str) -> None:
    """Remove a pin from the content mirror (called when pin is deleted from device)."""
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM device_content_mirror WHERE device_id=? AND pin=?",
            (device_id, pin),
        )
        conn.commit()


def list_device_mirror(*, device_id: int) -> List[Dict[str, Any]]:
    """Return all mirror rows for a device (used by API + drift detection)."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM device_content_mirror WHERE device_id=? ORDER BY pin",
            (device_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def clear_device_mirror(*, device_id: int) -> None:
    """Wipe the entire mirror for a device (called on FULL_REPLACE before re-push)."""
    with get_conn() as conn:
        conn.execute("DELETE FROM device_content_mirror WHERE device_id=?", (device_id,))
        conn.commit()


# -----------------------------
# P6: Member shadow
# -----------------------------

def upsert_member_shadow(*, users: List[Dict[str, Any]]) -> None:
    """
    Upsert the local shadow copy of backend member state.
    Called after every successful getSyncData response so the shadow
    always reflects the last known backend state.
    """
    if not users:
        return
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    def _write(conn: sqlite3.Connection, profile: Dict[str, Any]) -> None:
        for u in users:
            amid = u.get("activeMembershipId") or u.get("active_membership_id")
            if amid is None:
                continue
            try:
                amid = int(amid)
            except (TypeError, ValueError):
                continue
            # Build fingerprint hash from fingerprints list (if any)
            fps = u.get("fingerprints") or []
            if fps:
                import hashlib as _hashlib
                fp_str = json.dumps(
                    sorted([f.get("fingerId") for f in fps if isinstance(f, dict)]),
                    sort_keys=True,
                )
                fp_hash = _hashlib.sha1(fp_str.encode()).hexdigest()
            else:
                fp_hash = None

            conn.execute(
                """
                INSERT INTO member_shadow
                    (active_membership_id, pin, full_name, card_id, second_card_id,
                     membership_id, valid_from, valid_to, fp_hash, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(active_membership_id) DO UPDATE SET
                    pin            = excluded.pin,
                    full_name      = excluded.full_name,
                    card_id        = excluded.card_id,
                    second_card_id = excluded.second_card_id,
                    membership_id  = excluded.membership_id,
                    valid_from     = excluded.valid_from,
                    valid_to       = excluded.valid_to,
                    fp_hash        = excluded.fp_hash,
                    updated_at     = excluded.updated_at
                """,
                (
                    amid,
                    str(u.get("activeMembershipId") or u.get("active_membership_id") or amid),
                    u.get("fullName") or u.get("full_name"),
                    u.get("firstCardId") or u.get("first_card_id"),
                    u.get("secondCardId") or u.get("second_card_id"),
                    u.get("membershipId") or u.get("membership_id"),
                    u.get("validFrom") or u.get("valid_from"),
                    u.get("validTo") or u.get("valid_to"),
                    fp_hash,
                    now,
                ),
            )

    _run_db_write_sync("upsert_member_shadow", _write)


def delete_member_shadow(*, active_membership_ids: List[int]) -> None:
    """Remove shadow rows for deleted members."""
    if not active_membership_ids:
        return
    placeholders = ",".join("?" * len(active_membership_ids))

    def _write(conn: sqlite3.Connection, profile: Dict[str, Any]) -> None:
        conn.execute(
            f"DELETE FROM member_shadow WHERE active_membership_id IN ({placeholders})",
            active_membership_ids,
        )

    _run_db_write_sync("delete_member_shadow", _write)


def list_member_shadow_deleted_ids(*, valid_member_ids: List[int]) -> List[int]:
    """Return shadow ids that are missing from the backend valid-id set."""
    valid_set = set()
    for raw_id in valid_member_ids or []:
        try:
            valid_set.add(int(raw_id))
        except (TypeError, ValueError):
            continue

    with get_conn() as conn:
        rows = conn.execute("SELECT active_membership_id FROM member_shadow").fetchall()

    deleted_ids: List[int] = []
    for row in rows:
        try:
            amid = int(row["active_membership_id"])
        except (TypeError, ValueError):
            continue
        if amid not in valid_set:
            deleted_ids.append(amid)
    return deleted_ids


def apply_member_shadow_delta(
    *,
    users: List[Dict[str, Any]],
    valid_member_ids: List[int] | None = None,
) -> List[int]:
    """
    Apply delta-mode member shadow changes in one DB transaction.

    This keeps the sync hot path from paying separate SQLite lock waits for
    read -> upsert -> delete when only a handful of members changed.
    """
    normalized_valid_ids: set[int] | None = None
    if valid_member_ids is not None:
        normalized_valid_ids = set()
        for raw_id in valid_member_ids:
            try:
                normalized_valid_ids.add(int(raw_id))
            except (TypeError, ValueError):
                continue

    deleted_ids: List[int] = []
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    def _write(conn: sqlite3.Connection, profile: Dict[str, Any]) -> List[int]:
        if normalized_valid_ids is not None:
            rows = conn.execute(
                "SELECT active_membership_id FROM member_shadow"
            ).fetchall()
            for row in rows:
                try:
                    amid = int(row["active_membership_id"])
                except (TypeError, ValueError):
                    continue
                if amid not in normalized_valid_ids:
                    deleted_ids.append(amid)

        for u in users or []:
            amid = u.get("activeMembershipId") or u.get("active_membership_id")
            if amid is None:
                continue
            try:
                amid = int(amid)
            except (TypeError, ValueError):
                continue

            fps = u.get("fingerprints") or []
            if fps:
                fp_str = json.dumps(
                    sorted([f.get("fingerId") for f in fps if isinstance(f, dict)]),
                    sort_keys=True,
                )
                fp_hash = hashlib.sha1(fp_str.encode()).hexdigest()
            else:
                fp_hash = None

            conn.execute(
                """
                INSERT INTO member_shadow
                    (active_membership_id, pin, full_name, card_id, second_card_id,
                     membership_id, valid_from, valid_to, fp_hash, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(active_membership_id) DO UPDATE SET
                    pin            = excluded.pin,
                    full_name      = excluded.full_name,
                    card_id        = excluded.card_id,
                    second_card_id = excluded.second_card_id,
                    membership_id  = excluded.membership_id,
                    valid_from     = excluded.valid_from,
                    valid_to       = excluded.valid_to,
                    fp_hash        = excluded.fp_hash,
                    updated_at     = excluded.updated_at
                """,
                (
                    amid,
                    str(u.get("activeMembershipId") or u.get("active_membership_id") or amid),
                    u.get("fullName") or u.get("full_name"),
                    u.get("firstCardId") or u.get("first_card_id"),
                    u.get("secondCardId") or u.get("second_card_id"),
                    u.get("membershipId") or u.get("membership_id"),
                    u.get("validFrom") or u.get("valid_from"),
                    u.get("validTo") or u.get("valid_to"),
                    fp_hash,
                    now,
                ),
            )

        if deleted_ids:
            placeholders = ",".join("?" * len(deleted_ids))
            conn.execute(
                f"DELETE FROM member_shadow WHERE active_membership_id IN ({placeholders})",
                deleted_ids,
            )
        return deleted_ids

    return list(_run_db_write_sync("apply_member_shadow_delta", _write))


def get_member_shadow_cards() -> Dict[int, str | None]:
    """Return {activeMembershipId: cardId} for all shadow rows."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT active_membership_id, card_id FROM member_shadow"
        ).fetchall()
        return {int(r["active_membership_id"]): r["card_id"] for r in rows}


def diff_member_shadow(
    *,
    incoming_users: List[Dict[str, Any]],
    valid_member_ids: List[int] | None = None,
) -> Dict[str, List[int]]:
    """
    Compare incoming users against the local shadow and return classified changes.

    Returns:
        {
          "new":      [activeMembershipId, ...],   — not in shadow
          "modified": [activeMembershipId, ...],   — in shadow but fields changed
          "deleted":  [activeMembershipId, ...],   — in shadow but not in valid_member_ids
        }

    Uses only the fields that affect device access: card, name, fp_hash, validity dates.
    """
    with get_conn() as conn:
        shadow_rows = conn.execute("SELECT * FROM member_shadow").fetchall()
        shadow = {int(r["active_membership_id"]): dict(r) for r in shadow_rows}

    incoming_ids: set[int] = set()
    new_ids: List[int] = []
    modified_ids: List[int] = []

    for u in incoming_users or []:
        amid_raw = u.get("activeMembershipId") or u.get("active_membership_id")
        if amid_raw is None:
            continue
        try:
            amid = int(amid_raw)
        except (TypeError, ValueError):
            continue
        incoming_ids.add(amid)

        fps = u.get("fingerprints") or []
        if fps:
            import hashlib as _hashlib
            fp_str = json.dumps(
                sorted([f.get("fingerId") for f in fps if isinstance(f, dict)]),
                sort_keys=True,
            )
            fp_hash = _hashlib.sha1(fp_str.encode()).hexdigest()
        else:
            fp_hash = None

        if amid not in shadow:
            new_ids.append(amid)
            continue

        s = shadow[amid]
        changed = (
            (u.get("firstCardId") or u.get("first_card_id")) != s.get("card_id")
            or (u.get("secondCardId") or u.get("second_card_id")) != s.get("second_card_id")
            or (u.get("fullName") or u.get("full_name")) != s.get("full_name")
            or fp_hash != s.get("fp_hash")
            or (u.get("validFrom") or u.get("valid_from")) != s.get("valid_from")
            or (u.get("validTo") or u.get("valid_to")) != s.get("valid_to")
        )
        if changed:
            modified_ids.append(amid)

    deleted_ids: List[int] = []
    if valid_member_ids is not None:
        valid_set = set(valid_member_ids)
        for amid in shadow:
            if amid not in valid_set and amid not in incoming_ids:
                deleted_ids.append(amid)

    return {"new": new_ids, "modified": modified_ids, "deleted": deleted_ids}


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
                    qr_code_payload, birthday, image_source, user_image_status,
                    user_profile_image
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    u.get("userProfileImage"),
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


def list_fingerprints_by_pins(*, pins: List[str] | set[str] | tuple[str, ...]) -> List[FingerprintRecord]:
    normalized = sorted({
        str(pin or "").strip()
        for pin in (pins or [])
        if str(pin or "").strip()
    })
    if not normalized:
        return []
    placeholders = ",".join("?" for _ in normalized)
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM fingerprints WHERE pin IN ({placeholders}) ORDER BY id DESC",
            tuple(normalized),
        ).fetchall()
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
                INSERT OR REPLACE INTO sync_device_door_presets (
                    remote_id, device_id, door_number, pulse_seconds, door_name, created_at, updated_at,
                    favorite_enabled, favorite_order, favorite_shortcut
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

            anti_fraude_card, anti_fraude_qr_code, anti_fraude_duration,
            anti_fraude_daily_pass_limit
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
            ?, ?, ?,
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
                        totp_validation,

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
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        gym_id=excluded.gym_id,
                        access_server_host=excluded.access_server_host,
                        access_server_port=excluded.access_server_port,
                        access_server_enabled=excluded.access_server_enabled,
                        totp_validation=excluded.totp_validation,

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
                        _bool_to_i(s.get("totpValidation", s.get("totp_validation", True)), default=1),

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
                    image_source, user_image_status, user_profile_image
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    u.get("userProfileImage"),
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


def _normalize_sync_credential_payload_row(c: Dict[str, Any]) -> Dict[str, Any]:
    granted_ids = c.get("grantedActiveMembershipIds")
    if not isinstance(granted_ids, list):
        granted_ids = []

    return {
        "id": _to_int_or_none(c.get("id")),
        "gym_id": _to_int_or_none(c.get("gymId") if "gymId" in c else c.get("gym_id")),
        "account_id": _to_int_or_none(c.get("accountId") if "accountId" in c else c.get("account_id")),
        "secret_hex": str((c.get("secretHex") if "secretHex" in c else c.get("secret_hex")) or ""),
        "enabled": 1 if bool(c.get("enabled", False)) else 0,
        "rotated_at": c.get("rotatedAt") or c.get("rotated_at"),
        "created_at": c.get("createdAt") or c.get("created_at"),
        "updated_at": c.get("updatedAt") or c.get("updated_at"),
        "granted_active_membership_ids_json": json.dumps(granted_ids, ensure_ascii=False),
    }


def _sync_credential_identity(row: Dict[str, Any]) -> tuple[int, int] | None:
    gym_id = row.get("gym_id")
    account_id = row.get("account_id")
    if gym_id is None or account_id is None:
        return None
    return (int(gym_id), int(account_id))


def _sync_credential_params(row: Dict[str, Any]) -> tuple[Any, ...]:
    return (
        row.get("id"),
        row.get("gym_id"),
        row.get("account_id"),
        row.get("secret_hex"),
        row.get("enabled"),
        row.get("rotated_at"),
        row.get("created_at"),
        row.get("updated_at"),
        row.get("granted_active_membership_ids_json"),
    )


def _replace_sync_credentials(cur: sqlite3.Cursor, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    cur.execute("DELETE FROM sync_gym_access_credentials")
    if rows:
        cur.executemany(
            """
            INSERT INTO sync_gym_access_credentials (
                id, gym_id, account_id, secret_hex, enabled,
                rotated_at, created_at, updated_at,
                granted_active_membership_ids_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [_sync_credential_params(row) for row in rows],
        )
    return {"mode": "replace", "deleted": None, "upserted": len(rows)}


def _sync_gym_access_credentials_rows(
    cur: sqlite3.Cursor,
    payload_rows: List[Dict[str, Any]],
    *,
    merge_mode: str | None = None,
) -> Dict[str, Any]:
    t0 = time.perf_counter()
    normalized_rows = [_normalize_sync_credential_payload_row(c) for c in payload_rows if isinstance(c, dict)]
    normalize_ms = (time.perf_counter() - t0) * 1000.0
    merge_only = str(merge_mode or "").strip().upper() == "UPSERT_ONLY"
    if not normalized_rows:
        if merge_only:
            return {"mode": "merge", "deleted": 0, "upserted": 0, "normalize_ms": normalize_ms}
        cur.execute("DELETE FROM sync_gym_access_credentials")
        return {"mode": "replace", "deleted": None, "upserted": 0, "normalize_ms": normalize_ms}

    incoming_by_key: Dict[tuple[int, int], Dict[str, Any]] = {}
    for row in normalized_rows:
        key = _sync_credential_identity(row)
        if key is None:
            return _replace_sync_credentials(cur, normalized_rows)
        incoming_by_key[key] = row

    existing_keys_fetch_ms = 0.0
    existing_fetch_ms = 0.0
    existing_key_set: set[tuple[int, int]] = set()
    if not merge_only:
        t_keys = time.perf_counter()
        existing_keys = cur.execute(
            "SELECT gym_id, account_id FROM sync_gym_access_credentials"
        ).fetchall()
        existing_keys_fetch_ms = (time.perf_counter() - t_keys) * 1000.0
        for gym_id, account_id in existing_keys:
            if gym_id is None or account_id is None:
                return _replace_sync_credentials(cur, normalized_rows)
            existing_key_set.add((int(gym_id), int(account_id)))

    # Avoid full-row reads (granted_active_membership_ids_json can be huge).
    # We diff using a lightweight field set; JSON changes that don't update
    # these fields will not be detected.
    prefer_upsert_all = False
    lite_diff = True
    existing_by_key: Dict[tuple[int, int], Dict[str, Any]] = {}
    if incoming_by_key:
        t_fetch = time.perf_counter()
        incoming_keys = list(incoming_by_key.keys())
        chunk_size = 200
        for i in range(0, len(incoming_keys), chunk_size):
            chunk = incoming_keys[i:i + chunk_size]
            predicates = " OR ".join(["(gym_id=? AND account_id=?)"] * len(chunk))
            params: List[Any] = []
            for gym_id, account_id in chunk:
                params.extend([gym_id, account_id])
            rows = cur.execute(
                f"""
                SELECT
                    id, gym_id, account_id, secret_hex, enabled,
                    rotated_at, created_at, updated_at
                FROM sync_gym_access_credentials
                WHERE {predicates}
                """,
                params,
            ).fetchall()
            for r in rows:
                row = dict(r)
                key = _sync_credential_identity(row)
                if key is None:
                    return _replace_sync_credentials(cur, normalized_rows)
                existing_by_key[key] = row
        existing_fetch_ms = (time.perf_counter() - t_fetch) * 1000.0

    t_diff = time.perf_counter()
    fields = (
        "id",
        "gym_id",
        "account_id",
        "secret_hex",
        "enabled",
        "rotated_at",
        "created_at",
        "updated_at",
    )
    to_upsert = [
        row
        for key, row in incoming_by_key.items()
        if key not in existing_by_key or any(existing_by_key[key].get(field) != row.get(field) for field in fields)
    ]
    to_delete = [] if merge_only else [key for key in existing_key_set if key not in incoming_by_key]
    diff_ms = (time.perf_counter() - t_diff) * 1000.0

    delete_ms = 0.0
    if to_delete:
        t_del = time.perf_counter()
        chunk_size = 200
        for i in range(0, len(to_delete), chunk_size):
            chunk = to_delete[i:i + chunk_size]
            predicates = " OR ".join(["(gym_id=? AND account_id=?)"] * len(chunk))
            params: List[Any] = []
            for gym_id, account_id in chunk:
                params.extend([gym_id, account_id])
            cur.execute(f"DELETE FROM sync_gym_access_credentials WHERE {predicates}", params)
        delete_ms = (time.perf_counter() - t_del) * 1000.0

    upsert_ms = 0.0
    if to_upsert:
        t_up = time.perf_counter()
        cur.executemany(
            """
            INSERT INTO sync_gym_access_credentials (
                id, gym_id, account_id, secret_hex, enabled,
                rotated_at, created_at, updated_at,
                granted_active_membership_ids_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(account_id, gym_id) DO UPDATE SET
                id=excluded.id,
                secret_hex=excluded.secret_hex,
                enabled=excluded.enabled,
                rotated_at=excluded.rotated_at,
                created_at=excluded.created_at,
                updated_at=excluded.updated_at,
                granted_active_membership_ids_json=excluded.granted_active_membership_ids_json
            """,
            [_sync_credential_params(row) for row in to_upsert],
        )
        upsert_ms = (time.perf_counter() - t_up) * 1000.0

    return {
        "mode": "merge" if merge_only else "delta",
        "deleted": len(to_delete),
        "upserted": len(to_upsert),
        "normalize_ms": round(normalize_ms, 3),
        "existing_fetch_ms": round(existing_fetch_ms, 3),
        "existing_keys_fetch_ms": round(existing_keys_fetch_ms, 3),
        "diff_ms": round(diff_ms, 3),
        "delete_ms": round(delete_ms, 3),
        "upsert_ms": round(upsert_ms, 3),
        "upsert_all": prefer_upsert_all,
        "lite_diff": lite_diff,
    }


def _upsert_sync_meta_row(
    cur: sqlite3.Cursor,
    *,
    contract_status: bool,
    contract_end_date: str | None,
    updated_at: str,
) -> None:
    cur.execute(
        """
        INSERT INTO sync_meta (id, contract_status, contract_end_date, updated_at)
        VALUES (1, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            contract_status=excluded.contract_status,
            contract_end_date=excluded.contract_end_date,
            updated_at=excluded.updated_at
        """,
        (1 if contract_status else 0, _safe_str(contract_end_date, ""), updated_at),
    )


def _upsert_sync_access_software_settings_row(
    cur: sqlite3.Cursor,
    settings: Dict[str, Any],
    *,
    updated_at: str,
) -> None:
    cur.execute(
        """
        INSERT INTO sync_access_software_settings (
            id, gym_id, access_server_host, access_server_port, access_server_enabled, totp_validation,
            image_cache_enabled, image_cache_timeout_sec, image_cache_max_bytes, image_cache_max_files,
            event_queue_max, notification_queue_max, history_queue_max, popup_queue_max,
            decision_workers, decision_ema_alpha,
            history_retention_days, notification_rate_limit_per_minute, notification_dedupe_window_sec,
            notification_service_enabled, history_service_enabled,
            agent_sync_backend_refresh_min,
            default_authorize_door_id, sdk_read_initial_bytes,
            optional_data_sync_delay_minutes,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            gym_id=excluded.gym_id,
            access_server_host=excluded.access_server_host,
            access_server_port=excluded.access_server_port,
            access_server_enabled=excluded.access_server_enabled,
            totp_validation=excluded.totp_validation,
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
            _to_int_or_none(settings.get("gymId") if "gymId" in settings else settings.get("gym_id")),
            _safe_str(settings.get("accessServerHost") if "accessServerHost" in settings else settings.get("access_server_host"), ""),
            _to_int_or_none(settings.get("accessServerPort") if "accessServerPort" in settings else settings.get("access_server_port")),
            _bool_to_i(settings.get("accessServerEnabled", True), default=1),
            _bool_to_i(settings.get("totpValidation", settings.get("totp_validation", True)), default=1),
            _bool_to_i(settings.get("imageCacheEnabled", True), default=1),
            _to_int_or_none(settings.get("imageCacheTimeoutSec", 2)),
            _to_int_or_none(settings.get("imageCacheMaxBytes", 5242880)),
            _to_int_or_none(settings.get("imageCacheMaxFiles", 1000)),
            _to_int_or_none(settings.get("eventQueueMax", 5000)),
            _to_int_or_none(settings.get("notificationQueueMax", 5000)),
            _to_int_or_none(settings.get("historyQueueMax", 5000)),
            _to_int_or_none(settings.get("popupQueueMax", 5000)),
            _to_int_or_none(settings.get("decisionWorkers", 1)),
            _to_float_or_none(settings.get("decisionEmaAlpha", 0.2)),
            _to_int_or_none(settings.get("historyRetentionDays", 30)),
            _to_int_or_none(settings.get("notificationRateLimitPerMinute", 30)),
            _to_int_or_none(settings.get("notificationDedupeWindowSec", 30)),
            _bool_to_i(settings.get("notificationServiceEnabled", True), default=1),
            _bool_to_i(settings.get("historyServiceEnabled", True), default=1),
            _to_int_or_none(settings.get("agentSyncBackendRefreshMin", 30)),
            _to_int_or_none(settings.get("defaultAuthorizeDoorId", 15)),
            _to_int_or_none(settings.get("sdkReadInitialBytes", 1048576)),
            _to_int_or_none(settings.get("optionalDataSyncDelayMinutes", 60)),
            _safe_str(settings.get("createdAt"), ""),
            _safe_str(settings.get("updatedAt"), updated_at) or updated_at,
        ),
    )


def _upsert_sync_user_row(cur: sqlite3.Cursor, member: Dict[str, Any]) -> None:
    fps = member.get("fingerprints") or []
    if not isinstance(fps, list):
        fps = []

    active_membership_id = member.get("activeMembershipId")
    membership_id = member.get("membershipId")
    if active_membership_id is None or str(active_membership_id).strip() == "":
        active_membership_id = membership_id

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
            image_source, user_image_status, user_profile_image
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            member.get("userId"),
            active_membership_id,
            membership_id,
            member.get("fullName"),
            member.get("phone"),
            member.get("email"),
            member.get("validFrom"),
            member.get("validTo"),
            member.get("firstCardId"),
            member.get("secondCardId"),
            member.get("image"),
            json.dumps(fps, ensure_ascii=False),
            member.get("faceId"),
            member.get("accountUsernameId") or member.get("account_username_id"),
            member.get("qrCodePayload"),
            member.get("birthday"),
            member.get("imageSource"),
            member.get("userImageStatus"),
            member.get("userProfileImage"),
        ),
    )


def _replace_sync_memberships(cur: sqlite3.Cursor, memberships: List[Dict[str, Any]]) -> None:
    cur.execute("DELETE FROM sync_memberships")
    for membership in memberships:
        if not isinstance(membership, dict):
            continue
        cur.execute(
            "INSERT INTO sync_memberships (id, title, description, price, duration_in_days) VALUES (?, ?, ?, ?, ?)",
            (
                membership.get("id"),
                membership.get("title"),
                membership.get("description"),
                membership.get("price"),
                membership.get("durationInDays"),
            ),
        )


def _replace_sync_infrastructures(cur: sqlite3.Cursor, infrastructures: List[Dict[str, Any]]) -> None:
    cur.execute("DELETE FROM sync_infrastructures")
    for infrastructure in infrastructures:
        if not isinstance(infrastructure, dict):
            continue
        cur.execute(
            """
            INSERT INTO sync_infrastructures (id, name, gym_agent_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                infrastructure.get("id"),
                infrastructure.get("name"),
                json.dumps(infrastructure.get("gymAgent") or {}, ensure_ascii=False),
                infrastructure.get("createdAt"),
                infrastructure.get("updatedAt"),
            ),
        )


def _apply_fast_patch_item(cur: sqlite3.Cursor, item: Dict[str, Any]) -> None:
    kind = str(item.get("kind") or "").strip().upper()
    entity_type = str(item.get("entityType") or "").strip().upper()
    payload = item.get("payload") or {}
    revision = str(item.get("revision") or now_iso())

    if kind == "ENTITY_UPSERT" and entity_type == "ACTIVE_MEMBERSHIP":
        member = payload.get("member")
        if not isinstance(member, dict):
            raise ValueError("ACTIVE_MEMBERSHIP upsert requires payload.member")
        _upsert_sync_user_row(cur, member)
        return

    if kind == "ENTITY_DELETE" and entity_type == "ACTIVE_MEMBERSHIP":
        active_membership_id = _to_int_or_none(item.get("entityId"))
        cur.execute("DELETE FROM sync_users WHERE active_membership_id = ?", (active_membership_id,))
        return

    if kind == "ENTITY_UPSERT" and entity_type == "GYM_DEVICE":
        device = payload.get("device")
        if not isinstance(device, dict):
            raise ValueError("GYM_DEVICE upsert requires payload.device")
        device_id = _to_int_or_none(device.get("id") or item.get("entityId"))
        cur.execute("DELETE FROM sync_device_door_presets WHERE device_id = ?", (device_id,))
        cur.execute("DELETE FROM sync_devices WHERE id = ?", (device_id,))
        _insert_device_row(cur, device)
        return

    if kind == "ENTITY_DELETE" and entity_type == "GYM_DEVICE":
        device_id = _to_int_or_none(item.get("entityId"))
        cur.execute("DELETE FROM sync_device_door_presets WHERE device_id = ?", (device_id,))
        cur.execute("DELETE FROM sync_devices WHERE id = ?", (device_id,))
        return

    if kind == "SECTION_REPLACE" and entity_type == "SETTINGS":
        access_settings = payload.get("accessSoftwareSettings") or payload.get("access_software_settings")
        if isinstance(access_settings, dict):
            _upsert_sync_access_software_settings_row(cur, access_settings, updated_at=revision)
        _upsert_sync_meta_row(
            cur,
            contract_status=bool(payload.get("contractStatus", False)),
            contract_end_date=payload.get("contractEndDate"),
            updated_at=revision,
        )
        return

    if kind == "SECTION_REPLACE" and entity_type == "CREDENTIALS":
        rows = payload.get("gymAccessCredentials") or payload.get("gym_access_credentials") or []
        _sync_gym_access_credentials_rows(
            cur,
            rows if isinstance(rows, list) else [],
            merge_mode=payload.get("mergeMode"),
        )
        return

    if kind == "SECTION_REPLACE" and entity_type == "INFRASTRUCTURES":
        rows = payload.get("infrastructures") or payload.get("infrastructure") or []
        _replace_sync_infrastructures(cur, rows if isinstance(rows, list) else [])
        return

    if kind == "SECTION_REPLACE" and entity_type == "MEMBERSHIP_TYPE":
        rows = payload.get("membership") or payload.get("memberships") or []
        _replace_sync_memberships(cur, rows if isinstance(rows, list) else [])
        return

    raise ValueError(f"Unsupported fast patch item: {kind} {entity_type}")


def apply_fast_patch_bundle(bundle: Dict[str, Any]) -> Dict[str, Any]:
    from app.core.fast_patch import patch_key

    bundle_id = str(bundle.get("bundleId") or "").strip() or str(uuid.uuid4())
    generated_at = str(bundle.get("generatedAt") or now_iso())
    items = [item for item in list(bundle.get("items") or []) if isinstance(item, dict)]

    applied = 0
    skipped = 0

    with get_conn() as conn:
        cur = conn.cursor()
        duplicate = cur.execute(
            "SELECT 1 FROM fast_patch_bundles WHERE bundle_id = ?",
            (bundle_id,),
        ).fetchone()
        if duplicate:
            return {"applied": 0, "skipped": 0, "ignored": "duplicate_bundle"}

        cur.execute(
            """
            INSERT INTO fast_patch_bundles (bundle_id, generated_at, applied_at)
            VALUES (?, ?, ?)
            """,
            (bundle_id, generated_at, now_iso()),
        )

        for item in items:
            key = patch_key(item.get("entityType"), item.get("entityId"))
            revision = str(item.get("revision") or generated_at)
            existing = cur.execute(
                "SELECT revision FROM fast_patch_revisions WHERE patch_key = ?",
                (key,),
            ).fetchone()
            if existing and revision <= str(existing["revision"] or ""):
                skipped += 1
                continue

            _apply_fast_patch_item(cur, item)
            cur.execute(
                """
                INSERT INTO fast_patch_revisions (patch_key, revision, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(patch_key) DO UPDATE SET
                    revision=excluded.revision,
                    updated_at=excluded.updated_at
                """,
                (key, revision, now_iso()),
            )
            applied += 1

        conn.commit()

    return {"applied": applied, "skipped": skipped, "ignored": None}


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
    def _write(conn: sqlite3.Connection, profile: Dict[str, Any]) -> Dict[str, Any]:
        cur = conn.cursor()
        profile["members_refresh"] = bool(refresh.get("members", True))
        profile["devices_refresh"] = bool(refresh.get("devices", True))
        profile["credentials_refresh"] = bool(refresh.get("credentials", True))
        profile["settings_refresh"] = bool(refresh.get("settings", True))

        # Contract meta must stay current for every delta, even when the backend
        # only refreshed one section.
        with _profile_write_step(profile, "meta_ms"):
            _upsert_sync_meta_row(
                cur,
                contract_status=contract_status,
                contract_end_date=contract_end_date,
                updated_at=updated_at,
            )

        if refresh.get("settings", True):
            with _profile_write_step(profile, "settings_ms"):
                if isinstance(access_settings, dict):
                    try:
                        _upsert_sync_access_software_settings_row(
                            cur,
                            access_settings,
                            updated_at=updated_at,
                        )
                    except Exception:
                        pass  # never break sync
                _replace_sync_memberships(cur, memberships if isinstance(memberships, list) else [])

        # Conditional: members (users + fingerprints)
        if refresh.get("members", True):
            with _profile_write_step(profile, "members_ms"):
                users = data.get("users") or []
                delta_mode = bool(data.get("membersDeltaMode", False))
                valid_ids = data.get("validMemberIds")
                profile["members_delta_mode"] = delta_mode
                profile["incoming_users"] = len(users) if isinstance(users, list) else 0

                if delta_mode:
                    # Delta mode: upsert changed users + delete ones absent from validMemberIds
                    upserted_count = 0
                    members_upsert_ms = 0.0
                    members_validset_ms = 0.0
                    members_cached_fetch_ms = 0.0
                    members_delete_ms = 0.0
                    deleted_count = 0
                    if users:
                        t_upsert = time.perf_counter()
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
                                    image_source, user_image_status, user_profile_image
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                                    u.get("userProfileImage"),
                                ),
                            )
                            upserted_count += 1
                        members_upsert_ms = (time.perf_counter() - t_upsert) * 1000.0
                    if valid_ids is not None:
                        t_valid = time.perf_counter()
                        valid_set = set(valid_ids)
                        members_validset_ms = (time.perf_counter() - t_valid) * 1000.0
                        t_fetch = time.perf_counter()
                        cached_rows = cur.execute(
                            "SELECT active_membership_id FROM sync_users WHERE active_membership_id IS NOT NULL"
                        ).fetchall()
                        members_cached_fetch_ms = (time.perf_counter() - t_fetch) * 1000.0
                        ids_to_remove = {r[0] for r in cached_rows} - valid_set
                        ids_list = list(ids_to_remove)
                        deleted_count = len(ids_list)
                        t_delete = time.perf_counter()
                        for i in range(0, len(ids_list), 500):
                            chunk = ids_list[i:i + 500]
                            placeholders = ",".join("?" * len(chunk))
                            cur.execute(
                                f"DELETE FROM sync_users WHERE active_membership_id IN ({placeholders})",
                                chunk,
                            )
                        members_delete_ms = (time.perf_counter() - t_delete) * 1000.0
                    profile["members_upserted"] = upserted_count
                    profile["members_deleted"] = deleted_count
                    profile["members_upsert_ms"] = round(members_upsert_ms, 3)
                    profile["members_validset_ms"] = round(members_validset_ms, 3)
                    profile["members_cached_fetch_ms"] = round(members_cached_fetch_ms, 3)
                    profile["members_delete_ms"] = round(members_delete_ms, 3)
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
                            return {"credentials": None}
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
                                f"{u.get('imageSource')}|{u.get('userImageStatus')}|"
                                f"{u.get('userProfileImage', '')}"
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
                            "image_source, user_image_status, user_profile_image FROM sync_users"
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
                                "userProfileImage": r[18],
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
                                    image_source, user_image_status, user_profile_image
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                                    u.get("userProfileImage"),
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
            with _profile_write_step(profile, "devices_ms"):
                cur.execute("DELETE FROM sync_devices")
                cur.execute("DELETE FROM sync_device_door_presets")
                for d in (data.get("devices") or []):
                    _insert_device_row(cur, d)

        creds_summary: Dict[str, Any] | None = None
        # Conditional: credentials
        if refresh.get("credentials", True):
            with _profile_write_step(profile, "credentials_ms"):
                creds_summary = _sync_gym_access_credentials_rows(
                    cur,
                    list(data.get("gymAccessCredentials") or data.get("gym_access_credentials") or []),
                )
            profile["credentials_mode"] = creds_summary.get("mode")
            profile["credentials_upserted"] = creds_summary.get("upserted")
            profile["credentials_deleted"] = creds_summary.get("deleted")
            profile["credentials_normalize_ms"] = creds_summary.get("normalize_ms")
            profile["credentials_existing_fetch_ms"] = creds_summary.get("existing_fetch_ms")
            profile["credentials_existing_keys_fetch_ms"] = creds_summary.get("existing_keys_fetch_ms")
            profile["credentials_diff_ms"] = creds_summary.get("diff_ms")
            profile["credentials_delete_ms"] = creds_summary.get("delete_ms")
            profile["credentials_upsert_ms"] = creds_summary.get("upsert_ms")
            profile["credentials_upsert_all"] = creds_summary.get("upsert_all")
            profile["credentials_lite_diff"] = creds_summary.get("lite_diff")

        # Conditional: settings (infrastructures)
        if refresh.get("settings", True):
            with _profile_write_step(profile, "infrastructures_ms"):
                _replace_sync_infrastructures(
                    cur,
                    (data.get("infrastructures") or data.get("infrastructure") or []),
                )

        return {"credentials": creds_summary}

    result = _run_db_write_sync("save_sync_cache_delta", _write) or {}
    _creds_summary = result.get("credentials")
    if _creds_summary:
        _logger.info(
            "[SYNC-DEBUG] credentials sync: mode=%s upserted=%s deleted=%s",
            _creds_summary.get("mode"),
            _creds_summary.get("upserted"),
            _creds_summary.get("deleted"),
        )
    profile = get_last_db_write_profile("save_sync_cache_delta")
    if profile:
        queue_wait = float(profile.get("queue_wait_ms") or 0.0)
        total = float(profile.get("total_ms") or 0.0)
        # Always log if queue wait is significant — this diagnoses DbWriter backlog
        # even when the actual transaction is fast (total_ms < threshold).
        if queue_wait >= 100.0 or total >= 100.0:
            _logger.info("[SYNC-DEBUG] save_sync_cache_delta profile=%s", profile)


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
        "userProfileImage": g("userProfileImage", "user_profile_image"),
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
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT remote_id, device_id, door_number, pulse_seconds, door_name, created_at, updated_at,
                   favorite_enabled, favorite_order, favorite_shortcut
            FROM sync_device_door_presets
            ORDER BY device_id ASC, door_number ASC, remote_id ASC, id ASC
            """
        ).fetchall()
    return _build_synced_door_presets_index_from_rows([dict(r) for r in rows])


def _build_synced_door_presets_index_from_rows(rows: List[Dict[str, Any]]) -> Dict[int, List[Dict[str, Any]]]:
    idx: Dict[int, List[Dict[str, Any]]] = {}
    for r in rows:
        did = _to_int_or_none(r.get("device_id"))
        if did is None:
            continue
        rid = _to_int_or_none(r.get("remote_id"))
        idx.setdefault(int(did), []).append(
            {
                "id": rid,
                "deviceId": int(did),
                "doorNumber": _to_int_or_none(r.get("door_number")),
                "pulseSeconds": _to_int_or_none(r.get("pulse_seconds")),
                "doorName": _safe_str(r.get("door_name"), ""),
                "createdAt": _safe_str(r.get("created_at"), ""),
                "updatedAt": _safe_str(r.get("updated_at"), ""),
                "favoriteEnabled": bool(r.get("favorite_enabled")),
                "favoriteOrder": r.get("favorite_order"),
                "favoriteShortcut": r.get("favorite_shortcut"),
            }
        )
    return idx


def list_sync_device_door_presets_payload(device_id: int) -> List[Dict[str, Any]]:
    try:
        did = int(device_id)
    except Exception:
        return []

    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT remote_id, device_id, door_number, pulse_seconds, door_name, created_at, updated_at,
                   favorite_enabled, favorite_order, favorite_shortcut
            FROM sync_device_door_presets
            WHERE device_id = ?
            ORDER BY door_number ASC, remote_id ASC, id ASC
            """,
            (did,),
        ).fetchall()

    payload: List[Dict[str, Any]] = []
    for r in rows:
        payload.append(
            {
                "id": _to_int_or_none(r["remote_id"]),  # type: ignore[index]
                "deviceId": _to_int_or_none(r["device_id"]) or did,  # type: ignore[index]
                "doorNumber": _to_int_or_none(r["door_number"]) or 1,  # type: ignore[index]
                "pulseSeconds": _to_int_or_none(r["pulse_seconds"]) or 3,  # type: ignore[index]
                "doorName": _safe_str(r["door_name"], ""),  # type: ignore[index]
                "createdAt": _safe_str(r["created_at"], ""),  # type: ignore[index]
                "updatedAt": _safe_str(r["updated_at"], ""),  # type: ignore[index]
                "favoriteEnabled": bool(r["favorite_enabled"]),  # type: ignore[index]
                "favoriteOrder": r["favorite_order"],  # type: ignore[index]
                "favoriteShortcut": r["favorite_shortcut"],  # type: ignore[index]
            }
        )
    return payload


def list_favorite_presets(include_all: bool = False) -> List[Dict[str, Any]]:
    """Returns door presets for the favorites overlay.

    By default only presets with favorite_enabled=1 are returned, sorted by
    favorite_order. When include_all=True the filter is dropped and every
    synced preset is returned, ordered so marked favorites come first (then
    by device, door number)."""
    query = """
        SELECT p.*, d.name as device_name, d.ip_address, d.id as device_id_val
        FROM sync_device_door_presets p
        JOIN sync_devices d ON d.id = p.device_id
    """
    if include_all:
        query += """
        ORDER BY
            p.favorite_enabled DESC,
            p.favorite_order ASC NULLS LAST,
            d.id ASC,
            p.door_number ASC
        """
    else:
        query += """
        WHERE p.favorite_enabled = 1
        ORDER BY p.favorite_order ASC NULLS LAST
        """
    with get_conn() as conn:
        rows = conn.execute(query).fetchall()
        result: List[Dict[str, Any]] = []
        for r in rows:
            row = dict(r)
            result.append({
                "id": row.get("remote_id") or row.get("id"),
                "deviceId": row.get("device_id"),
                "deviceName": row.get("device_name", ""),
                "doorNumber": row.get("door_number"),
                "pulseSeconds": row.get("pulse_seconds"),
                "doorName": row.get("door_name", ""),
                "favoriteEnabled": bool(row.get("favorite_enabled")),
                "favoriteOrder": row.get("favorite_order"),
                "favoriteShortcut": row.get("favorite_shortcut"),
            })
        return result


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

        "antiFraudeCard":             _boolish(g("anti_fraude_card",    default=1), True),
        "antiFraudeQrCode":           _boolish(g("anti_fraude_qr_code", default=1), True),
        "antiFraudeDuration":         _to_int_or_none(g("anti_fraude_duration", default=30)) or 30,
        "antiFraudeDailyPassLimit":   int(g("anti_fraude_daily_pass_limit", default=0) or 0),

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


def _coerce_sync_access_software_settings_row_to_payload(
    row: Dict[str, Any] | sqlite3.Row | None,
) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    d = dict(row)
    return {
        "gymId": d.get("gym_id"),
        "accessServerHost": d.get("access_server_host"),
        "accessServerPort": d.get("access_server_port"),
        "accessServerEnabled": bool(int(d.get("access_server_enabled") or 0)),
        "totpValidation": True if d.get("totp_validation") is None else bool(int(d.get("totp_validation") or 0)),
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
                totp_validation,
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
    return _coerce_sync_access_software_settings_row_to_payload(r)


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


def _finish_sync_cache_load(
    *,
    evt: threading.Event,
    result: "SyncCacheState | None" = None,
    success: bool,
) -> None:
    global _sync_cache_entry, _sync_cache_loading
    with _sync_cache_lock:
        if success:
            _sync_cache_entry = (time.monotonic() + _SYNC_CACHE_TTL, result)
        if _sync_cache_loading is evt:
            _sync_cache_loading = None
    evt.set()


def _load_sync_cache_background(evt: threading.Event) -> None:
    try:
        result = _load_sync_cache_db()
    except Exception:
        _finish_sync_cache_load(evt=evt, success=False)
        return
    _finish_sync_cache_load(evt=evt, result=result, success=True)


def refresh_sync_cache_async() -> bool:
    """Start a background refresh of the sync cache if one is not already running."""
    global _sync_cache_loading
    with _sync_cache_lock:
        if _sync_cache_loading is not None:
            return False
        evt = threading.Event()
        _sync_cache_loading = evt
    threading.Thread(
        target=_load_sync_cache_background,
        args=(evt,),
        name="SyncCacheRefresh",
        daemon=True,
    ).start()
    return True


def invalidate_sync_cache(*, clear_cached: bool = False) -> None:
    """Expire the sync cache; optionally drop the stale snapshot entirely."""
    global _sync_cache_entry
    with _sync_cache_lock:
        _, cached = _sync_cache_entry
        _sync_cache_entry = (0.0, None if clear_cached else cached)


def load_sync_cache() -> "SyncCacheState | None":
    global _sync_cache_entry, _sync_cache_loading
    now = time.monotonic()
    cached_snapshot: "SyncCacheState | None" = None
    load_inline = False
    start_background = False
    evt: threading.Event | None = None

    with _sync_cache_lock:
        expires, cached = _sync_cache_entry
        if now < expires and cached is not None:
            return cached
        cached_snapshot = cached

        if _sync_cache_loading is not None:
            evt = _sync_cache_loading
        elif cached_snapshot is not None:
            evt = threading.Event()
            _sync_cache_loading = evt
            start_background = True
        else:
            evt = threading.Event()
            _sync_cache_loading = evt
            load_inline = True

    if start_background and evt is not None:
        threading.Thread(
            target=_load_sync_cache_background,
            args=(evt,),
            name="SyncCacheRefresh",
            daemon=True,
        ).start()
        return cached_snapshot

    if not load_inline:
        if cached_snapshot is not None:
            return cached_snapshot
        assert evt is not None
        evt.wait(timeout=10.0)
        with _sync_cache_lock:
            _, cached = _sync_cache_entry
        return cached

    assert evt is not None
    try:
        result = _load_sync_cache_db()
        _finish_sync_cache_load(evt=evt, result=result, success=True)
        return result
    except Exception:
        _finish_sync_cache_load(evt=evt, success=False)
        raise


def peek_sync_cache() -> "SyncCacheState | None":
    """Return the current in-memory sync cache snapshot without triggering a refresh."""
    with _sync_cache_lock:
        _, cached = _sync_cache_entry
        return cached


def _fetch_sync_cache_snapshot() -> Dict[str, Any] | None:
    with get_conn() as conn:
        meta = conn.execute("SELECT contract_status, contract_end_date, updated_at FROM sync_meta WHERE id=1").fetchone()
        if not meta:
            raw = conn.execute("SELECT updated_at, payload_json FROM sync_cache WHERE id=1").fetchone()
            if not raw:
                return None
            return {
                "legacy_payload": {
                    "updated_at": raw["updated_at"],
                    "payload_json": raw["payload_json"],
                }
            }

        settings_row = conn.execute(
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
        users_rows = [dict(r) for r in conn.execute("SELECT * FROM sync_users").fetchall()]
        membership_rows = [dict(r) for r in conn.execute("SELECT * FROM sync_memberships").fetchall()]
        devices_rows = [dict(r) for r in conn.execute("SELECT * FROM sync_devices").fetchall()]
        preset_rows = [
            dict(r)
            for r in conn.execute(
                """
                SELECT remote_id, device_id, door_number, pulse_seconds, door_name, created_at, updated_at,
                       favorite_enabled, favorite_order, favorite_shortcut
                FROM sync_device_door_presets
                ORDER BY device_id ASC, door_number ASC, remote_id ASC, id ASC
                """
            ).fetchall()
        ]
        infrastructures_rows = [dict(r) for r in conn.execute("SELECT * FROM sync_infrastructures").fetchall()]
        credential_rows = [dict(r) for r in conn.execute("SELECT * FROM sync_gym_access_credentials").fetchall()]

    return {
        "meta_row": dict(meta),
        "settings_row": dict(settings_row) if settings_row else None,
        "users_rows": users_rows,
        "membership_rows": membership_rows,
        "devices_rows": devices_rows,
        "preset_rows": preset_rows,
        "infrastructures_rows": infrastructures_rows,
        "credential_rows": credential_rows,
    }


def _build_sync_cache_state_from_snapshot(snapshot: Dict[str, Any] | None) -> "SyncCacheState | None":
    if not snapshot:
        return None

    legacy_payload = snapshot.get("legacy_payload")
    if legacy_payload is not None:
        try:
            data = json.loads(legacy_payload.get("payload_json") or "{}")
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
            updated_at=(legacy_payload.get("updated_at") or ""),
        )

    meta = snapshot.get("meta_row") or {}
    access_settings = _coerce_sync_access_software_settings_row_to_payload(snapshot.get("settings_row"))

    users_rows = list(snapshot.get("users_rows") or [])
    users = [_coerce_user_row_to_payload(u) for u in users_rows]
    try:
        users.extend(list_projected_offline_users(base_users=users))
    except Exception:
        pass

    membership = list(snapshot.get("membership_rows") or [])

    devices_rows = [_expand_device_json_fields(d) for d in list(snapshot.get("devices_rows") or [])]
    presets_idx = _build_synced_door_presets_index_from_rows(list(snapshot.get("preset_rows") or []))
    for d in devices_rows:
        try:
            did = _to_int_or_none(d.get("id"))
            d["door_presets"] = presets_idx.get(int(did), []) if did is not None else []
        except Exception:
            d["door_presets"] = []

    infrastructures = list(snapshot.get("infrastructures_rows") or [])
    for inf in infrastructures:
        try:
            inf["gym_agent"] = json.loads(inf.get("gym_agent_json") or "{}")
        except Exception:
            inf["gym_agent"] = {}

    creds_rows = [_expand_gym_access_credential_json_fields(c) for c in list(snapshot.get("credential_rows") or [])]
    creds_payload = [_coerce_gym_access_credential_row_to_payload(c) for c in creds_rows]

    return SyncCacheState(
        contract_status=bool(int(meta.get("contract_status") or 0)),
        contract_end_date=meta.get("contract_end_date") or "",
        access_software_settings=access_settings,
        users=users,
        membership=membership,
        devices=devices_rows,
        infrastructures=infrastructures,
        gym_access_credentials=creds_payload,
        updated_at=meta.get("updated_at") or "",
    )


def _load_sync_cache_db() -> "SyncCacheState | None":
    snapshot = _fetch_sync_cache_snapshot()
    return _build_sync_cache_state_from_snapshot(snapshot)


def load_sync_contract_meta() -> Dict[str, Any] | None:
    """Direct query for contract snapshot metadata without loading the full sync cache."""
    with get_conn() as conn:
        meta = conn.execute(
            "SELECT contract_status, contract_end_date, updated_at FROM sync_meta WHERE id=1"
        ).fetchone()
        if meta:
            return {
                "contractStatus": bool(int(meta["contract_status"] or 0)),
                "contractEndDate": meta["contract_end_date"],
                "updatedAt": meta["updated_at"],
            }

        raw = conn.execute("SELECT updated_at, payload_json FROM sync_cache WHERE id=1").fetchone()

    if not raw:
        return None

    try:
        data = json.loads(raw["payload_json"] or "{}")
    except Exception:
        return None

    return {
        "contractStatus": bool(data.get("contractStatus", False)),
        "contractEndDate": data.get("contractEndDate"),
        "updatedAt": raw["updated_at"],
    }


def _count_rows(table_name: str) -> int:
    with get_conn() as conn:
        row = conn.execute(f"SELECT COUNT(*) AS count FROM {table_name}").fetchone()
    try:
        return int(row["count"] if row is not None else 0)  # type: ignore[index]
    except Exception:
        return 0


def count_sync_users() -> int:
    return _count_rows("sync_users")


def count_sync_memberships() -> int:
    return _count_rows("sync_memberships")


def count_sync_devices() -> int:
    return _count_rows("sync_devices")


def count_sync_infrastructures() -> int:
    return _count_rows("sync_infrastructures")


def count_sync_gym_access_credentials() -> int:
    return _count_rows("sync_gym_access_credentials")


def summarize_access_mode_counts(devices: Iterable[Dict[str, Any]] | None) -> Dict[str, int]:
    summary = {"DEVICE": 0, "AGENT": 0, "ULTRA": 0, "UNKNOWN": 0}
    for device in devices or []:
        if not isinstance(device, dict):
            continue
        raw_mode = device.get("accessDataMode")
        if raw_mode in (None, ""):
            raw_mode = device.get("access_data_mode")
        normalized_mode = _safe_str(raw_mode, "").strip().upper()
        if normalized_mode not in ("DEVICE", "AGENT", "ULTRA"):
            normalized_mode = "UNKNOWN"
        summary[normalized_mode] += 1
    return summary


def load_sync_device_mode_summary() -> Dict[str, int]:
    summary = {"DEVICE": 0, "AGENT": 0, "ULTRA": 0, "UNKNOWN": 0}
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT UPPER(TRIM(COALESCE(access_data_mode, ''))) AS mode, COUNT(*) AS count
            FROM sync_devices
            GROUP BY UPPER(TRIM(COALESCE(access_data_mode, '')))
            """
        ).fetchall()
    for row in rows:
        raw_mode = _safe_str(row["mode"] if row is not None else "", "").upper()  # type: ignore[index]
        count = _to_int_or_none(row["count"] if row is not None else 0) or 0  # type: ignore[index]
        normalized_mode = raw_mode if raw_mode in ("DEVICE", "AGENT", "ULTRA") else "UNKNOWN"
        summary[normalized_mode] += int(count)
    return summary


def list_sync_users_page(*, limit: int = 0, offset: int = 0) -> tuple[List[Dict[str, Any]], int]:
    """Paged direct query for UI endpoints that should not hydrate the full sync cache."""
    normalized_limit = max(0, int(limit or 0))
    normalized_offset = max(0, int(offset or 0))
    with get_conn() as conn:
        total = int(conn.execute("SELECT COUNT(*) FROM sync_users").fetchone()[0] or 0)
        sql = "SELECT * FROM sync_users ORDER BY COALESCE(active_membership_id, membership_id, user_id)"
        params: List[Any] = []
        if normalized_limit > 0:
            sql += " LIMIT ? OFFSET ?"
            params.extend([normalized_limit, normalized_offset])
        elif normalized_offset > 0:
            sql += " LIMIT -1 OFFSET ?"
            params.append(normalized_offset)
        rows = [dict(r) for r in conn.execute(sql, tuple(params)).fetchall()]

    users = [_coerce_user_row_to_payload(r) for r in rows]
    include_projected_offline = normalized_offset == 0 and (normalized_limit <= 0 or normalized_limit >= total)
    if include_projected_offline:
        try:
            projected = list_projected_offline_users(base_users=users)
            users.extend(projected)
            total += len(projected)
        except Exception:
            pass
    return users, total


def list_sync_users() -> List[Dict[str, Any]]:
    """Direct query — avoids loading memberships/devices/infra via load_sync_cache() hot path."""
    users, _total = list_sync_users_page(limit=0, offset=0)
    return users


def list_sync_users_by_active_membership_ids(
    active_membership_ids: List[int] | set[int] | tuple[int, ...],
) -> List[Dict[str, Any]]:
    normalized = sorted({
        int(member_id)
        for member_id in (active_membership_ids or [])
        if member_id is not None
    })
    if not normalized:
        return []
    placeholders = ",".join("?" for _ in normalized)
    with get_conn() as conn:
        rows = [
            dict(r)
            for r in conn.execute(
                f"SELECT * FROM sync_users WHERE active_membership_id IN ({placeholders})",
                tuple(normalized),
            ).fetchall()
        ]
    return [_coerce_user_row_to_payload(r) for r in rows]


def list_sync_memberships() -> List[Dict[str, Any]]:
    with get_conn() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM sync_memberships").fetchall()]


def list_sync_devices(*, include_door_presets: bool = True) -> List[Dict[str, Any]]:
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM sync_devices").fetchall()]

    out: List[Dict[str, Any]] = []
    presets_idx = _load_synced_door_presets_index() if include_door_presets else {}

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


def list_sync_devices_payload_from_cache(
    cache: "SyncCacheState | None",
    *,
    include_door_presets: bool = True,
) -> List[Dict[str, Any]]:
    payload: List[Dict[str, Any]] = []
    devices = list(getattr(cache, "devices", []) or []) if cache is not None else []
    for device in devices:
        if not isinstance(device, dict):
            continue
        row = dict(device)
        if not include_door_presets:
            row["door_presets"] = []
            row["doorPresets"] = []
        payload.append(_coerce_device_row_to_payload(row))
    return payload


def list_sync_device_door_presets_payload_from_cache(
    device_id: int,
    cache: "SyncCacheState | None",
) -> List[Dict[str, Any]] | None:
    try:
        did = int(device_id)
    except Exception:
        return None

    devices = list(getattr(cache, "devices", []) or []) if cache is not None else []
    for device in devices:
        if not isinstance(device, dict):
            continue
        if _to_int_or_none(device.get("id")) != did:
            continue
        raw_presets = device.get("door_presets")
        if raw_presets is None:
            raw_presets = device.get("doorPresets")
        payload: List[Dict[str, Any]] = []
        for preset in list(raw_presets or []):
            if not isinstance(preset, dict):
                continue
            payload.append(
                {
                    "id": _to_int_or_none(preset.get("id")),
                    "deviceId": _to_int_or_none(preset.get("deviceId")) or did,
                    "doorNumber": _to_int_or_none(preset.get("doorNumber")) or 1,
                    "pulseSeconds": _to_int_or_none(preset.get("pulseSeconds")) or 3,
                    "doorName": _safe_str(preset.get("doorName"), ""),
                    "createdAt": _safe_str(preset.get("createdAt"), ""),
                    "updatedAt": _safe_str(preset.get("updatedAt"), ""),
                    "favoriteEnabled": bool(preset.get("favoriteEnabled")),
                    "favoriteOrder": preset.get("favoriteOrder"),
                    "favoriteShortcut": preset.get("favoriteShortcut"),
                }
            )
        return payload
    return None


def list_sync_devices_payload(*, include_door_presets: bool = True) -> List[Dict[str, Any]]:
    rows = list_sync_devices(include_door_presets=include_door_presets)
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


def save_device_sync_state_batch(
    *,
    device_id: int,
    rows: "Iterable[tuple[str, str | None, bool, str | None]]",
) -> int:
    """
    Batch-upsert multiple (pin, desired_hash, ok, error) rows for a single device
    in ONE DbWriter transaction instead of one transaction per pin.

    Calling ``save_device_sync_state`` N times for N pins = N DbWriter round-trips
    (~2 ms each × 1277 pins = ~2.5 s per device). This function collapses them to
    a single round-trip, preventing the DbWriter queue from backing up when the
    next sync cycle tries to write ``save_sync_cache_delta``.

    Returns the number of rows processed.
    """
    did = int(device_id)
    updated_at = now_iso()

    params_list: list[tuple] = []
    for pin, desired_hash, ok, error in (rows or []):
        p = str(pin or "").strip()
        if not p:
            continue
        params_list.append((
            did,
            p,
            str(desired_hash or "").strip() if desired_hash else "",
            1 if bool(ok) else 0,
            (str(error or "")[:1000]) if error else None,
            updated_at,
        ))

    if not params_list:
        return 0

    def _write(conn: sqlite3.Connection, profile: Dict[str, Any]) -> int:
        conn.executemany(
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
            params_list,
        )
        profile["rows"] = len(params_list)
        return len(params_list)

    return int(_run_db_write_sync("save_device_sync_state_batch", _write))


def save_device_sync_state(*, device_id: int, pin: str, desired_hash: str | None, ok: bool, error: str | None) -> None:
    did = int(device_id)
    p = str(pin or "").strip()
    if not p:
        return

    err = (str(error or "")[:1000]) if error else None
    ok_i = 1 if bool(ok) else 0
    dh = str(desired_hash or "").strip() if desired_hash else ""

    def _write(conn: sqlite3.Connection, profile: Dict[str, Any]) -> None:
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

    _run_db_write_sync("save_device_sync_state", _write)


def delete_device_sync_state(*, device_id: int, pin: str) -> None:
    did = int(device_id)
    p = str(pin or "").strip()
    if not p:
        return
    def _write(conn: sqlite3.Connection, profile: Dict[str, Any]) -> None:
        conn.execute("DELETE FROM device_sync_state WHERE device_id=? AND pin=?", (did, p))

    _run_db_write_sync("delete_device_sync_state", _write)


def prune_device_sync_state(*, device_id: int, keep_pins: Iterable[str]) -> int:
    did = int(device_id)
    keep = {str(x).strip() for x in (keep_pins or []) if str(x).strip()}
    existing = set(list_device_sync_pins(device_id=did))
    to_remove = sorted([p for p in existing if p not in keep])
    if not to_remove:
        return 0

    def _write(conn: sqlite3.Connection, profile: Dict[str, Any]) -> int:
        deleted = 0
        CHUNK = 300
        for i in range(0, len(to_remove), CHUNK):
            chunk = to_remove[i : i + CHUNK]
            q = ",".join(["?"] * len(chunk))
            cur = conn.execute(
                f"DELETE FROM device_sync_state WHERE device_id=? AND pin IN ({q})",
                (did, *chunk),
            )
            deleted += int(cur.rowcount or 0)
        return deleted

    return int(_run_db_write_sync("prune_device_sync_state", _write))


# -----------------------------
def clear_device_sync_hashes(*, device_id: int) -> int:
    """F-015: Clear all sync hashes for a device to force full re-sync on next cycle."""
    did = int(device_id)
    def _write(conn: sqlite3.Connection, profile: Dict[str, Any]) -> int:
        cursor = conn.execute("DELETE FROM device_sync_state WHERE device_id=?", (did,))
        return int(cursor.rowcount or 0)

    return int(_run_db_write_sync("clear_device_sync_hashes", _write))


def clear_all_device_sync_hashes() -> int:
    """Hard-reset: clear sync hashes for ALL devices so next sync re-pushes every user."""
    def _write(conn: sqlite3.Connection, profile: Dict[str, Any]) -> int:
        cursor = conn.execute("DELETE FROM device_sync_state")
        return int(cursor.rowcount or 0)

    return int(_run_db_write_sync("clear_all_device_sync_hashes", _write))


# -----------------------------
# Sync observability
# -----------------------------

def _normalize_page_size(*, page: int, size: int, max_size: int = 200) -> tuple[int, int]:
    page_num = max(int(page), 0)
    page_size = max(int(size), 1)
    if page_size > max_size:
        page_size = max_size
    return page_num, page_size


def insert_sync_run(
    *,
    run_type: str,
    trigger_source: str,
    trigger_hint: str | None = None,
    status: str = "IN_PROGRESS",
    created_at: str,
) -> int:
    def _write(conn: sqlite3.Connection, profile: Dict[str, Any]) -> int:
        cur = conn.execute(
            """
            INSERT INTO sync_run_history (
                run_type, trigger_source, trigger_hint, status, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(run_type).strip().upper(),
                str(trigger_source).strip().upper(),
                trigger_hint,
                str(status).strip().upper(),
                created_at,
            ),
        )
        return int(cur.lastrowid)

    return int(_run_db_write_sync("insert_sync_run", _write))


def update_sync_run(
    *,
    id: int,
    status: str,
    members_total: int = 0,
    members_changed: int = 0,
    devices_synced: int = 0,
    duration_ms: int = 0,
    error_message: str | None = None,
    raw_response: str | None = None,
) -> None:
    def _write(conn: sqlite3.Connection, profile: Dict[str, Any]) -> None:
        conn.execute(
            """
            UPDATE sync_run_history
               SET status = ?,
                   members_total = ?,
                   members_changed = ?,
                   devices_synced = ?,
                   duration_ms = ?,
                   error_message = ?,
                   raw_response = ?
             WHERE id = ?
            """,
            (
                str(status).strip().upper(),
                int(members_total or 0),
                int(members_changed or 0),
                int(devices_synced or 0),
                int(duration_ms or 0),
                error_message,
                raw_response,
                int(id),
            ),
        )

    _run_db_write_sync("update_sync_run", _write)


def get_sync_run(id: int) -> Dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM sync_run_history WHERE id = ?", (int(id),)).fetchone()
    return dict(row) if row else None


def list_sync_runs(
    *,
    page: int,
    size: int,
    run_type: str | None = None,
    status: str | None = None,
) -> Dict[str, Any]:
    page_num, page_size = _normalize_page_size(page=page, size=size)
    clauses: List[str] = []
    params: List[Any] = []
    if run_type:
        clauses.append("run_type = ?")
        params.append(str(run_type).strip().upper())
    if status:
        clauses.append("status = ?")
        params.append(str(status).strip().upper())
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with get_conn() as conn:
        total = int(
            conn.execute(
                f"SELECT COUNT(*) FROM sync_run_history {where_sql}",
                params,
            ).fetchone()[0]
        )
        rows = conn.execute(
            f"""
            SELECT
                id,
                run_type,
                trigger_source,
                trigger_hint,
                status,
                members_total,
                members_changed,
                devices_synced,
                duration_ms,
                error_message,
                created_at
            FROM sync_run_history
            {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            [*params, page_size, page_num * page_size],
        ).fetchall()
    return {
        "items": [dict(row) for row in rows],
        "total": total,
        "page": page_num,
        "size": page_size,
    }


def insert_push_batch(
    *,
    sync_run_id: int | None,
    device_id: int,
    device_name: str,
    policy: str,
    status: str = "IN_PROGRESS",
    created_at: str,
) -> int:
    def _write(conn: sqlite3.Connection, profile: Dict[str, Any]) -> int:
        cur = conn.execute(
            """
            INSERT INTO push_batch_history (
                sync_run_id,
                device_id,
                device_name,
                policy,
                status,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                int(sync_run_id) if sync_run_id is not None else None,
                int(device_id),
                str(device_name or ""),
                str(policy).strip().upper(),
                str(status).strip().upper(),
                created_at,
            ),
        )
        return int(cur.lastrowid)

    return int(_run_db_write_sync("insert_push_batch", _write))


def update_push_batch(
    *,
    id: int,
    pins_attempted: int,
    pins_success: int,
    pins_failed: int,
    status: str,
    duration_ms: int,
    error_message: str | None = None,
) -> None:
    def _write(conn: sqlite3.Connection, profile: Dict[str, Any]) -> None:
        conn.execute(
            """
            UPDATE push_batch_history
               SET pins_attempted = ?,
                   pins_success = ?,
                   pins_failed = ?,
                   status = ?,
                   duration_ms = ?,
                   error_message = ?
             WHERE id = ?
            """,
            (
                int(pins_attempted or 0),
                int(pins_success or 0),
                int(pins_failed or 0),
                str(status).strip().upper(),
                int(duration_ms or 0),
                error_message,
                int(id),
            ),
        )

    _run_db_write_sync("update_push_batch", _write)


def insert_push_pin(
    *,
    batch_id: int,
    pin: str,
    full_name: str | None,
    operation: str,
    status: str,
    error_message: str | None = None,
    duration_ms: int = 0,
) -> int:
    def _write(conn: sqlite3.Connection, profile: Dict[str, Any]) -> int:
        cur = conn.execute(
            """
            INSERT INTO push_pin_history (
                batch_id,
                pin,
                full_name,
                operation,
                status,
                error_message,
                duration_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(batch_id),
                str(pin),
                full_name,
                str(operation).strip().upper(),
                str(status).strip().upper(),
                error_message,
                int(duration_ms or 0),
            ),
        )
        return int(cur.lastrowid)

    return int(_run_db_write_sync("insert_push_pin", _write))


def insert_push_pin_batch(
    *,
    batch_id: int,
    rows: "Iterable[tuple[str, str | None, str, str, str | None, int]]",
) -> int:
    """
    Batch-insert multiple push_pin_history rows in ONE DbWriter transaction.

    Each row is a tuple of (pin, full_name, operation, status, error_message, duration_ms).
    Replaces calling ``insert_push_pin`` N times, which would be N DbWriter round-trips.
    Returns the number of rows inserted.
    """
    params_list: list[tuple] = []
    bid = int(batch_id)
    for pin, full_name, operation, status, error_message, duration_ms in (rows or []):
        params_list.append((
            bid,
            str(pin),
            full_name,
            str(operation).strip().upper(),
            str(status).strip().upper(),
            error_message,
            int(duration_ms or 0),
        ))

    if not params_list:
        return 0

    def _write(conn: sqlite3.Connection, profile: Dict[str, Any]) -> int:
        conn.executemany(
            """
            INSERT INTO push_pin_history (
                batch_id, pin, full_name, operation, status, error_message, duration_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            params_list,
        )
        profile["rows"] = len(params_list)
        return len(params_list)

    return int(_run_db_write_sync("insert_push_pin_batch", _write))


def get_push_batch(batch_id: int) -> Dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM push_batch_history WHERE id = ?",
            (int(batch_id),),
        ).fetchone()
    return dict(row) if row else None


def get_push_batch_pins(batch_id: int) -> List[Dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, batch_id, pin, full_name, operation, status, error_message, duration_ms
            FROM push_pin_history
            WHERE batch_id = ?
            ORDER BY id ASC
            """,
            (int(batch_id),),
        ).fetchall()
    return [dict(row) for row in rows]


def list_push_batches(
    *,
    page: int,
    size: int,
    device_id: int | None = None,
    status: str | None = None,
) -> Dict[str, Any]:
    page_num, page_size = _normalize_page_size(page=page, size=size)
    clauses: List[str] = []
    params: List[Any] = []
    if device_id is not None:
        clauses.append("device_id = ?")
        params.append(int(device_id))
    if status:
        clauses.append("status = ?")
        params.append(str(status).strip().upper())
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with get_conn() as conn:
        total = int(
            conn.execute(
                f"SELECT COUNT(*) FROM push_batch_history {where_sql}",
                params,
            ).fetchone()[0]
        )
        rows = conn.execute(
            f"""
            SELECT
                id,
                sync_run_id,
                device_id,
                device_name,
                policy,
                pins_attempted,
                pins_success,
                pins_failed,
                status,
                duration_ms,
                error_message,
                created_at
            FROM push_batch_history
            {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            [*params, page_size, page_num * page_size],
        ).fetchall()
    return {
        "items": [dict(row) for row in rows],
        "total": total,
        "page": page_num,
        "size": page_size,
    }


def prune_sync_run_history(*, retention_days: int = 30) -> int:
    days = max(int(retention_days), 1)
    with get_conn() as conn:
        cur = conn.execute(
            """
            DELETE FROM sync_run_history
            WHERE julianday('now') - julianday(created_at) > ?
            """,
            (days,),
        )
        conn.commit()
        return int(cur.rowcount or 0)


def prune_push_batch_history(*, retention_days: int = 30) -> int:
    days = max(int(retention_days), 1)
    with get_conn() as conn:
        cur = conn.execute(
            """
            DELETE FROM push_batch_history
            WHERE julianday('now') - julianday(created_at) > ?
            """,
            (days,),
        )
        conn.commit()
        return int(cur.rowcount or 0)


def cleanup_stale_in_progress_sync_runs() -> int:
    """Mark any IN_PROGRESS sync runs left over from a previous session as INTERRUPTED.

    Called once at application startup to prevent phantom IN_PROGRESS rows appearing
    in the historique page after a crash or force-quit.
    """
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE sync_run_history
               SET status        = 'INTERRUPTED',
                   error_message = 'Application restarted while sync was in progress'
             WHERE status = 'IN_PROGRESS'
            """
        )
        conn.commit()
        return int(cur.rowcount or 0)


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
    user_id: int | None = None,
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
        int(user_id) if user_id is not None else None,
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
    user_id: int | None = None,
) -> int:
    """
    Insert an access history row using INSERT OR IGNORE (UNIQUE on event_id).
    Returns rowcount: 1 if inserted (first worker to claim), 0 if already exists.
    F-013: callers should only open_door if return value is 1.

    user_id is optional — resolved by DecisionService after verify_card/verify_totp
    when available. It powers the anti-fraud daily-pass-limit counter
    (count_today_for_user_door). Rows inserted before this feature shipped have
    NULL user_id; the counter query filters WHERE user_id IS NOT NULL so those
    rows never participate.
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
                    backend_sync_state,
                    user_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    user_id=user_id,
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
                user_id=row.get("user_id", row.get("userId")),
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
                backend_sync_state,
                user_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            batch,
        )
        conn.commit()
        return int(cur.rowcount or 0)


def count_today_for_user_door(
    *, user_id: int, device_id: int, door_id: int
) -> int:
    """
    Number of successful (allowed=1) access_history rows for this user on
    this device's given door since local midnight (today in local timezone).

    Powers the anti-fraud daily-pass-limit alert in DecisionService.
    Filters WHERE user_id IS NOT NULL implicitly — passing None short-circuits
    SQLite's NULL-comparison rule and returns 0, so pre-feature rows never
    participate. Uses ix_access_history_user_door_day composite index.
    """
    if user_id is None:
        return 0
    sql = """
        SELECT COUNT(*) FROM access_history
        WHERE user_id = ?
          AND device_id = ?
          AND door_id = ?
          AND allowed = 1
          AND date(created_at, 'localtime') = date('now', 'localtime')
    """
    with get_conn() as conn:
        row = conn.execute(sql, (int(user_id), int(device_id), int(door_id))).fetchone()
    return int(row[0]) if row else 0


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
                "userProfileImage": user_src.get("userProfileImage", ""),
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
            "userProfileImage": "",
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

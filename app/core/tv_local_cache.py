
"""TV local cache module with F23 ad-injection wrappers.

This file bootstraps the previously compiled implementation from
``__pycache__/tv_local_cache.cpython-313.pyc`` and then layers
Functionality 23 runtime coordination logic on top.
"""

from __future__ import annotations

import hashlib
import json
import marshal
import os
import pathlib
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple
from app.core.db import get_conn


def _load_compiled_baseline() -> None:
    pyc_path = pathlib.Path(__file__).resolve().parent / "__pycache__" / "tv_local_cache.cpython-313.pyc"
    if not pyc_path.exists():
        raise RuntimeError(f"Missing compiled baseline module: {pyc_path}")
    with pyc_path.open("rb") as fh:
        fh.read(16)
        code = marshal.load(fh)
    exec(code, globals(), globals())


_load_compiled_baseline()


_BASE_ENSURE_TV_LOCAL_SCHEMA = ensure_tv_local_schema
_BASE_GET_TV_PLAYER_RENDER_CONTEXT = get_tv_player_render_context
_BASE_LOAD_TV_PLAYER_STATUS = load_tv_player_status
_BASE_REPORT_TV_PLAYER_STATE = report_tv_player_state
_BASE_LIST_TV_AD_TASK_CACHE = list_tv_ad_task_cache
_BASE_LIST_TV_SCREEN_BINDINGS = list_tv_screen_bindings
_BASE_GET_TV_SCREEN_BINDING = get_tv_screen_binding
_BASE_LOAD_TV_SCREEN_BINDING_BY_ID = load_tv_screen_binding_by_id
_BASE_LOAD_TV_BINDING_SUPPORT_SUMMARY = load_tv_binding_support_summary


_F23_DUE_GRACE_SECONDS = 30
_F23_REMOTE_TERMINAL = {"CANCELLED", "EXPIRED", "DONE", "FAILED"}
_F23_TASK_READY_LOCAL = {"READY_LOCAL", "READY_CONFIRM_PENDING", "READY_CONFIRMED"}
_F23_COORD_IDLE = "IDLE"
_F23_COORD_INJECTING = "INJECTING"
_F23_COORD_DISPLAYING = "DISPLAYING"
_F23_COORD_COMPLETING = "COMPLETING"
_F23_COORD_COMPLETED = "COMPLETED"
_F23_COORD_ABORTED = "ABORTED"
_F23_COORD_ERROR = "ERROR"

_F23_DISPLAY_READY = "READY_TO_DISPLAY_LOCAL"
_F23_DISPLAYING = "DISPLAYING"
_F23_DISPLAY_COMPLETED = "DISPLAY_COMPLETED_LOCAL"
_F23_DISPLAY_ABORTED = "DISPLAY_ABORTED_LOCAL"
_F23_DISPLAY_SKIPPED = "SKIPPED_WINDOW_MISSED"
_F23_DISPLAY_CANCELLED = "CANCELLED_REMOTE"
_F23_DISPLAY_EXPIRED = "EXPIRED_REMOTE"
_F23_TERMINAL_DISPLAY_STATES = {
    _F23_DISPLAY_COMPLETED,
    _F23_DISPLAY_ABORTED,
    _F23_DISPLAY_SKIPPED,
    _F23_DISPLAY_CANCELLED,
    _F23_DISPLAY_EXPIRED,
}

_F23_GYM_LOCKS: Dict[int, threading.Lock] = {}
_F23_GYM_LOCKS_GUARD = threading.Lock()

# ── F24: Proof + Completion Feedback constants ──────────────────────
_F24_COMPLETION_TOLERANCE_SEC = 2
_F24_OUTBOX_MAX_ATTEMPTS = 50
_F24_OUTBOX_BACKOFF_SCHEDULE = [30, 60, 120, 300, 600, 1800, 3600]  # seconds

_F24_DISPLAY_STATE_TO_RESULT = {
    _F23_DISPLAY_COMPLETED: "COMPLETED",
    _F23_DISPLAY_ABORTED: "ABORTED",
    _F23_DISPLAY_SKIPPED: "FAILED_TO_START",
    _F23_DISPLAY_CANCELLED: "CANCELLED_REMOTE",
    _F23_DISPLAY_EXPIRED: "EXPIRED_REMOTE",
}

_F24_OUTBOX_QUEUED = "QUEUED"
_F24_OUTBOX_SENDING = "SENDING"
_F24_OUTBOX_SENT = "SENT"
_F24_OUTBOX_FAILED_RETRYABLE = "FAILED_RETRYABLE"
_F24_OUTBOX_FAILED_TERMINAL = "FAILED_TERMINAL"


def _f23_now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _f23_iso_utc(dt: Optional[datetime] = None) -> str:
    value = dt or _f23_now_utc()
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _f23_parse_utc(value: Any) -> Optional[datetime]:
    s = str(value or "").strip()
    if not s:
        return None
    candidate = s
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(candidate)
    except Exception:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(s[:19], fmt)
                break
            except Exception:
                dt = None
        if dt is None:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _f23_safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


def _f23_safe_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        s = value.strip().lower()
        if s in {"1", "true", "yes", "on"}:
            return True
        if s in {"0", "false", "no", "off"}:
            return False
    return default


def _f23_safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    try:
        return str(value)
    except Exception:
        return default


def _f23_json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _f23_json_load(value: Any, default: Any) -> Any:
    raw = _f23_safe_str(value, "").strip()
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:
        return default


def _f23_row_dict(row: Any) -> Dict[str, Any]:
    if row is None:
        return {}
    if isinstance(row, dict):
        return dict(row)
    try:
        return dict(row)
    except Exception:
        return {}


def _f23_get_gym_lock(gym_id: int) -> threading.Lock:
    with _F23_GYM_LOCKS_GUARD:
        lock = _F23_GYM_LOCKS.get(gym_id)
        if lock is None:
            lock = threading.Lock()
            _F23_GYM_LOCKS[gym_id] = lock
        return lock


def _f23_add_column(conn: Any, table: str, column: str, ddl_suffix: str) -> None:
    cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_suffix}")

def _f23_ensure_schema_extensions() -> None:
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tv_ad_task_runtime (
                campaign_task_id INTEGER PRIMARY KEY,
                campaign_id INTEGER,
                gym_id INTEGER NOT NULL,
                ad_media_id TEXT,
                layout TEXT,
                display_duration_sec INTEGER,
                scheduled_at TEXT,
                local_display_state TEXT NOT NULL DEFAULT 'READY_TO_DISPLAY_LOCAL',
                currently_injected INTEGER NOT NULL DEFAULT 0,
                display_started_at TEXT,
                display_finished_at TEXT,
                display_aborted_at TEXT,
                display_abort_reason TEXT,
                participating_binding_ids_json TEXT,
                failed_binding_ids_json TEXT,
                last_event_at TEXT,
                updated_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tv_gym_ad_runtime (
                gym_id INTEGER PRIMARY KEY,
                current_campaign_task_id INTEGER,
                coordination_state TEXT NOT NULL DEFAULT 'IDLE',
                started_at TEXT,
                expected_finish_at TEXT,
                participating_binding_ids_json TEXT,
                failed_binding_ids_json TEXT,
                last_event_at TEXT,
                updated_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tv_ad_task_runtime_gym_state ON tv_ad_task_runtime(gym_id, local_display_state)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tv_gym_ad_runtime_state ON tv_gym_ad_runtime(coordination_state, updated_at)")

        _f23_add_column(conn, "tv_player_state", "ad_override_active", "INTEGER NOT NULL DEFAULT 0")
        _f23_add_column(conn, "tv_player_state", "current_ad_task_id", "INTEGER")
        _f23_add_column(conn, "tv_player_state", "current_ad_media_id", "TEXT")
        _f23_add_column(conn, "tv_player_state", "ad_layout", "TEXT")
        _f23_add_column(conn, "tv_player_state", "ad_audio_override_active", "INTEGER NOT NULL DEFAULT 0")
        _f23_add_column(conn, "tv_player_state", "ad_runtime_state", "TEXT")
        _f23_add_column(conn, "tv_player_state", "ad_runtime_message", "TEXT")
        _f23_add_column(conn, "tv_player_state", "ad_fallback_reason", "TEXT")

        # F23 schema hardening: add missing runtime fields (idempotent via _f23_add_column)
        _f23_add_column(conn, "tv_ad_task_runtime", "binding_scope_count", "INTEGER NOT NULL DEFAULT 0")
        _f23_add_column(conn, "tv_ad_task_runtime", "correlation_id", "TEXT")
        _f23_add_column(conn, "tv_ad_task_runtime", "injected_layout", "TEXT")
        _f23_add_column(conn, "tv_ad_task_runtime", "display_abort_message", "TEXT")

        # F23 gym runtime hardening: add missing fields
        _f23_add_column(conn, "tv_gym_ad_runtime", "active_binding_count", "INTEGER NOT NULL DEFAULT 0")
        _f23_add_column(conn, "tv_gym_ad_runtime", "failed_binding_count", "INTEGER NOT NULL DEFAULT 0")
        _f23_add_column(conn, "tv_gym_ad_runtime", "audio_override_active", "INTEGER NOT NULL DEFAULT 0")
        _f23_add_column(conn, "tv_gym_ad_runtime", "last_error_code", "TEXT")
        _f23_add_column(conn, "tv_gym_ad_runtime", "last_error_message", "TEXT")

        # F24: Proof outbox
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tv_ad_proof_outbox (
                local_proof_id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_task_id INTEGER NOT NULL,
                campaign_id INTEGER,
                gym_id INTEGER NOT NULL,
                ad_media_id TEXT,
                idempotency_key TEXT NOT NULL UNIQUE,
                started_at TEXT,
                finished_at TEXT,
                displayed_duration_sec INTEGER,
                expected_duration_sec INTEGER,
                completed_fully INTEGER NOT NULL DEFAULT 0,
                countable INTEGER NOT NULL DEFAULT 0,
                result_status TEXT NOT NULL,
                reason_if_not_countable TEXT,
                correlation_id TEXT,
                participating_binding_count INTEGER,
                failed_binding_count INTEGER,
                outbox_state TEXT NOT NULL DEFAULT 'QUEUED',
                attempt_count INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT,
                last_error TEXT,
                backend_proof_id INTEGER,
                backend_task_status TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tv_ad_proof_outbox_task ON tv_ad_proof_outbox(campaign_task_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tv_ad_proof_outbox_state ON tv_ad_proof_outbox(outbox_state, next_attempt_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tv_ad_proof_outbox_gym ON tv_ad_proof_outbox(gym_id)")
        conn.commit()


def _f23_load_task_cache_row(conn: Any, campaign_task_id: int) -> Dict[str, Any]:
    row = conn.execute("SELECT * FROM tv_ad_task_cache WHERE campaign_task_id=? LIMIT 1", (campaign_task_id,)).fetchone()
    return _f23_row_dict(row)


def _f23_load_task_runtime_row(conn: Any, campaign_task_id: int) -> Dict[str, Any]:
    row = conn.execute("SELECT * FROM tv_ad_task_runtime WHERE campaign_task_id=? LIMIT 1", (campaign_task_id,)).fetchone()
    return _f23_row_dict(row)


def _f23_load_gym_runtime_row(conn: Any, gym_id: int) -> Dict[str, Any]:
    row = conn.execute("SELECT * FROM tv_gym_ad_runtime WHERE gym_id=? LIMIT 1", (gym_id,)).fetchone()
    return _f23_row_dict(row)


def _f23_remote_terminal_state(remote_status: str) -> Optional[str]:
    v = _f23_safe_str(remote_status, "").strip().upper()
    if v == "CANCELLED":
        return _F23_DISPLAY_CANCELLED
    if v == "EXPIRED":
        return _F23_DISPLAY_EXPIRED
    return None


def _f23_is_task_ready_local(task: Dict[str, Any]) -> bool:
    remote_status = _f23_safe_str(task.get("remote_status"), "").strip().upper()
    if remote_status in _F23_REMOTE_TERMINAL:
        return False
    local_state = _f23_safe_str(task.get("local_preparation_state"), "").strip().upper()
    if local_state not in _F23_TASK_READY_LOCAL:
        return False
    return bool(_f23_safe_str(task.get("expected_local_path"), "").strip())


def _f23_validate_ad_asset(task: Dict[str, Any]) -> Tuple[bool, str, str]:
    path = _f23_safe_str(task.get("expected_local_path"), "").strip()
    if not path:
        return False, "MISSING_EXPECTED_LOCAL_PATH", "WEAK"
    if not os.path.exists(path):
        return False, "ASSET_FILE_MISSING", "WEAK"
    if not os.path.isfile(path):
        return False, "ASSET_PATH_NOT_FILE", "WEAK"
    try:
        size = os.path.getsize(path)
    except Exception:
        return False, "ASSET_FILE_UNREADABLE", "WEAK"
    declared_size = _f23_safe_int(task.get("ad_size_bytes"), 0)
    if declared_size > 0 and size != declared_size:
        return False, "SIZE_MISMATCH", "STRONG"
    checksum = _f23_safe_str(task.get("ad_checksum_sha256"), "").strip().lower()
    if checksum:
        sha = hashlib.sha256()
        try:
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(1024 * 1024)
                    if not chunk:
                        break
                    sha.update(chunk)
        except Exception:
            return False, "ASSET_FILE_UNREADABLE", "STRONG"
        if sha.hexdigest().lower() != checksum:
            return False, "CHECKSUM_MISMATCH", "STRONG"
        return True, "VALID_STRONG", "STRONG"
    if declared_size > 0:
        return True, "VALID_STRONG_SIZE_ONLY", "STRONG"
    return True, "VALID_WEAK_NO_INTEGRITY_METADATA", "WEAK"


def _f23_list_gym_binding_health(conn: Any, gym_id: int) -> List[Dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT b.id, b.screen_id, b.gym_id, b.enabled, b.desired_state, b.monitor_id,
               COALESCE(r.window_exists, 0) AS window_exists,
               COALESCE(r.launch_outcome, '') AS launch_outcome,
               CASE WHEN hm.monitor_id IS NULL THEN 0 ELSE 1 END AS monitor_available
        FROM tv_screen_binding b
        LEFT JOIN tv_screen_binding_runtime r ON r.binding_id = b.id
        LEFT JOIN tv_host_monitor hm ON hm.monitor_id = b.monitor_id
        WHERE b.gym_id = ?
        ORDER BY b.id ASC
        """,
        (gym_id,),
    ).fetchall()
    out: List[Dict[str, Any]] = []
    for raw in rows:
        row = _f23_row_dict(raw)
        enabled = _f23_safe_bool(row.get("enabled"), False)
        desired_running = _f23_safe_str(row.get("desired_state"), "").strip().upper() == "RUNNING"
        window_exists = _f23_safe_bool(row.get("window_exists"), False)
        monitor_ok = _f23_safe_bool(row.get("monitor_available"), False)
        launch_outcome = _f23_safe_str(row.get("launch_outcome"), "").strip().upper()
        row["healthy"] = enabled and desired_running and window_exists and monitor_ok and launch_outcome not in {"FAILED", "CRASHED"}
        out.append(row)
    return out

def _f23_upsert_task_runtime(
    conn: Any,
    task: Dict[str, Any],
    *,
    local_display_state: str,
    currently_injected: bool,
    display_started_at: Optional[str] = None,
    display_finished_at: Optional[str] = None,
    display_aborted_at: Optional[str] = None,
    display_abort_reason: Optional[str] = None,
    display_abort_message: Optional[str] = None,
    participating_binding_ids: Optional[Sequence[int]] = None,
    failed_binding_ids: Optional[Sequence[int]] = None,
    correlation_id: Optional[str] = None,
    injected_layout: Optional[str] = None,
    binding_scope_count: int = 0,
) -> Dict[str, Any]:
    now_iso = _f23_iso_utc()
    part_ids = list(participating_binding_ids or [])
    scope_count = binding_scope_count if binding_scope_count > 0 else len(part_ids)
    layout_val = injected_layout or _f23_safe_str(task.get("layout"), "") or None
    conn.execute(
        """
        INSERT INTO tv_ad_task_runtime (
            campaign_task_id, campaign_id, gym_id, ad_media_id, layout, display_duration_sec, scheduled_at,
            local_display_state, currently_injected, display_started_at, display_finished_at, display_aborted_at,
            display_abort_reason, display_abort_message, participating_binding_ids_json, failed_binding_ids_json,
            correlation_id, injected_layout, binding_scope_count, last_event_at, updated_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(campaign_task_id) DO UPDATE SET
            campaign_id=excluded.campaign_id,
            gym_id=excluded.gym_id,
            ad_media_id=excluded.ad_media_id,
            layout=excluded.layout,
            display_duration_sec=excluded.display_duration_sec,
            scheduled_at=excluded.scheduled_at,
            local_display_state=excluded.local_display_state,
            currently_injected=excluded.currently_injected,
            display_started_at=COALESCE(excluded.display_started_at, tv_ad_task_runtime.display_started_at),
            display_finished_at=COALESCE(excluded.display_finished_at, tv_ad_task_runtime.display_finished_at),
            display_aborted_at=COALESCE(excluded.display_aborted_at, tv_ad_task_runtime.display_aborted_at),
            display_abort_reason=COALESCE(excluded.display_abort_reason, tv_ad_task_runtime.display_abort_reason),
            display_abort_message=COALESCE(excluded.display_abort_message, tv_ad_task_runtime.display_abort_message),
            participating_binding_ids_json=excluded.participating_binding_ids_json,
            failed_binding_ids_json=excluded.failed_binding_ids_json,
            correlation_id=COALESCE(excluded.correlation_id, tv_ad_task_runtime.correlation_id),
            injected_layout=COALESCE(excluded.injected_layout, tv_ad_task_runtime.injected_layout),
            binding_scope_count=excluded.binding_scope_count,
            last_event_at=excluded.last_event_at,
            updated_at=excluded.updated_at
        """,
        (
            _f23_safe_int(task.get("campaign_task_id"), 0),
            _f23_safe_int(task.get("campaign_id"), 0),
            _f23_safe_int(task.get("gym_id"), 0),
            _f23_safe_str(task.get("ad_media_id"), "") or None,
            _f23_safe_str(task.get("layout"), "") or None,
            _f23_safe_int(task.get("display_duration_sec"), 0),
            _f23_safe_str(task.get("scheduled_at"), "") or None,
            local_display_state,
            1 if currently_injected else 0,
            display_started_at,
            display_finished_at,
            display_aborted_at,
            display_abort_reason,
            display_abort_message,
            _f23_json_dump(part_ids),
            _f23_json_dump(list(failed_binding_ids or [])),
            correlation_id,
            layout_val,
            scope_count,
            now_iso,
            now_iso,
            now_iso,
        ),
    )
    return _f23_load_task_runtime_row(conn, _f23_safe_int(task.get("campaign_task_id"), 0))


def _f23_upsert_gym_runtime(
    conn: Any,
    *,
    gym_id: int,
    current_campaign_task_id: Optional[int],
    coordination_state: str,
    started_at: Optional[str] = None,
    expected_finish_at: Optional[str] = None,
    participating_binding_ids: Optional[Sequence[int]] = None,
    failed_binding_ids: Optional[Sequence[int]] = None,
    audio_override_active: bool = False,
    last_error_code: Optional[str] = None,
    last_error_message: Optional[str] = None,
) -> Dict[str, Any]:
    now_iso = _f23_iso_utc()
    part_ids = list(participating_binding_ids or [])
    fail_ids = list(failed_binding_ids or [])
    conn.execute(
        """
        INSERT INTO tv_gym_ad_runtime (
            gym_id, current_campaign_task_id, coordination_state, started_at, expected_finish_at,
            participating_binding_ids_json, failed_binding_ids_json,
            active_binding_count, failed_binding_count,
            audio_override_active, last_error_code, last_error_message,
            last_event_at, updated_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(gym_id) DO UPDATE SET
            current_campaign_task_id=excluded.current_campaign_task_id,
            coordination_state=excluded.coordination_state,
            started_at=excluded.started_at,
            expected_finish_at=excluded.expected_finish_at,
            participating_binding_ids_json=excluded.participating_binding_ids_json,
            failed_binding_ids_json=excluded.failed_binding_ids_json,
            active_binding_count=excluded.active_binding_count,
            failed_binding_count=excluded.failed_binding_count,
            audio_override_active=excluded.audio_override_active,
            last_error_code=COALESCE(excluded.last_error_code, tv_gym_ad_runtime.last_error_code),
            last_error_message=COALESCE(excluded.last_error_message, tv_gym_ad_runtime.last_error_message),
            last_event_at=excluded.last_event_at,
            updated_at=excluded.updated_at
        """,
        (
            gym_id,
            current_campaign_task_id,
            coordination_state,
            started_at,
            expected_finish_at,
            _f23_json_dump(part_ids),
            _f23_json_dump(fail_ids),
            len(part_ids),
            len(fail_ids),
            1 if audio_override_active else 0,
            last_error_code,
            last_error_message,
            now_iso,
            now_iso,
            now_iso,
        ),
    )
    return _f23_load_gym_runtime_row(conn, gym_id)


def _f23_clear_gym_runtime(conn: Any, gym_id: int) -> None:
    _f23_upsert_gym_runtime(
        conn,
        gym_id=gym_id,
        current_campaign_task_id=None,
        coordination_state=_F23_COORD_IDLE,
        started_at=None,
        expected_finish_at=None,
        participating_binding_ids=[],
        failed_binding_ids=[],
        audio_override_active=False,
        last_error_code=None,
        last_error_message=None,
    )


def _f23_apply_remote_terminal_precedence(conn: Any, gym_id: int, now_iso: str) -> None:
    gym_runtime = _f23_load_gym_runtime_row(conn, gym_id)
    task_id = _f23_safe_int(gym_runtime.get("current_campaign_task_id"), 0)
    if task_id <= 0:
        return
    task = _f23_load_task_cache_row(conn, task_id)
    if not task:
        _f23_clear_gym_runtime(conn, gym_id)
        return
    terminal_state = _f23_remote_terminal_state(_f23_safe_str(task.get("remote_status"), ""))
    if not terminal_state:
        return
    participants = _f23_json_load(gym_runtime.get("participating_binding_ids_json"), [])
    failed = _f23_json_load(gym_runtime.get("failed_binding_ids_json"), [])
    task_rt = _f23_upsert_task_runtime(
        conn,
        task,
        local_display_state=terminal_state,
        currently_injected=False,
        display_aborted_at=now_iso,
        display_abort_reason=f"REMOTE_STATUS_{_f23_safe_str(task.get('remote_status'), '').upper()}",
        participating_binding_ids=participants,
        failed_binding_ids=failed,
    )
    _f24_create_proof_from_terminal(
        conn, task=task, task_runtime=task_rt, gym_runtime=gym_runtime,
        terminal_display_state=terminal_state,
    )
    _f23_clear_gym_runtime(conn, gym_id)


def _f23_mark_missed_due_tasks(conn: Any, gym_id: int, now_dt: datetime) -> None:
    rows = conn.execute(
        """
        SELECT * FROM tv_ad_task_cache
        WHERE gym_id=? AND remote_status NOT IN ('CANCELLED','EXPIRED')
        ORDER BY scheduled_at ASC, campaign_task_id ASC
        """,
        (gym_id,),
    ).fetchall()
    now_iso = _f23_iso_utc(now_dt)
    for raw in rows:
        task = _f23_row_dict(raw)
        if not _f23_is_task_ready_local(task):
            continue
        task_id = _f23_safe_int(task.get("campaign_task_id"), 0)
        if task_id <= 0:
            continue
        rt = _f23_load_task_runtime_row(conn, task_id)
        rt_state = _f23_safe_str(rt.get("local_display_state"), "")
        if rt_state in _F23_TERMINAL_DISPLAY_STATES or rt_state == _F23_DISPLAYING:
            continue
        scheduled = _f23_parse_utc(task.get("scheduled_at"))
        if scheduled is None:
            continue
        if now_dt <= scheduled + timedelta(seconds=_F23_DUE_GRACE_SECONDS):
            continue
        skipped_rt = _f23_upsert_task_runtime(
            conn,
            task,
            local_display_state=_F23_DISPLAY_SKIPPED,
            currently_injected=False,
            display_aborted_at=now_iso,
            display_abort_reason="MISSED_DUE_WINDOW",
            participating_binding_ids=[],
            failed_binding_ids=[],
        )
        _f24_create_proof_from_terminal(
            conn, task=task, task_runtime=skipped_rt, gym_runtime={},
            terminal_display_state=_F23_DISPLAY_SKIPPED,
        )

def _f23_pick_due_task(conn: Any, gym_id: int, now_dt: datetime, force_task_id: Optional[int]) -> Dict[str, Any]:
    if force_task_id and force_task_id > 0:
        forced = _f23_load_task_cache_row(conn, force_task_id)
        if _f23_safe_int(forced.get("gym_id"), 0) != gym_id:
            return {}
        return forced

    rows = conn.execute(
        """
        SELECT * FROM tv_ad_task_cache
        WHERE gym_id=? AND remote_status NOT IN ('CANCELLED','EXPIRED','DONE','FAILED')
        ORDER BY scheduled_at ASC, campaign_task_id ASC
        """,
        (gym_id,),
    ).fetchall()
    for raw in rows:
        task = _f23_row_dict(raw)
        if not _f23_is_task_ready_local(task):
            continue
        task_id = _f23_safe_int(task.get("campaign_task_id"), 0)
        rt = _f23_load_task_runtime_row(conn, task_id)
        if _f23_safe_str(rt.get("local_display_state"), "") in _F23_TERMINAL_DISPLAY_STATES:
            continue
        scheduled = _f23_parse_utc(task.get("scheduled_at"))
        if not scheduled:
            continue
        if now_dt < scheduled:
            continue
        if now_dt > scheduled + timedelta(seconds=_F23_DUE_GRACE_SECONDS):
            continue
        return task
    return {}


def _f23_reconcile_gym_runtime(conn: Any, *, gym_id: int, force_task_id: Optional[int] = None) -> Dict[str, Any]:
    now_dt = _f23_now_utc()
    now_iso = _f23_iso_utc(now_dt)
    bindings = _f23_list_gym_binding_health(conn, gym_id)
    healthy_binding_ids = sorted(_f23_safe_int(r.get("id"), 0) for r in bindings if _f23_safe_bool(r.get("healthy"), False))
    healthy_binding_ids = [x for x in healthy_binding_ids if x > 0]

    _f23_apply_remote_terminal_precedence(conn, gym_id, now_iso)
    gym_runtime = _f23_load_gym_runtime_row(conn, gym_id)
    current_task_id = _f23_safe_int(gym_runtime.get("current_campaign_task_id"), 0)

    if current_task_id > 0:
        task = _f23_load_task_cache_row(conn, current_task_id)
        if not task:
            _f23_clear_gym_runtime(conn, gym_id)
        else:
            valid, reason, _strength = _f23_validate_ad_asset(task)
            if not valid:
                participants = _f23_json_load(gym_runtime.get("participating_binding_ids_json"), [])
                failed = sorted(set(_f23_json_load(gym_runtime.get("failed_binding_ids_json"), []) + participants))
                aborted_rt = _f23_upsert_task_runtime(
                    conn,
                    task,
                    local_display_state=_F23_DISPLAY_ABORTED,
                    currently_injected=False,
                    display_aborted_at=now_iso,
                    display_abort_reason=reason,
                    participating_binding_ids=participants,
                    failed_binding_ids=failed,
                )
                _f24_create_proof_from_terminal(
                    conn, task=task, task_runtime=aborted_rt, gym_runtime=gym_runtime,
                    terminal_display_state=_F23_DISPLAY_ABORTED,
                )
                _f23_clear_gym_runtime(conn, gym_id)
            else:
                start_dt = _f23_parse_utc(gym_runtime.get("started_at")) or now_dt
                duration = max(1, _f23_safe_int(task.get("display_duration_sec"), 0))
                expected_finish_dt = start_dt + timedelta(seconds=duration)
                participants = sorted(set(_f23_json_load(gym_runtime.get("participating_binding_ids_json"), [])))
                if not participants:
                    participants = list(healthy_binding_ids)
                failed = sorted(set(_f23_json_load(gym_runtime.get("failed_binding_ids_json"), [])))
                healthy_set = set(healthy_binding_ids)
                for pid in participants:
                    if pid not in healthy_set and pid not in failed:
                        failed.append(pid)
                if now_dt >= expected_finish_dt:
                    completed_rt = _f23_upsert_task_runtime(
                        conn,
                        task,
                        local_display_state=_F23_DISPLAY_COMPLETED,
                        currently_injected=False,
                        display_finished_at=now_iso,
                        participating_binding_ids=participants,
                        failed_binding_ids=failed,
                    )
                    _f24_create_proof_from_terminal(
                        conn, task=task, task_runtime=completed_rt, gym_runtime=gym_runtime,
                        terminal_display_state=_F23_DISPLAY_COMPLETED,
                    )
                    _f23_clear_gym_runtime(conn, gym_id)
                else:
                    _f23_upsert_task_runtime(
                        conn,
                        task,
                        local_display_state=_F23_DISPLAYING,
                        currently_injected=True,
                        display_started_at=_f23_iso_utc(start_dt),
                        participating_binding_ids=participants,
                        failed_binding_ids=failed,
                        injected_layout=_f23_safe_str(task.get("layout"), "") or None,
                        binding_scope_count=len(participants),
                    )
                    _f23_upsert_gym_runtime(
                        conn,
                        gym_id=gym_id,
                        current_campaign_task_id=current_task_id,
                        coordination_state=_F23_COORD_DISPLAYING,
                        started_at=_f23_iso_utc(start_dt),
                        expected_finish_at=_f23_iso_utc(expected_finish_dt),
                        participating_binding_ids=participants,
                        failed_binding_ids=failed,
                        audio_override_active=True,
                    )

    gym_runtime = _f23_load_gym_runtime_row(conn, gym_id)
    current_task_id = _f23_safe_int(gym_runtime.get("current_campaign_task_id"), 0)
    if current_task_id > 0:
        return {
            "gymRuntime": gym_runtime,
            "task": _f23_load_task_cache_row(conn, current_task_id),
            "runtime": _f23_load_task_runtime_row(conn, current_task_id),
            "healthyBindingIds": healthy_binding_ids,
        }

    if not healthy_binding_ids:
        return {"gymRuntime": gym_runtime, "task": {}, "runtime": {}, "healthyBindingIds": healthy_binding_ids, "reason": "NO_HEALTHY_BINDINGS"}

    _f23_mark_missed_due_tasks(conn, gym_id, now_dt)
    winner = _f23_pick_due_task(conn, gym_id, now_dt, force_task_id)
    if not winner:
        return {"gymRuntime": gym_runtime, "task": {}, "runtime": {}, "healthyBindingIds": healthy_binding_ids}

    valid, reason, strength = _f23_validate_ad_asset(winner)
    if not valid:
        winner_aborted_rt = _f23_upsert_task_runtime(
            conn,
            winner,
            local_display_state=_F23_DISPLAY_ABORTED,
            currently_injected=False,
            display_aborted_at=now_iso,
            display_abort_reason=reason,
            participating_binding_ids=[],
            failed_binding_ids=[],
        )
        _f24_create_proof_from_terminal(
            conn, task=winner, task_runtime=winner_aborted_rt, gym_runtime={},
            terminal_display_state=_F23_DISPLAY_ABORTED,
        )
        return {"gymRuntime": gym_runtime, "task": winner, "runtime": _f23_load_task_runtime_row(conn, _f23_safe_int(winner.get("campaign_task_id"), 0)), "healthyBindingIds": healthy_binding_ids, "reason": reason}

    duration = max(1, _f23_safe_int(winner.get("display_duration_sec"), 0))
    expected_finish_dt = now_dt + timedelta(seconds=duration)
    participants = list(healthy_binding_ids)
    _f23_upsert_task_runtime(
        conn,
        winner,
        local_display_state=_F23_DISPLAYING,
        currently_injected=True,
        display_started_at=now_iso,
        participating_binding_ids=participants,
        failed_binding_ids=[],
        injected_layout=_f23_safe_str(winner.get("layout"), "") or None,
        binding_scope_count=len(participants),
    )
    _f23_upsert_gym_runtime(
        conn,
        gym_id=gym_id,
        current_campaign_task_id=_f23_safe_int(winner.get("campaign_task_id"), 0),
        coordination_state=_F23_COORD_DISPLAYING,
        started_at=now_iso,
        expected_finish_at=_f23_iso_utc(expected_finish_dt),
        participating_binding_ids=participants,
        failed_binding_ids=[],
        audio_override_active=True,
    )
    return {
        "gymRuntime": _f23_load_gym_runtime_row(conn, gym_id),
        "task": winner,
        "runtime": _f23_load_task_runtime_row(conn, _f23_safe_int(winner.get("campaign_task_id"), 0)),
        "healthyBindingIds": healthy_binding_ids,
        "validationStrength": strength,
    }

# ── F24: Proof creation + outbox internals ──────────────────────────

def _f24_proof_exists(conn: Any, campaign_task_id: int, correlation_id: str) -> bool:
    """Check if a proof row already exists for this task + correlation combo."""
    key = f"{campaign_task_id}:{correlation_id}"
    row = conn.execute(
        "SELECT 1 FROM tv_ad_proof_outbox WHERE idempotency_key=? LIMIT 1", (key,)
    ).fetchone()
    return row is not None


def _f24_compute_displayed_duration(started_at: Optional[str], finished_at: Optional[str]) -> int:
    """Compute displayed duration in seconds from gym-level timestamps."""
    start = _f23_parse_utc(started_at)
    end = _f23_parse_utc(finished_at)
    if start is None or end is None:
        return 0
    diff = (end - start).total_seconds()
    return max(0, int(diff))


def _f24_create_proof_from_terminal(
    conn: Any,
    *,
    task: Dict[str, Any],
    task_runtime: Dict[str, Any],
    gym_runtime: Dict[str, Any],
    terminal_display_state: str,
) -> Optional[Dict[str, Any]]:
    """Create a proof outbox row when a task reaches terminal display state.

    Uses gym-level timing (from gym_runtime or task_runtime).
    Exactly one proof per gym-level task attempt. Idempotent by campaignTaskId:correlationId.
    """
    campaign_task_id = _f23_safe_int(task.get("campaign_task_id"), 0)
    if campaign_task_id <= 0:
        return None

    # Derive correlation_id from the display session
    correlation_id = (
        _f23_safe_str(task_runtime.get("correlation_id"), "").strip()
        or _f23_safe_str(gym_runtime.get("correlation_id"), "").strip()
        or _f23_safe_str(task.get("correlation_id"), "").strip()
    )
    if not correlation_id:
        correlation_id = str(uuid.uuid4())

    idempotency_key = f"{campaign_task_id}:{correlation_id}"

    # Idempotency guard: do not create duplicate local proof
    if _f24_proof_exists(conn, campaign_task_id, correlation_id):
        return None

    # Gym-level timing truth
    started_at = (
        _f23_safe_str(gym_runtime.get("started_at"), "").strip()
        or _f23_safe_str(task_runtime.get("display_started_at"), "").strip()
    )
    finished_at = (
        _f23_safe_str(task_runtime.get("display_finished_at"), "").strip()
        or _f23_safe_str(task_runtime.get("display_aborted_at"), "").strip()
        or _f23_iso_utc()
    )

    displayed_duration_sec = _f24_compute_displayed_duration(started_at, finished_at)
    expected_duration_sec = _f23_safe_int(task.get("display_duration_sec"), 0)

    # Result status from display state
    result_status = _F24_DISPLAY_STATE_TO_RESULT.get(terminal_display_state, "ABORTED")

    # Completion and countability
    completed_fully = (terminal_display_state == _F23_DISPLAY_COMPLETED)
    countable = (
        completed_fully
        and result_status == "COMPLETED"
        and displayed_duration_sec >= max(0, expected_duration_sec - _F24_COMPLETION_TOLERANCE_SEC)
        and expected_duration_sec > 0
    )

    reason_if_not_countable = None
    if not countable:
        if not completed_fully:
            if terminal_display_state == _F23_DISPLAY_SKIPPED:
                reason_if_not_countable = "MISSED_DISPLAY_WINDOW"
            elif terminal_display_state == _F23_DISPLAY_CANCELLED:
                reason_if_not_countable = "CANCELLED_REMOTE"
            elif terminal_display_state == _F23_DISPLAY_EXPIRED:
                reason_if_not_countable = "EXPIRED_REMOTE"
            else:
                reason_if_not_countable = _f23_safe_str(
                    task_runtime.get("display_abort_reason"), "DISPLAY_NOT_COMPLETED"
                )
        elif displayed_duration_sec < max(0, expected_duration_sec - _F24_COMPLETION_TOLERANCE_SEC):
            reason_if_not_countable = "PARTIAL_DISPLAY"
        else:
            reason_if_not_countable = "UNKNOWN"

    # Support metadata
    participants_json = (
        task_runtime.get("participating_binding_ids_json")
        or gym_runtime.get("participating_binding_ids_json")
        or "[]"
    )
    failed_json = (
        task_runtime.get("failed_binding_ids_json")
        or gym_runtime.get("failed_binding_ids_json")
        or "[]"
    )
    participating_binding_count = len(_f23_json_load(participants_json, []))
    failed_binding_count = len(_f23_json_load(failed_json, []))

    now_iso = _f23_iso_utc()
    conn.execute(
        """
        INSERT INTO tv_ad_proof_outbox (
            campaign_task_id, campaign_id, gym_id, ad_media_id,
            idempotency_key, started_at, finished_at,
            displayed_duration_sec, expected_duration_sec,
            completed_fully, countable, result_status, reason_if_not_countable,
            correlation_id, participating_binding_count, failed_binding_count,
            outbox_state, attempt_count, next_attempt_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
        """,
        (
            campaign_task_id,
            _f23_safe_int(task.get("campaign_id"), 0) or None,
            _f23_safe_int(task.get("gym_id"), 0),
            _f23_safe_str(task.get("ad_media_id"), "") or None,
            idempotency_key,
            started_at or None,
            finished_at or None,
            displayed_duration_sec,
            expected_duration_sec,
            1 if completed_fully else 0,
            1 if countable else 0,
            result_status,
            reason_if_not_countable,
            correlation_id,
            participating_binding_count,
            failed_binding_count,
            _F24_OUTBOX_QUEUED,
            now_iso,  # next_attempt_at = now (send immediately)
            now_iso,
            now_iso,
        ),
    )

    row = conn.execute(
        "SELECT * FROM tv_ad_proof_outbox WHERE idempotency_key=? LIMIT 1", (idempotency_key,)
    ).fetchone()
    return _f23_row_dict(row)


def _f24_compute_next_attempt(attempt_count: int) -> str:
    idx = min(attempt_count, len(_F24_OUTBOX_BACKOFF_SCHEDULE) - 1)
    delay = _F24_OUTBOX_BACKOFF_SCHEDULE[idx]
    return _f23_iso_utc(_f23_now_utc() + timedelta(seconds=delay))


def _f23_enrich_binding_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not rows:
        return rows
    with get_conn() as conn:
        for row in rows:
            binding_id = _f23_safe_int(row.get("id"), 0)
            if binding_id <= 0:
                continue
            ps = conn.execute(
                "SELECT ad_override_active, current_ad_task_id, current_ad_media_id, ad_layout, ad_audio_override_active, ad_runtime_state FROM tv_player_state WHERE binding_id=? LIMIT 1",
                (binding_id,),
            ).fetchone()
            p = _f23_row_dict(ps)
            row["player_ad_override_active"] = _f23_safe_bool(p.get("ad_override_active"), False)
            row["player_current_ad_task_id"] = p.get("current_ad_task_id")
            row["player_current_ad_media_id"] = p.get("current_ad_media_id")
            row["player_ad_layout"] = p.get("ad_layout")
            row["player_ad_audio_override_active"] = _f23_safe_bool(p.get("ad_audio_override_active"), False)
            row["player_ad_runtime_state"] = p.get("ad_runtime_state")

            gym_id = _f23_safe_int(row.get("gym_id"), 0)
            if gym_id > 0:
                gr = _f23_load_gym_runtime_row(conn, gym_id)
                row["gym_ad_current_task_id"] = gr.get("current_campaign_task_id")
                row["gym_ad_coordination_state"] = gr.get("coordination_state")
    return rows


def _f23_append_ad_fields_to_player_state(conn: Any, binding_id: int, payload: Dict[str, Any]) -> None:
    now_iso = _f23_iso_utc()
    conn.execute(
        """
        UPDATE tv_player_state
        SET ad_override_active=?, current_ad_task_id=?, current_ad_media_id=?, ad_layout=?,
            ad_audio_override_active=?, ad_runtime_state=?, ad_runtime_message=?, updated_at=?
        WHERE binding_id=?
        """,
        (
            1 if _f23_safe_bool(payload.get("ad_override_active"), False) else 0,
            _f23_safe_int(payload.get("current_ad_task_id"), 0) or None,
            _f23_safe_str(payload.get("current_ad_media_id"), "") or None,
            _f23_safe_str(payload.get("ad_layout"), "") or None,
            1 if _f23_safe_bool(payload.get("ad_audio_override_active"), False) else 0,
            _f23_safe_str(payload.get("ad_runtime_state"), "") or None,
            _f23_safe_str(payload.get("ad_runtime_message"), "") or None,
            now_iso,
            binding_id,
        ),
    )


def ensure_tv_local_schema() -> None:  # type: ignore[override]
    _BASE_ENSURE_TV_LOCAL_SCHEMA()
    _f23_ensure_schema_extensions()


def list_tv_screen_bindings() -> List[Dict[str, Any]]:  # type: ignore[override]
    ensure_tv_local_schema()
    rows = _BASE_LIST_TV_SCREEN_BINDINGS()
    return _f23_enrich_binding_rows(list(rows or []))


def get_tv_screen_binding(*, binding_id: int) -> Optional[Dict[str, Any]]:  # type: ignore[override]
    ensure_tv_local_schema()
    row = _BASE_GET_TV_SCREEN_BINDING(binding_id=binding_id)
    if not row:
        return row
    return _f23_enrich_binding_rows([dict(row)])[0]


def load_tv_screen_binding_by_id(*, binding_id: int) -> Optional[Dict[str, Any]]:  # type: ignore[override]
    ensure_tv_local_schema()
    row = _BASE_LOAD_TV_SCREEN_BINDING_BY_ID(binding_id=binding_id)
    if not row:
        return row
    return _f23_enrich_binding_rows([dict(row)])[0]


def load_tv_binding_support_summary(*, binding_id: int) -> Dict[str, Any]:  # type: ignore[override]
    ensure_tv_local_schema()
    out = _BASE_LOAD_TV_BINDING_SUPPORT_SUMMARY(binding_id=binding_id)
    if not bool(out.get("ok")):
        return out
    binding = out.get("binding") or {}
    gym_id = _f23_safe_int(binding.get("gym_id"), 0)
    with get_conn() as conn:
        if gym_id > 0:
            out["gymAdRuntime"] = _f23_load_gym_runtime_row(conn, gym_id)
    return out


def list_tv_ad_task_cache(*, gym_id: Optional[int] = None, remote_statuses: Optional[List[str]] = None, local_states: Optional[List[str]] = None, q: Optional[str] = None, limit: int = 500, offset: int = 0) -> Dict[str, Any]:  # type: ignore[override]
    ensure_tv_local_schema()
    data = _BASE_LIST_TV_AD_TASK_CACHE(gym_id=gym_id, remote_statuses=remote_statuses, local_states=local_states, q=q, limit=limit, offset=offset)
    rows = list(data.get("rows") or [])
    if not rows:
        return data
    task_ids = [_f23_safe_int(r.get("campaign_task_id"), 0) for r in rows]
    gym_ids = sorted({_f23_safe_int(r.get("gym_id"), 0) for r in rows if _f23_safe_int(r.get("gym_id"), 0) > 0})
    with get_conn() as conn:
        runtime_map: Dict[int, Dict[str, Any]] = {}
        if task_ids:
            placeholders = ",".join("?" for _ in task_ids)
            for raw in conn.execute(f"SELECT * FROM tv_ad_task_runtime WHERE campaign_task_id IN ({placeholders})", tuple(task_ids)).fetchall():
                runtime_map[_f23_safe_int(raw["campaign_task_id"], 0)] = _f23_row_dict(raw)
        gym_runtime_map: Dict[int, Dict[str, Any]] = {}
        if gym_ids:
            placeholders = ",".join("?" for _ in gym_ids)
            for raw in conn.execute(f"SELECT * FROM tv_gym_ad_runtime WHERE gym_id IN ({placeholders})", tuple(gym_ids)).fetchall():
                gym_runtime_map[_f23_safe_int(raw["gym_id"], 0)] = _f23_row_dict(raw)
        for row in rows:
            task_id = _f23_safe_int(row.get("campaign_task_id"), 0)
            gym = _f23_safe_int(row.get("gym_id"), 0)
            rt = runtime_map.get(task_id, {})
            gr = gym_runtime_map.get(gym, {})
            row["local_display_state"] = rt.get("local_display_state")
            row["display_started_at"] = rt.get("display_started_at")
            row["display_finished_at"] = rt.get("display_finished_at")
            row["display_aborted_at"] = rt.get("display_aborted_at")
            row["display_abort_reason"] = rt.get("display_abort_reason")
            row["currently_injected"] = _f23_safe_bool(rt.get("currently_injected"), False)
            row["participating_binding_ids"] = _f23_json_load(rt.get("participating_binding_ids_json"), [])
            row["failed_binding_ids"] = _f23_json_load(rt.get("failed_binding_ids_json"), [])
            row["gym_coordination_state"] = gr.get("coordination_state")
            row["gym_current_task_id"] = gr.get("current_campaign_task_id")
        # F24: Enrich with proof outbox data
        proof_map: Dict[int, Dict[str, Any]] = {}
        if task_ids:
            placeholders = ",".join("?" for _ in task_ids)
            for raw in conn.execute(
                f"SELECT * FROM tv_ad_proof_outbox WHERE campaign_task_id IN ({placeholders}) ORDER BY created_at DESC",
                tuple(task_ids),
            ).fetchall():
                tid = _f23_safe_int(raw["campaign_task_id"], 0)
                if tid not in proof_map:  # keep latest proof per task
                    proof_map[tid] = _f23_row_dict(raw)
        for row in rows:
            task_id = _f23_safe_int(row.get("campaign_task_id"), 0)
            pf = proof_map.get(task_id, {})
            row["proof_result_status"] = pf.get("result_status")
            row["proof_countable"] = _f23_safe_bool(pf.get("countable"), False) if pf else None
            row["proof_outbox_state"] = pf.get("outbox_state")
            row["proof_displayed_duration_sec"] = pf.get("displayed_duration_sec")
            row["proof_expected_duration_sec"] = pf.get("expected_duration_sec")
            row["proof_reason_if_not_countable"] = pf.get("reason_if_not_countable")
    data["rows"] = rows
    return data

def load_tv_player_status(*, binding_id: int) -> Dict[str, Any]:  # type: ignore[override]
    ensure_tv_local_schema()
    return _BASE_LOAD_TV_PLAYER_STATUS(binding_id=binding_id)


def report_tv_player_state(*, binding_id: int, payload: Dict[str, Any], event_type: str = "PLAYER_STATE_CHANGED", force: bool = False, freshness_seconds: int = 20) -> Dict[str, Any]:  # type: ignore[override]
    ensure_tv_local_schema()
    out = _BASE_REPORT_TV_PLAYER_STATE(
        binding_id=binding_id,
        payload=payload,
        event_type=event_type,
        force=force,
        freshness_seconds=freshness_seconds,
    )
    if bool(out.get("updated")) or bool(out.get("changed")):
        with get_conn() as conn:
            _f23_append_ad_fields_to_player_state(conn, binding_id, payload if isinstance(payload, dict) else {})
            row = conn.execute("SELECT * FROM tv_player_state WHERE binding_id=? LIMIT 1", (binding_id,)).fetchone()
            out["row"] = _f23_row_dict(row)
            conn.commit()
    return out


def _f23_resolve_ad_override_for_binding(binding_id: int, force_task_id: Optional[int] = None) -> Dict[str, Any]:
    with get_conn() as conn:
        binding = conn.execute(
            """
            SELECT b.id, b.gym_id
            FROM tv_screen_binding b
            WHERE b.id=?
            LIMIT 1
            """,
            (binding_id,),
        ).fetchone()
        if not binding:
            return {"overrideActive": False, "reason": "BINDING_NOT_FOUND"}
        gym_id = _f23_safe_int(binding["gym_id"], 0)
        if gym_id <= 0:
            return {"overrideActive": False, "reason": "GYM_NOT_RESOLVED"}

        lock = _f23_get_gym_lock(gym_id)
        with lock:
            resolved = _f23_reconcile_gym_runtime(conn, gym_id=gym_id, force_task_id=force_task_id)
            conn.commit()

        task = _f23_row_dict(resolved.get("task"))
        runtime = _f23_row_dict(resolved.get("runtime"))
        gym_runtime = _f23_row_dict(resolved.get("gymRuntime"))
        if not task:
            return {"overrideActive": False, "reason": _f23_safe_str(resolved.get("reason"), "NO_DUE_TASK"), "gymRuntime": gym_runtime}

        participants = _f23_json_load(runtime.get("participating_binding_ids_json"), [])
        failed = _f23_json_load(runtime.get("failed_binding_ids_json"), [])
        healthy_binding_ids = set(resolved.get("healthyBindingIds") or [])
        if binding_id not in participants or binding_id not in healthy_binding_ids:
            return {
                "overrideActive": False,
                "reason": "BINDING_NOT_PARTICIPATING_OR_UNHEALTHY",
                "task": task,
                "runtime": runtime,
                "gymRuntime": gym_runtime,
            }

        valid, reason, strength = _f23_validate_ad_asset(task)
        if not valid:
            return {"overrideActive": False, "reason": reason, "task": task, "runtime": runtime, "gymRuntime": gym_runtime}

        return {
            "overrideActive": True,
            "task": task,
            "runtime": runtime,
            "gymRuntime": gym_runtime,
            "validationStrength": strength,
            "participatingBindingIds": participants,
            "failedBindingIds": failed,
        }


def get_tv_player_render_context(*, binding_id: int, persist: bool = False) -> Dict[str, Any]:  # type: ignore[override]
    ensure_tv_local_schema()
    base = _BASE_GET_TV_PLAYER_RENDER_CONTEXT(binding_id=binding_id, persist=persist)
    if not bool(base.get("ok")):
        base["adOverrideActive"] = False
        return base

    ad = _f23_resolve_ad_override_for_binding(binding_id)
    if not bool(ad.get("overrideActive")):
        base["adOverrideActive"] = False
        base["adFallbackReason"] = ad.get("reason")
        if isinstance(ad.get("gymRuntime"), dict):
            base["gymAdRuntime"] = ad.get("gymRuntime")
        return base

    task = _f23_row_dict(ad.get("task"))
    runtime = _f23_row_dict(ad.get("runtime"))
    gym_runtime = _f23_row_dict(ad.get("gymRuntime"))
    base["adOverrideActive"] = True
    base["adAudioOverrideActive"] = True
    base["currentAdTaskId"] = _f23_safe_int(task.get("campaign_task_id"), 0)
    base["currentAdMediaId"] = _f23_safe_str(task.get("ad_media_id"), "") or None
    base["adLayout"] = _f23_safe_str(task.get("layout"), "") or "FULL_SCREEN"
    base["adAssetPath"] = _f23_safe_str(task.get("expected_local_path"), "") or None
    base["adDisplayState"] = _f23_safe_str(runtime.get("local_display_state"), "") or _F23_DISPLAYING
    base["adDisplayStartedAt"] = runtime.get("display_started_at") or gym_runtime.get("started_at")
    base["adExpectedFinishAt"] = gym_runtime.get("expected_finish_at")
    base["adValidationStrength"] = ad.get("validationStrength")
    base["adParticipatingBindingIds"] = ad.get("participatingBindingIds") or _f23_json_load(runtime.get("participating_binding_ids_json"), [])
    base["adFailedBindingIds"] = ad.get("failedBindingIds") or _f23_json_load(runtime.get("failed_binding_ids_json"), [])
    base["gymAdRuntime"] = gym_runtime
    return base


def list_tv_ad_task_runtime(*, gym_id: Optional[int] = None, campaign_task_id: Optional[int] = None, limit: int = 500, offset: int = 0) -> Dict[str, Any]:
    ensure_tv_local_schema()
    clauses: List[str] = []
    params: List[Any] = []
    if gym_id and gym_id > 0:
        clauses.append("r.gym_id=?")
        params.append(gym_id)
    if campaign_task_id and campaign_task_id > 0:
        clauses.append("r.campaign_task_id=?")
        params.append(campaign_task_id)
    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    lim = max(1, min(int(limit or 500), 5000))
    off = max(0, int(offset or 0))
    with get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT r.*, c.remote_status, c.local_preparation_state, c.expected_local_path, c.display_duration_sec
            FROM tv_ad_task_runtime r
            LEFT JOIN tv_ad_task_cache c ON c.campaign_task_id = r.campaign_task_id
            {where_sql}
            ORDER BY COALESCE(r.display_started_at, c.scheduled_at, r.updated_at) DESC, r.campaign_task_id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params + [lim, off]),
        ).fetchall()
        total = conn.execute(f"SELECT COUNT(*) AS c FROM tv_ad_task_runtime r {where_sql}", tuple(params)).fetchone()[0]
    out_rows: List[Dict[str, Any]] = []
    for raw in rows:
        row = _f23_row_dict(raw)
        row["participating_binding_ids"] = _f23_json_load(row.get("participating_binding_ids_json"), [])
        row["failed_binding_ids"] = _f23_json_load(row.get("failed_binding_ids_json"), [])
        out_rows.append(row)
    return {"rows": out_rows, "total": int(total or 0), "limit": lim, "offset": off}


def load_tv_ad_task_runtime(*, campaign_task_id: int) -> Optional[Dict[str, Any]]:
    ensure_tv_local_schema()
    if campaign_task_id <= 0:
        return None
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT r.*, c.remote_status, c.local_preparation_state, c.expected_local_path, c.display_duration_sec
            FROM tv_ad_task_runtime r
            LEFT JOIN tv_ad_task_cache c ON c.campaign_task_id = r.campaign_task_id
            WHERE r.campaign_task_id=?
            LIMIT 1
            """,
            (campaign_task_id,),
        ).fetchone()
    out = _f23_row_dict(row)
    if not out:
        return None
    out["participating_binding_ids"] = _f23_json_load(out.get("participating_binding_ids_json"), [])
    out["failed_binding_ids"] = _f23_json_load(out.get("failed_binding_ids_json"), [])
    return out


def load_tv_gym_ad_runtime(*, gym_id: int) -> Optional[Dict[str, Any]]:
    ensure_tv_local_schema()
    if gym_id <= 0:
        return None
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM tv_gym_ad_runtime WHERE gym_id=? LIMIT 1", (gym_id,)).fetchone()
    out = _f23_row_dict(row)
    if not out:
        return None
    out["participating_binding_ids"] = _f23_json_load(out.get("participating_binding_ids_json"), [])
    out["failed_binding_ids"] = _f23_json_load(out.get("failed_binding_ids_json"), [])
    return out


def inject_tv_ad_task_now(*, campaign_task_id: int, correlation_id: Optional[str] = None) -> Dict[str, Any]:
    ensure_tv_local_schema()
    if campaign_task_id <= 0:
        return {"ok": False, "error": "INVALID_TASK_ID"}
    with get_conn() as conn:
        task = _f23_load_task_cache_row(conn, campaign_task_id)
        if not task:
            return {"ok": False, "error": "TASK_NOT_FOUND"}
        remote_status = _f23_safe_str(task.get("remote_status"), "").strip().upper()
        if remote_status in _F23_REMOTE_TERMINAL:
            return {"ok": False, "error": "TASK_REMOTE_TERMINAL", "remoteStatus": remote_status}
        if not _f23_is_task_ready_local(task):
            return {"ok": False, "error": "TASK_NOT_LOCALLY_READY", "localPreparationState": task.get("local_preparation_state")}
        valid, reason, strength = _f23_validate_ad_asset(task)
        if not valid:
            return {"ok": False, "error": "TASK_ASSET_INVALID", "reason": reason}
        gym_id = _f23_safe_int(task.get("gym_id"), 0)
        if gym_id <= 0:
            return {"ok": False, "error": "TASK_GYM_NOT_RESOLVED"}

        lock = _f23_get_gym_lock(gym_id)
        with lock:
            current = _f23_load_gym_runtime_row(conn, gym_id)
            current_task_id = _f23_safe_int(current.get("current_campaign_task_id"), 0)
            if current_task_id > 0 and current_task_id != campaign_task_id:
                return {"ok": False, "error": "GYM_SINGLE_FLIGHT_ACTIVE", "activeTaskId": current_task_id}
            resolved = _f23_reconcile_gym_runtime(conn, gym_id=gym_id, force_task_id=campaign_task_id)
            conn.commit()

        active_task = _f23_row_dict(resolved.get("task"))
        if _f23_safe_int(active_task.get("campaign_task_id"), 0) != campaign_task_id:
            return {"ok": False, "error": "TASK_NOT_INJECTED", "reason": resolved.get("reason")}
        return {
            "ok": True,
            "result": "DISPLAYING",
            "campaignTaskId": campaign_task_id,
            "gymId": gym_id,
            "runtime": load_tv_ad_task_runtime(campaign_task_id=campaign_task_id),
            "gymRuntime": load_tv_gym_ad_runtime(gym_id=gym_id),
            "correlationId": correlation_id,
            "validationStrength": strength,
        }


def abort_tv_ad_task_now(*, campaign_task_id: int, reason: str = "MANUAL_ABORT", correlation_id: Optional[str] = None) -> Dict[str, Any]:
    """Abort a currently-displaying ad task from support/admin UI."""
    ensure_tv_local_schema()
    if campaign_task_id <= 0:
        return {"ok": False, "error": "INVALID_TASK_ID"}
    with get_conn() as conn:
        task = _f23_load_task_cache_row(conn, campaign_task_id)
        if not task:
            return {"ok": False, "error": "TASK_NOT_FOUND"}
        gym_id = _f23_safe_int(task.get("gym_id"), 0)
        if gym_id <= 0:
            return {"ok": False, "error": "TASK_GYM_NOT_RESOLVED"}

        lock = _f23_get_gym_lock(gym_id)
        with lock:
            rt = _f23_load_task_runtime_row(conn, campaign_task_id)
            rt_state = _f23_safe_str(rt.get("local_display_state"), "")
            if rt_state in _F23_TERMINAL_DISPLAY_STATES:
                return {"ok": False, "error": "TASK_ALREADY_TERMINAL", "localDisplayState": rt_state}

            gym_runtime = _f23_load_gym_runtime_row(conn, gym_id)
            current_task_id = _f23_safe_int(gym_runtime.get("current_campaign_task_id"), 0)
            now_iso = _f23_iso_utc()
            participants = _f23_json_load(rt.get("participating_binding_ids_json"), []) if rt else []
            failed = _f23_json_load(rt.get("failed_binding_ids_json"), []) if rt else []

            abort_rt = _f23_upsert_task_runtime(
                conn,
                task,
                local_display_state=_F23_DISPLAY_ABORTED,
                currently_injected=False,
                display_aborted_at=now_iso,
                display_abort_reason=reason,
                participating_binding_ids=participants,
                failed_binding_ids=failed,
            )
            _f24_create_proof_from_terminal(
                conn, task=task, task_runtime=abort_rt, gym_runtime=gym_runtime,
                terminal_display_state=_F23_DISPLAY_ABORTED,
            )
            if current_task_id == campaign_task_id:
                _f23_clear_gym_runtime(conn, gym_id)
            conn.commit()

    return {
        "ok": True,
        "result": "ABORTED",
        "campaignTaskId": campaign_task_id,
        "gymId": gym_id,
        "reason": reason,
        "runtime": load_tv_ad_task_runtime(campaign_task_id=campaign_task_id),
        "gymRuntime": load_tv_gym_ad_runtime(gym_id=gym_id),
        "correlationId": correlation_id,
    }


def startup_recover_ad_runtime() -> Dict[str, Any]:
    """F27: Startup recovery for ad runtime state after crash or restart.

    Repairs transient states that were left mid-flight:
    - SENDING proof outbox rows reset to FAILED_RETRYABLE (safe retry on restart)
    - Gym runtimes in INJECTING state (not yet displaying) reset to IDLE
    - Gym runtimes in COMPLETING state are checked for existing proof; if missing, proof outbox
      rows are queued for retry; gym is then cleared to IDLE
    All actions are safe and idempotent.
    """
    ensure_tv_local_schema()
    now_iso = _f23_iso_utc()
    result: Dict[str, Any] = {"proofSendingReset": 0, "injectingReset": 0, "completingRecovered": 0}

    with get_conn() as conn:
        # 1. Reset SENDING → FAILED_RETRYABLE so proof outbox retries after crash
        cur = conn.execute(
            "UPDATE tv_ad_proof_outbox SET outbox_state=?, next_attempt_at=?, updated_at=? WHERE outbox_state=?",
            (_F24_OUTBOX_FAILED_RETRYABLE, now_iso, now_iso, _F24_OUTBOX_SENDING),
        )
        result["proofSendingReset"] = cur.rowcount

        # 2. Reset INJECTING gym runtimes to IDLE — we never started displaying
        injecting_rows = conn.execute(
            "SELECT * FROM tv_gym_ad_runtime WHERE coordination_state=?",
            (_F23_COORD_INJECTING,),
        ).fetchall()
        for raw in injecting_rows:
            gym = _f23_row_dict(raw)
            gym_id = _f23_safe_int(gym.get("gym_id"), 0)
            if gym_id > 0:
                _f23_clear_gym_runtime(conn, gym_id)
                result["injectingReset"] += 1

        # 3. For COMPLETING gym runtimes — display finished but proof may not have been created yet.
        # Check if proof exists; if not, mark the task runtime ABORTED so proof is created on next reconcile.
        completing_rows = conn.execute(
            "SELECT * FROM tv_gym_ad_runtime WHERE coordination_state=?",
            (_F23_COORD_COMPLETING,),
        ).fetchall()
        for raw in completing_rows:
            gym = _f23_row_dict(raw)
            gym_id = _f23_safe_int(gym.get("gym_id"), 0)
            task_id = _f23_safe_int(gym.get("current_campaign_task_id"), 0)
            if gym_id <= 0 or task_id <= 0:
                if gym_id > 0:
                    _f23_clear_gym_runtime(conn, gym_id)
                continue
            existing_proof = conn.execute(
                "SELECT 1 FROM tv_ad_proof_outbox WHERE campaign_task_id=? LIMIT 1", (task_id,)
            ).fetchone()
            if not existing_proof:
                # Proof not yet created — mark task runtime as aborted so next reconcile creates proof
                task = _f23_load_task_cache_row(conn, task_id)
                rt = _f23_load_task_runtime_row(conn, task_id)
                if task and rt and _f23_safe_str(rt.get("local_display_state"), "") not in _F23_TERMINAL_DISPLAY_STATES:
                    abort_rt = _f23_upsert_task_runtime(
                        conn, task,
                        local_display_state=_F23_DISPLAY_ABORTED,
                        currently_injected=False,
                        display_aborted_at=now_iso,
                        display_abort_reason="STARTUP_RECOVERY_COMPLETING",
                        display_abort_message="Crash during COMPLETING state; proof re-created on recovery",
                        participating_binding_ids=_f23_json_load(rt.get("participating_binding_ids_json"), []),
                        failed_binding_ids=_f23_json_load(rt.get("failed_binding_ids_json"), []),
                        correlation_id=_f23_safe_str(rt.get("correlation_id"), "") or None,
                    )
                    _f24_create_proof_from_terminal(
                        conn, task=task, task_runtime=abort_rt, gym_runtime=gym,
                        terminal_display_state=_F23_DISPLAY_ABORTED,
                    )
            _f23_clear_gym_runtime(conn, gym_id)
            result["completingRecovered"] += 1

        conn.commit()

    return {"ok": True, **result}


def reconcile_all_active_gyms() -> Dict[str, Any]:
    """Tick function: reconcile ad runtime for every gym that has active or pending ad tasks.

    Should be called periodically (e.g. every 10-30s) to advance display states,
    mark completed/missed tasks, and handle remote terminal precedence without
    waiting for a render context request.
    """
    ensure_tv_local_schema()
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT gym_id FROM (
                SELECT gym_id FROM tv_gym_ad_runtime WHERE coordination_state NOT IN ('IDLE')
                UNION
                SELECT gym_id FROM tv_ad_task_runtime WHERE local_display_state NOT IN ('DISPLAY_COMPLETED_LOCAL','DISPLAY_ABORTED_LOCAL','SKIPPED_WINDOW_MISSED','CANCELLED_REMOTE','EXPIRED_REMOTE')
                UNION
                SELECT gym_id FROM tv_ad_task_cache WHERE remote_status NOT IN ('CANCELLED','EXPIRED','DONE','FAILED')
            )
            """,
        ).fetchall()
    gym_ids = sorted({_f23_safe_int(r[0] if isinstance(r, (tuple, list)) else (r.get("gym_id") if isinstance(r, dict) else r), 0) for r in rows})
    gym_ids = [g for g in gym_ids if g > 0]
    results: List[Dict[str, Any]] = []
    for gym_id in gym_ids:
        lock = _f23_get_gym_lock(gym_id)
        with lock:
            with get_conn() as conn:
                resolved = _f23_reconcile_gym_runtime(conn, gym_id=gym_id)
                conn.commit()
        gym_runtime = _f23_row_dict(resolved.get("gymRuntime"))
        task = _f23_row_dict(resolved.get("task"))
        results.append({
            "gymId": gym_id,
            "coordinationState": gym_runtime.get("coordination_state"),
            "activeTaskId": _f23_safe_int(task.get("campaign_task_id"), 0) or None,
        })
    return {"ok": True, "gymsReconciled": len(results), "results": results}


# ── F24: Public proof / outbox functions ────────────────────────────

def list_tv_ad_proof_outbox(
    *,
    gym_id: Optional[int] = None,
    campaign_task_id: Optional[int] = None,
    outbox_states: Optional[List[str]] = None,
    limit: int = 300,
    offset: int = 0,
) -> Dict[str, Any]:
    """List local proof outbox rows with optional filters."""
    ensure_tv_local_schema()
    clauses: List[str] = []
    params: List[Any] = []
    if gym_id and gym_id > 0:
        clauses.append("p.gym_id=?")
        params.append(gym_id)
    if campaign_task_id and campaign_task_id > 0:
        clauses.append("p.campaign_task_id=?")
        params.append(campaign_task_id)
    if outbox_states:
        placeholders = ",".join("?" for _ in outbox_states)
        clauses.append(f"p.outbox_state IN ({placeholders})")
        params.extend(outbox_states)
    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    lim = max(1, min(int(limit or 300), 5000))
    off = max(0, int(offset or 0))
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT p.* FROM tv_ad_proof_outbox p {where_sql} ORDER BY p.created_at DESC LIMIT ? OFFSET ?",
            tuple(params + [lim, off]),
        ).fetchall()
        total = conn.execute(
            f"SELECT COUNT(*) FROM tv_ad_proof_outbox p {where_sql}", tuple(params)
        ).fetchone()[0]
    out_rows = [_f23_row_dict(r) for r in rows]
    return {"rows": out_rows, "total": int(total or 0), "limit": lim, "offset": off}


def load_tv_ad_proof(*, local_proof_id: int) -> Optional[Dict[str, Any]]:
    """Load a single proof outbox row by local ID."""
    ensure_tv_local_schema()
    if local_proof_id <= 0:
        return None
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM tv_ad_proof_outbox WHERE local_proof_id=? LIMIT 1",
            (local_proof_id,),
        ).fetchone()
    return _f23_row_dict(row) or None


def _f24_build_proof_payload(proof: Dict[str, Any]) -> Dict[str, Any]:
    """Build the JSON payload to send to the backend proof endpoint."""
    return {
        "idempotencyKey": _f23_safe_str(proof.get("idempotency_key"), ""),
        "correlationId": _f23_safe_str(proof.get("correlation_id"), ""),
        "startedAt": proof.get("started_at"),
        "finishedAt": proof.get("finished_at"),
        "displayedDurationSec": _f23_safe_int(proof.get("displayed_duration_sec"), 0),
        "expectedDurationSec": _f23_safe_int(proof.get("expected_duration_sec"), 0),
        "completedFully": _f23_safe_bool(proof.get("completed_fully"), False),
        "countable": _f23_safe_bool(proof.get("countable"), False),
        "resultStatus": _f23_safe_str(proof.get("result_status"), "ABORTED"),
        "reasonIfNotCountable": proof.get("reason_if_not_countable"),
        "participatingBindingCount": _f23_safe_int(proof.get("participating_binding_count"), 0) or None,
        "failedBindingCount": _f23_safe_int(proof.get("failed_binding_count"), 0) or None,
    }


def _f24_send_single_proof(app: Any, proof: Dict[str, Any]) -> Dict[str, Any]:
    """Try to send a single proof to the backend. Returns {ok, retryable, error?}."""
    local_proof_id = _f23_safe_int(proof.get("local_proof_id"), 0)
    campaign_task_id = _f23_safe_int(proof.get("campaign_task_id"), 0)
    if local_proof_id <= 0 or campaign_task_id <= 0:
        return {"ok": False, "retryable": False, "error": "INVALID_IDS"}

    now_iso = _f23_iso_utc()

    # Mark as SENDING
    with get_conn() as conn:
        conn.execute(
            "UPDATE tv_ad_proof_outbox SET outbox_state=?, updated_at=? WHERE local_proof_id=?",
            (_F24_OUTBOX_SENDING, now_iso, local_proof_id),
        )
        conn.commit()

    payload = _f24_build_proof_payload(proof)

    try:
        token = app.get_token() if hasattr(app, "get_token") else ""
        api = app.api if hasattr(app, "api") else None
        if api is None:
            raise RuntimeError("app.api not available")

        result = api.submit_tv_ad_task_proof(
            token=token,
            task_id=campaign_task_id,
            payload=payload,
            timeout=20,
        )

        # Success
        with get_conn() as conn:
            conn.execute(
                """UPDATE tv_ad_proof_outbox
                   SET outbox_state=?, backend_proof_id=?, backend_task_status=?,
                       attempt_count=attempt_count+1, last_error=NULL, updated_at=?
                   WHERE local_proof_id=?""",
                (
                    _F24_OUTBOX_SENT,
                    result.get("proofId"),
                    result.get("taskStatus"),
                    _f23_iso_utc(),
                    local_proof_id,
                ),
            )
            conn.commit()
        return {"ok": True, "result": result}

    except Exception as e:
        error_str = str(e)[:500]
        status_code = getattr(e, "status_code", 0)
        retryable = True
        if isinstance(status_code, int) and 400 <= status_code < 500:
            retryable = False

        attempt_count = _f23_safe_int(proof.get("attempt_count"), 0) + 1
        if attempt_count >= _F24_OUTBOX_MAX_ATTEMPTS:
            retryable = False

        new_state = _F24_OUTBOX_FAILED_RETRYABLE if retryable else _F24_OUTBOX_FAILED_TERMINAL
        next_at = _f24_compute_next_attempt(attempt_count) if retryable else None

        with get_conn() as conn:
            conn.execute(
                """UPDATE tv_ad_proof_outbox
                   SET outbox_state=?, attempt_count=?, next_attempt_at=?,
                       last_error=?, updated_at=?
                   WHERE local_proof_id=?""",
                (new_state, attempt_count, next_at, error_str, _f23_iso_utc(), local_proof_id),
            )
            conn.commit()
        return {"ok": False, "retryable": retryable, "error": error_str}


def process_tv_ad_proof_outbox(
    *,
    app: Any,
    limit: int = 50,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Process pending proof outbox rows: send to backend with retry."""
    ensure_tv_local_schema()
    now_iso = _f23_iso_utc()
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT * FROM tv_ad_proof_outbox
               WHERE outbox_state IN (?, ?)
                 AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
               ORDER BY created_at ASC
               LIMIT ?""",
            (_F24_OUTBOX_QUEUED, _F24_OUTBOX_FAILED_RETRYABLE, now_iso, max(1, min(limit, 200))),
        ).fetchall()

    proofs = [_f23_row_dict(r) for r in rows]
    sent = 0
    failed = 0
    for proof in proofs:
        result = _f24_send_single_proof(app, proof)
        if result.get("ok"):
            sent += 1
        else:
            failed += 1

    return {
        "ok": True,
        "processed": len(proofs),
        "sent": sent,
        "failed": failed,
        "correlationId": correlation_id,
    }


def retry_tv_ad_proof(*, app: Any, local_proof_id: int) -> Dict[str, Any]:
    """Retry sending a single proof row (even if FAILED_TERMINAL)."""
    ensure_tv_local_schema()
    if local_proof_id <= 0:
        return {"ok": False, "error": "INVALID_PROOF_ID"}
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM tv_ad_proof_outbox WHERE local_proof_id=? LIMIT 1",
            (local_proof_id,),
        ).fetchone()
    proof = _f23_row_dict(row)
    if not proof:
        return {"ok": False, "error": "PROOF_NOT_FOUND"}
    if _f23_safe_str(proof.get("outbox_state"), "") == _F24_OUTBOX_SENT:
        return {"ok": True, "alreadySent": True}

    result = _f24_send_single_proof(app, proof)
    return {"ok": result.get("ok", False), "sendResult": result}

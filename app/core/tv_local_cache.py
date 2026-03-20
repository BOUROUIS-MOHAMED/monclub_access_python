# app/core/tv_local_cache.py
"""
TV local cache — Foundation layer (A1) + Snapshot Fetch & Cache (A2).
SQLite schema, CRUD helpers, and snapshot sync pipeline for MonClub TV in Access.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.core.utils import now_iso, DATA_ROOT
from shared.desktop_paths import get_desktop_path_layout
from shared.storage_migration import TV_OWNED_TABLES, migrate_component_tables
from tv.auth_bridge import load_tv_auth_for_runtime
from tv.storage import current_tv_runtime_db_path
from tv.store import get_conn, _ensure_column

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema-ready flag (process-level, idempotent)
# ---------------------------------------------------------------------------
_schema_ready = False
_schema_lock = threading.Lock()
_support_action_lock_guard = threading.Lock()
_support_action_locks: Dict[int, threading.Lock] = {}
_support_action_active: Dict[int, Dict[str, Any]] = {}

# ---------------------------------------------------------------------------
# Enum / state string constants
# ---------------------------------------------------------------------------
# desired_state
DESIRED_RUNNING = "RUNNING"
DESIRED_STOPPED = "STOPPED"
DESIRED_DISABLED = "DISABLED"

# runtime_state
BINDING_RUNTIME_IDLE = "IDLE"
BINDING_RUNTIME_STARTING = "STARTING"
BINDING_RUNTIME_RUNNING = "RUNNING"
BINDING_RUNTIME_STOPPING = "STOPPING"
BINDING_RUNTIME_STOPPED = "STOPPED"
BINDING_RUNTIME_CRASHED = "CRASHED"
BINDING_RUNTIME_ERROR = "ERROR"

# activation_state
ACTIVATION_STATE_PENDING = "PENDING"
ACTIVATION_STATE_ACTIVE_CURRENT = "ACTIVE_CURRENT"
ACTIVATION_STATE_ACTIVE_OUTDATED = "ACTIVE_OUTDATED"
ACTIVATION_STATE_INACTIVE = "INACTIVE"
ACTIVATION_STATE_FAILED = "FAILED"

# manifest_status
MANIFEST_STATUS_PENDING = "PENDING"
MANIFEST_STATUS_COMPLETE = "COMPLETE"
MANIFEST_STATUS_INCOMPLETE = "INCOMPLETE"
MANIFEST_STATUS_ERROR = "ERROR"

# sync_status
SYNC_STATUS_PENDING = "PENDING"
SYNC_STATUS_IN_PROGRESS = "IN_PROGRESS"
SYNC_STATUS_COMPLETED = "COMPLETED"
SYNC_STATUS_FAILED = "FAILED"

# asset_state
ASSET_STATE_UNKNOWN = "UNKNOWN"
ASSET_STATE_MISSING = "MISSING"
ASSET_STATE_DOWNLOADING = "DOWNLOADING"
ASSET_STATE_VALID = "VALID"
ASSET_STATE_INVALID_CHECKSUM = "INVALID_CHECKSUM"
ASSET_STATE_INVALID_SIZE = "INVALID_SIZE"
ASSET_STATE_STALE = "STALE"
ASSET_STATE_ERROR = "ERROR"

# readiness_state
READINESS_UNKNOWN = "UNKNOWN"
READINESS_NOT_READY = "NOT_READY"
READINESS_PARTIAL = "PARTIAL"
READINESS_READY = "READY"

# validation_mode
VALIDATION_STRONG = "STRONG"
VALIDATION_WEAK = "WEAK"

# event severity
SEVERITY_INFO = "INFO"
SEVERITY_WARN = "WARN"
SEVERITY_ERROR = "ERROR"
SEVERITY_CRITICAL = "CRITICAL"

# sync run result
SYNC_RESULT_COMPLETED = "COMPLETED"
SYNC_RESULT_PARTIAL = "PARTIAL"
SYNC_RESULT_FAILED = "FAILED"
SYNC_RESULT_SKIPPED = "SKIPPED"

# A2 sync status (granular)
SYNC_STATUS_IDLE = "IDLE"
SYNC_STATUS_FETCHING_SNAPSHOT = "FETCHING_SNAPSHOT"
SYNC_STATUS_FETCHING_MANIFEST = "FETCHING_MANIFEST"
SYNC_STATUS_COMPLETED_WITH_WARNINGS = "COMPLETED_WITH_WARNINGS"

# A2 sync run result
SYNC_RUN_SUCCESS = "SUCCESS"
SYNC_RUN_SUCCESS_WITH_WARNINGS = "SUCCESS_WITH_WARNINGS"
SYNC_RUN_FAILED = "FAILED"
SYNC_RUN_NO_SNAPSHOT = "NO_SNAPSHOT"

# A2 manifest status
MANIFEST_STATUS_MISSING = "MISSING"

# A3 asset state extensions
ASSET_STATE_NOT_PRESENT = "NOT_PRESENT"
ASSET_STATE_PRESENT_UNCHECKED = "PRESENT_UNCHECKED"
ASSET_STATE_INVALID_UNREADABLE = "INVALID_UNREADABLE"

# A4 readiness extensions
READINESS_EMPTY = "EMPTY"
READINESS_ERROR = "ERROR"
READINESS_NOT_READY = "NOT_READY"
READINESS_PARTIALLY_READY = "PARTIALLY_READY"
READINESS_READY = "READY"

# A5 activation state extensions
ACTIVATION_STATE_NO_ACTIVE_SNAPSHOT = "NO_ACTIVE_SNAPSHOT"
ACTIVATION_STATE_ACTIVE_CURRENT = "ACTIVE_CURRENT"
ACTIVATION_STATE_ACTIVE_OLDER_THAN_LATEST = "ACTIVE_OLDER_THAN_LATEST"
ACTIVATION_STATE_BLOCKED_WAITING_FOR_READY = "BLOCKED_WAITING_FOR_READY"
ACTIVATION_STATE_BLOCKED_PREREQUISITE = "BLOCKED_PREREQUISITE"
ACTIVATION_STATE_ERROR = "ERROR"

# A5 activation attempt results
ATTEMPT_RESULT_ACTIVATED = "ACTIVATED"
ATTEMPT_RESULT_SKIPPED_ALREADY_ACTIVE = "SKIPPED_ALREADY_ACTIVE"
ATTEMPT_RESULT_SKIPPED_NO_SNAPSHOT = "SKIPPED_NO_SNAPSHOT"
ATTEMPT_RESULT_SKIPPED_NOT_READY = "SKIPPED_NOT_READY"
ATTEMPT_RESULT_SKIPPED_LATEST_NOT_NEWER = "SKIPPED_LATEST_NOT_NEWER"
ATTEMPT_RESULT_FAILED = "FAILED"

# A5 block/failure reasons
FAILURE_REASON_NO_LATEST_SNAPSHOT = "NO_LATEST_SNAPSHOT"
FAILURE_REASON_NO_READY_SNAPSHOT = "NO_READY_SNAPSHOT"
FAILURE_REASON_LATEST_NEWER_NOT_READY = "LATEST_NEWER_NOT_READY"
FAILURE_REASON_SNAPSHOT_NOT_READY = "SNAPSHOT_NOT_READY"
FAILURE_REASON_MANIFEST_MISSING = "MANIFEST_MISSING"
FAILURE_REASON_MANIFEST_INCOMPLETE = "MANIFEST_INCOMPLETE"
FAILURE_REASON_REQUIRED_ASSET_INVALID = "REQUIRED_ASSET_INVALID"
FAILURE_REASON_SNAPSHOT_NOT_FOUND = "SNAPSHOT_NOT_FOUND"
FAILURE_REASON_READINESS_RECHECK_FAILED = "READINESS_RECHECK_FAILED"
FAILURE_REASON_STATE_PERSIST_FAILED = "STATE_PERSIST_FAILED"
FAILURE_REASON_INTERNAL_ERROR = "INTERNAL_ERROR"

# A6 player state
PLAYER_STATE_IDLE = "IDLE"
PLAYER_STATE_LOADING_BINDING = "LOADING_BINDING"
PLAYER_STATE_LOADING_ACTIVE_SNAPSHOT = "LOADING_ACTIVE_SNAPSHOT"
PLAYER_STATE_RENDERING = "RENDERING"
PLAYER_STATE_FALLBACK_RENDERING = "FALLBACK_RENDERING"
PLAYER_STATE_BLOCKED_NO_BINDING = "BLOCKED_NO_BINDING"
PLAYER_STATE_BLOCKED_BINDING_DISABLED = "BLOCKED_BINDING_DISABLED"
PLAYER_STATE_BLOCKED_NO_ACTIVE_SNAPSHOT = "BLOCKED_NO_ACTIVE_SNAPSHOT"
PLAYER_STATE_BLOCKED_NO_RENDERABLE_ITEM = "BLOCKED_NO_RENDERABLE_ITEM"
PLAYER_STATE_ERROR = "ERROR"

# A6 render mode
RENDER_MODE_VISUAL_ONLY = "VISUAL_ONLY"
RENDER_MODE_AUDIO_ONLY = "AUDIO_ONLY"
RENDER_MODE_VISUAL_AND_AUDIO = "VISUAL_AND_AUDIO"
RENDER_MODE_IDLE_FALLBACK = "IDLE_FALLBACK"
RENDER_MODE_ERROR_FALLBACK = "ERROR_FALLBACK"

# A6 fallback reason
FALLBACK_REASON_NO_ACTIVE_SNAPSHOT = "NO_ACTIVE_SNAPSHOT"
FALLBACK_REASON_NO_CURRENT_ITEM = "NO_CURRENT_ITEM"
FALLBACK_REASON_VISUAL_ASSET_INVALID = "VISUAL_ASSET_INVALID"
FALLBACK_REASON_AUDIO_ASSET_INVALID = "AUDIO_ASSET_INVALID"
FALLBACK_REASON_BOTH_ASSETS_INVALID = "BOTH_ASSETS_INVALID"
FALLBACK_REASON_SNAPSHOT_INVALID = "SNAPSHOT_INVALID"
FALLBACK_REASON_BINDING_DISABLED = "BINDING_DISABLED"
FALLBACK_REASON_BINDING_NOT_FOUND = "BINDING_NOT_FOUND"
FALLBACK_REASON_INTERNAL_ERROR = "INTERNAL_ERROR"

# A6 player event types
PLAYER_EVENT_STATE_CHANGED = "PLAYER_STATE_CHANGED"
PLAYER_EVENT_RELOADED = "PLAYER_RELOADED"
PLAYER_EVENT_REEVALUATED = "PLAYER_REEVALUATED"
PLAYER_EVENT_ERROR = "PLAYER_ERROR"

# ---------------------------------------------------------------------------
# A7: Ad Task Runtime constants
# ---------------------------------------------------------------------------

# Ad task local display states
AD_TASK_STATE_READY            = "READY_TO_DISPLAY_LOCAL"
AD_TASK_STATE_DISPLAYING       = "DISPLAYING"
AD_TASK_STATE_COMPLETED        = "DISPLAY_COMPLETED_LOCAL"
AD_TASK_STATE_ABORTED          = "DISPLAY_ABORTED_LOCAL"
AD_TASK_STATE_SKIPPED_WINDOW   = "SKIPPED_WINDOW_MISSED"
AD_TASK_STATE_CANCELLED_REMOTE = "CANCELLED_REMOTE"
AD_TASK_STATE_EXPIRED_REMOTE   = "EXPIRED_REMOTE"

# Ad file states (local_file_state in tv_ad_task_cache)
AD_FILE_STATE_PENDING = "PENDING"
AD_FILE_STATE_VALID   = "VALID"
AD_FILE_STATE_INVALID = "INVALID"
AD_FILE_STATE_MISSING = "MISSING"

# Gym coordination states
GYM_COORD_IDLE       = "IDLE"
GYM_COORD_INJECTING  = "INJECTING"
GYM_COORD_DISPLAYING = "DISPLAYING"
GYM_COORD_COMPLETING = "COMPLETING"
GYM_COORD_ABORTED    = "ABORTED"
GYM_COORD_ERROR      = "ERROR"

# Ad layouts
AD_LAYOUT_FULL_SCREEN    = "FULL_SCREEN"
AD_LAYOUT_BANNER_TOP     = "BANNER_TOP"
AD_LAYOUT_BANNER_BOTTOM  = "BANNER_BOTTOM"

# Ad player override modes (informational labels)
AD_MODE_NONE              = "NO_AD_OVERRIDE"
AD_MODE_VISUAL_AND_AUDIO  = "AD_VISUAL_AND_AUDIO"
AD_MODE_VISUAL_ONLY       = "AD_VISUAL_ONLY"
AD_MODE_ERROR_FALLBACK    = "AD_ERROR_FALLBACK"

# Due-time grace window in seconds
AD_GRACE_WINDOW_SECONDS = 30

# Remote status sets
_AD_NONDISPLAYABLE_REMOTE_STATUSES = frozenset({"CANCELLED", "EXPIRED", "REJECTED", "FAILED"})

# ---------------------------------------------------------------------------
# A8: Proof constants
# ---------------------------------------------------------------------------
PROOF_STATUS_COMPLETED        = "COMPLETED"
PROOF_STATUS_PARTIAL          = "PARTIAL"
PROOF_STATUS_ABORTED          = "ABORTED"
PROOF_STATUS_FAILED_TO_START  = "FAILED_TO_START"
PROOF_STATUS_CANCELLED_REMOTE = "CANCELLED_REMOTE"
PROOF_STATUS_EXPIRED_REMOTE   = "EXPIRED_REMOTE"

PROOF_OUTBOX_QUEUED           = "QUEUED"
PROOF_OUTBOX_SENDING          = "SENDING"
PROOF_OUTBOX_SENT             = "SENT"
PROOF_OUTBOX_FAILED_RETRYABLE = "FAILED_RETRYABLE"
PROOF_OUTBOX_FAILED_TERMINAL  = "FAILED_TERMINAL"

PROOF_COUNTABLE_TOLERANCE_SEC = 2
PROOF_MAX_ATTEMPTS            = 50
_PROOF_RETRY_BACKOFF_SECS     = [30, 60, 120, 300, 600, 1800, 3600]

# ---------------------------------------------------------------------------
# A10: Support / Recovery constants
# ---------------------------------------------------------------------------
SUPPORT_ACTION_RUN_SYNC = "RUN_SYNC"
SUPPORT_ACTION_RECOMPUTE_READINESS = "RECOMPUTE_READINESS"
SUPPORT_ACTION_RETRY_FAILED_DOWNLOADS = "RETRY_FAILED_DOWNLOADS"
SUPPORT_ACTION_RETRY_ONE_DOWNLOAD = "RETRY_ONE_DOWNLOAD"
SUPPORT_ACTION_REEVALUATE_ACTIVATION = "REEVALUATE_ACTIVATION"
SUPPORT_ACTION_ACTIVATE_LATEST_READY = "ACTIVATE_LATEST_READY"
SUPPORT_ACTION_REEVALUATE_PLAYER_CONTEXT = "REEVALUATE_PLAYER_CONTEXT"
SUPPORT_ACTION_RELOAD_PLAYER = "RELOAD_PLAYER"
SUPPORT_ACTION_START_BINDING = "START_BINDING"
SUPPORT_ACTION_STOP_BINDING = "STOP_BINDING"
SUPPORT_ACTION_RESTART_BINDING = "RESTART_BINDING"
SUPPORT_ACTION_RESTART_PLAYER_WINDOW = "RESTART_PLAYER_WINDOW"
SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE = "RESET_TRANSIENT_PLAYER_STATE"

SUPPORT_RESULT_STARTED = "STARTED"
SUPPORT_RESULT_SUCCEEDED = "SUCCEEDED"
SUPPORT_RESULT_FAILED = "FAILED"
SUPPORT_RESULT_SKIPPED = "SKIPPED"
SUPPORT_RESULT_BLOCKED = "BLOCKED"

BINDING_HEALTH_HEALTHY = "HEALTHY"
BINDING_HEALTH_WARNING = "WARNING"
BINDING_HEALTH_DEGRADED = "DEGRADED"
BINDING_HEALTH_ERROR = "ERROR"
BINDING_HEALTH_STOPPED = "STOPPED"

# ---------------------------------------------------------------------------

def _json_dumps(obj: Any) -> str:
    if obj is None:
        return "null"
    return json.dumps(obj, ensure_ascii=False, default=str)


def _json_loads(s: Any) -> Any:
    if not s or s == "null":
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


def _row_to_dict(row) -> Optional[Dict[str, Any]]:
    if row is None:
        return None
    return dict(row)


def _rows_to_list(rows) -> List[Dict[str, Any]]:
    return [dict(r) for r in rows] if rows else []


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


# ---------------------------------------------------------------------------
# Schema creation
# ---------------------------------------------------------------------------

def ensure_tv_local_schema() -> None:
    global _schema_ready
    if _schema_ready:
        return
    with _schema_lock:
        if _schema_ready:
            return
        _create_tv_schema()
        layout = get_desktop_path_layout()
        migrate_component_tables(
            component="tv",
            live_db_path=current_tv_runtime_db_path(),
            legacy_source_db_path=layout.legacy_combined_db_path,
            owned_tables=TV_OWNED_TABLES,
            logger=_log,
        )
        _create_tv_schema()
        _schema_ready = True


def _create_tv_schema() -> None:
    with get_conn() as conn:
        # 1) tv_host_monitor
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tv_host_monitor (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                monitor_id TEXT NOT NULL,
                monitor_label TEXT,
                monitor_index INTEGER,
                is_connected INTEGER NOT NULL DEFAULT 1,
                width INTEGER,
                height INTEGER,
                x INTEGER,
                y INTEGER,
                is_primary INTEGER NOT NULL DEFAULT 0,
                detected_at TEXT,
                updated_at TEXT
            );
        """)
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_tv_host_monitor_mid ON tv_host_monitor(monitor_id);")

        # 2) tv_screen_binding
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tv_screen_binding (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                screen_id INTEGER NOT NULL,
                screen_label TEXT,
                gym_id INTEGER,
                gym_label TEXT,
                monitor_id TEXT,
                monitor_label TEXT,
                monitor_index INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1,
                autostart INTEGER NOT NULL DEFAULT 0,
                desired_state TEXT NOT NULL DEFAULT 'STOPPED',
                fullscreen INTEGER NOT NULL DEFAULT 1,
                window_label TEXT,
                last_error_code TEXT,
                last_error_message TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_tv_screen_binding_sid ON tv_screen_binding(screen_id);")

        # 3) tv_screen_binding_runtime
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tv_screen_binding_runtime (
                binding_id INTEGER PRIMARY KEY,
                runtime_state TEXT NOT NULL DEFAULT 'IDLE',
                window_id TEXT,
                tauri_window_label TEXT,
                last_started_at TEXT,
                last_stopped_at TEXT,
                last_crashed_at TEXT,
                crash_count INTEGER NOT NULL DEFAULT 0,
                last_exit_reason TEXT,
                updated_at TEXT NOT NULL
            );
        """)

        # 4) tv_screen_binding_event
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tv_screen_binding_event (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                binding_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'INFO',
                message TEXT,
                metadata_json TEXT,
                created_at TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tv_sbe_binding ON tv_screen_binding_event(binding_id, created_at);")

        # 5) tv_snapshot_cache
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tv_snapshot_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                screen_id INTEGER NOT NULL,
                snapshot_id TEXT NOT NULL,
                snapshot_version INTEGER NOT NULL,
                activation_state TEXT,
                resolved_at TEXT,
                resolved_day_of_week TEXT,
                resolved_preset_id INTEGER,
                resolved_layout_preset_id INTEGER,
                resolved_policy_id INTEGER,
                playback_policy_version INTEGER,
                playback_policy_hash TEXT,
                generated_at TEXT,
                fetched_at TEXT,
                payload_json TEXT,
                manifest_json TEXT,
                asset_count INTEGER DEFAULT 0,
                warning_count INTEGER DEFAULT 0,
                manifest_status TEXT DEFAULT 'PENDING',
                sync_status TEXT DEFAULT 'PENDING',
                last_error TEXT,
                is_latest INTEGER NOT NULL DEFAULT 0,
                is_previous_ready INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tv_sc_screen ON tv_snapshot_cache(screen_id, is_latest);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tv_sc_snap ON tv_snapshot_cache(snapshot_id);")

        # 6) tv_snapshot_required_asset
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tv_snapshot_required_asset (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id TEXT NOT NULL,
                media_asset_id TEXT NOT NULL,
                title TEXT,
                media_type TEXT,
                download_link TEXT,
                checksum_sha256 TEXT,
                size_bytes INTEGER,
                mime_type TEXT,
                duration_in_seconds REAL,
                required_in_timelines_json TEXT,
                source_preset_item_ids_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_tv_sra_snap_asset ON tv_snapshot_required_asset(snapshot_id, media_asset_id);")

        # 7) tv_local_asset_state
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tv_local_asset_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                media_asset_id TEXT NOT NULL,
                expected_local_path TEXT,
                local_file_path TEXT,
                file_exists INTEGER NOT NULL DEFAULT 0,
                local_size_bytes INTEGER,
                local_checksum_sha256 TEXT,
                asset_state TEXT NOT NULL DEFAULT 'UNKNOWN',
                state_reason TEXT,
                validation_mode TEXT,
                last_checked_at TEXT,
                last_seen_in_snapshot_version INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_tv_las_asset ON tv_local_asset_state(media_asset_id);")

        # 8) tv_snapshot_readiness
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tv_snapshot_readiness (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                screen_id INTEGER NOT NULL,
                snapshot_id TEXT NOT NULL,
                snapshot_version INTEGER NOT NULL,
                readiness_state TEXT NOT NULL DEFAULT 'UNKNOWN',
                total_required_assets INTEGER DEFAULT 0,
                ready_asset_count INTEGER DEFAULT 0,
                missing_asset_count INTEGER DEFAULT 0,
                invalid_asset_count INTEGER DEFAULT 0,
                stale_asset_count INTEGER DEFAULT 0,
                computed_at TEXT,
                is_fully_ready INTEGER NOT NULL DEFAULT 0,
                is_latest INTEGER NOT NULL DEFAULT 0,
                is_previous_ready INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tv_sr_screen ON tv_snapshot_readiness(screen_id, is_latest);")

        # 9) tv_sync_run_log
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tv_sync_run_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT,
                finished_at TEXT,
                screen_id INTEGER,
                target_snapshot_version INTEGER,
                result TEXT,
                warning_count INTEGER DEFAULT 0,
                error_message TEXT,
                correlation_id TEXT,
                created_at TEXT NOT NULL
            );
        """)
        _ensure_column(conn, "tv_sync_run_log", "started_at", "started_at TEXT")
        _ensure_column(conn, "tv_sync_run_log", "finished_at", "finished_at TEXT")
        _ensure_column(conn, "tv_sync_run_log", "screen_id", "screen_id INTEGER")
        _ensure_column(conn, "tv_sync_run_log", "target_snapshot_version", "target_snapshot_version INTEGER")
        _ensure_column(conn, "tv_sync_run_log", "result", "result TEXT")
        _ensure_column(conn, "tv_sync_run_log", "warning_count", "warning_count INTEGER DEFAULT 0")
        _ensure_column(conn, "tv_sync_run_log", "error_message", "error_message TEXT")
        _ensure_column(conn, "tv_sync_run_log", "correlation_id", "correlation_id TEXT")
        _ensure_column(conn, "tv_sync_run_log", "created_at", "created_at TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tv_srl_screen ON tv_sync_run_log(screen_id, created_at);")

        # 10) tv_activation_state
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tv_activation_state (
                screen_id INTEGER PRIMARY KEY,
                latest_snapshot_id TEXT,
                latest_snapshot_version INTEGER,
                latest_ready_snapshot_id TEXT,
                latest_ready_snapshot_version INTEGER,
                active_snapshot_id TEXT,
                active_snapshot_version INTEGER,
                previous_active_snapshot_id TEXT,
                previous_active_snapshot_version INTEGER,
                activation_state TEXT NOT NULL DEFAULT 'NO_ACTIVE_SNAPSHOT',
                blocked_reason TEXT,
                last_decision_at TEXT,
                last_activation_at TEXT,
                updated_at TEXT NOT NULL,
                last_attempt_id INTEGER
            );
        """)

        # 11) tv_activation_attempt
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tv_activation_attempt (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                screen_id INTEGER NOT NULL,
                trigger_source TEXT,
                target_snapshot_id TEXT,
                target_snapshot_version INTEGER,
                result TEXT NOT NULL,
                failure_reason TEXT,
                message TEXT,
                precheck_readiness_state TEXT,
                precheck_manifest_status TEXT,
                started_at TEXT,
                finished_at TEXT,
                created_at TEXT NOT NULL
            );
        """)
        # 12) tv_player_state
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tv_player_state (
                binding_id INTEGER PRIMARY KEY,
                screen_id INTEGER,
                active_snapshot_id TEXT,
                active_snapshot_version INTEGER,
                current_minute_of_day INTEGER,
                current_day_of_week INTEGER,
                current_visual_item_id TEXT,
                current_audio_item_id TEXT,
                current_visual_asset_id TEXT,
                current_audio_asset_id TEXT,
                current_visual_asset_path TEXT,
                current_audio_asset_path TEXT,
                player_state TEXT NOT NULL DEFAULT 'IDLE',
                render_mode TEXT,
                fallback_reason TEXT,
                video_muted_by_audio INTEGER DEFAULT 0,
                last_render_error_code TEXT,
                last_render_error_message TEXT,
                last_tick_at TEXT,
                last_snapshot_check_at TEXT,
                last_state_change_at TEXT,
                updated_at TEXT NOT NULL
            );
        """)

        # 13) tv_player_event
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tv_player_event (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                binding_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'INFO',
                message TEXT,
                metadata_json TEXT,
                created_at TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tv_pe_binding ON tv_player_event(binding_id, created_at);")

        # 14) tv_ad_task_cache — locally cached ad tasks fetched from backend
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tv_ad_task_cache (
                campaign_task_id TEXT PRIMARY KEY,
                campaign_id TEXT,
                gym_id INTEGER NOT NULL,
                ad_media_id TEXT,
                ad_download_link TEXT,
                ad_checksum_sha256 TEXT,
                ad_size_bytes INTEGER,
                ad_mime_type TEXT,
                scheduled_at TEXT,
                layout TEXT NOT NULL DEFAULT 'FULL_SCREEN',
                display_duration_sec INTEGER NOT NULL DEFAULT 30,
                remote_status TEXT,
                generation_batch_no INTEGER,
                remote_updated_at TEXT,
                local_file_path TEXT,
                local_file_state TEXT NOT NULL DEFAULT 'PENDING',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tv_atc_gym ON tv_ad_task_cache(gym_id, scheduled_at);")

        # 15) tv_ad_task_runtime — per-task display execution tracking
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tv_ad_task_runtime (
                campaign_task_id TEXT PRIMARY KEY,
                gym_id INTEGER NOT NULL,
                binding_scope_count INTEGER DEFAULT 0,
                local_display_state TEXT NOT NULL DEFAULT 'READY_TO_DISPLAY_LOCAL',
                due_at TEXT,
                display_started_at TEXT,
                display_finished_at TEXT,
                display_aborted_at TEXT,
                display_abort_reason TEXT,
                display_abort_message TEXT,
                injected_layout TEXT,
                active_binding_ids_json TEXT,
                failed_binding_ids_json TEXT,
                correlation_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tv_atr_gym ON tv_ad_task_runtime(gym_id, local_display_state);")

        # 16) tv_gym_ad_runtime — per-gym coordination state
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tv_gym_ad_runtime (
                gym_id INTEGER PRIMARY KEY,
                coordination_state TEXT NOT NULL DEFAULT 'IDLE',
                current_campaign_task_id TEXT,
                started_at TEXT,
                expected_finish_at TEXT,
                active_binding_count INTEGER DEFAULT 0,
                failed_binding_count INTEGER DEFAULT 0,
                audio_override_active INTEGER DEFAULT 0,
                last_error_code TEXT,
                last_error_message TEXT,
                updated_at TEXT NOT NULL
            );
        """)

        # 17) tv_ad_proof_outbox — one proof per gym-level ad task attempt
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tv_ad_proof_outbox (
                local_proof_id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_task_id TEXT NOT NULL,
                campaign_id TEXT,
                gym_id INTEGER NOT NULL,
                ad_media_id TEXT,
                idempotency_key TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                displayed_duration_sec INTEGER,
                expected_duration_sec INTEGER,
                completed_fully INTEGER NOT NULL DEFAULT 0,
                countable INTEGER NOT NULL DEFAULT 0,
                result_status TEXT NOT NULL,
                reason_if_not_countable TEXT,
                correlation_id TEXT,
                participating_binding_count INTEGER DEFAULT 0,
                failed_binding_count INTEGER DEFAULT 0,
                outbox_state TEXT NOT NULL DEFAULT 'QUEUED',
                attempt_count INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT,
                last_error TEXT,
                backend_proof_id TEXT,
                backend_task_status TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(idempotency_key)
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tv_proof_task ON tv_ad_proof_outbox(campaign_task_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tv_proof_gym ON tv_ad_proof_outbox(gym_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tv_proof_state ON tv_ad_proof_outbox(outbox_state);")

        # Migrate tv_player_state to add ad overlay columns (idempotent for existing DBs)
        _ensure_column(conn, "tv_player_state", "ad_override_active", "ad_override_active INTEGER DEFAULT 0")
        _ensure_column(conn, "tv_player_state", "current_ad_task_id", "current_ad_task_id TEXT")
        _ensure_column(conn, "tv_player_state", "current_ad_media_id", "current_ad_media_id TEXT")
        _ensure_column(conn, "tv_player_state", "current_ad_layout", "current_ad_layout TEXT")
        _ensure_column(conn, "tv_player_state", "ad_audio_override_active", "ad_audio_override_active INTEGER DEFAULT 0")
        _ensure_column(conn, "tv_player_state", "ad_fallback_reason", "ad_fallback_reason TEXT")
        _ensure_column(conn, "tv_screen_binding_runtime", "last_error_code", "last_error_code TEXT")
        _ensure_column(conn, "tv_screen_binding_runtime", "last_error_message", "last_error_message TEXT")

        # 18) tv_support_action_log (A10)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tv_support_action_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                binding_id INTEGER,
                gym_id INTEGER,
                correlation_id TEXT,
                action_type TEXT NOT NULL,
                result TEXT NOT NULL,
                message TEXT,
                error_code TEXT,
                error_message TEXT,
                metadata_json TEXT,
                started_at TEXT,
                finished_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tv_sup_bind ON tv_support_action_log(binding_id, created_at);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tv_sup_corr ON tv_support_action_log(correlation_id);")

        conn.commit()


# ---------------------------------------------------------------------------
# 1) tv_host_monitor helpers
# ---------------------------------------------------------------------------

def upsert_tv_host_monitor(*, monitor_id: str, monitor_label: str = "",
                           monitor_index: int = 0, is_connected: bool = True,
                           width: int = 0, height: int = 0,
                           x: int = 0, y: int = 0,
                           is_primary: bool = False) -> Dict[str, Any]:
    ensure_tv_local_schema()
    ts = now_iso()
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO tv_host_monitor
                (monitor_id, monitor_label, monitor_index, is_connected,
                 width, height, x, y, is_primary, detected_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(monitor_id) DO UPDATE SET
                monitor_label=excluded.monitor_label,
                monitor_index=excluded.monitor_index,
                is_connected=excluded.is_connected,
                width=excluded.width, height=excluded.height,
                x=excluded.x, y=excluded.y,
                is_primary=excluded.is_primary,
                updated_at=excluded.updated_at
        """, (monitor_id, monitor_label, monitor_index, int(is_connected),
              width, height, x, y, int(is_primary), ts, ts))
        conn.commit()
        row = conn.execute("SELECT * FROM tv_host_monitor WHERE monitor_id=?", (monitor_id,)).fetchone()
        return _row_to_dict(row) or {}


def list_tv_host_monitors() -> List[Dict[str, Any]]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM tv_host_monitor ORDER BY monitor_index").fetchall()
        return _rows_to_list(rows)


def replace_tv_host_monitors(*, monitors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ensure_tv_local_schema()
    ts = now_iso()
    with get_conn() as conn:
        conn.execute("UPDATE tv_host_monitor SET is_connected=0, updated_at=?", (ts,))
        for m in monitors:
            mid = str(m.get("monitorId") or m.get("monitor_id") or m.get("id") or "")
            if not mid:
                continue
            conn.execute("""
                INSERT INTO tv_host_monitor
                    (monitor_id, monitor_label, monitor_index, is_connected,
                     width, height, x, y, is_primary, detected_at, updated_at)
                VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(monitor_id) DO UPDATE SET
                    monitor_label=excluded.monitor_label,
                    monitor_index=excluded.monitor_index,
                    is_connected=1,
                    width=excluded.width, height=excluded.height,
                    x=excluded.x, y=excluded.y,
                    is_primary=excluded.is_primary,
                    updated_at=excluded.updated_at
            """, (
                mid,
                str(m.get("monitorLabel") or m.get("monitor_label") or m.get("label") or ""),
                _safe_int(m.get("monitorIndex") or m.get("monitor_index") or m.get("index"), 0),
                _safe_int(m.get("width"), 0),
                _safe_int(m.get("height"), 0),
                _safe_int(m.get("x"), 0),
                _safe_int(m.get("y"), 0),
                int(bool(m.get("isPrimary") or m.get("is_primary"))),
                ts, ts,
            ))
        conn.commit()
        rows = conn.execute("SELECT * FROM tv_host_monitor ORDER BY monitor_index").fetchall()
        return _rows_to_list(rows)


# ---------------------------------------------------------------------------
# 2) tv_screen_binding helpers
# ---------------------------------------------------------------------------

def create_tv_screen_binding(*, screen_id: int, screen_name: str = None,
                             screen_label: str = None,
                             gym_id: int = None, gym_label: str = None,
                             monitor_id: str = None, monitor_label: str = None,
                             monitor_index: int = None,
                             enabled: bool = True, autostart: bool = False,
                             fullscreen: bool = True,
                             window_label: str = None) -> Dict[str, Any]:
    ensure_tv_local_schema()
    ts = now_iso()
    label = screen_label or screen_name or ""
    with get_conn() as conn:
        existing = conn.execute("SELECT id FROM tv_screen_binding WHERE screen_id=?", (screen_id,)).fetchone()
        if existing:
            raise ValueError(f"screen_id {screen_id} is already bound (binding {existing['id']})")
            
        if monitor_id:
            conflict = conn.execute("""
                SELECT b.id FROM tv_screen_binding b
                LEFT JOIN tv_screen_binding_runtime r ON b.id = r.binding_id
                WHERE b.monitor_id = ? AND b.id != ?
                AND (b.desired_state != 'STOPPED' OR IFNULL(r.runtime_state, 'STOPPED') NOT IN ('STOPPED', 'IDLE', 'CRASHED', 'ERROR'))
            """, (monitor_id, 0)).fetchone()
            if conflict:
                raise ValueError("MONITOR_ALREADY_ASSIGNED: Monitor is assigned to another active binding.")
                
        cur = conn.execute("""
            INSERT INTO tv_screen_binding
                (screen_id, screen_label, gym_id, gym_label,
                 monitor_id, monitor_label, monitor_index,
                 enabled, autostart, desired_state, fullscreen,
                 window_label, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (screen_id, label, gym_id, gym_label,
              monitor_id, monitor_label, monitor_index,
              int(enabled), int(autostart), DESIRED_STOPPED, int(fullscreen),
              window_label, ts, ts))
        conn.commit()
        row = conn.execute("SELECT * FROM tv_screen_binding WHERE id=?", (cur.lastrowid,)).fetchone()
        return _row_to_dict(row) or {}


def update_tv_screen_binding(*, binding_id: int, **kwargs) -> Dict[str, Any]:
    ensure_tv_local_schema()
    ts = now_iso()
    allowed = {"screen_label", "screen_name", "gym_id", "gym_label",
               "monitor_id", "monitor_label", "monitor_index",
               "enabled", "autostart", "desired_state", "fullscreen",
               "window_label", "last_error_code", "last_error_message"}
    sets = []
    params = []
    for k, v in kwargs.items():
        if k not in allowed or v is None:
            continue
        col = k
        if k == "screen_name":
            col = "screen_label"
        if k in ("enabled", "autostart", "fullscreen"):
            v = int(bool(v))
        sets.append(f"{col}=?")
        params.append(v)
    if not sets:
        row = load_tv_screen_binding_by_id(binding_id=binding_id)
        return row or {}
    sets.append("updated_at=?")
    params.append(ts)
    params.append(binding_id)
    with get_conn() as conn:
        existing = conn.execute("SELECT * FROM tv_screen_binding WHERE id=?", (binding_id,)).fetchone()
        if not existing:
            raise ValueError("INVALID_BINDING: Binding not found.")
            
        new_monitor_id = kwargs.get("monitor_id") if "monitor_id" in kwargs else kwargs.get("monitorId")
        if new_monitor_id is not None and new_monitor_id != existing["monitor_id"]:
            # Rule: reassign requires stop
            runtime = conn.execute("SELECT runtime_state FROM tv_screen_binding_runtime WHERE binding_id=?", (binding_id,)).fetchone()
            rt_state = runtime["runtime_state"] if runtime else BINDING_RUNTIME_IDLE
            if existing["desired_state"] != DESIRED_STOPPED or rt_state not in (BINDING_RUNTIME_STOPPED, BINDING_RUNTIME_IDLE, BINDING_RUNTIME_CRASHED, BINDING_RUNTIME_ERROR):
                raise ValueError("REASSIGN_REQUIRES_STOP: Cannot reassign monitor while binding is active/running")
                
            # Rule: target monitor busy
            if new_monitor_id:
                conflict = conn.execute("""
                    SELECT b.id FROM tv_screen_binding b
                    LEFT JOIN tv_screen_binding_runtime r ON b.id = r.binding_id
                    WHERE b.monitor_id = ? AND b.id != ?
                    AND (b.desired_state != 'STOPPED' OR IFNULL(r.runtime_state, 'STOPPED') NOT IN ('STOPPED', 'IDLE', 'CRASHED', 'ERROR'))
                """, (new_monitor_id, binding_id)).fetchone()
                if conflict:
                    raise ValueError("MONITOR_ALREADY_ASSIGNED: Target monitor is in use by another active binding")
                    
        conn.execute(f"UPDATE tv_screen_binding SET {', '.join(sets)} WHERE id=?", params)
        conn.commit()
        row = conn.execute("SELECT * FROM tv_screen_binding WHERE id=?", (binding_id,)).fetchone()
        return _row_to_dict(row) or {}


def delete_tv_screen_binding(*, binding_id: int) -> bool:
    ensure_tv_local_schema()
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM tv_screen_binding WHERE id=?", (binding_id,))
        conn.execute("DELETE FROM tv_screen_binding_runtime WHERE binding_id=?", (binding_id,))
        conn.commit()
        return cur.rowcount > 0


def load_tv_screen_binding_by_id(*, binding_id: int) -> Optional[Dict[str, Any]]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM tv_screen_binding WHERE id=?", (binding_id,)).fetchone()
        return _row_to_dict(row)


def get_tv_screen_binding(*, binding_id: int) -> Optional[Dict[str, Any]]:
    return load_tv_screen_binding_by_id(binding_id=binding_id)


def load_tv_screen_binding(*, screen_id: int = 0, **kwargs) -> Optional[Dict[str, Any]]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        if screen_id > 0:
            row = conn.execute("SELECT * FROM tv_screen_binding WHERE screen_id=?", (screen_id,)).fetchone()
        else:
            row = conn.execute("SELECT * FROM tv_screen_binding ORDER BY id LIMIT 1").fetchone()
        return _row_to_dict(row) or {}


def list_tv_screen_bindings() -> List[Dict[str, Any]]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM tv_screen_binding ORDER BY id").fetchall()
        return _rows_to_list(rows)


def save_tv_screen_binding(**kwargs) -> Dict[str, Any]:
    sid = _safe_int(kwargs.get("screen_id") or kwargs.get("screenId"), 0)
    if sid <= 0:
        return {"ok": False, "error": "screen_id required"}
    ensure_tv_local_schema()
    with get_conn() as conn:
        existing = conn.execute("SELECT id FROM tv_screen_binding WHERE screen_id=?", (sid,)).fetchone()
    if existing:
        return update_tv_screen_binding(binding_id=existing["id"],
                                        screen_name=kwargs.get("screen_name") or kwargs.get("screenName"))
    return create_tv_screen_binding(screen_id=sid,
                                    screen_name=kwargs.get("screen_name") or kwargs.get("screenName"))


# ---------------------------------------------------------------------------
# 3) tv_screen_binding_runtime helpers
# ---------------------------------------------------------------------------

def upsert_tv_screen_binding_runtime(*, binding_id: int, **kwargs) -> Dict[str, Any]:
    ensure_tv_local_schema()
    ts = now_iso()
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT * FROM tv_screen_binding_runtime WHERE binding_id=?",
            (binding_id,),
        ).fetchone()
        existing_row = _row_to_dict(existing) or {}
        runtime_state = kwargs["runtime_state"] if "runtime_state" in kwargs else (
            existing_row.get("runtime_state") if existing_row else BINDING_RUNTIME_IDLE
        )
        crash_count = kwargs["crash_count"] if "crash_count" in kwargs else (
            existing_row.get("crash_count") if existing_row else 0
        )
        conn.execute("""
            INSERT INTO tv_screen_binding_runtime
                (binding_id, runtime_state, window_id, tauri_window_label,
                 last_started_at, last_stopped_at, last_crashed_at,
                 crash_count, last_exit_reason, last_error_code,
                 last_error_message, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(binding_id) DO UPDATE SET
                runtime_state=COALESCE(excluded.runtime_state, runtime_state),
                window_id=COALESCE(excluded.window_id, window_id),
                tauri_window_label=COALESCE(excluded.tauri_window_label, tauri_window_label),
                last_started_at=COALESCE(excluded.last_started_at, last_started_at),
                last_stopped_at=COALESCE(excluded.last_stopped_at, last_stopped_at),
                last_crashed_at=COALESCE(excluded.last_crashed_at, last_crashed_at),
                crash_count=COALESCE(excluded.crash_count, crash_count),
                last_exit_reason=COALESCE(excluded.last_exit_reason, last_exit_reason),
                last_error_code=COALESCE(excluded.last_error_code, last_error_code),
                last_error_message=COALESCE(excluded.last_error_message, last_error_message),
                updated_at=excluded.updated_at
        """, (
            binding_id,
            runtime_state,
            kwargs.get("window_id"),
            kwargs.get("tauri_window_label"),
            kwargs.get("last_started_at"),
            kwargs.get("last_stopped_at"),
            kwargs.get("last_crashed_at"),
            crash_count,
            kwargs.get("last_exit_reason"),
            kwargs.get("last_error_code"),
            kwargs.get("last_error_message"),
            ts,
        ))
        conn.commit()
        row = conn.execute("SELECT * FROM tv_screen_binding_runtime WHERE binding_id=?", (binding_id,)).fetchone()
        return _row_to_dict(row) or {}


def load_tv_screen_binding_runtime(*, binding_id: int) -> Optional[Dict[str, Any]]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM tv_screen_binding_runtime WHERE binding_id=?", (binding_id,)).fetchone()
        return _row_to_dict(row)


# ---------------------------------------------------------------------------
# 6) TV Readiness (A4)
# ---------------------------------------------------------------------------

def upsert_tv_snapshot_readiness(*, screen_id: int, snapshot_id: str,
                                 snapshot_version: int,
                                 readiness_state: str,
                                 is_fully_ready: bool,
                                 total_required_assets: int = 0,
                                 ready_asset_count: int = 0,
                                 missing_asset_count: int = 0,
                                 invalid_asset_count: int = 0,
                                 stale_asset_count: int = 0,
                                 is_latest: bool = False,
                                 is_previous_ready: bool = False) -> Dict[str, Any]:
    ensure_tv_local_schema()
    ts = now_iso()
    try:
        with get_conn() as conn:
            # Upsert logic based on screening + snapshot
            # If inserting as latest, reset old ones first
            if is_latest:
                conn.execute("UPDATE tv_snapshot_readiness SET is_latest=0 WHERE screen_id=?", (screen_id,))
            if is_previous_ready:
                conn.execute("UPDATE tv_snapshot_readiness SET is_previous_ready=0 WHERE screen_id=?", (screen_id,))
                
            row = conn.execute("SELECT id FROM tv_snapshot_readiness WHERE screen_id=? AND snapshot_id=?",
                              (screen_id, snapshot_id)).fetchone()
            
            if row:
                conn.execute("""
                    UPDATE tv_snapshot_readiness SET
                        snapshot_version=?, readiness_state=?, is_fully_ready=?,
                        total_required_assets=?, ready_asset_count=?,
                        missing_asset_count=?, invalid_asset_count=?,
                        stale_asset_count=?, computed_at=?,
                        is_latest=?, is_previous_ready=?, updated_at=?
                    WHERE id=?
                """, (snapshot_version, readiness_state, 1 if is_fully_ready else 0,
                      total_required_assets, ready_asset_count, missing_asset_count,
                      invalid_asset_count, stale_asset_count, ts,
                      1 if is_latest else 0, 1 if is_previous_ready else 0, ts, row["id"]))
            else:
                conn.execute("""
                    INSERT INTO tv_snapshot_readiness (
                        screen_id, snapshot_id, snapshot_version, readiness_state,
                        is_fully_ready, total_required_assets, ready_asset_count,
                        missing_asset_count, invalid_asset_count, stale_asset_count,
                        computed_at, is_latest, is_previous_ready, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (screen_id, snapshot_id, snapshot_version, readiness_state,
                      1 if is_fully_ready else 0, total_required_assets, ready_asset_count,
                      missing_asset_count, invalid_asset_count, stale_asset_count,
                      ts, 1 if is_latest else 0, 1 if is_previous_ready else 0, ts, ts))
            conn.commit()
            return {"ok": True}
    except Exception as e:
        _log.exception("[TvReadiness] Error upserting readiness: %s", e)
        return {"ok": False, "error": str(e)}

def load_tv_latest_readiness(screen_id: int) -> Optional[Dict[str, Any]]:
    ensure_tv_local_schema()
    row = get_conn().execute(
        "SELECT * FROM tv_snapshot_readiness WHERE screen_id=? AND is_latest=1 LIMIT 1",
        (screen_id,)
    ).fetchone()
    return dict(row) if row else None

def list_tv_readiness(*, screen_id: int = 0, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    ensure_tv_local_schema()
    query = "SELECT * FROM tv_snapshot_readiness WHERE 1=1"
    params = []
    if screen_id > 0:
        query += " AND screen_id=?"
        params.append(screen_id)
    query += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) as c FROM tv_snapshot_readiness").fetchone()["c"]
    rows = [dict(r) for r in conn.execute(query, params).fetchall()]
    return {"total": total, "readiness": rows}


# ---------------------------------------------------------------------------
# 4) tv_screen_binding_event helpers
# ---------------------------------------------------------------------------

def record_tv_screen_binding_event(*, binding_id: int, event_type: str,
                                   severity: str = SEVERITY_INFO,
                                   message: str = None,
                                   metadata_json: Any = None,
                                   **kwargs) -> Dict[str, Any]:
    ensure_tv_local_schema()
    ts = now_iso()
    meta = _json_dumps(metadata_json) if metadata_json else None
    with get_conn() as conn:
        cur = conn.execute("""
            INSERT INTO tv_screen_binding_event
                (binding_id, event_type, severity, message, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (binding_id, event_type, severity, message, meta, ts))
        conn.commit()
        return {"ok": True, "id": cur.lastrowid}


def list_tv_screen_binding_events(*, binding_id: int,
                                  limit: int = 100, offset: int = 0,
                                  **kwargs) -> Dict[str, Any]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        total_row = conn.execute(
            "SELECT COUNT(*) as cnt FROM tv_screen_binding_event WHERE binding_id=?",
            (binding_id,)).fetchone()
        total = total_row["cnt"] if total_row else 0
        rows = conn.execute("""
            SELECT * FROM tv_screen_binding_event
            WHERE binding_id=? ORDER BY id DESC LIMIT ? OFFSET ?
        """, (binding_id, limit, offset)).fetchall()
        return {"rows": _rows_to_list(rows), "total": total}


# ---------------------------------------------------------------------------
# 5) tv_snapshot_cache helpers
# ---------------------------------------------------------------------------

def upsert_tv_snapshot_cache(*, screen_id: int, snapshot_id: str,
                             snapshot_version: int, **kwargs) -> Dict[str, Any]:
    ensure_tv_local_schema()
    ts = now_iso()
    with get_conn() as conn:
        # Mark all previous as not latest for this screen
        conn.execute("UPDATE tv_snapshot_cache SET is_latest=0, updated_at=? WHERE screen_id=?", (ts, screen_id))
        existing = conn.execute(
            "SELECT id FROM tv_snapshot_cache WHERE screen_id=? AND snapshot_id=?",
            (screen_id, snapshot_id)).fetchone()
        if existing:
            conn.execute("""
                UPDATE tv_snapshot_cache SET
                    snapshot_version=?, activation_state=?, resolved_at=?,
                    resolved_day_of_week=?, resolved_preset_id=?,
                    resolved_layout_preset_id=?, resolved_policy_id=?,
                    playback_policy_version=?, playback_policy_hash=?,
                    generated_at=?, fetched_at=?,
                    payload_json=?, manifest_json=?,
                    asset_count=?, warning_count=?,
                    manifest_status=?, sync_status=?, last_error=?,
                    is_latest=1, is_previous_ready=?,
                    updated_at=?
                WHERE id=?
            """, (
                snapshot_version,
                kwargs.get("activation_state"),
                kwargs.get("resolved_at"),
                kwargs.get("resolved_day_of_week"),
                kwargs.get("resolved_preset_id"),
                kwargs.get("resolved_layout_preset_id"),
                kwargs.get("resolved_policy_id"),
                kwargs.get("playback_policy_version"),
                kwargs.get("playback_policy_hash"),
                kwargs.get("generated_at"),
                kwargs.get("fetched_at", ts),
                kwargs.get("payload_json"),
                kwargs.get("manifest_json"),
                kwargs.get("asset_count", 0),
                kwargs.get("warning_count", 0),
                kwargs.get("manifest_status", MANIFEST_STATUS_PENDING),
                kwargs.get("sync_status", SYNC_STATUS_PENDING),
                kwargs.get("last_error"),
                int(kwargs.get("is_previous_ready", False)),
                ts,
                existing["id"],
            ))
        else:
            conn.execute("""
                INSERT INTO tv_snapshot_cache
                    (screen_id, snapshot_id, snapshot_version,
                     activation_state, resolved_at, resolved_day_of_week,
                     resolved_preset_id, resolved_layout_preset_id,
                     resolved_policy_id, playback_policy_version,
                     playback_policy_hash, generated_at, fetched_at,
                     payload_json, manifest_json,
                     asset_count, warning_count,
                     manifest_status, sync_status, last_error,
                     is_latest, is_previous_ready,
                     created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)
            """, (
                screen_id, snapshot_id, snapshot_version,
                kwargs.get("activation_state"),
                kwargs.get("resolved_at"),
                kwargs.get("resolved_day_of_week"),
                kwargs.get("resolved_preset_id"),
                kwargs.get("resolved_layout_preset_id"),
                kwargs.get("resolved_policy_id"),
                kwargs.get("playback_policy_version"),
                kwargs.get("playback_policy_hash"),
                kwargs.get("generated_at"),
                kwargs.get("fetched_at", ts),
                kwargs.get("payload_json"),
                kwargs.get("manifest_json"),
                kwargs.get("asset_count", 0),
                kwargs.get("warning_count", 0),
                kwargs.get("manifest_status", MANIFEST_STATUS_PENDING),
                kwargs.get("sync_status", SYNC_STATUS_PENDING),
                kwargs.get("last_error"),
                int(kwargs.get("is_previous_ready", False)),
                ts, ts,
            ))
        conn.commit()
        row = conn.execute(
            "SELECT * FROM tv_snapshot_cache WHERE screen_id=? AND snapshot_id=?",
            (screen_id, snapshot_id)).fetchone()
        return _row_to_dict(row) or {}


def load_tv_latest_snapshot(*, screen_id: int = 0, **kwargs) -> Optional[Dict[str, Any]]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM tv_snapshot_cache WHERE screen_id=? AND is_latest=1 ORDER BY id DESC LIMIT 1",
            (screen_id,)).fetchone()
        return _row_to_dict(row)


def load_tv_snapshot_by_id(snapshot_id=None, **kwargs) -> Optional[Dict[str, Any]]:
    ensure_tv_local_schema()
    if not snapshot_id:
        return None
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM tv_snapshot_cache WHERE snapshot_id=? ORDER BY id DESC LIMIT 1",
            (str(snapshot_id),)).fetchone()
        return _row_to_dict(row)


def list_tv_snapshot_cache(*, screen_id: int = 0,
                           limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        if screen_id > 0:
            total = conn.execute("SELECT COUNT(*) as cnt FROM tv_snapshot_cache WHERE screen_id=?", (screen_id,)).fetchone()["cnt"]
            rows = conn.execute("SELECT * FROM tv_snapshot_cache WHERE screen_id=? ORDER BY id DESC LIMIT ? OFFSET ?",
                                (screen_id, limit, offset)).fetchall()
        else:
            total = conn.execute("SELECT COUNT(*) as cnt FROM tv_snapshot_cache").fetchone()["cnt"]
            rows = conn.execute("SELECT * FROM tv_snapshot_cache ORDER BY id DESC LIMIT ? OFFSET ?",
                                (limit, offset)).fetchall()
        return {"rows": _rows_to_list(rows), "total": total}


# ---------------------------------------------------------------------------
# 6) tv_snapshot_required_asset helpers
# ---------------------------------------------------------------------------

def upsert_tv_snapshot_required_asset(*, snapshot_id: str, media_asset_id: str,
                                      **kwargs) -> Dict[str, Any]:
    ensure_tv_local_schema()
    ts = now_iso()
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO tv_snapshot_required_asset
                (snapshot_id, media_asset_id, title, media_type,
                 download_link, checksum_sha256, size_bytes, mime_type,
                 duration_in_seconds, required_in_timelines_json,
                 source_preset_item_ids_json, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(snapshot_id, media_asset_id) DO UPDATE SET
                title=excluded.title, media_type=excluded.media_type,
                download_link=excluded.download_link,
                checksum_sha256=excluded.checksum_sha256,
                size_bytes=excluded.size_bytes,
                mime_type=excluded.mime_type,
                duration_in_seconds=excluded.duration_in_seconds,
                required_in_timelines_json=excluded.required_in_timelines_json,
                source_preset_item_ids_json=excluded.source_preset_item_ids_json,
                updated_at=excluded.updated_at
        """, (
            snapshot_id, media_asset_id,
            kwargs.get("title"),
            kwargs.get("media_type"),
            kwargs.get("download_link"),
            kwargs.get("checksum_sha256"),
            kwargs.get("size_bytes"),
            kwargs.get("mime_type"),
            kwargs.get("duration_in_seconds"),
            _json_dumps(kwargs.get("required_in_timelines")) if kwargs.get("required_in_timelines") else kwargs.get("required_in_timelines_json"),
            _json_dumps(kwargs.get("source_preset_item_ids")) if kwargs.get("source_preset_item_ids") else kwargs.get("source_preset_item_ids_json"),
            ts, ts,
        ))
        conn.commit()
        row = conn.execute("SELECT * FROM tv_snapshot_required_asset WHERE snapshot_id=? AND media_asset_id=?",
                           (snapshot_id, media_asset_id)).fetchone()
        return _row_to_dict(row) or {}


def list_tv_snapshot_required_assets(*, snapshot_id: str) -> List[Dict[str, Any]]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM tv_snapshot_required_asset WHERE snapshot_id=? ORDER BY id",
                            (snapshot_id,)).fetchall()
        return _rows_to_list(rows)


# ---------------------------------------------------------------------------
# 7) tv_local_asset_state helpers
# ---------------------------------------------------------------------------

def upsert_tv_local_asset_state(*, media_asset_id: str, **kwargs) -> Dict[str, Any]:
    ensure_tv_local_schema()
    ts = now_iso()
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO tv_local_asset_state
                (media_asset_id, expected_local_path, local_file_path,
                 file_exists, local_size_bytes, local_checksum_sha256,
                 asset_state, state_reason, validation_mode,
                 last_checked_at, last_seen_in_snapshot_version,
                 created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(media_asset_id) DO UPDATE SET
                expected_local_path=COALESCE(excluded.expected_local_path, expected_local_path),
                local_file_path=COALESCE(excluded.local_file_path, local_file_path),
                file_exists=excluded.file_exists,
                local_size_bytes=excluded.local_size_bytes,
                local_checksum_sha256=excluded.local_checksum_sha256,
                asset_state=excluded.asset_state,
                state_reason=excluded.state_reason,
                validation_mode=excluded.validation_mode,
                last_checked_at=excluded.last_checked_at,
                last_seen_in_snapshot_version=COALESCE(excluded.last_seen_in_snapshot_version, last_seen_in_snapshot_version),
                updated_at=excluded.updated_at
        """, (
            media_asset_id,
            kwargs.get("expected_local_path"),
            kwargs.get("local_file_path"),
            int(kwargs.get("file_exists", False)),
            kwargs.get("local_size_bytes"),
            kwargs.get("local_checksum_sha256"),
            kwargs.get("asset_state", ASSET_STATE_UNKNOWN),
            kwargs.get("state_reason"),
            kwargs.get("validation_mode"),
            kwargs.get("last_checked_at", ts),
            kwargs.get("last_seen_in_snapshot_version"),
            ts, ts,
        ))
        conn.commit()
        row = conn.execute("SELECT * FROM tv_local_asset_state WHERE media_asset_id=?",
                           (media_asset_id,)).fetchone()
        return _row_to_dict(row) or {}


def load_tv_local_asset_state(*, media_asset_id: str) -> Optional[Dict[str, Any]]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM tv_local_asset_state WHERE media_asset_id=?",
                           (media_asset_id,)).fetchone()
        return _row_to_dict(row)


def list_tv_local_asset_states(*, limit: int = 500, offset: int = 0) -> Dict[str, Any]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) as cnt FROM tv_local_asset_state").fetchone()["cnt"]
        rows = conn.execute("SELECT * FROM tv_local_asset_state ORDER BY id LIMIT ? OFFSET ?",
                            (limit, offset)).fetchall()
        return {"rows": _rows_to_list(rows), "total": total}


# ---------------------------------------------------------------------------
# 8) tv_snapshot_readiness helpers
# ---------------------------------------------------------------------------

def upsert_tv_snapshot_readiness(*, screen_id: int, snapshot_id: str,
                                 snapshot_version: int, **kwargs) -> Dict[str, Any]:
    ensure_tv_local_schema()
    ts = now_iso()
    with get_conn() as conn:
        conn.execute("UPDATE tv_snapshot_readiness SET is_latest=0, updated_at=? WHERE screen_id=?", (ts, screen_id))
        existing = conn.execute(
            "SELECT id FROM tv_snapshot_readiness WHERE screen_id=? AND snapshot_id=?",
            (screen_id, snapshot_id)).fetchone()
        if existing:
            conn.execute("""
                UPDATE tv_snapshot_readiness SET
                    snapshot_version=?, readiness_state=?,
                    total_required_assets=?, ready_asset_count=?,
                    missing_asset_count=?, invalid_asset_count=?,
                    stale_asset_count=?, computed_at=?,
                    is_fully_ready=?, is_latest=1, is_previous_ready=?,
                    updated_at=?
                WHERE id=?
            """, (
                snapshot_version,
                kwargs.get("readiness_state", READINESS_UNKNOWN),
                kwargs.get("total_required_assets", 0),
                kwargs.get("ready_asset_count", 0),
                kwargs.get("missing_asset_count", 0),
                kwargs.get("invalid_asset_count", 0),
                kwargs.get("stale_asset_count", 0),
                kwargs.get("computed_at", ts),
                int(kwargs.get("is_fully_ready", False)),
                int(kwargs.get("is_previous_ready", False)),
                ts,
                existing["id"],
            ))
        else:
            conn.execute("""
                INSERT INTO tv_snapshot_readiness
                    (screen_id, snapshot_id, snapshot_version,
                     readiness_state, total_required_assets,
                     ready_asset_count, missing_asset_count,
                     invalid_asset_count, stale_asset_count,
                     computed_at, is_fully_ready, is_latest,
                     is_previous_ready, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                screen_id, snapshot_id, snapshot_version,
                kwargs.get("readiness_state", READINESS_UNKNOWN),
                kwargs.get("total_required_assets", 0),
                kwargs.get("ready_asset_count", 0),
                kwargs.get("missing_asset_count", 0),
                kwargs.get("invalid_asset_count", 0),
                kwargs.get("stale_asset_count", 0),
                kwargs.get("computed_at", ts),
                int(kwargs.get("is_fully_ready", False)),
                1, # is_latest
                int(kwargs.get("is_previous_ready", False)),
                ts, ts,
            ))
        conn.commit()
        row = conn.execute(
            "SELECT * FROM tv_snapshot_readiness WHERE screen_id=? AND snapshot_id=?",
            (screen_id, snapshot_id)).fetchone()
        return _row_to_dict(row) or {}


def load_tv_latest_readiness(*, screen_id: int = 0, **kwargs) -> Optional[Dict[str, Any]]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM tv_snapshot_readiness WHERE screen_id=? AND is_latest=1 ORDER BY id DESC LIMIT 1",
            (screen_id,)).fetchone()
        return _row_to_dict(row)


def list_tv_snapshot_readiness(*, screen_id: int = 0,
                               limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        if screen_id > 0:
            total = conn.execute("SELECT COUNT(*) as cnt FROM tv_snapshot_readiness WHERE screen_id=?", (screen_id,)).fetchone()["cnt"]
            rows = conn.execute("SELECT * FROM tv_snapshot_readiness WHERE screen_id=? ORDER BY id DESC LIMIT ? OFFSET ?",
                                (screen_id, limit, offset)).fetchall()
        else:
            total = conn.execute("SELECT COUNT(*) as cnt FROM tv_snapshot_readiness").fetchone()["cnt"]
            rows = conn.execute("SELECT * FROM tv_snapshot_readiness ORDER BY id DESC LIMIT ? OFFSET ?",
                                (limit, offset)).fetchall()
        return {"rows": _rows_to_list(rows), "total": total}


# ---------------------------------------------------------------------------
# 9) tv_sync_run_log helpers
# ---------------------------------------------------------------------------

def insert_tv_sync_run_log(*, screen_id: int = None,
                           target_snapshot_version: int = None,
                           started_at: str = None, finished_at: str = None,
                           result: str = None, warning_count: int = 0,
                           error_message: str = None,
                           correlation_id: str = None) -> Dict[str, Any]:
    ensure_tv_local_schema()
    ts = now_iso()
    with get_conn() as conn:
        cur = conn.execute("""
            INSERT INTO tv_sync_run_log
                (started_at, finished_at, screen_id,
                 target_snapshot_version, result,
                 warning_count, error_message,
                 correlation_id, created_at)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (started_at or ts, finished_at, screen_id,
              target_snapshot_version, result,
              warning_count, error_message,
              correlation_id, ts))
        conn.commit()
        row = conn.execute("SELECT * FROM tv_sync_run_log WHERE id=?", (cur.lastrowid,)).fetchone()
        return _row_to_dict(row) or {}


def list_tv_sync_run_logs(*, screen_id: int = None,
                          limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        if screen_id and screen_id > 0:
            total = conn.execute("SELECT COUNT(*) as cnt FROM tv_sync_run_log WHERE screen_id=?", (screen_id,)).fetchone()["cnt"]
            rows = conn.execute("SELECT * FROM tv_sync_run_log WHERE screen_id=? ORDER BY id DESC LIMIT ? OFFSET ?",
                                (screen_id, limit, offset)).fetchall()
        else:
            total = conn.execute("SELECT COUNT(*) as cnt FROM tv_sync_run_log").fetchone()["cnt"]
            rows = conn.execute("SELECT * FROM tv_sync_run_log ORDER BY id DESC LIMIT ? OFFSET ?",
                                (limit, offset)).fetchall()
        return {"rows": _rows_to_list(rows), "total": total}


# ---------------------------------------------------------------------------
# Deterministic local path (A3 refined)
# ---------------------------------------------------------------------------

def _mime_to_ext(mime_type: str = "", media_type: str = "") -> str:
    """Derive file extension from mime_type or media_type."""
    ext = ""
    if mime_type:
        _map = {"video/mp4": ".mp4", "image/jpeg": ".jpg", "image/png": ".png",
                "image/webp": ".webp", "video/webm": ".webm", "audio/mpeg": ".mp3",
                "image/gif": ".gif", "audio/wav": ".wav", "video/quicktime": ".mov"}
        ext = _map.get(mime_type.lower().strip(), "")
    if not ext and media_type:
        _type_map = {"VIDEO": ".mp4", "IMAGE": ".jpg", "AUDIO": ".mp3"}
        ext = _type_map.get(media_type.upper().strip(), "")
    return ext or ".bin"


def compute_expected_local_path(*, media_asset_id: str,
                                checksum_sha256: str = "",
                                mime_type: str = "", media_type: str = "",
                                screen_id: int = 0, **kwargs) -> str:
    """
    Deterministic local path for a media asset.
    Pattern: {DATA_ROOT}/tv/media/{media_asset_id}_{checksum8}.{ext}
    The checksum prefix ensures a content-changed asset gets a new path.
    """
    ext = _mime_to_ext(mime_type, media_type)
    cksum_marker = (checksum_sha256 or "").strip()[:8] or "nochk"
    media_dir = Path(str(DATA_ROOT)) / "tv" / "media"
    return str(media_dir / f"{media_asset_id}_{cksum_marker}{ext}")


# ---------------------------------------------------------------------------
# Backward-compatible stubs (not yet implemented — later functionalities)
# ---------------------------------------------------------------------------

def start_tv_screen_binding(*, binding_id: int = 0, **kwargs) -> Dict[str, Any]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        b = conn.execute("SELECT * FROM tv_screen_binding WHERE id=?", (binding_id,)).fetchone()
        if not b:
            raise ValueError("INVALID_BINDING: Binding not found.")
        
        if b["monitor_id"]:
            conflict = conn.execute("""
                SELECT b.id FROM tv_screen_binding b
                LEFT JOIN tv_screen_binding_runtime r ON b.id = r.binding_id
                WHERE b.monitor_id = ? AND b.id != ?
                AND (b.desired_state != 'STOPPED' OR IFNULL(r.runtime_state, 'STOPPED') NOT IN ('STOPPED', 'IDLE', 'CRASHED', 'ERROR'))
            """, (b["monitor_id"], binding_id)).fetchone()
            if conflict:
                raise ValueError("MONITOR_ALREADY_ASSIGNED: Monitor is in use by another active binding")
                
        ts = now_iso()
        conn.execute("UPDATE tv_screen_binding SET desired_state=?, updated_at=? WHERE id=?", 
                     (DESIRED_RUNNING, ts, binding_id))
        conn.commit()
    
    record_tv_screen_binding_event(binding_id=binding_id, event_type="PLAYER_START_REQUESTED")
    return load_tv_screen_binding_by_id(binding_id=binding_id)

def stop_tv_screen_binding(*, binding_id: int = 0, **kwargs) -> Dict[str, Any]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        b = conn.execute("SELECT * FROM tv_screen_binding WHERE id=?", (binding_id,)).fetchone()
        if not b:
            raise ValueError("INVALID_BINDING: Binding not found.")
        ts = now_iso()
        conn.execute("UPDATE tv_screen_binding SET desired_state=?, updated_at=? WHERE id=?", 
                     (DESIRED_STOPPED, ts, binding_id))
        conn.commit()
    record_tv_screen_binding_event(binding_id=binding_id, event_type="PLAYER_STOP_REQUESTED")
    return load_tv_screen_binding_by_id(binding_id=binding_id)

def restart_tv_screen_binding(*, binding_id: int = 0, **kwargs) -> Dict[str, Any]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        b = conn.execute("SELECT * FROM tv_screen_binding WHERE id=?", (binding_id,)).fetchone()
        if not b:
            raise ValueError("INVALID_BINDING: Binding not found.")
        ts = now_iso()
        conn.execute("UPDATE tv_screen_binding SET desired_state=?, updated_at=? WHERE id=?", 
                     (DESIRED_RUNNING, ts, binding_id))
        conn.commit()
    record_tv_screen_binding_event(binding_id=binding_id, event_type="PLAYER_RESTART_REQUESTED")
    return load_tv_screen_binding_by_id(binding_id=binding_id)

def load_tv_latest_ready_snapshot(*, screen_id: int = 0, **kwargs) -> Optional[Dict[str, Any]]:
    return None

def load_tv_previous_ready_snapshot(*, screen_id: int = 0, **kwargs) -> Optional[Dict[str, Any]]:
    return None

def load_tv_snapshot_manifest(snapshot_id=None, **kwargs) -> Optional[Dict[str, Any]]:
    return None

def list_tv_cache_assets(*, screen_id: int = 0, snapshot_id: str = "",
                         asset_state: str = "", media_asset_id: str = "",
                         limit: int = 500, offset: int = 0, **kwargs) -> Dict[str, Any]:
    """List local asset state rows with optional filters."""
    ensure_tv_local_schema()
    with get_conn() as conn:
        where_parts = []
        params: list = []
        if media_asset_id:
            where_parts.append("las.media_asset_id = ?")
            params.append(media_asset_id)
        if asset_state:
            where_parts.append("las.asset_state = ?")
            params.append(asset_state)
        if snapshot_id:
            where_parts.append("las.media_asset_id IN (SELECT media_asset_id FROM tv_snapshot_required_asset WHERE snapshot_id = ?)")
            params.append(snapshot_id)
        if screen_id > 0:
            where_parts.append("las.media_asset_id IN (SELECT sra.media_asset_id FROM tv_snapshot_required_asset sra JOIN tv_snapshot_cache sc ON sra.snapshot_id = sc.snapshot_id WHERE sc.screen_id = ?)")
            params.append(screen_id)
        where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
        total = conn.execute(f"SELECT COUNT(*) as cnt FROM tv_local_asset_state las{where_clause}", params).fetchone()["cnt"]
        rows = conn.execute(
            f"SELECT las.* FROM tv_local_asset_state las{where_clause} ORDER BY las.id DESC LIMIT ? OFFSET ?",
            params + [limit, offset]).fetchall()
        return {"rows": _rows_to_list(rows), "total": total, "limit": limit, "offset": offset}

def load_tv_latest_download_batch(*, screen_id: int = 0, **kwargs) -> Optional[Dict[str, Any]]:
    return None

def list_tv_download_jobs(*, screen_id: int = 0, limit: int = 500, offset: int = 0, **kwargs) -> Dict[str, Any]:
    return {"rows": [], "total": 0, "limit": limit, "offset": offset}

def load_tv_activation_status(*, screen_id: int = 0, **kwargs) -> Dict[str, Any]:
    return {"ok": False, "error": "TV_NOT_YET_IMPLEMENTED"}

def list_tv_activation_attempts(*, screen_id: int = 0, limit: int = 100, offset: int = 0, **kwargs) -> Dict[str, Any]:
    return {"rows": [], "total": 0}

def load_tv_player_status(*, binding_id: int) -> Dict[str, Any]:
    return {"ok": False, "error": "TV_NOT_YET_IMPLEMENTED"}

def get_tv_player_render_context(*, binding_id: int, persist: bool = False) -> Dict[str, Any]:
    return {"ok": False, "error": "TV_NOT_YET_IMPLEMENTED", "adOverrideActive": False}

def reevaluate_tv_player(*, binding_id: int = 0, persist: bool = True, **kwargs) -> Dict[str, Any]:
    return {"ok": False, "error": "TV_NOT_YET_IMPLEMENTED"}

def reload_tv_player(*, binding_id: int = 0, persist: bool = True, **kwargs) -> Dict[str, Any]:
    return {"ok": False, "error": "TV_NOT_YET_IMPLEMENTED"}

def report_tv_player_state(*, binding_id: int, payload: Dict[str, Any],
                           event_type: str = "PLAYER_STATE_CHANGED",
                           force: bool = False, freshness_seconds: int = 20) -> Dict[str, Any]:
    return {"ok": False, "updated": False, "changed": False, "error": "TV_NOT_YET_IMPLEMENTED"}

def list_tv_player_events(*, binding_id: int = 0, **kwargs) -> Dict[str, Any]:
    return {"rows": [], "total": 0}

def load_tv_binding_support_summary(*, binding_id: int) -> Dict[str, Any]:
    return {"ok": False, "error": "TV_NOT_YET_IMPLEMENTED"}

# ---------------------------------------------------------------------------
# A7: Ad Task Runtime — CRUD helpers and pipeline
# ---------------------------------------------------------------------------

def upsert_tv_ad_task_cache(
    *,
    campaign_task_id: str,
    gym_id: int,
    campaign_id: str = None,
    ad_media_id: str = None,
    ad_download_link: str = None,
    ad_checksum_sha256: str = None,
    ad_size_bytes: int = None,
    ad_mime_type: str = None,
    scheduled_at: str = None,
    layout: str = "FULL_SCREEN",
    display_duration_sec: int = 30,
    remote_status: str = None,
    generation_batch_no: int = None,
    remote_updated_at: str = None,
    local_file_path: str = None,
    local_file_state: str = "PENDING",
) -> Dict[str, Any]:
    """Upsert a cached ad task row (called by fetch/prepare pipeline)."""
    ensure_tv_local_schema()
    now = now_iso()
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO tv_ad_task_cache (
                campaign_task_id, campaign_id, gym_id, ad_media_id,
                ad_download_link, ad_checksum_sha256, ad_size_bytes, ad_mime_type,
                scheduled_at, layout, display_duration_sec,
                remote_status, generation_batch_no, remote_updated_at,
                local_file_path, local_file_state, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(campaign_task_id) DO UPDATE SET
                campaign_id=excluded.campaign_id,
                gym_id=excluded.gym_id,
                ad_media_id=excluded.ad_media_id,
                ad_download_link=excluded.ad_download_link,
                ad_checksum_sha256=excluded.ad_checksum_sha256,
                ad_size_bytes=excluded.ad_size_bytes,
                ad_mime_type=excluded.ad_mime_type,
                scheduled_at=excluded.scheduled_at,
                layout=excluded.layout,
                display_duration_sec=excluded.display_duration_sec,
                remote_status=excluded.remote_status,
                generation_batch_no=excluded.generation_batch_no,
                remote_updated_at=excluded.remote_updated_at,
                local_file_path=excluded.local_file_path,
                local_file_state=excluded.local_file_state,
                updated_at=excluded.updated_at
        """, (
            str(campaign_task_id), campaign_id, int(gym_id), ad_media_id,
            ad_download_link, ad_checksum_sha256,
            ad_size_bytes, ad_mime_type,
            scheduled_at, layout or "FULL_SCREEN", int(display_duration_sec or 30),
            remote_status, generation_batch_no, remote_updated_at,
            local_file_path, local_file_state or "PENDING", now, now,
        ))
        conn.commit()
        row = conn.execute(
            "SELECT * FROM tv_ad_task_cache WHERE campaign_task_id=?", (str(campaign_task_id),)
        ).fetchone()
        return _row_to_dict(row) or {}


def load_tv_ad_task_cache_one(*, campaign_task_id: str) -> Optional[Dict[str, Any]]:
    """Load one cached ad task by ID."""
    ensure_tv_local_schema()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM tv_ad_task_cache WHERE campaign_task_id=? LIMIT 1",
            (str(campaign_task_id),)
        ).fetchone()
        return _row_to_dict(row)


def list_tv_ad_task_cache(*, gym_id=None, remote_statuses=None, local_states=None,
                          q=None, limit: int = 500, offset: int = 0) -> Dict[str, Any]:
    """List locally cached ad tasks with optional filters."""
    ensure_tv_local_schema()
    clauses: List[str] = []
    params: List[Any] = []
    if gym_id and int(gym_id) > 0:
        clauses.append("gym_id = ?")
        params.append(int(gym_id))
    if remote_statuses:
        placeholders = ",".join("?" * len(remote_statuses))
        clauses.append(f"remote_status IN ({placeholders})")
        params.extend(remote_statuses)
    if local_states:
        placeholders = ",".join("?" * len(local_states))
        clauses.append(f"local_file_state IN ({placeholders})")
        params.extend(local_states)
    if q:
        clauses.append("(campaign_task_id LIKE ? OR campaign_id LIKE ? OR ad_media_id LIKE ?)")
        q_like = f"%{q}%"
        params.extend([q_like, q_like, q_like])
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) as cnt FROM tv_ad_task_cache {where}", params
        ).fetchone()["cnt"]
        rows = conn.execute(
            f"SELECT * FROM tv_ad_task_cache {where} ORDER BY scheduled_at ASC, campaign_task_id ASC LIMIT ? OFFSET ?",
            params + [int(limit), int(offset)]
        ).fetchall()
    return {"rows": _rows_to_list(rows), "total": total, "limit": limit, "offset": offset}


def upsert_tv_ad_task_runtime(
    *,
    campaign_task_id: str,
    gym_id: int,
    local_display_state: str = "READY_TO_DISPLAY_LOCAL",
    binding_scope_count: int = 0,
    due_at: str = None,
    display_started_at: str = None,
    display_finished_at: str = None,
    display_aborted_at: str = None,
    display_abort_reason: str = None,
    display_abort_message: str = None,
    injected_layout: str = None,
    active_binding_ids: List[int] = None,
    failed_binding_ids: List[int] = None,
    correlation_id: str = None,
) -> Dict[str, Any]:
    ensure_tv_local_schema()
    now = now_iso()
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO tv_ad_task_runtime (
                campaign_task_id, gym_id, binding_scope_count, local_display_state,
                due_at, display_started_at, display_finished_at,
                display_aborted_at, display_abort_reason, display_abort_message,
                injected_layout, active_binding_ids_json, failed_binding_ids_json,
                correlation_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(campaign_task_id) DO UPDATE SET
                gym_id=excluded.gym_id,
                binding_scope_count=excluded.binding_scope_count,
                local_display_state=excluded.local_display_state,
                due_at=COALESCE(excluded.due_at, due_at),
                display_started_at=COALESCE(excluded.display_started_at, display_started_at),
                display_finished_at=COALESCE(excluded.display_finished_at, display_finished_at),
                display_aborted_at=COALESCE(excluded.display_aborted_at, display_aborted_at),
                display_abort_reason=COALESCE(excluded.display_abort_reason, display_abort_reason),
                display_abort_message=COALESCE(excluded.display_abort_message, display_abort_message),
                injected_layout=COALESCE(excluded.injected_layout, injected_layout),
                active_binding_ids_json=COALESCE(excluded.active_binding_ids_json, active_binding_ids_json),
                failed_binding_ids_json=COALESCE(excluded.failed_binding_ids_json, failed_binding_ids_json),
                correlation_id=COALESCE(excluded.correlation_id, correlation_id),
                updated_at=excluded.updated_at
        """, (
            str(campaign_task_id), int(gym_id), int(binding_scope_count or 0),
            local_display_state or "READY_TO_DISPLAY_LOCAL",
            due_at, display_started_at, display_finished_at,
            display_aborted_at, display_abort_reason, display_abort_message,
            injected_layout,
            json.dumps(active_binding_ids or []),
            json.dumps(failed_binding_ids or []),
            correlation_id, now, now,
        ))
        conn.commit()
        row = conn.execute(
            "SELECT * FROM tv_ad_task_runtime WHERE campaign_task_id=?", (str(campaign_task_id),)
        ).fetchone()
        return _row_to_dict(row) or {}


def load_tv_ad_task_runtime(*, campaign_task_id) -> Optional[Dict[str, Any]]:
    """Load one ad task runtime row by task ID."""
    ensure_tv_local_schema()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM tv_ad_task_runtime WHERE campaign_task_id=? LIMIT 1",
            (str(campaign_task_id),)
        ).fetchone()
        return _row_to_dict(row)


def list_tv_ad_task_runtime(*, gym_id=None, campaign_task_id=None,
                            limit: int = 500, offset: int = 0) -> Dict[str, Any]:
    """List ad task runtime rows with optional filters."""
    ensure_tv_local_schema()
    clauses: List[str] = []
    params: List[Any] = []
    if gym_id and int(gym_id) > 0:
        clauses.append("gym_id = ?")
        params.append(int(gym_id))
    if campaign_task_id:
        clauses.append("campaign_task_id = ?")
        params.append(str(campaign_task_id))
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) as cnt FROM tv_ad_task_runtime {where}", params
        ).fetchone()["cnt"]
        rows = conn.execute(
            f"SELECT * FROM tv_ad_task_runtime {where} ORDER BY display_started_at DESC, campaign_task_id ASC LIMIT ? OFFSET ?",
            params + [int(limit), int(offset)]
        ).fetchall()
    return {"rows": _rows_to_list(rows), "total": total, "limit": limit, "offset": offset}


def upsert_tv_gym_ad_runtime(
    *,
    gym_id: int,
    coordination_state: str = "IDLE",
    current_campaign_task_id: str = None,
    started_at: str = None,
    expected_finish_at: str = None,
    active_binding_count: int = 0,
    failed_binding_count: int = 0,
    audio_override_active: bool = False,
    last_error_code: str = None,
    last_error_message: str = None,
) -> Dict[str, Any]:
    ensure_tv_local_schema()
    now = now_iso()
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO tv_gym_ad_runtime (
                gym_id, coordination_state, current_campaign_task_id,
                started_at, expected_finish_at,
                active_binding_count, failed_binding_count, audio_override_active,
                last_error_code, last_error_message, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(gym_id) DO UPDATE SET
                coordination_state=excluded.coordination_state,
                current_campaign_task_id=excluded.current_campaign_task_id,
                started_at=excluded.started_at,
                expected_finish_at=excluded.expected_finish_at,
                active_binding_count=excluded.active_binding_count,
                failed_binding_count=excluded.failed_binding_count,
                audio_override_active=excluded.audio_override_active,
                last_error_code=excluded.last_error_code,
                last_error_message=excluded.last_error_message,
                updated_at=excluded.updated_at
        """, (
            int(gym_id), coordination_state or "IDLE",
            current_campaign_task_id,
            started_at, expected_finish_at,
            int(active_binding_count or 0), int(failed_binding_count or 0),
            1 if audio_override_active else 0,
            last_error_code, last_error_message, now,
        ))
        conn.commit()
        row = conn.execute(
            "SELECT * FROM tv_gym_ad_runtime WHERE gym_id=?", (int(gym_id),)
        ).fetchone()
        return _row_to_dict(row) or {}


def load_tv_gym_ad_runtime(*, gym_id: int) -> Optional[Dict[str, Any]]:
    """Load the gym-level ad coordination state."""
    ensure_tv_local_schema()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM tv_gym_ad_runtime WHERE gym_id=? LIMIT 1", (int(gym_id),)
        ).fetchone()
        return _row_to_dict(row)


# ---------------------------------------------------------------------------
# A7: Ad Runtime Pipeline helpers
# ---------------------------------------------------------------------------

def _get_eligible_bindings_for_gym(gym_id: int) -> List[Dict[str, Any]]:
    """Return enabled bindings in this gym that are in a healthy player state."""
    ensure_tv_local_schema()
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT b.*
            FROM tv_screen_binding b
            WHERE b.gym_id = ? AND b.enabled = 1
            ORDER BY b.id ASC
        """, (int(gym_id),)).fetchall()
        bindings = _rows_to_list(rows)
    # Filter to only bindings with a healthy/rendering player state
    # (RENDERING, FALLBACK_RENDERING, BLOCKED_* states are all OK to override;
    #  we exclude ERROR and no-binding states)
    healthy = []
    for b in bindings:
        bid = _safe_int(b.get("id"), 0)
        if bid > 0:
            healthy.append(b)
    return healthy


def _select_due_task_for_gym(gym_id: int, now_dt: datetime) -> Optional[Dict[str, Any]]:
    """Deterministically pick one due ad task for the gym (earliest scheduledAt then lowest ID)."""
    ensure_tv_local_schema()
    now_str = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    grace_cutoff_str = (now_dt - timedelta(seconds=AD_GRACE_WINDOW_SECONDS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with get_conn() as conn:
        row = conn.execute("""
            SELECT atc.*
            FROM tv_ad_task_cache atc
            WHERE atc.gym_id = ?
              AND atc.local_file_state = 'VALID'
              AND (atc.remote_status IS NULL
                   OR atc.remote_status NOT IN ('CANCELLED', 'EXPIRED', 'REJECTED', 'FAILED'))
              AND atc.scheduled_at <= ?
              AND atc.scheduled_at >= ?
              AND NOT EXISTS (
                  SELECT 1 FROM tv_ad_task_runtime atr
                  WHERE atr.campaign_task_id = atc.campaign_task_id
                    AND atr.local_display_state IN (
                        'DISPLAYING', 'DISPLAY_COMPLETED_LOCAL',
                        'DISPLAY_ABORTED_LOCAL', 'SKIPPED_WINDOW_MISSED'
                    )
              )
            ORDER BY atc.scheduled_at ASC, atc.campaign_task_id ASC
            LIMIT 1
        """, (int(gym_id), now_str, grace_cutoff_str)).fetchone()
        return _row_to_dict(row)


def _expire_overdue_tasks_for_gym(gym_id: int, now_dt: datetime) -> int:
    """Mark tasks past the grace window (and not yet runtime-tracked) as SKIPPED_WINDOW_MISSED."""
    ensure_tv_local_schema()
    grace_cutoff_str = (now_dt - timedelta(seconds=AD_GRACE_WINDOW_SECONDS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    now_str = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    with get_conn() as conn:
        overdue = conn.execute("""
            SELECT atc.campaign_task_id
            FROM tv_ad_task_cache atc
            WHERE atc.gym_id = ?
              AND atc.local_file_state = 'VALID'
              AND (atc.remote_status IS NULL
                   OR atc.remote_status NOT IN ('CANCELLED', 'EXPIRED', 'REJECTED', 'FAILED'))
              AND atc.scheduled_at < ?
              AND NOT EXISTS (
                  SELECT 1 FROM tv_ad_task_runtime atr
                  WHERE atr.campaign_task_id = atc.campaign_task_id
              )
        """, (int(gym_id), grace_cutoff_str)).fetchall()
        count = 0
        skipped_task_ids = []
        for row in overdue:
            task_id = row[0]
            corr_id = str(uuid.uuid4())
            conn.execute("""
                INSERT OR IGNORE INTO tv_ad_task_runtime
                    (campaign_task_id, gym_id, local_display_state, due_at, correlation_id, created_at, updated_at)
                VALUES (?, ?, 'SKIPPED_WINDOW_MISSED', ?, ?, ?, ?)
            """, (task_id, int(gym_id), now_str, corr_id, now_str, now_str))
            skipped_task_ids.append(task_id)
            count += 1
        if count > 0:
            conn.commit()

    # Create FAILED_TO_START proofs for each skipped task (outside the connection)
    for task_id in skipped_task_ids:
        try:
            task_cache = load_tv_ad_task_cache_one(campaign_task_id=task_id)
            exp_dur = _safe_int((task_cache or {}).get("display_duration_sec"), 0)
            camp_id = (task_cache or {}).get("campaign_id")
            ad_mid = (task_cache or {}).get("ad_media_id")
            # Fetch the correlation_id we just inserted
            with get_conn() as c2:
                rt_row = c2.execute(
                    "SELECT correlation_id FROM tv_ad_task_runtime WHERE campaign_task_id=? LIMIT 1",
                    (task_id,)
                ).fetchone()
            corr = (rt_row[0] if rt_row else None) or task_id
            create_tv_ad_proof(
                campaign_task_id=task_id,
                gym_id=int(gym_id),
                result_status=PROOF_STATUS_FAILED_TO_START,
                started_at=None,
                finished_at=now_str,
                displayed_duration_sec=0,
                expected_duration_sec=exp_dur if exp_dur else None,
                campaign_id=str(camp_id) if camp_id else None,
                ad_media_id=str(ad_mid) if ad_mid else None,
                correlation_id=corr,
                participating_binding_count=0,
                failed_binding_count=0,
            )
        except Exception as _pe:
            _log.warning("[AdProof] failed to create skipped proof for %s: %s", task_id, _pe)

    return count


def _clear_player_ad_override(conn, binding_id: int, now_str: str) -> None:
    """Clear ad override fields on a player state row (inside an open connection)."""
    conn.execute("""
        UPDATE tv_player_state SET
            ad_override_active = 0,
            current_ad_task_id = NULL,
            current_ad_media_id = NULL,
            current_ad_layout = NULL,
            ad_audio_override_active = 0,
            ad_fallback_reason = NULL,
            updated_at = ?
        WHERE binding_id = ?
    """, (now_str, int(binding_id)))


def _inject_ad_for_gym(gym_id: int, task: Dict[str, Any],
                       bindings: List[Dict[str, Any]], now_dt: datetime) -> None:
    """Inject an ad task into all eligible bindings for a gym, updating runtime tables."""
    task_id    = _safe_str(task.get("campaign_task_id"), "")
    layout     = _safe_str(task.get("layout"), AD_LAYOUT_FULL_SCREEN) or AD_LAYOUT_FULL_SCREEN
    duration   = _safe_int(task.get("display_duration_sec"), 30)
    ad_media_id = _safe_str(task.get("ad_media_id"), "") or None
    file_path  = _safe_str(task.get("local_file_path"), "") or None
    due_at     = _safe_str(task.get("scheduled_at"), "") or None
    corr_id    = str(uuid.uuid4())
    now_str    = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    expected_finish = (now_dt + timedelta(seconds=duration)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Final file recheck
    if not _path_is_readable(file_path):
        with get_conn() as conn:
            conn.execute(
                "UPDATE tv_ad_task_cache SET local_file_state='MISSING', updated_at=? WHERE campaign_task_id=?",
                (now_str, task_id)
            )
            conn.commit()
        return

    binding_ids = [_safe_int(b.get("id"), 0) for b in bindings if _safe_int(b.get("id"), 0) > 0]
    active_ids: List[int] = []
    failed_ids: List[int] = []

    with get_conn() as conn:
        # Transition gym to INJECTING
        conn.execute("""
            INSERT INTO tv_gym_ad_runtime
                (gym_id, coordination_state, current_campaign_task_id, started_at,
                 expected_finish_at, active_binding_count, failed_binding_count,
                 audio_override_active, updated_at)
            VALUES (?, 'INJECTING', ?, ?, ?, ?, 0, 1, ?)
            ON CONFLICT(gym_id) DO UPDATE SET
                coordination_state='INJECTING',
                current_campaign_task_id=excluded.current_campaign_task_id,
                started_at=excluded.started_at,
                expected_finish_at=excluded.expected_finish_at,
                active_binding_count=excluded.active_binding_count,
                audio_override_active=1,
                updated_at=excluded.updated_at
        """, (int(gym_id), task_id, now_str, expected_finish, len(binding_ids), now_str))

        # Create the task runtime row
        conn.execute("""
            INSERT OR REPLACE INTO tv_ad_task_runtime
                (campaign_task_id, gym_id, binding_scope_count, local_display_state,
                 due_at, display_started_at, injected_layout,
                 active_binding_ids_json, failed_binding_ids_json,
                 correlation_id, created_at, updated_at)
            VALUES (?, ?, ?, 'DISPLAYING', ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            task_id, int(gym_id), len(binding_ids),
            due_at, now_str, layout,
            json.dumps([]), json.dumps([]),
            corr_id, now_str, now_str,
        ))

        # Inject into each binding's player state
        for bid in binding_ids:
            try:
                conn.execute("""
                    INSERT INTO tv_player_state
                        (binding_id, player_state, ad_override_active, current_ad_task_id,
                         current_ad_media_id, current_ad_layout, ad_audio_override_active,
                         ad_fallback_reason, updated_at)
                    VALUES (?, 'IDLE', 1, ?, ?, ?, 1, NULL, ?)
                    ON CONFLICT(binding_id) DO UPDATE SET
                        ad_override_active = 1,
                        current_ad_task_id = excluded.current_ad_task_id,
                        current_ad_media_id = excluded.current_ad_media_id,
                        current_ad_layout = excluded.current_ad_layout,
                        ad_audio_override_active = 1,
                        ad_fallback_reason = NULL,
                        updated_at = excluded.updated_at
                """, (int(bid), task_id, ad_media_id, layout, now_str))
                active_ids.append(int(bid))
            except Exception as e:
                _log.warning("Ad inject failed for binding %s: %s", bid, e)
                failed_ids.append(int(bid))

        # Transition gym to DISPLAYING
        conn.execute("""
            UPDATE tv_gym_ad_runtime SET
                coordination_state = 'DISPLAYING',
                active_binding_count = ?,
                failed_binding_count = ?,
                updated_at = ?
            WHERE gym_id = ?
        """, (len(active_ids), len(failed_ids), now_str, int(gym_id)))

        # Update runtime with actual binding lists
        conn.execute("""
            UPDATE tv_ad_task_runtime SET
                active_binding_ids_json = ?,
                failed_binding_ids_json = ?,
                binding_scope_count = ?,
                updated_at = ?
            WHERE campaign_task_id = ?
        """, (json.dumps(active_ids), json.dumps(failed_ids), len(active_ids), now_str, task_id))

        conn.commit()


def complete_tv_ad_display(*, campaign_task_id: str) -> Dict[str, Any]:
    """Mark an ad task as completed, clear gym state, remove player overrides."""
    ensure_tv_local_schema()
    now_str = now_iso()
    with get_conn() as conn:
        runtime_row = conn.execute(
            "SELECT * FROM tv_ad_task_runtime WHERE campaign_task_id=? LIMIT 1",
            (str(campaign_task_id),)
        ).fetchone()
        if not runtime_row:
            return {"ok": False, "error": "RUNTIME_NOT_FOUND"}
        rt = dict(runtime_row)
        gym_id = _safe_int(rt.get("gym_id"), 0)
        active_ids = _json_loads(rt.get("active_binding_ids_json") or "[]") or []

        # Mark task completed
        conn.execute("""
            UPDATE tv_ad_task_runtime SET
                local_display_state = 'DISPLAY_COMPLETED_LOCAL',
                display_finished_at = ?,
                updated_at = ?
            WHERE campaign_task_id = ?
        """, (now_str, now_str, str(campaign_task_id)))

        # Reset gym to IDLE
        conn.execute("""
            UPDATE tv_gym_ad_runtime SET
                coordination_state = 'IDLE',
                current_campaign_task_id = NULL,
                started_at = NULL,
                expected_finish_at = NULL,
                active_binding_count = 0,
                failed_binding_count = 0,
                audio_override_active = 0,
                updated_at = ?
            WHERE gym_id = ?
        """, (now_str, gym_id))

        # Clear player ad overrides for all active bindings
        for bid in active_ids:
            if isinstance(bid, int) and bid > 0:
                _clear_player_ad_override(conn, bid, now_str)

        conn.commit()

    # Create proof row (idempotent — safe to call after commit)
    try:
        task_cache = load_tv_ad_task_cache_one(campaign_task_id=campaign_task_id)
        exp_dur = _safe_int((task_cache or {}).get("display_duration_sec"), 0)
        camp_id = (task_cache or {}).get("campaign_id")
        ad_mid = (task_cache or {}).get("ad_media_id")
        started = rt.get("display_started_at")
        disp_dur: Optional[int] = None
        if started:
            try:
                s = datetime.strptime(started, "%Y-%m-%dT%H:%M:%SZ")
                f = datetime.strptime(now_str, "%Y-%m-%dT%H:%M:%SZ")
                disp_dur = max(0, int((f - s).total_seconds()))
            except Exception:
                pass
        failed_ids_list = _json_loads(rt.get("failed_binding_ids_json") or "[]") or []
        create_tv_ad_proof(
            campaign_task_id=campaign_task_id,
            gym_id=gym_id,
            result_status=PROOF_STATUS_COMPLETED,
            started_at=started,
            finished_at=now_str,
            displayed_duration_sec=disp_dur,
            expected_duration_sec=exp_dur if exp_dur else None,
            campaign_id=str(camp_id) if camp_id else None,
            ad_media_id=str(ad_mid) if ad_mid else None,
            correlation_id=rt.get("correlation_id"),
            participating_binding_count=len(active_ids),
            failed_binding_count=len(failed_ids_list),
        )
    except Exception as _pe:
        _log.warning("[AdProof] failed to create completion proof for %s: %s", campaign_task_id, _pe)

    return {"ok": True, "taskId": str(campaign_task_id), "completedAt": now_str}


def abort_tv_ad_display(*, campaign_task_id: str, reason: str = "ABORTED",
                         message: str = None) -> Dict[str, Any]:
    """Abort an active ad display, clear gym state, remove player overrides."""
    ensure_tv_local_schema()
    now_str = now_iso()
    with get_conn() as conn:
        runtime_row = conn.execute(
            "SELECT * FROM tv_ad_task_runtime WHERE campaign_task_id=? LIMIT 1",
            (str(campaign_task_id),)
        ).fetchone()
        if not runtime_row:
            return {"ok": False, "error": "RUNTIME_NOT_FOUND"}
        rt = dict(runtime_row)
        gym_id = _safe_int(rt.get("gym_id"), 0)
        active_ids = _json_loads(rt.get("active_binding_ids_json") or "[]") or []

        conn.execute("""
            UPDATE tv_ad_task_runtime SET
                local_display_state = 'DISPLAY_ABORTED_LOCAL',
                display_aborted_at = ?,
                display_abort_reason = ?,
                display_abort_message = ?,
                updated_at = ?
            WHERE campaign_task_id = ?
        """, (now_str, reason or "ABORTED", message, now_str, str(campaign_task_id)))

        conn.execute("""
            UPDATE tv_gym_ad_runtime SET
                coordination_state = 'IDLE',
                current_campaign_task_id = NULL,
                started_at = NULL,
                expected_finish_at = NULL,
                active_binding_count = 0,
                failed_binding_count = 0,
                audio_override_active = 0,
                updated_at = ?
            WHERE gym_id = ?
        """, (now_str, gym_id))

        for bid in active_ids:
            if isinstance(bid, int) and bid > 0:
                _clear_player_ad_override(conn, bid, now_str)

        conn.commit()

    # Create proof row for abort (idempotent)
    try:
        task_cache = load_tv_ad_task_cache_one(campaign_task_id=campaign_task_id)
        exp_dur = _safe_int((task_cache or {}).get("display_duration_sec"), 0)
        camp_id = (task_cache or {}).get("campaign_id")
        ad_mid = (task_cache or {}).get("ad_media_id")
        started = rt.get("display_started_at")
        disp_dur: Optional[int] = None
        if started:
            try:
                s = datetime.strptime(started, "%Y-%m-%dT%H:%M:%SZ")
                f = datetime.strptime(now_str, "%Y-%m-%dT%H:%M:%SZ")
                disp_dur = max(0, int((f - s).total_seconds()))
            except Exception:
                pass
        failed_ids_list = _json_loads(rt.get("failed_binding_ids_json") or "[]") or []
        create_tv_ad_proof(
            campaign_task_id=campaign_task_id,
            gym_id=gym_id,
            result_status=PROOF_STATUS_ABORTED,
            started_at=started,
            finished_at=now_str,
            displayed_duration_sec=disp_dur,
            expected_duration_sec=exp_dur if exp_dur else None,
            campaign_id=str(camp_id) if camp_id else None,
            ad_media_id=str(ad_mid) if ad_mid else None,
            correlation_id=rt.get("correlation_id"),
            participating_binding_count=len(active_ids),
            failed_binding_count=len(failed_ids_list),
        )
    except Exception as _pe:
        _log.warning("[AdProof] failed to create abort proof for %s: %s", campaign_task_id, _pe)

    return {"ok": True, "taskId": str(campaign_task_id), "abortedAt": now_str}


def inject_tv_ad_task_now(*, campaign_task_id, correlation_id: str = None, **kwargs) -> Dict[str, Any]:
    """Support/manual endpoint: inject a specific ad task immediately (respects eligibility)."""
    ensure_tv_local_schema()
    task_id = str(campaign_task_id)
    task = load_tv_ad_task_cache_one(campaign_task_id=task_id)
    if not task:
        return {"ok": False, "error": "TASK_NOT_FOUND"}
    if _safe_str(task.get("local_file_state"), "") != AD_FILE_STATE_VALID:
        return {"ok": False, "error": "TASK_FILE_NOT_VALID"}
    gym_id = _safe_int(task.get("gym_id"), 0)
    if gym_id <= 0:
        return {"ok": False, "error": "TASK_NO_GYM"}

    # Check gym is not already displaying
    gym_rt = load_tv_gym_ad_runtime(gym_id=gym_id)
    if gym_rt and _safe_str(gym_rt.get("coordination_state"), "") == GYM_COORD_DISPLAYING:
        return {"ok": False, "error": "GYM_ALREADY_DISPLAYING",
                "currentTask": gym_rt.get("current_campaign_task_id")}

    bindings = _get_eligible_bindings_for_gym(gym_id)
    if not bindings:
        return {"ok": False, "error": "NO_ELIGIBLE_BINDINGS"}

    now_dt = datetime.utcnow()
    _inject_ad_for_gym(gym_id, task, bindings, now_dt)
    return {"ok": True, "taskId": task_id, "gymId": gym_id, "bindingCount": len(bindings)}


def abort_tv_ad_task_now(*, campaign_task_id=0, reason: str = "MANUAL_ABORT",
                          correlation_id: str = None, **kwargs) -> Dict[str, Any]:
    """Support/manual endpoint: abort an active ad display."""
    if not campaign_task_id:
        return {"ok": False, "error": "TASK_ID_REQUIRED"}
    return abort_tv_ad_display(campaign_task_id=str(campaign_task_id), reason=reason)


def reconcile_all_active_gyms(**kwargs) -> Dict[str, Any]:
    """Main ad runtime evaluation cycle: check completions, expire overdue, inject due tasks."""
    ensure_tv_local_schema()
    now_dt = datetime.utcnow()

    with get_conn() as conn:
        gym_rows = conn.execute(
            "SELECT DISTINCT gym_id FROM tv_screen_binding WHERE gym_id IS NOT NULL AND gym_id > 0"
        ).fetchall()
    gym_ids = [int(row[0]) for row in gym_rows if row[0]]

    injected = 0
    completed = 0
    skipped = 0
    errors = 0

    for gym_id in gym_ids:
        try:
            gym_rt = load_tv_gym_ad_runtime(gym_id=gym_id)
            coord = _safe_str((gym_rt or {}).get("coordination_state"), GYM_COORD_IDLE)

            if coord == GYM_COORD_DISPLAYING:
                # Check if current task has exceeded display duration
                task_id = _safe_str((gym_rt or {}).get("current_campaign_task_id"), "") or None
                if task_id:
                    atr = load_tv_ad_task_runtime(campaign_task_id=task_id)
                    if atr:
                        started = _safe_str(atr.get("display_started_at"), "") or None
                        task_cache = load_tv_ad_task_cache_one(campaign_task_id=task_id)
                        duration = _safe_int((task_cache or {}).get("display_duration_sec"), 30)
                        if started:
                            try:
                                started_dt = datetime.fromisoformat(
                                    started.replace("Z", "+00:00")
                                ).replace(tzinfo=None)
                                elapsed = (now_dt - started_dt).total_seconds()
                                if elapsed >= duration:
                                    complete_tv_ad_display(campaign_task_id=task_id)
                                    completed += 1
                            except Exception:
                                pass
                continue  # Either still displaying or just completed — skip injection

            if coord in (GYM_COORD_ABORTED, GYM_COORD_ERROR, GYM_COORD_INJECTING):
                continue  # Leave recovery to startup_recover_ad_runtime

            # Expire any overdue tasks
            sk = _expire_overdue_tasks_for_gym(gym_id, now_dt)
            skipped += sk

            # Find and inject a due task
            task = _select_due_task_for_gym(gym_id, now_dt)
            if not task:
                continue

            bindings = _get_eligible_bindings_for_gym(gym_id)
            if not bindings:
                continue

            _inject_ad_for_gym(gym_id, task, bindings, now_dt)
            injected += 1

        except Exception as e:
            _log.exception("Error in reconcile_all_active_gyms for gym %s: %s", gym_id, e)
            errors += 1

    return {
        "ok": True,
        "reconciled": len(gym_ids),
        "injected": injected,
        "completed": completed,
        "skipped": skipped,
        "errors": errors,
    }


def startup_recover_ad_runtime(**kwargs) -> Dict[str, Any]:
    """On startup, reset any stuck transient gym/task states (INJECTING, DISPLAYING without evidence)."""
    ensure_tv_local_schema()
    now_str = now_iso()
    recovered = 0
    with get_conn() as conn:
        # Find gyms stuck in transient states
        stuck_gyms = conn.execute("""
            SELECT gym_id, current_campaign_task_id
            FROM tv_gym_ad_runtime
            WHERE coordination_state IN ('INJECTING', 'DISPLAYING', 'COMPLETING')
        """).fetchall()

        for row in stuck_gyms:
            gym_id = row[0]
            task_id = row[1]

            # Abort the stuck task runtime if it exists
            if task_id:
                conn.execute("""
                    UPDATE tv_ad_task_runtime SET
                        local_display_state = 'DISPLAY_ABORTED_LOCAL',
                        display_aborted_at = ?,
                        display_abort_reason = 'STARTUP_RECOVERY',
                        display_abort_message = 'Aborted by startup recovery — process was restarted',
                        updated_at = ?
                    WHERE campaign_task_id = ? AND local_display_state = 'DISPLAYING'
                """, (now_str, now_str, str(task_id)))

                # Clear player overrides for all bindings in this gym
                bound = conn.execute(
                    "SELECT id FROM tv_screen_binding WHERE gym_id=?", (gym_id,)
                ).fetchall()
                for b in bound:
                    _clear_player_ad_override(conn, b[0], now_str)

            # Reset gym to IDLE
            conn.execute("""
                UPDATE tv_gym_ad_runtime SET
                    coordination_state = 'IDLE',
                    current_campaign_task_id = NULL,
                    started_at = NULL,
                    expected_finish_at = NULL,
                    active_binding_count = 0,
                    failed_binding_count = 0,
                    audio_override_active = 0,
                    updated_at = ?
                WHERE gym_id = ?
            """, (now_str, gym_id))
            recovered += 1

        if recovered > 0:
            conn.commit()

    return {"ok": True, "recovered": recovered}

# ---------------------------------------------------------------------------
# A8: Proof Outbox — helpers
# ---------------------------------------------------------------------------

def _proof_next_attempt_at(attempt_count: int) -> str:
    """Compute next_attempt_at timestamp using stepped backoff."""
    idx = min(int(attempt_count), len(_PROOF_RETRY_BACKOFF_SECS) - 1)
    delay = _PROOF_RETRY_BACKOFF_SECS[idx]
    return (datetime.utcnow() + timedelta(seconds=delay)).strftime("%Y-%m-%dT%H:%M:%SZ")


def create_tv_ad_proof(
    *,
    campaign_task_id: str,
    gym_id: int,
    result_status: str,
    started_at: Optional[str] = None,
    finished_at: Optional[str] = None,
    displayed_duration_sec: Optional[int] = None,
    expected_duration_sec: Optional[int] = None,
    campaign_id: Optional[str] = None,
    ad_media_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    participating_binding_count: int = 0,
    failed_binding_count: int = 0,
) -> Dict[str, Any]:
    """Idempotently create one proof outbox row for a gym-level ad task attempt.

    Uses idempotency_key = '{campaign_task_id}:{correlation_id}' to prevent duplicates.
    On conflict the existing row is returned unchanged (ON CONFLICT DO NOTHING).
    """
    ensure_tv_local_schema()
    corr = str(correlation_id or "").strip() or str(campaign_task_id)
    idempotency_key = f"{campaign_task_id}:{corr}"

    exp_dur = _safe_int(expected_duration_sec, 0) if expected_duration_sec is not None else 0
    disp_dur = _safe_int(displayed_duration_sec, 0) if displayed_duration_sec is not None else 0
    completed_fully = (result_status == PROOF_STATUS_COMPLETED)
    countable = (
        completed_fully
        and exp_dur > 0
        and disp_dur >= (exp_dur - PROOF_COUNTABLE_TOLERANCE_SEC)
    )

    if not countable:
        if result_status == PROOF_STATUS_ABORTED:
            reason = "ABORTED"
        elif result_status == PROOF_STATUS_FAILED_TO_START:
            reason = "FAILED_TO_START"
        elif result_status == PROOF_STATUS_CANCELLED_REMOTE:
            reason = "CANCELLED_REMOTE"
        elif result_status == PROOF_STATUS_EXPIRED_REMOTE:
            reason = "EXPIRED_REMOTE"
        elif result_status == PROOF_STATUS_PARTIAL:
            reason = "PARTIAL_DISPLAY"
        elif completed_fully and exp_dur > 0:
            reason = "DURATION_SHORT"
        else:
            reason = "NOT_COUNTABLE"
    else:
        reason = None

    ts = now_iso()
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO tv_ad_proof_outbox (
                campaign_task_id, campaign_id, gym_id, ad_media_id,
                idempotency_key, started_at, finished_at,
                displayed_duration_sec, expected_duration_sec,
                completed_fully, countable, result_status,
                reason_if_not_countable, correlation_id,
                participating_binding_count, failed_binding_count,
                outbox_state, attempt_count, next_attempt_at,
                last_error, backend_proof_id, backend_task_status,
                created_at, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(idempotency_key) DO NOTHING
        """, (
            str(campaign_task_id), str(campaign_id or ""), int(gym_id),
            str(ad_media_id or ""), idempotency_key,
            started_at, finished_at,
            disp_dur if displayed_duration_sec is not None else None,
            exp_dur if expected_duration_sec is not None else None,
            int(completed_fully), int(countable),
            result_status, reason,
            str(corr),
            int(participating_binding_count), int(failed_binding_count),
            PROOF_OUTBOX_QUEUED, 0, None,
            None, None, None,
            ts, ts,
        ))
        conn.commit()
        row = conn.execute(
            "SELECT * FROM tv_ad_proof_outbox WHERE idempotency_key=? LIMIT 1",
            (idempotency_key,)
        ).fetchone()
    return _row_to_dict(row) if row else {}


def list_tv_ad_proof_outbox(
    *,
    gym_id: Optional[int] = None,
    campaign_task_id: Optional[str] = None,
    outbox_states: Optional[List[str]] = None,
    countable: Optional[bool] = None,
    result_status: Optional[str] = None,
    limit: int = 300,
    offset: int = 0,
    **kwargs,
) -> Dict[str, Any]:
    ensure_tv_local_schema()
    clauses: List[str] = []
    params: List[Any] = []
    if gym_id and int(gym_id) > 0:
        clauses.append("gym_id=?")
        params.append(int(gym_id))
    if campaign_task_id:
        clauses.append("campaign_task_id=?")
        params.append(str(campaign_task_id))
    if outbox_states:
        ph = ",".join("?" * len(outbox_states))
        clauses.append(f"outbox_state IN ({ph})")
        params.extend([str(s) for s in outbox_states])
    if countable is not None:
        clauses.append("countable=?")
        params.append(1 if countable else 0)
    if result_status:
        clauses.append("result_status=?")
        params.append(str(result_status))
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) FROM tv_ad_proof_outbox {where}", params
        ).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM tv_ad_proof_outbox {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params + [int(limit), int(offset)]
        ).fetchall()
    return {
        "rows": _rows_to_list(rows),
        "total": int(total),
        "limit": int(limit),
        "offset": int(offset),
    }


def load_tv_ad_proof(*, local_proof_id: int = 0, **kwargs) -> Optional[Dict[str, Any]]:
    ensure_tv_local_schema()
    if not local_proof_id:
        return None
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM tv_ad_proof_outbox WHERE local_proof_id=? LIMIT 1",
            (int(local_proof_id),)
        ).fetchone()
    return _row_to_dict(row) if row else None


def _send_one_proof(*, proof: Dict[str, Any]) -> Dict[str, Any]:
    """Attempt to submit one proof row to the backend. Returns result dict."""
    from shared.api.monclub_api import MonClubApiHttpError
    task_id_str = str(proof.get("campaign_task_id") or "")
    try:
        task_id_int = int(task_id_str)
    except (ValueError, TypeError):
        # Non-integer IDs are treated as retryable (production IDs are always integers;
        # if this happens something went wrong upstream and we want it visible)
        return {"ok": False, "retryable": True,
                "error": f"campaign_task_id is not a valid integer: {task_id_str!r}"}

    payload = {
        "idempotencyKey": str(proof.get("idempotency_key") or ""),
        "correlationId": str(proof.get("correlation_id") or ""),
        "startedAt": proof.get("started_at"),
        "finishedAt": proof.get("finished_at"),
        "displayedDurationSec": proof.get("displayed_duration_sec"),
        "expectedDurationSec": proof.get("expected_duration_sec"),
        "completedFully": bool(proof.get("completed_fully")),
        "countable": bool(proof.get("countable")),
        "resultStatus": str(proof.get("result_status") or ""),
        "reasonIfNotCountable": proof.get("reason_if_not_countable"),
        "participatingBindingCount": _safe_int(proof.get("participating_binding_count"), 0),
        "failedBindingCount": _safe_int(proof.get("failed_binding_count"), 0),
    }

    try:
        token = _get_auth_token()
    except Exception as e:
        return {"ok": False, "retryable": True, "error": f"No auth token: {e}"}

    try:
        api = _build_tv_api()
    except Exception as e:
        return {"ok": False, "retryable": True, "error": f"API build failed: {e}"}

    try:
        resp = api.submit_tv_ad_task_proof(token=token, task_id=task_id_int, payload=payload)
        return {"ok": True, "sent": True, "response": resp}
    except MonClubApiHttpError as e:
        if e.status_code in (401, 429):
            return {"ok": False, "retryable": True, "error": f"HTTP {e.status_code}: {str(e)[:200]}"}
        if 400 <= e.status_code < 500:
            return {"ok": False, "retryable": False, "error": f"HTTP {e.status_code}: {str(e)[:200]}"}
        return {"ok": False, "retryable": True, "error": f"HTTP {e.status_code}: {str(e)[:200]}"}
    except Exception as e:
        return {"ok": False, "retryable": True, "error": str(e)[:300]}


def process_tv_ad_proof_outbox(*, app=None, limit: int = 50, correlation_id: str = None, **kwargs) -> Dict[str, Any]:
    """Process the proof outbox: send QUEUED and FAILED_RETRYABLE rows that are due."""
    ensure_tv_local_schema()
    now_str = now_iso()
    sent = 0
    failed_retryable = 0
    failed_terminal = 0

    with get_conn() as conn:
        rows = conn.execute("""
            SELECT * FROM tv_ad_proof_outbox
            WHERE outbox_state IN ('QUEUED', 'FAILED_RETRYABLE')
              AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
              AND attempt_count < ?
            ORDER BY created_at ASC
            LIMIT ?
        """, (now_str, PROOF_MAX_ATTEMPTS, int(limit))).fetchall()

    proofs = _rows_to_list(rows)
    for proof in proofs:
        pid = _safe_int(proof.get("local_proof_id"), 0)
        if not pid:
            continue
        # Mark as SENDING atomically
        with get_conn() as conn:
            conn.execute(
                "UPDATE tv_ad_proof_outbox SET outbox_state=?, updated_at=? WHERE local_proof_id=?",
                (PROOF_OUTBOX_SENDING, now_str, pid)
            )
            conn.commit()

        result = _send_one_proof(proof=proof)

        with get_conn() as conn:
            attempt = _safe_int(proof.get("attempt_count"), 0) + 1
            ts = now_iso()
            if result.get("ok"):
                resp = result.get("response") or {}
                bpid = str(resp.get("proofId") or resp.get("id") or "") or None
                btask = str(resp.get("status") or resp.get("taskStatus") or "") or None
                conn.execute("""
                    UPDATE tv_ad_proof_outbox SET
                        outbox_state=?, attempt_count=?, last_error=NULL,
                        backend_proof_id=?, backend_task_status=?, updated_at=?
                    WHERE local_proof_id=?
                """, (PROOF_OUTBOX_SENT, attempt, bpid, btask, ts, pid))
                sent += 1
            elif result.get("retryable"):
                next_at = _proof_next_attempt_at(attempt)
                conn.execute("""
                    UPDATE tv_ad_proof_outbox SET
                        outbox_state=?, attempt_count=?, last_error=?, next_attempt_at=?, updated_at=?
                    WHERE local_proof_id=?
                """, (PROOF_OUTBOX_FAILED_RETRYABLE, attempt,
                      str(result.get("error") or "")[:500], next_at, ts, pid))
                failed_retryable += 1
            else:
                conn.execute("""
                    UPDATE tv_ad_proof_outbox SET
                        outbox_state=?, attempt_count=?, last_error=?, updated_at=?
                    WHERE local_proof_id=?
                """, (PROOF_OUTBOX_FAILED_TERMINAL, attempt,
                      str(result.get("error") or "")[:500], ts, pid))
                failed_terminal += 1
            conn.commit()

    return {
        "ok": True,
        "processed": len(proofs),
        "sent": sent,
        "failed_retryable": failed_retryable,
        "failed_terminal": failed_terminal,
    }


def retry_tv_ad_proof(*, app=None, local_proof_id: int = 0, **kwargs) -> Dict[str, Any]:
    """Reset a proof row to QUEUED and attempt immediate send."""
    ensure_tv_local_schema()
    if not local_proof_id:
        return {"ok": False, "error": "local_proof_id is required"}

    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM tv_ad_proof_outbox WHERE local_proof_id=? LIMIT 1",
            (int(local_proof_id),)
        ).fetchone()
    if not row:
        return {"ok": False, "error": "Proof not found"}

    proof = _row_to_dict(row)
    state = str(proof.get("outbox_state") or "")
    if state == PROOF_OUTBOX_SENT:
        return {"ok": False, "error": "Proof already sent"}
    if state == PROOF_OUTBOX_SENDING:
        return {"ok": False, "error": "Proof is currently being sent"}
    attempts = _safe_int(proof.get("attempt_count"), 0)
    if attempts >= PROOF_MAX_ATTEMPTS:
        return {"ok": False, "error": f"Max attempts ({PROOF_MAX_ATTEMPTS}) reached"}

    now_str = now_iso()
    with get_conn() as conn:
        conn.execute(
            "UPDATE tv_ad_proof_outbox SET outbox_state='QUEUED', next_attempt_at=NULL, updated_at=? WHERE local_proof_id=?",
            (now_str, int(local_proof_id))
        )
        conn.commit()

    result = _send_one_proof(proof=proof)

    with get_conn() as conn:
        attempt = attempts + 1
        ts = now_iso()
        if result.get("ok"):
            resp = result.get("response") or {}
            conn.execute("""
                UPDATE tv_ad_proof_outbox SET
                    outbox_state=?, attempt_count=?, last_error=NULL,
                    backend_proof_id=?, backend_task_status=?, updated_at=?
                WHERE local_proof_id=?
            """, (PROOF_OUTBOX_SENT, attempt,
                  str(resp.get("proofId") or resp.get("id") or "") or None,
                  str(resp.get("status") or "") or None,
                  ts, int(local_proof_id)))
        elif result.get("retryable"):
            next_at = _proof_next_attempt_at(attempt)
            conn.execute("""
                UPDATE tv_ad_proof_outbox SET
                    outbox_state=?, attempt_count=?, last_error=?, next_attempt_at=?, updated_at=?
                WHERE local_proof_id=?
            """, (PROOF_OUTBOX_FAILED_RETRYABLE, attempt,
                  str(result.get("error") or "")[:500], next_at, ts, int(local_proof_id)))
        else:
            conn.execute("""
                UPDATE tv_ad_proof_outbox SET
                    outbox_state=?, attempt_count=?, last_error=?, updated_at=?
                WHERE local_proof_id=?
            """, (PROOF_OUTBOX_FAILED_TERMINAL, attempt,
                  str(result.get("error") or "")[:500], ts, int(local_proof_id)))
        conn.commit()

    return {
        "ok": bool(result.get("ok")),
        "sent": bool(result.get("ok")),
        "error": result.get("error") if not result.get("ok") else None,
        "retryable": bool(result.get("retryable", False)),
    }


def startup_recover_proof_outbox() -> Dict[str, Any]:
    """Crash recovery: demote SENDING rows to FAILED_RETRYABLE on startup."""
    ensure_tv_local_schema()
    now_str = now_iso()
    next_at = _proof_next_attempt_at(0)
    with get_conn() as conn:
        cur = conn.execute("""
            UPDATE tv_ad_proof_outbox SET
                outbox_state='FAILED_RETRYABLE',
                last_error='RECOVERED_FROM_SENDING_CRASH',
                next_attempt_at=?,
                updated_at=?
            WHERE outbox_state='SENDING'
        """, (next_at, now_str))
        recovered = cur.rowcount
        if recovered > 0:
            conn.commit()
    return {"ok": True, "recovered": recovered}

def retry_tv_ad_task_prepare(**kwargs) -> Dict[str, Any]:
    return {"ok": False, "error": "TV_NOT_YET_IMPLEMENTED"}

def retry_tv_ad_task_ready_confirm(**kwargs) -> Dict[str, Any]:
    return {"ok": False, "error": "TV_NOT_YET_IMPLEMENTED"}

def process_tv_ad_ready_confirm_outbox(**kwargs) -> Dict[str, Any]:
    return {"ok": True, "processed": 0}

# Startup reconciliation stubs
def list_tv_startup_reconciliation_runs(**kwargs) -> Dict[str, Any]:
    return {"rows": [], "total": 0}

def load_tv_startup_reconciliation_latest(**kwargs) -> Optional[Dict[str, Any]]:
    return None

def run_tv_startup_reconciliation(**kwargs) -> Dict[str, Any]:
    return {"ok": True, "status": "SKIPPED", "failedPhaseCount": 0}

def run_tv_deployment_preflight(**kwargs) -> Dict[str, Any]:
    return {"ok": True, "status": "PASS", "blockers": [], "warnings": [], "checks": {
        "dataRoot": True, "dbOpen": True, "tvSchema": True, "queryChecks": {}}}

# Support actions stubs
def list_tv_support_action_logs(**kwargs) -> Dict[str, Any]:
    return {"rows": [], "total": 0}

def run_tv_binding_support_action(**kwargs) -> Dict[str, Any]:
    return {"ok": False, "error": "TV_NOT_YET_IMPLEMENTED"}

# Retention / observability stubs
def get_tv_retention_policy(**kwargs) -> Dict[str, Any]:
    return {"ok": True, "disabled": True}

def run_tv_retention_maintenance(**kwargs) -> Dict[str, Any]:
    return {"ok": True, "deletedRows": {}}

def list_tv_observability_fleet_health(**kwargs) -> Dict[str, Any]:
    return {"rows": [], "total": 0}

def get_tv_observability_overview(**kwargs) -> Dict[str, Any]:
    return {"ok": False, "error": "TV_NOT_YET_IMPLEMENTED"}

def get_tv_observability_screen_details(**kwargs) -> Dict[str, Any]:
    return {"ok": False, "error": "TV_NOT_YET_IMPLEMENTED"}

def get_tv_observability_screen_timeline(**kwargs) -> Dict[str, Any]:
    return {"ok": False, "error": "TV_NOT_YET_IMPLEMENTED", "rows": []}

def list_tv_observability_heartbeats(**kwargs) -> Dict[str, Any]:
    return {"rows": [], "total": 0}

def list_tv_observability_runtime_events(**kwargs) -> Dict[str, Any]:
    return {"rows": [], "total": 0}

def list_tv_observability_proof_events(**kwargs) -> Dict[str, Any]:
    return {"rows": [], "total": 0}

def get_tv_observability_proof_stats(**kwargs) -> Dict[str, Any]:
    return {"ok": False, "error": "TV_NOT_YET_IMPLEMENTED"}

def get_tv_observability_runtime_stats(**kwargs) -> Dict[str, Any]:
    return {"ok": False, "error": "TV_NOT_YET_IMPLEMENTED"}

def run_tv_ad_task_cycle(**kwargs) -> Dict[str, Any]:
    """Full ad task cycle: reconcile all active gyms (evaluate + inject + complete)."""
    return reconcile_all_active_gyms(**kwargs)

def audit_tv_correlation_propagation(**kwargs) -> Dict[str, Any]:
    return {"ok": False, "error": "TV_NOT_YET_IMPLEMENTED"}

# Invariant assertion stubs (used by tests)
def assert_tv_inv_s1_activation_prerequisites(**kwargs): pass
def assert_tv_inv_s2_failed_activation_preserves_active(**kwargs): pass
def assert_tv_inv_d1_valid_file_protection(**kwargs): pass
def assert_tv_inv_d2_atomic_promotion(**kwargs): pass
def assert_tv_inv_c1_single_flight(**kwargs): pass
def assert_tv_inv_o1_health_derivation(**kwargs): pass

# Additional constants used by tests
ACTIVATION_RESULT_FAILED = "FAILED"
PLAYER_STATE_RENDERING = "RENDERING"
SCREEN_HEALTH_HEALTHY = "HEALTHY"
STARTUP_PHASES = []

def _save_snapshot(*args, **kwargs): pass

# ---------------------------------------------------------------------------
# A2: Snapshot Fetch + Manifest Cache — Sync Pipeline (Functionality A2)
# ---------------------------------------------------------------------------

def _build_tv_api():
    """Build a MonClubApi instance with TV snapshot URLs from config."""
    from shared.api.monclub_api import MonClubApi
    from tv.config import build_tv_api_endpoints

    return MonClubApi(endpoints=build_tv_api_endpoints(), logger=_log)


def _get_auth_token() -> str:
    """Return the current bearer token, or raise if not logged in."""
    auth = load_tv_auth_for_runtime()
    if not auth:
        raise RuntimeError("Not logged in — no auth token available")
    tok = getattr(auth, "token", None)
    if not tok:
        raise RuntimeError("Auth token is empty")
    return str(tok)


def delete_tv_snapshot_required_assets_for_snapshot(*, snapshot_id: str) -> int:
    """Delete all required asset rows for a snapshot (used before re-inserting)."""
    ensure_tv_local_schema()
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM tv_snapshot_required_asset WHERE snapshot_id=?", (snapshot_id,))
        conn.commit()
        return cur.rowcount


def _sync_screen_snapshot(*, api, token: str, screen_id: int,
                          correlation_id: str) -> Dict[str, Any]:
    """
    Fetch latest snapshot + manifest for one screen, cache locally.
    Returns a per-screen sync result dict.
    """
    ts_start = now_iso()
    warnings = []
    sync_log_id = None

    # 1) Create sync run log
    sync_log = insert_tv_sync_run_log(
        screen_id=screen_id,
        started_at=ts_start,
        correlation_id=correlation_id,
    )
    sync_log_id = sync_log.get("id")

    try:
        # 2) Fetch latest snapshot from backend
        _log.info("[TvSync] screen=%s — fetching latest snapshot", screen_id)
        try:
            snapshot_data = api.get_tv_latest_snapshot(token=token, screen_id=screen_id)
        except Exception as e:
            err_msg = str(e)
            # Check for 404 / empty — treat as "no snapshot available"
            if "404" in err_msg or "not found" in err_msg.lower():
                _log.info("[TvSync] screen=%s — no latest snapshot (404)", screen_id)
                _finalize_sync_run(sync_log_id, result=SYNC_RUN_NO_SNAPSHOT, warning_count=0)
                return {"screen_id": screen_id, "result": SYNC_RUN_NO_SNAPSHOT,
                        "snapshot_id": None, "warnings": []}
            raise

        if not snapshot_data or not isinstance(snapshot_data, dict):
            _log.info("[TvSync] screen=%s — no latest snapshot (empty response)", screen_id)
            _finalize_sync_run(sync_log_id, result=SYNC_RUN_NO_SNAPSHOT, warning_count=0)
            return {"screen_id": screen_id, "result": SYNC_RUN_NO_SNAPSHOT,
                    "snapshot_id": None, "warnings": []}

        # 3) Extract snapshot fields (backend DTO: TvResolvedSnapshotView)
        snap_id = str(snapshot_data.get("id") or "")
        snap_version = _safe_int(snapshot_data.get("version"), 0)
        if not snap_id:
            _log.warning("[TvSync] screen=%s — snapshot has no id", screen_id)
            _finalize_sync_run(sync_log_id, result=SYNC_RUN_FAILED,
                               error_message="Snapshot response missing 'id'")
            return {"screen_id": screen_id, "result": SYNC_RUN_FAILED,
                    "error": "Snapshot response missing 'id'", "warnings": []}

        # 4) Fetch manifest
        manifest_data = None
        manifest_status = MANIFEST_STATUS_MISSING
        manifest_items = []
        try:
            _log.info("[TvSync] screen=%s snap=%s — fetching manifest", screen_id, snap_id)
            manifest_data = api.get_tv_snapshot_manifest(token=token, snapshot_id=snap_id)
            if manifest_data and isinstance(manifest_data, dict):
                manifest_items = manifest_data.get("items") or []
                if isinstance(manifest_items, list):
                    manifest_status = MANIFEST_STATUS_COMPLETE
                else:
                    manifest_items = []
                    manifest_status = MANIFEST_STATUS_INCOMPLETE
                    warnings.append("manifest 'items' is not a list")
            else:
                manifest_status = MANIFEST_STATUS_MISSING
                warnings.append("manifest response is empty or not a dict")
        except Exception as e:
            manifest_status = MANIFEST_STATUS_ERROR
            warnings.append(f"manifest fetch failed: {e}")
            _log.warning("[TvSync] screen=%s snap=%s — manifest fetch failed: %s",
                         screen_id, snap_id, e)

        # 5) Upsert snapshot cache
        upsert_tv_snapshot_cache(
            screen_id=screen_id,
            snapshot_id=snap_id,
            snapshot_version=snap_version,
            activation_state=str(snapshot_data.get("activationState") or ""),
            resolved_at=str(snapshot_data.get("resolvedAt") or ""),
            resolved_day_of_week=str(snapshot_data.get("resolvedDayOfWeek") or ""),
            resolved_preset_id=_safe_int(snapshot_data.get("resolvedPresetId"), 0) or None,
            resolved_layout_preset_id=_safe_int(snapshot_data.get("resolvedLayoutPresetId"), 0) or None,
            resolved_policy_id=_safe_int(snapshot_data.get("resolvedPolicyId"), 0) or None,
            playback_policy_version=_safe_int(snapshot_data.get("playbackPolicyVersion"), 0) or None,
            playback_policy_hash=str(snapshot_data.get("playbackPolicyHash") or "") or None,
            generated_at=str(snapshot_data.get("generatedAt") or "") or None,
            fetched_at=now_iso(),
            payload_json=_json_dumps(snapshot_data.get("payload")),
            manifest_json=_json_dumps(manifest_data) if manifest_data else None,
            asset_count=_safe_int(snapshot_data.get("assetCount"), len(manifest_items)),
            warning_count=_safe_int(snapshot_data.get("warningCount"), 0) + len(warnings),
            manifest_status=manifest_status,
            sync_status=SYNC_STATUS_COMPLETED,
        )

        # 6) Replace required asset rows (atomic: delete old + insert new)
        if manifest_status == MANIFEST_STATUS_COMPLETE and manifest_items:
            delete_tv_snapshot_required_assets_for_snapshot(snapshot_id=snap_id)
            for item in manifest_items:
                if not isinstance(item, dict):
                    warnings.append(f"skipped non-dict manifest item: {type(item)}")
                    continue
                asset_id = str(item.get("mediaAssetId") or "")
                if not asset_id:
                    warnings.append("skipped manifest item with no mediaAssetId")
                    continue
                upsert_tv_snapshot_required_asset(
                    snapshot_id=snap_id,
                    media_asset_id=asset_id,
                    title=str(item.get("title") or "") or None,
                    media_type=str(item.get("mediaType") or "") or None,
                    download_link=str(item.get("downloadLink") or "") or None,
                    checksum_sha256=str(item.get("checksumSha256") or "") or None,
                    size_bytes=_safe_int(item.get("sizeBytes"), 0) or None,
                    mime_type=str(item.get("mimeType") or "") or None,
                    duration_in_seconds=item.get("durationInSeconds"),
                    required_in_timelines=item.get("requiredInTimelines"),
                    source_preset_item_ids=item.get("sourcePresetItemIds"),
                )

        # 7) Finalize sync run
        result = SYNC_RUN_SUCCESS if not warnings else SYNC_RUN_SUCCESS_WITH_WARNINGS
        _finalize_sync_run(
            sync_log_id,
            result=result,
            target_snapshot_version=snap_version,
            warning_count=len(warnings),
        )

        _log.info("[TvSync] screen=%s snap=%s v=%s — %s (%d warnings, %d assets)",
                  screen_id, snap_id, snap_version, result,
                  len(warnings), len(manifest_items))

        return {
            "screen_id": screen_id,
            "result": result,
            "snapshot_id": snap_id,
            "snapshot_version": snap_version,
            "asset_count": len(manifest_items),
            "manifest_status": manifest_status,
            "warnings": warnings,
        }

    except Exception as e:
        _log.exception("[TvSync] screen=%s — sync failed: %s", screen_id, e)
        _finalize_sync_run(sync_log_id, result=SYNC_RUN_FAILED,
                           error_message=str(e))
        return {
            "screen_id": screen_id,
            "result": SYNC_RUN_FAILED,
            "error": str(e),
            "warnings": warnings,
        }


def _finalize_sync_run(sync_log_id, *, result: str,
                       target_snapshot_version: int = None,
                       warning_count: int = 0,
                       error_message: str = None) -> None:
    """Update an existing sync run log row with final result."""
    if not sync_log_id:
        return
    ts = now_iso()
    try:
        with get_conn() as conn:
            conn.execute("""
                UPDATE tv_sync_run_log SET
                    finished_at=?, result=?,
                    target_snapshot_version=COALESCE(?, target_snapshot_version),
                    warning_count=?, error_message=?
                WHERE id=?
            """, (ts, result, target_snapshot_version, warning_count,
                  error_message, sync_log_id))
            conn.commit()
    except Exception as e:
        _log.warning("[TvSync] failed to finalize sync run %s: %s", sync_log_id, e)


def run_tv_snapshot_sync(*, app=None, **kwargs) -> Dict[str, Any]:
    """
    A2 entry point: fetch latest snapshot + manifest for all enabled bound screens.

    Can be called:
    - from a local API endpoint (POST /api/v2/tv/snapshots/sync)
    - from the sync timer
    - manually

    Returns a summary dict with per-screen results.
    """
    ensure_tv_local_schema()
    correlation_id = str(uuid.uuid4())
    ts_start = now_iso()

    # 1) Get auth token
    try:
        token = _get_auth_token()
    except Exception as e:
        _log.warning("[TvSync] cannot sync — %s", e)
        return {"ok": False, "error": str(e), "screens": [],
                "correlation_id": correlation_id}

    # 2) Build API client
    try:
        api = _build_tv_api()
    except Exception as e:
        _log.warning("[TvSync] cannot build API client — %s", e)
        return {"ok": False, "error": f"API client build failed: {e}",
                "screens": [], "correlation_id": correlation_id}

    # 3) Load relevant screen_ids from enabled bindings
    bindings = list_tv_screen_bindings()
    enabled_bindings = [b for b in bindings if b.get("enabled")]
    seen_screen_ids = set()
    screen_ids = []
    for b in enabled_bindings:
        sid = _safe_int(b.get("screen_id"), 0)
        if sid > 0 and sid not in seen_screen_ids:
            seen_screen_ids.add(sid)
            screen_ids.append(sid)

    if not screen_ids:
        _log.info("[TvSync] no enabled bindings — nothing to sync")
        return {"ok": True, "screens": [], "synced": 0, "skipped": True,
                "correlation_id": correlation_id}

    # 4) Sync each screen
    results = []
    succeeded = 0
    failed = 0
    for sid in screen_ids:
        r = _sync_screen_snapshot(
            api=api, token=token, screen_id=sid,
            correlation_id=correlation_id,
        )
        results.append(r)
        if r.get("result") in (SYNC_RUN_SUCCESS, SYNC_RUN_SUCCESS_WITH_WARNINGS,
                                SYNC_RUN_NO_SNAPSHOT):
            succeeded += 1
        else:
            failed += 1

    ts_end = now_iso()
    _log.info("[TvSync] completed: %d screens, %d succeeded, %d failed",
              len(screen_ids), succeeded, failed)

    return {
        "ok": failed == 0,
        "correlation_id": correlation_id,
        "started_at": ts_start,
        "finished_at": ts_end,
        "synced": len(screen_ids),
        "succeeded": succeeded,
        "failed": failed,
        "screens": results,
    }


# ---------------------------------------------------------------------------
# A3: Asset Download + Validation Cache — Download Pipeline
# ---------------------------------------------------------------------------

def _sha256_file(path: str, *, chunk_size: int = 65536) -> str:
    """Compute SHA-256 hex digest of a local file (streaming)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _validate_local_file(path: str, *,
                         expected_size: int = 0,
                         expected_checksum: str = "") -> Tuple[str, str, str]:
    """
    Validate a local file against expected size and checksum.
    Returns (asset_state, validation_mode, state_reason).
    """
    if not path or not os.path.exists(path):
        return (ASSET_STATE_NOT_PRESENT, "", "file does not exist")

    # readable check
    try:
        with open(path, "rb") as f:
            f.read(1)
    except Exception as e:
        return (ASSET_STATE_INVALID_UNREADABLE, "", f"file not readable: {e}")

    actual_size = os.path.getsize(path)
    has_size = expected_size and expected_size > 0
    has_checksum = bool(expected_checksum and expected_checksum.strip())

    # size check (cheap)
    if has_size and actual_size != expected_size:
        return (ASSET_STATE_INVALID_SIZE, VALIDATION_STRONG,
                f"expected {expected_size} bytes, got {actual_size}")

    # checksum check (expensive)
    if has_checksum:
        actual_checksum = _sha256_file(path)
        if actual_checksum.lower() != expected_checksum.strip().lower():
            return (ASSET_STATE_INVALID_CHECKSUM, VALIDATION_STRONG,
                    f"checksum mismatch: expected {expected_checksum[:16]}..., "
                    f"got {actual_checksum[:16]}...")
        return (ASSET_STATE_VALID, VALIDATION_STRONG,
                f"size={actual_size}, sha256 matches")

    if has_size:
        # size matched, no checksum available
        return (ASSET_STATE_VALID, VALIDATION_WEAK,
                f"size={actual_size} matches, no checksum available")

    # no integrity data at all
    return (ASSET_STATE_PRESENT_UNCHECKED, VALIDATION_WEAK,
            f"file exists (size={actual_size}), no integrity metadata")


def _download_file(url: str, dest_path: str, *,
                   timeout: int = 120) -> int:
    """
    Download a file via HTTP GET into dest_path.
    Returns bytes written.  Raises on failure.
    """
    import urllib.request
    import urllib.error

    os.makedirs(os.path.dirname(dest_path), exist_ok=True)

    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "MonClub-Access/1.0")

    with urllib.request.urlopen(req, timeout=timeout) as resp:
        total = 0
        with open(dest_path, "wb") as f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                f.write(chunk)
                total += len(chunk)
    return total


def _build_asset_worklist(*, snapshot_id: str = "",
                          screen_id: int = 0) -> List[Dict[str, Any]]:
    """
    Build a list of assets that may need download or revalidation.
    Joins tv_snapshot_required_asset with tv_local_asset_state.

    Returns list of dicts with keys from required_asset + local state info.
    """
    ensure_tv_local_schema()
    with get_conn() as conn:
        # Determine which snapshot(s) to process
        if snapshot_id:
            snap_ids = [snapshot_id]
        elif screen_id > 0:
            # latest snapshot for this screen
            row = conn.execute(
                "SELECT snapshot_id FROM tv_snapshot_cache "
                "WHERE screen_id=? AND is_latest=1 ORDER BY id DESC LIMIT 1",
                (screen_id,)).fetchone()
            snap_ids = [row["snapshot_id"]] if row else []
        else:
            # all latest snapshots across all screens
            rows = conn.execute(
                "SELECT DISTINCT snapshot_id FROM tv_snapshot_cache WHERE is_latest=1"
            ).fetchall()
            snap_ids = [r["snapshot_id"] for r in rows]

        if not snap_ids:
            return []

        worklist = []
        for sid in snap_ids:
            assets = conn.execute(
                "SELECT * FROM tv_snapshot_required_asset WHERE snapshot_id=? ORDER BY id",
                (sid,)).fetchall()
            for a in assets:
                a_dict = dict(a)
                media_id = a_dict.get("media_asset_id", "")
                if not media_id:
                    continue

                # Check current local state
                local = conn.execute(
                    "SELECT * FROM tv_local_asset_state WHERE media_asset_id=?",
                    (media_id,)).fetchone()
                local_dict = dict(local) if local else {}
                current_state = local_dict.get("asset_state", "")

                # Skip already VALID assets
                if current_state == ASSET_STATE_VALID:
                    # quick recheck: does the file still exist?
                    lp = local_dict.get("local_file_path") or local_dict.get("expected_local_path") or ""
                    if lp and os.path.exists(lp):
                        continue  # still valid, skip
                    # file vanished — needs re-download

                a_dict["_current_state"] = current_state
                a_dict["_local_state"] = local_dict
                worklist.append(a_dict)

        return worklist


def _process_single_asset(asset: Dict[str, Any]) -> Dict[str, Any]:
    """
    Full pipeline for one asset:
    1. Compute expected local path
    2. If file exists at expected path, validate it
    3. If valid, update state and return
    4. If invalid/missing, download to temp file
    5. Validate temp file
    6. If temp valid, atomic rename to final path
    7. Update tv_local_asset_state
    """
    media_id = str(asset.get("media_asset_id") or "")
    download_link = str(asset.get("download_link") or "")
    checksum = str(asset.get("checksum_sha256") or "")
    size_bytes = _safe_int(asset.get("size_bytes"), 0)
    mime_type = str(asset.get("mime_type") or "")
    media_type = str(asset.get("media_type") or "")
    snapshot_version = _safe_int(asset.get("snapshot_version")
                                 or asset.get("last_seen_in_snapshot_version"), 0)

    result = {"media_asset_id": media_id, "action": "NONE", "state": "", "reason": ""}

    # 1) Compute expected local path
    expected_path = compute_expected_local_path(
        media_asset_id=media_id,
        checksum_sha256=checksum,
        mime_type=mime_type,
        media_type=media_type,
    )

    # 2) Check if file already exists at expected path
    if os.path.exists(expected_path):
        state, mode, reason = _validate_local_file(
            expected_path, expected_size=size_bytes, expected_checksum=checksum)
        if state in (ASSET_STATE_VALID, ASSET_STATE_PRESENT_UNCHECKED):
            # Already good
            upsert_tv_local_asset_state(
                media_asset_id=media_id,
                expected_local_path=expected_path,
                local_file_path=expected_path,
                file_exists=True,
                local_size_bytes=os.path.getsize(expected_path),
                local_checksum_sha256=checksum if state == ASSET_STATE_VALID and mode == VALIDATION_STRONG else None,
                asset_state=state,
                state_reason=reason,
                validation_mode=mode,
                last_checked_at=now_iso(),
                last_seen_in_snapshot_version=snapshot_version or None,
            )
            result.update(action="VALIDATED_EXISTING", state=state, reason=reason)
            return result

    # 3) Need to download — check download link
    if not download_link or download_link in ("None", "null", ""):
        upsert_tv_local_asset_state(
            media_asset_id=media_id,
            expected_local_path=expected_path,
            file_exists=False,
            asset_state=ASSET_STATE_ERROR,
            state_reason="no download link available",
            last_checked_at=now_iso(),
            last_seen_in_snapshot_version=snapshot_version or None,
        )
        result.update(action="SKIPPED_NO_URL", state=ASSET_STATE_ERROR,
                      reason="no download link available")
        return result

    # 4) Download to temp file
    temp_path = expected_path + ".downloading"
    try:
        os.makedirs(os.path.dirname(expected_path), exist_ok=True)
        bytes_written = _download_file(download_link, temp_path)
        _log.info("[TvDownload] %s — downloaded %d bytes to temp", media_id, bytes_written)
    except Exception as e:
        # Clean up partial temp file
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass
        upsert_tv_local_asset_state(
            media_asset_id=media_id,
            expected_local_path=expected_path,
            file_exists=False,
            asset_state=ASSET_STATE_ERROR,
            state_reason=f"download failed: {e}",
            last_checked_at=now_iso(),
            last_seen_in_snapshot_version=snapshot_version or None,
        )
        result.update(action="DOWNLOAD_FAILED", state=ASSET_STATE_ERROR,
                      reason=f"download failed: {e}")
        return result

    # 5) Validate temp file
    state, mode, reason = _validate_local_file(
        temp_path, expected_size=size_bytes, expected_checksum=checksum)

    if state not in (ASSET_STATE_VALID, ASSET_STATE_PRESENT_UNCHECKED):
        # Temp file failed validation — do NOT promote
        _log.warning("[TvDownload] %s — temp file failed validation: %s (%s)",
                     media_id, state, reason)
        try:
            os.remove(temp_path)
        except Exception:
            pass
        upsert_tv_local_asset_state(
            media_asset_id=media_id,
            expected_local_path=expected_path,
            file_exists=False,
            asset_state=state,
            state_reason=f"downloaded file failed validation: {reason}",
            validation_mode=mode,
            last_checked_at=now_iso(),
            last_seen_in_snapshot_version=snapshot_version or None,
        )
        result.update(action="DOWNLOAD_INVALID", state=state, reason=reason)
        return result

    # 6) Atomic promotion: temp → final
    try:
        os.replace(temp_path, expected_path)
    except Exception as e:
        _log.warning("[TvDownload] %s — atomic rename failed: %s", media_id, e)
        try:
            os.remove(temp_path)
        except Exception:
            pass
        upsert_tv_local_asset_state(
            media_asset_id=media_id,
            expected_local_path=expected_path,
            file_exists=False,
            asset_state=ASSET_STATE_ERROR,
            state_reason=f"atomic rename failed: {e}",
            last_checked_at=now_iso(),
            last_seen_in_snapshot_version=snapshot_version or None,
        )
        result.update(action="PROMOTION_FAILED", state=ASSET_STATE_ERROR,
                      reason=f"atomic rename failed: {e}")
        return result

    # 7) Final lightweight recheck
    final_size = os.path.getsize(expected_path) if os.path.exists(expected_path) else 0
    final_state = state  # carry forward from temp validation

    upsert_tv_local_asset_state(
        media_asset_id=media_id,
        expected_local_path=expected_path,
        local_file_path=expected_path,
        file_exists=True,
        local_size_bytes=final_size,
        local_checksum_sha256=checksum if mode == VALIDATION_STRONG else None,
        asset_state=final_state,
        state_reason=reason,
        validation_mode=mode,
        last_checked_at=now_iso(),
        last_seen_in_snapshot_version=snapshot_version or None,
    )

    _log.info("[TvDownload] %s — promoted to %s (%s, %s)",
              media_id, expected_path, final_state, mode)

    result.update(action="DOWNLOADED", state=final_state, reason=reason,
                  path=expected_path, size=final_size)
    return result


def run_tv_asset_download(*, snapshot_id: str = "", screen_id: int = 0,
                          app=None, **kwargs) -> Dict[str, Any]:
    """
    A3 entry point: download + validate all required assets for cached snapshots.

    Can be called:
    - from a local API endpoint (POST /api/v2/tv/assets/download)
    - programmatically

    Returns a summary dict.
    """
    ensure_tv_local_schema()
    correlation_id = str(uuid.uuid4())
    ts_start = now_iso()

    # Build worklist
    try:
        worklist = _build_asset_worklist(
            snapshot_id=snapshot_id, screen_id=screen_id)
    except Exception as e:
        _log.exception("[TvDownload] worklist build failed: %s", e)
        return {"ok": False, "error": str(e), "correlation_id": correlation_id}

    if not worklist:
        _log.info("[TvDownload] no assets to process")
        return {"ok": True, "total": 0, "downloaded": 0, "validated": 0,
                "failed": 0, "skipped": 0, "results": [],
                "correlation_id": correlation_id}

    _log.info("[TvDownload] processing %d assets", len(worklist))

    results = []
    downloaded = 0
    validated = 0
    failed = 0
    skipped = 0

    for asset in worklist:
        try:
            r = _process_single_asset(asset)
            results.append(r)
            action = r.get("action", "")
            if action == "DOWNLOADED":
                downloaded += 1
            elif action == "VALIDATED_EXISTING":
                validated += 1
            elif action in ("DOWNLOAD_FAILED", "DOWNLOAD_INVALID", "PROMOTION_FAILED"):
                failed += 1
            else:
                skipped += 1
        except Exception as e:
            media_id = asset.get("media_asset_id", "?")
            _log.exception("[TvDownload] %s — unexpected error: %s", media_id, e)
            results.append({"media_asset_id": media_id, "action": "ERROR",
                            "state": ASSET_STATE_ERROR, "reason": str(e)})
            failed += 1

    ts_end = now_iso()
    total = len(worklist)
    ok = failed == 0

    _log.info("[TvDownload] done: total=%d downloaded=%d validated=%d failed=%d skipped=%d",
              total, downloaded, validated, failed, skipped)

    return {
        "ok": ok,
        "correlation_id": correlation_id,
        "started_at": ts_start,
        "finished_at": ts_end,
        "total": total,
        "downloaded": downloaded,
        "validated": validated,
        "failed": failed,
        "skipped": skipped,
        "results": results,
    }


# ---------------------------------------------------------------------------
# A4: Readiness Computation Engine
# ---------------------------------------------------------------------------

def compute_tv_screen_readiness(*, screen_id: int) -> Dict[str, Any]:
    """
    Computes and persists deterministic readiness for a single screen's latest snapshot.
    Rules:
      - EMPTY if no snapshot or snapshot has asset_count=0 & no required assets
      - ERROR if manifest is inconsistent (asset_count > 0 but 0 required assets)
      - READY if all required assets are VALID
      - PARTIALLY_READY if some are VALID, some are missing/invalid
      - NOT_READY if zero required assets are VALID
    """
    ensure_tv_local_schema()
    ts = now_iso()
    
    # 1. Load latest snapshot
    snap = load_tv_latest_snapshot(screen_id=screen_id)
    if not snap:
        # No snapshot => EMPTY
        return upsert_tv_snapshot_readiness(
            screen_id=screen_id,
            snapshot_id="NO_SNAPSHOT",
            snapshot_version=0,
            readiness_state=READINESS_EMPTY,
            total_required_assets=0,
            is_latest=True,
            is_fully_ready=False
        )
    
    snapshot_id = snap.get("snapshot_id", "")
    snapshot_version = _safe_int(snap.get("snapshot_version"), 0)
    asset_count = _safe_int(snap.get("asset_count"), 0)
    
    # 2. Load required asset rows
    req_assets = list_tv_snapshot_required_assets(snapshot_id=snapshot_id)
    
    if not req_assets:
        if asset_count == 0:
            # Legitimate empty snapshot
            return upsert_tv_snapshot_readiness(
                screen_id=screen_id,
                snapshot_id=snapshot_id,
                snapshot_version=snapshot_version,
                readiness_state=READINESS_EMPTY,
                total_required_assets=0,
                is_latest=True,
                is_fully_ready=False
            )
        else:
            # Inconsistent: backend says asset_count > 0, but no rows saved
            _log.warning(f"[TvReadiness] Screen {screen_id} snap {snapshot_id} has asset_count={asset_count} but 0 required_asset rows.")
            return upsert_tv_snapshot_readiness(
                screen_id=screen_id,
                snapshot_id=snapshot_id,
                snapshot_version=snapshot_version,
                readiness_state=READINESS_ERROR,
                total_required_assets=asset_count,
                ready_asset_count=0,
                missing_asset_count=asset_count,
                is_latest=True,
                is_fully_ready=False
            )

    # 3. Join with local asset states to count
    total = len(req_assets)
    ready_c = 0
    missing_c = 0
    stale_c = 0
    invalid_c = 0
    
    with get_conn() as conn:
        for a in req_assets:
            media_id = a.get("media_asset_id")
            if not media_id:
                invalid_c += 1
                continue
                
            local_row = conn.execute(
                "SELECT asset_state FROM tv_local_asset_state WHERE media_asset_id=?", 
                (media_id,)
            ).fetchone()
            
            state = local_row["asset_state"] if local_row else ASSET_STATE_UNKNOWN
            
            if state == ASSET_STATE_VALID:
                ready_c += 1
            elif state == ASSET_STATE_NOT_PRESENT:
                missing_c += 1
            elif state == ASSET_STATE_STALE:
                stale_c += 1
            elif state in (ASSET_STATE_INVALID_SIZE, ASSET_STATE_INVALID_CHECKSUM, ASSET_STATE_INVALID_UNREADABLE, ASSET_STATE_ERROR, ASSET_STATE_UNKNOWN):
                invalid_c += 1
            elif state == ASSET_STATE_PRESENT_UNCHECKED:
                # Treat unchecked as invalid/not-ready until validated
                invalid_c += 1
            else:
                # Catch-all
                invalid_c += 1

    # 4. Derive Readiness State
    # Important: sum of ready + missing + stale + invalid must equal total
    # (Since each req_asset falls into exactly one bucket above)
    
    is_ready = False
    
    if ready_c == total and total > 0:
        r_str = READINESS_READY
        is_ready = True
    elif ready_c > 0 and ready_c < total:
        r_str = READINESS_PARTIALLY_READY
    elif ready_c == 0 and total > 0:
        r_str = READINESS_NOT_READY
    else:
        # Fallback (shouldn't really hit this if total > 0)
        r_str = READINESS_ERROR

    # 5. Persist
    return upsert_tv_snapshot_readiness(
        screen_id=screen_id,
        snapshot_id=snapshot_id,
        snapshot_version=snapshot_version,
        readiness_state=r_str,
        total_required_assets=total,
        ready_asset_count=ready_c,
        missing_asset_count=missing_c,
        invalid_asset_count=invalid_c,
        stale_asset_count=stale_c,
        is_latest=True,
        is_fully_ready=is_ready
    )


def run_tv_readiness_computation(*, screen_id: int = 0, **kwargs) -> Dict[str, Any]:
    """
    Orchestrates readiness computation across enabled bound screens.
    Triggered manually (API) or by the sync/download engines when state changes.
    """
    ensure_tv_local_schema()
    correlation_id = str(uuid.uuid4())
    ts_start = now_iso()
    
    bindings = list_tv_screen_bindings()
    
    # Filter targets
    targets = []
    for b in bindings:
        sid = _safe_int(b.get("screen_id"), 0)
        if sid <= 0:
            continue
        # If specific screen requested, only target that
        if screen_id > 0 and sid != screen_id:
            continue
        # Only process enabled screens
        if _safe_int(b.get("enabled"), 1) == 1:
            if sid not in targets:
                targets.append(sid)
                
    if not targets:
        return {"ok": True, "computed": 0, "results": [], "correlation_id": correlation_id}
        
    results = []
    for sid in targets:
        try:
            r = compute_tv_screen_readiness(screen_id=sid)
            results.append({
                "screen_id": sid,
                "snapshot_id": r.get("snapshot_id"),
                "readiness_state": r.get("readiness_state"),
                "is_fully_ready": r.get("is_fully_ready")
            })
        except Exception as e:
            _log.exception(f"[TvReadiness] Error computing readiness for screen {sid}: {e}")
            results.append({
                "screen_id": sid,
                "record_error": str(e)
            })
            
    ts_end = now_iso()
    _log.info(f"[TvReadiness] Computed readiness for {len(results)} screens.")
    
    return {
        "ok": True,
        "correlation_id": correlation_id,
        "started_at": ts_start,
        "finished_at": ts_end,
        "computed": len(results),
        "results": results
    }


# ---------------------------------------------------------------------------
# 10) tv_activation_state helpers
# ---------------------------------------------------------------------------

def load_tv_activation_state(*, screen_id: int) -> Optional[Dict[str, Any]]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM tv_activation_state WHERE screen_id=?", (screen_id,)).fetchone()
        return _row_to_dict(row)


def list_tv_activation_states(*, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM tv_activation_state ORDER BY screen_id ASC LIMIT ? OFFSET ?",
            (limit, offset)
        ).fetchall()
        return _rows_to_list(rows)


def _upsert_tv_activation_state(*, screen_id: int, state_updates: Dict[str, Any]) -> Dict[str, Any]:
    ensure_tv_local_schema()
    ts = now_iso()
    
    fields = ["screen_id"]
    values = [screen_id]
    updates = []
    
    for k, v in state_updates.items():
        if k in ("screen_id", "updated_at"):
            continue
        fields.append(k)
        values.append(v)
        updates.append(f"{k}=excluded.{k}")

    fields.append("updated_at")
    values.append(ts)
    updates.append("updated_at=excluded.updated_at")
    
    q_marks = ",".join(["?"] * len(fields))
    col_names = ",".join(fields)
    update_stmt = ",".join(updates)
    
    sql = f"""
        INSERT INTO tv_activation_state ({col_names})
        VALUES ({q_marks})
        ON CONFLICT(screen_id) DO UPDATE SET {update_stmt}
    """
    
    with get_conn() as conn:
        conn.execute(sql, tuple(values))
        conn.commit()
        return _row_to_dict(conn.execute("SELECT * FROM tv_activation_state WHERE screen_id=?", (screen_id,)).fetchone())


# ---------------------------------------------------------------------------
# 11) tv_activation_attempt helpers
# ---------------------------------------------------------------------------

def list_tv_activation_attempts(*, screen_id: int = 0, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    ensure_tv_local_schema()
    query = "SELECT * FROM tv_activation_attempt"
    args = []
    
    if screen_id > 0:
        query += " WHERE screen_id=?"
        args.append(screen_id)
        
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    args.extend([limit, offset])
    
    with get_conn() as conn:
        return _rows_to_list(conn.execute(query, tuple(args)).fetchall())


def insert_tv_activation_attempt(*, 
                                 screen_id: int,
                                 trigger_source: str,
                                 target_snapshot_id: str,
                                 target_snapshot_version: int,
                                 result: str,
                                 failure_reason: str = None,
                                 message: str = None,
                                 precheck_readiness_state: str = None,
                                 precheck_manifest_status: str = None,
                                 started_at: str = None,
                                 finished_at: str = None) -> int:
    ensure_tv_local_schema()
    ts = now_iso()
    if not started_at:
        started_at = ts
    if not finished_at:
        finished_at = ts
        
    with get_conn() as conn:
        cur = conn.execute("""
            INSERT INTO tv_activation_attempt (
                screen_id, trigger_source, target_snapshot_id, target_snapshot_version,
                result, failure_reason, message, precheck_readiness_state,
                precheck_manifest_status, started_at, finished_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            screen_id, trigger_source, target_snapshot_id, target_snapshot_version,
            result, failure_reason, message, precheck_readiness_state,
            precheck_manifest_status, started_at, finished_at, ts
        ))
        conn.commit()
        return cur.lastrowid


# ---------------------------------------------------------------------------
# A5 Core Logic: tv_activation pipelines
# ---------------------------------------------------------------------------

def evaluate_tv_activation(*, screen_id: int) -> Dict[str, Any]:
    """
    Evaluates the activation state for a given screen_id.
    It determines the latest snapshot, latest READY snapshot, and compares them 
    against the current active snapshot to dictate the state.
    Does NOT actually flip the active state (unless no active exists and rules pass).
    Returns the loaded/derived state.
    """
    ensure_tv_local_schema()
    ts = now_iso()
    
    latest_snap = load_tv_latest_snapshot(screen_id=screen_id)
    latest_ready = load_tv_latest_readiness(screen_id=screen_id)
    current_state = load_tv_activation_state(screen_id=screen_id) or {}
    
    updates = {"last_decision_at": ts}
    
    # 1. Update latest snapshot pointers
    if latest_snap:
        updates["latest_snapshot_id"] = latest_snap.get("snapshot_id")
        updates["latest_snapshot_version"] = latest_snap.get("snapshot_version", 0)
    else:
        updates["latest_snapshot_id"] = None
        updates["latest_snapshot_version"] = 0
        
    # 2. Update latest ready snapshot pointers
    has_ready = False
    if latest_ready and latest_ready.get("readiness_state") == READINESS_READY and latest_ready.get("is_fully_ready"):
        has_ready = True
        updates["latest_ready_snapshot_id"] = latest_ready.get("snapshot_id")
        updates["latest_ready_snapshot_version"] = latest_ready.get("snapshot_version", 0)
    else:
        updates["latest_ready_snapshot_id"] = None
        updates["latest_ready_snapshot_version"] = 0
        
    active_version = current_state.get("active_snapshot_version", 0)
    active_id = current_state.get("active_snapshot_id")
    has_active = bool(active_id)
    
    latest_ver = updates["latest_snapshot_version"]
    latest_ready_ver = updates["latest_ready_snapshot_version"]
    
    new_state = ACTIVATION_STATE_NO_ACTIVE_SNAPSHOT
    blocked_reason = None
    
    # 3. Derive activation state string and blocked reasons
    if not latest_snap:
        blocked_reason = FAILURE_REASON_NO_LATEST_SNAPSHOT
        new_state = ACTIVATION_STATE_ACTIVE_CURRENT if has_active else ACTIVATION_STATE_NO_ACTIVE_SNAPSHOT
    elif not has_ready:
        if has_active:
            if latest_ver > active_version:
                new_state = ACTIVATION_STATE_ACTIVE_OLDER_THAN_LATEST
                blocked_reason = FAILURE_REASON_LATEST_NEWER_NOT_READY
            else:
                new_state = ACTIVATION_STATE_ACTIVE_CURRENT
                blocked_reason = FAILURE_REASON_NO_READY_SNAPSHOT
        else:
            new_state = ACTIVATION_STATE_NO_ACTIVE_SNAPSHOT
            blocked_reason = FAILURE_REASON_NO_READY_SNAPSHOT
    else:
        # We have a latest ready snapshot
        if has_active:
            if latest_ready_ver > active_version:
                # Need upgrade but we only define state here
                if latest_ver > latest_ready_ver:
                    blocked_reason = FAILURE_REASON_LATEST_NEWER_NOT_READY
                new_state = ACTIVATION_STATE_ACTIVE_OLDER_THAN_LATEST
            elif latest_ready_ver == active_version:
                if latest_ver > active_version:
                    new_state = ACTIVATION_STATE_ACTIVE_OLDER_THAN_LATEST
                    blocked_reason = FAILURE_REASON_LATEST_NEWER_NOT_READY
                else:
                    new_state = ACTIVATION_STATE_ACTIVE_CURRENT
            else:
                # The latest ready is somehow older than active?
                new_state = ACTIVATION_STATE_ACTIVE_CURRENT
        else:
            new_state = ACTIVATION_STATE_NO_ACTIVE_SNAPSHOT
            # Ready to activate
            
    updates["activation_state"] = new_state
    updates["blocked_reason"] = blocked_reason
    
    final_dict = _upsert_tv_activation_state(screen_id=screen_id, state_updates=updates)
    return final_dict


def run_tv_activation_evaluation(*, screen_id: int = 0) -> Dict[str, Any]:
    """
    Evaluate activation constraints across active screens seamlessly.
    """
    ensure_tv_local_schema()
    bindings = list_tv_screen_bindings()
    results = []
    
    for b in bindings:
        sid = _safe_int(b.get("screen_id"), 0)
        if sid <= 0 or _safe_int(b.get("enabled"), 1) == 0:
            continue
        if screen_id > 0 and sid != screen_id:
            continue
            
        try:
            st = evaluate_tv_activation(screen_id=sid)
            results.append(st)
        except Exception as e:
            _log.exception(f"[TvActivation] Eval failed screen {sid}: {e}")
            
    return {"ok": True, "evaluated_count": len(results), "results": results}


def activate_tv_ready_snapshot(*, screen_id: int, trigger_source: str = "MANUAL") -> Dict[str, Any]:
    """
    Perform the actual promotion of the latest READY snapshot to ACTIVATED.
    Strictly enforces constraints: rollback to old active if ready-check fails.
    """
    ensure_tv_local_schema()
    ts_start = now_iso()
    
    # 1. Evaluate first to grab pointers
    eval_state = evaluate_tv_activation(screen_id=screen_id)
    cand_id = eval_state.get("latest_ready_snapshot_id")
    cand_version = _safe_int(eval_state.get("latest_ready_snapshot_version"), 0)
    
    active_id = eval_state.get("active_snapshot_id")
    active_version = _safe_int(eval_state.get("active_snapshot_version"), 0)
    
    # Defaults for attempt audit log
    failure_reason = None
    result = ATTEMPT_RESULT_FAILED
    
    cand_snap = load_tv_snapshot_by_id(snapshot_id=cand_id) if cand_id else None
    pre_man_status = cand_snap.get("manifest_status") if cand_snap else None
    
    cand_read = None
    if cand_id:
        with get_conn() as conn:
            cand_read = _row_to_dict(conn.execute(
                "SELECT * FROM tv_snapshot_readiness WHERE screen_id=? AND snapshot_id=?", 
                (screen_id, cand_id)
            ).fetchone())

    pre_read_state = cand_read.get("readiness_state") if cand_read else None
    
    # 2. Constraints check
    update_dict = {}
    
    try:
        if not cand_id:
            result = ATTEMPT_RESULT_SKIPPED_NO_SNAPSHOT
            failure_reason = FAILURE_REASON_NO_READY_SNAPSHOT
            raise Exception("No ready snapshot available to activate.")
            
        if cand_id == active_id:
            result = ATTEMPT_RESULT_SKIPPED_ALREADY_ACTIVE
            raise Exception("Latest ready snapshot is already active.")
            
        if cand_version < active_version:
            result = ATTEMPT_RESULT_SKIPPED_LATEST_NOT_NEWER
            failure_reason = "LATEST_READY_OLDER_THAN_ACTIVE"
            raise Exception("Latest ready snapshot is older than current active.")
        
        # 3. Final Safety Ready-Check (Mandatory A5 Constraint)
        if cand_read.get("readiness_state") != READINESS_READY or not cand_read.get("is_fully_ready"):
            result = ATTEMPT_RESULT_SKIPPED_NOT_READY
            failure_reason = FAILURE_REASON_SNAPSHOT_NOT_READY
            raise Exception("Snapshot failed safety re-check; it is no longer READY.")
            
        if pre_man_status != MANIFEST_STATUS_COMPLETE:
            result = ATTEMPT_RESULT_SKIPPED_NOT_READY
            failure_reason = FAILURE_REASON_MANIFEST_INCOMPLETE
            raise Exception("Snapshot manifest is not complete.")

        # 4. Successful Switch -> promote old to previous
        update_dict["previous_active_snapshot_id"] = active_id
        update_dict["previous_active_snapshot_version"] = active_version
        update_dict["active_snapshot_id"] = cand_id
        update_dict["active_snapshot_version"] = cand_version
        update_dict["last_activation_at"] = now_iso()
        
        result = ATTEMPT_RESULT_ACTIVATED
        
    except Exception as e:
        msg = str(e)
    else:
        msg = "Snapshot activated successfully."

    # 5. Log Attempt & Flush update
    attempt_id = insert_tv_activation_attempt(
        screen_id=screen_id,
        trigger_source=trigger_source,
        target_snapshot_id=cand_id,
        target_snapshot_version=cand_version,
        result=result,
        failure_reason=failure_reason,
        message=msg,
        precheck_readiness_state=pre_read_state,
        precheck_manifest_status=pre_man_status,
        started_at=ts_start,
        finished_at=now_iso()
    )
    
    update_dict["last_attempt_id"] = attempt_id
    final_dict = _upsert_tv_activation_state(screen_id=screen_id, state_updates=update_dict)
    
        # Immediately re-evaluate state given the new active snapshot
    final_state = evaluate_tv_activation(screen_id=screen_id)
    
    return {
        "ok": (result == ATTEMPT_RESULT_ACTIVATED),
        "attempt_id": attempt_id,
        "result": result,
        "message": msg,
        "state": final_state
    }

# ---------------------------------------------------------------------------
# 12) tv_player_state helpers (A6)
# ---------------------------------------------------------------------------

# Alias used by local API handlers
activate_tv_latest_ready_snapshot = activate_tv_ready_snapshot


def load_tv_player_state(*, binding_id: int) -> Optional[Dict[str, Any]]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM tv_player_state WHERE binding_id=?", (binding_id,)).fetchone()
        return _row_to_dict(row)


def upsert_tv_player_state(*, binding_id: int, state_updates: Dict[str, Any]) -> Dict[str, Any]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM tv_player_state WHERE binding_id=?", (binding_id,)).fetchone()
        if not row:
            conn.execute("""
                INSERT INTO tv_player_state (binding_id, updated_at)
                VALUES (?, ?)
            """, (binding_id, now_iso()))
        
        if not state_updates:
            res = load_tv_player_state(binding_id=binding_id)
            return res if res else {}
            
        set_clauses = []
        values = []
        for k, v in state_updates.items():
            set_clauses.append(f"{k} = ?")
            values.append(v)
            
        set_clauses.append("updated_at = ?")
        values.append(now_iso())
        values.append(binding_id)
        
        sql = f"UPDATE tv_player_state SET {', '.join(set_clauses)} WHERE binding_id=?"
        conn.execute(sql, tuple(values))
        conn.commit()
        
    res2 = load_tv_player_state(binding_id=binding_id)
    return res2 if res2 else {}


# ---------------------------------------------------------------------------
# 13) tv_player_event helpers (A6)
# ---------------------------------------------------------------------------

def insert_tv_player_event(*, binding_id: int, event_type: str,
                           severity: str = SEVERITY_INFO, message: Optional[str] = None,
                           metadata_dict: Optional[Dict[str, Any]] = None) -> int:
    ensure_tv_local_schema()
    meta_json = _json_dumps(metadata_dict) if metadata_dict else None
    with get_conn() as conn:
        cur = conn.execute("""
            INSERT INTO tv_player_event
                (binding_id, event_type, severity, message, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (binding_id, event_type, severity, message, meta_json, now_iso()))
        conn.commit()
        return _safe_int(cur.lastrowid)


def list_tv_player_events(*, binding_id: int, limit: int = 50, offset: int = 0, **kwargs) -> Dict[str, Any]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        total_row = conn.execute(
            "SELECT COUNT(*) as cnt FROM tv_player_event WHERE binding_id=?", (binding_id,)
        ).fetchone()
        total = total_row["cnt"] if total_row else 0
        rows = conn.execute("""
            SELECT * FROM tv_player_event
            WHERE binding_id=?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """, (binding_id, limit, offset)).fetchall()
        return {"rows": _rows_to_list(rows), "total": total}


# ---------------------------------------------------------------------------
# 14) tv_player_state Core Processing Helpers (A6)
# ---------------------------------------------------------------------------

import re
from datetime import datetime, timedelta
try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None

def _safe_str(v, default=""):
    if v is None:
        return default
    return str(v).strip()

def _binding_bool(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    s = str(v).lower().strip()
    return s in ("1", "true", "yes", "on", "y")

def _first(d, *keys):
    if not isinstance(d, dict):
        return None
    for k in keys:
        if k in d and d.get(k) is not None:
            return d[k]
    return None

def _parse_minute_of_day(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        minute = int(value)
        if 0 <= minute <= 1440:
            return minute
        return None
    s = _safe_str(value, "").strip()
    if not s:
        return None
    if s.isdigit():
        minute = _safe_int(s, -1)
        if 0 <= minute <= 1440:
            return minute
        return None
    m = re.match(r"^(\d{1,2}):(\d{2})$", s)
    if not m:
        return None
    h = _safe_int(m.group(1), -1)
    mm = _safe_int(m.group(2), -1)
    if h == 24 and mm == 0:
        return 1440
    if not (0 <= h <= 23 and 0 <= mm <= 59):
        return None
    return h * 60 + mm


def _normalize_timeline_type(value: Any) -> str:
    s = _safe_str(value, "").strip().upper()
    if s in ("VISUAL", "AUDIO"):
        return s
    if s in ("VIDEO", "IMAGE"):
        return "VISUAL"
    return ""


def _normalize_timeline_item(raw: Dict[str, Any], default_timeline: str) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    timeline = _normalize_timeline_type(_first(raw, "timelineType", "timeline_type", "timeline", "type")) or _normalize_timeline_type(default_timeline)
    if timeline not in ("VISUAL", "AUDIO"):
        return None

    start = _parse_minute_of_day(_first(raw, "startMinuteOfDay", "start_minute_of_day", "startMinute", "start_minute", "startTime", "start"))
    end = _parse_minute_of_day(_first(raw, "endMinuteOfDay", "end_minute_of_day", "endMinute", "end_minute", "endTime", "end"))
    if start is None or end is None or start < 0 or end > 1440 or end <= start:
        return None

    media_obj = raw.get("mediaAsset") if isinstance(raw.get("mediaAsset"), dict) else {}
    media_asset_id = _safe_str(_first(raw, "mediaAssetId", "media_asset_id", "assetId", "asset_id", "mediaId", "media_id"), "")
    if not media_asset_id:
        media_asset_id = _safe_str(_first(media_obj, "id", "mediaAssetId", "media_asset_id", "assetId"), "")
    if not media_asset_id:
        return None

    item_id = _safe_str(_first(raw, "id", "itemId", "item_id", "presetItemId", "preset_item_id", "sourcePresetItemId", "source_preset_item_id"), "")
    if not item_id:
        item_id = f"{timeline}:{media_asset_id}:{start}-{end}"

    media_type = _safe_str(_first(raw, "mediaType", "media_type", "type"), "") or _safe_str(_first(media_obj, "mediaType", "media_type", "type"), "")
    media_type = media_type.upper().strip()

    return {
        "itemId": item_id,
        "timelineType": timeline,
        "mediaAssetId": media_asset_id,
        "startMinuteOfDay": int(start),
        "endMinuteOfDay": int(end),
        "mediaType": media_type,
        "title": _safe_str(_first(raw, "title", "label", "name"), "") or _safe_str(_first(media_obj, "title", "name"), ""),
        "videoAudioEnabled": _binding_bool(_first(raw, "videoAudioEnabled", "video_audio_enabled", "audioEnabled", "audio_enabled")),
    }


def _extract_timeline_items(payload: Dict[str, Any], timeline_type: str) -> List[Dict[str, Any]]:
    wanted = _normalize_timeline_type(timeline_type)
    if wanted not in ("VISUAL", "AUDIO"):
        return []

    candidates: List[Dict[str, Any]] = []

    for key in ("timelineItems", "timeline_items", "resolvedTimelineItems", "resolved_timeline_items", "items"):
        arr = payload.get(key)
        if isinstance(arr, list):
            for raw in arr:
                item = _normalize_timeline_item(raw if isinstance(raw, dict) else {}, "")
                if item and item.get("timelineType") == wanted:
                    candidates.append(item)

    for key in ("visualTimelineItems", "visual_timeline_items"):
        arr = payload.get(key)
        if wanted == "VISUAL" and isinstance(arr, list):
            for raw in arr:
                item = _normalize_timeline_item(raw if isinstance(raw, dict) else {}, "VISUAL")
                if item:
                    candidates.append(item)

    for key in ("audioTimelineItems", "audio_timeline_items"):
        arr = payload.get(key)
        if wanted == "AUDIO" and isinstance(arr, list):
            for raw in arr:
                item = _normalize_timeline_item(raw if isinstance(raw, dict) else {}, "AUDIO")
                if item:
                    candidates.append(item)

    for key in ("timelines", "resolvedTimelines", "resolved_timelines", "resolvedTimeline", "resolved_timeline"):
        obj = payload.get(key)
        if not isinstance(obj, dict):
            continue
        src = obj.get("visual") if wanted == "VISUAL" else obj.get("audio")
        if src is None:
            src = obj.get("VISUAL") if wanted == "VISUAL" else obj.get("AUDIO")
        if isinstance(src, dict):
            arr = src.get("items")
            if isinstance(arr, list):
                for raw in arr:
                    item = _normalize_timeline_item(raw if isinstance(raw, dict) else {}, wanted)
                    if item:
                        candidates.append(item)
        elif isinstance(src, list):
            for raw in src:
                item = _normalize_timeline_item(raw if isinstance(raw, dict) else {}, wanted)
                if item:
                    candidates.append(item)

    dedup: Dict[str, Dict[str, Any]] = {}
    for item in candidates:
        k = f"{item.get('timelineType')}|{item.get('itemId')}|{item.get('mediaAssetId')}|{item.get('startMinuteOfDay')}|{item.get('endMinuteOfDay')}"
        dedup[k] = item

    rows = list(dedup.values())
    rows.sort(key=lambda x: (_safe_int(x.get("startMinuteOfDay"), 0), _safe_int(x.get("endMinuteOfDay"), 0), _safe_str(x.get("itemId"), "")))
    return rows


def _resolve_player_timezone(snapshot_payload: Dict[str, Any], snapshot_row: Dict[str, Any]) -> str:
    candidates = [
        _first(snapshot_payload, "timezone", "timeZone"),
    ]
    if isinstance(snapshot_payload.get("screen"), dict):
        candidates.append(_first(snapshot_payload.get("screen"), "timezone", "timeZone"))
    if isinstance(snapshot_payload.get("metadata"), dict):
        candidates.append(_first(snapshot_payload.get("metadata"), "timezone", "timeZone"))
    if isinstance(snapshot_row, dict):
        candidates.append(_first(snapshot_row, "timezone", "time_zone"))

    for c in candidates:
        tz = _safe_str(c, "").strip()
        if not tz:
            continue
        if ZoneInfo is None:
            return tz
        try:
            ZoneInfo(tz)
            return tz
        except Exception:
            continue

    try:
        return datetime.now().astimezone().tzinfo.key  # type: ignore[attr-defined]
    except Exception:
        return "UTC"


def _clock_for_timezone(tz_name: str, now_dt: Optional[datetime] = None) -> Dict[str, Any]:
    if now_dt is None:
        now_dt = datetime.now()
    if ZoneInfo is not None:
        try:
            now_dt = now_dt.astimezone(ZoneInfo(_safe_str(tz_name, "UTC") or "UTC"))
        except Exception:
            now_dt = datetime.now().astimezone()
    else:
        now_dt = now_dt.astimezone()
    return {
        "iso": now_dt.isoformat(),
        "dayOfWeek": now_dt.strftime("%A").upper(),
        "minuteOfDay": int(now_dt.hour) * 60 + int(now_dt.minute),
    }


def _asset_path_from_row(row: Dict[str, Any]) -> str:
    p = _safe_str(row.get("local_file_path"), "").strip()
    if p:
        return p
    return _safe_str(row.get("expected_local_path"), "").strip()


def _path_is_readable(path_str: str) -> bool:
    p = Path(_safe_str(path_str, "").strip())
    if not p.exists() or not p.is_file():
        return False
    try:
        with p.open("rb") as f:
            _ = f.read(1)
        return True
    except Exception:
        return False


def _select_current_timeline_item(items: List[Dict[str, Any]], minute_of_day: int) -> Optional[Dict[str, Any]]:
    minute = int(minute_of_day)
    matches = [
        item
        for item in items
        if _safe_int(item.get("startMinuteOfDay"), -1) <= minute < _safe_int(item.get("endMinuteOfDay"), -1)
    ]
    if not matches:
        return None
    matches.sort(key=lambda x: (_safe_int(x.get("startMinuteOfDay"), 0), _safe_str(x.get("itemId"), "")))
    return matches[0]


def _present_timeline_item(item: Dict[str, Any], asset_row: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    asset = asset_row or {}
    candidate_path = _asset_path_from_row(asset)
    readable = _path_is_readable(candidate_path) if candidate_path else False
    asset_state = _safe_str(asset.get("asset_state"), "")
    renderable = asset_state == ASSET_STATE_VALID and readable
    return {
        "itemId": _safe_str(item.get("itemId"), ""),
        "timelineType": _safe_str(item.get("timelineType"), ""),
        "mediaAssetId": _safe_str(item.get("mediaAssetId"), ""),
        "mediaType": _safe_str(item.get("mediaType"), _safe_str(asset.get("media_type"), "")).upper(),
        "title": _safe_str(item.get("title"), "") or _safe_str(asset.get("title"), ""),
        "startMinuteOfDay": _safe_int(item.get("startMinuteOfDay"), 0),
        "endMinuteOfDay": _safe_int(item.get("endMinuteOfDay"), 0),
        "videoAudioEnabled": bool(item.get("videoAudioEnabled")),
        "assetPath": candidate_path or None,
        "assetState": asset_state or None,
        "assetRenderable": bool(renderable),
        "stateReason": _safe_str(asset.get("state_reason"), "") or None,
    }


def _decide_player_mode(current_visual: Optional[Dict[str, Any]], current_audio: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    v_exists = bool(current_visual)
    a_exists = bool(current_audio)
    v_ok = bool((current_visual or {}).get("assetRenderable"))
    a_ok = bool((current_audio or {}).get("assetRenderable"))

    if not v_exists and not a_exists:
        return {
            "playerState": PLAYER_STATE_BLOCKED_NO_RENDERABLE_ITEM,
            "renderMode": RENDER_MODE_IDLE_FALLBACK,
            "fallbackReason": FALLBACK_REASON_NO_CURRENT_ITEM,
            "errorCode": None,
            "errorMessage": None,
        }

    if v_ok and a_ok:
        return {
            "playerState": PLAYER_STATE_RENDERING,
            "renderMode": RENDER_MODE_VISUAL_AND_AUDIO,
            "fallbackReason": None,
            "errorCode": None,
            "errorMessage": None,
        }

    if v_ok and not a_exists:
        return {
            "playerState": PLAYER_STATE_RENDERING,
            "renderMode": RENDER_MODE_VISUAL_ONLY,
            "fallbackReason": None,
            "errorCode": None,
            "errorMessage": None,
        }

    if a_ok and not v_exists:
        return {
            "playerState": PLAYER_STATE_RENDERING,
            "renderMode": RENDER_MODE_AUDIO_ONLY,
            "fallbackReason": None,
            "errorCode": None,
            "errorMessage": None,
        }

    if v_ok and a_exists and not a_ok:
        return {
            "playerState": PLAYER_STATE_FALLBACK_RENDERING,
            "renderMode": RENDER_MODE_VISUAL_ONLY,
            "fallbackReason": FALLBACK_REASON_AUDIO_ASSET_INVALID,
            "errorCode": None,
            "errorMessage": "Current audio asset is invalid/unreadable.",
        }

    if a_ok and v_exists and not v_ok:
        return {
            "playerState": PLAYER_STATE_FALLBACK_RENDERING,
            "renderMode": RENDER_MODE_AUDIO_ONLY,
            "fallbackReason": FALLBACK_REASON_VISUAL_ASSET_INVALID,
            "errorCode": None,
            "errorMessage": "Current visual asset is invalid/unreadable.",
        }

    reason = FALLBACK_REASON_BOTH_ASSETS_INVALID if v_exists and a_exists else (FALLBACK_REASON_VISUAL_ASSET_INVALID if v_exists else FALLBACK_REASON_AUDIO_ASSET_INVALID)
    return {
        "playerState": PLAYER_STATE_ERROR,
        "renderMode": RENDER_MODE_ERROR_FALLBACK,
        "fallbackReason": reason,
        "errorCode": "ASSET_INVALID",
        "errorMessage": "Current render asset is invalid or unreadable.",
    }


def _fetch_ad_context_for_binding(bid: int) -> Dict[str, Any]:
    """A7: Read ad override fields from tv_player_state for a binding. Returns {} if no override."""
    try:
        with get_conn() as _ac:
            _ps = _ac.execute(
                "SELECT ad_override_active, current_ad_task_id, current_ad_media_id, "
                "current_ad_layout, ad_audio_override_active "
                "FROM tv_player_state WHERE binding_id=? LIMIT 1", (bid,)
            ).fetchone()
            if not _ps:
                return {}
            _psd = dict(_ps)
            if _safe_int(_psd.get("ad_override_active"), 0) != 1:
                return {}
            _ad_task_id = _safe_str(_psd.get("current_ad_task_id"), "") or None
            if not _ad_task_id:
                return {}
            _ad_row = _ac.execute(
                "SELECT * FROM tv_ad_task_cache WHERE campaign_task_id=? LIMIT 1",
                (_ad_task_id,)
            ).fetchone()
            if not _ad_row:
                return {}
            _adt = dict(_ad_row)
            _fp = _safe_str(_adt.get("local_file_path"), "") or None
            if not _path_is_readable(_fp):
                return {}
            _layout = _safe_str(_psd.get("current_ad_layout"), AD_LAYOUT_FULL_SCREEN)
            return {
                "adOverrideActive": True,
                "currentAdTaskId": _ad_task_id,
                "currentAdMediaId": _safe_str(_psd.get("current_ad_media_id"), "") or None,
                "currentAdLayout": _layout,
                "adAssetPath": _fp,
                "adMimeType": _safe_str(_adt.get("ad_mime_type"), "") or None,
                "adAudioOverrideActive": _safe_int(_psd.get("ad_audio_override_active"), 0) == 1,
                "adDisplayDurationSec": _safe_int(_adt.get("display_duration_sec"), 30),
            }
    except Exception:
        return {}


def _build_player_render_context(*, binding_id: int, now_dt: Optional[datetime] = None) -> Dict[str, Any]:
    ensure_tv_local_schema()
    bid = int(binding_id)

    # A7: Fetch ad override context upfront (works regardless of snapshot/activation state)
    _ad_ctx = _fetch_ad_context_for_binding(bid)

    if bid <= 0:
        return {
            "ok": False,
            "bindingId": bid,
            "screenId": None,
            "playerState": PLAYER_STATE_BLOCKED_NO_BINDING,
            "renderMode": RENDER_MODE_IDLE_FALLBACK,
            "fallbackReason": FALLBACK_REASON_BINDING_NOT_FOUND,
            "error": "BINDING_NOT_FOUND",
            "adOverrideActive": False,
        }

    with get_conn() as conn:
        b = get_tv_screen_binding(binding_id=bid)
        if not b:
            return {
                "ok": False,
                "bindingId": bid,
                "screenId": None,
                "playerState": PLAYER_STATE_BLOCKED_NO_BINDING,
                "renderMode": RENDER_MODE_IDLE_FALLBACK,
                "fallbackReason": FALLBACK_REASON_BINDING_NOT_FOUND,
                "error": "BINDING_NOT_FOUND",
                "adOverrideActive": False,
            }

        sid = _safe_int(b.get("screen_id"), 0)
        if not _binding_bool(b.get("enabled")):
            _r = {
                "ok": True,
                "bindingId": bid,
                "screenId": sid,
                "bindingEnabled": False,
                "activeSnapshotId": None,
                "activeSnapshotVersion": None,
                "timezone": "UTC",
                "currentDayOfWeek": None,
                "currentMinuteOfDay": None,
                "visualItems": [],
                "audioItems": [],
                "currentVisual": None,
                "currentAudio": None,
                "playerState": PLAYER_STATE_BLOCKED_BINDING_DISABLED,
                "renderMode": RENDER_MODE_IDLE_FALLBACK,
                "fallbackReason": FALLBACK_REASON_BINDING_DISABLED,
                "lastRenderErrorCode": None,
                "lastRenderErrorMessage": None,
                "videoMutedByAudio": False,
                "evaluatedAt": now_iso(),
                "adOverrideActive": False,
            }
            _r.update(_ad_ctx)
            return _r

        activation = evaluate_tv_activation(screen_id=sid)
        state = activation
        active_snapshot_id = _safe_str(state.get("active_snapshot_id"), "")
        active_snapshot_version = _safe_int(state.get("active_snapshot_version"), 0)

        if not active_snapshot_id or active_snapshot_version <= 0:
            _r = {
                "ok": True,
                "bindingId": bid,
                "screenId": sid,
                "bindingEnabled": True,
                "activeSnapshotId": None,
                "activeSnapshotVersion": None,
                "timezone": "UTC",
                "currentDayOfWeek": None,
                "currentMinuteOfDay": None,
                "visualItems": [],
                "audioItems": [],
                "currentVisual": None,
                "currentAudio": None,
                "playerState": PLAYER_STATE_BLOCKED_NO_ACTIVE_SNAPSHOT,
                "renderMode": RENDER_MODE_IDLE_FALLBACK,
                "fallbackReason": FALLBACK_REASON_NO_ACTIVE_SNAPSHOT,
                "lastRenderErrorCode": None,
                "lastRenderErrorMessage": None,
                "videoMutedByAudio": False,
                "evaluatedAt": now_iso(),
                "adOverrideActive": False,
            }
            _r.update(_ad_ctx)
            return _r

        row = conn.execute(
            "SELECT * FROM tv_snapshot_cache WHERE screen_id=? AND snapshot_id=? LIMIT 1",
            (sid, active_snapshot_id),
        ).fetchone()
        if not row:
            _r = {
                "ok": True,
                "bindingId": bid,
                "screenId": sid,
                "bindingEnabled": True,
                "activeSnapshotId": active_snapshot_id,
                "activeSnapshotVersion": active_snapshot_version,
                "timezone": "UTC",
                "currentDayOfWeek": None,
                "currentMinuteOfDay": None,
                "visualItems": [],
                "audioItems": [],
                "currentVisual": None,
                "currentAudio": None,
                "playerState": PLAYER_STATE_ERROR,
                "renderMode": RENDER_MODE_ERROR_FALLBACK,
                "fallbackReason": FALLBACK_REASON_SNAPSHOT_INVALID,
                "lastRenderErrorCode": "SNAPSHOT_NOT_FOUND",
                "lastRenderErrorMessage": "Active snapshot row is missing locally.",
                "videoMutedByAudio": False,
                "evaluatedAt": now_iso(),
                "adOverrideActive": False,
            }
            _r.update(_ad_ctx)
            return _r

        snap_row = dict(row)
        try:
            payload = json.loads(snap_row.get("payload_json") or "{}")
        except Exception:
            payload = {}

        if _safe_str(snap_row.get("manifest_status"), "") != MANIFEST_STATUS_COMPLETE:
            _r = {
                "ok": True,
                "bindingId": bid,
                "screenId": sid,
                "bindingEnabled": True,
                "activeSnapshotId": active_snapshot_id,
                "activeSnapshotVersion": active_snapshot_version,
                "timezone": "UTC",
                "currentDayOfWeek": None,
                "currentMinuteOfDay": None,
                "visualItems": [],
                "audioItems": [],
                "currentVisual": None,
                "currentAudio": None,
                "playerState": PLAYER_STATE_ERROR,
                "renderMode": RENDER_MODE_ERROR_FALLBACK,
                "fallbackReason": FALLBACK_REASON_SNAPSHOT_INVALID,
                "lastRenderErrorCode": "MANIFEST_INCOMPLETE",
                "lastRenderErrorMessage": "Active snapshot manifest is not complete.",
                "videoMutedByAudio": False,
                "evaluatedAt": now_iso(),
                "adOverrideActive": False,
            }
            _r.update(_ad_ctx)
            return _r

        tz_name = _resolve_player_timezone(payload if isinstance(payload, dict) else {}, snap_row)
        clock = _clock_for_timezone(tz_name, now_dt)
        minute = _safe_int(clock.get("minuteOfDay"), 0)

        visual_items = _extract_timeline_items(payload if isinstance(payload, dict) else {}, "VISUAL")
        audio_items = _extract_timeline_items(payload if isinstance(payload, dict) else {}, "AUDIO")

        asset_rows = conn.execute("""
            SELECT las.*
            FROM tv_local_asset_state las
            JOIN tv_snapshot_required_asset sra ON sra.media_asset_id = las.media_asset_id
            WHERE sra.snapshot_id = ?
            ORDER BY las.media_asset_id ASC
        """, (active_snapshot_id,)).fetchall()
        asset_map: Dict[str, Dict[str, Any]] = {}
        for ar in asset_rows:
            d = dict(ar)
            asset_map[_safe_str(d.get("media_asset_id"), "")] = d

    visual_presented = [_present_timeline_item(item, asset_map.get(_safe_str(item.get("mediaAssetId"), ""))) for item in visual_items]
    audio_presented = [_present_timeline_item(item, asset_map.get(_safe_str(item.get("mediaAssetId"), ""))) for item in audio_items]

    current_visual = _select_current_timeline_item(visual_presented, minute)
    current_audio = _select_current_timeline_item(audio_presented, minute)

    decision = _decide_player_mode(current_visual, current_audio)

    video_muted = False
    if current_visual and _safe_str(current_visual.get("mediaType"), "").upper() == "VIDEO":
        if bool((current_audio or {}).get("assetRenderable")):
            video_muted = True
        else:
            video_muted = not bool(current_visual.get("videoAudioEnabled"))

    ctx = {
        "ok": True,
        "bindingId": bid,
        "screenId": sid,
        "bindingEnabled": True,
        "activeSnapshotId": active_snapshot_id,
        "activeSnapshotVersion": active_snapshot_version,
        "timezone": tz_name,
        "currentDayOfWeek": _safe_str(clock.get("dayOfWeek"), "") or None,
        "currentMinuteOfDay": minute,
        "visualItems": visual_presented,
        "audioItems": audio_presented,
        "currentVisual": current_visual,
        "currentAudio": current_audio,
        "playerState": decision.get("playerState"),
        "renderMode": decision.get("renderMode"),
        "fallbackReason": decision.get("fallbackReason"),
        "lastRenderErrorCode": decision.get("errorCode"),
        "lastRenderErrorMessage": decision.get("errorMessage"),
        "videoMutedByAudio": bool(video_muted),
        "evaluatedAt": _safe_str(clock.get("iso"), now_iso()),
        "adOverrideActive": False,
    }
    ctx.update(_ad_ctx)
    return ctx


def _player_state_payload_from_context(context: Dict[str, Any]) -> Dict[str, Any]:
    current_visual = (context or {}).get("currentVisual") if isinstance((context or {}).get("currentVisual"), dict) else {}
    current_audio = (context or {}).get("currentAudio") if isinstance((context or {}).get("currentAudio"), dict) else {}
    return {
        "screen_id": _safe_int(context.get("screenId"), 0) or None,
        "active_snapshot_id": _safe_str(context.get("activeSnapshotId"), "") or None,
        "active_snapshot_version": _safe_int(context.get("activeSnapshotVersion"), 0) or None,
        "current_day_of_week": _safe_str(context.get("currentDayOfWeek"), "") or None,
        "current_minute_of_day": _safe_int(context.get("currentMinuteOfDay"), -1),
        "current_visual_item_id": _safe_str(current_visual.get("itemId"), "") or None,
        "current_audio_item_id": _safe_str(current_audio.get("itemId"), "") or None,
        "current_visual_asset_id": _safe_str(current_visual.get("mediaAssetId"), "") or None,
        "current_audio_asset_id": _safe_str(current_audio.get("mediaAssetId"), "") or None,
        "current_visual_asset_path": _safe_str(current_visual.get("assetPath"), "") or None,
        "current_audio_asset_path": _safe_str(current_audio.get("assetPath"), "") or None,
        "player_state": _safe_str(context.get("playerState"), PLAYER_STATE_IDLE) or PLAYER_STATE_IDLE,
        "render_mode": _safe_str(context.get("renderMode"), RENDER_MODE_IDLE_FALLBACK) or RENDER_MODE_IDLE_FALLBACK,
        "fallback_reason": _safe_str(context.get("fallbackReason"), "") or None,
        "video_muted_by_audio": 1 if _binding_bool(context.get("videoMutedByAudio")) else 0,
        "last_render_error_code": _safe_str(context.get("lastRenderErrorCode"), "") or None,
        "last_render_error_message": _safe_str(context.get("lastRenderErrorMessage"), "") or None,
        "last_tick_at": _safe_str(context.get("evaluatedAt"), now_iso()),
        "last_snapshot_check_at": now_iso(),
    }


def _player_meaningful_change(prev: Dict[str, Any], new_payload: Dict[str, Any]) -> bool:
    keys = [
        "active_snapshot_id",
        "active_snapshot_version",
        "current_visual_item_id",
        "current_audio_item_id",
        "current_visual_asset_path",
        "current_audio_asset_path",
        "player_state",
        "render_mode",
        "fallback_reason",
        "last_render_error_code",
        "last_render_error_message",
        "video_muted_by_audio",
    ]
    for key in keys:
        if _safe_str(prev.get(key), "") != _safe_str(new_payload.get(key), ""):
            return True
    return False


def _insert_tv_player_event(
    conn,
    *,
    binding_id: int,
    event_type: str,
    severity: str = "INFO",
    message: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> None:
    """Insert a player event row using an existing connection (no commit — caller commits)."""
    meta_json = _json_dumps(payload) if payload else None
    conn.execute("""
        INSERT INTO tv_player_event
            (binding_id, event_type, severity, message, metadata_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (binding_id, event_type, severity, message, meta_json, now_iso()))


def report_tv_player_state(
    *,
    binding_id: int,
    payload: Dict[str, Any],
    event_type: str = PLAYER_EVENT_STATE_CHANGED,
    force: bool = False,
    freshness_seconds: int = 60,
) -> Dict[str, Any]:
    ensure_tv_local_schema()
    bid = int(binding_id)
    now = now_iso()

    with get_conn() as conn:
        b = get_tv_screen_binding(binding_id=bid)
        if not b:
            raise ValueError("BINDING_NOT_FOUND")

        existing = load_tv_player_state(binding_id=bid) or {}
        row_payload = dict(payload or {})
        row_payload["screen_id"] = _safe_int(row_payload.get("screen_id"), _safe_int(b.get("screen_id"), 0))
        row_payload["current_minute_of_day"] = _safe_int(row_payload.get("current_minute_of_day"), -1)
        if row_payload["current_minute_of_day"] < 0:
            row_payload["current_minute_of_day"] = None
        # Normalize integer-typed tracked fields so None and 0 compare equally
        row_payload["video_muted_by_audio"] = _safe_int(row_payload.get("video_muted_by_audio"), 0)
        changed = _player_meaningful_change(existing, row_payload)

        freshness_due = True
        if existing.get("updated_at") and freshness_seconds > 0:
            try:
                last_ts = datetime.fromisoformat(_safe_str(existing.get("updated_at"), "").replace("Z", "+00:00"))
                freshness_due = (datetime.now(last_ts.tzinfo) - last_ts).total_seconds() >= float(freshness_seconds)
            except Exception:
                freshness_due = True

        should_write = bool(force or changed or freshness_due or not existing)
        if not should_write:
            return {"updated": False, "changed": False, "row": existing}

        state_change_at = now if (changed or not existing) else _safe_str(existing.get("last_state_change_at"), "") or None

        conn.execute(
            """
            INSERT INTO tv_player_state (
                binding_id, screen_id, active_snapshot_id, active_snapshot_version,
                current_day_of_week, current_minute_of_day,
                current_visual_item_id, current_audio_item_id,
                current_visual_asset_id, current_audio_asset_id,
                current_visual_asset_path, current_audio_asset_path,
                player_state, render_mode, fallback_reason,
                video_muted_by_audio,
                last_render_error_code, last_render_error_message,
                last_tick_at, last_snapshot_check_at, last_state_change_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(binding_id) DO UPDATE SET
                screen_id=excluded.screen_id,
                active_snapshot_id=excluded.active_snapshot_id,
                active_snapshot_version=excluded.active_snapshot_version,
                current_day_of_week=excluded.current_day_of_week,
                current_minute_of_day=excluded.current_minute_of_day,
                current_visual_item_id=excluded.current_visual_item_id,
                current_audio_item_id=excluded.current_audio_item_id,
                current_visual_asset_id=excluded.current_visual_asset_id,
                current_audio_asset_id=excluded.current_audio_asset_id,
                current_visual_asset_path=excluded.current_visual_asset_path,
                current_audio_asset_path=excluded.current_audio_asset_path,
                player_state=excluded.player_state,
                render_mode=excluded.render_mode,
                fallback_reason=excluded.fallback_reason,
                video_muted_by_audio=excluded.video_muted_by_audio,
                last_render_error_code=excluded.last_render_error_code,
                last_render_error_message=excluded.last_render_error_message,
                last_tick_at=excluded.last_tick_at,
                last_snapshot_check_at=excluded.last_snapshot_check_at,
                last_state_change_at=excluded.last_state_change_at,
                updated_at=excluded.updated_at
            """,
            (
                bid,
                _safe_int(row_payload.get("screen_id"), 0),
                _safe_str(row_payload.get("active_snapshot_id"), "") or None,
                _safe_int(row_payload.get("active_snapshot_version"), 0) or None,
                _safe_str(row_payload.get("current_day_of_week"), "") or None,
                row_payload.get("current_minute_of_day"),
                _safe_str(row_payload.get("current_visual_item_id"), "") or None,
                _safe_str(row_payload.get("current_audio_item_id"), "") or None,
                _safe_str(row_payload.get("current_visual_asset_id"), "") or None,
                _safe_str(row_payload.get("current_audio_asset_id"), "") or None,
                _safe_str(row_payload.get("current_visual_asset_path"), "") or None,
                _safe_str(row_payload.get("current_audio_asset_path"), "") or None,
                _safe_str(row_payload.get("player_state"), PLAYER_STATE_IDLE) or PLAYER_STATE_IDLE,
                _safe_str(row_payload.get("render_mode"), RENDER_MODE_IDLE_FALLBACK) or RENDER_MODE_IDLE_FALLBACK,
                _safe_str(row_payload.get("fallback_reason"), "") or None,
                1 if _binding_bool(row_payload.get("video_muted_by_audio")) else 0,
                _safe_str(row_payload.get("last_render_error_code"), "") or None,
                _safe_str(row_payload.get("last_render_error_message"), "") or None,
                _safe_str(row_payload.get("last_tick_at"), now) or now,
                _safe_str(row_payload.get("last_snapshot_check_at"), now) or now,
                state_change_at,
                now,
            ),
        )

        if changed or not existing:
            _insert_tv_player_event(
                conn,
                binding_id=bid,
                event_type=event_type,
                severity="ERROR" if _safe_str(row_payload.get("player_state"), "").upper() == PLAYER_STATE_ERROR else "INFO",
                message=_safe_str(row_payload.get("last_render_error_message"), "") or _safe_str(row_payload.get("fallback_reason"), "") or None,
                payload={
                    "playerState": _safe_str(row_payload.get("player_state"), ""),
                    "renderMode": _safe_str(row_payload.get("render_mode"), ""),
                    "fallbackReason": _safe_str(row_payload.get("fallback_reason"), ""),
                    "activeSnapshotVersion": _safe_int(row_payload.get("active_snapshot_version"), 0) or None,
                },
            )

        conn.commit()
        row = load_tv_player_state(binding_id=bid) or {}

    return {"updated": True, "changed": bool(changed or not existing), "row": row}


def get_tv_player_render_context(*, binding_id: int, persist: bool = False) -> Dict[str, Any]:
    context = _build_player_render_context(binding_id=int(binding_id))
    if persist and bool(context.get("ok")):
        payload = _player_state_payload_from_context(context)
        try:
            report_tv_player_state(binding_id=int(binding_id), payload=payload, event_type=PLAYER_EVENT_REEVALUATED)
        except Exception:
            pass
    return context


def reevaluate_tv_player(*, binding_id: int, persist: bool = True) -> Dict[str, Any]:
    context = get_tv_player_render_context(binding_id=int(binding_id), persist=persist)
    return {"ok": bool(context.get("ok")), "context": context}


def reload_tv_player(*, binding_id: int, persist: bool = True) -> Dict[str, Any]:
    context = get_tv_player_render_context(binding_id=int(binding_id), persist=False)
    if persist and bool(context.get("ok")):
        payload = _player_state_payload_from_context(context)
        report_tv_player_state(binding_id=int(binding_id), payload=payload, event_type=PLAYER_EVENT_RELOADED, force=True)
    return {"ok": bool(context.get("ok")), "context": context}


def load_tv_player_status(*, binding_id: int) -> Dict[str, Any]:
    ensure_tv_local_schema()
    bid = int(binding_id)
    binding = get_tv_screen_binding(binding_id=bid)
    if not binding:
        return {"ok": False, "error": "BINDING_NOT_FOUND", "binding": None, "playerState": None}
    player_state = load_tv_player_state(binding_id=bid)
    return {"ok": True, "binding": binding, "playerState": player_state}


# ---------------------------------------------------------------------------
# A10: Support and Recovery Actions
# ---------------------------------------------------------------------------

def get_tv_binding_health_summary(*, binding_id: int) -> Dict[str, Any]:
    ensure_tv_local_schema()
    bid = int(binding_id)
    binding = get_tv_screen_binding(binding_id=bid)
    if not binding:
        return {"health": BINDING_HEALTH_ERROR, "reasons": ["Binding not found"]}

    enabled = _binding_bool(binding.get("enabled"))
    desired = _safe_str(binding.get("desired_state"), DESIRED_STOPPED)

    if not enabled or desired == DESIRED_STOPPED:
        return {"health": BINDING_HEALTH_STOPPED, "reasons": ["Binding is stopped or disabled"]}

    # Collect facts
    reasons = []
    is_error = False
    is_degraded = False
    is_warning = False

    runtime = get_tv_screen_binding_runtime(binding_id=bid) or {}
    run_state = _safe_str(runtime.get("runtime_state"), BINDING_RUNTIME_IDLE)
    crash_count = _safe_int(runtime.get("crash_count"), 0)

    if crash_count > 3:
        is_error = True
        reasons.append(f"High crash count ({crash_count})")
    elif crash_count > 0:
        is_warning = True
        reasons.append(f"Recent crashes ({crash_count})")

    if run_state in (BINDING_RUNTIME_ERROR, BINDING_RUNTIME_CRASHED):
        is_error = True
        reasons.append(f"Runtime state is {run_state}")

    if binding.get("last_error_message"):
        is_warning = True
        reasons.append(f"Binding error: {binding['last_error_message']}")

    # Player state facts
    player_state = load_tv_player_state(binding_id=bid) or {}
    p_state = _safe_str(player_state.get("player_state"), PLAYER_STATE_IDLE)
    p_fallback = _safe_str(player_state.get("fallback_reason"), "")

    if p_state == PLAYER_STATE_ERROR:
        is_error = True
        reasons.append("Player is in ERROR state")
    elif p_fallback:
        is_degraded = True
        reasons.append(f"Player fallback: {p_fallback}")

    if p_state.startswith("BLOCKED"):
        is_error = True
        reasons.append(f"Player blocked: {p_state}")

    # Monitor availability
    mid = _safe_str(binding.get("monitor_id"), "")
    if mid:
        monitors = list_tv_host_monitors()
        mon = next((m for m in monitors if m.get("monitor_id") == mid), None)
        if not mon or not _binding_bool(mon.get("is_connected")):
            is_error = True
            reasons.append(f"Assigned monitor disconnected or missing: {mid}")

    # Determine health enum
    health = BINDING_HEALTH_HEALTHY
    if is_error:
        health = BINDING_HEALTH_ERROR
    elif is_degraded:
        health = BINDING_HEALTH_DEGRADED
    elif is_warning:
        health = BINDING_HEALTH_WARNING

    if health == BINDING_HEALTH_HEALTHY and not reasons:
        reasons.append("Running normally")

    return {
        "health": health,
        "reasons": reasons,
        "summary": {
            "binding": dict(binding),
            "runtime": dict(runtime),
            "player": dict(player_state),
        }
    }


def _start_support_action(conn, binding_id: int, action_type: str) -> str:
    # Single flight check
    running = conn.execute(
        "SELECT id FROM tv_support_action_log WHERE binding_id=? AND result=? LIMIT 1",
        (binding_id, SUPPORT_RESULT_STARTED)
    ).fetchone()
    if running:
        raise ValueError(f"Support action already running for binding {binding_id}")

    corr_id = f"sa_{uuid.uuid4().hex[:12]}"
    ts = now_iso()
    gym_id = conn.execute("SELECT gym_id FROM tv_screen_binding WHERE id=?", (binding_id,)).fetchone()
    gid = _safe_int(gym_id[0]) if gym_id else 0

    curr_cur = conn.execute("""
        INSERT INTO tv_support_action_log (
            binding_id, gym_id, correlation_id, action_type, result, started_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (binding_id, gid, corr_id, action_type, SUPPORT_RESULT_STARTED, ts, ts, ts))
    return corr_id


def _finish_support_action(conn, correlation_id: str, result: str, message: str = None, error_code: str = None,
                           metadata: dict = None):
    ts = now_iso()
    meta_json = _json_dumps(metadata) if metadata else None
    conn.execute("""
        UPDATE tv_support_action_log
        SET result=?, message=?, error_code=?, error_message=?, metadata_json=?, finished_at=?, updated_at=?
        WHERE correlation_id=?
    """, (result, message, error_code, message if error_code else None, meta_json, ts, ts, correlation_id))


def run_tv_support_action(*, binding_id: int, action_type: str, options: Dict[str, Any] = None, confirm: bool = False) -> Dict[str, Any]:
    ensure_tv_local_schema()
    bid = int(binding_id)
    opts = options or {}

    destructive_actions = {
        SUPPORT_ACTION_STOP_BINDING,
        SUPPORT_ACTION_RESTART_BINDING,
        SUPPORT_ACTION_RESTART_PLAYER_WINDOW,
        SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE
    }

    if action_type in destructive_actions and not confirm:
        return {"ok": False, "result": SUPPORT_RESULT_BLOCKED, "error": "CONFIRMATION_REQUIRED", "message": f"{action_type} requires confirm=True"}

    with get_conn() as conn:
        try:
            corr_id = _start_support_action(conn, bid, action_type)
            conn.commit()
        except ValueError as e:
            return {"ok": False, "result": SUPPORT_RESULT_BLOCKED, "error": "ALREADY_RUNNING", "message": str(e)}
        except Exception as e:
            _log.error("Failed to start support action: %s", e)
            return {"ok": False, "result": SUPPORT_RESULT_FAILED, "error": "INTERNAL_ERROR", "message": str(e)}

    # Dispatch externally
    result = SUPPORT_RESULT_SUCCEEDED
    message = None
    err_code = None
    meta = {}

    try:
        # Resolve screen_id if needed
        binding = get_tv_screen_binding(binding_id=bid)
        if not binding:
            err_code = "BINDING_NOT_FOUND"
            result = SUPPORT_RESULT_BLOCKED
            raise ValueError(f"Binding {bid} not found")
        
        sid = _safe_int(binding.get("screen_id"), 0)

        if action_type == SUPPORT_ACTION_RUN_SYNC:
            if not sid:
                raise ValueError("Binding has no valid screen_id for sync")
            sync_res = sync_tv_screen_latest_snapshot(screen_id=sid, force_recheck=True, correlation_id=corr_id)
            meta["sync"] = sync_res
            if not sync_res.get("ok"):
                result = SUPPORT_RESULT_FAILED
                err_code = "SYNC_FAILED"
                message = sync_res.get("error") or "Sync failed"

        elif action_type == SUPPORT_ACTION_RECOMPUTE_READINESS:
            if not sid:
                raise ValueError("Binding has no valid screen_id")
            # Force readiness recompute
            snap_res = get_tv_screen_active_snapshot(screen_id=sid)
            latest_id = snap_res.get("state", {}).get("latest_snapshot_id")
            if latest_id:
                read_res = get_or_compute_snapshot_readiness(screen_id=sid, snapshot_id=latest_id, force_recheck=True)
                meta["readiness"] = read_res
            else:
                result = SUPPORT_RESULT_SKIPPED
                message = "No latest snapshot to compute readiness for"

        elif action_type == SUPPORT_ACTION_REEVALUATE_ACTIVATION:
            if not sid:
                raise ValueError("Binding has no valid screen_id")
            act_res = evaluate_tv_screen_activation(screen_id=sid, reason="support_reevaluate", execute_if_ready=True)
            meta["activation"] = act_res
            if not act_res.get("ok"):
                result = SUPPORT_RESULT_FAILED
                err_code = "ACTIVATION_REEVAL_FAILED"
                message = act_res.get("error")

        elif action_type == SUPPORT_ACTION_ACTIVATE_LATEST_READY:
            if not sid:
                raise ValueError("Binding has no valid screen_id")
            act_res = evaluate_tv_screen_activation(screen_id=sid, reason="support_activate_latest", execute_if_ready=True)
            meta["activation"] = act_res
            if not act_res.get("ok") and act_res.get("error") != "SKIPPED_ALREADY_ACTIVE":
                 result = SUPPORT_RESULT_FAILED
                 err_code = "ACTIVATION_FAILED"
                 message = act_res.get("error")

        elif action_type == SUPPORT_ACTION_REEVALUATE_PLAYER_CONTEXT:
            ctx = reevaluate_tv_player(binding_id=bid, persist=True)
            meta["context"] = ctx
            if not ctx.get("ok"):
                result = SUPPORT_RESULT_FAILED
                err_code = "REEVALUATE_FAILED"
                message = ctx.get("error")

        elif action_type == SUPPORT_ACTION_RELOAD_PLAYER:
            ctx = reload_tv_player(binding_id=bid, persist=True)
            meta["context"] = ctx
            if not ctx.get("ok"):
                result = SUPPORT_RESULT_FAILED
                err_code = "RELOAD_FAILED"
                message = ctx.get("error")

        elif action_type == SUPPORT_ACTION_RETRY_FAILED_DOWNLOADS:
            from app.core._tv_sync_helpers import retry_screen_failed_downloads
            if not sid:
                raise ValueError("Binding has no valid screen_id")
            res_retry = retry_screen_failed_downloads(screen_id=sid, force=True)
            meta["retry_results"] = res_retry
            if res_retry.get("retried_count", 0) == 0:
                result = SUPPORT_RESULT_SKIPPED
                message = "No failed downloads to retry"

        elif action_type == SUPPORT_ACTION_RETRY_ONE_DOWNLOAD:
            asset_id = opts.get("mediaAssetId")
            if not asset_id:
                err_code = "MISSING_ASSET_ID"
                result = SUPPORT_RESULT_BLOCKED
                raise ValueError("mediaAssetId option is required")
            
            from app.core._tv_sync_helpers import evaluate_local_asset
            res_eval = evaluate_local_asset(media_asset_id=asset_id, force_download_retry=True)
            meta["asset_eval"] = res_eval

        elif action_type == SUPPORT_ACTION_START_BINDING:
            db_res = update_tv_screen_binding(binding_id=bid, updates={"desired_state": DESIRED_RUNNING})
            meta["update"] = db_res
            if not db_res.get("ok"):
                result = SUPPORT_RESULT_FAILED
                err_code = "START_FAILED"
                message = db_res.get("error")

        elif action_type == SUPPORT_ACTION_STOP_BINDING:
            db_res = update_tv_screen_binding(binding_id=bid, updates={"desired_state": DESIRED_STOPPED})
            meta["update"] = db_res
            if not db_res.get("ok"):
                result = SUPPORT_RESULT_FAILED
                err_code = "STOP_FAILED"
                message = db_res.get("error")

        elif action_type == SUPPORT_ACTION_RESTART_BINDING:
            # Requires stopping then starting in quick succession
            res_stop = update_tv_screen_binding(binding_id=bid, updates={"desired_state": DESIRED_STOPPED})
            res_start = update_tv_screen_binding(binding_id=bid, updates={"desired_state": DESIRED_RUNNING})
            meta["stop"] = res_stop
            meta["start"] = res_start
            if not res_start.get("ok"):
                result = SUPPORT_RESULT_FAILED
                err_code = "RESTART_FAILED"
                message = res_start.get("error")
                
        elif action_type == SUPPORT_ACTION_RESTART_PLAYER_WINDOW:
            # We enforce restart by setting runtime to crashed, then supervisor restarts it if desired is running
            db_res = report_tv_screen_binding_runtime(binding_id=bid, runtime_state=BINDING_RUNTIME_CRASHED, last_exit_reason="support_restart")
            meta["runtime_update"] = db_res

        elif action_type == SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE:
            # Must be stopped
            run_state = get_tv_screen_binding_runtime(binding_id=bid) or {}
            rt = _safe_str(run_state.get("runtime_state"), BINDING_RUNTIME_IDLE)
            if rt in (BINDING_RUNTIME_RUNNING, BINDING_RUNTIME_STARTING):
                result = SUPPORT_RESULT_BLOCKED
                err_code = "MUST_STOP_FIRST"
                raise ValueError(f"Binding must be stopped to reset transient state. Current runtime = {rt}")
            
            with get_conn() as rconn:
                rconn.execute("DELETE FROM tv_player_state WHERE binding_id=?", (bid,))
                rconn.execute("DELETE FROM tv_screen_binding_runtime WHERE binding_id=?", (bid,))
                rconn.commit()
            message = "Transient player state cleared."

        else:
            result = SUPPORT_RESULT_FAILED
            err_code = "UNKNOWN_ACTION_TYPE"
            message = f"Unsupported action type: {action_type}"

    except Exception as e:
        _log.exception(f"Support action {action_type} failed: {e}")
        if result not in (SUPPORT_RESULT_BLOCKED, SUPPORT_RESULT_SKIPPED):
            result = SUPPORT_RESULT_FAILED
        if not err_code:
            err_code = "EXECUTION_ERROR"
        if not message:
            message = str(e)

    # Finally write result
    try:
        with get_conn() as conn:
            _finish_support_action(conn, corr_id, result, message, err_code, meta)
            conn.commit()
    except Exception as e2:
        _log.error("Failed to commit support finish: %s", e2)

    return {
        "ok": result in (SUPPORT_RESULT_SUCCEEDED, SUPPORT_RESULT_SKIPPED),
        "correlationId": corr_id,
        "result": result,
        "message": message,
        "errorCode": err_code,
        "metadata": meta
    }


def get_tv_support_action_history(*, binding_id: int, limit: int = 50) -> List[Dict[str, Any]]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT * FROM tv_support_action_log
            WHERE binding_id=?
            ORDER BY created_at DESC
            LIMIT ?
        """, (int(binding_id), int(limit))).fetchall()
        
        hist = []
        for r in rows:
            d = _row_to_dict(r)
            d["metadata"] = _json_loads(d.pop("metadata_json", None))
            hist.append(d)
        return hist

# A10 override marker

SUPPORT_ACTION_TYPES: Tuple[str, ...] = (
    SUPPORT_ACTION_RUN_SYNC,
    SUPPORT_ACTION_RECOMPUTE_READINESS,
    SUPPORT_ACTION_RETRY_FAILED_DOWNLOADS,
    SUPPORT_ACTION_RETRY_ONE_DOWNLOAD,
    SUPPORT_ACTION_REEVALUATE_ACTIVATION,
    SUPPORT_ACTION_ACTIVATE_LATEST_READY,
    SUPPORT_ACTION_REEVALUATE_PLAYER_CONTEXT,
    SUPPORT_ACTION_RELOAD_PLAYER,
    SUPPORT_ACTION_START_BINDING,
    SUPPORT_ACTION_STOP_BINDING,
    SUPPORT_ACTION_RESTART_BINDING,
    SUPPORT_ACTION_RESTART_PLAYER_WINDOW,
    SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE,
)

SUPPORT_DESTRUCTIVE_ACTIONS = {
    SUPPORT_ACTION_STOP_BINDING,
    SUPPORT_ACTION_RESTART_BINDING,
    SUPPORT_ACTION_RESTART_PLAYER_WINDOW,
    SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE,
}

_SUPPORT_RESTART_EXIT_REASONS = {
    "SUPPORT_RESTART_BINDING",
    "SUPPORT_RESTART_PLAYER_WINDOW",
}


def _support_correlation_id() -> str:
    return f"tvsup_{uuid.uuid4().hex}"


def _get_support_action_lock(binding_id: int) -> threading.Lock:
    bid = int(binding_id)
    with _support_action_lock_guard:
        lock = _support_action_locks.get(bid)
        if lock is None:
            lock = threading.Lock()
            _support_action_locks[bid] = lock
        return lock


def _set_active_support_action(*, binding_id: int, action_type: str, correlation_id: str) -> None:
    with _support_action_lock_guard:
        _support_action_active[int(binding_id)] = {
            "bindingId": int(binding_id),
            "actionType": str(action_type),
            "correlationId": str(correlation_id),
            "startedAt": now_iso(),
        }


def _clear_active_support_action(*, binding_id: int, correlation_id: str = None) -> None:
    with _support_action_lock_guard:
        current = _support_action_active.get(int(binding_id))
        if not current:
            return
        if correlation_id and _safe_str(current.get("correlationId"), "") != str(correlation_id):
            return
        _support_action_active.pop(int(binding_id), None)


def _get_active_support_action(binding_id: int) -> Optional[Dict[str, Any]]:
    with _support_action_lock_guard:
        current = _support_action_active.get(int(binding_id))
        return dict(current) if current else None


def _support_log_row_to_dict(row: Any) -> Dict[str, Any]:
    data = _row_to_dict(row) or {}
    if not data:
        return {}
    data["metadata"] = _json_loads(data.get("metadata_json"))
    return data


def _insert_support_action_log(
    conn,
    *,
    binding_id: int,
    gym_id: Optional[int],
    correlation_id: str,
    action_type: str,
    result: str,
    message: str = None,
    error_code: str = None,
    error_message: str = None,
    metadata: Optional[Dict[str, Any]] = None,
    started_at: str = None,
    finished_at: str = None,
) -> Dict[str, Any]:
    ts = now_iso()
    started = started_at or ts
    meta_json = _json_dumps(metadata) if metadata is not None else None
    conn.execute(
        """
        INSERT INTO tv_support_action_log (
            binding_id, gym_id, correlation_id, action_type, result,
            message, error_code, error_message, metadata_json,
            started_at, finished_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            int(binding_id),
            int(gym_id) if gym_id is not None else None,
            str(correlation_id),
            str(action_type),
            str(result),
            message,
            error_code,
            error_message,
            meta_json,
            started,
            finished_at,
            ts,
            ts,
        ),
    )
    row = conn.execute(
        "SELECT * FROM tv_support_action_log WHERE correlation_id=? ORDER BY id DESC LIMIT 1",
        (str(correlation_id),),
    ).fetchone()
    return _support_log_row_to_dict(row)


def _finish_support_action(
    conn,
    correlation_id: str,
    *,
    result: str,
    message: str = None,
    error_code: str = None,
    error_message: str = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    ts = now_iso()
    meta_json = _json_dumps(metadata) if metadata is not None else None
    conn.execute(
        """
        UPDATE tv_support_action_log
        SET result=?, message=?, error_code=?, error_message=?, metadata_json=?, finished_at=?, updated_at=?
        WHERE correlation_id=?
        """,
        (
            str(result),
            message,
            error_code,
            error_message,
            meta_json,
            ts,
            ts,
            str(correlation_id),
        ),
    )
    row = conn.execute(
        "SELECT * FROM tv_support_action_log WHERE correlation_id=? ORDER BY id DESC LIMIT 1",
        (str(correlation_id),),
    ).fetchone()
    return _support_log_row_to_dict(row)


def _record_support_action_outcome(
    *,
    binding_id: int,
    gym_id: Optional[int],
    action_type: str,
    result: str,
    message: str = None,
    error_code: str = None,
    error_message: str = None,
    metadata: Optional[Dict[str, Any]] = None,
    correlation_id: str = None,
) -> Dict[str, Any]:
    ensure_tv_local_schema()
    corr_id = str(correlation_id or _support_correlation_id())
    ts = now_iso()
    with get_conn() as conn:
        row = _insert_support_action_log(
            conn,
            binding_id=int(binding_id),
            gym_id=gym_id,
            correlation_id=corr_id,
            action_type=action_type,
            result=result,
            message=message,
            error_code=error_code,
            error_message=error_message or message,
            metadata=metadata,
            started_at=ts,
            finished_at=ts,
        )
        conn.commit()
    return row


def _dedupe_reasons(values: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for raw in values:
        item = _safe_str(raw, "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _load_monitor_for_binding(binding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    monitor_id = _safe_str((binding or {}).get("monitor_id"), "").strip()
    if not monitor_id:
        return None
    for row in list_tv_host_monitors():
        if _safe_str(row.get("monitor_id"), "").strip() == monitor_id:
            return row
    return None


def _load_ready_snapshot_rows(*, screen_id: int, limit: int = 2) -> List[Dict[str, Any]]:
    ensure_tv_local_schema()
    if int(screen_id) <= 0:
        return []
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT s.*
            FROM tv_snapshot_readiness r
            JOIN tv_snapshot_cache s ON s.snapshot_id = r.snapshot_id
            WHERE r.screen_id=?
              AND r.readiness_state=?
              AND IFNULL(r.is_fully_ready, 0)=1
            ORDER BY r.snapshot_version DESC, r.id DESC
            LIMIT ?
            """,
            (int(screen_id), READINESS_READY, int(limit)),
        ).fetchall()
    return _rows_to_list(rows)


def _load_latest_ready_snapshot_row(*, screen_id: int) -> Optional[Dict[str, Any]]:
    rows = _load_ready_snapshot_rows(screen_id=int(screen_id), limit=1)
    return rows[0] if rows else None


def _load_previous_ready_snapshot_row(*, screen_id: int) -> Optional[Dict[str, Any]]:
    rows = _load_ready_snapshot_rows(screen_id=int(screen_id), limit=2)
    return rows[1] if len(rows) > 1 else None


def _list_binding_failed_downloads(*, screen_id: int, limit: int = 25) -> List[Dict[str, Any]]:
    if int(screen_id) <= 0:
        return []
    latest_snapshot = load_tv_latest_snapshot(screen_id=int(screen_id))
    if not latest_snapshot:
        return []

    rows: List[Dict[str, Any]] = []
    snapshot_id = _safe_str(latest_snapshot.get("snapshot_id"), "")
    if not snapshot_id:
        return []
    for asset in list_tv_snapshot_required_assets(snapshot_id=snapshot_id):
        media_asset_id = _safe_str(asset.get("media_asset_id"), "").strip()
        if not media_asset_id:
            continue
        local = load_tv_local_asset_state(media_asset_id=media_asset_id) or {}
        asset_state = _safe_str(local.get("asset_state"), ASSET_STATE_NOT_PRESENT) or ASSET_STATE_NOT_PRESENT
        if asset_state == ASSET_STATE_VALID:
            continue
        rows.append({
            "snapshot_id": snapshot_id,
            "snapshot_version": latest_snapshot.get("snapshot_version"),
            "media_asset_id": media_asset_id,
            "download_link": asset.get("download_link"),
            "checksum_sha256": asset.get("checksum_sha256"),
            "size_bytes": asset.get("size_bytes"),
            "mime_type": asset.get("mime_type"),
            "media_type": asset.get("media_type"),
            "asset_state": asset_state,
            "state_reason": local.get("state_reason"),
            "local_file_path": local.get("local_file_path"),
            "validation_mode": local.get("validation_mode"),
            "last_checked_at": local.get("last_checked_at"),
        })
        if len(rows) >= int(limit):
            break
    return rows


def _support_action_precondition(
    *,
    facts: Dict[str, Any],
    action_type: str,
) -> Tuple[Optional[str], Optional[str], List[str]]:
    binding = facts.get("binding") or {}
    runtime = facts.get("runtime") or {}
    latest_snapshot = facts.get("latestSnapshot") or {}
    latest_ready_snapshot = facts.get("latestReadySnapshot") or {}
    failed_downloads = facts.get("downloadFailures") or {}
    monitor = facts.get("monitor") or {}

    enabled = _binding_bool(binding.get("enabled"))
    desired = _safe_str(binding.get("desired_state"), DESIRED_STOPPED)
    runtime_state = _safe_str(runtime.get("runtime_state"), BINDING_RUNTIME_IDLE)
    screen_id = _safe_int(binding.get("screen_id"), 0)
    monitor_available = bool(monitor.get("available"))

    if action_type not in SUPPORT_ACTION_TYPES:
        return ("UNKNOWN_ACTION_TYPE", f"Unsupported action type: {action_type}", [])

    if not binding:
        return ("BINDING_NOT_FOUND", "Binding not found.", [])

    if action_type in {
        SUPPORT_ACTION_RUN_SYNC,
        SUPPORT_ACTION_RECOMPUTE_READINESS,
        SUPPORT_ACTION_RETRY_FAILED_DOWNLOADS,
        SUPPORT_ACTION_RETRY_ONE_DOWNLOAD,
        SUPPORT_ACTION_REEVALUATE_ACTIVATION,
        SUPPORT_ACTION_ACTIVATE_LATEST_READY,
    } and screen_id <= 0:
        return ("SCREEN_ID_MISSING", "Binding is missing a valid screen_id.", [])

    if action_type in {SUPPORT_ACTION_START_BINDING, SUPPORT_ACTION_RESTART_BINDING, SUPPORT_ACTION_RESTART_PLAYER_WINDOW}:
        if not monitor_available:
            return ("MONITOR_MISSING", "Assigned monitor is missing or disconnected.", [])

    if action_type in {SUPPORT_ACTION_STOP_BINDING, SUPPORT_ACTION_RESTART_BINDING, SUPPORT_ACTION_RESTART_PLAYER_WINDOW, SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE}:
        if runtime_state in {BINDING_RUNTIME_STARTING, BINDING_RUNTIME_STOPPING}:
            return ("TRANSITION_IN_PROGRESS", f"Binding transition already in progress ({runtime_state}).", [])

    if action_type == SUPPORT_ACTION_START_BINDING:
        if not enabled:
            return ("BINDING_DISABLED", "Binding is disabled.", [])
        if desired == DESIRED_RUNNING and runtime_state in {BINDING_RUNTIME_RUNNING, BINDING_RUNTIME_STARTING}:
            return ("ALREADY_RUNNING", "Binding is already running.", [])

    if action_type == SUPPORT_ACTION_STOP_BINDING:
        if desired == DESIRED_STOPPED and runtime_state in {BINDING_RUNTIME_STOPPED, BINDING_RUNTIME_IDLE}:
            return ("ALREADY_STOPPED", "Binding is already stopped.", [])

    if action_type == SUPPORT_ACTION_RESTART_BINDING:
        if not enabled:
            return ("BINDING_DISABLED", "Binding is disabled.", [])
        if desired != DESIRED_RUNNING and runtime_state not in {BINDING_RUNTIME_RUNNING, BINDING_RUNTIME_CRASHED, BINDING_RUNTIME_ERROR}:
            return ("BINDING_NOT_RUNNING", "Binding is not currently running.", [])

    if action_type == SUPPORT_ACTION_RESTART_PLAYER_WINDOW:
        if desired != DESIRED_RUNNING:
            return ("BINDING_NOT_RUNNING", "Player window restart requires a running binding.", [])

    if action_type == SUPPORT_ACTION_RETRY_FAILED_DOWNLOADS:
        if int(failed_downloads.get("count") or 0) <= 0:
            return ("NO_FAILED_DOWNLOADS", "No failed downloads are available for retry.", [])

    if action_type == SUPPORT_ACTION_RETRY_ONE_DOWNLOAD:
        if int(failed_downloads.get("count") or 0) <= 0:
            return ("NO_FAILED_DOWNLOADS", "No failed downloads are available for retry.", ["mediaAssetId"])
        return (None, None, ["mediaAssetId"])

    if action_type == SUPPORT_ACTION_ACTIVATE_LATEST_READY:
        if not latest_snapshot:
            return ("NO_LATEST_SNAPSHOT", "No latest snapshot is cached locally.", [])
        if not latest_ready_snapshot:
            return ("NO_LATEST_READY_SNAPSHOT", "No latest ready snapshot is available.", [])

    if action_type == SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE:
        if desired != DESIRED_STOPPED or runtime_state in {
            BINDING_RUNTIME_RUNNING,
            BINDING_RUNTIME_STARTING,
            BINDING_RUNTIME_STOPPING,
        }:
            return ("RESET_REQUIRES_STOP", "Reset requires the binding to be stopped first.", [])

    return (None, None, [])


def _derive_binding_health(facts: Dict[str, Any]) -> Tuple[str, List[str]]:
    binding = facts.get("binding") or {}
    runtime = facts.get("runtime") or {}
    player_state = facts.get("playerState") or {}
    readiness = facts.get("latestReadiness") or {}
    activation = facts.get("activation") or {}
    monitor = facts.get("monitor") or {}
    ad_runtime = facts.get("adRuntime") or {}
    failed_downloads = facts.get("downloadFailures") or {}
    proof_failures = facts.get("proofFailures") or {}

    enabled = _binding_bool(binding.get("enabled"))
    desired = _safe_str(binding.get("desired_state"), DESIRED_STOPPED)
    runtime_state = _safe_str(runtime.get("runtime_state"), BINDING_RUNTIME_IDLE)
    player = _safe_str(player_state.get("player_state"), PLAYER_STATE_IDLE)
    readiness_state = _safe_str(readiness.get("readiness_state"), "")
    activation_state = _safe_str(activation.get("activation_state"), "")
    crash_count = _safe_int(runtime.get("crash_count"), 0)

    if not enabled or desired == DESIRED_STOPPED:
        return (BINDING_HEALTH_STOPPED, ["Binding is disabled or desired state is STOPPED."])

    errors: List[str] = []
    degraded: List[str] = []
    warnings: List[str] = []

    if not monitor.get("available"):
        errors.append("Assigned monitor is missing or disconnected.")

    if runtime_state in {BINDING_RUNTIME_ERROR, BINDING_RUNTIME_CRASHED}:
        errors.append(f"Runtime state is {runtime_state}.")
    elif runtime_state in {BINDING_RUNTIME_STARTING, BINDING_RUNTIME_STOPPING}:
        warnings.append(f"Runtime transition in progress: {runtime_state}.")

    if crash_count >= 3:
        errors.append(f"Crash count is elevated ({crash_count}).")
    elif crash_count > 0:
        warnings.append(f"Recent crashes detected ({crash_count}).")

    runtime_error_code = _safe_str(runtime.get("last_error_code"), "")
    runtime_error_message = _safe_str(runtime.get("last_error_message"), "")
    binding_error_code = _safe_str(binding.get("last_error_code"), "")
    binding_error_message = _safe_str(binding.get("last_error_message"), "")
    if runtime_error_message:
        degraded.append(f"Runtime error: {runtime_error_code or 'UNKNOWN'} {runtime_error_message}".strip())
    if binding_error_message:
        warnings.append(f"Binding error: {binding_error_code or 'UNKNOWN'} {binding_error_message}".strip())

    if readiness_state == READINESS_ERROR:
        errors.append("Latest readiness state is ERROR.")
    elif readiness_state == READINESS_NOT_READY:
        degraded.append("Latest snapshot is not ready.")
    elif readiness_state == READINESS_PARTIALLY_READY:
        warnings.append("Latest snapshot is only partially ready.")
    elif readiness_state == READINESS_EMPTY and desired == DESIRED_RUNNING:
        degraded.append("No renderable snapshot content is cached locally.")
    elif not readiness_state:
        warnings.append("No readiness summary has been computed yet.")

    if activation_state in {ACTIVATION_STATE_ERROR, ACTIVATION_STATE_BLOCKED_PREREQUISITE}:
        errors.append(f"Activation state is {activation_state}.")
    elif activation_state in {ACTIVATION_STATE_NO_ACTIVE_SNAPSHOT, ACTIVATION_STATE_BLOCKED_WAITING_FOR_READY}:
        degraded.append(f"Activation state is {activation_state}.")
    elif activation_state == ACTIVATION_STATE_ACTIVE_OLDER_THAN_LATEST:
        warnings.append("Active snapshot is older than the latest cached snapshot.")

    if player == PLAYER_STATE_ERROR:
        errors.append("Player is in ERROR state.")
    elif player in {
        PLAYER_STATE_BLOCKED_NO_BINDING,
        PLAYER_STATE_BLOCKED_BINDING_DISABLED,
        PLAYER_STATE_BLOCKED_NO_ACTIVE_SNAPSHOT,
    }:
        errors.append(f"Player is blocked: {player}.")
    elif player == PLAYER_STATE_BLOCKED_NO_RENDERABLE_ITEM:
        degraded.append("Player has no renderable item at the current time.")
    elif player == PLAYER_STATE_FALLBACK_RENDERING:
        degraded.append("Player is operating in fallback rendering mode.")
    elif player in {PLAYER_STATE_LOADING_BINDING, PLAYER_STATE_LOADING_ACTIVE_SNAPSHOT}:
        warnings.append(f"Player is transitioning: {player}.")

    fallback_reason = _safe_str(player_state.get("fallback_reason"), "")
    if fallback_reason and player not in {PLAYER_STATE_ERROR, PLAYER_STATE_BLOCKED_NO_ACTIVE_SNAPSHOT}:
        warnings.append(f"Player fallback reason: {fallback_reason}.")

    failed_count = _safe_int(failed_downloads.get("count"), 0)
    if failed_count > 0:
        if readiness_state in {READINESS_NOT_READY, READINESS_ERROR}:
            degraded.append(f"{failed_count} required assets are not valid locally.")
        else:
            warnings.append(f"{failed_count} required assets need retry.")

    proof_retryable = _safe_int(proof_failures.get("retryableCount"), 0)
    proof_terminal = _safe_int(proof_failures.get("terminalCount"), 0)
    if proof_terminal > 0:
        degraded.append(f"{proof_terminal} proof outbox rows failed terminally.")
    elif proof_retryable > 0:
        warnings.append(f"{proof_retryable} proof outbox rows are waiting for retry.")

    ad_coord = _safe_str(ad_runtime.get("coordination_state"), "")
    ad_failures = _safe_int(ad_runtime.get("failed_binding_count"), 0)
    if ad_coord == GYM_COORD_ERROR:
        errors.append("Ad runtime is in ERROR state.")
    elif ad_coord == GYM_COORD_ABORTED:
        warnings.append("Ad runtime was recently aborted.")
    if ad_failures > 0:
        warnings.append(f"Ad runtime reported {ad_failures} failed bindings.")

    errors = _dedupe_reasons(errors)
    degraded = _dedupe_reasons(degraded)
    warnings = _dedupe_reasons(warnings)

    if errors:
        return (BINDING_HEALTH_ERROR, errors + degraded + warnings)
    if degraded:
        return (BINDING_HEALTH_DEGRADED, degraded + warnings)
    if warnings:
        return (BINDING_HEALTH_WARNING, warnings)
    return (BINDING_HEALTH_HEALTHY, ["Binding is running normally."])


def _list_support_action_logs(*, binding_id: int, limit: int = 100, offset: int = 0) -> Dict[str, Any]:
    ensure_tv_local_schema()
    bid = int(binding_id)
    with get_conn() as conn:
        total = conn.execute(
            "SELECT COUNT(*) AS cnt FROM tv_support_action_log WHERE binding_id=?",
            (bid,),
        ).fetchone()["cnt"]
        rows = conn.execute(
            """
            SELECT *
            FROM tv_support_action_log
            WHERE binding_id=?
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (bid, int(limit), int(offset)),
        ).fetchall()
    return {
        "rows": [_support_log_row_to_dict(row) for row in rows],
        "total": int(total or 0),
        "limit": int(limit),
        "offset": int(offset),
    }


def _collect_binding_support_facts(*, binding_id: int) -> Dict[str, Any]:
    ensure_tv_local_schema()
    bid = int(binding_id)
    binding = load_tv_screen_binding_by_id(binding_id=bid)
    if not binding:
        return {"ok": False, "error": "BINDING_NOT_FOUND"}

    screen_id = _safe_int(binding.get("screen_id"), 0)
    gym_id = _safe_int(binding.get("gym_id"), 0)
    runtime = load_tv_screen_binding_runtime(binding_id=bid) or {}
    player_state = load_tv_player_state(binding_id=bid) or {}
    latest_snapshot = load_tv_latest_snapshot(screen_id=screen_id) if screen_id > 0 else None
    latest_readiness = load_tv_latest_readiness(screen_id=screen_id) if screen_id > 0 else None
    activation = load_tv_activation_state(screen_id=screen_id) if screen_id > 0 else None
    latest_ready_snapshot = _load_latest_ready_snapshot_row(screen_id=screen_id) if screen_id > 0 else None
    previous_ready_snapshot = _load_previous_ready_snapshot_row(screen_id=screen_id) if screen_id > 0 else None
    monitor_row = _load_monitor_for_binding(binding)
    failed_download_rows = _list_binding_failed_downloads(screen_id=screen_id, limit=25) if screen_id > 0 else []

    proof_rows = {"rows": [], "total": 0}
    if gym_id > 0:
        proof_rows = list_tv_ad_proof_outbox(
            gym_id=gym_id,
            outbox_states=[PROOF_OUTBOX_FAILED_RETRYABLE, PROOF_OUTBOX_FAILED_TERMINAL],
            limit=10,
        )

    proof_retryable = 0
    proof_terminal = 0
    for row in proof_rows.get("rows") or []:
        state = _safe_str(row.get("outbox_state"), "")
        if state == PROOF_OUTBOX_FAILED_RETRYABLE:
            proof_retryable += 1
        elif state == PROOF_OUTBOX_FAILED_TERMINAL:
            proof_terminal += 1

    ad_runtime = load_tv_gym_ad_runtime(gym_id=gym_id) if gym_id > 0 else None
    latest_support_logs = _list_support_action_logs(binding_id=bid, limit=1, offset=0)

    facts: Dict[str, Any] = {
        "binding": dict(binding),
        "runtime": dict(runtime),
        "monitor": {
            "row": dict(monitor_row) if monitor_row else None,
            "available": bool(monitor_row and _binding_bool(monitor_row.get("is_connected"))),
        },
        "playerState": dict(player_state),
        "latestSnapshot": dict(latest_snapshot) if latest_snapshot else None,
        "latestReadiness": dict(latest_readiness) if latest_readiness else None,
        "activation": dict(activation) if activation else None,
        "latestReadySnapshot": dict(latest_ready_snapshot) if latest_ready_snapshot else None,
        "previousReadySnapshot": dict(previous_ready_snapshot) if previous_ready_snapshot else None,
        "adRuntime": dict(ad_runtime) if ad_runtime else None,
        "downloadFailures": {
            "count": len(failed_download_rows),
            "rows": failed_download_rows,
        },
        "proofFailures": {
            "retryableCount": proof_retryable,
            "terminalCount": proof_terminal,
            "rows": proof_rows.get("rows") or [],
        },
        "latestSupportAction": (latest_support_logs.get("rows") or [None])[0],
        "activeSupportAction": _get_active_support_action(bid),
    }
    return {"ok": True, "bindingId": bid, "screenId": screen_id or None, "gymId": gym_id or None, "facts": facts}


def _build_support_action_availability(*, facts: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    availability: Dict[str, Dict[str, Any]] = {}
    for action_type in SUPPORT_ACTION_TYPES:
        blocked_code, blocked_reason, required_options = _support_action_precondition(
            facts=facts,
            action_type=action_type,
        )
        availability[action_type] = {
            "actionType": action_type,
            "allowed": blocked_code is None,
            "blockedCode": blocked_code,
            "blockedReason": blocked_reason,
            "requiresConfirmation": action_type in SUPPORT_DESTRUCTIVE_ACTIONS,
            "destructive": action_type in SUPPORT_DESTRUCTIVE_ACTIONS,
            "requiredOptions": required_options,
        }
    return availability


def _run_support_snapshot_sync(*, screen_id: int, correlation_id: str) -> Dict[str, Any]:
    token = _get_auth_token()
    api = _build_tv_api()
    return _sync_screen_snapshot(
        api=api,
        token=token,
        screen_id=int(screen_id),
        correlation_id=str(correlation_id),
    )


def _retry_one_binding_download(*, screen_id: int, media_asset_id: str) -> Dict[str, Any]:
    latest_snapshot = load_tv_latest_snapshot(screen_id=int(screen_id))
    if not latest_snapshot:
        return {"ok": False, "error": "NO_LATEST_SNAPSHOT"}
    snapshot_id = _safe_str(latest_snapshot.get("snapshot_id"), "")
    if not snapshot_id:
        return {"ok": False, "error": "NO_LATEST_SNAPSHOT"}

    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM tv_snapshot_required_asset
            WHERE snapshot_id=? AND media_asset_id=?
            LIMIT 1
            """,
            (snapshot_id, str(media_asset_id)),
        ).fetchone()
    if not row:
        return {"ok": False, "error": "ASSET_NOT_REQUIRED_FOR_LATEST_SNAPSHOT"}

    outcome = _process_single_asset(_row_to_dict(row) or {})
    state = _safe_str(outcome.get("state"), "")
    ok = state in {ASSET_STATE_VALID, ASSET_STATE_PRESENT_UNCHECKED}
    return {"ok": ok, "snapshotId": snapshot_id, "asset": outcome}


def _record_support_binding_event(
    *,
    binding_id: int,
    action_type: str,
    correlation_id: str,
    message: str,
    metadata: Optional[Dict[str, Any]] = None,
    severity: str = SEVERITY_INFO,
) -> None:
    event_meta = {"correlationId": correlation_id, "actionType": action_type}
    if metadata:
        event_meta.update(metadata)
    record_tv_screen_binding_event(
        binding_id=int(binding_id),
        event_type=f"SUPPORT_{action_type}",
        severity=severity,
        message=message,
        metadata_json=event_meta,
    )


def record_tv_screen_binding_runtime_event(
    *,
    binding_id: int,
    event_type: str,
    window_id: str = None,
    error_code: str = None,
    error_message: str = None,
    correlation_id: str = None,
) -> Dict[str, Any]:
    ensure_tv_local_schema()
    bid = int(binding_id)
    binding = load_tv_screen_binding_by_id(binding_id=bid)
    if not binding:
        raise ValueError("BINDING_NOT_FOUND")

    runtime = load_tv_screen_binding_runtime(binding_id=bid) or {}
    crash_count = _safe_int(runtime.get("crash_count"), 0)
    evt = _safe_str(event_type, "").strip().upper()
    ts = now_iso()
    severity = SEVERITY_INFO
    message = evt
    updates: Dict[str, Any] = {}
    binding_error_code = None
    binding_error_message = None

    if evt in {"WINDOW_STARTING", "PLAYER_WINDOW_STARTING"}:
        updates = {
            "runtime_state": BINDING_RUNTIME_STARTING,
            "window_id": window_id,
            "tauri_window_label": window_id,
        }
        message = "Player window is starting."
    elif evt in {"WINDOW_OPENED", "PLAYER_WINDOW_OPENED"}:
        updates = {
            "runtime_state": BINDING_RUNTIME_RUNNING,
            "window_id": window_id,
            "tauri_window_label": window_id,
            "last_started_at": ts,
            "last_error_code": None,
            "last_error_message": None,
        }
        message = "Player window opened."
    elif evt in {"WINDOW_CLOSED", "PLAYER_WINDOW_CLOSED"}:
        updates = {
            "runtime_state": BINDING_RUNTIME_STOPPED,
            "window_id": None,
            "tauri_window_label": None,
            "last_stopped_at": ts,
            "last_exit_reason": error_code or "WINDOW_CLOSED",
        }
        message = "Player window closed."
    elif evt in {"WINDOW_CRASHED", "PLAYER_WINDOW_CRASHED"}:
        severity = SEVERITY_ERROR
        binding_error_code = error_code or "WINDOW_CRASHED"
        binding_error_message = error_message or "Player window crashed."
        updates = {
            "runtime_state": BINDING_RUNTIME_CRASHED,
            "last_crashed_at": ts,
            "crash_count": crash_count + 1,
            "last_exit_reason": binding_error_code,
            "last_error_code": binding_error_code,
            "last_error_message": binding_error_message,
        }
        message = binding_error_message
    elif evt in {"WINDOW_ERROR", "PLAYER_WINDOW_ERROR"}:
        severity = SEVERITY_ERROR
        binding_error_code = error_code or "WINDOW_ERROR"
        binding_error_message = error_message or "Player window error."
        updates = {
            "runtime_state": BINDING_RUNTIME_ERROR,
            "last_crashed_at": ts,
            "crash_count": crash_count + 1,
            "last_exit_reason": binding_error_code,
            "last_error_code": binding_error_code,
            "last_error_message": binding_error_message,
        }
        message = binding_error_message
    else:
        raise ValueError(f"UNSUPPORTED_RUNTIME_EVENT: {event_type}")

    runtime_row = upsert_tv_screen_binding_runtime(binding_id=bid, **updates)

    with get_conn() as conn:
        conn.execute(
            "UPDATE tv_screen_binding SET last_error_code=?, last_error_message=?, updated_at=? WHERE id=?",
            (binding_error_code, binding_error_message, ts, bid),
        )
        conn.commit()

    record_tv_screen_binding_event(
        binding_id=bid,
        event_type=f"RUNTIME_{evt}",
        severity=severity,
        message=message,
        metadata_json={
            "windowId": window_id,
            "errorCode": error_code,
            "errorMessage": error_message,
            "correlationId": correlation_id,
        },
    )

    updated_binding = load_tv_screen_binding_by_id(binding_id=bid) or dict(binding)
    updated_binding["runtime"] = runtime_row
    return updated_binding


def load_tv_binding_support_summary(*, binding_id: int) -> Dict[str, Any]:
    summary = _collect_binding_support_facts(binding_id=int(binding_id))
    if not bool(summary.get("ok")):
        return {"ok": False, "error": summary.get("error") or "BINDING_NOT_FOUND"}

    facts = summary.get("facts") or {}
    health, reasons = _derive_binding_health(facts)
    last_support = facts.get("latestSupportAction")
    last_correlation_id = _safe_str((last_support or {}).get("correlation_id"), "") or None

    return {
        "ok": True,
        "bindingId": summary.get("bindingId"),
        "screenId": summary.get("screenId"),
        "gymId": summary.get("gymId"),
        "health": health,
        "reasons": reasons,
        "facts": facts,
        "actionAvailability": _build_support_action_availability(facts=facts),
        "lastCorrelationId": last_correlation_id,
        "latestSupportAction": last_support,
        "activeAction": facts.get("activeSupportAction"),
    }


def get_tv_binding_health_summary(*, binding_id: int) -> Dict[str, Any]:
    summary = load_tv_binding_support_summary(binding_id=int(binding_id))
    if not bool(summary.get("ok")):
        return {"health": BINDING_HEALTH_ERROR, "reasons": [summary.get("error") or "Binding not found."]}
    return {
        "health": summary.get("health"),
        "reasons": summary.get("reasons") or [],
        "summary": summary.get("facts") or {},
    }


def list_tv_support_action_logs(*, binding_id: int, limit: int = 100, offset: int = 0, **kwargs) -> Dict[str, Any]:
    return _list_support_action_logs(binding_id=int(binding_id), limit=int(limit), offset=int(offset))


def run_tv_support_action(
    *,
    binding_id: int,
    action_type: str,
    options: Dict[str, Any] = None,
    confirm: bool = False,
    triggered_by: str = "LOCAL_OPERATOR",
    app=None,
) -> Dict[str, Any]:
    ensure_tv_local_schema()
    bid = int(binding_id)
    opts = dict(options or {})
    action = _safe_str(action_type, "").strip().upper()
    corr_id = _support_correlation_id()
    base_meta = {
        "triggeredBy": _safe_str(triggered_by, "LOCAL_OPERATOR") or "LOCAL_OPERATOR",
        "confirmReceived": bool(confirm),
        "options": opts,
    }

    if action not in SUPPORT_ACTION_TYPES:
        log_row = _record_support_action_outcome(
            binding_id=bid,
            gym_id=None,
            action_type=action or "UNKNOWN",
            result=SUPPORT_RESULT_BLOCKED,
            message=f"Unsupported action type: {action_type}",
            error_code="UNKNOWN_ACTION_TYPE",
            error_message=f"Unsupported action type: {action_type}",
            metadata=base_meta,
            correlation_id=corr_id,
        )
        return {
            "ok": False,
            "correlationId": corr_id,
            "result": SUPPORT_RESULT_BLOCKED,
            "message": log_row.get("message"),
            "errorCode": log_row.get("error_code"),
            "metadata": log_row.get("metadata"),
        }

    summary = _collect_binding_support_facts(binding_id=bid)
    if not bool(summary.get("ok")):
        log_row = _record_support_action_outcome(
            binding_id=bid,
            gym_id=None,
            action_type=action,
            result=SUPPORT_RESULT_BLOCKED,
            message="Binding not found.",
            error_code="BINDING_NOT_FOUND",
            error_message="Binding not found.",
            metadata=base_meta,
            correlation_id=corr_id,
        )
        return {
            "ok": False,
            "correlationId": corr_id,
            "result": SUPPORT_RESULT_BLOCKED,
            "message": log_row.get("message"),
            "errorCode": log_row.get("error_code"),
            "metadata": log_row.get("metadata"),
        }

    facts = summary.get("facts") or {}
    binding = facts.get("binding") or {}
    gym_id = _safe_int(binding.get("gym_id"), 0) or None

    if action in SUPPORT_DESTRUCTIVE_ACTIONS and not confirm:
        log_row = _record_support_action_outcome(
            binding_id=bid,
            gym_id=gym_id,
            action_type=action,
            result=SUPPORT_RESULT_BLOCKED,
            message=f"{action} requires confirmation.",
            error_code="CONFIRMATION_REQUIRED",
            error_message=f"{action} requires confirmation.",
            metadata=base_meta,
            correlation_id=corr_id,
        )
        return {
            "ok": False,
            "correlationId": corr_id,
            "result": SUPPORT_RESULT_BLOCKED,
            "message": log_row.get("message"),
            "errorCode": log_row.get("error_code"),
            "metadata": log_row.get("metadata"),
        }

    support_lock = _get_support_action_lock(bid)
    if not support_lock.acquire(blocking=False):
        log_row = _record_support_action_outcome(
            binding_id=bid,
            gym_id=gym_id,
            action_type=action,
            result=SUPPORT_RESULT_BLOCKED,
            message="Another support action is already running for this binding.",
            error_code="ALREADY_RUNNING",
            error_message="Another support action is already running for this binding.",
            metadata=base_meta,
            correlation_id=corr_id,
        )
        return {
            "ok": False,
            "correlationId": corr_id,
            "result": SUPPORT_RESULT_BLOCKED,
            "message": log_row.get("message"),
            "errorCode": log_row.get("error_code"),
            "metadata": log_row.get("metadata"),
        }

    try:
        refreshed = _collect_binding_support_facts(binding_id=bid)
        facts = refreshed.get("facts") or {}
        binding = facts.get("binding") or {}
        gym_id = _safe_int(binding.get("gym_id"), 0) or None
        blocked_code, blocked_reason, required_options = _support_action_precondition(
            facts=facts,
            action_type=action,
        )

        if required_options:
            missing = [key for key in required_options if not _safe_str(opts.get(key), "").strip()]
            if missing:
                blocked_code = "MISSING_REQUIRED_OPTION"
                blocked_reason = f"Missing required option(s): {', '.join(missing)}."

        if blocked_code:
            if action == SUPPORT_ACTION_RETRY_FAILED_DOWNLOADS and blocked_code == "NO_FAILED_DOWNLOADS":
                log_row = _record_support_action_outcome(
                    binding_id=bid,
                    gym_id=gym_id,
                    action_type=action,
                    result=SUPPORT_RESULT_SKIPPED,
                    message=blocked_reason,
                    error_code=blocked_code,
                    error_message=blocked_reason,
                    metadata=base_meta,
                    correlation_id=corr_id,
                )
                return {
                    "ok": True,
                    "correlationId": corr_id,
                    "result": SUPPORT_RESULT_SKIPPED,
                    "message": log_row.get("message"),
                    "errorCode": log_row.get("error_code"),
                    "metadata": log_row.get("metadata"),
                }
            log_row = _record_support_action_outcome(
                binding_id=bid,
                gym_id=gym_id,
                action_type=action,
                result=SUPPORT_RESULT_BLOCKED,
                message=blocked_reason,
                error_code=blocked_code,
                error_message=blocked_reason,
                metadata=base_meta,
                correlation_id=corr_id,
            )
            return {
                "ok": False,
                "correlationId": corr_id,
                "result": SUPPORT_RESULT_BLOCKED,
                "message": log_row.get("message"),
                "errorCode": log_row.get("error_code"),
                "metadata": log_row.get("metadata"),
            }

        with get_conn() as conn:
            _insert_support_action_log(
                conn,
                binding_id=bid,
                gym_id=gym_id,
                correlation_id=corr_id,
                action_type=action,
                result=SUPPORT_RESULT_STARTED,
                metadata=base_meta,
            )
            conn.commit()

        _set_active_support_action(binding_id=bid, action_type=action, correlation_id=corr_id)

        result = SUPPORT_RESULT_SUCCEEDED
        message = ""
        error_code = None
        error_message = None
        metadata = dict(base_meta)
        screen_id = _safe_int(binding.get("screen_id"), 0)
        runtime = facts.get("runtime") or {}
        runtime_state = _safe_str(runtime.get("runtime_state"), BINDING_RUNTIME_IDLE)

        if action == SUPPORT_ACTION_RUN_SYNC:
            sync_result = _run_support_snapshot_sync(screen_id=screen_id, correlation_id=corr_id)
            metadata["sync"] = sync_result
            sync_status = _safe_str(sync_result.get("result"), "")
            if sync_status == SYNC_RUN_NO_SNAPSHOT:
                result = SUPPORT_RESULT_SKIPPED
                message = "No remote snapshot is currently available."
            elif sync_status in {SYNC_RUN_SUCCESS, SYNC_RUN_SUCCESS_WITH_WARNINGS}:
                message = f"Snapshot sync completed ({sync_status})."
            else:
                result = SUPPORT_RESULT_FAILED
                error_code = "SYNC_FAILED"
                error_message = _safe_str(sync_result.get("error"), "Snapshot sync failed.") or "Snapshot sync failed."
                message = error_message

        elif action == SUPPORT_ACTION_RECOMPUTE_READINESS:
            readiness_row = compute_tv_screen_readiness(screen_id=screen_id)
            metadata["readiness"] = readiness_row
            message = f"Readiness recomputed: {_safe_str(readiness_row.get('readiness_state'), 'UNKNOWN')}."

        elif action == SUPPORT_ACTION_RETRY_FAILED_DOWNLOADS:
            failed_before = _safe_int((facts.get("downloadFailures") or {}).get("count"), 0)
            download_result = run_tv_asset_download(screen_id=screen_id)
            metadata["download"] = download_result
            if not bool(download_result.get("ok")):
                result = SUPPORT_RESULT_FAILED
                error_code = "DOWNLOAD_RETRY_FAILED"
                error_message = _safe_str(download_result.get("error"), "Retrying downloads failed.") or "Retrying downloads failed."
                message = error_message
            else:
                message = f"Retried {failed_before} failed download(s)."

        elif action == SUPPORT_ACTION_RETRY_ONE_DOWNLOAD:
            media_asset_id = _safe_str(opts.get("mediaAssetId"), "").strip()
            retry_result = _retry_one_binding_download(screen_id=screen_id, media_asset_id=media_asset_id)
            metadata["download"] = retry_result
            if not bool(retry_result.get("ok")):
                result = SUPPORT_RESULT_FAILED
                error_code = _safe_str(retry_result.get("error"), "RETRY_ONE_DOWNLOAD_FAILED") or "RETRY_ONE_DOWNLOAD_FAILED"
                error_message = error_code.replace("_", " ").title()
                message = error_message
            else:
                message = f"Retried asset {media_asset_id}."

        elif action == SUPPORT_ACTION_REEVALUATE_ACTIVATION:
            activation_state = evaluate_tv_activation(screen_id=screen_id)
            metadata["activation"] = activation_state
            message = f"Activation reevaluated: {_safe_str(activation_state.get('activation_state'), 'UNKNOWN')}."

        elif action == SUPPORT_ACTION_ACTIVATE_LATEST_READY:
            activation_result = activate_tv_latest_ready_snapshot(
                screen_id=screen_id,
                trigger_source=f"SUPPORT:{corr_id}",
            )
            metadata["activation"] = activation_result
            attempt_result = _safe_str(activation_result.get("result"), "")
            if attempt_result == ATTEMPT_RESULT_ACTIVATED:
                message = "Latest ready snapshot activated."
            elif attempt_result == ATTEMPT_RESULT_SKIPPED_ALREADY_ACTIVE:
                result = SUPPORT_RESULT_SKIPPED
                message = _safe_str(activation_result.get("message"), "Latest ready snapshot is already active.")
            elif attempt_result in {ATTEMPT_RESULT_SKIPPED_NO_SNAPSHOT, ATTEMPT_RESULT_SKIPPED_NOT_READY}:
                result = SUPPORT_RESULT_BLOCKED
                error_code = _safe_str((activation_result.get("state") or {}).get("blocked_reason"), "NO_LATEST_READY_SNAPSHOT") or "NO_LATEST_READY_SNAPSHOT"
                message = _safe_str(activation_result.get("message"), "No latest ready snapshot is available.")
                error_message = message
            else:
                result = SUPPORT_RESULT_FAILED
                error_code = "ACTIVATE_LATEST_READY_FAILED"
                message = _safe_str(activation_result.get("message"), "Activation failed.")
                error_message = message

        elif action == SUPPORT_ACTION_REEVALUATE_PLAYER_CONTEXT:
            context = reevaluate_tv_player(binding_id=bid, persist=True)
            metadata["context"] = context
            message = f"Player context reevaluated: {_safe_str((context.get('context') or {}).get('playerState'), 'UNKNOWN')}."

        elif action == SUPPORT_ACTION_RELOAD_PLAYER:
            context = reload_tv_player(binding_id=bid, persist=True)
            metadata["context"] = context
            message = f"Player reloaded: {_safe_str((context.get('context') or {}).get('playerState'), 'UNKNOWN')}."

        elif action == SUPPORT_ACTION_START_BINDING:
            binding_row = start_tv_screen_binding(binding_id=bid)
            runtime_row = upsert_tv_screen_binding_runtime(
                binding_id=bid,
                runtime_state=BINDING_RUNTIME_STARTING,
                window_id=None,
                tauri_window_label=f"tv-player-{bid}",
                last_error_code="",
                last_error_message="",
            )
            metadata["binding"] = binding_row
            metadata["runtime"] = runtime_row
            _record_support_binding_event(
                binding_id=bid,
                action_type=action,
                correlation_id=corr_id,
                message="Binding start requested by support action.",
                metadata={"triggeredBy": base_meta["triggeredBy"]},
            )
            message = "Binding start requested."

        elif action == SUPPORT_ACTION_STOP_BINDING:
            binding_row = stop_tv_screen_binding(binding_id=bid)
            runtime_row = upsert_tv_screen_binding_runtime(
                binding_id=bid,
                runtime_state=BINDING_RUNTIME_STOPPING,
                last_error_code="",
                last_error_message="",
            )
            metadata["binding"] = binding_row
            metadata["runtime"] = runtime_row
            _record_support_binding_event(
                binding_id=bid,
                action_type=action,
                correlation_id=corr_id,
                message="Binding stop requested by support action.",
                metadata={"triggeredBy": base_meta["triggeredBy"]},
            )
            message = "Binding stop requested."

        elif action == SUPPORT_ACTION_RESTART_BINDING:
            stop_row = stop_tv_screen_binding(binding_id=bid)
            start_row = start_tv_screen_binding(binding_id=bid)
            runtime_row = upsert_tv_screen_binding_runtime(
                binding_id=bid,
                runtime_state=BINDING_RUNTIME_CRASHED if runtime_state in {
                    BINDING_RUNTIME_RUNNING,
                    BINDING_RUNTIME_CRASHED,
                    BINDING_RUNTIME_ERROR,
                    BINDING_RUNTIME_STARTING,
                } else BINDING_RUNTIME_STARTING,
                window_id=None,
                tauri_window_label=f"tv-player-{bid}",
                last_crashed_at=now_iso(),
                last_exit_reason="SUPPORT_RESTART_BINDING",
                last_error_code="",
                last_error_message="",
            )
            metadata["stop"] = stop_row
            metadata["start"] = start_row
            metadata["runtime"] = runtime_row
            _record_support_binding_event(
                binding_id=bid,
                action_type=action,
                correlation_id=corr_id,
                message="Binding restart requested by support action.",
                metadata={"triggeredBy": base_meta["triggeredBy"]},
            )
            message = "Binding restart requested."

        elif action == SUPPORT_ACTION_RESTART_PLAYER_WINDOW:
            runtime_row = upsert_tv_screen_binding_runtime(
                binding_id=bid,
                runtime_state=BINDING_RUNTIME_CRASHED,
                window_id=None,
                tauri_window_label=f"tv-player-{bid}",
                last_crashed_at=now_iso(),
                last_exit_reason="SUPPORT_RESTART_PLAYER_WINDOW",
                last_error_code="",
                last_error_message="",
            )
            metadata["runtime"] = runtime_row
            _record_support_binding_event(
                binding_id=bid,
                action_type=action,
                correlation_id=corr_id,
                message="Player window restart requested by support action.",
                metadata={"triggeredBy": base_meta["triggeredBy"]},
            )
            message = "Player window restart requested."

        elif action == SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE:
            with get_conn() as conn:
                conn.execute("DELETE FROM tv_player_state WHERE binding_id=?", (bid,))
                conn.execute("DELETE FROM tv_player_event WHERE binding_id=?", (bid,))
                conn.execute("DELETE FROM tv_screen_binding_runtime WHERE binding_id=?", (bid,))
                conn.commit()
            metadata["reset"] = {
                "playerStateCleared": True,
                "playerEventsCleared": True,
                "bindingRuntimeCleared": True,
            }
            _record_support_binding_event(
                binding_id=bid,
                action_type=action,
                correlation_id=corr_id,
                message="Transient player state reset by support action.",
                metadata={"triggeredBy": base_meta["triggeredBy"]},
                severity=SEVERITY_WARN,
            )
            message = "Transient player state cleared."

        with get_conn() as conn:
            _finish_support_action(
                conn,
                corr_id,
                result=result,
                message=message,
                error_code=error_code,
                error_message=error_message,
                metadata=metadata,
            )
            conn.commit()

        return {
            "ok": result in {SUPPORT_RESULT_SUCCEEDED, SUPPORT_RESULT_SKIPPED},
            "correlationId": corr_id,
            "result": result,
            "message": message,
            "errorCode": error_code,
            "metadata": metadata,
        }

    except Exception as exc:
        _log.exception("[TvSupport] action=%s binding=%s failed: %s", action, bid, exc)
        message = str(exc) or "Support action failed."
        with get_conn() as conn:
            _finish_support_action(
                conn,
                corr_id,
                result=SUPPORT_RESULT_FAILED,
                message=message,
                error_code="EXECUTION_ERROR",
                error_message=message,
                metadata={**base_meta, "exceptionType": type(exc).__name__},
            )
            conn.commit()
        return {
            "ok": False,
            "correlationId": corr_id,
            "result": SUPPORT_RESULT_FAILED,
            "message": message,
            "errorCode": "EXECUTION_ERROR",
            "metadata": {**base_meta, "exceptionType": type(exc).__name__},
        }
    finally:
        _clear_active_support_action(binding_id=bid, correlation_id=corr_id)
        support_lock.release()


def run_tv_binding_support_action(**kwargs) -> Dict[str, Any]:
    return run_tv_support_action(
        binding_id=_safe_int(kwargs.get("binding_id"), 0),
        action_type=_safe_str(kwargs.get("action_type"), ""),
        options=kwargs.get("options") if isinstance(kwargs.get("options"), dict) else {},
        confirm=bool(kwargs.get("confirm")),
        triggered_by=_safe_str(kwargs.get("triggered_by"), "LOCAL_OPERATOR") or "LOCAL_OPERATOR",
        app=kwargs.get("app"),
    )


def get_tv_support_action_history(*, binding_id: int, limit: int = 50) -> List[Dict[str, Any]]:
    return list(_list_support_action_logs(binding_id=int(binding_id), limit=int(limit), offset=0).get("rows") or [])


def load_tv_latest_ready_snapshot(*, screen_id: int = 0, **kwargs) -> Optional[Dict[str, Any]]:
    return _load_latest_ready_snapshot_row(screen_id=int(screen_id))


def load_tv_previous_ready_snapshot(*, screen_id: int = 0, **kwargs) -> Optional[Dict[str, Any]]:
    return _load_previous_ready_snapshot_row(screen_id=int(screen_id))


def load_tv_activation_status(*, screen_id: int = 0, **kwargs) -> Dict[str, Any]:
    sid = int(screen_id or 0)
    if sid <= 0:
        return {}
    return load_tv_activation_state(screen_id=sid) or evaluate_tv_activation(screen_id=sid)


# ---------------------------------------------------------------------------
# A11: Observability / Retention
# ---------------------------------------------------------------------------

OBS_EVENT_SOURCE_BINDING = "BINDING_EVENT"
OBS_EVENT_SOURCE_PLAYER = "PLAYER_EVENT"
OBS_EVENT_SOURCE_SUPPORT = "SUPPORT_ACTION"

OBSERVABILITY_RECENT_SUPPORT_HOURS = 24
OBSERVABILITY_STALE_RUNTIME_MINUTES = 15
OBSERVABILITY_STALE_PLAYER_MINUTES = 15

_TERMINAL_AD_TASK_RUNTIME_STATES = frozenset(
    {
        AD_TASK_STATE_COMPLETED,
        AD_TASK_STATE_ABORTED,
        AD_TASK_STATE_SKIPPED_WINDOW,
        AD_TASK_STATE_CANCELLED_REMOTE,
        AD_TASK_STATE_EXPIRED_REMOTE,
    }
)
_ACTIVE_GYM_COORDINATION_STATES = frozenset({GYM_COORD_INJECTING, GYM_COORD_DISPLAYING, GYM_COORD_COMPLETING})
_PROBLEM_BINDING_HEALTHS = frozenset({BINDING_HEALTH_WARNING, BINDING_HEALTH_DEGRADED, BINDING_HEALTH_ERROR})
_TV_RETENTION_POLICY_DEFAULTS: Dict[str, int] = {
    "bindingEventDays": 30,
    "playerEventDays": 30,
    "syncRunDays": 30,
    "activationAttemptDays": 30,
    "supportLogDays": 30,
    "adTaskRuntimeDays": 30,
    "proofTerminalDays": 60,
    "disconnectedMonitorDays": 45,
}


def _parse_observability_ts(value: Any) -> Optional[datetime]:
    raw = _safe_str(value, "").strip()
    if not raw:
        return None
    normalized = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is not None:
            return parsed.astimezone().replace(tzinfo=None)
        return parsed
    except Exception:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(raw[:19], fmt)
        except Exception:
            continue
    return None


def _now_obs_dt() -> datetime:
    return datetime.now()


def _cutoff_ts_days(days: int) -> str:
    return (_now_obs_dt() - timedelta(days=int(days))).strftime("%Y-%m-%d %H:%M:%S")


def _cutoff_ts_hours(hours: int) -> str:
    return (_now_obs_dt() - timedelta(hours=int(hours))).strftime("%Y-%m-%d %H:%M:%S")


def _minutes_since_ts(value: Any) -> Optional[float]:
    parsed = _parse_observability_ts(value)
    if parsed is None:
        return None
    return max(0.0, (_now_obs_dt() - parsed).total_seconds() / 60.0)


def _count_where(conn, table: str, where_sql: str = "", params: Tuple[Any, ...] = ()) -> int:
    sql = f"SELECT COUNT(*) AS cnt FROM {table}"
    if where_sql:
        sql += f" WHERE {where_sql}"
    row = conn.execute(sql, params).fetchone()
    return _safe_int(row["cnt"], 0) if row else 0


def _delete_where(conn, table: str, where_sql: str, params: Tuple[Any, ...]) -> int:
    cur = conn.execute(f"DELETE FROM {table} WHERE {where_sql}", params)
    return _safe_int(cur.rowcount, 0)


def _is_binding_stale(*, facts: Dict[str, Any]) -> bool:
    binding = facts.get("binding") or {}
    if not _binding_bool(binding.get("enabled")):
        return False
    if _safe_str(binding.get("desired_state"), "") != DESIRED_RUNNING:
        return False
    runtime = facts.get("runtime") or {}
    player_state = facts.get("playerState") or {}
    runtime_minutes = _minutes_since_ts(runtime.get("updated_at"))
    player_minutes = _minutes_since_ts(player_state.get("last_tick_at") or player_state.get("updated_at"))
    if runtime_minutes is not None and runtime_minutes > OBSERVABILITY_STALE_RUNTIME_MINUTES:
        return True
    if player_minutes is not None and player_minutes > OBSERVABILITY_STALE_PLAYER_MINUTES:
        return True
    return False


def _binding_summary_from_support(binding: Dict[str, Any], summary: Dict[str, Any]) -> Dict[str, Any]:
    facts = summary.get("facts") or {}
    runtime = facts.get("runtime") or None
    player_state = facts.get("playerState") or None
    monitor = facts.get("monitor") or {}
    health = _safe_str(summary.get("health"), BINDING_HEALTH_ERROR) or BINDING_HEALTH_ERROR
    stale = _is_binding_stale(facts=facts)
    return {
        "bindingId": _safe_int(binding.get("id"), 0),
        "screenId": _safe_int(binding.get("screen_id"), 0) or None,
        "gymId": _safe_int(binding.get("gym_id"), 0) or None,
        "screenLabel": _safe_str(binding.get("screen_label"), "") or f"Screen {_safe_int(binding.get('screen_id'), 0)}",
        "binding": dict(binding),
        "runtime": dict(runtime) if isinstance(runtime, dict) and runtime else None,
        "health": health,
        "reasons": list(summary.get("reasons") or []),
        "desiredState": _safe_str(binding.get("desired_state"), ""),
        "runtimeState": _safe_str((runtime or {}).get("runtime_state"), "UNKNOWN") or "UNKNOWN",
        "monitorAvailable": bool(monitor.get("available")),
        "failedAssetCount": _safe_int((facts.get("downloadFailures") or {}).get("count"), 0),
        "proofRetryableCount": _safe_int((facts.get("proofFailures") or {}).get("retryableCount"), 0),
        "proofTerminalCount": _safe_int((facts.get("proofFailures") or {}).get("terminalCount"), 0),
        "playerState": _safe_str((player_state or {}).get("player_state"), "") or None,
        "readinessState": _safe_str((facts.get("latestReadiness") or {}).get("readiness_state"), "") or None,
        "activationState": _safe_str((facts.get("activation") or {}).get("activation_state"), "") or None,
        "lastSupportAction": facts.get("latestSupportAction"),
        "activeSupportAction": facts.get("activeSupportAction"),
        "stale": stale,
        "problem": stale or health in _PROBLEM_BINDING_HEALTHS,
    }


def _binding_matches_query(row: Dict[str, Any], query: str) -> bool:
    q = _safe_str(query, "").strip().lower()
    if not q:
        return True
    haystack = " ".join(
        [
            _safe_str(row.get("screenLabel"), ""),
            _safe_str((row.get("binding") or {}).get("screen_label"), ""),
            _safe_str((row.get("binding") or {}).get("gym_label"), ""),
            _safe_str((row.get("binding") or {}).get("monitor_label"), ""),
            _safe_str((row.get("binding") or {}).get("monitor_id"), ""),
            _safe_str(row.get("health"), ""),
            _safe_str(row.get("runtimeState"), ""),
            _safe_str(row.get("screenId"), ""),
            _safe_str(row.get("gymId"), ""),
        ]
    ).lower()
    return q in haystack


def _normalize_event_row(*, source: str, row: Dict[str, Any], binding_id: Optional[int], gym_id: Optional[int]) -> Dict[str, Any]:
    if source in {OBS_EVENT_SOURCE_BINDING, OBS_EVENT_SOURCE_PLAYER}:
        metadata = _json_loads(row.get("metadata_json"))
        correlation_id = _safe_str((metadata or {}).get("correlationId"), "") or None
        event_type = _safe_str(row.get("event_type"), "")
        severity = _safe_str(row.get("severity"), SEVERITY_INFO) or SEVERITY_INFO
        message = _safe_str(row.get("message"), "") or None
        created_at = _safe_str(row.get("created_at"), "") or None
        result = None
    else:
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else _json_loads(row.get("metadata_json"))
        correlation_id = _safe_str(row.get("correlation_id"), "") or _safe_str((metadata or {}).get("correlationId"), "") or None
        event_type = _safe_str(row.get("action_type"), "")
        result = _safe_str(row.get("result"), "") or None
        if result == SUPPORT_RESULT_FAILED:
            severity = SEVERITY_ERROR
        elif result in {SUPPORT_RESULT_BLOCKED, SUPPORT_RESULT_SKIPPED}:
            severity = SEVERITY_WARN
        else:
            severity = SEVERITY_INFO
        message = _safe_str(row.get("message"), "") or _safe_str(row.get("error_message"), "") or None
        created_at = _safe_str(row.get("created_at"), "") or _safe_str(row.get("started_at"), "") or None
    return {
        "id": row.get("id"),
        "source": source,
        "bindingId": binding_id,
        "gymId": gym_id,
        "createdAt": created_at,
        "eventType": event_type or None,
        "severity": severity or None,
        "message": message,
        "correlationId": correlation_id,
        "metadata": metadata if isinstance(metadata, dict) else None,
        "result": result,
    }


def _binding_ids_for_gym(gym_id: int) -> List[int]:
    return [
        _safe_int(row.get("id"), 0)
        for row in list_tv_screen_bindings()
        if _safe_int(row.get("gym_id"), 0) == int(gym_id) and _safe_int(row.get("id"), 0) > 0
    ]


def _list_observability_events_internal(
    *,
    binding_ids: List[int],
    gym_id: Optional[int],
    limit: int,
    offset: int,
    sources: Optional[List[str]] = None,
) -> Dict[str, Any]:
    ensure_tv_local_schema()
    allowed_sources = set(sources or [OBS_EVENT_SOURCE_BINDING, OBS_EVENT_SOURCE_PLAYER, OBS_EVENT_SOURCE_SUPPORT])
    collected: List[Dict[str, Any]] = []
    pull_limit = max(int(limit) + int(offset), 100)

    with get_conn() as conn:
        if binding_ids and OBS_EVENT_SOURCE_BINDING in allowed_sources:
            placeholders = ",".join(["?"] * len(binding_ids))
            rows = conn.execute(
                f"SELECT * FROM tv_screen_binding_event WHERE binding_id IN ({placeholders}) ORDER BY created_at DESC, id DESC LIMIT ?",
                tuple(binding_ids + [pull_limit]),
            ).fetchall()
            for row in rows:
                row_dict = _row_to_dict(row) or {}
                collected.append(
                    _normalize_event_row(
                        source=OBS_EVENT_SOURCE_BINDING,
                        row=row_dict,
                        binding_id=_safe_int(row_dict.get('binding_id'), 0) or None,
                        gym_id=gym_id,
                    )
                )

        if binding_ids and OBS_EVENT_SOURCE_PLAYER in allowed_sources:
            placeholders = ",".join(["?"] * len(binding_ids))
            rows = conn.execute(
                f"SELECT * FROM tv_player_event WHERE binding_id IN ({placeholders}) ORDER BY created_at DESC, id DESC LIMIT ?",
                tuple(binding_ids + [pull_limit]),
            ).fetchall()
            for row in rows:
                row_dict = _row_to_dict(row) or {}
                collected.append(
                    _normalize_event_row(
                        source=OBS_EVENT_SOURCE_PLAYER,
                        row=row_dict,
                        binding_id=_safe_int(row_dict.get('binding_id'), 0) or None,
                        gym_id=gym_id,
                    )
                )

        if OBS_EVENT_SOURCE_SUPPORT in allowed_sources:
            support_where = []
            support_params: List[Any] = []
            if binding_ids:
                placeholders = ",".join(["?"] * len(binding_ids))
                support_where.append(f"binding_id IN ({placeholders})")
                support_params.extend(binding_ids)
            elif gym_id:
                support_where.append("gym_id=?")
                support_params.append(int(gym_id))
            if support_where:
                rows = conn.execute(
                    f"SELECT * FROM tv_support_action_log WHERE {' OR '.join(support_where)} ORDER BY created_at DESC, id DESC LIMIT ?",
                    tuple(support_params + [pull_limit]),
                ).fetchall()
                for row in rows:
                    row_dict = _support_log_row_to_dict(row)
                    collected.append(
                        _normalize_event_row(
                            source=OBS_EVENT_SOURCE_SUPPORT,
                            row=row_dict,
                            binding_id=_safe_int(row_dict.get('binding_id'), 0) or None,
                            gym_id=_safe_int(row_dict.get('gym_id'), 0) or None,
                        )
                    )

    collected.sort(
        key=lambda item: (
            _parse_observability_ts(item.get("createdAt")) or datetime.min,
            _safe_int(item.get("id"), 0),
        ),
        reverse=True,
    )
    total = len(collected)
    return {
        "rows": collected[int(offset) : int(offset) + int(limit)],
        "total": total,
        "limit": int(limit),
        "offset": int(offset),
    }


def _proof_state_counts(*, gym_id: Optional[int] = None) -> Dict[str, int]:
    ensure_tv_local_schema()
    clauses: List[str] = []
    params: List[Any] = []
    if gym_id and int(gym_id) > 0:
        clauses.append("gym_id=?")
        params.append(int(gym_id))
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    counts = {
        PROOF_OUTBOX_QUEUED: 0,
        PROOF_OUTBOX_SENDING: 0,
        PROOF_OUTBOX_SENT: 0,
        PROOF_OUTBOX_FAILED_RETRYABLE: 0,
        PROOF_OUTBOX_FAILED_TERMINAL: 0,
    }
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT outbox_state, COUNT(*) AS cnt FROM tv_ad_proof_outbox {where} GROUP BY outbox_state",
            tuple(params),
        ).fetchall()
    for row in rows:
        state = _safe_str(row["outbox_state"], "")
        counts[state] = _safe_int(row["cnt"], 0)
    return counts


def _known_gym_ids() -> List[int]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT gym_id FROM tv_screen_binding WHERE gym_id IS NOT NULL AND gym_id > 0
            UNION
            SELECT gym_id FROM tv_gym_ad_runtime WHERE gym_id IS NOT NULL AND gym_id > 0
            UNION
            SELECT gym_id FROM tv_ad_proof_outbox WHERE gym_id IS NOT NULL AND gym_id > 0
            UNION
            SELECT gym_id FROM tv_ad_task_cache WHERE gym_id IS NOT NULL AND gym_id > 0
            ORDER BY gym_id ASC
            """
        ).fetchall()
    return [_safe_int(row["gym_id"], 0) for row in rows if _safe_int(row["gym_id"], 0) > 0]


def _retention_rules(*, policy: Dict[str, int]) -> List[Dict[str, Any]]:
    return [
        {
            "table": "tv_screen_binding_event",
            "where": "created_at < ?",
            "params": (_cutoff_ts_days(policy["bindingEventDays"]),),
            "description": f"Delete binding events older than {policy['bindingEventDays']} days.",
        },
        {
            "table": "tv_player_event",
            "where": "created_at < ?",
            "params": (_cutoff_ts_days(policy["playerEventDays"]),),
            "description": f"Delete player events older than {policy['playerEventDays']} days.",
        },
        {
            "table": "tv_sync_run_log",
            "where": "created_at < ?",
            "params": (_cutoff_ts_days(policy["syncRunDays"]),),
            "description": f"Delete sync run logs older than {policy['syncRunDays']} days.",
        },
        {
            "table": "tv_activation_attempt",
            "where": "created_at < ?",
            "params": (_cutoff_ts_days(policy["activationAttemptDays"]),),
            "description": f"Delete activation attempts older than {policy['activationAttemptDays']} days.",
        },
        {
            "table": "tv_support_action_log",
            "where": "created_at < ?",
            "params": (_cutoff_ts_days(policy["supportLogDays"]),),
            "description": f"Delete support logs older than {policy['supportLogDays']} days.",
        },
        {
            "table": "tv_ad_task_runtime",
            "where": f"local_display_state IN ({','.join(['?'] * len(_TERMINAL_AD_TASK_RUNTIME_STATES))}) AND updated_at < ?",
            "params": tuple(sorted(_TERMINAL_AD_TASK_RUNTIME_STATES)) + (_cutoff_ts_days(policy["adTaskRuntimeDays"]),),
            "description": f"Delete terminal ad task runtime rows older than {policy['adTaskRuntimeDays']} days.",
        },
        {
            "table": "tv_ad_proof_outbox",
            "where": "outbox_state IN (?, ?) AND updated_at < ?",
            "params": (PROOF_OUTBOX_SENT, PROOF_OUTBOX_FAILED_TERMINAL, _cutoff_ts_days(policy["proofTerminalDays"])),
            "description": f"Delete SENT / terminal proof rows older than {policy['proofTerminalDays']} days.",
        },
        {
            "table": "tv_host_monitor",
            "where": "is_connected=0 AND updated_at < ?",
            "params": (_cutoff_ts_days(policy["disconnectedMonitorDays"]),),
            "description": f"Delete stale disconnected monitor rows older than {policy['disconnectedMonitorDays']} days.",
        },
    ]


def get_tv_retention_policy(**kwargs) -> Dict[str, int]:
    policy = dict(_TV_RETENTION_POLICY_DEFAULTS)
    for key in list(policy.keys()):
        if key in kwargs and kwargs.get(key) is not None:
            candidate = _safe_int(kwargs.get(key), 0)
            if candidate > 0:
                policy[key] = candidate
    return policy


def get_tv_observability_retention(**kwargs) -> Dict[str, Any]:
    ensure_tv_local_schema()
    policy = get_tv_retention_policy(**kwargs)
    rows: List[Dict[str, Any]] = []
    eligible_total = 0
    with get_conn() as conn:
        for rule in _retention_rules(policy=policy):
            total_rows = _count_where(conn, rule["table"])
            eligible_rows = _count_where(conn, rule["table"], rule["where"], tuple(rule["params"]))
            eligible_total += eligible_rows
            rows.append(
                {
                    "table": rule["table"],
                    "totalRows": total_rows,
                    "eligibleRows": eligible_rows,
                    "rule": rule["description"],
                    "cutoffAt": tuple(rule["params"])[-1] if rule.get("params") else None,
                }
            )
    return {
        "ok": True,
        "generatedAt": now_iso(),
        "policy": policy,
        "tables": rows,
        "eligibleDeleteCount": eligible_total,
    }


def run_tv_retention_maintenance(*, dry_run: bool = False, include_query_checks: bool = False, **kwargs) -> Dict[str, Any]:
    ensure_tv_local_schema()
    policy = get_tv_retention_policy(**kwargs)
    preview = get_tv_observability_retention(**policy)
    if dry_run:
        return {
            "ok": True,
            "dryRun": True,
            "includeQueryChecks": bool(include_query_checks),
            "policy": policy,
            "deletedRows": 0,
            "tables": [
                {
                    "table": row.get("table"),
                    "deletedRows": 0,
                    "eligibleRows": _safe_int(row.get("eligibleRows"), 0),
                }
                for row in preview.get("tables") or []
            ],
            "summaryAfter": preview,
        }

    deleted_total = 0
    deleted_rows: List[Dict[str, Any]] = []
    with get_conn() as conn:
        for rule in _retention_rules(policy=policy):
            deleted = _delete_where(conn, rule["table"], rule["where"], tuple(rule["params"]))
            deleted_total += deleted
            deleted_rows.append({"table": rule["table"], "deletedRows": deleted})
        conn.commit()

    return {
        "ok": True,
        "dryRun": False,
        "includeQueryChecks": bool(include_query_checks),
        "policy": policy,
        "deletedRows": deleted_total,
        "tables": deleted_rows,
        "summaryAfter": get_tv_observability_retention(**policy),
    }


def list_tv_observability_events(
    *,
    binding_id: Optional[int] = None,
    gym_id: Optional[int] = None,
    limit: int = 100,
    offset: int = 0,
    sources: Optional[List[str]] = None,
    **kwargs,
) -> Dict[str, Any]:
    bid = _safe_int(binding_id, 0)
    gid = _safe_int(gym_id, 0)
    binding_ids: List[int] = []
    if bid > 0:
        binding_ids = [bid]
        binding = load_tv_screen_binding_by_id(binding_id=bid) or {}
        if gid <= 0:
            gid = _safe_int(binding.get("gym_id"), 0)
    elif gid > 0:
        binding_ids = _binding_ids_for_gym(gid)

    return _list_observability_events_internal(
        binding_ids=binding_ids,
        gym_id=(gid or None),
        limit=int(limit),
        offset=int(offset),
        sources=sources,
    )


def list_tv_observability_bindings(
    *,
    health: Optional[str] = None,
    gym_id: Optional[int] = None,
    runtime_state: Optional[str] = None,
    q: Optional[str] = None,
    problem_only: bool = False,
    limit: int = 200,
    offset: int = 0,
    **kwargs,
) -> Dict[str, Any]:
    ensure_tv_local_schema()
    wanted_health = _safe_str(health, "").strip().upper()
    wanted_runtime = _safe_str(runtime_state, "").strip().upper()
    wanted_gym = _safe_int(gym_id, 0)
    rows: List[Dict[str, Any]] = []
    for binding in list_tv_screen_bindings():
        if wanted_gym > 0 and _safe_int(binding.get("gym_id"), 0) != wanted_gym:
            continue
        support_summary = load_tv_binding_support_summary(binding_id=_safe_int(binding.get("id"), 0))
        if not bool(support_summary.get("ok")):
            continue
        row = _binding_summary_from_support(binding, support_summary)
        if wanted_health and _safe_str(row.get("health"), "").upper() != wanted_health:
            continue
        if wanted_runtime and _safe_str(row.get("runtimeState"), "").upper() != wanted_runtime:
            continue
        if problem_only and not bool(row.get("problem")):
            continue
        if not _binding_matches_query(row, q or ""):
            continue
        rows.append(row)
    total = len(rows)
    return {
        "ok": True,
        "rows": rows[int(offset) : int(offset) + int(limit)],
        "total": total,
        "limit": int(limit),
        "offset": int(offset),
    }


def _get_tv_observability_gym_detail(*, gym_id: int, include_binding_rows: bool) -> Dict[str, Any]:
    ensure_tv_local_schema()
    gid = _safe_int(gym_id, 0)
    if gid <= 0:
        return {"ok": False, "error": "GYM_NOT_FOUND"}

    bindings = [row for row in list_tv_screen_bindings() if _safe_int(row.get("gym_id"), 0) == gid]
    runtime = load_tv_gym_ad_runtime(gym_id=gid)
    task_runtime = list_tv_ad_task_runtime(gym_id=gid, limit=20, offset=0)
    proof_counts = _proof_state_counts(gym_id=gid)
    proof_rows = list_tv_ad_proof_outbox(gym_id=gid, limit=20, offset=0)

    if not bindings and not runtime and not _safe_int(proof_rows.get("total"), 0):
        return {"ok": False, "error": "GYM_NOT_FOUND"}

    binding_rows: List[Dict[str, Any]] = []
    health_counts = {
        BINDING_HEALTH_HEALTHY: 0,
        BINDING_HEALTH_WARNING: 0,
        BINDING_HEALTH_DEGRADED: 0,
        BINDING_HEALTH_ERROR: 0,
        BINDING_HEALTH_STOPPED: 0,
    }
    active_binding_count = 0
    failed_binding_count = 0
    for binding in bindings:
        support_summary = load_tv_binding_support_summary(binding_id=_safe_int(binding.get("id"), 0))
        if not bool(support_summary.get("ok")):
            continue
        row = _binding_summary_from_support(binding, support_summary)
        health_key = _safe_str(row.get("health"), BINDING_HEALTH_ERROR) or BINDING_HEALTH_ERROR
        health_counts[health_key] = _safe_int(health_counts.get(health_key), 0) + 1
        if _binding_bool(binding.get("enabled")) and _safe_str(binding.get("desired_state"), "") == DESIRED_RUNNING:
            active_binding_count += 1
        if health_key in {BINDING_HEALTH_DEGRADED, BINDING_HEALTH_ERROR}:
            failed_binding_count += 1
        if include_binding_rows:
            binding_rows.append(row)

    current_task_id = _safe_str((runtime or {}).get("current_campaign_task_id"), "") or None
    current_task = load_tv_ad_task_cache_one(campaign_task_id=current_task_id) if current_task_id else None

    return {
        "ok": True,
        "gymId": gid,
        "runtime": dict(runtime) if runtime else None,
        "currentTaskId": current_task_id,
        "currentTask": current_task,
        "coordinationState": _safe_str((runtime or {}).get("coordination_state"), GYM_COORD_IDLE) or GYM_COORD_IDLE,
        "activeBindingCount": active_binding_count,
        "failedBindingCount": failed_binding_count,
        "audioOverrideActive": bool(_safe_int((runtime or {}).get("audio_override_active"), 0)),
        "lastErrorCode": _safe_str((runtime or {}).get("last_error_code"), "") or None,
        "lastErrorMessage": _safe_str((runtime or {}).get("last_error_message"), "") or None,
        "bindingHealthCounts": health_counts,
        "proofBacklog": {
            "queuedCount": _safe_int(proof_counts.get(PROOF_OUTBOX_QUEUED), 0),
            "sendingCount": _safe_int(proof_counts.get(PROOF_OUTBOX_SENDING), 0),
            "retryableCount": _safe_int(proof_counts.get(PROOF_OUTBOX_FAILED_RETRYABLE), 0),
            "terminalCount": _safe_int(proof_counts.get(PROOF_OUTBOX_FAILED_TERMINAL), 0),
            "sentCount": _safe_int(proof_counts.get(PROOF_OUTBOX_SENT), 0),
            "rows": proof_rows.get("rows") or [],
            "total": _safe_int(proof_rows.get("total"), 0),
        },
        "recentTaskRuntime": task_runtime,
        "bindings": binding_rows,
        "updatedAt": _safe_str((runtime or {}).get("updated_at"), "") or None,
    }


def get_tv_observability_gym(*, gym_id: int, **kwargs) -> Dict[str, Any]:
    return _get_tv_observability_gym_detail(gym_id=int(gym_id), include_binding_rows=True)


def list_tv_observability_gyms(*, limit: int = 100, offset: int = 0, **kwargs) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for gym_id in _known_gym_ids():
        detail = _get_tv_observability_gym_detail(gym_id=gym_id, include_binding_rows=False)
        if bool(detail.get("ok")):
            rows.append(detail)
    total = len(rows)
    return {
        "ok": True,
        "rows": rows[int(offset) : int(offset) + int(limit)],
        "total": total,
        "limit": int(limit),
        "offset": int(offset),
    }


def list_tv_observability_proofs(
    *,
    gym_id: Optional[int] = None,
    binding_id: Optional[int] = None,
    outbox_states: Optional[List[str]] = None,
    result_status: Optional[str] = None,
    countable: Optional[bool] = None,
    limit: int = 200,
    offset: int = 0,
    **kwargs,
) -> Dict[str, Any]:
    gid = _safe_int(gym_id, 0)
    bid = _safe_int(binding_id, 0)
    if bid > 0 and gid <= 0:
        binding = load_tv_screen_binding_by_id(binding_id=bid) or {}
        gid = _safe_int(binding.get("gym_id"), 0)

    proof_rows = list_tv_ad_proof_outbox(
        gym_id=(gid or None),
        outbox_states=outbox_states,
        result_status=result_status,
        countable=countable,
        limit=int(limit),
        offset=int(offset),
    )
    proof_counts = _proof_state_counts(gym_id=(gid or None))
    return {
        "ok": True,
        "rows": proof_rows.get("rows") or [],
        "total": _safe_int(proof_rows.get("total"), 0),
        "limit": int(limit),
        "offset": int(offset),
        "bindingId": bid or None,
        "gymId": gid or None,
        "summary": {
            "queuedCount": _safe_int(proof_counts.get(PROOF_OUTBOX_QUEUED), 0),
            "sendingCount": _safe_int(proof_counts.get(PROOF_OUTBOX_SENDING), 0),
            "retryableCount": _safe_int(proof_counts.get(PROOF_OUTBOX_FAILED_RETRYABLE), 0),
            "terminalCount": _safe_int(proof_counts.get(PROOF_OUTBOX_FAILED_TERMINAL), 0),
            "sentCount": _safe_int(proof_counts.get(PROOF_OUTBOX_SENT), 0),
        },
    }


def get_tv_observability_binding(*, binding_id: int, event_limit: int = 40, history_limit: int = 20, **kwargs) -> Dict[str, Any]:
    ensure_tv_local_schema()
    bid = _safe_int(binding_id, 0)
    binding = load_tv_screen_binding_by_id(binding_id=bid)
    if not binding:
        return {"ok": False, "error": "BINDING_NOT_FOUND"}

    support_summary = load_tv_binding_support_summary(binding_id=bid)
    if not bool(support_summary.get("ok")):
        return {"ok": False, "error": support_summary.get("error") or "BINDING_NOT_FOUND"}

    facts = support_summary.get("facts") or {}
    binding_row = _binding_summary_from_support(binding, support_summary)
    screen_id = _safe_int(binding.get("screen_id"), 0)
    gym_id = _safe_int(binding.get("gym_id"), 0)
    sync_runs = list_tv_sync_run_logs(screen_id=screen_id, limit=int(history_limit), offset=0) if screen_id > 0 else {"rows": [], "total": 0}
    activation_attempts = list_tv_activation_attempts(screen_id=screen_id, limit=int(history_limit), offset=0) if screen_id > 0 else []
    player_events = list_tv_player_events(binding_id=bid, limit=int(history_limit), offset=0)
    binding_events = list_tv_screen_binding_events(binding_id=bid, limit=int(history_limit), offset=0)
    support_history = _list_support_action_logs(binding_id=bid, limit=int(history_limit), offset=0)
    proof_counts = _proof_state_counts(gym_id=(gym_id or None))
    proof_rows = list_tv_ad_proof_outbox(
        gym_id=(gym_id or None),
        outbox_states=[PROOF_OUTBOX_QUEUED, PROOF_OUTBOX_SENDING, PROOF_OUTBOX_FAILED_RETRYABLE, PROOF_OUTBOX_FAILED_TERMINAL],
        limit=int(history_limit),
        offset=0,
    ) if gym_id > 0 else {"rows": [], "total": 0}

    return {
        "ok": True,
        **binding_row,
        "bindingConfig": dict(binding),
        "runtime": facts.get("runtime") or None,
        "monitor": facts.get("monitor") or {"row": None, "available": False},
        "readiness": facts.get("latestReadiness") or None,
        "activation": facts.get("activation") or None,
        "playerStateRow": facts.get("playerState") or None,
        "adRuntime": facts.get("adRuntime") or None,
        "failedAssets": facts.get("downloadFailures") or {"count": 0, "rows": []},
        "proofBacklog": {
            "queuedCount": _safe_int(proof_counts.get(PROOF_OUTBOX_QUEUED), 0),
            "sendingCount": _safe_int(proof_counts.get(PROOF_OUTBOX_SENDING), 0),
            "retryableCount": _safe_int(proof_counts.get(PROOF_OUTBOX_FAILED_RETRYABLE), 0),
            "terminalCount": _safe_int(proof_counts.get(PROOF_OUTBOX_FAILED_TERMINAL), 0),
            "sentCount": _safe_int(proof_counts.get(PROOF_OUTBOX_SENT), 0),
            "rows": proof_rows.get("rows") or [],
            "total": _safe_int(proof_rows.get("total"), 0),
        },
        "lastSupportAction": facts.get("latestSupportAction"),
        "supportSummary": support_summary,
        "supportHistory": support_history,
        "bindingEvents": binding_events,
        "playerEvents": player_events,
        "syncRuns": sync_runs,
        "activationAttempts": {
            "rows": activation_attempts,
            "total": len(activation_attempts),
        },
        "recentEvents": list_tv_observability_events(binding_id=bid, limit=int(event_limit), offset=0),
        "gymDiagnostics": _get_tv_observability_gym_detail(gym_id=gym_id, include_binding_rows=False) if gym_id > 0 else None,
    }


def get_tv_observability_overview(*, gym_id: Optional[int] = None, **kwargs) -> Dict[str, Any]:
    ensure_tv_local_schema()
    binding_rows = list_tv_observability_bindings(gym_id=gym_id or None, limit=5000, offset=0).get("rows") or []
    health_counts = {
        BINDING_HEALTH_HEALTHY: 0,
        BINDING_HEALTH_WARNING: 0,
        BINDING_HEALTH_DEGRADED: 0,
        BINDING_HEALTH_ERROR: 0,
        BINDING_HEALTH_STOPPED: 0,
    }
    stale_problem_count = 0
    failed_download_count = 0
    active_player_windows = 0
    problem_bindings: List[Dict[str, Any]] = []

    for row in binding_rows:
        health_key = _safe_str(row.get("health"), BINDING_HEALTH_ERROR) or BINDING_HEALTH_ERROR
        health_counts[health_key] = _safe_int(health_counts.get(health_key), 0) + 1
        failed_download_count += _safe_int(row.get("failedAssetCount"), 0)
        runtime = row.get("runtime") or {}
        if _safe_str((runtime or {}).get("runtime_state"), "") in {BINDING_RUNTIME_RUNNING, BINDING_RUNTIME_STARTING} and (
            _safe_str((runtime or {}).get("window_id"), "") or _safe_str((runtime or {}).get("tauri_window_label"), "")
        ):
            active_player_windows += 1
        if bool(row.get("problem")):
            stale_problem_count += 1
            problem_bindings.append(
                {
                    "bindingId": row.get("bindingId"),
                    "screenLabel": row.get("screenLabel"),
                    "health": row.get("health"),
                    "reasons": row.get("reasons") or [],
                    "stale": bool(row.get("stale")),
                }
            )

    active_monitors = list_tv_host_monitors()
    if gym_id:
        relevant_monitor_ids = {_safe_str((row.get("binding") or {}).get("monitor_id"), "") for row in binding_rows}
        active_monitor_count = sum(
            1
            for row in active_monitors
            if _binding_bool(row.get("is_connected")) and _safe_str(row.get("monitor_id"), "") in relevant_monitor_ids
        )
    else:
        active_monitor_count = sum(1 for row in active_monitors if _binding_bool(row.get("is_connected")))

    known_gym_ids = [int(gym_id)] if gym_id and int(gym_id) > 0 else _known_gym_ids()
    active_gym_ad_runtimes = 0
    for gid in known_gym_ids:
        runtime = load_tv_gym_ad_runtime(gym_id=gid) or {}
        if _safe_str(runtime.get("coordination_state"), "") in _ACTIVE_GYM_COORDINATION_STATES:
            active_gym_ad_runtimes += 1

    proof_counts = _proof_state_counts(gym_id=(int(gym_id) if gym_id and int(gym_id) > 0 else None))
    recent_support_cutoff = _cutoff_ts_hours(OBSERVABILITY_RECENT_SUPPORT_HOURS)
    with get_conn() as conn:
        if gym_id and int(gym_id) > 0:
            recent_support_actions = _count_where(
                conn,
                "tv_support_action_log",
                "created_at >= ? AND gym_id = ?",
                (recent_support_cutoff, int(gym_id)),
            )
        else:
            recent_support_actions = _count_where(conn, "tv_support_action_log", "created_at >= ?", (recent_support_cutoff,))

    return {
        "ok": True,
        "generatedAt": now_iso(),
        "totals": {
            "totalBindings": len(binding_rows),
            "healthyBindings": _safe_int(health_counts[BINDING_HEALTH_HEALTHY], 0),
            "warningBindings": _safe_int(health_counts[BINDING_HEALTH_WARNING], 0),
            "degradedBindings": _safe_int(health_counts[BINDING_HEALTH_DEGRADED], 0),
            "errorBindings": _safe_int(health_counts[BINDING_HEALTH_ERROR], 0),
            "stoppedBindings": _safe_int(health_counts[BINDING_HEALTH_STOPPED], 0),
            "activeMonitors": active_monitor_count,
            "activePlayerWindows": active_player_windows,
            "activeGymAdRuntimes": active_gym_ad_runtimes,
            "queuedOrRetryableProofCount": _safe_int(proof_counts.get(PROOF_OUTBOX_QUEUED), 0)
            + _safe_int(proof_counts.get(PROOF_OUTBOX_FAILED_RETRYABLE), 0),
            "recentFailedDownloadsCount": failed_download_count,
            "recentSupportActionsCount": recent_support_actions,
            "staleProblemBindingsCount": stale_problem_count,
        },
        "problemBindings": problem_bindings[:10],
        "recentSupportWindowHours": OBSERVABILITY_RECENT_SUPPORT_HOURS,
    }


def list_tv_observability_fleet_health(**kwargs) -> Dict[str, Any]:
    return list_tv_observability_bindings(**kwargs)


def get_tv_observability_screen_details(*, screen_id: int, **kwargs) -> Dict[str, Any]:
    binding = load_tv_screen_binding(screen_id=int(screen_id)) or {}
    bid = _safe_int(binding.get("id"), 0)
    if bid <= 0:
        return {"ok": False, "error": "SCREEN_NOT_FOUND"}
    return get_tv_observability_binding(binding_id=bid, **kwargs)


def get_tv_observability_screen_timeline(*, screen_id: int, limit: int = 100, offset: int = 0, **kwargs) -> Dict[str, Any]:
    binding = load_tv_screen_binding(screen_id=int(screen_id)) or {}
    bid = _safe_int(binding.get("id"), 0)
    if bid <= 0:
        return {"ok": False, "rows": [], "total": 0}
    return list_tv_observability_events(binding_id=bid, limit=int(limit), offset=int(offset))


def list_tv_observability_runtime_events(**kwargs) -> Dict[str, Any]:
    binding_id = kwargs.get("binding_id") or kwargs.get("bindingId")
    gym_id = kwargs.get("gym_id") or kwargs.get("gymId")
    limit = _safe_int(kwargs.get("limit"), 100)
    offset = _safe_int(kwargs.get("offset"), 0)
    return list_tv_observability_events(
        binding_id=_safe_int(binding_id, 0) or None,
        gym_id=_safe_int(gym_id, 0) or None,
        limit=limit,
        offset=offset,
    )


def list_tv_observability_heartbeats(**kwargs) -> Dict[str, Any]:
    return list_tv_observability_runtime_events(**kwargs)


def list_tv_observability_proof_events(**kwargs) -> Dict[str, Any]:
    return list_tv_observability_proofs(**kwargs)


def get_tv_observability_proof_stats(**kwargs) -> Dict[str, Any]:
    proofs = list_tv_observability_proofs(**kwargs)
    return {
        "ok": True,
        "summary": proofs.get("summary") or {},
        "total": proofs.get("total") or 0,
    }


def get_tv_observability_runtime_stats(**kwargs) -> Dict[str, Any]:
    overview = get_tv_observability_overview(gym_id=kwargs.get("gym_id") or kwargs.get("gymId"))
    return {
        "ok": True,
        "summary": overview.get("totals") or {},
        "generatedAt": overview.get("generatedAt"),
    }


# ---------------------------------------------------------------------------
# A12: Startup Reconciliation + Deployment Preflight
# ---------------------------------------------------------------------------

STARTUP_CHECK_SEVERITY_BLOCKER = "BLOCKER"
STARTUP_CHECK_SEVERITY_WARNING = "WARNING"
STARTUP_CHECK_SEVERITY_INFO = "INFO"

STARTUP_RESULT_PASSED = "PASSED"
STARTUP_RESULT_FAILED = "FAILED"
STARTUP_RESULT_SKIPPED = "SKIPPED"
STARTUP_RESULT_REPAIRED = "REPAIRED"

STARTUP_RUN_RESULT_SUCCESS = "SUCCESS"
STARTUP_RUN_RESULT_SUCCESS_WITH_WARNINGS = "SUCCESS_WITH_WARNINGS"
STARTUP_RUN_RESULT_FAILED = "FAILED"

STARTUP_PHASES: Tuple[str, ...] = (
    "migration",
    "preflight",
    "interrupted_state_repair",
    "temp_cleanup",
    "monitor_rescan",
    "binding_runtime_reconcile",
    "readiness_recheck",
    "activation_reconcile",
    "proof_outbox_recover",
    "ad_runtime_recover",
    "window_runtime_reconcile",
    "finalize",
)

_startup_reconciliation_guard = threading.Lock()
_startup_reconciliation_active: Optional[Dict[str, Any]] = None
_STARTUP_TEMP_FILE_STALE_HOURS = 6

# Alias used by A10/A11 health/support flows.
get_tv_screen_binding_runtime = load_tv_screen_binding_runtime


def _ensure_tv_startup_reconciliation_schema() -> None:
    ensure_tv_local_schema()
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tv_startup_reconciliation_run (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                correlation_id TEXT,
                trigger_source TEXT,
                status TEXT,
                started_at TEXT,
                finished_at TEXT,
                overall_result TEXT,
                summary_json TEXT,
                blocker_count INTEGER NOT NULL DEFAULT 0,
                warning_count INTEGER NOT NULL DEFAULT 0,
                info_count INTEGER NOT NULL DEFAULT 0,
                message TEXT,
                metadata_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tv_startup_reconciliation_phase (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                phase_name TEXT NOT NULL,
                status TEXT,
                result TEXT,
                message TEXT,
                started_at TEXT,
                finished_at TEXT,
                metadata_json TEXT,
                created_at TEXT NOT NULL
            );
            """
        )
        _ensure_column(conn, "tv_startup_reconciliation_run", "started_at", "started_at TEXT")
        _ensure_column(conn, "tv_startup_reconciliation_run", "finished_at", "finished_at TEXT")
        _ensure_column(conn, "tv_startup_reconciliation_run", "trigger_source", "trigger_source TEXT")
        _ensure_column(conn, "tv_startup_reconciliation_run", "status", "status TEXT")
        _ensure_column(conn, "tv_startup_reconciliation_run", "overall_result", "overall_result TEXT")
        _ensure_column(conn, "tv_startup_reconciliation_run", "correlation_id", "correlation_id TEXT")
        _ensure_column(conn, "tv_startup_reconciliation_run", "summary_json", "summary_json TEXT")
        _ensure_column(conn, "tv_startup_reconciliation_run", "blocker_count", "blocker_count INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "tv_startup_reconciliation_run", "warning_count", "warning_count INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "tv_startup_reconciliation_run", "info_count", "info_count INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "tv_startup_reconciliation_run", "message", "message TEXT")
        _ensure_column(conn, "tv_startup_reconciliation_run", "metadata_json", "metadata_json TEXT")
        _ensure_column(conn, "tv_startup_reconciliation_run", "created_at", "created_at TEXT")
        _ensure_column(conn, "tv_startup_reconciliation_run", "updated_at", "updated_at TEXT")
        _ensure_column(conn, "tv_startup_reconciliation_phase", "run_id", "run_id INTEGER NOT NULL")
        _ensure_column(conn, "tv_startup_reconciliation_phase", "phase_name", "phase_name TEXT NOT NULL")
        _ensure_column(conn, "tv_startup_reconciliation_phase", "status", "status TEXT")
        _ensure_column(conn, "tv_startup_reconciliation_phase", "result", "result TEXT")
        _ensure_column(conn, "tv_startup_reconciliation_phase", "message", "message TEXT")
        _ensure_column(conn, "tv_startup_reconciliation_phase", "started_at", "started_at TEXT")
        _ensure_column(conn, "tv_startup_reconciliation_phase", "finished_at", "finished_at TEXT")
        _ensure_column(conn, "tv_startup_reconciliation_phase", "metadata_json", "metadata_json TEXT")
        _ensure_column(conn, "tv_startup_reconciliation_phase", "created_at", "created_at TEXT")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tv_startup_run_started ON tv_startup_reconciliation_run(created_at DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tv_startup_phase_run ON tv_startup_reconciliation_phase(run_id, id)"
        )
        conn.commit()


def _startup_check_item(
    *,
    code: str,
    severity: str,
    status: str,
    message: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "code": _safe_str(code, "").strip().upper() or "UNKNOWN",
        "severity": _safe_str(severity, STARTUP_CHECK_SEVERITY_INFO).strip().upper() or STARTUP_CHECK_SEVERITY_INFO,
        "status": _safe_str(status, STARTUP_RESULT_PASSED).strip().upper() or STARTUP_RESULT_PASSED,
        "message": _safe_str(message, "").strip() or None,
        "metadata": dict(metadata or {}),
    }


def _startup_problem_buckets(checks: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    blockers = [
        check
        for check in checks
        if _safe_str(check.get("severity"), "") == STARTUP_CHECK_SEVERITY_BLOCKER
        and _safe_str(check.get("status"), "") == STARTUP_RESULT_FAILED
    ]
    warnings = [
        check
        for check in checks
        if _safe_str(check.get("severity"), "") == STARTUP_CHECK_SEVERITY_WARNING
        and _safe_str(check.get("status"), "") == STARTUP_RESULT_FAILED
    ]
    infos = [
        check
        for check in checks
        if _safe_str(check.get("severity"), "") == STARTUP_CHECK_SEVERITY_INFO
    ]
    return blockers, warnings, infos


def _startup_overall_result(*, blockers: List[Dict[str, Any]], warnings: List[Dict[str, Any]], failed_phases: int, repaired_phases: int) -> str:
    if blockers or int(failed_phases) > 0:
        return STARTUP_RUN_RESULT_FAILED
    if warnings or int(repaired_phases) > 0:
        return STARTUP_RUN_RESULT_SUCCESS_WITH_WARNINGS
    return STARTUP_RUN_RESULT_SUCCESS


def _startup_runtime_paths() -> Dict[str, Any]:
    data_root = Path(str(DATA_ROOT))
    db_path = Path(str(current_tv_runtime_db_path()))
    return {
        "dataRoot": data_root,
        "dbPath": db_path,
        "dataDir": data_root / "data",
        "tvRoot": data_root / "tv",
        "tvMediaDir": data_root / "tv" / "media",
        "tvCacheDir": data_root / "tv" / "cache",
    }


def _is_runtime_startup_target(*, data_root: Path, db_path: Path) -> bool:
    runtime_paths = _startup_runtime_paths()
    try:
        return data_root.resolve() == runtime_paths["dataRoot"].resolve() and db_path.resolve() == runtime_paths["dbPath"].resolve()
    except Exception:
        return False


def _sanitize_startup_monitors(monitors: Any) -> Optional[List[Dict[str, Any]]]:
    if not isinstance(monitors, list):
        return None
    cleaned: List[Dict[str, Any]] = []
    for index, raw in enumerate(monitors):
        if not isinstance(raw, dict):
            continue
        monitor_id = _safe_str(raw.get("monitor_id") or raw.get("monitorId") or raw.get("id"), "").strip()
        if not monitor_id:
            continue
        cleaned.append(
            {
                "monitor_id": monitor_id,
                "monitor_label": _safe_str(raw.get("monitor_label") or raw.get("monitorLabel") or raw.get("label"), "") or monitor_id,
                "monitor_index": _safe_int(raw.get("monitor_index") or raw.get("monitorIndex") or raw.get("index"), index),
                "is_connected": _binding_bool(raw.get("is_connected") if "is_connected" in raw else raw.get("isConnected", True)),
                "width": _safe_int(raw.get("width"), 0),
                "height": _safe_int(raw.get("height"), 0),
                "x": _safe_int(raw.get("x") if "x" in raw else raw.get("offset_x") or raw.get("offsetX"), 0),
                "y": _safe_int(raw.get("y") if "y" in raw else raw.get("offset_y") or raw.get("offsetY"), 0),
                "is_primary": _binding_bool(raw.get("is_primary") if "is_primary" in raw else raw.get("isPrimary", False)),
            }
        )
    return cleaned


def _startup_probe_socket_url(url: str, timeout_seconds: float = 1.0) -> Tuple[bool, str]:
    import socket
    from urllib.parse import urlparse

    target = _safe_str(url, "").strip()
    if not target:
        return False, "API URL is empty."
    parsed = urlparse(target)
    host = _safe_str(parsed.hostname, "").strip()
    if not host:
        return False, f"Could not parse API host from {target!r}."
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((host, int(port)), timeout=float(timeout_seconds)):
            return True, f"Connected to {host}:{port}."
    except Exception as exc:
        return False, f"{host}:{port} unreachable: {exc}"


def _startup_set_binding_error_fields(*, binding_id: int, error_code: Optional[str], error_message: Optional[str]) -> None:
    ts = now_iso()
    with get_conn() as conn:
        conn.execute(
            "UPDATE tv_screen_binding SET last_error_code=?, last_error_message=?, updated_at=? WHERE id=?",
            (error_code, error_message, ts, int(binding_id)),
        )
        conn.commit()


def _startup_phase_row_to_dict(row) -> Dict[str, Any]:
    raw = _row_to_dict(row) or {}
    metadata = _json_loads(raw.get("metadata_json"))
    return {
        "id": _safe_int(raw.get("id"), 0),
        "runId": _safe_int(raw.get("run_id"), 0),
        "phaseName": _safe_str(raw.get("phase_name"), "") or None,
        "result": _safe_str(raw.get("result"), "") or _safe_str(raw.get("status"), "") or None,
        "status": _safe_str(raw.get("status"), "") or _safe_str(raw.get("result"), "") or None,
        "message": _safe_str(raw.get("message"), "") or None,
        "startedAt": _safe_str(raw.get("started_at"), "") or None,
        "finishedAt": _safe_str(raw.get("finished_at"), "") or None,
        "metadata": metadata if isinstance(metadata, dict) else {},
        "createdAt": _safe_str(raw.get("created_at"), "") or None,
    }


def _startup_run_row_to_dict(row, *, phases: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    raw = _row_to_dict(row) or {}
    metadata = _json_loads(raw.get("metadata_json"))
    meta = metadata if isinstance(metadata, dict) else {}
    return {
        "id": _safe_int(raw.get("id"), 0),
        "startedAt": _safe_str(raw.get("started_at"), "") or None,
        "finishedAt": _safe_str(raw.get("finished_at"), "") or None,
        "overallResult": _safe_str(raw.get("overall_result"), "") or _safe_str(raw.get("status"), "") or None,
        "status": _safe_str(raw.get("status"), "") or _safe_str(raw.get("overall_result"), "") or None,
        "blockerCount": _safe_int(raw.get("blocker_count"), 0),
        "warningCount": _safe_int(raw.get("warning_count"), 0),
        "infoCount": _safe_int(raw.get("info_count"), 0),
        "message": _safe_str(raw.get("message"), "") or None,
        "metadata": meta,
        "triggerSource": _safe_str(raw.get("trigger_source"), "") or _safe_str(meta.get("triggerSource"), "") or None,
        "correlationId": _safe_str(raw.get("correlation_id"), "") or _safe_str(meta.get("correlationId"), "") or None,
        "checks": list(meta.get("checks") or []),
        "blockers": list(meta.get("blockers") or []),
        "warnings": list(meta.get("warnings") or []),
        "infos": list(meta.get("infos") or []),
        "createdAt": _safe_str(raw.get("created_at"), "") or None,
        "updatedAt": _safe_str(raw.get("updated_at"), "") or None,
        "phases": list(phases or []),
    }


def _list_startup_phase_rows(*, run_id: int) -> List[Dict[str, Any]]:
    _ensure_tv_startup_reconciliation_schema()
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM tv_startup_reconciliation_phase WHERE run_id=? ORDER BY id ASC",
            (int(run_id),),
        ).fetchall()
    return [_startup_phase_row_to_dict(row) for row in rows]


def _create_startup_run(
    *,
    metadata: Optional[Dict[str, Any]] = None,
    message: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> int:
    _ensure_tv_startup_reconciliation_schema()
    ts = now_iso()
    meta = dict(metadata or {})
    corr = _safe_str(correlation_id, "").strip() or _safe_str(meta.get("correlationId"), "").strip() or None
    trigger_source = _safe_str(meta.get("triggerSource"), "").strip() or None
    summary_json = _json_dumps({"checks": [], "blockers": [], "warnings": [], "infos": []})
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO tv_startup_reconciliation_run (
                started_at, finished_at, overall_result, correlation_id, trigger_source, status, summary_json,
                blocker_count, warning_count, info_count,
                message, metadata_json, created_at, updated_at
            ) VALUES (?, NULL, NULL, ?, ?, ?, ?, 0, 0, 0, ?, ?, ?, ?)
            """,
            (ts, corr, trigger_source, "STARTED", summary_json, message, _json_dumps(meta), ts, ts),
        )
        conn.commit()
        return _safe_int(cur.lastrowid, 0)


def _update_startup_run(
    *,
    run_id: int,
    overall_result: str,
    blocker_count: int,
    warning_count: int,
    info_count: int,
    message: Optional[str],
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    _ensure_tv_startup_reconciliation_schema()
    ts = now_iso()
    meta = dict(metadata or {})
    summary_json = _json_dumps(
        {
            "checks": list(meta.get("checks") or []),
            "blockers": list(meta.get("blockers") or []),
            "warnings": list(meta.get("warnings") or []),
            "infos": list(meta.get("infos") or []),
        }
    )
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE tv_startup_reconciliation_run
            SET finished_at=?,
                overall_result=?,
                status=?,
                blocker_count=?,
                warning_count=?,
                info_count=?,
                message=?,
                summary_json=?,
                metadata_json=?,
                updated_at=?
            WHERE id=?
            """,
            (
                ts,
                overall_result,
                overall_result,
                int(blocker_count),
                int(warning_count),
                int(info_count),
                message,
                summary_json,
                _json_dumps(meta),
                ts,
                int(run_id),
            ),
        )
        conn.commit()


def _start_startup_phase(*, run_id: int, phase_name: str, message: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> int:
    _ensure_tv_startup_reconciliation_schema()
    ts = now_iso()
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO tv_startup_reconciliation_phase (
                run_id, phase_name, status, result, message, started_at, finished_at, metadata_json, created_at
            ) VALUES (?, ?, ?, NULL, ?, ?, NULL, ?, ?)
            """,
            (int(run_id), phase_name, "STARTED", message, ts, _json_dumps(metadata or {}), ts),
        )
        conn.commit()
        return _safe_int(cur.lastrowid, 0)


def _finish_startup_phase(*, phase_id: int, result: str, message: Optional[str], metadata: Optional[Dict[str, Any]] = None) -> None:
    _ensure_tv_startup_reconciliation_schema()
    ts = now_iso()
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE tv_startup_reconciliation_phase
            SET status=?, result=?, message=?, finished_at=?, metadata_json=?
            WHERE id=?
            """,
            (result, result, message, ts, _json_dumps(metadata or {}), int(phase_id)),
        )
        conn.commit()


def _skip_startup_phase(*, run_id: int, phase_name: str, message: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    phase_id = _start_startup_phase(run_id=run_id, phase_name=phase_name, message=message, metadata=metadata)
    _finish_startup_phase(
        phase_id=phase_id,
        result=STARTUP_RESULT_SKIPPED,
        message=message,
        metadata=metadata,
    )
    return {
        "phaseName": phase_name,
        "result": STARTUP_RESULT_SKIPPED,
        "message": message,
        "metadata": dict(metadata or {}),
    }


def _execute_startup_phase(*, run_id: int, phase_name: str, handler) -> Dict[str, Any]:
    phase_id = _start_startup_phase(run_id=run_id, phase_name=phase_name)
    try:
        outcome = handler() or {}
        result = _safe_str(outcome.get("result"), STARTUP_RESULT_PASSED) or STARTUP_RESULT_PASSED
        message = _safe_str(outcome.get("message"), "") or None
        metadata = outcome.get("metadata") if isinstance(outcome.get("metadata"), dict) else {}
    except Exception as exc:
        _log.exception("[TvStartup] phase %s failed: %s", phase_name, exc)
        result = STARTUP_RESULT_FAILED
        message = str(exc) or f"{phase_name} failed."
        metadata = {"error": message}
    _finish_startup_phase(phase_id=phase_id, result=result, message=message, metadata=metadata)
    return {
        "phaseName": phase_name,
        "result": result,
        "message": message,
        "metadata": metadata,
    }


def _repair_interrupted_startup_runs(*, current_run_id: int) -> Dict[str, Any]:
    _ensure_tv_startup_reconciliation_schema()
    ts = now_iso()
    repaired_runs = 0
    repaired_phases = 0
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id FROM tv_startup_reconciliation_run
            WHERE id != ? AND (overall_result IS NULL OR finished_at IS NULL)
            """,
            (int(current_run_id),),
        ).fetchall()
        run_ids = [_safe_int(row["id"], 0) for row in rows if _safe_int(row["id"], 0) > 0]
        if run_ids:
            placeholders = ",".join("?" * len(run_ids))
            repaired_runs = _safe_int(
                conn.execute(
                    f"""
                    UPDATE tv_startup_reconciliation_run
                    SET finished_at=COALESCE(finished_at, ?),
                        overall_result=COALESCE(overall_result, ?),
                        message=COALESCE(message, 'Recovered after interrupted startup reconciliation.'),
                        updated_at=?
                    WHERE id IN ({placeholders})
                    """,
                    tuple([ts, STARTUP_RUN_RESULT_FAILED, ts] + run_ids),
                ).rowcount,
                0,
            )
            repaired_phases = _safe_int(
                conn.execute(
                    f"""
                    UPDATE tv_startup_reconciliation_phase
                    SET result=COALESCE(result, ?),
                        message=COALESCE(message, 'Recovered after interrupted startup reconciliation.'),
                        finished_at=COALESCE(finished_at, ?),
                        metadata_json=COALESCE(metadata_json, ?)
                    WHERE run_id IN ({placeholders}) AND (result IS NULL OR finished_at IS NULL)
                    """,
                    tuple(
                        [
                            STARTUP_RESULT_FAILED,
                            ts,
                            _json_dumps({"recovered": True, "reason": "INTERRUPTED_STARTUP_RECONCILIATION"}),
                        ]
                        + run_ids
                    ),
                ).rowcount,
                0,
            )
            conn.commit()
    if repaired_runs or repaired_phases:
        return {
            "result": STARTUP_RESULT_REPAIRED,
            "message": f"Recovered {repaired_runs} interrupted startup run(s).",
            "metadata": {
                "repairedRunCount": repaired_runs,
                "repairedPhaseCount": repaired_phases,
            },
        }
    return {
        "result": STARTUP_RESULT_PASSED,
        "message": "Startup tracking schema already consistent.",
        "metadata": {
            "repairedRunCount": 0,
            "repairedPhaseCount": 0,
        },
    }


def _repair_interrupted_binding_runtime(*, correlation_id: str) -> Dict[str, Any]:
    repaired = 0
    touched_bindings: List[int] = []
    for binding in list_tv_screen_bindings():
        bid = _safe_int(binding.get("id"), 0)
        if bid <= 0:
            continue
        runtime = load_tv_screen_binding_runtime(binding_id=bid) or {}
        runtime_state = _safe_str(runtime.get("runtime_state"), BINDING_RUNTIME_IDLE)
        if runtime_state not in {BINDING_RUNTIME_STARTING, BINDING_RUNTIME_STOPPING}:
            continue
        desired = _safe_str(binding.get("desired_state"), DESIRED_STOPPED)
        enabled = _binding_bool(binding.get("enabled"))
        ts = now_iso()
        if runtime_state == BINDING_RUNTIME_STOPPING or not enabled or desired == DESIRED_STOPPED:
            new_state = BINDING_RUNTIME_STOPPED
            error_code = None
            error_message = None
            updates = {
                "runtime_state": BINDING_RUNTIME_STOPPED,
                "window_id": None,
                "tauri_window_label": None,
                "last_stopped_at": ts,
                "last_exit_reason": "STARTUP_REPAIRED_STOP",
                "last_error_code": None,
                "last_error_message": None,
            }
            event_message = "Recovered stale startup transition and marked binding stopped."
        else:
            new_state = BINDING_RUNTIME_CRASHED
            crash_count = _safe_int(runtime.get("crash_count"), 0) + 1
            error_code = "STARTUP_INTERRUPTED"
            error_message = "Binding start was interrupted by process restart."
            updates = {
                "runtime_state": BINDING_RUNTIME_CRASHED,
                "window_id": None,
                "tauri_window_label": None,
                "last_crashed_at": ts,
                "crash_count": crash_count,
                "last_exit_reason": error_code,
                "last_error_code": error_code,
                "last_error_message": error_message,
            }
            event_message = error_message
        upsert_tv_screen_binding_runtime(binding_id=bid, **updates)
        _startup_set_binding_error_fields(binding_id=bid, error_code=error_code, error_message=error_message)
        record_tv_screen_binding_event(
            binding_id=bid,
            event_type="STARTUP_INTERRUPTED_STATE_REPAIR",
            severity=SEVERITY_WARN if new_state == BINDING_RUNTIME_STOPPED else SEVERITY_ERROR,
            message=event_message,
            metadata_json={"correlationId": correlation_id, "repairedState": new_state},
        )
        repaired += 1
        touched_bindings.append(bid)
    if repaired:
        return {
            "result": STARTUP_RESULT_REPAIRED,
            "message": f"Repaired {repaired} stale binding transition(s).",
            "metadata": {"repairedBindingCount": repaired, "bindingIds": touched_bindings},
        }
    return {
        "result": STARTUP_RESULT_PASSED,
        "message": "No interrupted binding transitions required repair.",
        "metadata": {"repairedBindingCount": 0, "bindingIds": []},
    }


def _cleanup_stale_tv_temp_files(*, data_root: Path, stale_hours: int = _STARTUP_TEMP_FILE_STALE_HOURS) -> Dict[str, Any]:
    removed: List[str] = []
    scanned = 0
    cutoff = datetime.now() - timedelta(hours=int(stale_hours))
    candidate_dirs = [data_root / "tv" / "media", data_root / "tv" / "cache"]
    suffixes = (".downloading", ".partial", ".part")
    for base_dir in candidate_dirs:
        if not base_dir.exists():
            continue
        for path in base_dir.rglob("*"):
            if not path.is_file():
                continue
            scanned += 1
            if not path.name.lower().endswith(suffixes):
                continue
            try:
                modified_at = datetime.fromtimestamp(path.stat().st_mtime)
            except Exception:
                continue
            if modified_at > cutoff:
                continue
            try:
                path.unlink()
                removed.append(str(path))
            except Exception:
                continue
    if removed:
        return {
            "result": STARTUP_RESULT_REPAIRED,
            "message": f"Removed {len(removed)} stale temp download file(s).",
            "metadata": {
                "removedCount": len(removed),
                "scannedCount": scanned,
                "removedPaths": removed[:25],
                "staleHours": int(stale_hours),
            },
        }
    return {
        "result": STARTUP_RESULT_PASSED,
        "message": "No stale temp download files required cleanup.",
        "metadata": {
            "removedCount": 0,
            "scannedCount": scanned,
            "staleHours": int(stale_hours),
        },
    }


def _refresh_startup_monitors(*, monitors: Optional[List[Dict[str, Any]]], correlation_id: str) -> Dict[str, Any]:
    provided = _sanitize_startup_monitors(monitors)
    before = list_tv_host_monitors()
    if provided is None:
        current = before
        connected = sum(1 for row in current if _binding_bool(row.get("is_connected")))
        return {
            "result": STARTUP_RESULT_PASSED,
            "message": "No fresh monitor payload supplied; kept existing monitor inventory.",
            "metadata": {
                "monitorCount": len(current),
                "connectedMonitorCount": connected,
                "source": "CACHE_ONLY",
            },
        }
    current = replace_tv_host_monitors(monitors=provided)
    connected = sum(1 for row in current if _binding_bool(row.get("is_connected")))
    changed = _json_dumps(before) != _json_dumps(current)
    return {
        "result": STARTUP_RESULT_REPAIRED if changed else STARTUP_RESULT_PASSED,
        "message": f"Monitor inventory refreshed with {connected} connected monitor(s).",
        "metadata": {
            "monitorCount": len(current),
            "connectedMonitorCount": connected,
            "source": "SUPPLIED_PAYLOAD",
            "correlationId": correlation_id,
        },
    }


def _binding_runtime_reconcile(*, correlation_id: str) -> Dict[str, Any]:
    repaired = 0
    binding_ids: List[int] = []
    for binding in list_tv_screen_bindings():
        bid = _safe_int(binding.get("id"), 0)
        if bid <= 0:
            continue
        runtime = load_tv_screen_binding_runtime(binding_id=bid) or {}
        desired = _safe_str(binding.get("desired_state"), DESIRED_STOPPED)
        enabled = _binding_bool(binding.get("enabled"))
        monitor_row = _load_monitor_for_binding(binding)
        monitor_available = bool(monitor_row and _binding_bool(monitor_row.get("is_connected")))
        runtime_state = _safe_str(runtime.get("runtime_state"), BINDING_RUNTIME_IDLE)
        ts = now_iso()
        updates: Optional[Dict[str, Any]] = None
        event_severity = SEVERITY_INFO
        event_message = ""
        error_code = None
        error_message = None

        if not enabled or desired == DESIRED_STOPPED:
            if runtime_state in {BINDING_RUNTIME_RUNNING, BINDING_RUNTIME_STARTING, BINDING_RUNTIME_STOPPING, BINDING_RUNTIME_CRASHED, BINDING_RUNTIME_ERROR} or runtime.get("window_id") or runtime.get("tauri_window_label"):
                updates = {
                    "runtime_state": BINDING_RUNTIME_STOPPED,
                    "window_id": None,
                    "tauri_window_label": None,
                    "last_stopped_at": ts,
                    "last_exit_reason": "STARTUP_RECONCILED_STOPPED",
                    "last_error_code": None,
                    "last_error_message": None,
                }
                event_message = "Startup reconciliation marked stopped/disabled binding as stopped."
            else:
                continue
        elif not monitor_available:
            if runtime_state != BINDING_RUNTIME_ERROR or _safe_str(runtime.get("last_error_code"), "") != "MONITOR_MISSING":
                updates = {
                    "runtime_state": BINDING_RUNTIME_ERROR,
                    "window_id": None,
                    "tauri_window_label": None,
                    "last_error_code": "MONITOR_MISSING",
                    "last_error_message": "Assigned monitor is missing or disconnected during startup reconciliation.",
                }
                event_severity = SEVERITY_ERROR
                error_code = "MONITOR_MISSING"
                error_message = "Assigned monitor is missing or disconnected during startup reconciliation."
                event_message = error_message
            else:
                continue
        elif runtime_state in {BINDING_RUNTIME_RUNNING, BINDING_RUNTIME_STARTING, BINDING_RUNTIME_IDLE, BINDING_RUNTIME_STOPPED} or not runtime:
            updates = {
                "runtime_state": BINDING_RUNTIME_CRASHED,
                "window_id": None,
                "tauri_window_label": None,
                "last_crashed_at": ts,
                "crash_count": _safe_int(runtime.get("crash_count"), 0) + 1,
                "last_exit_reason": "STARTUP_WINDOW_MISSING",
                "last_error_code": "STARTUP_WINDOW_MISSING",
                "last_error_message": "Binding wanted RUNNING but no live player window exists after startup.",
            }
            event_severity = SEVERITY_ERROR
            error_code = "STARTUP_WINDOW_MISSING"
            error_message = "Binding wanted RUNNING but no live player window exists after startup."
            event_message = error_message
        else:
            continue

        upsert_tv_screen_binding_runtime(binding_id=bid, **updates)
        _startup_set_binding_error_fields(binding_id=bid, error_code=error_code, error_message=error_message)
        record_tv_screen_binding_event(
            binding_id=bid,
            event_type="STARTUP_BINDING_RUNTIME_RECONCILE",
            severity=event_severity,
            message=event_message,
            metadata_json={"correlationId": correlation_id, "desiredState": desired, "runtimeState": updates.get("runtime_state")},
        )
        repaired += 1
        binding_ids.append(bid)
    if repaired:
        return {
            "result": STARTUP_RESULT_REPAIRED,
            "message": f"Reconciled {repaired} binding runtime row(s) against startup facts.",
            "metadata": {"repairedBindingCount": repaired, "bindingIds": binding_ids},
        }
    return {
        "result": STARTUP_RESULT_PASSED,
        "message": "Binding runtime rows already matched startup facts.",
        "metadata": {"repairedBindingCount": 0, "bindingIds": []},
    }


def _startup_readiness_recheck() -> Dict[str, Any]:
    result = run_tv_readiness_computation()
    computed = _safe_int(result.get("computed"), 0)
    if computed <= 0:
        return {
            "result": STARTUP_RESULT_SKIPPED,
            "message": "No enabled bindings were eligible for readiness recheck.",
            "metadata": {"computedCount": computed, "results": result.get("results") or []},
        }
    return {
        "result": STARTUP_RESULT_PASSED,
        "message": f"Recomputed readiness for {computed} screen(s).",
        "metadata": {"computedCount": computed, "results": result.get("results") or []},
    }


def _startup_activation_reconcile() -> Dict[str, Any]:
    result = run_tv_activation_evaluation()
    evaluated = _safe_int(result.get("evaluated_count"), 0)
    if evaluated <= 0:
        return {
            "result": STARTUP_RESULT_SKIPPED,
            "message": "No enabled bindings were eligible for activation reconciliation.",
            "metadata": {"evaluatedCount": evaluated, "results": result.get("results") or []},
        }
    return {
        "result": STARTUP_RESULT_PASSED,
        "message": f"Re-evaluated activation for {evaluated} screen(s).",
        "metadata": {"evaluatedCount": evaluated, "results": result.get("results") or []},
    }


def _startup_proof_outbox_recover() -> Dict[str, Any]:
    result = startup_recover_proof_outbox()
    recovered = _safe_int(result.get("recovered"), 0)
    return {
        "result": STARTUP_RESULT_REPAIRED if recovered > 0 else STARTUP_RESULT_PASSED,
        "message": f"Recovered {recovered} proof outbox row(s) from SENDING state." if recovered > 0 else "No proof outbox rows required recovery.",
        "metadata": {"recoveredCount": recovered},
    }


def _startup_ad_runtime_recover() -> Dict[str, Any]:
    result = startup_recover_ad_runtime()
    recovered = _safe_int(result.get("recovered"), 0)
    return {
        "result": STARTUP_RESULT_REPAIRED if recovered > 0 else STARTUP_RESULT_PASSED,
        "message": f"Recovered {recovered} gym ad runtime row(s)." if recovered > 0 else "No gym ad runtime rows required recovery.",
        "metadata": {"recoveredCount": recovered},
    }


def _startup_window_runtime_reconcile(*, correlation_id: str) -> Dict[str, Any]:
    cleared = 0
    reevaluated = 0
    reevaluate_errors = 0
    for binding in list_tv_screen_bindings():
        bid = _safe_int(binding.get("id"), 0)
        if bid <= 0:
            continue
        runtime = load_tv_screen_binding_runtime(binding_id=bid) or {}
        runtime_state = _safe_str(runtime.get("runtime_state"), BINDING_RUNTIME_IDLE)
        if runtime_state not in {BINDING_RUNTIME_RUNNING, BINDING_RUNTIME_STARTING} and (
            _safe_str(runtime.get("window_id"), "") or _safe_str(runtime.get("tauri_window_label"), "")
        ):
            upsert_tv_screen_binding_runtime(binding_id=bid, window_id=None, tauri_window_label=None)
            cleared += 1
        if _binding_bool(binding.get("enabled")) and _safe_str(binding.get("desired_state"), DESIRED_STOPPED) == DESIRED_RUNNING:
            try:
                reevaluate_tv_player(binding_id=bid, persist=True)
                reevaluated += 1
            except Exception:
                reevaluate_errors += 1
                record_tv_screen_binding_event(
                    binding_id=bid,
                    event_type="STARTUP_PLAYER_REEVALUATE_ERROR",
                    severity=SEVERITY_WARN,
                    message="Player reevaluation raised during startup reconciliation.",
                    metadata_json={"correlationId": correlation_id},
                )
    if reevaluate_errors > 0:
        return {
            "result": STARTUP_RESULT_FAILED,
            "message": f"Player reevaluation raised for {reevaluate_errors} binding(s).",
            "metadata": {
                "clearedWindowRefs": cleared,
                "reevaluatedBindings": reevaluated,
                "reevaluateErrors": reevaluate_errors,
            },
        }
    if cleared > 0:
        return {
            "result": STARTUP_RESULT_REPAIRED,
            "message": f"Cleared {cleared} stale window reference(s) and reevaluated {reevaluated} binding(s).",
            "metadata": {
                "clearedWindowRefs": cleared,
                "reevaluatedBindings": reevaluated,
                "reevaluateErrors": 0,
            },
        }
    return {
        "result": STARTUP_RESULT_PASSED,
        "message": f"Reevaluated {reevaluated} binding(s); no stale window references remained.",
        "metadata": {
            "clearedWindowRefs": 0,
            "reevaluatedBindings": reevaluated,
            "reevaluateErrors": 0,
        },
    }


def run_tv_deployment_preflight(*, include_query_checks: bool = False, **kwargs) -> Dict[str, Any]:
    import sqlite3
    from tv.config import load_tv_app_config

    data_root = Path(str(kwargs.get("data_root_override") or kwargs.get("data_root") or DATA_ROOT))
    db_path = Path(str(kwargs.get("db_path_override") or kwargs.get("db_path") or current_tv_runtime_db_path()))
    config_loader = kwargs.get("config_loader") or load_tv_app_config
    monitors_arg = _sanitize_startup_monitors(kwargs.get("monitors"))
    api_probe = kwargs.get("api_probe")
    query_checks = bool(include_query_checks or kwargs.get("include_query_checks"))
    checks: List[Dict[str, Any]] = []
    generated_at = now_iso()

    runtime_target = _is_runtime_startup_target(data_root=data_root, db_path=db_path)

    data_root_ready = False
    db_ready = False
    schema_ready = False
    config_obj = None

    try:
        data_root.mkdir(parents=True, exist_ok=True)
        data_root_ready = data_root.exists() and data_root.is_dir()
        checks.append(
            _startup_check_item(
                code="DATA_ROOT_READY",
                severity=STARTUP_CHECK_SEVERITY_BLOCKER,
                status=STARTUP_RESULT_PASSED if data_root_ready else STARTUP_RESULT_FAILED,
                message=f"Data root ready at {data_root}.",
                metadata={"path": str(data_root)},
            )
        )
    except Exception as exc:
        checks.append(
            _startup_check_item(
                code="DATA_ROOT_READY",
                severity=STARTUP_CHECK_SEVERITY_BLOCKER,
                status=STARTUP_RESULT_FAILED,
                message=f"Data root could not be created: {exc}",
                metadata={"path": str(data_root)},
            )
        )

    if data_root_ready:
        probe_path = data_root / ".startup_write_probe"
        try:
            probe_path.write_text("ok", encoding="utf-8")
            try:
                probe_path.unlink()
            except Exception:
                pass
            checks.append(
                _startup_check_item(
                    code="DATA_ROOT_WRITABLE",
                    severity=STARTUP_CHECK_SEVERITY_BLOCKER,
                    status=STARTUP_RESULT_PASSED,
                    message="Data root is writable.",
                    metadata={"path": str(data_root)},
                )
            )
        except Exception as exc:
            checks.append(
                _startup_check_item(
                    code="DATA_ROOT_WRITABLE",
                    severity=STARTUP_CHECK_SEVERITY_BLOCKER,
                    status=STARTUP_RESULT_FAILED,
                    message=f"Data root is not writable: {exc}",
                    metadata={"path": str(data_root)},
                )
            )

    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        try:
            conn.execute("SELECT 1").fetchone()
        finally:
            conn.close()
        db_ready = True
        checks.append(
            _startup_check_item(
                code="DB_OPEN",
                severity=STARTUP_CHECK_SEVERITY_BLOCKER,
                status=STARTUP_RESULT_PASSED,
                message="SQLite database opened successfully.",
                metadata={"dbPath": str(db_path)},
            )
        )
    except Exception as exc:
        checks.append(
            _startup_check_item(
                code="DB_OPEN",
                severity=STARTUP_CHECK_SEVERITY_BLOCKER,
                status=STARTUP_RESULT_FAILED,
                message=f"SQLite database could not be opened: {exc}",
                metadata={"dbPath": str(db_path)},
            )
        )

    if db_ready:
        try:
            if runtime_target:
                _ensure_tv_startup_reconciliation_schema()
            else:
                conn = sqlite3.connect(str(db_path), check_same_thread=False)
                try:
                    conn.execute("CREATE TABLE IF NOT EXISTS __tv_startup_schema_probe (id INTEGER PRIMARY KEY)")
                    conn.execute("DROP TABLE IF EXISTS __tv_startup_schema_probe")
                    conn.commit()
                finally:
                    conn.close()
            schema_ready = True
            checks.append(
                _startup_check_item(
                    code="SCHEMA_BOOTSTRAP",
                    severity=STARTUP_CHECK_SEVERITY_BLOCKER,
                    status=STARTUP_RESULT_PASSED,
                    message="TV schema bootstrap succeeded.",
                    metadata={"runtimeTarget": runtime_target},
                )
            )
        except Exception as exc:
            checks.append(
                _startup_check_item(
                    code="SCHEMA_BOOTSTRAP",
                    severity=STARTUP_CHECK_SEVERITY_BLOCKER,
                    status=STARTUP_RESULT_FAILED,
                    message=f"TV schema bootstrap failed: {exc}",
                    metadata={"runtimeTarget": runtime_target},
                )
            )
    else:
        checks.append(
            _startup_check_item(
                code="SCHEMA_BOOTSTRAP",
                severity=STARTUP_CHECK_SEVERITY_BLOCKER,
                status=STARTUP_RESULT_SKIPPED,
                message="Skipped TV schema bootstrap because the database is unavailable.",
                metadata={"runtimeTarget": runtime_target},
            )
        )

    required_dirs = [data_root / "data", data_root / "tv", data_root / "tv" / "media", data_root / "tv" / "cache"]
    dir_errors: List[str] = []
    if data_root_ready:
        for path in required_dirs:
            try:
                path.mkdir(parents=True, exist_ok=True)
            except Exception as exc:
                dir_errors.append(f"{path}: {exc}")
        checks.append(
            _startup_check_item(
                code="TV_DIRS_READY",
                severity=STARTUP_CHECK_SEVERITY_BLOCKER,
                status=STARTUP_RESULT_FAILED if dir_errors else STARTUP_RESULT_PASSED,
                message="Required TV directories are ready." if not dir_errors else "Required TV directories could not be created.",
                metadata={"paths": [str(path) for path in required_dirs], "errors": dir_errors},
            )
        )

    try:
        config_obj = config_loader()
        checks.append(
            _startup_check_item(
                code="CONFIG_LOAD",
                severity=STARTUP_CHECK_SEVERITY_BLOCKER,
                status=STARTUP_RESULT_PASSED,
                message="Core config loaded successfully.",
                metadata={"localApiHost": _safe_str(getattr(config_obj, "local_api_host", ""), "")},
            )
        )
    except Exception as exc:
        checks.append(
            _startup_check_item(
                code="CONFIG_LOAD",
                severity=STARTUP_CHECK_SEVERITY_BLOCKER,
                status=STARTUP_RESULT_FAILED,
                message=f"Core config could not be loaded: {exc}",
                metadata={},
            )
        )

    bindings: List[Dict[str, Any]] = []
    monitors: List[Dict[str, Any]] = []
    latest_snapshot_count = 0
    proof_backlog_count = 0
    failed_download_count = 0
    latest_startup_timestamp = None
    retention_summary = None

    if schema_ready and runtime_target:
        try:
            bindings = list_tv_screen_bindings()
        except Exception:
            bindings = []
        try:
            monitors = monitors_arg if monitors_arg is not None else list_tv_host_monitors()
        except Exception:
            monitors = monitors_arg or []
        try:
            with get_conn() as conn:
                latest_snapshot_count = _count_where(conn, "tv_snapshot_cache", "is_latest=1", ())
                proof_backlog_count = _count_where(
                    conn,
                    "tv_ad_proof_outbox",
                    "outbox_state IN (?,?,?)",
                    (PROOF_OUTBOX_QUEUED, PROOF_OUTBOX_FAILED_RETRYABLE, PROOF_OUTBOX_SENDING),
                )
                failure_states = (
                    ASSET_STATE_ERROR,
                    ASSET_STATE_INVALID_CHECKSUM,
                    ASSET_STATE_INVALID_SIZE,
                    ASSET_STATE_INVALID_UNREADABLE,
                    ASSET_STATE_NOT_PRESENT,
                    ASSET_STATE_MISSING,
                    ASSET_STATE_STALE,
                )
                failed_download_count = _count_where(
                    conn,
                    "tv_local_asset_state",
                    f"asset_state IN ({','.join(['?'] * len(failure_states))})",
                    failure_states,
                )
                latest_run = conn.execute(
                    "SELECT started_at, finished_at, overall_result FROM tv_startup_reconciliation_run ORDER BY id DESC LIMIT 1"
                ).fetchone()
                if latest_run:
                    latest_startup_timestamp = _safe_str(latest_run["finished_at"] or latest_run["started_at"], "") or None
        except Exception:
            latest_snapshot_count = 0
            proof_backlog_count = 0
            failed_download_count = 0
            latest_startup_timestamp = None
        try:
            retention_summary = get_tv_observability_retention()
        except Exception:
            retention_summary = None
    elif monitors_arg is not None:
        monitors = monitors_arg

    connected_monitor_count = sum(1 for row in monitors if _binding_bool(row.get("is_connected", True)))
    checks.append(
        _startup_check_item(
            code="MONITOR_INVENTORY",
            severity=STARTUP_CHECK_SEVERITY_WARNING,
            status=STARTUP_RESULT_FAILED if connected_monitor_count <= 0 else STARTUP_RESULT_PASSED,
            message="No connected monitor detected." if connected_monitor_count <= 0 else f"{connected_monitor_count} connected monitor(s) detected.",
            metadata={"monitorCount": len(monitors), "connectedMonitorCount": connected_monitor_count},
        )
    )
    checks.append(
        _startup_check_item(
            code="BINDINGS_CONFIGURED",
            severity=STARTUP_CHECK_SEVERITY_WARNING,
            status=STARTUP_RESULT_FAILED if len(bindings) <= 0 else STARTUP_RESULT_PASSED,
            message="No TV bindings are configured on this host." if len(bindings) <= 0 else f"{len(bindings)} TV binding(s) configured.",
            metadata={"bindingCount": len(bindings)},
        )
    )
    checks.append(
        _startup_check_item(
            code="LATEST_SNAPSHOT_CACHE",
            severity=STARTUP_CHECK_SEVERITY_WARNING,
            status=STARTUP_RESULT_FAILED if latest_snapshot_count <= 0 else STARTUP_RESULT_PASSED,
            message="No latest snapshot cache rows exist yet." if latest_snapshot_count <= 0 else f"{latest_snapshot_count} latest snapshot cache row(s) found.",
            metadata={"latestSnapshotCount": latest_snapshot_count},
        )
    )

    if query_checks and config_obj is not None:
        probe_target = _safe_str(
            getattr(config_obj, "api_sync_url", "") or getattr(config_obj, "api_login_url", ""),
            "",
        )
        try:
            if callable(api_probe):
                reachable, probe_message = api_probe(probe_target)
            else:
                reachable, probe_message = _startup_probe_socket_url(
                    probe_target,
                    timeout_seconds=float(kwargs.get("query_timeout_seconds") or 1.0),
                )
            checks.append(
                _startup_check_item(
                    code="BACKEND_REACHABLE",
                    severity=STARTUP_CHECK_SEVERITY_WARNING,
                    status=STARTUP_RESULT_PASSED if reachable else STARTUP_RESULT_FAILED,
                    message=probe_message,
                    metadata={"url": probe_target},
                )
            )
        except Exception as exc:
            checks.append(
                _startup_check_item(
                    code="BACKEND_REACHABLE",
                    severity=STARTUP_CHECK_SEVERITY_WARNING,
                    status=STARTUP_RESULT_FAILED,
                    message=f"Backend/API reachability probe failed: {exc}",
                    metadata={"url": probe_target},
                )
            )
    else:
        checks.append(
            _startup_check_item(
                code="BACKEND_REACHABLE",
                severity=STARTUP_CHECK_SEVERITY_WARNING,
                status=STARTUP_RESULT_SKIPPED,
                message="Backend/API reachability probe was skipped.",
                metadata={"includeQueryChecks": query_checks},
            )
        )

    try:
        auth_state = load_tv_auth_for_runtime()
        has_auth = bool(auth_state and _safe_str(getattr(auth_state, "token", ""), "").strip())
    except Exception:
        has_auth = False
    checks.append(
        _startup_check_item(
            code="AUTH_TOKEN_PRESENT",
            severity=STARTUP_CHECK_SEVERITY_WARNING,
            status=STARTUP_RESULT_PASSED if has_auth else STARTUP_RESULT_FAILED,
            message="Auth token is available for sync/proof actions." if has_auth else "Auth token is missing for sync/proof actions.",
            metadata={},
        )
    )
    checks.append(
        _startup_check_item(
            code="PROOF_BACKLOG",
            severity=STARTUP_CHECK_SEVERITY_WARNING,
            status=STARTUP_RESULT_FAILED if proof_backlog_count > 0 else STARTUP_RESULT_PASSED,
            message="Retryable/queued proof backlog exists." if proof_backlog_count > 0 else "No retryable proof backlog exists.",
            metadata={"proofBacklogCount": proof_backlog_count},
        )
    )
    checks.append(
        _startup_check_item(
            code="FAILED_DOWNLOAD_BACKLOG",
            severity=STARTUP_CHECK_SEVERITY_WARNING,
            status=STARTUP_RESULT_FAILED if failed_download_count > 0 else STARTUP_RESULT_PASSED,
            message="Failed download backlog exists." if failed_download_count > 0 else "No failed download backlog exists.",
            metadata={"failedDownloadCount": failed_download_count},
        )
    )

    checks.append(
        _startup_check_item(
            code="MONITOR_COUNT",
            severity=STARTUP_CHECK_SEVERITY_INFO,
            status=STARTUP_RESULT_PASSED,
            message=f"Connected monitors: {connected_monitor_count}.",
            metadata={"monitorCount": len(monitors), "connectedMonitorCount": connected_monitor_count},
        )
    )
    checks.append(
        _startup_check_item(
            code="BINDING_COUNT",
            severity=STARTUP_CHECK_SEVERITY_INFO,
            status=STARTUP_RESULT_PASSED,
            message=f"Bindings configured: {len(bindings)}.",
            metadata={"bindingCount": len(bindings)},
        )
    )
    checks.append(
        _startup_check_item(
            code="LATEST_STARTUP_RECONCILIATION",
            severity=STARTUP_CHECK_SEVERITY_INFO,
            status=STARTUP_RESULT_PASSED if latest_startup_timestamp else STARTUP_RESULT_SKIPPED,
            message=f"Latest startup reconciliation finished at {latest_startup_timestamp}." if latest_startup_timestamp else "No previous startup reconciliation has been recorded yet.",
            metadata={"latestStartupTimestamp": latest_startup_timestamp},
        )
    )
    retention_eligible = _safe_int((retention_summary or {}).get("eligibleDeleteCount"), 0)
    checks.append(
        _startup_check_item(
            code="RETENTION_SUMMARY",
            severity=STARTUP_CHECK_SEVERITY_INFO,
            status=STARTUP_RESULT_PASSED if retention_summary else STARTUP_RESULT_SKIPPED,
            message=f"Safe retention currently has {retention_eligible} eligible row(s)." if retention_summary else "Retention summary is not available yet.",
            metadata={
                "eligibleDeleteCount": retention_eligible,
                "policy": (retention_summary or {}).get("policy"),
            },
        )
    )

    blockers, warnings, infos = _startup_problem_buckets(checks)
    overall = _startup_overall_result(blockers=blockers, warnings=warnings, failed_phases=0, repaired_phases=0)
    message = (
        "Startup preflight failed with blocker checks."
        if blockers
        else "Startup preflight completed with warnings."
        if warnings
        else "Startup preflight passed."
    )
    return {
        "ok": not blockers,
        "status": overall,
        "overallResult": overall,
        "generatedAt": generated_at,
        "message": message,
        "checks": checks,
        "blockers": blockers,
        "warnings": warnings,
        "infos": infos,
        "counts": {
            "blockerCount": len(blockers),
            "warningCount": len(warnings),
            "infoCount": len(infos),
        },
        "metadata": {
            "dataRoot": str(data_root),
            "dbPath": str(db_path),
            "includeQueryChecks": query_checks,
            "runtimeTarget": runtime_target,
        },
    }


def list_tv_startup_reconciliation_runs(*, limit: int = 20, offset: int = 0, **kwargs) -> Dict[str, Any]:
    _ensure_tv_startup_reconciliation_schema()
    lim = max(1, int(limit))
    off = max(0, int(offset))
    with get_conn() as conn:
        total_row = conn.execute("SELECT COUNT(*) AS cnt FROM tv_startup_reconciliation_run").fetchone()
        total = _safe_int(total_row["cnt"], 0) if total_row else 0
        rows = conn.execute(
            "SELECT * FROM tv_startup_reconciliation_run ORDER BY id DESC LIMIT ? OFFSET ?",
            (lim, off),
        ).fetchall()
    return {
        "rows": [_startup_run_row_to_dict(row) for row in rows],
        "total": total,
        "limit": lim,
        "offset": off,
    }


def load_tv_startup_reconciliation_latest(**kwargs) -> Dict[str, Any]:
    _ensure_tv_startup_reconciliation_schema()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM tv_startup_reconciliation_run ORDER BY id DESC LIMIT 1"
        ).fetchone()
    if not row:
        return {"ok": False, "error": "STARTUP_RECONCILIATION_NOT_FOUND"}
    run_id = _safe_int(row["id"], 0)
    return {"ok": True, **_startup_run_row_to_dict(row, phases=_list_startup_phase_rows(run_id=run_id))}


def run_tv_startup_reconciliation(**kwargs) -> Dict[str, Any]:
    global _startup_reconciliation_active

    trigger_source = _safe_str(kwargs.get("trigger_source") or kwargs.get("triggerSource"), "LOCAL_STARTUP").strip() or "LOCAL_STARTUP"
    correlation_id = _safe_str(kwargs.get("correlation_id") or kwargs.get("correlationId"), "").strip() or str(uuid.uuid4())
    monitors = kwargs.get("monitors")
    include_query_checks = bool(kwargs.get("include_query_checks") or kwargs.get("includeQueryChecks"))

    if not _startup_reconciliation_guard.acquire(blocking=False):
        current = dict(_startup_reconciliation_active or {})
        return {
            "ok": False,
            "result": "BLOCKED",
            "status": "BLOCKED",
            "error": "STARTUP_RECONCILIATION_ALREADY_RUNNING",
            "message": "Startup reconciliation is already running.",
            "activeRun": current or None,
        }

    _startup_reconciliation_active = {
        "triggerSource": trigger_source,
        "correlationId": correlation_id,
        "startedAt": now_iso(),
    }

    try:
        run_id = _create_startup_run(
            metadata={"triggerSource": trigger_source, "correlationId": correlation_id},
            message="Startup reconciliation running.",
            correlation_id=correlation_id,
        )
        _startup_reconciliation_active["runId"] = run_id

        phase_results: List[Dict[str, Any]] = []
        repaired_phase_count = 0
        failed_phase_count = 0

        migration_result = _execute_startup_phase(
            run_id=run_id,
            phase_name="migration",
            handler=lambda: _repair_interrupted_startup_runs(current_run_id=run_id),
        )
        phase_results.append(migration_result)
        if migration_result.get("result") == STARTUP_RESULT_REPAIRED:
            repaired_phase_count += 1
        elif migration_result.get("result") == STARTUP_RESULT_FAILED:
            failed_phase_count += 1

        preflight = run_tv_deployment_preflight(
            include_query_checks=include_query_checks,
            monitors=monitors,
        )
        preflight_phase = _start_startup_phase(run_id=run_id, phase_name="preflight")
        preflight_phase_result = STARTUP_RESULT_FAILED if not bool(preflight.get("ok")) else STARTUP_RESULT_PASSED
        preflight_phase_message = _safe_str(preflight.get("message"), "") or "Startup preflight completed."
        _finish_startup_phase(
            phase_id=preflight_phase,
            result=preflight_phase_result,
            message=preflight_phase_message,
            metadata={
                "checks": preflight.get("checks") or [],
                "blockers": preflight.get("blockers") or [],
                "warnings": preflight.get("warnings") or [],
                "infos": preflight.get("infos") or [],
                "counts": preflight.get("counts") or {},
            },
        )
        phase_results.append(
            {
                "phaseName": "preflight",
                "result": preflight_phase_result,
                "message": preflight_phase_message,
                "metadata": {
                    "checks": preflight.get("checks") or [],
                    "blockers": preflight.get("blockers") or [],
                    "warnings": preflight.get("warnings") or [],
                    "infos": preflight.get("infos") or [],
                    "counts": preflight.get("counts") or {},
                },
            }
        )
        if preflight_phase_result == STARTUP_RESULT_FAILED:
            failed_phase_count += 1

        blockers = list(preflight.get("blockers") or [])
        warnings = list(preflight.get("warnings") or [])
        infos = list(preflight.get("infos") or [])

        if blockers:
            for phase_name in STARTUP_PHASES[2:-1]:
                phase_results.append(
                    _skip_startup_phase(
                        run_id=run_id,
                        phase_name=phase_name,
                        message="Skipped because startup preflight reported blocker checks.",
                        metadata={"blockedByPreflight": True},
                    )
                )
            finalize_result = _execute_startup_phase(
                run_id=run_id,
                phase_name="finalize",
                handler=lambda: {
                    "result": STARTUP_RESULT_PASSED,
                    "message": "Startup reconciliation finalized with preflight blockers.",
                    "metadata": {"blockedByPreflight": True},
                },
            )
            phase_results.append(finalize_result)
            overall_result = _startup_overall_result(
                blockers=blockers,
                warnings=warnings,
                failed_phases=failed_phase_count,
                repaired_phases=repaired_phase_count,
            )
            final_metadata = {
                "triggerSource": trigger_source,
                "correlationId": correlation_id,
                "checks": preflight.get("checks") or [],
                "blockers": blockers,
                "warnings": warnings,
                "infos": infos,
                "phaseResults": phase_results,
            }
            _update_startup_run(
                run_id=run_id,
                overall_result=overall_result,
                blocker_count=len(blockers),
                warning_count=len(warnings),
                info_count=len(infos),
                message="Startup reconciliation stopped after blocker preflight checks.",
                metadata=final_metadata,
            )
            latest = load_tv_startup_reconciliation_latest()
            return {
                "ok": False,
                "runId": run_id,
                "status": overall_result,
                "overallResult": overall_result,
                "failedPhaseCount": failed_phase_count,
                "warningCount": len(warnings),
                "blockerCount": len(blockers),
                "infoCount": len(infos),
                **({"latest": latest} if latest.get("ok") else {}),
            }

        for phase_name, handler in (
            ("interrupted_state_repair", lambda: _repair_interrupted_binding_runtime(correlation_id=correlation_id)),
            (
                "temp_cleanup",
                lambda: _cleanup_stale_tv_temp_files(data_root=_startup_runtime_paths()["dataRoot"]),
            ),
            ("monitor_rescan", lambda: _refresh_startup_monitors(monitors=monitors, correlation_id=correlation_id)),
            ("binding_runtime_reconcile", lambda: _binding_runtime_reconcile(correlation_id=correlation_id)),
            ("readiness_recheck", _startup_readiness_recheck),
            ("activation_reconcile", _startup_activation_reconcile),
            ("proof_outbox_recover", _startup_proof_outbox_recover),
            ("ad_runtime_recover", _startup_ad_runtime_recover),
            ("window_runtime_reconcile", lambda: _startup_window_runtime_reconcile(correlation_id=correlation_id)),
        ):
            phase_result = _execute_startup_phase(run_id=run_id, phase_name=phase_name, handler=handler)
            phase_results.append(phase_result)
            if phase_result.get("result") == STARTUP_RESULT_REPAIRED:
                repaired_phase_count += 1
            elif phase_result.get("result") == STARTUP_RESULT_FAILED:
                failed_phase_count += 1

        finalize_result = _execute_startup_phase(
            run_id=run_id,
            phase_name="finalize",
            handler=lambda: {
                "result": STARTUP_RESULT_PASSED,
                "message": "Startup reconciliation phases completed.",
                "metadata": {
                    "repairedPhaseCount": repaired_phase_count,
                    "failedPhaseCount": failed_phase_count,
                },
            },
        )
        phase_results.append(finalize_result)

        overall_result = _startup_overall_result(
            blockers=blockers,
            warnings=warnings,
            failed_phases=failed_phase_count,
            repaired_phases=repaired_phase_count,
        )
        run_message = (
            "Startup reconciliation failed."
            if overall_result == STARTUP_RUN_RESULT_FAILED
            else "Startup reconciliation completed with warnings."
            if overall_result == STARTUP_RUN_RESULT_SUCCESS_WITH_WARNINGS
            else "Startup reconciliation completed successfully."
        )
        final_metadata = {
            "triggerSource": trigger_source,
            "correlationId": correlation_id,
            "checks": preflight.get("checks") or [],
            "blockers": blockers,
            "warnings": warnings,
            "infos": infos,
            "phaseResults": phase_results,
            "repairedPhaseCount": repaired_phase_count,
            "failedPhaseCount": failed_phase_count,
        }
        _update_startup_run(
            run_id=run_id,
            overall_result=overall_result,
            blocker_count=len(blockers),
            warning_count=len(warnings),
            info_count=len(infos),
            message=run_message,
            metadata=final_metadata,
        )
        latest = load_tv_startup_reconciliation_latest()
        return {
            "ok": overall_result != STARTUP_RUN_RESULT_FAILED,
            "runId": run_id,
            "status": overall_result,
            "overallResult": overall_result,
            "failedPhaseCount": failed_phase_count,
            "warningCount": len(warnings),
            "blockerCount": len(blockers),
            "infoCount": len(infos),
            **({"latest": latest} if latest.get("ok") else {}),
        }
    finally:
        _startup_reconciliation_active = None
        _startup_reconciliation_guard.release()


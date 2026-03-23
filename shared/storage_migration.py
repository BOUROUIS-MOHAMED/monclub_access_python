"""Shared SQLite split migration helpers for Access and TV.

This module owns only migration infrastructure:
- table ownership constants
- one-time legacy copy from the old combined `app.db`
- per-component storage status rows for diagnostics

It does not own business queries or runtime table logic.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence


ACCESS_OWNED_TABLES: tuple[str, ...] = (
    "fingerprints",
    "auth_state",
    "sync_cache",
    "sync_meta",
    "sync_users",
    "sync_memberships",
    "sync_access_software_settings",
    "sync_devices",
    "sync_device_door_presets",
    "sync_infrastructures",
    "sync_gym_access_credentials",
    "device_door_presets",
    "agent_rtlog_state",
    "access_history",
    "device_sync_state",
    "offline_creation_queue",
)

TV_OWNED_TABLES: tuple[str, ...] = (
    "tv_host_monitor",
    "tv_screen_binding",
    "tv_screen_binding_runtime",
    "tv_screen_binding_event",
    "tv_snapshot_cache",
    "tv_snapshot_required_asset",
    "tv_local_asset_state",
    "tv_snapshot_readiness",
    "tv_sync_run_log",
    "tv_activation_state",
    "tv_activation_attempt",
    "tv_player_state",
    "tv_player_event",
    "tv_ad_task_cache",
    "tv_ad_task_runtime",
    "tv_gym_ad_runtime",
    "tv_ad_proof_outbox",
    "tv_support_action_log",
    "tv_startup_reconciliation_run",
    "tv_startup_reconciliation_phase",
    "tv_screen_message",
)

STORAGE_STATUS_TABLE = "__desktop_storage_status"
MIGRATION_NOT_STARTED = "NOT_STARTED"
MIGRATION_COMPLETED = "COMPLETED"
MIGRATION_SOURCE_MISSING = "SOURCE_MISSING"
MIGRATION_FAILED = "FAILED"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_status_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {STORAGE_STATUS_TABLE} (
            component TEXT PRIMARY KEY,
            live_db_path TEXT NOT NULL,
            legacy_source_db_path TEXT,
            migration_state TEXT NOT NULL,
            migration_ran_at TEXT,
            migration_completed_at TEXT,
            legacy_source_exists INTEGER NOT NULL DEFAULT 0,
            copied_tables_json TEXT,
            skipped_tables_json TEXT,
            notes_json TEXT,
            updated_at TEXT NOT NULL
        );
        """
    )


def _list_tables(conn: sqlite3.Connection, *, schema: str = "main") -> List[str]:
    rows = conn.execute(
        f"SELECT name FROM {schema}.sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    return [str(r[0]) for r in rows]


def _table_exists(conn: sqlite3.Connection, table: str, *, schema: str = "main") -> bool:
    row = conn.execute(
        f"SELECT 1 FROM {schema}.sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _table_columns(conn: sqlite3.Connection, table: str, *, schema: str = "main") -> List[str]:
    try:
        rows = conn.execute(f"PRAGMA {schema}.table_info([{table}])").fetchall()
        return [str(r["name"]) for r in rows]
    except Exception:
        return []


def _upsert_status(
    conn: sqlite3.Connection,
    *,
    component: str,
    live_db_path: Path,
    legacy_source_db_path: Path,
    migration_state: str,
    migration_ran_at: str | None,
    migration_completed_at: str | None,
    legacy_source_exists: bool,
    copied_tables: Sequence[str],
    skipped_tables: Sequence[str],
    notes: Sequence[str],
) -> None:
    ts = _utc_now_iso()
    conn.execute(
        f"""
        INSERT INTO {STORAGE_STATUS_TABLE} (
            component,
            live_db_path,
            legacy_source_db_path,
            migration_state,
            migration_ran_at,
            migration_completed_at,
            legacy_source_exists,
            copied_tables_json,
            skipped_tables_json,
            notes_json,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(component) DO UPDATE SET
            live_db_path=excluded.live_db_path,
            legacy_source_db_path=excluded.legacy_source_db_path,
            migration_state=excluded.migration_state,
            migration_ran_at=excluded.migration_ran_at,
            migration_completed_at=excluded.migration_completed_at,
            legacy_source_exists=excluded.legacy_source_exists,
            copied_tables_json=excluded.copied_tables_json,
            skipped_tables_json=excluded.skipped_tables_json,
            notes_json=excluded.notes_json,
            updated_at=excluded.updated_at
        """,
        (
            component,
            str(live_db_path),
            str(legacy_source_db_path),
            migration_state,
            migration_ran_at,
            migration_completed_at,
            1 if legacy_source_exists else 0,
            json.dumps(list(copied_tables), ensure_ascii=False),
            json.dumps(list(skipped_tables), ensure_ascii=False),
            json.dumps(list(notes), ensure_ascii=False),
            ts,
        ),
    )


def read_component_storage_status(
    *,
    component: str,
    live_db_path: Path,
    legacy_source_db_path: Path,
    owned_tables: Iterable[str],
) -> Dict[str, Any]:
    live_db_path = Path(live_db_path)
    legacy_source_db_path = Path(legacy_source_db_path)
    owned = list(owned_tables)

    status: Dict[str, Any] = {
        "component": component,
        "liveDbPath": str(live_db_path),
        "liveDbExists": live_db_path.exists(),
        "legacySourceDbPath": str(legacy_source_db_path),
        "legacySourceExists": legacy_source_db_path.exists(),
        "migrationState": MIGRATION_NOT_STARTED,
        "migrationRanAt": None,
        "migrationCompletedAt": None,
        "copiedTables": [],
        "skippedTables": [],
        "notes": [],
        "ownedTables": owned,
        "presentOwnedTables": [],
        "fallbackActive": False,
    }

    if not live_db_path.exists():
        return status

    try:
        with _connect(live_db_path) as conn:
            _ensure_status_table(conn)
            row = conn.execute(
                f"SELECT * FROM {STORAGE_STATUS_TABLE} WHERE component=?",
                (component,),
            ).fetchone()
            status["presentOwnedTables"] = [
                table for table in owned if _table_exists(conn, table)
            ]
            if row:
                status["migrationState"] = row["migration_state"] or MIGRATION_NOT_STARTED
                status["migrationRanAt"] = row["migration_ran_at"]
                status["migrationCompletedAt"] = row["migration_completed_at"]
                status["legacySourceExists"] = bool(row["legacy_source_exists"])
                try:
                    status["copiedTables"] = json.loads(row["copied_tables_json"] or "[]")
                except Exception:
                    status["copiedTables"] = []
                try:
                    status["skippedTables"] = json.loads(row["skipped_tables_json"] or "[]")
                except Exception:
                    status["skippedTables"] = []
                try:
                    status["notes"] = json.loads(row["notes_json"] or "[]")
                except Exception:
                    status["notes"] = []
    except Exception as exc:
        status["notes"] = [f"status_read_failed:{exc}"]

    return status


def _sync_sqlite_sequence(conn: sqlite3.Connection, table: str) -> None:
    try:
        columns = conn.execute(f"PRAGMA main.table_info([{table}])").fetchall()
        pk_names = [str(r["name"]) for r in columns if int(r["pk"] or 0) == 1]
        if len(pk_names) != 1:
            return
        pk_name = pk_names[0]
        max_value = conn.execute(f"SELECT MAX([{pk_name}]) FROM main.[{table}]").fetchone()[0]
        if max_value is None:
            return
        conn.execute("DELETE FROM sqlite_sequence WHERE name=?", (table,))
        conn.execute(
            "INSERT INTO sqlite_sequence(name, seq) VALUES (?, ?)",
            (table, int(max_value)),
        )
    except Exception:
        pass


def migrate_component_tables(
    *,
    component: str,
    live_db_path: Path,
    legacy_source_db_path: Path,
    owned_tables: Iterable[str],
    logger: logging.Logger | None = None,
) -> Dict[str, Any]:
    live_db_path = Path(live_db_path)
    legacy_source_db_path = Path(legacy_source_db_path)
    owned = list(owned_tables)
    log = logger or logging.getLogger(__name__)

    with _connect(live_db_path) as conn:
        _ensure_status_table(conn)
        existing = conn.execute(
            f"SELECT * FROM {STORAGE_STATUS_TABLE} WHERE component=?",
            (component,),
        ).fetchone()
        if existing and (existing["migration_state"] or "") in (MIGRATION_COMPLETED, MIGRATION_SOURCE_MISSING):
            return read_component_storage_status(
                component=component,
                live_db_path=live_db_path,
                legacy_source_db_path=legacy_source_db_path,
                owned_tables=owned,
            )

    copied_tables: List[str] = []
    skipped_tables: List[str] = []
    notes: List[str] = []
    ran_at = _utc_now_iso()

    if not legacy_source_db_path.exists():
        with _connect(live_db_path) as conn:
            _ensure_status_table(conn)
            notes.append("legacy_source_missing")
            _upsert_status(
                conn,
                component=component,
                live_db_path=live_db_path,
                legacy_source_db_path=legacy_source_db_path,
                migration_state=MIGRATION_SOURCE_MISSING,
                migration_ran_at=ran_at,
                migration_completed_at=ran_at,
                legacy_source_exists=False,
                copied_tables=copied_tables,
                skipped_tables=list(owned),
                notes=notes,
            )
            conn.commit()
        return read_component_storage_status(
            component=component,
            live_db_path=live_db_path,
            legacy_source_db_path=legacy_source_db_path,
            owned_tables=owned,
        )

    if live_db_path.resolve() == legacy_source_db_path.resolve():
        with _connect(live_db_path) as conn:
            _ensure_status_table(conn)
            notes.append("live_db_matches_legacy_source")
            _upsert_status(
                conn,
                component=component,
                live_db_path=live_db_path,
                legacy_source_db_path=legacy_source_db_path,
                migration_state=MIGRATION_COMPLETED,
                migration_ran_at=ran_at,
                migration_completed_at=ran_at,
                legacy_source_exists=True,
                copied_tables=copied_tables,
                skipped_tables=list(owned),
                notes=notes,
            )
            conn.commit()
        return read_component_storage_status(
            component=component,
            live_db_path=live_db_path,
            legacy_source_db_path=legacy_source_db_path,
            owned_tables=owned,
        )

    try:
        with _connect(live_db_path) as conn:
            _ensure_status_table(conn)
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("ATTACH DATABASE ? AS legacy", (str(legacy_source_db_path),))
            legacy_tables = set(_list_tables(conn, schema="legacy"))
            for table in owned:
                if table not in legacy_tables:
                    skipped_tables.append(table)
                    continue
                if not _table_exists(conn, table, schema="main"):
                    skipped_tables.append(table)
                    notes.append(f"target_missing:{table}")
                    continue

                target_cols = _table_columns(conn, table, schema="main")
                legacy_cols = _table_columns(conn, table, schema="legacy")
                common_cols = [col for col in target_cols if col in legacy_cols]
                if not common_cols:
                    skipped_tables.append(table)
                    notes.append(f"no_common_columns:{table}")
                    continue

                cols_sql = ", ".join(f"[{col}]" for col in common_cols)
                conn.execute(f"DELETE FROM main.[{table}]")
                conn.execute(
                    f"INSERT INTO main.[{table}] ({cols_sql}) SELECT {cols_sql} FROM legacy.[{table}]"
                )
                _sync_sqlite_sequence(conn, table)
                copied_tables.append(table)

            _upsert_status(
                conn,
                component=component,
                live_db_path=live_db_path,
                legacy_source_db_path=legacy_source_db_path,
                migration_state=MIGRATION_COMPLETED,
                migration_ran_at=ran_at,
                migration_completed_at=ran_at,
                legacy_source_exists=True,
                copied_tables=copied_tables,
                skipped_tables=skipped_tables,
                notes=notes,
            )
            conn.commit()

        if copied_tables:
            log.info(
                "%s DB migration completed from legacy source into %s (%s tables copied).",
                component.upper(),
                live_db_path,
                len(copied_tables),
            )
        else:
            log.info(
                "%s DB migration completed with no owned legacy tables to copy.",
                component.upper(),
            )
    except Exception as exc:
        try:
            with _connect(live_db_path) as conn:
                _ensure_status_table(conn)
                notes.append(f"migration_failed:{exc}")
                _upsert_status(
                    conn,
                    component=component,
                    live_db_path=live_db_path,
                    legacy_source_db_path=legacy_source_db_path,
                    migration_state=MIGRATION_FAILED,
                    migration_ran_at=ran_at,
                    migration_completed_at=None,
                    legacy_source_exists=legacy_source_db_path.exists(),
                    copied_tables=copied_tables,
                    skipped_tables=skipped_tables,
                    notes=notes,
                )
                conn.commit()
        except Exception:
            pass
        raise

    return read_component_storage_status(
        component=component,
        live_db_path=live_db_path,
        legacy_source_db_path=legacy_source_db_path,
        owned_tables=owned,
    )


__all__ = [
    "ACCESS_OWNED_TABLES",
    "MIGRATION_COMPLETED",
    "MIGRATION_FAILED",
    "MIGRATION_NOT_STARTED",
    "MIGRATION_SOURCE_MISSING",
    "STORAGE_STATUS_TABLE",
    "TV_OWNED_TABLES",
    "migrate_component_tables",
    "read_component_storage_status",
]

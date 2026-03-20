"""TV-owned connection helpers over the live TV SQLite store."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List

from shared.auth_state import AuthTokenState, protect_auth_token, unprotect_auth_token
from shared.desktop_paths import get_desktop_path_layout
from shared.runtime_support import ensure_dirs
from shared.storage_migration import TV_OWNED_TABLES, read_component_storage_status
from tv.storage import current_tv_runtime_db_path


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    ensure_dirs()
    db_path = current_tv_runtime_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _table_columns(conn: sqlite3.Connection, table: str) -> List[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info([{table}])").fetchall()
        return [str(r["name"]) for r in rows]
    except Exception:
        return []


def _ensure_column(conn: sqlite3.Connection, table: str, col_name: str, col_def_sql: str) -> None:
    cols = set(_table_columns(conn, table))
    if col_name in cols:
        return
    try:
        conn.execute(f"ALTER TABLE [{table}] ADD COLUMN {col_def_sql}")
    except Exception:
        pass


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _ensure_tv_backend_auth_state_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tv_backend_auth_state (
            id INTEGER PRIMARY KEY CHECK (id=1),
            email TEXT,
            token_protected TEXT,
            last_login_at TEXT,
            imported_from TEXT,
            imported_at TEXT
        );
        """
    )
    _ensure_column(conn, "tv_backend_auth_state", "email", "email TEXT")
    _ensure_column(conn, "tv_backend_auth_state", "token_protected", "token_protected TEXT")
    _ensure_column(conn, "tv_backend_auth_state", "last_login_at", "last_login_at TEXT")
    _ensure_column(conn, "tv_backend_auth_state", "imported_from", "imported_from TEXT")
    _ensure_column(conn, "tv_backend_auth_state", "imported_at", "imported_at TEXT")


def save_tv_backend_auth_state(
    *,
    email: str,
    token: str,
    last_login_at: str | None = None,
    imported_from: str | None = None,
) -> None:
    with get_conn() as conn:
        _ensure_tv_backend_auth_state_table(conn)
        conn.execute(
            """
            INSERT INTO tv_backend_auth_state (
                id, email, token_protected, last_login_at, imported_from, imported_at
            )
            VALUES (1, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                email=excluded.email,
                token_protected=excluded.token_protected,
                last_login_at=excluded.last_login_at,
                imported_from=excluded.imported_from,
                imported_at=excluded.imported_at
            """,
            (
                (email or "").strip(),
                protect_auth_token(token),
                (last_login_at or _utc_now_iso()).strip(),
                (imported_from or "").strip() or None,
                _utc_now_iso() if imported_from else None,
            ),
        )
        conn.commit()


def clear_tv_backend_auth_state() -> None:
    with get_conn() as conn:
        _ensure_tv_backend_auth_state_table(conn)
        conn.execute("DELETE FROM tv_backend_auth_state WHERE id=1")
        conn.commit()


def _load_local_tv_backend_auth_state(conn: sqlite3.Connection) -> AuthTokenState | None:
    _ensure_tv_backend_auth_state_table(conn)
    row = conn.execute(
        "SELECT email, token_protected, last_login_at FROM tv_backend_auth_state WHERE id=1"
    ).fetchone()
    if not row:
        return None
    token = unprotect_auth_token(row["token_protected"] or "")
    if not token:
        return None
    return AuthTokenState(
        email=(row["email"] or "").strip(),
        token=token,
        last_login_at=(row["last_login_at"] or "").strip(),
    )


def load_tv_backend_auth_state() -> AuthTokenState | None:
    with get_conn() as conn:
        return _load_local_tv_backend_auth_state(conn)


def get_tv_storage_status() -> Dict[str, Any]:
    layout = get_desktop_path_layout()
    return read_component_storage_status(
        component="tv",
        live_db_path=current_tv_runtime_db_path(),
        legacy_source_db_path=layout.legacy_combined_db_path,
        owned_tables=TV_OWNED_TABLES,
    )


__all__ = [
    "_ensure_column",
    "clear_tv_backend_auth_state",
    "current_tv_runtime_db_path",
    "get_conn",
    "get_tv_storage_status",
    "load_tv_backend_auth_state",
    "save_tv_backend_auth_state",
]

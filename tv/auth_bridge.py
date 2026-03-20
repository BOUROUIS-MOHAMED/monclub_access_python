"""Transitional TV auth compatibility helpers.

This module keeps the remaining auth-compatibility seam explicit:
- TV owns its live auth row in tv.db
- Access may mirror auth into TV on a best-effort basis
- TV may import auth one time from access.db or legacy app.db if its own row is empty

It is intentionally small so the compatibility behavior does not leak back into
the general TV storage boundary.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from shared.auth_state import AuthTokenState, unprotect_auth_token
from shared.desktop_paths import get_desktop_path_layout
from tv.store import clear_tv_backend_auth_state, load_tv_backend_auth_state, save_tv_backend_auth_state


def _read_access_auth_state_from(path: Path) -> AuthTokenState | None:
    if not path.exists():
        return None
    conn = sqlite3.connect(str(path), check_same_thread=False, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT email, token_protected, last_login_at FROM auth_state WHERE id=1"
        ).fetchone()
    finally:
        conn.close()
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


def import_access_auth_into_tv_if_missing() -> AuthTokenState | None:
    current = load_tv_backend_auth_state()
    if current:
        return current

    layout = get_desktop_path_layout()
    for candidate in (layout.access_db_path, layout.legacy_combined_db_path):
        try:
            state = _read_access_auth_state_from(Path(candidate))
            if not state:
                continue
            save_tv_backend_auth_state(
                email=state.email,
                token=state.token,
                last_login_at=state.last_login_at,
                imported_from=str(candidate),
            )
            return state
        except Exception:
            continue
    return None


def load_tv_auth_for_runtime() -> AuthTokenState | None:
    current = load_tv_backend_auth_state()
    if current:
        return current
    return import_access_auth_into_tv_if_missing()


def mirror_access_auth_to_tv(*, email: str, token: str, last_login_at: str | None = None) -> None:
    save_tv_backend_auth_state(email=email, token=token, last_login_at=last_login_at)


def clear_tv_auth_bridge_state() -> None:
    clear_tv_backend_auth_state()


__all__ = [
    "clear_tv_auth_bridge_state",
    "import_access_auth_into_tv_if_missing",
    "load_tv_auth_for_runtime",
    "mirror_access_auth_to_tv",
]

"""Small persistence helpers for P3b-2 (the ``v2_kv`` table and friends in db.init_db).

Reads use ``get_conn``; writes go through the DbWriter thread like every other write here.
"""
from __future__ import annotations

import json
import time
from typing import Any, Optional


def kv_get(key: str) -> Optional[Any]:
    from app.core.db import get_conn

    try:
        with get_conn() as conn:
            row = conn.execute("SELECT value_json FROM v2_kv WHERE key = ?", (str(key),)).fetchone()
    except Exception:
        return None
    if not row:
        return None
    try:
        return json.loads(row[0])
    except Exception:
        return None


def kv_put(key: str, value: Any, *, durable: bool = False) -> None:
    from app.core.db import _run_db_write_sync

    raw = json.dumps(value, separators=(",", ":"), sort_keys=True)

    def op(conn, _profile):
        conn.execute(
            "INSERT INTO v2_kv (key, value_json, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
            (str(key), raw, time.time()),
        )

    _run_db_write_sync(f"v2_kv:{key}", op, durable=durable)


def kv_delete(key: str) -> None:
    from app.core.db import _run_db_write_sync

    _run_db_write_sync(f"v2_kv_del:{key}", lambda conn, _p: conn.execute("DELETE FROM v2_kv WHERE key = ?", (str(key),)))

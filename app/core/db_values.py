"""Value coercions shared by db.py and sync_device_store.py.

Moved out of db.py unchanged (ULTRA merge plan 2, Task 1). db.py re-imports every name.
"""
from __future__ import annotations

from typing import Any


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

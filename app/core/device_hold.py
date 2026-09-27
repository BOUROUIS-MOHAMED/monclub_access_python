"""Turnstiles on hold: MonClub writes nothing to them until an operator presses Refill.

Set by the Erase-content wizard (``app/core/erase_wizard.py``) before it reads its backup, and
kept after an erase whose refill option is "Hold until I press Refill" -- the cutover night
erases a terminal, switches its pin scheme to "Par personne", restarts Access, and only then
refills it. So the hold is DURABLE (``db.device_write_hold``) and loaded before the first sync
tick can start a worker (``MainApp.__init__``).

What it stops is exactly what a handover's write freeze stops, at the same gates (guide §3.2h):
the ULTRA worker's member drain, full-sync drain, mid-push chunks and maintenance slot
(``ultra_engine._v2_writes_blocked``), and the PullSDK engine's pass, its batch and its targeted
member sync (``device_sync``). The door, the events and the rescues keep running. Reading it is
one lookup in an immutable set: no lock, no database -- it sits on the worker loop.
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Dict, FrozenSet, Optional

_log = logging.getLogger("zkapp.device_hold")

_lock = threading.Lock()
_held: FrozenSet[int] = frozenset()


def _as_id(value: Any) -> Optional[int]:
    try:
        did = int(value)
    except (TypeError, ValueError):
        return None
    return did if did > 0 else None


def is_held(device_id: Any) -> bool:
    did = _as_id(device_id)
    return did is not None and did in _held


def held_ids() -> FrozenSet[int]:
    return _held


def load() -> FrozenSet[int]:
    """Install the holds recorded in the database (start-up). A read failure keeps what is
    installed and is logged: it is re-raised to the caller, which decides."""
    global _held
    from app.core.db import list_device_write_holds

    ids = frozenset(int(d) for d in (list_device_write_holds() or {}))
    with _lock:
        _held = ids
    if ids:
        _log.warning("[HOLD] turnstile(s) on hold since an erase, nothing is written to them "
                     "until Refill: %s", ",".join(str(d) for d in sorted(ids)))
    return ids


def hold(device_id: int, *, reason: str = "erase", run_id: Optional[str] = None) -> None:
    """Hold a turnstile. The database row is written (durably) BEFORE the in-memory gate, so a
    crash cannot leave a hold that the next start forgets."""
    global _held
    did = _as_id(device_id)
    if did is None:
        raise ValueError(f"bad device id {device_id!r}")
    from app.core.db import set_device_write_hold

    set_device_write_hold(device_id=did, reason=reason, run_id=run_id)
    with _lock:
        _held = frozenset(_held | {did})
    _log.warning("[HOLD] turnstile %s on hold (%s, run %s): nothing is written to it", did,
                 reason, run_id)


def release(device_id: int) -> bool:
    """Release a turnstile's hold. The gate opens only once the row is gone. Returns whether
    it was held."""
    global _held
    did = _as_id(device_id)
    if did is None:
        return False
    from app.core.db import clear_device_write_hold

    removed = clear_device_write_hold(device_id=did)
    with _lock:
        was = did in _held
        _held = frozenset(_held - {did})
    if was or removed:
        _log.warning("[HOLD] turnstile %s released: MonClub writes to it again", did)
    return bool(was or removed)


def holds_detail() -> Dict[int, Dict[str, Any]]:
    """The recorded holds with their reason, run and time (a database read)."""
    from app.core.db import list_device_write_holds

    return dict(list_device_write_holds() or {})


def reset_for_tests() -> None:
    global _held
    with _lock:
        _held = frozenset()

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

A start-up load that FAILS holds every turnstile (fail closed, review round 1): not knowing which
turnstile is held must not let the first pass refill one under the pin scheme recorded before the
switch. ``ensure_loaded`` (every sync tick) retries until the read succeeds.
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Dict, FrozenSet, Optional

_log = logging.getLogger("zkapp.device_hold")

_lock = threading.Lock()
_held: FrozenSet[int] = frozenset()
_load_failed = False


def _as_id(value: Any) -> Optional[int]:
    try:
        did = int(value)
    except (TypeError, ValueError):
        return None
    return did if did > 0 else None


def is_held(device_id: Any) -> bool:
    did = _as_id(device_id)
    return did is not None and (_load_failed or did in _held)


def held_ids() -> FrozenSet[int]:
    """The turnstiles recorded on hold. While ``load_failed()`` every turnstile reads as held
    (``is_held``) and this set is only what was installed before."""
    return _held


def load_failed() -> bool:
    return _load_failed


def load() -> FrozenSet[int]:
    """Install the holds recorded in the database (start-up). A read failure HOLDS EVERY
    turnstile until a later ``load`` succeeds, and is re-raised to the caller."""
    global _held, _load_failed
    from app.core.db import list_device_write_holds

    # Under the lock for the read AND the install: a hold() or release() landing between the
    # two would otherwise be overwritten by a stale read (review round 2, R2-5).
    with _lock:
        try:
            ids = frozenset(int(d) for d in (list_device_write_holds() or {}))
        except Exception:
            _load_failed = True
            raise
        _held = ids
        _load_failed = False
    if ids:
        _log.warning("[HOLD] turnstile(s) on hold since an erase, nothing is written to them "
                     "until Refill: %s", ",".join(str(d) for d in sorted(ids)))
    return ids


def ensure_loaded() -> bool:
    """Retry a failed start-up load (the sync tick). No database read when the holds are
    loaded. Returns whether they are."""
    if not _load_failed:
        return True
    try:
        load()
    except Exception:
        _log.error("[HOLD] erase holds still unreadable: every turnstile stays on hold",
                   exc_info=True)
        return False
    _log.warning("[HOLD] erase holds read after a failed start-up load")
    return True


def hold(device_id: int, *, reason: str = "erase", run_id: Optional[str] = None) -> None:
    """Hold a turnstile. The database row is written (durably) BEFORE the in-memory gate, so a
    crash cannot leave a hold that the next start forgets."""
    global _held
    did = _as_id(device_id)
    if did is None:
        raise ValueError(f"bad device id {device_id!r}")
    from app.core.db import set_device_write_hold

    with _lock:
        set_device_write_hold(device_id=did, reason=reason, run_id=run_id)
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

    with _lock:
        removed = clear_device_write_hold(device_id=did)
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
    global _held, _load_failed
    with _lock:
        _held = frozenset()
        _load_failed = False

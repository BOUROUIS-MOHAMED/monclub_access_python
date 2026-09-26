"""Loss detection and re-add (owner decision 6, 2026-09-26).

A member MonClub pushed can disappear from a terminal (another system, someone at the
terminal's menu). Only those members are re-added; a user MonClub cannot prove it owns is never
touched (re-adding writes a user only at a pin that is ABSENT from the terminal).

* **What is missing**: pins MonClub owns (``ownership_confirmed = 1``) that are absent from a
  TRUSTED listing of the terminal. Trusted = a successful listing that shows at least one pin
  MonClub owns, and whose missing set is within the removal ceiling
  (``max(10, 25 % of what MonClub owns)``). P3a-2's first attempt re-pushed most of the roster
  after a listing cut short (review R6-02/03): a listing that loses more than the ceiling is
  not believed — reported (``MISSING_OWNED``) and nothing is re-added.
* **What is re-added**: missing pins still in the last COMPLETE desired roster, through a
  separate marker (``v2_readd``) that the next pass reads — never by clearing ``desired_hash``
  or ``last_ok`` (that reset the retry clock of pins in backoff, R6-03). At most
  ``READD_MAX_PER_PASS`` a pass; a marker is dropped once the pin's push is confirmed, or after
  ``READD_MAX_ATTEMPTS`` passes.
* **When** (MB2000): the daily intent read-back when it runs, and an extra one when the user
  count read at connect dropped by more than MonClub itself removed since the last connect.
  The PullSDK path already re-pushes a desired pin missing from its per-pass PIN read (the
  existing F-011 drift check); only its ``MISSING_OWNED`` report is new.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, Iterable, Optional, Set

from app.core.v2 import problems as _problems

_log = logging.getLogger("zkapp.v2.loss")

READD_MAX_PER_PASS = 50
READD_MAX_ATTEMPTS = 3
ABSOLUTE_FLOOR = 10
FRACTION = 0.25


def trusted_ceiling(owned_count: int) -> float:
    return max(float(ABSOLUTE_FLOOR), max(0, int(owned_count)) * FRACTION)


_enabled = False


def set_enabled(value: bool) -> None:
    """Loss re-add runs only while the server has v2 (seen ON in this process, or roles cached
    from it): on an old server the PC behaves exactly as before (review R5)."""
    global _enabled
    _enabled = bool(value)


def is_enabled() -> bool:
    return _enabled


def evaluate_listing(device_id: int, *, on_device: Iterable[str], owned: Iterable[str],
                     desired: Optional[Iterable[str]]) -> Dict[str, Any]:
    """Decide what a listing says was lost; record MISSING_OWNED; mark re-adds."""
    on = {str(p).strip() for p in on_device if str(p).strip()}
    own = {str(p).strip() for p in owned if str(p).strip()}
    missing = sorted(own - on)
    trusted = bool(on) and bool(own & on) and len(missing) <= trusted_ceiling(len(own))
    out: Dict[str, Any] = {"missing": missing, "trusted": trusted, "readd": []}
    if not on or not (own & on):
        return out                      # an untrustworthy listing changes nothing, reports nothing
    if missing:
        _problems.registry.set_code(device_id, _problems.MISSING_OWNED, missing, count=len(missing))
    else:
        _problems.registry.clear_code(device_id, _problems.MISSING_OWNED)
    if not trusted or desired is None or not _enabled:
        if missing and not trusted:
            _log.warning("[V2] loss check turnstile %s: %d owned pin(s) absent -- more than the "
                         "ceiling (%.0f), so the listing is not believed: reported, nothing re-added",
                         device_id, len(missing), trusted_ceiling(len(own)))
        return out
    want = {str(p).strip() for p in desired}
    readd = [p for p in missing if p in want]
    if readd:
        mark_readd(device_id, readd)
        _log.warning("[V2] loss check turnstile %s: %d MonClub member(s) missing from the terminal "
                     "will be pushed again: %s", device_id, len(readd), ",".join(readd[:20]))
    out["readd"] = readd
    return out


def mark_readd(device_id: int, pins: Iterable[str]) -> None:
    from app.core.db import _run_db_write_sync
    now = time.time()
    rows = [(int(device_id), str(p), now) for p in pins]

    def op(conn, _p):
        conn.executemany("INSERT OR IGNORE INTO v2_readd (device_id, pin, found_at, attempts) "
                         "VALUES (?, ?, ?, 0)", rows)
    _run_db_write_sync("v2_readd_mark", op)


def readd_pins(device_id: int) -> Set[str]:
    try:
        from app.core.db import get_conn
        with get_conn() as conn:
            rows = conn.execute("SELECT pin FROM v2_readd WHERE device_id = ? AND attempts < ? "
                                "ORDER BY found_at, pin LIMIT ?",
                                (int(device_id), READD_MAX_ATTEMPTS, READD_MAX_PER_PASS)).fetchall()
        return {str(r[0]) for r in rows}
    except Exception:
        return set()


def note_attempts(device_id: int, pins: Iterable[str]) -> None:
    pins = [str(p) for p in pins]
    if not pins:
        return
    from app.core.db import _run_db_write_sync

    def op(conn, _p):
        conn.executemany("UPDATE v2_readd SET attempts = attempts + 1 WHERE device_id = ? AND pin = ?",
                         [(int(device_id), p) for p in pins])
        conn.execute("DELETE FROM v2_readd WHERE device_id = ? AND attempts >= ?",
                     (int(device_id), READD_MAX_ATTEMPTS))
    _run_db_write_sync("v2_readd_attempt", op)


def clear_readd(device_id: int, pins: Iterable[str]) -> None:
    pins = [str(p) for p in pins]
    if not pins:
        return
    from app.core.db import _run_db_write_sync
    _run_db_write_sync("v2_readd_clear", lambda conn, _p: conn.executemany(
        "DELETE FROM v2_readd WHERE device_id = ? AND pin = ?", [(int(device_id), p) for p in pins]))


_counts_lock = __import__("threading").Lock()
_pending_counts: Dict[int, Any] = {}


def note_user_count(device_id: Any, users_now: Any) -> None:
    """Called on the worker thread at connect: memory only."""
    try:
        did = int(device_id)
    except (TypeError, ValueError):
        return
    with _counts_lock:
        _pending_counts[did] = users_now


def pop_user_counts() -> Dict[int, Any]:
    with _counts_lock:
        out = dict(_pending_counts)
        _pending_counts.clear()
    return out


class LossWatch:
    """v2 control-thread step: compares the connect-time user counts (off the door thread) and
    asks the turnstile's worker for a loss check in its maintenance slot. Runs whether or not
    the server has v2 (loss detection is local)."""

    def __init__(self, runtime: Any = None) -> None:
        self.rt = runtime
        self.flagged: Dict[int, float] = {}

    def tick(self, runtime: Any) -> None:
        counts = pop_user_counts()
        if not _enabled:
            return
        for did, count in counts.items():
            try:
                if not user_count_dropped(did, count):
                    continue
            except Exception:
                continue
            eng = getattr(getattr(runtime, "app", None), "_ultra_engine", None)
            worker = (getattr(eng, "_workers", None) or {}).get(did) if eng is not None else None
            if worker is not None:
                worker._loss_check_due = True
                self.flagged[did] = time.time()
                _log.warning("[V2] turnstile %s: user count dropped more than MonClub removed -- a loss "
                             "check (terminal listing) runs in today's maintenance slot", did)

    def status(self) -> Dict[str, Any]:
        return {"lossChecksRequested": {str(k): v for k, v in self.flagged.items()}}


def user_count_dropped(device_id: int, users_now: Any) -> bool:
    """Connect-time check: did the terminal lose users MonClub did not remove?

    Compares the user count read at this connect with the last one (persisted, so a PC off
    overnight compares with yesterday evening); MonClub's own removals since then (the
    removal log) explain part of a drop. Additions by MonClub can hide a loss of the same
    size — the daily read-back remains the backstop."""
    try:
        now_count = int(users_now)
    except (TypeError, ValueError):
        return False
    from app.core.v2 import store
    key = f"usercount:{int(device_id)}"
    prev = store.kv_get(key)
    wall = time.time()
    try:
        store.kv_put(key, {"count": now_count, "at": wall})
    except Exception:
        pass
    if not isinstance(prev, dict):
        return False
    try:
        prev_count, prev_at = int(prev.get("count")), float(prev.get("at"))
    except (TypeError, ValueError):
        return False
    drop = prev_count - now_count
    if drop <= 0:
        return False
    try:
        from app.core.db import get_conn
        with get_conn() as conn:
            removed = conn.execute("SELECT COUNT(*) FROM v2_removal_log WHERE device_id = ? AND removed_at >= ?",
                                   (int(device_id), prev_at - 600.0)).fetchone()[0]
    except Exception:
        removed = 0
    return drop > int(removed or 0)

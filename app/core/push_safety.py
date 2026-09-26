"""Safety rails shared by every turnstile push path (P3a-2, guide §3.2g).

A leaf module: it imports only telemetry, so both ``device_sync`` (PullSDK) and
``ultra_engine`` (ZK_STANDALONE) can use it without an import cycle.

ONE removal ceiling
-------------------
Every bulk removal from a terminal -- the standalone revoke pass, the PullSDK
stale-pin delete, and any table clear -- goes through :func:`check_bulk_removal`.
Above ``max(REVOKE_ABSOLUTE_FLOOR, roster * MAX_DELETE_FRACTION)`` the removal step
is refused, nothing is removed, the per-pin state is kept (so a later pass can still
remove them once the cause is understood) and ``[T] REVOKE_ABORTED`` is emitted with
the count. The rest of the pass continues.

The ceiling was the standalone revoke pass's own rule (``ultra_engine`` before
P3a-2). The PullSDK INCREMENTAL "nuke-and-repave" heuristic fired when
``stale > desired and stale > 10``; that condition is always above this ceiling
(roster R <= 40: ceiling 10 < stale; R > 40: 0.25 R < R < stale), so routing every
removal through it retires the automatic wipe everywhere.

ABORTED is not SKIPPED
----------------------
``REVOKE_ABORTED`` (above the ceiling, or an empty roster) is RETRYABLE: nothing is
decided about the pins, their state is kept, an explicit revocation that depended on
the step stays unconfirmed. ``SKIPPED_NOT_OWNED`` is FINAL: MonClub cannot prove it
wrote that pin, so it will never delete it; the revocation is finished and the pass
continues. The two must never be confused -- an abort that finalised a revocation
would silently drop it.

P3b-2 (driver leases, Confirm removal)
--------------------------------------
Three more answers, in this order, before the ceiling:

* a turnstile this PC is handing over (``release[]``) or runs ADD-ONLY (a forced handover,
  or its ownership backup not restored yet for the lease it holds) refuses every removal with
  reason ``handover_release`` / ``add_only``: retryable exactly like a ceiling refusal, but
  reported as ``[T] REMOVAL_DEFERRED``, never as ``REVOKE_ABORTED`` (nothing is wrong, the PC
  is waiting for a record it can trust);
* above the ceiling, a "Confirm removal" (``REMOVAL_CONFIRM``) the owner approved for EXACTLY
  this pin set — same count, same canonical hash, not expired, on the standalone revoke pass
  or the PullSDK stale step only — lets that one step through, once;
* every refusal of those two steps is recorded (all its pins) for the turnstile problem
  report; the table clear (which deletes foreign users too) and the renewal release are not.

It still imports no engine module: the lease gate and the problem registry are leaves.
"""
from __future__ import annotations

import logging
from typing import Iterable, NamedTuple

from app.core import telemetry as _tel
from app.core.v2 import lease_gate as _lease_gate
from app.core.v2 import problems as _problems

logger = logging.getLogger(__name__)

# Carried over unchanged from ultra_engine (_REVOKE_ABSOLUTE_FLOOR /
# _MIRROR_MAX_DELETE_FRACTION), which keeps its names as aliases.
REVOKE_ABSOLUTE_FLOOR = 10
MAX_DELETE_FRACTION = 0.25

# Reason codes. Carried in [T] events and in push-batch notes
# (push_batch_history.error_message, served at /api/v2/push-history), which is where
# a later dashboard (P3b/P3c) reads them. The heartbeat wire format is unchanged.
REVOKE_ABORTED = "REVOKE_ABORTED"
SKIPPED_NOT_OWNED = "SKIPPED_NOT_OWNED"
CAPACITY_FULL = "CAPACITY_FULL"
TEMPLATE_VERSION_MISMATCH = "TEMPLATE_VERSION_MISMATCH"
PUSH_CAPPED = "PUSH_CAPPED"


class RemovalVerdict(NamedTuple):
    allowed: bool
    count: int
    roster: int
    ceiling: float
    reason: str  # "" when allowed, else "empty_roster" | "above_ceiling"


def removal_ceiling(roster_count: int) -> float:
    """The most pins one removal step may take off a terminal."""
    return max(float(REVOKE_ABSOLUTE_FLOOR), max(0, int(roster_count or 0)) * MAX_DELETE_FRACTION)


def check_bulk_removal(
    *,
    count: int,
    roster_count: int,
    path: str,
    device_id: object = None,
    protocol: str = "",
    worker: str = "",
    sample: Iterable[str] = (),
) -> RemovalVerdict:
    """Decide whether one removal step may run; report a refusal.

    ``count`` is how many device users the step would remove, ``roster_count`` the
    size of the DESIRED roster for this device (after its filters), ``path`` names
    the step (``standalone_revoke``, ``stale``, ``table_clear``...).

    Nothing to remove is always allowed. An empty desired roster refuses any removal:
    a failed or half-built roster must never read as "everyone left". Above the
    ceiling (strictly greater, as the standalone rule always was) is refused.
    """
    n = max(0, int(count or 0))
    roster = max(0, int(roster_count or 0))
    ceiling = removal_ceiling(roster)
    pins = [str(p) for p in (sample or ())]
    if n <= 0:
        _problems.registry.removal_allowed(device_id, path)
        return RemovalVerdict(True, 0, roster, ceiling, "")
    blocked = _lease_gate.removals_blocked(device_id) if device_id is not None else None
    if blocked:
        try:
            _tel.warn("REMOVAL_DEFERRED", worker=worker or None, device_id=device_id,
                      protocol=protocol or None, path=path, count=n, reason=blocked)
        except Exception:
            pass
        logger.warning(
            "REMOVAL_DEFERRED device=%s path=%s: %d pin(s) kept -- %s (driver lease); "
            "retried once the turnstile's record is trusted.", device_id, path, n, blocked,
        )
        return RemovalVerdict(False, n, roster, ceiling, blocked)
    if roster <= 0:
        reason = "empty_roster"
    elif n > ceiling:
        reason = "above_ceiling"
    else:
        _problems.registry.removal_allowed(device_id, path)
        return RemovalVerdict(True, n, roster, ceiling, "")
    if (reason == "above_ceiling" and path in _problems.CONFIRMABLE_PATHS and len(set(pins)) == n
            and _problems.registry.consume_approval(device_id, pins)):
        try:
            _tel.warn("REMOVAL_CONFIRMED", worker=worker or None, device_id=device_id,
                      protocol=protocol or None, path=path, count=n, roster=roster,
                      ceiling=round(ceiling, 1))
        except Exception:
            pass
        logger.warning(
            "REMOVAL_CONFIRMED device=%s path=%s: %d pin(s) above the ceiling (%.0f) removed "
            "on the owner's Confirm removal for exactly this list.", device_id, path, n, ceiling,
        )
        _problems.registry.removal_allowed(device_id, path)
        return RemovalVerdict(True, n, roster, ceiling, "")
    _problems.registry.revoke_aborted(device_id, path, pins, reason)
    try:
        _tel.warn(
            REVOKE_ABORTED,
            worker=worker or None,
            device_id=device_id,
            protocol=protocol or None,
            path=path,
            count=n,
            roster=roster,
            ceiling=round(ceiling, 1),
            max_frac=MAX_DELETE_FRACTION,
            abs_floor=REVOKE_ABSOLUTE_FLOOR,
            reason=reason,
            sample=",".join(sorted(str(p) for p in sample)[:10]) or None,
        )
    except Exception:
        pass
    logger.warning(
        "REVOKE_ABORTED device=%s path=%s: %d pin(s) would be removed against a desired "
        "roster of %d (ceiling %.0f, reason=%s) -- nothing removed, per-pin state kept; "
        "the rest of the pass continues.",
        device_id, path, n, roster, ceiling, reason,
    )
    return RemovalVerdict(False, n, roster, ceiling, reason)


def outcome_note(code: str, count: int, detail: str = "") -> str:
    """One push-batch note fragment, e.g. ``REVOKE_ABORTED=12 (stale; ceiling 10)``."""
    base = f"{code}={int(count)}"
    return f"{base} ({detail})" if detail else base


def join_notes(*parts: str) -> str:
    return "; ".join(p for p in parts if p)

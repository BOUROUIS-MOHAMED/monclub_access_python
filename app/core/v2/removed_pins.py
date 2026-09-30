"""Revocations MonClub has already carried out (the ownership backup's ``REMOVED`` fact).

A pin is ``REMOVED`` on a turnstile when MonClub itself removed it (``v2_removal_log``, written
in the removal's own transaction) and has not written it since -- no state row, no write-ahead
intent -- under the device's current pin scheme (``ownership.local_facts``, the same fact the
ownership upload sends the server). It also settles SKIPPED_NOT_OWNED turnstile problems
(``settle_skipped``).

The same revocation often reaches a worker twice (gym 45, 2026-09-30): a fast-patch bundle,
then the pull delta that re-derives the deletion; a date-flip pass removes the departed, then
the change detector revokes them. The first removal erases the ownership row the second one
checks, which then read "no MonClub ownership proof" (SKIPPED_NOT_OWNED, a false turnstile
problem). A revocation of a ``REMOVED`` pin is DONE. Nothing is deleted either way: a pin
MonClub never wrote is still never touched, and still reported.

Only a RECENT removal that still STANDS counts (review 2026-09-30): ``v2_removal_log`` rows are
never deleted and a vanished state row reads ``REMOVED`` whatever happened after, so an old
removal (another PC may have written the pin after a handover; a retired terminal may have been
refilled from outside MonClub) or one followed by a push attempt of the pin
(``device_push_result.at`` later) proves nothing about the terminal now. Times are compared on
the PC's clock: a ``corrected`` time (the server's clock) is moved back by the current offset.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, Iterable, List, Optional, Set

from app.core import telemetry as _tel

_log = logging.getLogger("zkapp.v2.removed_pins")

# A removal older than this is no proof: the duplicate revocations seen on gym 45 came 7 s to
# 65 s after the removal (18:03:37 -> 18:03:44; 00:00:08 -> 00:01:13).
RECENT_SEC = 24 * 3600.0


def _offset() -> float:
    from app.core.v2 import server_clock

    clock = server_clock.get_default()
    return (clock.offset() if clock is not None else None) or 0.0


def _pc_time(at: Any, corrected: Any, offset: float) -> float:
    return float(at) - offset if corrected else float(at)


def pin_states(device_id: Any, pins: Iterable[Any]) -> Dict[str, Dict[str, Any]]:
    """pin -> its ownership-backup fact (``state`` APPLIED/FAILED/INTENT/REMOVED; ``removedAt``,
    the PC-clock time of a REMOVED fact whose removal still stands -- no push attempt of the pin
    recorded after it -- else None). A pin with no fact is left out. Raises when unreadable."""
    from app.core.db import get_conn
    from app.core.v2 import ownership

    want = sorted({str(p).strip() for p in pins if str(p).strip()})
    if not want:
        return {}
    offset = _offset()
    facts = ownership.local_facts(int(device_id), offset=offset, pins=want)
    out = {p: {"state": str(facts[p].get("state")), "removedAt": None} for p in want if p in facts}
    removed = [p for p, f in out.items() if f["state"] == "REMOVED"]
    if removed:
        with get_conn() as conn:
            attempts = {str(r[0]): _pc_time(r[1], r[2], offset) for r in conn.execute(
                f"SELECT pin, at, corrected FROM device_push_result WHERE device_id = ? AND at IS NOT "
                f"NULL AND pin IN ({','.join('?' * len(removed))})", (int(device_id), *removed))}
        for p in removed:
            at = _pc_time(facts[p]["at"], facts[p].get("corrected"), offset)
            if p not in attempts or attempts[p] <= at:
                out[p]["removedAt"] = at
    return out


def already_removed(device_id: Any, pins: Iterable[Any]) -> Set[str]:
    """The pins MonClub removed from this turnstile within ``RECENT_SEC`` and has not tried to
    write since. An unreadable record proves nothing: empty, so the caller reports as before."""
    try:
        now = time.time()
        return {p for p, f in pin_states(device_id, pins).items()
                if f["removedAt"] is not None and now - f["removedAt"] <= RECENT_SEC}
    except Exception:
        _log.warning("[V2] turnstile %s: removal record unreadable -- not-owned pins are reported "
                     "as usual", device_id, exc_info=True)
        return set()


def settle_unowned(device_id: Any, prefix: str, tel_wid: str, not_owned: Dict[int, str], *,
                   rows_seen: Optional[Set[str]] = None) -> Dict[int, str]:
    """Finish revocations of pins MonClub does not own ({membership: pin}); none is deleted.

    Already removed by MonClub: DONE, one INFO line + ``MEMBER_REVOKE_DONE mode=already_removed``
    each. Every other one is SKIPPED_NOT_OWNED as before (P3a-2 item 4): CRITICAL line, telemetry
    and the turnstile problem. ``rows_seen``: the full-sync pass's state rows (its line names an
    "unconfirmed" or "absent" row); None for a targeted revoke. Returns the SKIPPED ones.
    """
    done = already_removed(device_id, not_owned.values())
    skipped: Dict[int, str] = {}
    for member_id, pin in sorted(not_owned.items()):
        if pin in done:
            _log.info("%s revocation of membership %s: pin %s was already removed by MonClub -- "
                      "nothing left to delete, revocation finished", prefix, member_id, pin)
            _tel.event("MEMBER_REVOKE_DONE", worker=tel_wid, member_id=member_id, pin=pin,
                       mode="already_removed", ok=True)
            continue
        skipped[member_id] = pin
        extra: Dict[str, Any] = {}
        if rows_seen is None:
            _log.critical("%s member revoke SKIPPED_NOT_OWNED: no MonClub ownership proof for pin %s "
                          "-- nothing deleted, revocation finished", prefix, pin)
        else:
            extra["row"] = "unconfirmed" if pin in rows_seen else "absent"
            _log.critical("%s revocation SKIPPED_NOT_OWNED: membership %s pin %s (%s row) -- MonClub "
                          "has no proof it wrote this device user, so it is never deleted; the rest "
                          "of the pass continues", prefix, member_id, pin, extra["row"])
        try:
            _tel.warn("MEMBER_REVOKE_SKIPPED_NOT_OWNED", worker=tel_wid, member_id=member_id,
                      pin=pin, protocol="ZK_STANDALONE", **extra)
        except Exception:
            pass
    if skipped:
        try:
            from app.core.v2 import problems as _problems
            _problems.registry.skipped_not_owned(device_id, skipped.values())
        except Exception:
            pass
    return skipped


def settle_skipped(device_id: Any) -> List[str]:
    """Resolve the turnstile's SKIPPED_NOT_OWNED pins the local record now settles: MonClub owns
    the pin again (``APPLIED``: re-pushed and confirmed, or proven by the intent read-back) or
    removed it AFTER the skip was recorded (a standing ``REMOVED``; an older removal was already
    on record when the skip was decided). Run before each problem report, so the next one tells the
    server (a code left out of a snapshot is resolved there). An unreadable record resolves
    nothing. Returns the resolved pins."""
    from app.core.v2.problems import registry

    checked_at = time.time()
    pins = registry.skipped_pins(device_id)
    if not pins:
        return []
    try:
        states = pin_states(device_id, pins)
    except Exception:
        _log.debug("[V2] turnstile %s: SKIPPED_NOT_OWNED not re-checked (record unreadable)",
                   device_id, exc_info=True)
        return []
    done = sorted(p for p, f in states.items() if f["state"] == "APPLIED"
                  or (f["removedAt"] is not None and f["removedAt"] > pins[p]))
    if done:
        registry.resolve_skipped(device_id, done, recorded_before=checked_at)
        _log.info("[V2] turnstile %s: SKIPPED_NOT_OWNED resolved for %d pin(s) MonClub re-pushed "
                  "or removed since: %s", device_id, len(done), ",".join(done[:20]))
    return done

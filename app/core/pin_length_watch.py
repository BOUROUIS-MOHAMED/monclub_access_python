"""PIN length watch: how long is the longest PIN a push to each turnstile has confirmed, and is
a failing push the first one of a longer PIN?

Why: a device PIN is ``main_account.id`` (pinScheme ACCOUNT) or ``active_membership.id``
(MEMBERSHIP), both auto-increment. Until 2026-11 every id in production had at most 5 digits, so
no turnstile has ever received a longer PIN. How many digits each controller model stores is not
field-proven. The day the ids reach 6 digits, this module says in the log, per turnstile, whether
the first longer PIN was confirmed or refused.

OBSERVATION ONLY. Nothing here decides what is pushed, withheld or removed, and nothing here can
fail a push: every entry point swallows its own errors. It is fed from the one place every push
result of both SDKs is recorded, ``db.record_push_results``.

What a line does and does not prove:
* ``PIN_LENGTH_FIRST_PUSH_OK`` -- the driver CONFIRMED a write of a PIN this long. It does not
  prove the terminal stored every digit: a terminal that silently cut a PIN would confirm too.
  Only a door event that comes back with the full PIN proves that.
* ``PIN_LENGTH_PUSH_FAILED`` -- a push failed for a PIN longer than any confirmed on this
  turnstile. The length is a suspect, not a verdict: the result code names what the driver saw.

The longest confirmed length is read from ``device_push_result`` once per turnstile and process,
then kept in memory. A restore or an erase makes results unknown (``ok`` NULL), so after a restart
the baseline can be lower than before and ``PIN_LENGTH_FIRST_PUSH_OK`` can be said again. That is
a repeated information line, never a wrong one.
"""
from __future__ import annotations

import threading
from typing import Any, Callable, Dict, Iterable, Optional, Set, Tuple

from app.core import telemetry as _tel

_lock = threading.Lock()
# device_id -> digits of the longest PIN whose push this process knows as confirmed.
_longest_ok: Dict[int, int] = {}
# (device_id, digits, code) already reported as PIN_LENGTH_PUSH_FAILED by this process.
_failed_said: Set[Tuple[int, int, str]] = set()


def reset_for_tests() -> None:
    with _lock:
        _longest_ok.clear()
        _failed_said.clear()


def baseline(device_id: Any, load: Callable[[int], Optional[int]]) -> Optional[int]:
    """Digits of the longest PIN confirmed on this turnstile BEFORE the write being recorded.

    ``load(device_id)`` reads it from storage; it is called once per turnstile and process.
    None when it cannot be known (the caller then observes nothing). Never raises.
    """
    try:
        did = int(device_id)
        with _lock:
            known = _longest_ok.get(did)
        if known is not None:
            return known
        loaded = load(did)
        digits = int(loaded or 0)
        with _lock:
            # Another thread may have recorded a longer confirmed PIN while this one read.
            digits = max(digits, _longest_ok.get(did, 0))
            _longest_ok[did] = digits
        return digits
    except Exception:
        return None


def observe(device_id: Any, rows: Iterable[tuple], longest_before: Optional[int]) -> None:
    """Look at the push results just recorded: ``rows`` = ``(pin, ok, code)``.

    ``longest_before`` is ``baseline()`` taken before the write. Never raises.
    """
    try:
        if longest_before is None:
            return
        did = int(device_id)
        longest = int(longest_before)
        first_ok_pin: Dict[int, str] = {}
        failed: Dict[Tuple[int, str], list] = {}
        for row in rows or []:
            pin = str(row[0] if row[0] is not None else "").strip()
            if not pin.isdigit():
                continue
            digits = len(pin)
            if bool(row[1]):
                first_ok_pin.setdefault(digits, pin)
            else:
                code = str(row[2] or "OTHER") if len(row) > 2 else "OTHER"
                failed.setdefault((digits, code), []).append(pin)

        new_longest = max(first_ok_pin, default=0)
        if new_longest > longest:
            with _lock:
                already = _longest_ok.get(did, 0)
                if new_longest > already:
                    _longest_ok[did] = new_longest
            if new_longest > already:
                _tel.event("PIN_LENGTH_FIRST_PUSH_OK", device_id=did, digits=new_longest,
                           previous=longest, pin=first_ok_pin[new_longest])
            longest = max(longest, new_longest)

        for (digits, code), pins in sorted(failed.items()):
            if digits <= longest:
                continue
            key = (did, digits, code)
            with _lock:
                if key in _failed_said:
                    continue
                _failed_said.add(key)
            _tel.warn("PIN_LENGTH_PUSH_FAILED", device_id=did, digits=digits, longest_ok=longest,
                      code=code, count=len(pins), pin=pins[0])
    except Exception:
        pass

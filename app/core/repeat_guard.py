"""Per-member repeat block for PC-decided entries (ULTRA merge, spec 2026-10-02 sections 3 and 5).

After the PC opened the door for a member -- a QR rescue, or a card the PC decides -- that member
is refused on the same device for ``member_block_seconds``. The refusal goes through
card_decision.py with the reason ``DENY_REPEAT_BLOCK`` (popup, history, and plan 3's refusal
sound), never as a silent drop. Staff are exempt (card_decision decides that, not this module).
A card or a finger the turnstile decided never arms or meets the block: the turnstile opened the
door before the PC learned of it (spec section 3, "Correction recorded during the design").

One guard per ULTRA worker, so per device, like AGENT's AntiFraudGuard (anti_fraud.py), and in
memory: a restart forgets it. Pure apart from its own table: the caller passes the monotonic time.
"""
from __future__ import annotations

import threading
from typing import Any, Dict, Mapping, Optional


def _positive_int(value: Any) -> Optional[int]:
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def member_key(user: Any, account_id: Any = None) -> Optional[str]:
    """The person behind an entry: main account, else user id, else membership; None if unknown.

    ``account_id`` is a matched QR credential's account (verify_totp's ``accountId``), the same
    number as a member row's ``mainAccountId`` (access_verification._account_on_roster compares
    the two), so a QR and a card of one person share the key.
    """
    acc = _positive_int(account_id)
    if acc is None and isinstance(user, Mapping):
        acc = _positive_int(user.get("mainAccountId"))
    if acc is not None:
        return f"acc:{acc}"
    if isinstance(user, Mapping):
        uid = _positive_int(user.get("userId"))
        if uid is not None:
            return f"user:{uid}"
        am = _positive_int(user.get("activeMembershipId"))
        if am is not None:
            return f"am:{am}"
    return None


class RepeatGuard:
    """member key -> monotonic end of its block. Thread-safe (the worker loop and the sync-yield
    path can both decide)."""

    PRUNE_AT = 512

    def __init__(self) -> None:
        self._until: Dict[str, float] = {}
        self._lock = threading.Lock()

    def remaining(self, key: Optional[str], *, now: float) -> float:
        """Seconds left in this member's block at ``now``; 0.0 when not blocked or no key."""
        if not key:
            return 0.0
        with self._lock:
            until = self._until.get(key)
        if until is None:
            return 0.0
        return max(0.0, float(until) - float(now))

    def arm(self, key: Optional[str], seconds: float, *, now: float) -> None:
        """Start (or restart) the block of ``key`` for ``seconds``. No key or 0 s arms nothing."""
        if not key or float(seconds) <= 0:
            return
        with self._lock:
            if len(self._until) >= self.PRUNE_AT:
                self._until = {k: v for k, v in self._until.items() if v > now}
            self._until[key] = float(now) + float(seconds)

    def size(self) -> int:
        with self._lock:
            return len(self._until)

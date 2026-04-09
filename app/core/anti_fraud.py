"""
Anti-fraud guard — in-memory per-device token block store.

Blocks reuse of a card number or QR credential ID on the same device
for a configurable duration after a successful access grant.

Thread-safe. State is intentionally ephemeral (lost on restart).
At gym scale (<100 doors, 30 s TTL) the internal dict stays small enough
that lazy eviction on every record() call is sufficient.
"""
from __future__ import annotations

import math
import threading
import time
from typing import Dict, Tuple


class AntiFraudGuard:
    """
    Key:   (device_id: int, token: str, kind: str)
    Value: expires_at — time.monotonic() float

    kind is "card" or "qr".
    For cards : token = card_no string from the ZKTeco event.
    For QR    : token = credential ID UUID string (stable across TOTP rotations).
    """

    def __init__(self) -> None:
        self._entries: Dict[Tuple[int, str, str], float] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(
        self, device_id: int, token: str, kind: str
    ) -> Tuple[bool, float]:
        """
        Returns (is_blocked, seconds_remaining).
        seconds_remaining is 0.0 when not blocked.
        """
        key = (device_id, token, kind)
        now = time.monotonic()
        with self._lock:
            expires_at = self._entries.get(key, 0.0)
            if expires_at > now:
                return True, expires_at - now
            return False, 0.0

    def record(
        self, device_id: int, token: str, kind: str, duration: float
    ) -> None:
        """
        Record a successful access grant and start the block window.

        Lazily evicts all stale entries on every call (O(n) but n is tiny).
        Overwrites any existing entry for the same key — extends the window
        if called again before the previous TTL expires.
        """
        key = (device_id, token, kind)
        now = time.monotonic()
        with self._lock:
            stale = [k for k, exp in self._entries.items() if exp <= now]
            for k in stale:
                del self._entries[k]
            self._entries[key] = now + duration

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def format_remaining(seconds: float) -> str:
        """Human-readable remaining time, e.g. '28s'."""
        return f"{math.ceil(seconds)}s"

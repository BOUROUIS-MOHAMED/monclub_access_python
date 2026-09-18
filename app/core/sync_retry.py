"""Failure-retry schedule for the periodic backend sync (``MainApp.reschedule_sync_timer``).

After a failed ``getSyncData`` the next attempt comes at about 15, 30, 60, 120, then every
300 s (each ±20 % jitter, never above 300 s), and never later than the healthy interval the
app would have used anyway. A ``Retry-After`` the backend sent with a 429 or 503 can push a
retry later, again never past the healthy interval. The first success returns the app to the
healthy interval.
"""
from __future__ import annotations

import random
from typing import Callable, Optional

SYNC_RETRY_STEPS_SEC = (15, 30, 60, 120, 300)
SYNC_RETRY_CAP_SEC = 300
SYNC_RETRY_JITTER_FRACTION = 0.20
_RETRY_AFTER_MAX_SEC = 999_999_999.0


def sync_retry_delay_sec(
    fail_count: int,
    healthy_interval_sec: float,
    *,
    retry_after_sec: Optional[float] = None,
    uniform: Callable[[float, float], float] = random.uniform,
) -> float:
    """Seconds until the next sync attempt after ``fail_count`` consecutive failures."""
    steps = SYNC_RETRY_STEPS_SEC
    step = steps[min(max(int(fail_count), 1), len(steps)) - 1]
    jitter = uniform(-SYNC_RETRY_JITTER_FRACTION, SYNC_RETRY_JITTER_FRACTION)
    delay = min(step * (1.0 + jitter), float(SYNC_RETRY_CAP_SEC))
    if retry_after_sec is not None and retry_after_sec > delay:
        delay = float(retry_after_sec)
    return max(1.0, min(delay, float(healthy_interval_sec)))


def parse_retry_after_sec(value: Optional[str]) -> Optional[float]:
    """``Retry-After`` as delta-seconds; None when absent or not a non-negative integer.

    The backend's RateLimitFilter sends integer seconds. The HTTP-date form is not parsed:
    it is ignored and the normal retry schedule applies.
    """
    text = str(value or "").strip()
    # ASCII digits only: str.isdigit also accepts e.g. "²", which int() rejects.
    if not (text.isascii() and text.isdigit()):
        return None
    # Bounded before int(): a huge value still means "wait long", and sync_retry_delay_sec
    # clamps it to the healthy interval; 10+ digits would overflow float or int() limits.
    if len(text) > 9:
        return _RETRY_AFTER_MAX_SEC
    return float(int(text))

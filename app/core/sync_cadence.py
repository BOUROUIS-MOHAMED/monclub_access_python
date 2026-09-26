"""The healthy sync timer's cadence on a v2 PC -- the promised safety sync (guide §3.6, §3.9).

Pure: no clock, no database. ``MainApp`` decides whether the PC is in safety mode
(``_v2_safety_sync``: the v2 runtime answers ``availability == ON``, the protocol-2 windows are
trusted and the server sent a positive ``syncMeta.reconcileSec``) and whether the notice socket
is connected; this module turns that into the delay of the next healthy sync.

* Not in safety mode -> the healthy interval (``agentSyncBackendRefreshMin``, else
  ``sync_interval_sec``) exactly, as before.
* Socket connected -> at least every ``reconcileSec`` (the server's own hint: "how often an idle
  v2 PC should compare its list with the server's"; 600 s by default), floored at
  ``SAFETY_MIN_SEC``. Notices already bring every change the server announces within seconds; this
  catches what it does not announce.
* Socket down -> every ``SAFETY_SOCKET_DOWN_SEC`` (120 s): the only change detection left, since
  the 45 s members-version probe is gated off in safety mode.
* Never longer than the healthy interval. A shorter cadence is spread by ``uniform(0.8, 1.0)``:
  a server restart drops every socket of a gym at once, and the PCs must not then sync in step.
  The spread only ever brings a sync forward.

The failure-retry schedule (``sync_retry``) and the ``Retry-After`` clamp keep the healthy interval
as their cap: an outage or a 429 is not retried faster because of this cadence.
"""
from __future__ import annotations

import random
from typing import Any, Callable, Mapping, Optional

SAFETY_SOCKET_DOWN_SEC = 120
SAFETY_MIN_SEC = 60
SAFETY_SPREAD_LOW = 0.8

_uniform: Callable[[float, float], float] = random.uniform


def safety_target_sec(safety: Mapping[str, Any]) -> float:
    """The safety cadence before the spread: 120 s with the socket down, else reconcileSec."""
    if not bool(safety.get("socket_connected")):
        return float(SAFETY_SOCKET_DOWN_SEC)
    return float(max(SAFETY_MIN_SEC, int(safety.get("reconcile_sec") or 0)))


def healthy_sync_delay_sec(
    base_sec: float,
    safety: Optional[Mapping[str, Any]],
    *,
    uniform: Optional[Callable[[float, float], float]] = None,
) -> float:
    """Seconds until the next healthy sync. ``safety`` is None outside safety mode."""
    base = float(base_sec)
    if not safety:
        return base
    target = safety_target_sec(safety)
    if target >= base:
        return base
    return target * (uniform or _uniform)(SAFETY_SPREAD_LOW, 1.0)

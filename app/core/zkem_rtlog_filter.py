"""MB2000 (zkemkeeper) RTLog events the ULTRA worker must not process a second time.

Replays (gym 45, 2026-09-30). After the 30-min safety refresh reconnect the terminal delivered
again the last event the worker had already processed: device 10 read
``2026-09-30 15:56:55|ZKPIN:69048|0|1|69048|zkem|10`` live at 15:56:54 and
``...|zkem|1`` at 16:08:08 (device 8 and the 16:38:12 reconnect the same). The event id ends in
the driver's per-connection counter (``zk_standalone.normalize_att_event``, ``_event_seq`` reset
for every new driver), so the worker's ``_is_seen`` never matched, and each replay was a second
ALLOW, popup and history row. A replay is recognised here by its CONTENT -- pin, device time,
door, verify method -- in a bounded memory per turnstile; a real re-scan carries another device
time (one-second resolution) and passes. The pin, not ``cardNo``: the pin->card map is re-read on
every connect. PullSDK events (no ``table == "zkem"``) are never touched.

Limits: the memory is this process's, so a replay delivered at the first connect after an app
restart is not recognised (none was seen after the 07:50 and 17:43 restarts that day).
"""
from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from typing import Any, Dict, Optional, Tuple

_log = logging.getLogger("zkapp.zkem_rtlog")

# Keys kept per turnstile. A replay is the last event(s) read before the reconnect; on gym 45
# on 2026-09-30 no connection's event counter went past 40 (blank records included).
MAX_KEYS = 512

_lock = threading.Lock()
_seen: Dict[int, "OrderedDict[Tuple[str, str, str, str], None]"] = {}


def content_key(evt: Dict[str, Any]) -> Optional[Tuple[str, str, str, str]]:
    """(pin, device time, door, verify method) of a zkemkeeper event; None for any other."""
    if not isinstance(evt, dict) or evt.get("table") != "zkem":
        return None
    raw = evt.get("rawRow") if isinstance(evt.get("rawRow"), dict) else {}
    return (str(raw.get("pin") or "").strip(), str(evt.get("eventTime") or "").strip(),
            str(evt.get("doorId")), str(raw.get("verifyMethod")))


def skip(device_id: Any, evt: Dict[str, Any], prefix: str) -> bool:
    """True (and one DEBUG line) when this zkemkeeper event was already processed on this
    turnstile; otherwise it is remembered and False."""
    key = content_key(evt)
    if key is None:
        return False
    try:
        did = int(device_id or 0)
    except (TypeError, ValueError):
        did = 0
    with _lock:
        seen = _seen.setdefault(did, OrderedDict())
        if key in seen:
            replay = True
        else:
            replay = False
            seen[key] = None
            while len(seen) > MAX_KEYS:
                seen.popitem(last=False)
    if replay:
        _log.debug("%s SKIP replayed event (already processed): pin=%s time=%s door=%s verify=%s "
                   "event_id=%s", prefix, key[0], key[1], key[2], key[3], evt.get("eventId"))
    return replay


def reset_for_tests() -> None:
    with _lock:
        _seen.clear()

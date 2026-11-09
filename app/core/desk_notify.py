"""Per-PC desk presentation settings and test events. Never makes access decisions."""
from __future__ import annotations

import threading
import time
import uuid
from collections import deque
from typing import Any, Mapping

from app.core.v2.store import kv_get, kv_put

DEFAULTS = dict(enabled=False, mode="REFUSALS_AND_ALERTS", position="BOTTOM_RIGHT", screen=0,
                durationSec=8, maxVisible=3, sound=False, renewButton=True, payRestButton=True, testNonce=0)
_CHOICES = dict(mode=("ALL", "REFUSALS_AND_ALERTS", "REFUSALS_ONLY"),
                position=("TOP_LEFT", "TOP_CENTER", "TOP_RIGHT", "BOTTOM_LEFT", "BOTTOM_CENTER", "BOTTOM_RIGHT"),
                screen=(0, 1, 2), durationSec=(0, 5, 8, 15), maxVisible=(1, 2, 3, 5))
_lock = threading.RLock()
_settings = None
_events = deque(maxlen=32)
_seq = 0


def normalize(raw: Any) -> dict:
    raw = raw if isinstance(raw, Mapping) else {}
    result = DEFAULTS.copy()
    for key, default in DEFAULTS.items():
        value = raw.get(key)
        if type(value) is not type(default):
            continue
        if key in _CHOICES and value not in _CHOICES[key]:
            continue
        if key == "testNonce" and (value < 0 or value > 9007199254740991):
            continue
        result[key] = value
    return result


def settings() -> dict:
    global _settings
    with _lock:
        if _settings is None:
            _settings = normalize(kv_get("desk_notify_settings"))
        return _settings.copy()


def is_enabled() -> bool:
    return settings()["enabled"]


def on_heartbeat_response(response: Mapping[str, Any]) -> None:
    global _settings
    if "deskNotify" not in response:  # Older backend: keep the last durable settings.
        return
    with _lock:
        before = settings()
        after = normalize(response["deskNotify"])
        if after != before:
            kv_put("desk_notify_settings", after, durable=True)
            _settings = after
        if after["testNonce"] > before["testNonce"]:
            queue_test()


def queue_test() -> bool:
    global _seq
    with _lock:
        if not is_enabled():
            return False
        _seq += 1
        _events.append((_seq, dict(eventId="desk-test-" + uuid.uuid4().hex, deskTest=True, deskOnly=True,
                                  allowed=True, userFullName="Test MonClub", deviceName="Entrée", reason="ALLOW_CARD",
                                  scanMode="RFID_CARD", receivedAt=int(time.time() * 1000))))
        return True


def events_since(seq: int) -> list:
    with _lock:
        # Tests are transient, never replay an old test after a long disconnection.
        cutoff = time.time() * 1000 - 60000
        return [(s, event.copy()) for s, event in _events if s > seq and event["receivedAt"] >= cutoff]

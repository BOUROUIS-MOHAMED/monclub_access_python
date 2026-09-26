"""The turnstile problem report (P2c-2 §2): one snapshot per turnstile this PC drives.

A snapshot REPLACES this PC's previous one for that turnstile on the server (a code left out
is resolved). It is sent when its content changes, and again every hour while it has
problems (the server empties a report not refreshed for 30 days). ``observedAt`` is the
server-corrected "now" (owner decision 5a); ``sentAt`` is stamped per attempt by the API.
Only turnstiles whose removal step ran in this process are reported, so a restart never
sends an empty snapshot that would hide a problem the first pass has not re-detected yet.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any, Dict, Optional

from app.core.v2 import lease_gate, timefmt
from app.core.v2.api import V2ApiError
from app.core.v2.problems import registry

_log = logging.getLogger("zkapp.v2.reports")

CHECK_EVERY_SEC = 30.0
REFRESH_EVERY_SEC = 3600.0
RETRY_SEC = 60.0


class ProblemReporter:
    def __init__(self, runtime: Any) -> None:
        self.rt = runtime
        self._sent: Dict[int, tuple] = {}          # did -> (content key, mono sent)
        self._next_check = 0.0
        self._retry: Dict[int, float] = {}
        self._attempt_key: Dict[int, str] = {}
        self.last: Dict[str, Any] = {}

    def _scheme(self, did: int) -> Optional[str]:
        try:
            from app.core.db import get_sync_device_payload
            from app.core.pin_scheme import device_pin_scheme
            payload = get_sync_device_payload(int(did))
            return device_pin_scheme(payload) if payload else None
        except Exception:
            return None

    def send(self, did: int, *, force: bool = False) -> Optional[Dict[str, Any]]:
        problems = registry.snapshot(did)
        key = hashlib.sha1(json.dumps(problems, sort_keys=True).encode()).hexdigest()
        prev = self._sent.get(did)
        now = time.monotonic()
        if not force and prev is not None and prev[0] == key and (not problems or now - prev[1] < REFRESH_EVERY_SEC):
            return None
        scheme = self._scheme(did)
        if scheme is None:
            return None
        self._attempt_key[did] = key
        body = {"gymDeviceId": did, "pinScheme": scheme,
                "observedAt": timefmt.format_utc(self.rt.clock.now()), "problems": problems}
        ans = self.rt.api.turnstile_problems(body)
        self._sent[did] = (key, now)
        self.last[str(did)] = {"codes": [p["code"] for p in problems], "stale": ans.get("stale"),
                               "ignored": ans.get("ignoredCodes")}
        return ans

    def tick(self, runtime: Any) -> None:
        now = time.monotonic()
        if now < self._next_check:
            return
        self._next_check = now + CHECK_EVERY_SEC
        for did in registry.devices():
            if not lease_gate.device_allowed(did) or now < self._retry.get(did, 0.0):
                continue
            try:
                self.send(did)
            except V2ApiError as exc:
                self._retry[did] = now + RETRY_SEC
                self.last[str(did)] = {"error": exc.code}
                if exc.backend and exc.status == 400:
                    # A report the server cannot take (a bug on one side): do not resend the
                    # same content every minute.
                    _log.warning("[V2] problem report refused for turnstile %s: %s %s",
                                 did, exc.code, exc.details)
                    self._sent[did] = (self._attempt_key.get(did, ""), now)

    def status(self) -> Dict[str, Any]:
        return {"problemReports": dict(self.last)}

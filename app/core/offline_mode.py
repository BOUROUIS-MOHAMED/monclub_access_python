"""Connectivity inferred only from the existing staff poll, plus a manual override."""
from datetime import datetime
import threading


class OfflineDetector:
    def __init__(self):
        self._lock = threading.RLock()
        self._automatic = False
        self._manual = False
        self._failures = 0
        self._successes = 0
        self._since = None

    def _update_since(self):
        if self._automatic or self._manual:
            if self._since is None:
                self._since = datetime.now().isoformat(timespec="microseconds")
        else:
            self._since = None

    def network_error(self):
        with self._lock:
            self._successes = 0
            self._failures += 1
            if self._failures >= 4:
                self._automatic = True
            self._update_since()

    def http_error(self):
        with self._lock:
            self._failures = self._successes = 0

    def success(self):
        with self._lock:
            self._failures = 0
            self._successes += 1
            if self._successes >= 2:
                self._automatic = False
            self._update_since()

    def set_manual(self, on: bool):
        with self._lock:
            self._manual = bool(on)
            self._update_since()

    def state(self) -> dict:
        with self._lock:
            return {"offline": self._automatic or self._manual,
                    "manual": self._manual, "since": self._since}


def is_network_error(exc: Exception) -> bool:
    from requests.exceptions import ConnectionError as RequestsConnectionError, Timeout
    # The API wraps requests errors with `raise ... from e`.
    while exc is not None:
        if isinstance(exc, (ConnectionError, TimeoutError, RequestsConnectionError, Timeout)):
            return True
        exc = exc.__cause__
    return False


def offline_status(staff) -> dict:
    from app.core.v2 import lease_gate
    state = staff.offline_detector.state()
    enabled = staff.snapshot()["enabled"]
    lease = lease_gate.current()
    return {"active": enabled and state["offline"], "manual": enabled and state["manual"],
            "since": state["since"] if enabled else None, "unlocked": False, "actAs": None,
            "role": lease.role, "driverName": next((name for _, name in lease.reader_of), None),
            "codeSet": False, "lock": {"remaining": 5, "lockedSeconds": 0},
            "limits": {"door": {"used": 0, "max": 0}, "money": {"used": 0, "max": 0}},
            "pending": {"count": 0, "lastError": None}, "lastUpload": None}

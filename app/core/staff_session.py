"""Access staff session. This is independent of the realtime device engine."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import json
import threading
import time

from app.core.v2.store import kv_get, kv_put, kv_delete
from shared.auth_state import protect_auth_token, unprotect_auth_token
from app.core.offline_mode import OfflineDetector, is_network_error


def _empty_snapshot() -> dict:
    return {"enabled": False, "agent": None, "allowedAgents": [], "permissions": [],
            "changedAt": None, "previousAgentName": None}


class StaffSession:
    def __init__(self, on_change=None, is_token_current=None):
        self._lock = threading.RLock()
        self._generation = 0
        self._on_change = on_change
        self._is_token_current = is_token_current
        self._snapshot = _empty_snapshot()
        self.offline_detector = OfflineDetector()
        self._offline_config = {}
        from app.core.offline_session import OfflineSession
        self.offline_session = OfflineSession(self)
        self._token = None
        self._last_activity = float("-inf")
        cached = kv_get("staff_session")
        if isinstance(cached, dict) and isinstance(cached.get("snapshot"), dict):
            self._snapshot.update(cached["snapshot"])
            try:
                self._offline_config = json.loads(unprotect_auth_token(cached.get("offline") or "") or "{}")
            except (TypeError, ValueError):
                self._offline_config = {}
            if self._snapshot["enabled"] and self._snapshot["agent"]:
                self._token = unprotect_auth_token(cached.get("token") or "") or None

    def snapshot(self) -> dict:
        with self._lock:
            return deepcopy(self._snapshot)

    def offline_config(self) -> dict:
        with self._lock:
            return deepcopy(self._offline_config)

    def apply_cookie(self, api) -> None:
        with self._lock:
            api.set_staff_cookie(self._token if self._snapshot["enabled"] else None)

    def poll_once(self, api, token: str) -> str | None:
        with self._lock:
            generation = self._generation
        try:
            data = api.get_staff_current(token=token)
            if not isinstance(data, dict) or not isinstance(data.get("staffLoginEnabled"), bool):
                raise ValueError("Invalid staff snapshot")  # Keep a known session, without counting a network failure.
        except Exception as exc:
            from app.api.monclub_api import MonClubApiHttpError
            with self._lock:
                if generation == self._generation and (not self._is_token_current or self._is_token_current(token)):
                    if isinstance(exc, MonClubApiHttpError):
                        self.offline_detector.http_error()
                    elif is_network_error(exc):
                        self.offline_detector.network_error()
                    else:
                        self.offline_detector.http_error()
            return  # Release 1 keeps the last known session during a network failure.
        with self._lock:
            if generation != self._generation:
                return  # A logout happened while the request was in flight.
            if self._is_token_current and not self._is_token_current(token):
                return  # The gym login changed before this poll could start/finish.
            was_offline = self.offline_detector.state()
            self.offline_detector.success()
            if was_offline["offline"] and not was_offline["manual"] and not self.offline_detector.state()["offline"]:
                self.offline_session.recovery_pending = True
                self.offline_session.recovery_upload_started = False
            enabled = data["staffLoginEnabled"]
            config = data.get("offline") or {} if enabled else {}
            config_changed = config != self._offline_config
            self._offline_config = deepcopy(config)
            staff = data.get("agent") if enabled else None
            previous = self._snapshot.get("agent") or {}
            snapshot = {
                "enabled": enabled,
                "agent": {k: staff.get(k) for k in ("id", "name", "adminAgent", "since")} if staff else None,
                "allowedAgents": data.get("allowedAgents") or [] if enabled else [],
                "permissions": list(staff.get("permissions") or []) if staff else [],
                "changedAt": self._snapshot["changedAt"],
                "previousAgentName": self._snapshot["previousAgentName"],
            }
            if previous.get("id") != (staff or {}).get("id"):
                snapshot["changedAt"] = datetime.now().isoformat(timespec="microseconds")
                snapshot["previousAgentName"] = previous.get("name")
            changed = snapshot != self._snapshot
            self._snapshot = snapshot
            self._token = data.get("token") if enabled and staff else None
            api.set_staff_cookie(self._token)
            kv_put("staff_session", {"snapshot": snapshot,
                                    "offline": protect_auth_token(json.dumps(config)) if config else None,
                                    "token": protect_auth_token(self._token) if self._token else None})
        if config_changed or not enabled or not self.offline_detector.state()["offline"]:
            self.offline_session.relock()
        if changed and self._on_change:
            self._on_change()
        return "success"

    def has_permission(self, *perms: str) -> bool:
        return self.require(*perms)[0]

    def require(self, *perms: str) -> tuple[bool, str | None]:
        if self.snapshot()["enabled"] and self.offline_detector.state()["offline"]:
            return self.offline_session.require(*perms)
        with self._lock:
            if not self._snapshot["enabled"]:
                return True, None
            staff = self._snapshot["agent"]
            if not staff:
                return False, "NO_AGENT"
            if staff.get("adminAgent") or all(p in self._snapshot["permissions"] for p in perms):
                return True, None
            return False, "MISSING_PERMISSION"

    def clear(self, api=None) -> None:
        with self._lock:
            self._generation += 1
            self._snapshot = _empty_snapshot()
            self.offline_detector = OfflineDetector()
            self._offline_config = {}
            self._token = None
            self._last_activity = float("-inf")
            if api:
                api.set_staff_cookie(None)
            kv_delete("staff_session")
        self.offline_session.relock()
        if self._on_change:
            self._on_change()

    def post_activity(self, api_factory, token: str) -> None:
        """Real operator actions only; at most one best-effort background ping per minute."""
        with self._lock:
            if not self._snapshot["enabled"] or not self._snapshot["agent"]:
                return
            now = time.monotonic()
            if now - self._last_activity < 60:
                return
            self._last_activity = now
            api = api_factory()
            self.apply_cookie(api)
        def run():
            try:
                api.post_staff_activity(token=token)
            except Exception:
                pass
        threading.Thread(target=run, name="staff-activity", daemon=True).start()

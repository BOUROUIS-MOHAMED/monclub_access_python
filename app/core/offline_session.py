"""Offline gym-code unlock, selected staff permissions and daily usage."""
from __future__ import annotations

import base64
from datetime import datetime
import hashlib
import hmac
import math
import sqlite3
import threading
import time

from app.core.v2.store import kv_get, kv_put


def local_day() -> str:
    from app.core.access_dates import gym_local_date
    from app.core.v2.server_clock import get_default
    clock = get_default()
    if clock and clock.utc_offset is not None:
        return gym_local_date(clock.now(), clock.utc_offset).isoformat()
    return datetime.now().date().isoformat()


class OfflineSession:
    def __init__(self, staff):
        self._staff = staff
        self._lock = threading.RLock()
        self._unlocked = False
        self._agent_id = None
        self.upload_lock = threading.Lock()
        self.last_upload = None
        self.recovery_pending = False
        self.recovery_upload_started = False
        self.receipt_page = 0

    def lock_state(self) -> dict:
        row = kv_get("offline_unlock") or {}
        seconds = max(0, math.ceil(float(row.get("until") or 0) - time.time()))
        failures = int(row.get("failures") or 0) if seconds or not row.get("until") else 0
        return {"remaining": max(0, 5 - failures), "lockedSeconds": seconds}

    def unlock(self, code: str) -> dict:
        with self._lock:
            self.relock()
            state = self.lock_state()
            if state["lockedSeconds"]:
                return {"ok": False, "code": "LOCKED", "seconds": state["lockedSeconds"]}
            verifier = self._staff.offline_config().get("code")
            if not verifier:
                return {"ok": False, "code": "NO_CODE"}
            valid = False
            try:
                if isinstance(code, str) and len(code) == 6 and code.isascii() and code.isdigit():
                    salt = base64.b64decode(verifier["salt"], validate=True)
                    expected = base64.b64decode(verifier["hash"], validate=True)
                    if len(salt) == 16 and len(expected) == 32 and verifier["iterations"] == 210000:
                        actual = hashlib.pbkdf2_hmac("sha256", code.encode("ascii"), salt, 210000, dklen=32)
                        valid = hmac.compare_digest(actual, expected)
            except (KeyError, TypeError, ValueError):
                pass
            if valid:
                kv_put("offline_unlock", {"failures": 0, "until": 0}, durable=True)
                self._unlocked = True
                return {"ok": True}
            failures = 6 - state["remaining"]
            kv_put("offline_unlock", {"failures": failures,
                                      "until": time.time() + 300 if failures >= 5 else 0}, durable=True)
            if failures >= 5:
                return {"ok": False, "code": "LOCKED", "seconds": 300}
            return {"ok": False, "code": "WRONG", "remaining": 5 - failures}

    def selected(self) -> dict | None:
        with self._lock:
            return next((a for a in self._staff.snapshot()["allowedAgents"]
                         if a.get("id") == self._agent_id), None) if self._unlocked else None

    def act_as(self, agent_id: int) -> dict:
        with self._lock:
            if not self._unlocked:
                return {"ok": False, "code": "OFFLINE_LOCKED"}
            if not any(a.get("id") == agent_id for a in self._staff.snapshot()["allowedAgents"]):
                return {"ok": False, "code": "NO_AGENT"}
            self._agent_id = agent_id
            return {"ok": True}

    def require(self, *perms: str) -> tuple[bool, str | None]:
        with self._lock:
            if not self._unlocked:
                return False, "OFFLINE_LOCKED"
            staff = self.selected()
            if not staff:
                return False, "NO_AGENT"
            if staff.get("adminAgent") or all(p in (staff.get("permissions") or []) for p in perms):
                return True, None
            return False, "MISSING_PERMISSION"

    def relock(self):
        with self._lock:
            self._unlocked = False
            self._agent_id = None

    def limits(self) -> dict:
        from app.core.db import get_conn
        day = local_day()
        used = dict((kv_get("offline_uploaded_usage:" + day) or {}))
        try:
            with get_conn() as conn:
                rows = conn.execute("SELECT category, COUNT(*) FROM offline_pending_actions "
                                    "WHERE local_day = ? GROUP BY category", (day,)).fetchall()
            for category, count in rows:
                used[category] = used.get(category, 0) + count
        except sqlite3.OperationalError as exc:
            if "no such table" not in str(exc):
                raise
        config = self._staff.offline_config()
        return {c.lower(): {"used": used.get(c, 0), "max": int(config.get(key) or 0)}
                for c, key in (("DOOR", "doorLimit"), ("MONEY", "moneyLimit"))}

    def status(self) -> dict:
        from app.core.offline_mode import offline_status
        state = offline_status(self._staff)
        staff = self.selected()
        state.update(unlocked=self._unlocked, actAs={"id": staff["id"], "name": staff["name"]} if staff else None,
                     codeSet=bool(self._staff.offline_config().get("code")),
                     lock=self.lock_state(), limits=self.limits())
        if self._staff.snapshot()["enabled"]:
            from app.core.db import offline_pending_status
            try:
                state["pending"] = offline_pending_status()
            except sqlite3.OperationalError as exc:
                if "no such table" not in str(exc):
                    raise
        state["lastUpload"] = self.last_upload
        if self._staff.snapshot()["enabled"]:
            from app.core.offline_overlay import expiry_pending
            state["expiryPending"] = expiry_pending()
        return state

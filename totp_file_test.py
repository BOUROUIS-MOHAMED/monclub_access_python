#!/usr/bin/env python3
# Local (SQLite) TOTP verifier for MonClub Access.
# - Reads credential secrets from local sync cache (app.core.db).
# - Strict expiry + future skew checks.
# - No replay denial (records nothing).
#
# Input: one token per line (digits are extracted). Prints ALLOW/DENY with a check time.

from __future__ import annotations

import os
import sys
import time
import hmac
import hashlib
import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


# ===================== TOTP CONFIG =====================

TOTP_DIGITS = int(os.getenv("MC_TOTP_DIGITS", "8"))
PERIOD_SECONDS = int(os.getenv("MC_TOTP_PERIOD_SECONDS", "30"))
DRIFT_STEPS = int(os.getenv("MC_TOTP_DRIFT_STEPS", "1"))

# Strict rules (seconds)
MAX_PAST_AGE_SECONDS = int(os.getenv("MC_TOTP_MAX_PAST_AGE_SECONDS", "32"))
MAX_FUTURE_SKEW_SECONDS = int(os.getenv("MC_TOTP_MAX_FUTURE_SKEW_SECONDS", "3"))

# How often to refresh from SQLite (seconds)
REFRESH_EVERY_SECONDS = float(os.getenv("MC_TOTP_REFRESH_EVERY_SECONDS", "2.0"))


# ===================== LOCAL DB IMPORT =====================

def _import_db():
    try:
        from app.core.db import list_sync_gym_access_credentials, list_sync_users  # type: ignore
        return list_sync_gym_access_credentials, list_sync_users
    except Exception:
        # fallback: add project root
        here = os.path.abspath(os.path.dirname(__file__))
        sys.path.insert(0, here)
        sys.path.insert(0, os.path.abspath(os.path.join(here, "..")))
        sys.path.insert(0, os.path.abspath(os.path.join(here, "../..")))
        from app.core.db import list_sync_gym_access_credentials, list_sync_users  # type: ignore
        return list_sync_gym_access_credentials, list_sync_users


_list_sync_gym_access_credentials, _list_sync_users = _import_db()


# ===================== TOTP CORE =====================

def _counter(unix_time: int, period: int) -> int:
    return int(unix_time) // int(period)


def _is_hex(s: str) -> bool:
    s = (s or "").strip()
    if not s:
        return False
    if s.startswith(("0x", "0X")):
        s = s[2:]
    if len(s) % 2 != 0:
        return False
    try:
        bytes.fromhex(s)
        return True
    except Exception:
        return False


def _hex_to_bytes(s: str) -> bytes:
    s = (s or "").strip()
    if s.startswith(("0x", "0X")):
        s = s[2:]
    return bytes.fromhex(s)


def _hotp(secret: bytes, counter: int, digits: int) -> str:
    msg = struct.pack(">Q", int(counter))
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return str(code_int % (10 ** int(digits))).zfill(int(digits))


# ===================== DATA =====================

@dataclass(frozen=True)
class Cred:
    cred_id: str
    account_id: str
    secret_hex: str
    enabled: bool
    granted_active_membership_ids: List[int]

    def usable(self) -> bool:
        if not self.enabled:
            return False
        if not self.cred_id or not self.account_id:
            return False
        if not self.secret_hex or not _is_hex(self.secret_hex):
            return False
        if not self.granted_active_membership_ids:
            return False
        return True


@dataclass(frozen=True)
class Match:
    ok: bool
    reason: str
    account_id: str = ""
    cred_id: str = ""
    matched_counter: Optional[int] = None
    age_seconds: Optional[int] = None
    check_ms: float = 0.0
    user: Optional[Dict[str, Any]] = None
    active_membership_id: Optional[int] = None


# ===================== VERIFIER =====================

class OfflineVerifier:
    def __init__(self) -> None:
        self._creds: Dict[str, Cred] = {}
        self._users_by_am: Dict[int, Dict[str, Any]] = {}
        self._last_refresh = 0.0

    def refresh_if_needed(self) -> None:
        now = time.time()
        if (now - self._last_refresh) < REFRESH_EVERY_SECONDS and self._creds:
            return

        creds_payload = _list_sync_gym_access_credentials() or []
        users_payload = _list_sync_users() or []

        # creds
        merged: Dict[str, Cred] = {}
        for c in creds_payload:
            if not isinstance(c, dict):
                continue

            enabled = bool(c.get("enabled", False))
            cred_id = str(c.get("id") or "").strip()
            account_id = str(c.get("accountId") or "").strip()
            secret_hex = str(c.get("secretHex") or "").strip()

            grants_raw = c.get("grantedActiveMembershipIds") or []
            grants: List[int] = []
            if isinstance(grants_raw, list):
                for g in grants_raw:
                    try:
                        grants.append(int(str(g).strip()))
                    except Exception:
                        continue

            cred = Cred(
                cred_id=cred_id,
                account_id=account_id,
                secret_hex=secret_hex,
                enabled=enabled,
                granted_active_membership_ids=grants,
            )
            if cred.usable():
                merged[cred_id] = cred

        # users
        users_idx: Dict[int, Dict[str, Any]] = {}
        for u in users_payload:
            if not isinstance(u, dict):
                continue
            am = u.get("activeMembershipId")
            try:
                if am is None:
                    continue
                s = str(am).strip()
                if not s:
                    continue
                users_idx[int(s)] = u
            except Exception:
                continue

        self._creds = merged
        self._users_by_am = users_idx
        self._last_refresh = now

    def verify_code(self, scanned: str) -> Match:
        self.refresh_if_needed()
        t0 = time.perf_counter()

        code = "".join(ch for ch in (scanned or "").strip() if ch.isdigit())

        if len(code) != TOTP_DIGITS or (not code.isdigit()):
            return Match(ok=False, reason="INVALID_FORMAT", check_ms=(time.perf_counter() - t0) * 1000.0)

        now = int(time.time())
        cur = _counter(now, PERIOD_SECONDS)
        allowed_ctrs = list(range(cur - DRIFT_STEPS, cur + DRIFT_STEPS + 1))

        hits: List[Tuple[str, int]] = []
        for cid, c in self._creds.items():
            if not c.usable():
                continue
            secret = _hex_to_bytes(c.secret_hex)
            for ctr in allowed_ctrs:
                if _hotp(secret, ctr, TOTP_DIGITS) == code:
                    hits.append((cid, ctr))

        if not hits:
            return Match(ok=False, reason="DENY_NO_MATCH", check_ms=(time.perf_counter() - t0) * 1000.0)

        uniq_creds = sorted(set(cid for cid, _ in hits))
        if len(uniq_creds) != 1:
            return Match(ok=False, reason="DENY_COLLISION", check_ms=(time.perf_counter() - t0) * 1000.0)

        cred_id = uniq_creds[0]
        ctrs = sorted(set(ctr for cid, ctr in hits if cid == cred_id))
        if len(ctrs) != 1:
            return Match(ok=False, reason="DENY_AMBIGUOUS_COUNTER", check_ms=(time.perf_counter() - t0) * 1000.0)

        matched_ctr = ctrs[0]
        age = now - (matched_ctr * PERIOD_SECONDS)

        if age < -MAX_FUTURE_SKEW_SECONDS:
            return Match(
                ok=False,
                reason="DENY_FUTURE_SKEW",
                cred_id=cred_id,
                matched_counter=matched_ctr,
                age_seconds=age,
                check_ms=(time.perf_counter() - t0) * 1000.0,
            )

        if age > MAX_PAST_AGE_SECONDS:
            return Match(
                ok=False,
                reason="DENY_EXPIRED",
                cred_id=cred_id,
                matched_counter=matched_ctr,
                age_seconds=age,
                check_ms=(time.perf_counter() - t0) * 1000.0,
            )

        cred = self._creds.get(cred_id)
        if not cred:
            return Match(ok=False, reason="DENY_NO_CRED", check_ms=(time.perf_counter() - t0) * 1000.0)

        user: Optional[Dict[str, Any]] = None
        chosen_am: Optional[int] = None
        for am in cred.granted_active_membership_ids:
            if am in self._users_by_am:
                user = self._users_by_am.get(am)
                chosen_am = am
                break
            if chosen_am is None:
                chosen_am = am

        return Match(
            ok=True,
            reason="ALLOW",
            account_id=cred.account_id,
            cred_id=cred_id,
            matched_counter=matched_ctr,
            age_seconds=age,
            check_ms=(time.perf_counter() - t0) * 1000.0,
            user=user,
            active_membership_id=chosen_am,
        )


# ===================== CLI =====================

def _fmt_user(u: Optional[Dict[str, Any]], am_id: Optional[int]) -> str:
    if not isinstance(u, dict):
        return f"amId={am_id}" if am_id is not None else ""
    name = str(u.get("fullName") or "").strip()
    phone = str(u.get("phone") or "").strip()
    uid = str(u.get("userId") or "").strip()
    parts: List[str] = []
    if name:
        parts.append(name)
    if phone:
        parts.append(f"phone={phone}")
    if uid:
        parts.append(f"userId={uid}")
    if am_id is not None:
        parts.append(f"amId={am_id}")
    return " | ".join(parts)


def main() -> int:
    v = OfflineVerifier()

    while True:
        try:
            line = input()
        except (EOFError, KeyboardInterrupt):
            return 0

        if not line:
            continue

        m = v.verify_code(line)

        if m.ok:
            extra = _fmt_user(m.user, m.active_membership_id)
            suffix = f" | {extra}" if extra else ""
            print(
                f"ALLOW accountId={m.account_id} credId={m.cred_id} age={m.age_seconds}s checkMs={m.check_ms:.1f}{suffix}"
            )
        else:
            parts = [f"DENY reason={m.reason}", f"checkMs={m.check_ms:.1f}"]
            if m.cred_id:
                parts.append(f"credId={m.cred_id}")
            if m.matched_counter is not None:
                parts.append(f"ctr={m.matched_counter}")
            if m.age_seconds is not None:
                parts.append(f"age={m.age_seconds}s")
            print(" ".join(parts))


if __name__ == "__main__":
    raise SystemExit(main())

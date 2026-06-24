# app/core/access_verification.py
"""
Shared TOTP / RFID verification logic used by both AGENT and ULTRA engines.

Extracted from realtime_agent.py — pure functions, no class dependency.
"""

import hashlib
import hmac
import logging
import struct
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.core.db import (
    list_sync_users,
    list_sync_gym_access_credentials,
)
from app.core import telemetry as _tel

logger = logging.getLogger(__name__)


# ===================== event-time parsing =====================

def parse_event_time_to_epoch(s: str, tz_offset_sec: int = 0) -> Optional[float]:
    """
    Best-effort parsing of an RTLog eventTime string into epoch seconds.

    Supports:
      - unix seconds or milliseconds
      - ISO 8601 (with Z or numeric offset)
      - 'YYYY-MM-DD HH:MM:SS' or 'YYYY-MM-DDTHH:MM:SS' (device local time)

    ``tz_offset_sec`` is the device's UTC offset in seconds (e.g. +3600 for
    UTC+1). For the local-time formats it is subtracted so the result is an
    approximate UTC epoch comparable to ``time.time()``.

    Returns None when the string can't be parsed.

    NOTE: kept identical to realtime_agent's historical helper so the AGENT and
    ULTRA engines parse device timestamps the same way; that module now imports
    this implementation.
    """
    raw = (s or "").strip()
    if not raw:
        return None

    # numeric epoch (seconds/ms)
    if raw.isdigit():
        try:
            v = int(raw)
            if v > 10_000_000_000:  # ms
                return float(v) / 1000.0
            if v > 1_000_000_000:  # sec
                return float(v)
        except Exception:
            pass

    # ISO 8601 — ONLY when an explicit timezone is present (Z or numeric offset).
    # A naive 'YYYY-MM-DD HH:MM:SS' string is ALSO accepted by fromisoformat, but
    # ZKTeco devices emit *local* wall-clock time, not UTC. Treating such a naive
    # string as UTC would shift every scan by the site's UTC offset (e.g. +3600s
    # in UTC+1) and make TOTP validation fail. So only trust this branch when the
    # parsed value is tz-aware; otherwise fall through to the local-time branch.
    try:
        iso = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is not None:
            return dt.timestamp()
    except Exception:
        pass

    # common fallback formats (device local time). dt.timestamp() on a naive
    # datetime interprets it in the host's local timezone; tz_offset_sec corrects
    # for any device/host timezone mismatch (0 when they share a timezone).
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(raw, fmt)
            return dt.timestamp() - tz_offset_sec
        except Exception:
            continue

    return None


# Beyond this distance from the PC wall clock, a scan timestamp is treated as a
# misconfigured device clock (not mere skew) and ignored in favour of time.time().
EVENT_TIME_SANITY_BOUND_SEC = 3600.0  # 1 hour


def resolve_totp_clock(
    scan_epoch: Optional[float],
    *,
    sanity_bound_sec: float = EVENT_TIME_SANITY_BOUND_SEC,
    now: Optional[float] = None,
) -> Optional[float]:
    """Decide which clock to validate a TOTP code against.

    Returns ``scan_epoch`` (the instant the device read the code) when it is
    present and within ``sanity_bound_sec`` of the PC wall clock — this removes
    RTLog pipeline latency from the TOTP window. Returns None (caller falls back
    to ``time.time()``) when the scan time is missing or implausibly far off,
    which indicates a broken device clock rather than ordinary skew.
    """
    if scan_epoch is None:
        return None
    ref = now if now is not None else time.time()
    if abs(ref - float(scan_epoch)) <= sanity_bound_sec:
        return float(scan_epoch)
    return None


# ===================== helpers (private, used in _safe_int / _safe_str) =====================

def _safe_int(v: Any, default: int = 0) -> int:
    try:
        if v is None:
            return default  # type: ignore[return-value]
        if isinstance(v, bool):
            return int(v)
        return int(float(str(v).strip()))
    except Exception:
        return default  # type: ignore[return-value]


def _safe_str(v: Any, default: str = "") -> str:
    if v is None:
        return default
    try:
        return str(v)
    except Exception:
        return default


# ===================== TOTP (QR) =====================

def _totp_counter(unix_time: int, period: int) -> int:
    return int(unix_time) // int(period)


def _totp_is_hex(s: str) -> bool:
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


def _totp_hex_to_bytes(s: str) -> bytes:
    s = (s or "").strip()
    if s.startswith(("0x", "0X")):
        s = s[2:]
    return bytes.fromhex(s)


def _totp_hotp(secret: bytes, counter: int, digits: int) -> str:
    msg = struct.pack(">Q", int(counter))
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return str(code_int % (10 ** int(digits))).zfill(int(digits))


# ===================== verification functions =====================

def verify_card(
    *,
    scanned: str,
    settings: Dict[str, Any],
    users_by_card: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, Any]:
    t0 = time.perf_counter()

    if not bool(settings.get("rfid_enabled", True)):
        return {
            "allowed": False,
            "reason": "DENY_RFID_DISABLED",
            "scanMode": "RFID_CARD",
            "tookMs": (time.perf_counter() - t0) * 1000.0,
            "user": None,
        }

    code = (scanned or "").strip()
    if (not code) or (not code.isdigit()):
        return {
            "allowed": False,
            "reason": "INVALID_CARD_FORMAT",
            "scanMode": "RFID_CARD",
            "tookMs": (time.perf_counter() - t0) * 1000.0,
            "user": None,
        }

    # Backend supports 1..16 digits
    min_len = _safe_int(settings.get("rfid_min_digits"), 1)
    max_len = _safe_int(settings.get("rfid_max_digits"), 16)

    if min_len < 1:
        min_len = 1
    if max_len > 16:
        max_len = 16
    if max_len < min_len:
        max_len = min_len

    if not (min_len <= len(code) <= max_len):
        return {
            "allowed": False,
            "reason": "INVALID_CARD_LENGTH",
            "scanMode": "RFID_CARD",
            "minDigits": int(min_len),
            "maxDigits": int(max_len),
            "tookMs": (time.perf_counter() - t0) * 1000.0,
            "user": None,
        }

    hits = users_by_card.get(code) or []
    if not hits:
        return {
            "allowed": False,
            "reason": "DENY_NO_CARD_MATCH",
            "scanMode": "RFID_CARD",
            "tookMs": (time.perf_counter() - t0) * 1000.0,
            "user": None,
        }

    if len(hits) != 1:
        return {
            "allowed": False,
            "reason": "DENY_CARD_COLLISION",
            "scanMode": "RFID_CARD",
            "count": len(hits),
            "tookMs": (time.perf_counter() - t0) * 1000.0,
            "user": None,
        }

    user = hits[0]
    am_id = user.get("activeMembershipId")
    try:
        am_id = int(str(am_id).strip()) if am_id is not None else None
    except Exception:
        am_id = None

    return {
        "allowed": True,
        "reason": "ALLOW_CARD",
        "scanMode": "RFID_CARD",
        "activeMembershipId": am_id,
        "user": user,
        "tookMs": (time.perf_counter() - t0) * 1000.0,
    }


@_tel.timed("TOTP_VERIFY", slow_ms=50)
def verify_totp(
    *,
    scanned: str,
    settings: Dict[str, Any],
    creds_payload: List[Dict[str, Any]],
    users_by_am: Dict[int, Dict[str, Any]],
    users_by_card: Dict[str, List[Dict[str, Any]]],
    now_unix: Optional[float] = None,
) -> Dict[str, Any]:
    """Validate a scanned QR/TOTP string.

    ``now_unix`` overrides the validation clock. Callers SHOULD pass the moment
    the code was actually scanned (parsed from the RTLog eventTime) rather than
    letting it default to ``time.time()`` at processing time: the RTLog pipeline
    can deliver an event tens of seconds after the scan (poll backoff, sync
    pauses, reconnect), and validating against wall-clock-at-processing pushes a
    still-valid code past ``totp_max_past_age_seconds`` and rejects it as
    DENY_EXPIRED / DENY_NO_MATCH. Falls back to ``time.time()`` when None.
    """
    t0 = time.perf_counter()

    totp_enabled = bool(settings.get("totp_enabled", True))
    totp_validation = bool(settings.get("totp_validation", True))

    period = _safe_int(settings.get("totp_period_seconds", 30))
    drift = _safe_int(settings.get("totp_drift_steps", 1))
    max_past_age = _safe_int(settings.get("totp_max_past_age_seconds", 32))
    max_future_skew = _safe_int(settings.get("totp_max_future_skew_seconds", 3))

    prefix = _safe_str(settings.get("totp_prefix", "9"), "9").strip()
    if (len(prefix) != 1) or (not prefix.isdigit()):
        prefix = "9"

    digits = _safe_int(settings.get("totp_digits", 7))
    if digits < 4:
        digits = 4
    if digits > 10:
        digits = 10

    expected_len = 1 + int(digits)  # prefix + digits

    raw = (scanned or "").strip()

    if (not totp_enabled) or (not totp_validation):
        # TOTP disabled means "use RFID only" — not "allow everyone"
        vr = verify_card(scanned=scanned, settings=settings, users_by_card=users_by_card)
        if vr.get("allowed"):
            vr["scanMode"] = "RFID_ONLY"
        vr["tookMs"] = (time.perf_counter() - t0) * 1000.0
        return vr

    if (not raw) or (not raw.isdigit()):
        return {
            "allowed": False,
            "reason": "INVALID_FORMAT",
            "scanMode": "UNKNOWN",
            "tookMs": (time.perf_counter() - t0) * 1000.0,
            "user": None,
        }

    # If code doesn't match expected QR format => treat as RFID directly
    if len(raw) != expected_len or (not raw.startswith(prefix)):
        vr = verify_card(scanned=raw, settings=settings, users_by_card=users_by_card)
        if bool(vr.get("allowed", False)):
            vr["scanMode"] = "RFID_DIRECT"
        return vr

    # QR TOTP format => use LAST 'digits'
    code = raw[-digits:]

    # Validate against the moment the code was scanned (now_unix, from the RTLog
    # eventTime) when the caller provides it; otherwise fall back to wall-clock.
    now = int(now_unix if now_unix is not None else time.time())
    cur = _totp_counter(now, period)
    allowed_ctrs = list(range(cur - int(drift), cur + int(drift) + 1))

    # TOTP diagnostic: count eligible credentials
    _eligible_creds = sum(
        1 for c in creds_payload if isinstance(c, dict) and c.get("enabled")
        and (c.get("secretHex") or "").strip() and _totp_is_hex((c.get("secretHex") or "").strip())
    )
    logger.debug(
        "verify_totp: code_len=%d prefix=%r digits=%d eligible_creds=%d "
        "now=%d counter=%d drift=%d period=%d",
        len(raw), prefix, digits, _eligible_creds, now, cur, drift, period,
    )

    hits: List[Dict[str, Any]] = []
    for c in creds_payload:
        if not isinstance(c, dict):
            continue
        if not bool(c.get("enabled", False)):
            continue

        cred_id = c.get("id")
        account_id = c.get("accountId")
        secret_hex = (c.get("secretHex") or "").strip()
        grants = c.get("grantedActiveMembershipIds") or []

        if cred_id in (None, "", 0) or account_id in (None, "", 0):
            continue
        if not secret_hex or (not _totp_is_hex(secret_hex)):
            continue
        if not isinstance(grants, list) or not grants:
            continue

        try:
            secret = _totp_hex_to_bytes(secret_hex)
        except Exception:
            continue

        for ctr in allowed_ctrs:
            try:
                if _totp_hotp(secret, ctr, digits) == code:
                    hits.append(
                        {
                            "credId": str(cred_id),
                            "accountId": str(account_id),
                            "counter": int(ctr),
                            "grants": list(grants),
                        }
                    )
                    break  # F-022: one match per credential is sufficient; skip remaining counters
            except Exception:
                continue
        # F-022: if we already have a collision (2+ distinct cred IDs), we can short-circuit
        if len(set(h["credId"] for h in hits)) > 1:
            break

    if hits:
        uniq_creds = sorted(set(h["credId"] for h in hits))
        if len(uniq_creds) != 1:
            return {
                "allowed": False,
                "reason": "DENY_COLLISION",
                "scanMode": "QR_TOTP",
                "tookMs": (time.perf_counter() - t0) * 1000.0,
                "user": None,
            }

        cred_id = uniq_creds[0]
        counters = sorted(set(int(h["counter"]) for h in hits if h["credId"] == cred_id))
        if len(counters) != 1:
            return {
                "allowed": False,
                "reason": "DENY_AMBIGUOUS_COUNTER",
                "scanMode": "QR_TOTP",
                "tookMs": (time.perf_counter() - t0) * 1000.0,
                "user": None,
            }

        matched_ctr = int(counters[0])
        age = int(now - (matched_ctr * int(period)))

        if age < -int(max_future_skew):
            return {
                "allowed": False,
                "reason": "DENY_FUTURE_SKEW",
                "scanMode": "QR_TOTP",
                "credId": cred_id,
                "matchedCounter": matched_ctr,
                "ageSeconds": age,
                "tookMs": (time.perf_counter() - t0) * 1000.0,
                "user": None,
            }

        if age > int(max_past_age):
            return {
                "allowed": False,
                "reason": "DENY_EXPIRED",
                "scanMode": "QR_TOTP",
                "credId": cred_id,
                "matchedCounter": matched_ctr,
                "ageSeconds": age,
                "tookMs": (time.perf_counter() - t0) * 1000.0,
                "user": None,
            }

        hit0 = hits[0]
        account_id = str(hit0.get("accountId") or "")
        grants = hit0.get("grants") or []

        user: Optional[Dict[str, Any]] = None
        chosen_am_id: Optional[int] = None
        for gid in grants:
            try:
                am = int(str(gid).strip())
            except Exception:
                continue
            if am in users_by_am:
                user = users_by_am.get(am)
                chosen_am_id = am
                break
            if chosen_am_id is None:
                chosen_am_id = am

        return {
            "allowed": True,
            "reason": "ALLOW",
            "scanMode": "QR_TOTP",
            "accountId": account_id,
            "credId": cred_id,
            "matchedCounter": matched_ctr,
            "ageSeconds": age,
            "activeMembershipId": chosen_am_id,
            "user": user,
            "tookMs": (time.perf_counter() - t0) * 1000.0,
        }

    # TOTP failed => fallback to RFID
    vr_card = verify_card(scanned=raw, settings=settings, users_by_card=users_by_card)
    if bool(vr_card.get("allowed", False)):
        vr_card["scanMode"] = "CARD_FALLBACK_AFTER_TOTP_FAIL"
        vr_card["reason"] = "ALLOW_CARD_FALLBACK"
        return vr_card

    return {
        "allowed": False,
        "reason": "DENY_NO_MATCH",
        "scanMode": "QR_TOTP",
        "tookMs": (time.perf_counter() - t0) * 1000.0,
        "user": None,
    }


@_tel.timed("TOTP_VERIFY_RESILIENT", slow_ms=50)
def verify_totp_resilient(
    *,
    scanned: str,
    settings: Dict[str, Any],
    creds_payload: List[Dict[str, Any]],
    users_by_am: Dict[int, Dict[str, Any]],
    users_by_card: Dict[str, List[Dict[str, Any]]],
    scan_epoch: Optional[float] = None,
) -> Dict[str, Any]:
    """Validate a QR/TOTP code resiliently against unreliable clocks.

    Accepts the code if it is valid under EITHER reference:
      1. the scan time (``scan_epoch`` from the RTLog eventTime) — removes RTLog
         pipeline latency (poll backoff, sync pauses) from the window, and
      2. the local wall clock (``time.time()``) — the historical behaviour, which
         still works when the *device* clock is the skewed one.

    This avoids having to guess which clock is trustworthy: a field gym can have
    a bad PC clock, a bad turnstile RTC, or both, and they drift independently.
    Trying both means neither a processing delay nor a single skewed clock alone
    can reject an otherwise-valid code. The result carries ``clockUsed`` =
    ``"scan"`` | ``"wall"`` for diagnostics.

    The common ALLOW case costs a single verification; the second pass only runs
    when the first denies (i.e. the already-failing path).
    """
    now_unix = resolve_totp_clock(scan_epoch)

    primary = verify_totp(
        scanned=scanned, settings=settings, creds_payload=creds_payload,
        users_by_am=users_by_am, users_by_card=users_by_card, now_unix=now_unix,
    )
    primary_clock = "scan" if now_unix is not None else "wall"
    if primary.get("allowed") or now_unix is None:
        primary["clockUsed"] = primary_clock
        return primary

    # Scan-time validation denied — retry against the wall clock so a skewed
    # device clock can't reject a code the PC clock would accept.
    fallback = verify_totp(
        scanned=scanned, settings=settings, creds_payload=creds_payload,
        users_by_am=users_by_am, users_by_card=users_by_card, now_unix=None,
    )
    if fallback.get("allowed"):
        fallback["clockUsed"] = "wall"
        return fallback

    primary["clockUsed"] = primary_clock
    return primary


# ===================== local state loading =====================

def load_local_state() -> tuple[List[Dict[str, Any]], Dict[int, Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
    """
    Read credentials and users from the local sync DB and build lookup indexes.

    Returns:
        (creds_payload, users_by_active_membership_id, users_by_card)

    Note: This is the cache-free version. DecisionService wraps this with its
    own TTL-based caching + threading lock.
    """

    def add_card(idx: Dict[str, List[Dict[str, Any]]], v: Any, u: Dict[str, Any]) -> None:
        if v is None:
            return
        s = str(v).strip()
        if not s:
            return
        if s.isdigit():
            idx.setdefault(s, []).append(u)

    def add_cards_from_obj(idx: Dict[str, List[Dict[str, Any]]], obj: Any, u: Dict[str, Any]) -> None:
        if not isinstance(obj, dict):
            return
        for k in ("firstCardId", "cardId", "secondCardId", "cardNo", "rfid", "rfidCard", "rfidCardNo", "cardNumber"):
            if k in obj:
                add_card(idx, obj.get(k), u)

    p = _tel.profile("CACHE_LOAD_LOCAL_STATE")

    with p.step("creds"):
        try:
            creds = list_sync_gym_access_credentials()
        except Exception:
            creds = []

    with p.step("users"):
        try:
            users = list_sync_users()
        except Exception:
            users = []

    idx_by_am: Dict[int, Dict[str, Any]] = {}
    idx_by_card: Dict[str, List[Dict[str, Any]]] = {}

    with p.step("index"):
        for u in users:
            if not isinstance(u, dict):
                continue

            am_id = u.get("activeMembershipId")
            try:
                if am_id is not None:
                    s = str(am_id).strip()
                    if s:
                        idx_by_am[int(s)] = u
                else:
                    # Fallback: index by userId for users without activeMembershipId.
                    # device_sync uses userId as the device Pin when activeMembershipId
                    # is null, so the same key must be in this lookup index.
                    user_id = u.get("userId")
                    if user_id is not None:
                        s = str(user_id).strip()
                        if s.isdigit():
                            uid_int = int(s)
                            # Only add if no activeMembershipId user already owns this key
                            if uid_int not in idx_by_am:
                                idx_by_am[uid_int] = u
            except Exception:
                pass

            add_cards_from_obj(idx_by_card, u, u)

            for nested_key in ("activeMembership", "activeMembershipModel", "activeMembershipDto"):
                nested = u.get(nested_key)
                add_cards_from_obj(idx_by_card, nested, u)

            cards = u.get("cards")
            if isinstance(cards, list):
                for c in cards:
                    add_card(idx_by_card, c, u)

    p.done(creds=len(creds), users=len(users))

    return list(creds), dict(idx_by_am), dict(idx_by_card)

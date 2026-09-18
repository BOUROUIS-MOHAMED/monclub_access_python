# app/core/access_verification.py
"""
Shared TOTP / RFID verification logic used by both AGENT and ULTRA engines.

Extracted from realtime_agent.py — pure functions, no class dependency.
"""

import hashlib
import hmac
import logging
import struct
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.core.db import (
    list_sync_users_page,
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

# Roster check verdicts, carried in a matched QR result as ``rosterCheck``.
ROSTER_IN = "in_roster"            # a granted membership is on the PC's member list
ROSTER_IN_BY_ACCOUNT = "in_roster_by_account"  # no grant listed, but the same account is
ROSTER_NOT_IN = "not_in_roster"    # neither: the member was removed from the list
ROSTER_UNEVALUABLE = "roster_empty"  # the PC's member list is empty: nothing to check
ROSTER_BEHIND = "roster_behind"   # not listed, but the list is older than the matching index


# (member-list object, its main account ids). The ULTRA member list is a long-lived,
# read-only object between refreshes, so the set is built once per refresh; the
# AGENT path hands a fresh copy per scan and rebuilds (~1 ms for ~1800 rows).
_roster_account_ids_cache: tuple = (None, frozenset())


def _roster_account_ids(users_by_am: Dict[int, Dict[str, Any]]) -> frozenset:
    global _roster_account_ids_cache
    cached = _roster_account_ids_cache
    if cached[0] is users_by_am:
        return cached[1]
    ids = set()
    for u in users_by_am.values():
        if isinstance(u, dict):
            acc = u.get("mainAccountId")
            if type(acc) is not int:  # SQLite hands back int; coerce anything else
                acc = _safe_int(acc, 0)
            if acc > 0:
                ids.add(acc)
    result = frozenset(ids)
    _roster_account_ids_cache = (users_by_am, result)
    return result


def _account_on_roster(account_id: Any, users_by_am: Dict[int, Dict[str, Any]]) -> bool:
    """True when a row of the member list carries this credential's main account id.

    Only reached when no granted membership is listed (rare), never on an ordinary
    allow."""
    acc = _safe_int(account_id, 0)
    return acc > 0 and acc in _roster_account_ids(users_by_am)

# ``totp_roster_check_mode``: TRIAL records a would-be refusal and still allows;
# ENFORCE refuses (DENY_NOT_IN_LOCAL_ROSTER). Anything else reads as TRIAL.
ROSTER_MODE_TRIAL = "trial"
ROSTER_MODE_ENFORCE = "enforce"


def totp_roster_check_mode(settings: Dict[str, Any]) -> str:
    raw = _safe_str(settings.get("totp_roster_check_mode"), "").strip().lower()
    return ROSTER_MODE_ENFORCE if raw == ROSTER_MODE_ENFORCE else ROSTER_MODE_TRIAL


# Process-wide counts of roster verdicts, one per scan. verify_totp stays pure (the
# resilient wrapper can call it twice per scan, and tests call it freely); the two
# engines record the FINAL result once, after verify_totp_resilient returns.
# ``refused`` = not_in_roster scans actually denied (enforce mode).
ROSTER_REFUSED = "refused"
_roster_counts_lock = threading.Lock()
_roster_counts: Dict[str, int] = {
    ROSTER_IN: 0, ROSTER_IN_BY_ACCOUNT: 0, ROSTER_NOT_IN: 0, ROSTER_UNEVALUABLE: 0,
    ROSTER_BEHIND: 0,
    ROSTER_REFUSED: 0,
}
_roster_counts_since = datetime.now().astimezone().isoformat(timespec="seconds")

# Hourly [T] QR_ROSTER_SUMMARY with the running totals, so the newest uploaded log
# window always says where the counts stand (the owner reads it from the dashboard's
# Access logs page). Gated process-wide: at most one line per interval.
ROSTER_SUMMARY_INTERVAL_SEC = 3600.0
_roster_summary_next_mono = time.monotonic() + ROSTER_SUMMARY_INTERVAL_SEC


def record_totp_roster_check(result: Any, *, source: str = "") -> None:
    """Count one scan's roster verdict; log a [T] line for every non-member verdict.

    No member identity is logged or counted -- only the verdict, the mode and whether
    the scan was allowed. Never raises.
    """
    try:
        verdict = result.get("rosterCheck") if isinstance(result, dict) else None
        if verdict not in (
            ROSTER_IN, ROSTER_IN_BY_ACCOUNT, ROSTER_NOT_IN, ROSTER_UNEVALUABLE, ROSTER_BEHIND,
        ):
            return
        allowed = bool(result.get("allowed"))
        with _roster_counts_lock:
            _roster_counts[verdict] += 1
            if verdict == ROSTER_NOT_IN and not allowed:
                _roster_counts[ROSTER_REFUSED] += 1
        if verdict != ROSTER_IN:
            _tel.event(
                "QR_ROSTER_CHECK", source=source or None, verdict=verdict,
                mode=result.get("rosterCheckMode"), allowed=allowed,
            )
        maybe_log_totp_roster_summary()
    except Exception:
        pass


def totp_roster_check_counts() -> Dict[str, Any]:
    """Counts since this process started:
    ``{since, in_roster, in_roster_by_account, not_in_roster, roster_empty, roster_behind,
    refused}``."""
    with _roster_counts_lock:
        out: Dict[str, Any] = dict(_roster_counts)
    out["since"] = _roster_counts_since
    return out


def maybe_log_totp_roster_summary(*, now_mono: Optional[float] = None) -> bool:
    """Log ``[T] QR_ROSTER_SUMMARY`` once per ROSTER_SUMMARY_INTERVAL_SEC. Cheap when not
    due (one lock, one comparison). Called after each recorded scan and from the ULTRA
    background refresh loop, so a quiet hour still gets its line. Never raises."""
    global _roster_summary_next_mono
    try:
        now = time.monotonic() if now_mono is None else float(now_mono)
        with _roster_counts_lock:
            if now < _roster_summary_next_mono:
                return False
            _roster_summary_next_mono = now + ROSTER_SUMMARY_INTERVAL_SEC
            counts = dict(_roster_counts)
        _tel.event(
            "QR_ROSTER_SUMMARY", since=_roster_counts_since,
            in_roster=counts[ROSTER_IN], in_roster_by_account=counts[ROSTER_IN_BY_ACCOUNT],
            not_in_roster=counts[ROSTER_NOT_IN],
            roster_empty=counts[ROSTER_UNEVALUABLE], roster_behind=counts[ROSTER_BEHIND],
            refused=counts[ROSTER_REFUSED],
        )
        return True
    except Exception:
        return False


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
def _iter_eligible_totp_creds(creds_payload: List[Dict[str, Any]]):
    """Yield ``(cred_id, account_id, secret_bytes, grants)`` for every
    TOTP-eligible credential, applying the EXACT filters the verify loop uses.

    Shared by :func:`verify_totp`'s scan loop and :func:`build_totp_index` so the
    precomputed index can never contain a credential the loop would skip (or
    vice-versa) — that equivalence is what makes the index a safe pure-speed
    optimization rather than a second, divergent code path.
    """
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
        yield cred_id, account_id, secret, grants


def _totp_params(settings: Dict[str, Any]):
    """Resolve (period, drift, digits, prefix) exactly as verify_totp does."""
    period = _safe_int(settings.get("totp_period_seconds", 30))
    drift = _safe_int(settings.get("totp_drift_steps", 1))
    digits = _safe_int(settings.get("totp_digits", 7))
    if digits < 4:
        digits = 4
    if digits > 10:
        digits = 10
    prefix = _safe_str(settings.get("totp_prefix", "9"), "9").strip()
    if (len(prefix) != 1) or (not prefix.isdigit()):
        prefix = "9"
    return period, drift, digits, prefix


def build_totp_index(
    creds_payload: List[Dict[str, Any]],
    settings: Dict[str, Any],
    now_unix: Optional[float] = None,
    margin: int = 1,
) -> Dict[str, Any]:
    """Precompute ``{code -> [hit, ...]}`` for the counter window around ``now``.

    Built off the hot path (the ULTRA bg refresh thread). A scan then resolves
    its owning credential with an O(1) dict lookup instead of HMAC-ing every
    credential, turning ``verify_totp``'s ~350ms cred loop into ~microseconds.

    ``margin`` widens the counter window by ±N steps beyond the drift band so an
    index built a few seconds before the period rolls still covers the next
    scan's window; when it does NOT cover a scan's window (or the params differ),
    ``verify_totp`` transparently falls back to the full loop, so correctness
    never depends on the index being fresh.
    """
    period, drift, digits, prefix = _totp_params(settings)
    now = int(now_unix if now_unix is not None else time.time())
    cur = _totp_counter(now, period)
    lo = cur - int(drift) - int(max(0, margin))
    hi = cur + int(drift) + int(max(0, margin))
    counters = list(range(lo, hi + 1))
    index: Dict[str, List[Dict[str, Any]]] = {}
    n_creds = 0
    for cred_id, account_id, secret, grants in _iter_eligible_totp_creds(creds_payload):
        n_creds += 1
        for ctr in counters:
            try:
                code = _totp_hotp(secret, ctr, digits)
            except Exception:
                continue
            index.setdefault(code, []).append(
                {
                    "credId": str(cred_id),
                    "accountId": str(account_id),
                    "counter": int(ctr),
                    "grants": list(grants),
                }
            )
    return {
        "index": index,
        "counters": set(counters),
        "params": (period, drift, digits, prefix),
        "built_unix": float(now),
        "credCount": n_creds,
    }


def _hits_from_index(
    index: Dict[str, List[Dict[str, Any]]],
    code: str,
    allowed_ctrs: List[int],
) -> List[Dict[str, Any]]:
    """Reconstruct the SAME ``hits`` list the cred loop would build, from the
    precomputed index: one entry per credential (lowest matching counter, which
    is what the ascending-counter loop picks), restricted to ``allowed_ctrs``,
    short-circuiting at the first 2 distinct creds (collision) like the loop.
    """
    raw = index.get(code)
    if not raw:
        return []
    allowed_set = {int(x) for x in allowed_ctrs}
    hits: List[Dict[str, Any]] = []
    seen: set = set()
    for h in raw:
        if int(h["counter"]) not in allowed_set:
            continue
        cid = h["credId"]
        if cid in seen:
            continue
        seen.add(cid)
        hits.append(
            {
                "credId": h["credId"],
                "accountId": h["accountId"],
                "counter": int(h["counter"]),
                "grants": list(h["grants"]),
            }
        )
        if len(seen) > 1:
            break  # 2 distinct creds is enough to force DENY_COLLISION downstream
    return hits


def verify_totp(
    *,
    scanned: str,
    settings: Dict[str, Any],
    creds_payload: List[Dict[str, Any]],
    users_by_am: Dict[int, Dict[str, Any]],
    users_by_card: Dict[str, List[Dict[str, Any]]],
    now_unix: Optional[float] = None,
    totp_index: Optional[Dict[str, Any]] = None,
    roster_current: bool = True,
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

    # Resolve the matching credential(s). FAST PATH: a precomputed index keyed by
    # code (built off the hot path on the bg refresh thread) turns this from an
    # HMAC over every credential into an O(1) dict lookup. The index is consulted
    # ONLY when it was built with the same TOTP params AND fully covers this
    # scan's counter window; otherwise we fall through to the exact same loop, so
    # the decision is byte-for-byte identical whether or not the index is present.
    hits: Optional[List[Dict[str, Any]]] = None
    used_index = False
    if isinstance(totp_index, dict):
        try:
            if (
                totp_index.get("params") == (period, drift, digits, prefix)
                and set(allowed_ctrs).issubset(totp_index.get("counters") or set())
            ):
                hits = _hits_from_index(totp_index.get("index") or {}, code, allowed_ctrs)
                used_index = True
        except Exception:
            hits = None
            used_index = False

    if hits is None:
        hits = []
        for cred_id, account_id, secret, grants in _iter_eligible_totp_creds(creds_payload):
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
                        break  # F-022: one match per credential is sufficient
                except Exception:
                    continue
            # F-022: a collision (2+ distinct cred IDs) is enough to short-circuit
            if len(set(h["credId"] for h in hits)) > 1:
                break

    if logger.isEnabledFor(logging.DEBUG):
        _eligible_creds = sum(1 for _ in _iter_eligible_totp_creds(creds_payload))
        logger.debug(
            "verify_totp: code_len=%d prefix=%r digits=%d eligible_creds=%d "
            "now=%d counter=%d drift=%d period=%d indexed=%s",
            len(raw), prefix, digits, _eligible_creds, now, cur, drift, period, used_index,
        )

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
        roster_hit = False
        for gid in grants:
            try:
                am = int(str(gid).strip())
            except Exception:
                continue
            if am in users_by_am:
                user = users_by_am.get(am)
                chosen_am_id = am
                roster_hit = True
                break
            if chosen_am_id is None:
                chosen_am_id = am

        # Roster check (2026-09-18). The code matched a credential; is any membership
        # it grants on this PC's member list? Decided HERE, after the hits are
        # resolved, so the TOTP index and the loop reach it with the same grants and
        # the same users_by_am -- never in _iter_eligible_totp_creds, which the index
        # shares. An empty member list cannot be told apart from a failed read
        # (load_local_state swallows it), so it is ROSTER_UNEVALUABLE and always allows.
        if roster_hit:
            roster_check = ROSTER_IN
        elif not users_by_am:
            roster_check = ROSTER_UNEVALUABLE
        elif _account_on_roster(account_id, users_by_am):
            # The PC's cached grants can be stale: a member who renewed (new membership
            # id) keeps the old id here until a credentials sync re-sends the grants
            # (guide §3.1b says when that does not happen). The same main account on a
            # listed row is the same person with a valid membership (account<->user is 1:1).
            roster_check = ROSTER_IN_BY_ACCOUNT
        elif used_index and not roster_current:
            # The caller says its member list is older than the index, and the index
            # is what matched: the member may simply be newer than the list. Never
            # refused. (On the loop the caller's own credentials matched, which come
            # from the same load as its list, so the verdict stands.)
            roster_check = ROSTER_BEHIND
        else:
            roster_check = ROSTER_NOT_IN
        roster_mode = totp_roster_check_mode(settings)

        if roster_check == ROSTER_NOT_IN and roster_mode == ROSTER_MODE_ENFORCE:
            return {
                "allowed": False,
                "reason": "DENY_NOT_IN_LOCAL_ROSTER",
                "scanMode": "QR_TOTP",
                "accountId": account_id,
                "credId": cred_id,
                "matchedCounter": matched_ctr,
                "ageSeconds": age,
                "activeMembershipId": chosen_am_id,
                "rosterCheck": roster_check,
                "rosterCheckMode": roster_mode,
                "tookMs": (time.perf_counter() - t0) * 1000.0,
                "user": None,
            }

        return {
            "allowed": True,
            "reason": "ALLOW",
            "scanMode": "QR_TOTP",
            "accountId": account_id,
            "credId": cred_id,
            "matchedCounter": matched_ctr,
            "ageSeconds": age,
            "activeMembershipId": chosen_am_id,
            "rosterCheck": roster_check,
            "rosterCheckMode": roster_mode,
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
    totp_index: Optional[Dict[str, Any]] = None,
    roster_current: bool = True,
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
        totp_index=totp_index, roster_current=roster_current,
    )
    primary_clock = "scan" if now_unix is not None else "wall"
    # A roster refusal already matched a credential: the retry exists for clock skew
    # (no match / expired) and would repeat the full verification for nothing. It could
    # only differ if ANOTHER credential produced the same code in the wall-clock window.
    if (
        primary.get("allowed")
        or now_unix is None
        or primary.get("reason") == "DENY_NOT_IN_LOCAL_ROSTER"
    ):
        primary["clockUsed"] = primary_clock
        return primary

    # Scan-time validation denied — retry against the wall clock so a skewed
    # device clock can't reject a code the PC clock would accept.
    fallback = verify_totp(
        scanned=scanned, settings=settings, creds_payload=creds_payload,
        users_by_am=users_by_am, users_by_card=users_by_card, now_unix=None,
        totp_index=totp_index, roster_current=roster_current,
    )
    # Allowed on the wall clock -- or refused there by the roster check, which means
    # the code DID match a credential: report that verdict (and let it be counted),
    # not the scan-clock pass's no-match/expired.
    if fallback.get("allowed") or fallback.get("reason") == "DENY_NOT_IN_LOCAL_ROSTER":
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
            # Template-free projection on purpose. This state only indexes
            # activeMembershipId / userId and the card fields below; its consumers
            # (ultra_engine._get_cached_local_state -> users_by_am / users_by_card,
            # realtime_agent._load_local_state, verify_totp_resilient,
            # ultra_engine._prefetch_member_images) never read `fingerprints`. The push
            # path takes templates from load_sync_cache() /
            # DeviceSyncEngine._collect_templates_for_pin, never from here. Reading
            # fingerprints_json (~90 % of the row bytes) is what made this reload cost
            # 0.7-6.8 s per worker on the gym PC (DB_READ_users_split select_ms=6828).
            # CAUTION (see list_sync_users_page): every user in this state has
            # fingerprints == [], indistinguishable from "no fingerprints". No consumer
            # of this state may count or push templates from it.
            # [TEST: tests/test_local_state_template_free.py]
            users, _total = list_sync_users_page(limit=0, offset=0, include_templates=False)
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
                    # This index is keyed like a MEMBERSHIP-scheme device pin
                    # (device_sync.derive_member_pin: activeMembershipId, else userId).
                    # It is NOT the pin rule on a pinScheme=ACCOUNT device, whose pin is
                    # mainAccountId: pin -> member there goes through
                    # UltraDeviceWorker._user_for_device_pin (guide §3.2b). The other
                    # consumers (TOTP grants, image prefetch) key by membership id.
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

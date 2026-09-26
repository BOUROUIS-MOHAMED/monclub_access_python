from __future__ import annotations

import hashlib
import json
import logging
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

from access.config import build_access_api_endpoints
from app.core.db import (
    ACCESS_HISTORY_SOURCE_DEVICE,
    AccessHistoryRow,
    insert_access_history_batch,
    list_device_pin_scheme_switches,
    list_pending_access_history_for_sync,
    list_sync_devices_payload,
    load_device_attendance_state,
    expire_unresolved_access_history,
    mark_access_history_sync_failure,
    mark_access_history_synced,
    mark_access_history_unresolved,
    prune_access_history,
    save_device_attendance_state,
)
from app.core.settings_reader import get_backend_global_settings, normalize_device_settings
from app.core.pin_scheme import PIN_SCHEME_ACCOUNT, PIN_SCHEME_MEMBERSHIP, scheme_at
from app.core.utils import now_iso
from app.core.v2 import lease_gate as _lease_gate
from app.sdk.pullsdk import PullSDKDevice
from app.sdk.device_driver import get_driver
from shared.api.monclub_api import MonClubApi, MonClubApiError, MonClubApiHttpError

UPLOAD_BATCH_SIZE = 200
READ_ERROR_RETRY_SECONDS = 300
UPLOAD_FAILURE_RETRY_SECONDS = 300
PURGE_WINDOW_START_HOUR = 2
PURGE_WINDOW_DURATION_HOURS = 3

# ── Rows the backend keeps calling unresolved (its failedIds) ──────────────────────────
# Retry delay doubles per explicit verdict from UPLOAD_FAILURE_RETRY_SECONDS up to this cap,
# so once capped such a row costs one upload a day instead of one per sync tick
# (agentSyncBackendRefreshMin, default 30 min). POLICY, not a measured value.
UNRESOLVED_RETRY_MAX_SECONDS = 24 * 3600
# Explicit unresolved verdicts a row must have collected before it can be expired. A guard,
# not the bound -- the bound is history_retention_days. It ensures a row that first reaches
# the backend after an outage longer than retention still gets several judged attempts
# (the first three are >= 300 s and 600 s of backoff apart) before it is given up on. POLICY.
UNRESOLVED_MIN_VERDICTS_TO_EXPIRE = 3

# HTTP statuses that are a batch-level verdict for a row-level fault: one bad row fails
# the whole request. The batch is isolated row by row, and a row that gets one of these
# ALONE is quarantined as terminal. 400: the backend's Jackson mapping of the array fails
# on one element (GymAccessController.normalizeBulkSaveGymAccessHistoryPayload). 409: its
# GlobalExceptionHandler maps a DataIntegrityViolationException escaping saveAll to 409
# CONFLICT, and saveAll rolls back the whole batch. Every other status (401/403/422/5xx)
# and every network failure is not the rows' fault and keeps the whole-batch retry.
_ROW_VERDICT_HTTP_STATUSES = frozenset({400, 409})

# Response keys whose tokens are per-row RETRYABLE verdicts. Shared by _parse_upload_response
# and _named_retry_row_ids so the two can never disagree about what counts as a verdict.
_RETRY_TOKEN_KEYS = (
    "failedIds",
    "failedEventIds",
    "failedInsertionIds",
    "failedInsertionEventIds",
    "retryableFailedIds",
    "retryableFailedEventIds",
)


def _named_retry_row_ids(
    response: Any,
    row_ids_by_event: Dict[str, int],
    row_ids_by_local: Dict[str, int],
) -> set[int]:
    """Local row ids the response NAMES in a retryable list.

    _parse_upload_response also returns rows as retryable when the body named nothing about
    them -- ``ok`` false with no lists, or rows left over when ``failedCount`` is positive.
    Those are not verdicts on the row and must not count toward expiry; this is how the
    caller tells the two apart. Unwraps and maps tokens exactly as the parser does.
    """
    payload: Dict[str, Any] = response if isinstance(response, dict) else {"raw": response}
    data = payload.get("data")
    if isinstance(data, dict):
        payload = data
    named: set[int] = set()
    for key in _RETRY_TOKEN_KEYS:
        for token in _coerce_id_values(payload.get(key)):
            if token in row_ids_by_local:
                named.add(int(row_ids_by_local[token]))
            elif token in row_ids_by_event:
                named.add(int(row_ids_by_event[token]))
    return named


def _safe_str(v: Any, default: str = "") -> str:
    if v is None:
        return default
    try:
        return str(v)
    except Exception:
        return default


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(str(v).strip())
    except Exception:
        return default


def _boolish(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    s = _safe_str(v, "").strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return True
    if s in {"0", "false", "no", "off"}:
        return False
    return default


def _load_json_object(raw: str) -> Dict[str, Any]:
    txt = _safe_str(raw, "").strip()
    if not txt:
        return {}
    try:
        data = json.loads(txt)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _dt_from_any(value: Any) -> Optional[datetime]:
    raw = _safe_str(value, "").strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1]
    try:
        if raw.isdigit():
            iv = int(raw)
            if iv > 10_000_000_000:
                return datetime.fromtimestamp(iv / 1000.0)
            if iv > 1_000_000_000:
                return datetime.fromtimestamp(iv)
        return datetime.fromisoformat(raw.replace("T", " "))
    except Exception:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(raw, fmt)
        except Exception:
            continue
    return None


def _normalize_datetime_text(value: Any, fallback: str | None = None) -> str:
    dt_value = _dt_from_any(value)
    if dt_value is not None:
        return dt_value.strftime("%Y-%m-%dT%H:%M:%S")
    txt = _safe_str(value, "").strip()
    if txt:
        # Reached only when _dt_from_any could NOT parse the text (every valid ISO /
        # common form is handled above), i.e. the value is junk -- e.g. a month or
        # day of 00 from a terminal record. Until 2026-09-02 it was forwarded
        # verbatim and the backend's LocalDateTime mapping then rejected the WHOLE
        # batch with HTTP 400. Use the fallback (the PC's own receive time) and say
        # so, rather than send something no parser can accept. Hardening of a
        # proven gap; not asserted to be the cause of any specific field 400.
        logging.getLogger("zkapp").warning(
            "[DeviceAttendance] unparseable event time %r -- using fallback %r", txt[:40], fallback,
        )
    fb = _safe_str(fallback, "").strip()
    if fb:
        fb_dt = _dt_from_any(fb)
        if fb_dt is not None:
            return fb_dt.strftime("%Y-%m-%dT%H:%M:%S")
    from app.core.utils import now_iso
    return now_iso().replace(" ", "T")


def _lower_keys(row: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in (row or {}).items():
        k = _safe_str(key, "").strip().lower()
        if k and k not in out:
            out[k] = value
    return out


def _pick_ci(lowered: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        k = _safe_str(key, "").strip().lower()
        if k in lowered:
            return lowered.get(k)
    return None


def _canonicalize_row(device_id: int, row: Dict[str, Any]) -> Dict[str, Any]:
    canonical: Dict[str, Any] = {"deviceId": int(device_id), "row": {}}
    target = canonical["row"]
    assert isinstance(target, dict)
    for key in sorted(row.keys(), key=lambda x: _safe_str(x, "").lower()):
        normalized_key = _safe_str(key, "").strip().lower()
        if not normalized_key:
            continue
        target[normalized_key] = _safe_str(row.get(key), "").strip()
    return canonical


def _sha1_obj(obj: Any) -> str:
    payload = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


def _normalize_card_token(value: Any) -> str:
    token = _safe_str(value, "").strip()
    if not token:
        return ""
    return token.replace(" ", "")


def _credential_type_from_raw(lowered: Dict[str, Any]) -> str:
    # QR/TOTP entries are software-verified by the access app (the device sees only a
    # rotating token, no verifytype), so they carry an explicit scanMode tag instead.
    scan_mode = _safe_str(_pick_ci(lowered, "scanmode", "scan_mode"), "").upper()
    if "QR" in scan_mode or "TOTP" in scan_mode:
        return "QR_CODE"

    # ZK_STANDALONE (zkemkeeper / MB2000) publishes an explicit TEXTUAL modality tag
    # per punch as rawRow["scan_mode_hint"] (app/sdk/zk_standalone.py). Trust it
    # BEFORE the numeric heuristic below.
    #
    # It MUST be read as text, never fed through that digit table: the table is the
    # PullSDK/C3 verify namespace, where "2" means fingerprint -- but in the zkem
    # namespace 2 means CARD (zk_standalone._VERIFY_METHOD_SCAN_MODE, corroborated by
    # tools/mb2000_scripts/8_live_monitor.ps1). Routing the zkem integer through it
    # would relabel every MB2000 card scan as a fingerprint: a worse bug than the one
    # this fixes. PullSDK rows carry no scan_mode_hint, so C2-400 output is unchanged.
    hint = _safe_str(_pick_ci(lowered, "scan_mode_hint", "scanmodehint"), "").strip().upper()
    if hint in ("FINGERPRINT", "FINGER_PRINT"):
        return "FINGER_PRINT"
    if hint in ("RFID_CARD", "CARD"):
        return "CARD"

    verify = _safe_str(
        _pick_ci(lowered, "verifytype", "verified", "verifymode", "verify_mode", "credentialtype", "type"),
        "",
    ).strip()
    verify_upper = verify.upper()
    verify_digits = verify if verify.isdigit() else ""

    if any(token in verify_upper for token in ("FACE", "FACIAL")) or verify_digits in {"15", "17"}:
        return "FACE_ID"
    if any(token in verify_upper for token in ("FINGER", "FP", "BIO")) or verify_digits in {
        "1",
        "2",
        "6",
        "7",
        "8",
        "9",
    }:
        return "FINGER_PRINT"
    return "CARD"


def _direction_from_raw(lowered: Dict[str, Any]) -> Optional[str]:
    raw = _safe_str(
        _pick_ci(lowered, "direction", "inoutstatus", "inoutstate", "state", "status"),
        "",
    ).strip()
    if not raw:
        return None
    upper = raw.upper()
    if upper in {"IN", "ENTRY", "ENTER"}:
        return "IN"
    if upper in {"OUT", "EXIT", "LEAVE"}:
        return "OUT"
    if raw == "1":
        return "IN"
    if raw in {"2", "3"}:
        return "OUT"
    if raw == "0":
        return "IN"
    return upper


def _allowed_and_reason_from_raw(lowered: Dict[str, Any], event_type: str) -> Tuple[bool, str]:
    raw_reason = _safe_str(
        _pick_ci(lowered, "reason", "description", "eventdesc", "event_name", "event"),
        "",
    ).strip()
    haystack = f"{event_type} {raw_reason}".lower()
    if any(token in haystack for token in ("deny", "denied", "illegal", "invalid", "reject", "alarm", "error")):
        return False, raw_reason or "DEVICE_TRANSACTION_DENIED"
    return True, raw_reason or "DEVICE_TRANSACTION"


def _device_row_to_history(
    *,
    device_id: int,
    device_name: str,
    raw_row: Dict[str, Any],
    fallback_time: str,
) -> Dict[str, Any]:
    lowered = _lower_keys(raw_row)
    event_time = _normalize_datetime_text(
        _pick_ci(
            lowered,
            "eventtime",
            "time",
            "datetime",
            "date",
            "verifytime",
            "transactiontime",
            "timestamp",
        ),
        fallback=fallback_time,
    )
    event_type = _safe_str(
        _pick_ci(lowered, "eventtype", "event", "description", "verifytype", "verified", "type"),
        "",
    ).strip() or "DEVICE_TRANSACTION"
    card_no = _normalize_card_token(
        _pick_ci(lowered, "cardno", "card", "cardid", "badgeid", "credno", "credentialid"),
    )
    door_raw = _pick_ci(lowered, "doorid", "door", "eventaddr", "readerid", "doorno")
    door_id = _safe_int(door_raw, 0)
    if door_id <= 0:
        door_id = 0

    allowed, reason = _allowed_and_reason_from_raw(lowered, event_type)
    canonical = _canonicalize_row(device_id, raw_row)
    event_id = _sha1_obj(canonical)
    payload_raw = dict(raw_row)
    payload_raw.setdefault("_deviceId", int(device_id))
    payload_raw.setdefault("_deviceName", _safe_str(device_name, ""))

    return {
        "event_id": event_id,
        "device_id": int(device_id),
        "door_id": int(door_id) if door_id > 0 else None,
        "card_no": card_no,
        "event_time": event_time,
        "event_type": event_type,
        "allowed": bool(allowed),
        "reason": reason,
        "poll_ms": None,
        "decision_ms": None,
        "cmd_ms": None,
        "cmd_ok": None,
        "cmd_error": None,
        "raw": payload_raw,
        "history_source": ACCESS_HISTORY_SOURCE_DEVICE,
    }


def _user_indexes(
    users: Iterable[Dict[str, Any]],
) -> Tuple[Dict[int, Dict[str, Any]], Dict[str, Dict[str, Any]], Dict[int, Dict[str, Any]]]:
    """(by activeMembershipId, by card, by mainAccountId).

    The account index exists because the device PIN is derived from the PERSON
    (``main_account.id``) — see ``device_sync._filter_users_for_device``. A device reports a
    pin; without this index that pin is looked up in the membership index, where it either
    misses entirely or — for the ids that numerically collide between the two sequences —
    silently matches a REAL BUT UNRELATED member.

    One person may hold several memberships, so the account index resolves to the row the
    device's single collapsed row actually represents: the furthest-reaching one, chosen by
    the SAME ``furthest_reach`` helper the push uses. If these two disagreed, a door event
    would be attributed to a different membership than the one that opened the door.
    """
    by_am: Dict[int, Dict[str, Any]] = {}
    by_card: Dict[str, Dict[str, Any]] = {}
    by_account_rows: Dict[int, List[Dict[str, Any]]] = {}
    for user in users or []:
        if not isinstance(user, dict):
            continue
        am = _safe_int(user.get("activeMembershipId") or user.get("active_membership_id"), 0)
        if am > 0 and am not in by_am:
            by_am[am] = user
        acct = _safe_int(user.get("mainAccountId") or user.get("main_account_id"), 0)
        if acct > 0:
            by_account_rows.setdefault(acct, []).append(user)
        for key in ("firstCardId", "secondCardId", "first_card_id", "second_card_id", "cardNo", "card_no"):
            token = _normalize_card_token(user.get(key))
            if token and token not in by_card:
                by_card[token] = user

    from app.core.device_sync import furthest_reach

    by_account: Dict[int, Dict[str, Any]] = {}
    for acct, rows in by_account_rows.items():
        chosen = furthest_reach(rows)
        if chosen is not None:
            by_account[acct] = chosen
    return by_am, by_card, by_account


def _resolve_history_user(
    row: AccessHistoryRow,
    raw: Dict[str, Any],
    users_by_am: Dict[int, Dict[str, Any]],
    users_by_card: Dict[str, Dict[str, Any]],
    users_by_account: Optional[Dict[int, Dict[str, Any]]] = None,
    pin_scheme: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """The member a door-history row names: by its pin, else by its card.

    ``pin_scheme`` is the scheme the row's DEVICE ran when the event happened
    (``HistoryPinResolver.scheme_for``). When it is known the pin is read under exactly that
    scheme -- never the other index, because the two id sequences collide (110 values on the
    2026-09-12 data, 99 of them different people). ``None`` means it cannot be known (a
    legacy caller, or a switched device with an unparseable event time): then the
    unambiguous reading is used and a pin that is both prefers the MEMBERSHIP reading.
    """
    lowered = _lower_keys(raw)
    pin_raw = _pick_ci(lowered, "pin", "userid", "userpin", "personid", "enrollnumber")
    pin = _safe_int(pin_raw, 0)

    if pin_scheme in (PIN_SCHEME_ACCOUNT, PIN_SCHEME_MEMBERSHIP):
        index = (users_by_account or {}) if pin_scheme == PIN_SCHEME_ACCOUNT else users_by_am
        if pin > 0 and pin in index:
            return index[pin]
        card = _normalize_card_token(row.card_no or _pick_ci(lowered, "cardno", "card", "cardid"))
        if card and card in users_by_card:
            return users_by_card[card]
        return None

    # SCHEME UNKNOWN. Use whichever reading is unambiguous. c13d1c2 consulted the account
    # index unconditionally first, which INVERTED correctness on a device still holding
    # membership pins; the ambiguous case below prefers the membership reading.
    acct_hit = users_by_account.get(pin) if (pin > 0 and users_by_account) else None
    am_hit = users_by_am.get(pin) if pin > 0 else None

    if acct_hit is not None and am_hit is None:
        return acct_hit
    if am_hit is not None and acct_hit is None:
        return am_hit
    if acct_hit is not None and am_hit is not None:
        # AMBIGUOUS, and it cannot be resolved by inspection: this pin is simultaneously
        # one person's main_account.id and another person's active_membership.id. On the
        # 2026-09-12 dump that is 110 values, and for 99 of them the two are DIFFERENT
        # people (0 are the same person), so guessing wrong attributes a door event to a
        # stranger.
        #
        # Prefer the MEMBERSHIP reading, because that is what a device actually holds until
        # it has been wiped and re-pushed. An earlier revision consulted the account index
        # unconditionally first, which INVERTED correctness during the rollout window: a
        # device still holding old membership pins would have had those 110 resolved to the
        # account owner — a bug that did not exist before the account index was introduced.
        #
        # Reached only when the scheme cannot be known: HistoryPinResolver reads every pin
        # under its device's recorded scheme (guide §3.2b), so this is a legacy caller, a
        # device with history whose event time did not parse, or an event stamped before this
        # database first saw the device already on ACCOUNT (guide §3.2e, first sighting).
        logging.getLogger("zkapp").warning(
            "[DeviceAttendance] ambiguous pin %s on device %s — it is both an account id and "
            "a membership id for different people, and the device's pin scheme at this "
            "event's time cannot be determined; resolving as MEMBERSHIP.",
            pin, getattr(row, "device_id", None),
        )
        return am_hit

    card = _normalize_card_token(row.card_no or _pick_ci(lowered, "cardno", "card", "cardid"))
    if card and card in users_by_card:
        return users_by_card[card]
    return None


class HistoryPinResolver:
    """Resolve door-history rows under the pin scheme each row's DEVICE ran at the event's time.

    * scheme: the device's ``device_pin_scheme_switch`` history (``db.list_device_pin_scheme_switches``)
      read by ``pin_scheme.scheme_at`` at the row's ``event_time`` (the DEVICE's clock). No
      recorded row -> MEMBERSHIP. A device with rows and an unparseable time -> None; an event
      before a FIRST SIGHTING already on ACCOUNT (previous_scheme 'UNKNOWN') -> None.
    * ACCOUNT pins resolve through the collapsed row ``_filter_users_for_device`` builds for
      THAT device -- its allowedMemberships / validity policy and ``pin_row_rank`` -- so an
      event names the membership the device row represents. A device no longer in the cache
      falls back to the unfiltered by-account index, ranked the same way.
    * MEMBERSHIP pins resolve through the membership index only.

    Built once per upload batch / dashboard cache; the per-device ACCOUNT index is memoised.
    """

    def __init__(
        self,
        *,
        users: Iterable[Dict[str, Any]],
        devices_by_id: Dict[int, Dict[str, Any]] | None,
        switches_by_device: Dict[int, List[Dict[str, Any]]] | None,
    ) -> None:
        self.users = [u for u in (users or []) if isinstance(u, dict)]
        self.users_by_am, self.users_by_card, self.users_by_account = _user_indexes(self.users)
        self._devices_by_id = {int(k): v for k, v in (devices_by_id or {}).items()}
        self._switches: Dict[int, List[Tuple[str, Optional[datetime], str]]] = {}
        for device_id, entries in (switches_by_device or {}).items():
            # previous_scheme travels too: 'UNKNOWN' on the first row is a first sighting, and
            # events before it have no known scheme (pin_scheme.scheme_at).
            self._switches[int(device_id)] = [
                (str((e or {}).get("scheme") or ""), _dt_from_any((e or {}).get("switched_at")),
                 str((e or {}).get("previous_scheme") or PIN_SCHEME_MEMBERSHIP))
                for e in (entries or [])
            ]
        self._account_index: Dict[int, Dict[int, Dict[str, Any]]] = {}

    def scheme_for(self, row: Any) -> Optional[str]:
        device_id = _safe_int(getattr(row, "device_id", None), 0)
        switches = self._switches.get(device_id) or []
        if not switches:
            return PIN_SCHEME_MEMBERSHIP
        return scheme_at(switches, _dt_from_any(getattr(row, "event_time", None)))

    def account_index_for(self, device_id: Any) -> Dict[int, Dict[str, Any]]:
        did = _safe_int(device_id, 0)
        cached = self._account_index.get(did)
        if cached is not None:
            return cached
        device = self._devices_by_id.get(did)
        if not isinstance(device, dict):
            index = dict(self.users_by_account)
        else:
            from types import SimpleNamespace

            from app.core.device_sync import DeviceSyncEngine

            scoped = dict(device)
            # The event was minted under ACCOUNT even if the device has since switched back.
            scoped["pinScheme"] = PIN_SCHEME_ACCOUNT
            by_pin = DeviceSyncEngine(
                cfg=SimpleNamespace(), logger=logging.getLogger("zkapp"),
            )._filter_users_for_device(users=self.users, device=scoped, default_door_id=1)
            index = {int(p): u for p, u in by_pin.items() if str(p).isdigit()}
        self._account_index[did] = index
        return index

    def resolve(self, row: Any, raw: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        scheme = self.scheme_for(row)
        by_account = (
            self.account_index_for(getattr(row, "device_id", None))
            if scheme == PIN_SCHEME_ACCOUNT else self.users_by_account
        )
        user = _resolve_history_user(
            row, raw, self.users_by_am, self.users_by_card, by_account, pin_scheme=scheme,
        )
        return user, scheme


def _coerce_id_values(values: Any) -> List[str]:
    out: List[str] = []
    if isinstance(values, list):
        items = values
    elif values in (None, ""):
        items = []
    else:
        items = [values]
    for item in items:
        if isinstance(item, dict):
            for key in ("eventId", "event_id", "localRowId", "local_row_id", "id"):
                if key in item and item.get(key) not in (None, ""):
                    out.append(_safe_str(item.get(key), "").strip())
                    break
            continue
        token = _safe_str(item, "").strip()
        if token:
            out.append(token)
    return out


def _stable_jitter(device_id: int, *, max_seconds: int) -> int:
    if max_seconds <= 0:
        return 0
    digest = hashlib.sha1(f"attendance:{int(device_id)}".encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % (int(max_seconds) + 1)


class DeviceAttendanceMaintenanceEngine:
    def __init__(self, *, cfg, logger):
        self.cfg = cfg
        self.logger = logger
        self._run_lock = threading.Lock()
        self._running = False

    def run_blocking(self, *, source: str = "timer", sync_online: bool = False, token: str | None = None) -> Dict[str, Any]:
        with self._run_lock:
            if self._running:
                self.logger.info("[DeviceAttendance] Skip (%s): already running", source)
                return {"ok": True, "skipped": True, "source": source}
            self._running = True

        summary: Dict[str, Any] = {
            "ok": True,
            "source": source,
            "devicesConsidered": 0,
            "devicesRead": 0,
            "rowsRead": 0,
            "rowsInserted": 0,
            "devicesPurged": 0,
            "rowsPurged": 0,
            "uploaded": 0,
            "uploadFailed": 0,
            "expired": 0,
            "pruned": 0,
        }

        try:
            global_settings = get_backend_global_settings() or {}
            devices = self._list_device_candidates(global_settings)
            summary["devicesConsidered"] = len(devices)

            for device_payload, device_settings in devices:
                device_summary = self._process_device(
                    device_payload=device_payload,
                    device_settings=device_settings,
                    global_settings=global_settings,
                )
                summary["devicesRead"] += int(device_summary.get("deviceRead", 0))
                summary["rowsRead"] += int(device_summary.get("rowsRead", 0))
                summary["rowsInserted"] += int(device_summary.get("rowsInserted", 0))
                summary["devicesPurged"] += int(device_summary.get("devicePurged", 0))
                summary["rowsPurged"] += int(device_summary.get("rowsPurged", 0))

            upload_summary = self._sync_pending_history(token=token, sync_online=sync_online)
            summary["uploaded"] = int(upload_summary.get("uploaded", 0))
            summary["uploadFailed"] = int(upload_summary.get("failed", 0))

            retention_days = max(1, _safe_int(global_settings.get("history_retention_days"), 30))
            # Expire BEFORE pruning: an expired row is already past retention, so the prune
            # right below deletes it in this same pass (see expire_unresolved_access_history).
            summary["expired"] = int(
                expire_unresolved_access_history(
                    retention_days=retention_days,
                    min_unresolved_verdicts=UNRESOLVED_MIN_VERDICTS_TO_EXPIRE,
                )
            )
            summary["pruned"] = int(prune_access_history(retention_days=retention_days))

            self.logger.info(
                "[DeviceAttendance] source=%s devices=%s read_devices=%s rows_read=%s inserted=%s purged_devices=%s purged_rows=%s uploaded=%s upload_failed=%s expired=%s pruned=%s",
                source,
                summary["devicesConsidered"],
                summary["devicesRead"],
                summary["rowsRead"],
                summary["rowsInserted"],
                summary["devicesPurged"],
                summary["rowsPurged"],
                summary["uploaded"],
                summary["uploadFailed"],
                summary["expired"],
                summary["pruned"],
            )
            return summary
        except Exception as exc:
            self.logger.exception("[DeviceAttendance] Failed: %s", exc)
            summary["ok"] = False
            summary["error"] = str(exc)
            return summary
        finally:
            with self._run_lock:
                self._running = False

    def _list_device_candidates(self, global_settings: Dict[str, Any]) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
        out: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
        for device in list_sync_devices_payload():
            if not isinstance(device, dict):
                continue
            settings = normalize_device_settings(device, global_settings)
            if settings.get("access_data_mode") != "DEVICE":
                continue
            if not _boolish(device.get("active", True), True):
                continue
            if not _boolish(device.get("accessDevice", device.get("access_device", True)), True):
                continue
            if not _lease_gate.device_allowed(device.get("id")):
                # P3b-2: another PC drives this turnstile (driver/reader assignment).
                continue
            out.append((device, settings))
        return out

    def _prepare_pullsdk_payload(self, device_payload: Dict[str, Any], device_settings: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(device_payload or {})
        if not payload.get("ip"):
            payload["ip"] = payload.get("ipAddress") or payload.get("ip_address") or ""
        if not payload.get("port"):
            payload["port"] = payload.get("portNumber") or payload.get("port_number") or 4370
        if not payload.get("devicePort"):
            payload["devicePort"] = payload.get("port")
        if not payload.get("timeoutMs"):
            payload["timeoutMs"] = (
                payload.get("timeout_ms")
                or device_settings.get("timeout_ms")
                or getattr(self.cfg, "timeout_ms", 5000)
                or 5000
            )
        if not payload.get("dllPath"):
            payload["dllPath"] = getattr(self.cfg, "plcomm_dll_path", "") or ""
        return payload

    def _is_read_due(self, *, device_id: int, state, delay_seconds: int, now_dt: datetime) -> bool:
        last_value = ""
        if state:
            last_value = _safe_str(getattr(state, "last_read_finished_at", ""), "")
            if not last_value:
                last_value = _safe_str(getattr(state, "last_read_started_at", ""), "")
        if not last_value:
            return True

        last_dt = _dt_from_any(last_value)
        if last_dt is None:
            return True

        retry_delay = int(delay_seconds)
        if state and _safe_str(getattr(state, "last_read_error", ""), "").strip():
            retry_delay = min(retry_delay, READ_ERROR_RETRY_SECONDS)

        jitter = _stable_jitter(device_id, max_seconds=min(300, max(30, retry_delay // 10)))
        return now_dt >= (last_dt + timedelta(seconds=max(60, retry_delay) + jitter))

    def _purge_slot_for_today(self, device_id: int, now_dt: datetime) -> datetime:
        window_start = now_dt.replace(
            hour=PURGE_WINDOW_START_HOUR,
            minute=0,
            second=0,
            microsecond=0,
        )
        slot_minutes = _stable_jitter(device_id, max_seconds=(PURGE_WINDOW_DURATION_HOURS * 60) - 1)
        return window_start + timedelta(minutes=slot_minutes)

    def _is_purge_due(self, *, device_id: int, state, now_dt: datetime) -> bool:
        last_purge_raw = _safe_str(getattr(state, "last_purge_at", ""), "") if state else ""
        last_purge_dt = _dt_from_any(last_purge_raw) if last_purge_raw else None
        if last_purge_dt and last_purge_dt.date() == now_dt.date():
            return False

        window_start = now_dt.replace(hour=PURGE_WINDOW_START_HOUR, minute=0, second=0, microsecond=0)
        window_end = window_start + timedelta(hours=PURGE_WINDOW_DURATION_HOURS)
        if now_dt < window_start or now_dt >= window_end:
            return False
        return now_dt >= self._purge_slot_for_today(device_id, now_dt)

    def _read_device_transactions(
        self,
        *,
        sdk_device: PullSDKDevice,
        device_id: int,
        device_name: str,
        initial_size: int,
    ) -> Tuple[int, int]:
        raw_rows = sdk_device.read_transaction_rows(options="new record", initial_size=initial_size)
        fallback_time = now_iso()
        rows = [
            _device_row_to_history(
                device_id=device_id,
                device_name=device_name,
                raw_row=row,
                fallback_time=fallback_time,
            )
            for row in raw_rows
            if isinstance(row, dict)
        ]
        inserted = insert_access_history_batch(rows=rows)
        return len(rows), int(inserted)

    def _process_device(
        self,
        *,
        device_payload: Dict[str, Any],
        device_settings: Dict[str, Any],
        global_settings: Dict[str, Any],
    ) -> Dict[str, Any]:
        device_id = _safe_int(device_payload.get("id"), 0)
        device_name = _safe_str(device_payload.get("name"), f"device-{device_id}")
        summary = {"deviceRead": 0, "rowsRead": 0, "rowsInserted": 0, "devicePurged": 0, "rowsPurged": 0}
        if device_id <= 0:
            return summary
        if not _boolish(device_settings.get("save_history"), True):
            self.logger.info("[DeviceAttendance] Skip device=%s name=%r: saveHistory disabled", device_id, device_name)
            return summary

        state = load_device_attendance_state(device_id)
        now_dt = datetime.now()
        read_due = self._is_read_due(
            device_id=device_id,
            state=state,
            delay_seconds=max(60, _safe_int(device_settings.get("device_attendance_history_reading_delay_seconds"), 1800)),
            now_dt=now_dt,
        )
        purge_due = self._is_purge_due(device_id=device_id, state=state, now_dt=now_dt)
        if not read_due and not purge_due:
            return summary

        sdk_initial_size = _safe_int(global_settings.get("sdk_read_initial_bytes"), 1_048_576)
        # Route through the driver factory (protocol-keyed). Defaults to ZK_PULLSDK
        # -> PullSDKDevice, so this is a pure indirection for existing gyms.
        sdk_device = get_driver(self._prepare_pullsdk_payload(device_payload, device_settings), logger=self.logger)

        # Drivers whose SDK exposes no PullSDK-style "transaction" table can be
        # neither read nor purged here. Skip loudly and BEFORE any call, because:
        #   * calling delete_all_transaction_rows() on such a driver used to raise
        #     AttributeError (seen in the field on the MB2000), and
        #   * the purge bookkeeping below would otherwise record a purge that never
        #     happened -- get_table_count() returns 0, so it writes a success state
        #     for work no device ever did.
        # No disconnect() here: construction has not opened anything, and on
        # ZK_STANDALONE the live ULTRA worker owns the real COM connection.
        # getattr default True keeps every PullSDK gym on exactly its old path.
        if not getattr(sdk_device, "supports_transaction_table", True):
            self.logger.info(
                "[DeviceAttendance] device=%s name=%r skipped: driver %s exposes no transaction "
                "table (events arrive through its own event source instead)",
                device_id, device_name, type(sdk_device).__name__,
            )
            return summary

        try:
            if read_due:
                started_at = now_iso()
                save_device_attendance_state(
                    device_id=device_id,
                    last_read_started_at=started_at,
                    last_read_error="",
                )
                try:
                    rows_read, rows_inserted = self._read_device_transactions(
                        sdk_device=sdk_device,
                        device_id=device_id,
                        device_name=device_name,
                        initial_size=sdk_initial_size,
                    )
                    save_device_attendance_state(
                        device_id=device_id,
                        last_read_started_at=started_at,
                        last_read_finished_at=now_iso(),
                        last_read_event_count=int(rows_read),
                        last_read_error="",
                    )
                    summary["deviceRead"] = 1
                    summary["rowsRead"] += int(rows_read)
                    summary["rowsInserted"] += int(rows_inserted)
                    self.logger.info(
                        "[DeviceAttendance] device=%s name=%r read=%s inserted=%s",
                        device_id,
                        device_name,
                        rows_read,
                        rows_inserted,
                    )

                    # P5: Clear transaction table immediately after every successful read.
                    # Prevents record accumulation (which slows RTLog reads and TOTP lookups).
                    # Records are already in local SQLite — safe to clear from device.
                    # The 2-5 AM purge window remains as a safety-net drain.
                    _auto_clear = _boolish(global_settings.get("clear_transactions_after_read", True), True)
                    if _auto_clear:
                        try:
                            sdk_device.delete_all_transaction_rows()
                            save_device_attendance_state(
                                device_id=device_id,
                                last_purge_at=now_iso(),
                                last_purge_deleted_count=int(rows_read),
                                last_purge_error="",
                            )
                            summary["devicePurged"] = 1
                            summary["rowsPurged"] += int(rows_read)
                            self.logger.info(
                                "[DeviceAttendance] device=%s name=%r auto-cleared %s transaction(s) after read",
                                device_id, device_name, rows_read,
                            )
                        except Exception as _clr_exc:
                            # Non-fatal: cleared on next cycle or by 2AM safety-net purge
                            self.logger.warning(
                                "[DeviceAttendance] device=%s name=%r auto-clear after read failed (non-fatal): %s",
                                device_id, device_name, _clr_exc,
                            )

                except Exception as exc:
                    save_device_attendance_state(
                        device_id=device_id,
                        last_read_started_at=started_at,
                        last_read_finished_at=now_iso(),
                        last_read_event_count=0,
                        last_read_error=str(exc),
                    )
                    self.logger.warning(
                        "[DeviceAttendance] device=%s name=%r read failed: %s",
                        device_id,
                        device_name,
                        exc,
                    )
                    return summary

            if purge_due:
                try:
                    drain_read, drain_inserted = self._read_device_transactions(
                        sdk_device=sdk_device,
                        device_id=device_id,
                        device_name=device_name,
                        initial_size=sdk_initial_size,
                    )
                    if drain_read or drain_inserted:
                        save_device_attendance_state(
                            device_id=device_id,
                            last_read_finished_at=now_iso(),
                            last_read_event_count=int(drain_read),
                            last_read_error="",
                        )
                        summary["rowsRead"] += int(drain_read)
                        summary["rowsInserted"] += int(drain_inserted)

                    total_before_delete = sdk_device.get_table_count(table="transaction", filter_expr="", options="")
                    if int(total_before_delete) != 0:
                        delete_rc = sdk_device.delete_all_transaction_rows()
                        if int(delete_rc) < 0:
                            raise RuntimeError("DeleteDeviceData(transaction) failed")

                    save_device_attendance_state(
                        device_id=device_id,
                        last_purge_at=now_iso(),
                        last_purge_deleted_count=max(int(total_before_delete), 0),
                        last_purge_error="",
                    )
                    summary["devicePurged"] = 1
                    summary["rowsPurged"] += max(int(total_before_delete), 0)
                    self.logger.info(
                        "[DeviceAttendance] device=%s name=%r purged=%s drain_read=%s drain_inserted=%s",
                        device_id,
                        device_name,
                        max(int(total_before_delete), 0),
                        drain_read,
                        drain_inserted,
                    )
                except Exception as exc:
                    save_device_attendance_state(
                        device_id=device_id,
                        last_purge_error=str(exc),
                    )
                    self.logger.warning(
                        "[DeviceAttendance] device=%s name=%r purge failed: %s",
                        device_id,
                        device_name,
                        exc,
                    )
        finally:
            try:
                sdk_device.disconnect()
            except Exception:
                pass

        return summary

    def _serialize_row_for_backend(
        self,
        *,
        row: AccessHistoryRow,
        users_by_am: Dict[int, Dict[str, Any]],
        users_by_card: Dict[str, Dict[str, Any]],
        devices_by_id: Dict[int, Dict[str, Any]],
        users_by_account: Optional[Dict[int, Dict[str, Any]]] = None,
        resolver: Optional[HistoryPinResolver] = None,
    ) -> Dict[str, Any]:
        raw = _load_json_object(row.raw_json)
        lowered = _lower_keys(raw)
        scheme_known = resolver is not None
        pin_scheme: Optional[str] = None
        if resolver is not None:
            user, pin_scheme = resolver.resolve(row, raw)
        else:
            user = _resolve_history_user(row, raw, users_by_am, users_by_card, users_by_account)
        pin_raw = _pick_ci(lowered, "pin", "userid", "userpin", "personid", "enrollnumber")
        pin = _safe_int(pin_raw, 0)
        if pin <= 0 and user:
            pin = _safe_int(user.get("activeMembershipId") or user.get("active_membership_id"), 0)

        device = devices_by_id.get(int(row.device_id or 0), {})
        item: Dict[str, Any] = {
            "localRowId": int(row.id),
            "eventId": _safe_str(row.event_id, ""),
            # The raw pin is a membership id ONLY under MEMBERSHIP (or for a legacy caller that
            # knows no scheme -- the pre-existing behaviour). Under ACCOUNT it is a person id,
            # and when the scheme is unknowable it could be either; posted as activeMembership
            # it would be filed against whoever holds that membership id. guide §3.2b.
            "activeMembership": (
                int(pin) if (pin > 0 and (not scheme_known or pin_scheme == PIN_SCHEME_MEMBERSHIP))
                else None
            ),
            "deviceId": int(row.device_id) if row.device_id is not None else None,
            "deviceName": _safe_str(device.get("name"), ""),
            "doorId": int(row.door_id) if row.door_id is not None else None,
            "cardId": _normalize_card_token(row.card_no),
            "cardNo": _normalize_card_token(row.card_no),
            "pin": int(pin) if pin > 0 else None,
            "type": _credential_type_from_raw(lowered),
            "direction": _direction_from_raw(lowered),
            "date": _normalize_datetime_text(row.event_time, fallback=row.created_at),
            "eventType": _safe_str(row.event_type, ""),
            "allowed": bool(row.allowed),
            "reason": _safe_str(row.reason, ""),
            "historySource": _safe_str(row.history_source, ""),
        }

        if not user and scheme_known and pin_scheme == PIN_SCHEME_ACCOUNT and _safe_int(pin_raw, 0) > 0:
            # An account pin the local roster cannot name: send it as the PERSON. The backend
            # history ingest resolves mainAccountId gym-scoped and uses activeMembership only
            # when no person identifier is present.
            item["mainAccountId"] = int(_safe_int(pin_raw, 0))

        if user:
            active_membership_id = _safe_int(
                user.get("activeMembershipId") or user.get("active_membership_id"),
                0,
            ) or (int(pin) if pin > 0 else None)
            item["userId"] = _safe_int(user.get("userId") or user.get("user_id"), 0) or None
            item["activeMembership"] = active_membership_id
            item["activeMembershipId"] = active_membership_id
            item["membershipId"] = _safe_int(user.get("membershipId") or user.get("membership_id"), 0) or None
            item["userFullName"] = _safe_str(user.get("fullName") or user.get("full_name"), "")
            item["userPhone"] = _safe_str(user.get("phone"), "")
            item["userEmail"] = _safe_str(user.get("email"), "")

        # Fallback for rows the uploader cannot re-resolve from pin/card — notably
        # QR/TOTP, whose card_no is a rotating token absent from users_by_card. The
        # realtime agent already resolved the member at verify time and persisted it on
        # the row; use it so the backend (which keys solely on activeMembership) does
        # not silently drop the entry.
        if item.get("activeMembership") is None:
            am_fallback = _safe_int(getattr(row, "active_membership_id", None), 0)
            if am_fallback > 0:
                item["activeMembership"] = am_fallback
                item["activeMembershipId"] = am_fallback
        if not item.get("userId"):
            uid_fallback = _safe_int(getattr(row, "user_id", None), 0)
            if uid_fallback > 0:
                item["userId"] = uid_fallback

        return item

    @staticmethod
    def _item_summary(item: Dict[str, Any]) -> str:
        """Compact, secret-free description of one upload item for the log."""
        keys = ("localRowId", "eventId", "date", "type", "direction", "deviceId",
                "doorId", "activeMembership", "allowed", "reason")
        return " ".join(f"{k}={item.get(k)!r}" for k in keys if k in item)

    def _isolate_rejected_rows(
        self,
        *,
        api: Any,
        token: str,
        items: List[Dict[str, Any]],
        attempted_ids: List[int],
        row_ids_by_event: Dict[str, int],
        row_ids_by_local: Dict[str, int],
        attempted_at: str,
        batch_error: str,
        batch_status: int = 400,
    ) -> Dict[str, Any]:
        """After a batch HTTP 400 or 409 (``_ROW_VERDICT_HTTP_STATUSES``), post each row
        alone to find the one(s) the backend refuses.

        - A row that succeeds alone is marked synced.
        - A row that gets a 400 or 409 alone IS a poison row: it is marked TERMINAL (it
          leaves the retry queue for good) and logged in full so the cause is visible.
          The backend's reason -- which names the offending field since 2026-09-02 -- is
          stored on the row, with the real status.
        - Any other failure mid-way (network, 5xx, 422) is not the rows' fault: that row
          and every row not yet attempted are marked retryable and the loop stops,
          so a flapping backend is never hammered with N requests.

        Sequential and bounded by the batch size (UPLOAD_BATCH_SIZE), and it only runs
        for a batch that has already been rejected, so the extra requests are a
        one-time cost per poisoned batch.
        """
        if len(items) == 1:
            # The batch IS the row: the verdict already applies to it. Quarantine
            # without re-posting the same payload a second time.
            only = items[0]
            only_id = int(only.get("localRowId") or 0)
            self.logger.error(
                "[DeviceAttendance] access history row REJECTED by backend (quarantined, "
                "will not be retried): %s | backend=%s",
                self._item_summary(only), batch_error,
            )
            failed = mark_access_history_sync_failure(
                row_ids=[only_id] if only_id > 0 else attempted_ids,
                error=f"rejected by backend (HTTP {batch_status}): {batch_error}",
                retry_after_seconds=UPLOAD_FAILURE_RETRY_SECONDS,
                terminal=True,
                attempted_at=attempted_at,
            )
            return {"uploaded": 0, "failed": failed}
        self.logger.warning(
            "[DeviceAttendance] batch of %d rejected with HTTP %s -- isolating the poison row(s): %s",
            len(items), batch_status, batch_error,
        )
        uploaded = 0
        failed = 0
        pending_ids = list(attempted_ids)
        for item in items:
            row_id = int(item.get("localRowId") or 0)
            if row_id <= 0:
                continue
            if row_id in pending_ids:
                pending_ids.remove(row_id)
            try:
                response = api.sync_access_history(token=token, payload=[item], timeout=15)
            except MonClubApiHttpError as row_exc:
                row_status = getattr(row_exc, "status_code", None)
                if row_status in _ROW_VERDICT_HTTP_STATUSES:
                    # This row alone is refused: quarantine it and say exactly what it was.
                    self.logger.error(
                        "[DeviceAttendance] access history row REJECTED by backend (quarantined, "
                        "will not be retried): %s | backend=%s",
                        self._item_summary(item), row_exc,
                    )
                    failed += mark_access_history_sync_failure(
                        row_ids=[row_id],
                        error=f"rejected by backend (HTTP {row_status}): {row_exc}",
                        retry_after_seconds=UPLOAD_FAILURE_RETRY_SECONDS,
                        terminal=True,
                        attempted_at=attempted_at,
                    )
                    continue
                # Not a payload verdict -- stop and leave the rest for the next cycle.
                remaining = [row_id] + pending_ids
                failed += mark_access_history_sync_failure(
                    row_ids=remaining, error=str(row_exc),
                    retry_after_seconds=UPLOAD_FAILURE_RETRY_SECONDS,
                    terminal=False, attempted_at=attempted_at,
                )
                self.logger.warning(
                    "[DeviceAttendance] isolation stopped on HTTP %s; %d row(s) left retryable: %s",
                    getattr(row_exc, "status_code", "?"), len(remaining), row_exc,
                )
                return {"uploaded": uploaded, "failed": failed}
            except Exception as row_exc:  # network / unexpected: same rule as above
                remaining = [row_id] + pending_ids
                failed += mark_access_history_sync_failure(
                    row_ids=remaining, error=str(row_exc),
                    retry_after_seconds=UPLOAD_FAILURE_RETRY_SECONDS,
                    terminal=False, attempted_at=attempted_at,
                )
                self.logger.warning(
                    "[DeviceAttendance] isolation stopped (%s); %d row(s) left retryable: %s",
                    type(row_exc).__name__, len(remaining), row_exc,
                )
                return {"uploaded": uploaded, "failed": failed}

            success_ids, retryable_ids, terminal_ids = self._parse_upload_response(
                response=response,
                row_ids_by_event=row_ids_by_event,
                row_ids_by_local=row_ids_by_local,
                attempted_ids=[row_id],
            )
            if success_ids:
                uploaded += mark_access_history_synced(row_ids=success_ids, synced_at=attempted_at)
            if retryable_ids:
                failed += self._mark_retryable(
                    response=response,
                    retryable_ids=retryable_ids,
                    row_ids_by_event=row_ids_by_event,
                    row_ids_by_local=row_ids_by_local,
                    attempted_at=attempted_at,
                )
            if terminal_ids:
                failed += mark_access_history_sync_failure(
                    row_ids=terminal_ids,
                    error="syncAccessHistory response reported terminal failures",
                    retry_after_seconds=UPLOAD_FAILURE_RETRY_SECONDS,
                    terminal=True, attempted_at=attempted_at,
                )
        self.logger.info(
            "[DeviceAttendance] isolation done: uploaded=%d quarantined_or_failed=%d",
            uploaded, failed,
        )
        return {"uploaded": uploaded, "failed": failed}

    def _sync_pending_history(self, *, token: str | None, sync_online: bool) -> Dict[str, Any]:
        token_value = _safe_str(token, "").strip()
        if not token_value:
            return {"uploaded": 0, "failed": 0}
        if not sync_online:
            return {"uploaded": 0, "failed": 0}

        rows = list_pending_access_history_for_sync(limit=UPLOAD_BATCH_SIZE)
        if not rows:
            return {"uploaded": 0, "failed": 0}

        devices_by_id: Dict[int, Dict[str, Any]] = {}
        for device in list_sync_devices_payload():
            if not isinstance(device, dict):
                continue
            did = _safe_int(device.get("id"), 0)
            if did > 0:
                devices_by_id[did] = device

        users: List[Dict[str, Any]] = []
        try:
            from access.store import load_sync_cache

            cache = load_sync_cache()
            users = list(getattr(cache, "users", []) or []) if cache else []
        except Exception:
            users = []

        # Each row's pin is read under the scheme its device ran at the event's time
        # (guide §3.2b/§3.2e). Without the switch history that cannot be done, and uploading
        # anyway could file a door event against a stranger -- so the rows stay pending.
        try:
            switches_by_device = list_device_pin_scheme_switches() or {}
        except Exception:
            self.logger.warning(
                "[DeviceAttendance] pin-scheme switch history unreadable -- door history not "
                "uploaded this tick", exc_info=True,
            )
            return {"uploaded": 0, "failed": 0}
        resolver = HistoryPinResolver(
            users=users, devices_by_id=devices_by_id, switches_by_device=switches_by_device,
        )
        items = [
            self._serialize_row_for_backend(
                row=row,
                users_by_am=resolver.users_by_am,
                users_by_card=resolver.users_by_card,
                devices_by_id=devices_by_id,
                users_by_account=resolver.users_by_account,
                resolver=resolver,
            )
            for row in rows
        ]
        row_ids_by_event: Dict[str, int] = {item["eventId"]: int(item["localRowId"]) for item in items if item.get("eventId")}
        row_ids_by_local: Dict[str, int] = {str(item["localRowId"]): int(item["localRowId"]) for item in items}
        attempted_ids = [int(row.id) for row in rows]

        api = MonClubApi(endpoints=build_access_api_endpoints(self.cfg), logger=self.logger)
        attempted_at = now_iso()
        try:
            response = api.sync_access_history(
                token=token_value,
                payload=items,
                timeout=15,
            )
        except MonClubApiHttpError as exc:
            # HTTP 400 = the backend REJECTED THE PAYLOAD. That verdict applies to the
            # batch as a whole, yet the cause is (almost always) one row Jackson could
            # not map. Marking every row retryable here -- the previous behaviour --
            # meant the same poisoned batch was re-sent, and re-rejected, every 300s,
            # so one bad row silenced the gym's entire door history indefinitely
            # (OXYGENE_FIT, 2026-08-30: upload_failed=28, recurring). Isolate instead.
            # HTTP 409 is the same shape -- one row's constraint violation rolls back the
            # whole saveAll -- and is isolated the same way (_ROW_VERDICT_HTTP_STATUSES).
            #
            # Any OTHER status (401/403/422/5xx) is not the rows' fault: keep the old
            # whole-batch retry.
            batch_status = getattr(exc, "status_code", None)
            if batch_status in _ROW_VERDICT_HTTP_STATUSES:
                return self._isolate_rejected_rows(
                    api=api, token=token_value, items=items, attempted_ids=attempted_ids,
                    row_ids_by_event=row_ids_by_event, row_ids_by_local=row_ids_by_local,
                    attempted_at=attempted_at, batch_error=str(exc),
                    batch_status=int(batch_status),
                )
            mark_access_history_sync_failure(
                row_ids=attempted_ids,
                error=str(exc),
                retry_after_seconds=UPLOAD_FAILURE_RETRY_SECONDS,
                terminal=False,
                attempted_at=attempted_at,
            )
            self.logger.warning("[DeviceAttendance] access history upload failed (http): %s", exc)
            return {"uploaded": 0, "failed": len(attempted_ids)}
        except MonClubApiError as exc:
            mark_access_history_sync_failure(
                row_ids=attempted_ids,
                error=str(exc),
                retry_after_seconds=UPLOAD_FAILURE_RETRY_SECONDS,
                terminal=False,
                attempted_at=attempted_at,
            )
            self.logger.warning("[DeviceAttendance] access history upload failed: %s", exc)
            return {"uploaded": 0, "failed": len(attempted_ids)}
        except Exception as exc:
            mark_access_history_sync_failure(
                row_ids=attempted_ids,
                error=str(exc),
                retry_after_seconds=UPLOAD_FAILURE_RETRY_SECONDS,
                terminal=False,
                attempted_at=attempted_at,
            )
            self.logger.warning("[DeviceAttendance] access history upload failed (unexpected): %s", exc)
            return {"uploaded": 0, "failed": len(attempted_ids)}

        success_ids, retryable_ids, terminal_ids = self._parse_upload_response(
            response=response,
            row_ids_by_event=row_ids_by_event,
            row_ids_by_local=row_ids_by_local,
            attempted_ids=attempted_ids,
        )

        uploaded = 0
        failed = 0
        if success_ids:
            uploaded = mark_access_history_synced(row_ids=success_ids, synced_at=attempted_at)
        if retryable_ids:
            failed += self._mark_retryable(
                response=response,
                retryable_ids=retryable_ids,
                row_ids_by_event=row_ids_by_event,
                row_ids_by_local=row_ids_by_local,
                attempted_at=attempted_at,
            )
        if terminal_ids:
            failed += mark_access_history_sync_failure(
                row_ids=terminal_ids,
                error="syncAccessHistory response reported terminal failures",
                retry_after_seconds=UPLOAD_FAILURE_RETRY_SECONDS,
                terminal=True,
                attempted_at=attempted_at,
            )
        return {"uploaded": uploaded, "failed": failed}

    def _mark_retryable(
        self,
        *,
        response: Any,
        retryable_ids: List[int],
        row_ids_by_event: Dict[str, int],
        row_ids_by_local: Dict[str, int],
        attempted_at: str,
    ) -> int:
        """Persist retryable rows, counting a verdict only where the backend named the row.

        A named row is one the backend looked at and could not resolve: it backs off and
        moves toward expiry (mark_access_history_unresolved). Every other retryable row keeps
        the plain fixed retry and never counts, because nothing in the body was about it.
        """
        named = _named_retry_row_ids(response, row_ids_by_event, row_ids_by_local)
        unresolved = [rid for rid in retryable_ids if rid in named]
        unjudged = [rid for rid in retryable_ids if rid not in named]
        failed = 0
        if unresolved:
            failed += mark_access_history_unresolved(
                row_ids=unresolved,
                error="syncAccessHistory response reported the row unresolved (failedIds)",
                base_retry_seconds=UPLOAD_FAILURE_RETRY_SECONDS,
                max_retry_seconds=UNRESOLVED_RETRY_MAX_SECONDS,
                attempted_at=attempted_at,
            )
        if unjudged:
            failed += mark_access_history_sync_failure(
                row_ids=unjudged,
                error="syncAccessHistory response reported retryable failures",
                retry_after_seconds=UPLOAD_FAILURE_RETRY_SECONDS,
                terminal=False,
                attempted_at=attempted_at,
            )
        return failed

    def _parse_upload_response(
        self,
        *,
        response: Dict[str, Any],
        row_ids_by_event: Dict[str, int],
        row_ids_by_local: Dict[str, int],
        attempted_ids: List[int],
    ) -> Tuple[List[int], List[int], List[int]]:
        payload: Dict[str, Any] = response if isinstance(response, dict) else {"raw": response}
        data = payload.get("data")
        if isinstance(data, dict):
            payload = data

        ok_flag = payload.get("ok")
        success_flag = payload.get("success")
        status_flag = payload.get("status")
        overall_ok = True
        if ok_flag is not None:
            overall_ok = bool(ok_flag)
        elif success_flag is not None:
            overall_ok = bool(success_flag)
        elif status_flag is not None and isinstance(status_flag, bool):
            overall_ok = bool(status_flag)

        def map_tokens(tokens: List[str]) -> List[int]:
            ids: List[int] = []
            for token in tokens:
                if token in row_ids_by_local:
                    ids.append(int(row_ids_by_local[token]))
                    continue
                if token in row_ids_by_event:
                    ids.append(int(row_ids_by_event[token]))
                    continue
            return ids

        success_tokens: List[str] = []
        for key in (
            "successIds",
            "successEventIds",
            "insertedIds",
            "insertedEventIds",
            "syncedIds",
            "syncedEventIds",
            "duplicateIds",
            "duplicateEventIds",
        ):
            success_tokens.extend(_coerce_id_values(payload.get(key)))

        retry_tokens: List[str] = []
        for key in _RETRY_TOKEN_KEYS:
            retry_tokens.extend(_coerce_id_values(payload.get(key)))

        terminal_tokens: List[str] = []
        for key in (
            "terminalFailedIds",
            "terminalFailedEventIds",
            "validationFailedIds",
            "validationFailedEventIds",
        ):
            terminal_tokens.extend(_coerce_id_values(payload.get(key)))

        success_ids = sorted(set(map_tokens(success_tokens)))
        retryable_ids = sorted(set(map_tokens(retry_tokens)))
        terminal_ids = sorted(set(map_tokens(terminal_tokens)))

        if not overall_ok and not success_ids and not retryable_ids and not terminal_ids:
            return [], list(sorted(set(int(x) for x in attempted_ids))), []

        attempted_set = set(int(x) for x in attempted_ids)
        success_set = set(success_ids)
        retry_set = set(retryable_ids)
        terminal_set = set(terminal_ids)
        unresolved = attempted_set - success_set - retry_set - terminal_set

        failed_count = _safe_int(
            payload.get("failedCount")
            or payload.get("failedInsertionCount")
            or payload.get("numberOfFailedInsertion"),
            0,
        )

        if not success_set and not retry_set and not terminal_set and overall_ok and failed_count == 0:
            return list(sorted(attempted_set)), [], []

        if failed_count > 0 and unresolved:
            retry_set.update(unresolved)
            unresolved = set()

        if overall_ok and not retry_set and not terminal_set and unresolved:
            success_set.update(unresolved)
            unresolved = set()

        if unresolved:
            retry_set.update(unresolved)

        return list(sorted(success_set)), list(sorted(retry_set)), list(sorted(terminal_set))

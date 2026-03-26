from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

from access.config import build_access_api_endpoints
from app.core.db import (
    ACCESS_HISTORY_SOURCE_DEVICE,
    AccessHistoryRow,
    insert_access_history_batch,
    list_pending_access_history_for_sync,
    list_sync_devices_payload,
    load_device_attendance_state,
    mark_access_history_sync_failure,
    mark_access_history_synced,
    prune_access_history,
    save_device_attendance_state,
)
from app.core.settings_reader import get_backend_global_settings, normalize_device_settings
from app.core.utils import now_iso
from app.sdk.pullsdk import PullSDKDevice
from shared.api.monclub_api import MonClubApi, MonClubApiError, MonClubApiHttpError

UPLOAD_BATCH_SIZE = 200
READ_ERROR_RETRY_SECONDS = 300
UPLOAD_FAILURE_RETRY_SECONDS = 300
PURGE_WINDOW_START_HOUR = 2
PURGE_WINDOW_DURATION_HOURS = 3


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
        return dt_value.strftime("%Y-%m-%d %H:%M:%S")
    txt = _safe_str(value, "").strip()
    if txt:
        return txt.replace("T", " ").replace("Z", "")
    return _safe_str(fallback, now_iso())


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


def _user_indexes(users: Iterable[Dict[str, Any]]) -> Tuple[Dict[int, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    by_am: Dict[int, Dict[str, Any]] = {}
    by_card: Dict[str, Dict[str, Any]] = {}
    for user in users or []:
        if not isinstance(user, dict):
            continue
        am = _safe_int(user.get("activeMembershipId") or user.get("active_membership_id"), 0)
        if am > 0 and am not in by_am:
            by_am[am] = user
        for key in ("firstCardId", "secondCardId", "first_card_id", "second_card_id", "cardNo", "card_no"):
            token = _normalize_card_token(user.get(key))
            if token and token not in by_card:
                by_card[token] = user
    return by_am, by_card


def _resolve_history_user(
    row: AccessHistoryRow,
    raw: Dict[str, Any],
    users_by_am: Dict[int, Dict[str, Any]],
    users_by_card: Dict[str, Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    lowered = _lower_keys(raw)
    pin_raw = _pick_ci(lowered, "pin", "userid", "userpin", "personid", "enrollnumber")
    pin = _safe_int(pin_raw, 0)
    if pin > 0 and pin in users_by_am:
        return users_by_am[pin]

    card = _normalize_card_token(row.card_no or _pick_ci(lowered, "cardno", "card", "cardid"))
    if card and card in users_by_card:
        return users_by_card[card]
    return None


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

            retention_days = _safe_int(global_settings.get("history_retention_days"), 30)
            summary["pruned"] = int(prune_access_history(retention_days=max(1, retention_days)))

            self.logger.info(
                "[DeviceAttendance] source=%s devices=%s read_devices=%s rows_read=%s inserted=%s purged_devices=%s purged_rows=%s uploaded=%s upload_failed=%s pruned=%s",
                source,
                summary["devicesConsidered"],
                summary["devicesRead"],
                summary["rowsRead"],
                summary["rowsInserted"],
                summary["devicesPurged"],
                summary["rowsPurged"],
                summary["uploaded"],
                summary["uploadFailed"],
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
        sdk_device = PullSDKDevice(self._prepare_pullsdk_payload(device_payload, device_settings), logger=self.logger)

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
    ) -> Dict[str, Any]:
        raw = _load_json_object(row.raw_json)
        lowered = _lower_keys(raw)
        user = _resolve_history_user(row, raw, users_by_am, users_by_card)
        pin_raw = _pick_ci(lowered, "pin", "userid", "userpin", "personid", "enrollnumber")
        pin = _safe_int(pin_raw, 0)
        if pin <= 0 and user:
            pin = _safe_int(user.get("activeMembershipId") or user.get("active_membership_id"), 0)

        device = devices_by_id.get(int(row.device_id or 0), {})
        item: Dict[str, Any] = {
            "localRowId": int(row.id),
            "eventId": _safe_str(row.event_id, ""),
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

        if user:
            item["userId"] = _safe_int(user.get("userId") or user.get("user_id"), 0) or None
            item["activeMembershipId"] = _safe_int(
                user.get("activeMembershipId") or user.get("active_membership_id"),
                0,
            ) or None
            item["membershipId"] = _safe_int(user.get("membershipId") or user.get("membership_id"), 0) or None
            item["userFullName"] = _safe_str(user.get("fullName") or user.get("full_name"), "")
            item["userPhone"] = _safe_str(user.get("phone"), "")
            item["userEmail"] = _safe_str(user.get("email"), "")

        return item

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

        users_by_am, users_by_card = _user_indexes(users)
        items = [
            self._serialize_row_for_backend(
                row=row,
                users_by_am=users_by_am,
                users_by_card=users_by_card,
                devices_by_id=devices_by_id,
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
                payload={"items": items},
                timeout=15,
            )
        except MonClubApiHttpError as exc:
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
            failed += mark_access_history_sync_failure(
                row_ids=retryable_ids,
                error="syncAccessHistory response reported retryable failures",
                retry_after_seconds=UPLOAD_FAILURE_RETRY_SECONDS,
                terminal=False,
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
        for key in (
            "failedIds",
            "failedEventIds",
            "failedInsertionIds",
            "failedInsertionEventIds",
            "retryableFailedIds",
            "retryableFailedEventIds",
        ):
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

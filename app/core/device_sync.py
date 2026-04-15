# monclub_access_python/app/core/device_sync.py
from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Set, Tuple

from app.core.db import (
    list_fingerprints,
    list_fingerprints_by_pins,
    list_sync_users_by_active_membership_ids,
    list_device_sync_hashes,
    list_device_sync_hashes_and_status,
    save_device_sync_state,
    save_device_sync_state_batch,
    delete_device_sync_state,
    prune_device_sync_state,
    upsert_device_mirror_pin,
    delete_device_mirror_pin,
    insert_push_batch,
    insert_push_pin,
    insert_push_pin_batch,
    update_push_batch,
)
from app.core.settings_reader import get_backend_global_settings  # ✅ NEW: backend-driven settings (SQLite)
from app.sdk.pullsdk import PullSDK, PullSDKError


@dataclass
class FirmwareProfile:
    """
    Records which SDK field-name pattern works for a specific ZKTeco device firmware.
    Populated from SQLite on first use, updated on successful discovery.

    Fields:
        template_table       — "templatev10" or "template"
        template_body_index  — index into the bodies list in _push_templates (0-4)
        authorize_body_index — index into the patterns list in _push_userauthorize (0-3)
    """
    template_table: str | None = None
    template_body_index: int | None = None
    authorize_body_index: int | None = None
    name_supported: bool | None = None  # None=unknown, True=OK, False=rc=-101 on Name field


# Fallback if a device has no doorIds configured (will be overridden by backend global settings if present)
DEFAULT_AUTHORIZE_DOOR_ID_FALLBACK = 15

# ── Pushing policy constants ──────────────────────────────────────────────────
# Resolved from device.pushingToDevicePolicy (backend enum value).
# Controls HOW member data is pushed to a ZKTeco device during sync.
_PUSH_POLICY_INCREMENTAL   = "INCREMENTAL"    # delta: hash-based, delete stale + changed-then-insert
_PUSH_POLICY_FULL_REPLACE  = "FULL_REPLACE"   # nuke all tables then push entire desired roster
_PUSH_POLICY_ADDITIVE_ONLY = "ADDITIVE_ONLY"  # push changed/new (delete-then-insert), never remove stale


def _parse_dt_any(s: str) -> datetime | None:
    if not s:
        return None
    s = str(s).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1]
    try:
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    try:
        if len(s) == 10 and s[4] == "-" and s[7] == "-":
            return datetime.fromisoformat(s + "T00:00:00").replace(tzinfo=timezone.utc)
    except Exception:
        pass
    return None


def _pin_str(v) -> str:
    if v is None:
        return ""
    return str(v).strip()


def _safe_one_line(s: str) -> str:
    if not s:
        return ""
    return str(s).replace("\t", " ").replace("\r", " ").replace("\n", " ").strip()


def _safe_template_text(s: str) -> str:
    if not s:
        return ""
    return str(s).replace("\r", "").replace("\n", "").replace("\t", "").strip()


def _batch_row_field(row: str, key: str) -> str:
    prefix = f"{key}="
    for part in str(row or "").split("\t"):
        if part.startswith(prefix):
            return part[len(prefix):]
    return ""


def _to_int(v, default: int | None = None) -> int | None:
    try:
        if v is None:
            return default
        x = str(v).strip()
        if x == "":
            return default
        return int(x)
    except Exception:
        return default


def _to_float(v, default: float | None = None) -> float | None:
    try:
        if v is None:
            return default
        x = str(v).strip()
        if x == "":
            return default
        return float(x)
    except Exception:
        return default


def _boolish(v, default: bool = True) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    try:
        s = str(v).strip().lower()
        if s in ("1", "true", "yes", "y", "on"):
            return True
        if s in ("0", "false", "no", "n", "off"):
            return False
    except Exception:
        pass
    return default


def _as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return []


def _sha1_hex(text: str) -> str:
    return hashlib.sha1((text or "").encode("utf-8", errors="ignore")).hexdigest()


def _norm_int_list(xs: List[Any]) -> List[int]:
    out: List[int] = []
    for x in xs or []:
        xi = _to_int(x, default=None)
        if xi is None:
            continue
        if int(xi) > 0:
            out.append(int(xi))
    out = sorted(set(out))
    return out


@dataclass
class _OneShotDeviceSyncSession:
    device: Dict[str, Any]
    users: List[Dict[str, Any]]
    local_fp_index: Dict[str, List[Any]]
    default_door_id: int
    changed_ids: Set[int] | None
    sync_run_id: int | None
    pending: bool = True

    def has_pending_work(self) -> bool:
        return bool(self.pending)


class _DeviceSyncActorAdapter:
    def __init__(self, *, engine: "DeviceSyncEngine", device: Dict[str, Any]) -> None:
        self._engine = engine
        self._device = dict(device or {})

    def update_device(self, device: Dict[str, Any]) -> None:
        self._device = dict(device or {})

    def build_full_sync_session(self, *, device_id: int) -> _OneShotDeviceSyncSession:
        return self._build_session(changed_ids=None)

    def build_targeted_sync_session(
        self,
        *,
        device_id: int,
        member_ids: set[int],
    ) -> _OneShotDeviceSyncSession:
        return self._build_session(changed_ids=set(int(member_id) for member_id in member_ids))

    def run_sync_chunk(self, session: _OneShotDeviceSyncSession) -> bool:
        if not session.pending:
            return False
        session.pending = False
        self._engine._sync_one_device(
            device=dict(session.device),
            users=list(session.users),
            local_fp_index=session.local_fp_index,
            default_door_id=int(session.default_door_id),
            changed_ids=None if session.changed_ids is None else set(session.changed_ids),
            sync_run_id=session.sync_run_id,
        )
        return True

    def _build_session(self, *, changed_ids: Set[int] | None) -> _OneShotDeviceSyncSession:
        context = self._engine._get_actor_dispatch_context()
        return _OneShotDeviceSyncSession(
            device=self._engine._normalize_device(dict(self._device)),
            users=list(context.get("users") or []),
            local_fp_index={
                str(pin): list(rows)
                for pin, rows in (context.get("local_fp_index") or {}).items()
            },
            default_door_id=int(context.get("default_door_id") or DEFAULT_AUTHORIZE_DOOR_ID_FALLBACK),
            changed_ids=None if changed_ids is None else set(changed_ids),
            sync_run_id=context.get("sync_run_id"),
        )


class DeviceSyncEngine:
    """
    Synchronizes ZKTeco controllers (PullSDK) from cached backend payload.

    IMPORTANT CHANGE (Mar 2026):
    - accessDataMode is PER DEVICE.
    - This engine only syncs devices where accessDataMode == DEVICE.
    - Global defaults (default_authorize_door_id, sdk_read_initial_bytes, etc.) come from
      GymAccessSoftwareSettingsDto cached in SQLite, via settings_reader.get_backend_global_settings().

    IMPORTANT CHANGE (Apr 2026):
    - Per-device actors replace the old ThreadPool/worker-manager approach.
    - _sync_all_devices dispatches to DeviceActorRegistry (non-blocking).
    - Each device keeps one serialized actor inbox for full and targeted sync work.
    """

    def __init__(self, *, cfg, logger, feedback_callback: Callable[[str, Dict[str, Any]], None] | None = None):
        from app.core.device_actor_registry import DeviceActorRegistry
        self.cfg = cfg
        self.logger = logger
        self._feedback_callback = feedback_callback
        self._run_lock = threading.Lock()
        self._running = False
        self._progress_cond = threading.Condition()
        self._progress_seq = 0
        # Live progress readable by the status API (dict value assignments are
        # atomic under CPython GIL — safe across worker threads).
        self._sync_progress: Dict[str, Any] = {
            "running": False,
            "deviceName": "",
            "deviceId": None,
            "current": 0,
            "total": 0,
        }
        # Phase 2: in-session firmware profile cache (device_id -> FirmwareProfile).
        # L1 cache (memory) backed by L2 (SQLite via db.py).
        # Keyed by device_id (stable integer), not IP (DHCP can reassign IPs).
        self._firmware_profiles: dict[int, FirmwareProfile] = {}
        self._dispatch_context_lock = threading.Lock()
        self._actor_dispatch_context: Dict[str, Any] = {
            "users": [],
            "local_fp_index": {},
            "default_door_id": self._default_authorize_door_id(),
            "sync_run_id": None,
        }
        self._actor_registry = DeviceActorRegistry(
            adapter_factory=self._build_actor_adapter,
        )

    def _build_actor_adapter(self, device: Dict[str, Any]) -> "_DeviceSyncActorAdapter":
        return _DeviceSyncActorAdapter(engine=self, device=device)

    def _set_actor_dispatch_context(
        self,
        *,
        users: List[Dict[str, Any]],
        local_fp_index: Dict[str, List[Any]],
        default_door_id: int,
        sync_run_id: int | None,
    ) -> None:
        with self._dispatch_context_lock:
            self._actor_dispatch_context = {
                "users": list(users),
                "local_fp_index": {
                    str(pin): list(rows)
                    for pin, rows in (local_fp_index or {}).items()
                },
                "default_door_id": int(default_door_id),
                "sync_run_id": sync_run_id,
            }

    def _get_actor_dispatch_context(self) -> Dict[str, Any]:
        with self._dispatch_context_lock:
            context = dict(self._actor_dispatch_context)
        context["users"] = list(context.get("users") or [])
        context["local_fp_index"] = {
            str(pin): list(rows)
            for pin, rows in (context.get("local_fp_index") or {}).items()
        }
        return context

    def _emit_feedback_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        if not self._feedback_callback:
            return
        try:
            self._feedback_callback(event_type, dict(payload))
        except Exception:
            self.logger.debug("[DeviceSync] feedback callback failed for %s", event_type, exc_info=True)

    def _get_firmware_profile(self, device_id: int) -> FirmwareProfile:
        """
        Returns the FirmwareProfile for this device, loading from SQLite if not in session cache.
        Creates an empty profile if none exists yet (discovery happens on first push attempt).
        """
        if device_id not in self._firmware_profiles:
            from app.core.db import load_firmware_profile
            persisted = load_firmware_profile(device_id=device_id)
            if persisted:
                self._firmware_profiles[device_id] = FirmwareProfile(
                    template_table=persisted["template_table"],
                    template_body_index=persisted["template_body_index"],
                    authorize_body_index=persisted["authorize_body_index"],
                    name_supported=persisted.get("name_supported"),
                )
            else:
                self._firmware_profiles[device_id] = FirmwareProfile()
        return self._firmware_profiles[device_id]

    def _save_firmware_profile(self, profile: FirmwareProfile, device_id: int) -> None:
        """Persist the firmware profile to SQLite (L2 cache)."""
        from app.core.db import save_firmware_profile
        save_firmware_profile(
            device_id=device_id,
            template_table=profile.template_table or "",
            template_body_index=profile.template_body_index or 0,
            authorize_body_index=profile.authorize_body_index or 0,
            name_supported=profile.name_supported,
        )

    def _set_progress(self, **changes: Any) -> None:
        with self._progress_cond:
            changed = False
            for key, value in changes.items():
                if self._sync_progress.get(key) != value:
                    self._sync_progress[key] = value
                    changed = True
            if changed:
                self._progress_seq += 1
                self._progress_cond.notify_all()

    def get_progress_snapshot(self) -> tuple[Dict[str, Any], int]:
        with self._progress_cond:
            return dict(self._sync_progress), self._progress_seq

    def wait_for_progress_change(self, last_seq: int, timeout: float = 1.0) -> tuple[Dict[str, Any], int]:
        with self._progress_cond:
            if self._progress_seq == last_seq:
                self._progress_cond.wait(timeout=max(0.0, float(timeout)))
            return dict(self._sync_progress), self._progress_seq

    def stop_workers(self) -> None:
        """Stop all per-device worker threads. Call on logout / shutdown."""
        self._actor_registry.stop_all()

    def run_blocking(
        self,
        *,
        cache,
        source: str = "timer",
        changed_ids: set | None = None,
        sync_run_id: int | None = None,
    ) -> bool:
        with self._run_lock:
            if self._running:
                self.logger.info(f"[DeviceSync] Skip ({source}): already running")
                return False
            self._running = True

        try:
            self._sync_all_devices(cache=cache, changed_ids=changed_ids, sync_run_id=sync_run_id)
            return True
        except Exception as e:
            self.logger.exception(f"[DeviceSync] Failed: {e}")
            return True
        finally:
            with self._run_lock:
                self._running = False

    def run_one_device_blocking(
        self,
        *,
        cache,
        device: Dict[str, Any],
        source: str = "timer",
        changed_ids: set | None = None,
        sync_run_id: int | None = None,
    ) -> bool:
        """
        Synchronously push a single device on the current thread.

        ULTRA mode needs this direct path because the regular run_blocking()
        dispatches to persistent background workers and returns immediately.
        For RTLog TCP handoff we must keep the worker paused until the actual
        device push has completed.
        """
        return self._run_single_device_sync(
            cache=cache,
            device=device,
            source=source,
            changed_ids=changed_ids,
            sync_run_id=sync_run_id,
            sdk=None,
        )

    def run_one_device_on_connected_sdk(
        self,
        *,
        sdk: PullSDK,
        cache,
        device: Dict[str, Any],
        source: str = "timer",
        changed_ids: set | None = None,
        sync_run_id: int | None = None,
    ) -> bool:
        """Synchronously push a single device using an already-connected SDK."""
        return self._run_single_device_sync(
            cache=cache,
            device=device,
            source=source,
            changed_ids=changed_ids,
            sync_run_id=sync_run_id,
            sdk=sdk,
        )

    def _run_single_device_sync(
        self,
        *,
        cache,
        device: Dict[str, Any],
        source: str,
        changed_ids: set | None,
        sync_run_id: int | None,
        sdk: PullSDK | None,
    ) -> bool:
        with self._run_lock:
            if self._running:
                self.logger.info(f"[DeviceSync] Skip single-device ({source}): already running")
                return False
            self._running = True

        try:
            if not cache:
                self.logger.info("[DeviceSync] No cache -> skip single-device sync")
                return False

            normalized_device = self._normalize_device(device if isinstance(device, dict) else {})
            dev_id = normalized_device.get("id")
            dev_name = normalized_device.get("name", "")

            if not _boolish(normalized_device.get("active"), default=True):
                self.logger.info(
                    "[DeviceSync] Skip single-device id=%s name=%r: active=False",
                    dev_id, dev_name,
                )
                return False
            if not _boolish(normalized_device.get("accessDevice"), default=True):
                self.logger.info(
                    "[DeviceSync] Skip single-device id=%s name=%r: accessDevice=False",
                    dev_id, dev_name,
                )
                return False

            users = getattr(cache, "users", []) or []

            local_fp_index: Dict[str, List[Any]] = {}
            raw_fingerprint_enabled = normalized_device.get("fingerprintEnabled")
            if raw_fingerprint_enabled is None:
                raw_fingerprint_enabled = normalized_device.get("fingerprint_enabled")
            fingerprint_enabled = _boolish(
                raw_fingerprint_enabled,
                default=True,
            )
            if fingerprint_enabled:
                try:
                    recs = list_fingerprints()
                    for r in recs:
                        pin = _pin_str(getattr(r, "pin", "") or "")
                        if not pin:
                            continue
                        local_fp_index.setdefault(pin, []).append(r)
                except Exception:
                    local_fp_index = {}

            default_door_id = self._default_authorize_door_id()
            self._set_progress(
                running=True,
                deviceName=str(dev_name or ""),
                deviceId=dev_id,
                current=0,
                total=1,
            )
            sync_kwargs = {
                "device": normalized_device,
                "users": users,
                "local_fp_index": local_fp_index,
                "default_door_id": default_door_id,
                "changed_ids": changed_ids,
                "sync_run_id": sync_run_id,
            }
            if sdk is not None:
                sync_kwargs["sdk"] = sdk
            self._sync_one_device(
                **sync_kwargs,
            )
            self._set_progress(current=1)
            return True
        except Exception as e:
            self.logger.exception(f"[DeviceSync] Single-device sync failed: {e}")
            return False
        finally:
            self._set_progress(
                running=False,
                deviceName="",
                deviceId=None,
                current=0,
                total=0,
            )
            with self._run_lock:
                self._running = False

    # ---------------- internal ----------------

    def _build_local_fp_index_for_pins(
        self,
        *,
        pins: set[str],
        fingerprint_enabled: bool,
    ) -> Dict[str, List[Any]]:
        if not fingerprint_enabled or not pins:
            return {}
        try:
            records = list_fingerprints_by_pins(pins=pins)
        except Exception:
            return {}

        local_fp_index: Dict[str, List[Any]] = {}
        for record in records:
            pin = _pin_str(getattr(record, "pin", "") or "")
            if not pin:
                continue
            local_fp_index.setdefault(pin, []).append(record)
        return local_fp_index

    def _push_pin_to_connected_sdk(
        self,
        *,
        sdk: PullSDK,
        device_id: int,
        device_name: str,
        pin: str,
        user: Dict[str, Any],
        desired_hash: str,
        door_ids: List[int],
        door_bitmask: int,
        authorize_timezone_id: int,
        templates: List[Dict[str, Any]],
    ) -> bool:
        full_name = _safe_one_line(user.get("fullName") or "") or f"U{pin}"
        card = _pin_str(user.get("firstCardId") or "")
        auth_err: str | None = None

        try:
            self._delete_pin_unconditional(sdk=sdk, pin=pin)

            card_valid = card if (card and card.isdigit()) else ""
            if card and not card_valid:
                self.logger.warning(
                    "[DeviceSync] Device id=%s Pin=%s CardNo=%r is not numeric - skipping CardNo",
                    device_id,
                    pin,
                    card,
                )

            profile = self._get_firmware_profile(device_id)
            use_name = profile.name_supported is not False
            pairs = [f"Pin={pin}"]
            if use_name:
                pairs.append(f"Name={full_name}")
            if card_valid:
                pairs.append(f"CardNo={card_valid}")

            try:
                sdk.set_device_data(table="user", data="\t".join(pairs) + "\r\n", options="")
                if profile.name_supported is None and use_name:
                    profile.name_supported = True
                    self._save_firmware_profile(profile, device_id)
            except PullSDKError as set_err:
                if "rc=-101" not in str(set_err):
                    raise
                self.logger.warning(
                    "[DeviceSync] Device id=%s Pin=%s SetDeviceData rc=-101 - retrying without Name",
                    device_id,
                    pin,
                )
                self._delete_auth_and_templates_best_effort(sdk=sdk, pin=pin)
                try:
                    sdk.delete_device_data(table="user", data=f"Pin={pin}", options="")
                except Exception:
                    pass
                minimal_pairs = [f"Pin={pin}"]
                if card_valid:
                    minimal_pairs.append(f"CardNo={card_valid}")
                sdk.set_device_data(
                    table="user",
                    data="\t".join(minimal_pairs) + "\r\n",
                    options="",
                )
                if use_name and profile.name_supported is None:
                    profile.name_supported = False
                    self._save_firmware_profile(profile, device_id)

            auth_complete = True
            auth_ok_count, auth_err = self._push_userauthorize(
                sdk,
                pin=pin,
                door_bitmask=door_bitmask,
                authorize_timezone_id=int(authorize_timezone_id),
                device_id=device_id,
            )
            if auth_err:
                auth_complete = (auth_ok_count == len(door_ids))
                self.logger.warning(
                    "[DeviceSync] Device id=%s Pin=%s authorize %s: %s/%s doors - %s",
                    device_id,
                    pin,
                    "PARTIAL" if not auth_complete else "warn",
                    auth_ok_count,
                    len(door_ids),
                    auth_err,
                )

            if templates:
                _ok_count, errs = self._push_templates(
                    sdk,
                    pin=pin,
                    templates=templates,
                    device_id=device_id,
                )
                if errs:
                    self.logger.warning(
                        "[DeviceSync] Device id=%s Pin=%s template errors (%d): %s",
                        device_id,
                        pin,
                        len(errs),
                        errs[:5],
                    )

            save_device_sync_state(
                device_id=device_id,
                pin=pin,
                desired_hash=desired_hash,
                ok=bool(auth_complete),
                error=None if auth_complete else (auth_err or "authorize incomplete"),
            )
            try:
                upsert_device_mirror_pin(
                    device_id=device_id,
                    pin=pin,
                    full_name=full_name,
                    card_no=card or None,
                    door_bitmask=door_bitmask,
                    authorize_tz_id=int(authorize_timezone_id),
                    fp_count=len(templates),
                    push_ok=bool(auth_complete),
                )
            except Exception:
                pass

            self.logger.info(
                "[DeviceSync] targeted member sync: device_id=%s device_name=%r pin=%s ok=%s",
                device_id,
                device_name,
                pin,
                bool(auth_complete),
            )
            return bool(auth_complete)
        except Exception as exc:
            save_device_sync_state(
                device_id=device_id,
                pin=pin,
                desired_hash=desired_hash,
                ok=False,
                error=str(exc),
            )
            try:
                upsert_device_mirror_pin(
                    device_id=device_id,
                    pin=pin,
                    full_name=full_name,
                    card_no=card or None,
                    door_bitmask=door_bitmask,
                    authorize_tz_id=int(authorize_timezone_id),
                    fp_count=len(templates),
                    push_ok=False,
                )
            except Exception:
                pass
            self.logger.warning(
                "[DeviceSync] targeted member sync failed: device_id=%s device_name=%r pin=%s err=%s",
                device_id,
                device_name,
                pin,
                exc,
            )
            return False

    def sync_member_on_connected_sdk(
        self,
        *,
        sdk: PullSDK,
        device: Dict[str, Any],
        member_id: int,
        source: str = "targeted_member_sync",
    ) -> bool:
        normalized_device = self._normalize_device(device if isinstance(device, dict) else {})
        dev_id = normalized_device.get("id")
        dev_name = normalized_device.get("name", "")
        if dev_id is None:
            return False
        did = int(_to_int(dev_id, default=0) or 0)
        if did <= 0:
            return False
        if not _boolish(normalized_device.get("active"), default=True):
            return False
        if not _boolish(normalized_device.get("accessDevice"), default=True):
            return False

        pin = _pin_str(member_id)
        if not pin or not pin.isdigit():
            return False

        default_door_id = self._default_authorize_door_id()
        door_ids, door_bitmask, authorize_timezone_id, fingerprint_enabled = self._resolve_push_context(
            device=normalized_device,
            default_door_id=default_door_id,
        )

        target_users = list_sync_users_by_active_membership_ids({int(member_id)})
        desired = self._filter_users_for_device(
            users=target_users,
            device=normalized_device,
            default_door_id=default_door_id,
        )
        desired_user = desired.get(pin)

        if not isinstance(desired_user, dict):
            deleted = self._delete_pin_unconditional(sdk=sdk, pin=pin)
            delete_device_sync_state(device_id=did, pin=pin)
            try:
                delete_device_mirror_pin(device_id=did, pin=pin)
            except Exception:
                pass
            self.logger.info(
                "[DeviceSync] targeted member delete: device_id=%s device_name=%r pin=%s deleted=%s source=%s",
                did,
                dev_name,
                pin,
                bool(deleted),
                source,
            )
            return bool(deleted)

        local_fp_index = self._build_local_fp_index_for_pins(
            pins={pin},
            fingerprint_enabled=fingerprint_enabled,
        )
        templates = self._collect_templates_for_pin(
            user=desired_user,
            pin=pin,
            local_fp_index=local_fp_index,
            fingerprint_enabled=fingerprint_enabled,
        )
        desired_hash = self._compute_desired_hash(
            pin=pin,
            user=desired_user,
            door_bitmask=door_bitmask,
            templates=templates,
            authorize_timezone_id=authorize_timezone_id,
        )

        prev_hash, prev_ok = list_device_sync_hashes_and_status(device_id=did).get(pin, ("", True))
        if prev_hash == desired_hash and prev_ok:
            self.logger.info(
                "[DeviceSync] targeted member sync skip: device_id=%s device_name=%r pin=%s unchanged source=%s",
                did,
                dev_name,
                pin,
                source,
            )
            return False

        return self._push_pin_to_connected_sdk(
            sdk=sdk,
            device_id=did,
            device_name=str(dev_name or ""),
            pin=pin,
            user=desired_user,
            desired_hash=desired_hash,
            door_ids=door_ids,
            door_bitmask=door_bitmask,
            authorize_timezone_id=authorize_timezone_id,
            templates=templates,
        )

    def _global_defaults(self) -> Dict[str, Any]:
        """
        Backend-driven global settings (snake_case). Never raises.
        """
        try:
            g = get_backend_global_settings() or {}
            return g if isinstance(g, dict) else {}
        except Exception:
            return {}

    def _default_authorize_door_id(self) -> int:
        g = self._global_defaults()
        v = _to_int(g.get("default_authorize_door_id"), default=DEFAULT_AUTHORIZE_DOOR_ID_FALLBACK)
        if v is None or int(v) < 1:
            return int(DEFAULT_AUTHORIZE_DOOR_ID_FALLBACK)
        return int(v)

    def _resolve_push_policy(self, device: Dict[str, Any]) -> str:
        """
        Map device.pushingToDevicePolicy (backend enum string) to one of the three
        canonical push-policy constants.  Defaults to INCREMENTAL.

        Backend enum → policy mapping:
          DELETE_ALL_BEFORE_PUSHING                             → FULL_REPLACE
          DELETE_ALL_KNOWING_PINS_BUT_NO_LONGER_DESIRED_*      → INCREMENTAL (default)
          DELETE_ALL_NOT_DESIRED_PINS_BEFORE_PUSHING           → INCREMENTAL
          PUSH_WITHOUT_DELETING                                → ADDITIVE_ONLY
          DELETE_ALL_NOT_KNOWING_PINS_AND_DONT_PUSH            → FULL_REPLACE (clear, no push — treated as reset)
        """
        raw = str(device.get("pushingToDevicePolicy") or "").strip().upper()
        if not raw:
            return _PUSH_POLICY_INCREMENTAL
        # Explicit FULL_REPLACE triggers
        if raw in ("DELETE_ALL_BEFORE_PUSHING", "FULL_REPLACE",
                   "DELETE_ALL_NOT_KNOWING_PINS_AND_DONT_PUSH"):
            return _PUSH_POLICY_FULL_REPLACE
        # Explicit ADDITIVE_ONLY triggers
        if raw in ("PUSH_WITHOUT_DELETING", "ADDITIVE_ONLY"):
            return _PUSH_POLICY_ADDITIVE_ONLY
        # Everything else: INCREMENTAL (safe default)
        return _PUSH_POLICY_INCREMENTAL

    def _resolve_push_context(
        self,
        *,
        device: Dict[str, Any],
        default_door_id: int,
    ) -> Tuple[List[int], int, int, bool]:
        authorize_timezone_id = _to_int(device.get("authorizeTimezoneId"), default=1) or 1
        if authorize_timezone_id < 1:
            authorize_timezone_id = 1

        raw_fingerprint_enabled = device.get("fingerprintEnabled")
        if raw_fingerprint_enabled is None:
            raw_fingerprint_enabled = device.get("fingerprint_enabled")
        fingerprint_enabled = _boolish(raw_fingerprint_enabled, default=False)

        # Resolve AuthorizeDoorId bitmask for userauthorize.
        # AuthorizeDoorId is a bitmask: door1=1, door2=2, door3=4, door4=8.
        #
        # Priority: use doorIds from the backend (already bitmask values set in
        # the dashboard, e.g. [1, 2, 4, 8]). OR them to get combined bitmask.
        # Fallback: compute bitmask from doorPresets physical door numbers.
        door_ids_raw = device.get("doorIds") or []
        door_ids_list = _norm_int_list(door_ids_raw)

        if door_ids_list:
            door_bitmask = 0
            for v in door_ids_list:
                door_bitmask |= int(v)
            door_ids = door_ids_list
        else:
            presets = device.get("doorPresets") or []
            physical_doors = sorted(set(
                int(p.get("doorNumber") or p.get("door_number") or 0)
                for p in presets if isinstance(p, dict)
                and (p.get("doorNumber") or p.get("door_number"))
            ))
            physical_doors = [d for d in physical_doors if d > 0]

            if physical_doors:
                door_bitmask = 0
                for d in physical_doors:
                    door_bitmask |= 1 << (int(d) - 1)
                door_ids = physical_doors
            else:
                door_bitmask = int(default_door_id)
                door_ids = [int(default_door_id)]

        return door_ids, door_bitmask, authorize_timezone_id, fingerprint_enabled

    def _sdk_read_initial_bytes(self) -> int:
        """
        Backend-driven knob used when reading device data (PullSDK initial_size).
        Falls back to 1 MiB.
        """
        g = self._global_defaults()
        v = _to_int(g.get("sdk_read_initial_bytes"), default=1_048_576) or 1_048_576
        # clamp: [64KiB, 16MiB]
        if v < 64 * 1024:
            v = 64 * 1024
        if v > 16 * 1024 * 1024:
            v = 16 * 1024 * 1024
        return int(v)

    def _resolve_connect_timeout_ms(self, device: Dict[str, Any]) -> int:
        timeout_ms = _to_int(
            (
                device.get("timeoutMs")
                or device.get("timeout_ms")
                or device.get("timeout")
                or device.get("connectTimeoutMs")
                or device.get("connect_timeout_ms")
            ),
            default=None,
        )
        if timeout_ms is None or int(timeout_ms) <= 0:
            timeout_ms = _to_int(getattr(self.cfg, "timeout_ms", None), default=None)
        if timeout_ms is None or int(timeout_ms) <= 0:
            timeout_ms = 3000
        # Keep connect waits bounded when a device is offline so one bad controller
        # does not stall the whole local runtime for long stretches.
        return max(500, min(int(timeout_ms), 15000))

    def _normalize_device(self, d: Dict[str, Any]) -> Dict[str, Any]:
        def g(*keys, default=None):
            for k in keys:
                if isinstance(d, dict) and k in d:
                    return d.get(k)
            return default

        allowed = g("allowedMemberships", "allowed_memberships", default=None)
        doors = g("doorIds", "door_ids", default=None)

        # accessDataMode: per-device mode (DEVICE or AGENT)
        adm_raw = g("accessDataMode", "access_data_mode", default="DEVICE")
        adm = str(adm_raw or "").strip().upper()
        if adm not in ("DEVICE", "AGENT", "ULTRA"):
            adm = "DEVICE"

        # per-device timezone/policy (used for userauthorize)
        tz_id = _to_int(g("authorizeTimezoneId", "authorize_timezone_id", default=1), default=1) or 1
        if tz_id < 1:
            tz_id = 1

        pushing_policy = g("pushingToDevicePolicy", "pushing_to_device_policy", default=None)

        return {
            "id": g("id"),
            "name": g("name", default=""),
            "active": _boolish(g("active", default=True), default=True),
            "accessDevice": _boolish(g("accessDevice", "access_device", default=True), default=True),
            "accessDataMode": adm,
            "ipAddress": g("ipAddress", "ip_address", default=""),
            "portNumber": g("portNumber", "port_number", default=4370),
            "password": g("password", default=""),
            "allowedMemberships": _as_list(allowed),
            "doorIds": _as_list(doors),
            "timeoutMs": _to_int(
                g("timeoutMs", "timeout_ms", "timeout", "connectTimeoutMs", "connect_timeout_ms", default=None),
                default=None,
            ),

            # NEW (from backend/device DTO)
            "authorizeTimezoneId": int(tz_id),
            "pushingToDevicePolicy": pushing_policy,
            "doorPresets": list(g("doorPresets", "door_presets", default=None) or []),
            "fingerprintEnabled": _boolish(g("fingerprintEnabled", "fingerprint_enabled", default=False), False),

            # Anti-fraud settings (per-device)
            "anti_fraude_card":             _boolish(g("anti_fraude_card",             "antiFraudeCard",             default=True), True),
            "anti_fraude_qr_code":          _boolish(g("anti_fraude_qr_code",          "antiFraudeQrCode",           default=True), True),
            "anti_fraude_duration":         _to_int(g("anti_fraude_duration",          "antiFraudeDuration",         default=30), default=30) or 30,
            "anti_fraude_daily_pass_limit": _to_int(g("anti_fraude_daily_pass_limit",  "antiFraudeDailyPassLimit",   default=0),  default=0)  or 0,
        }

    def _filter_users_for_device(self, *, users: List[Dict[str, Any]], device: Dict[str, Any], default_door_id: int) -> Dict[str, Dict[str, Any]]:
        """
        Returns dict(pin -> user).

        Filters:
        - allowedMemberships (if provided) uses user.membershipId
        - validFrom/validTo ONLY when pushingToDevicePolicy == "VALID_ONLY"
          (default: push ALL members with an activeMembershipId regardless of
          expiry — the PC/ULTRA engine handles real-time validity at scan time)
        - pin must be digits (controllers expect numeric Pin)

        Also ensures device has a usable doorIds list (fallback to default_door_id).
        """
        allowed_raw = device.get("allowedMemberships") or []
        allowed_set: Set[int] = set()
        for x in allowed_raw:
            xi = _to_int(x, default=None)
            if xi is not None:
                allowed_set.add(int(xi))

        door_ids = _norm_int_list(device.get("doorIds") or [])
        if not door_ids:
            door_ids = [int(default_door_id)]
        device["doorIds"] = door_ids  # keep for downstream use

        # Validity-date filter: ONLY apply when explicitly opted in via
        # pushingToDevicePolicy="VALID_ONLY".  The default (null / any other
        # value) pushes every member so the full roster is on the device and
        # the PC-side logic decides access at scan time.
        policy = str(device.get("pushingToDevicePolicy") or "").strip().upper()
        filter_by_validity = (policy == "VALID_ONLY")

        now = datetime.now(tz=timezone.utc)
        out: Dict[str, Dict[str, Any]] = {}

        for u in users or []:
            if not isinstance(u, dict):
                continue

            # Prefer activeMembershipId as Pin; fall back to userId for users that
            # have no active membership record in the backend (activeMembershipId=null).
            # userId is always present, always unique — safe as a device Pin.
            am_pin = _pin_str(u.get("activeMembershipId"))
            pin = am_pin or _pin_str(u.get("userId"))
            if not pin:
                continue
            if not pin.isdigit():
                continue

            # Collision guard: a userId-fallback pin must not overwrite an
            # activeMembershipId-based entry already placed in the output.
            if pin in out and not am_pin:
                continue

            mid = _to_int(u.get("membershipId"), default=None)
            if allowed_set and (mid is None or int(mid) not in allowed_set):
                continue

            if filter_by_validity:
                vf = _parse_dt_any(u.get("validFrom") or "")
                vt = _parse_dt_any(u.get("validTo") or "")
                if vf and now < vf:
                    continue
                if vt and now > vt:
                    continue

            out[pin] = u

        return out

    def _collect_templates_for_pin(
        self,
        *,
        user: Dict[str, Any],
        pin: str,
        local_fp_index: Dict[str, List[Any]],
        fingerprint_enabled: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Priority:
          1) user['fingerprints'] from cache
          2) local SQLite fingerprints table (newest per finger_id)

        Output items:
          { fingerId:int, templateVersion:int, templateData:str, templateSize:int }
        """
        if not fingerprint_enabled:
            return []

        out: List[Dict[str, Any]] = []

        fps = user.get("fingerprints")
        if isinstance(fps, list):
            for fp in fps:
                if not isinstance(fp, dict):
                    continue
                if fp.get("enabled") is False:
                    continue
                fid = _to_int(fp.get("fingerId"), default=None)
                if fid is None:
                    continue
                tv = _to_int(fp.get("templateVersion"), default=10) or 10
                td = _safe_template_text(fp.get("templateData") or "")
                if not td:
                    continue
                ts = _to_int(fp.get("templateSize"), default=None)
                if ts is None:
                    ts = len(td)

                out.append(
                    {
                        "fingerId": int(fid),
                        "templateVersion": int(tv),
                        "templateData": td,
                        "templateSize": int(ts),
                    }
                )

        if out:
            best: Dict[int, Dict[str, Any]] = {}
            for x in out:
                best[int(x["fingerId"])] = x
            return [best[k] for k in sorted(best.keys())]

        recs = local_fp_index.get(pin) or []
        best_local: Dict[int, Dict[str, Any]] = {}
        for r in recs:
            try:
                fid_i = int(getattr(r, "finger_id"))
            except Exception:
                continue
            td = _safe_template_text(getattr(r, "template_data", "") or "")
            if not td:
                continue
            try:
                tmpl_version_i = int(getattr(r, "template_version"))
            except Exception:
                tmpl_version_i = 10
            try:
                ts_i = int(getattr(r, "template_size"))
            except Exception:
                ts_i = len(td)
            best_local[fid_i] = {
                "fingerId": fid_i,
                "templateVersion": tmpl_version_i,
                "templateData": td,
                "templateSize": ts_i,
            }

        return [best_local[k] for k in sorted(best_local.keys())]

    def _push_userauthorize(
        self,
        sdk: PullSDK,
        *,
        pin: str,
        door_bitmask: int,
        authorize_timezone_id: int,
        device_id: int,
    ) -> Tuple[int, str | None]:
        """Push a single userauthorize record with a pre-computed bitmask.

        Tries the cached firmware pattern first (1 SDK call). Falls back to the
        full retry loop on cache miss or if the cached pattern stopped working
        (e.g., after a firmware upgrade). Caches the winning pattern on success.

        door_bitmask is the OR of individual door bits (1=door1, 2=door2, 4=door3, 8=door4).
        For all 4 doors on a C3-400: bitmask = 1|2|4|8 = 15.
        """
        if door_bitmask <= 0:
            door_bitmask = self._default_authorize_door_id()

        tz = int(authorize_timezone_id or 1)
        if tz < 1:
            tz = 1

        # Pattern list — order matters: preferred (AuthorizeDoorId) first, legacy fallbacks after.
        patterns = [
            f"Pin={pin}\tAuthorizeTimezoneId={tz}\tAuthorizeDoorId={door_bitmask}\r\n",
            f"Pin={pin}\tAuthorizeDoorId={door_bitmask}\tAuthorizeTimezoneId={tz}\r\n",
            f"Pin={pin}\tDoorID={door_bitmask}\tTimeZoneID={tz}\r\n",
            f"Pin={pin}\tDoorID={door_bitmask}\tTimeZone={tz}\r\n",
        ]

        profile = self._get_firmware_profile(device_id)

        # L1: try cached pattern first (1 SDK call)
        if profile.authorize_body_index is not None:
            cached_data = patterns[profile.authorize_body_index]
            try:
                sdk.set_device_data(table="userauthorize", data=cached_data, options="")
                self.logger.debug("[DeviceSync] Pin=%s userauthorize OK (cached pattern=%d)",
                                  pin, profile.authorize_body_index)
                return 1, None
            except Exception as ex:
                # Cached pattern failed — firmware may have been upgraded. Clear and fall through.
                self.logger.warning(
                    "[DeviceSync] Pin=%s userauthorize cached pattern=%d FAILED (%s), "
                    "clearing cache for device_id=%d",
                    pin, profile.authorize_body_index, ex, device_id,
                )
                profile.authorize_body_index = None
                from app.core.db import clear_firmware_profile
                clear_firmware_profile(device_id=device_id)

        # L2: retry loop — discover working pattern and cache it
        last_err = None
        for i, data in enumerate(patterns):
            try:
                sdk.set_device_data(table="userauthorize", data=data, options="")
                self.logger.debug("[DeviceSync] Pin=%s userauthorize OK (pattern=%d)", pin, i)
                # Cache discovery
                profile.authorize_body_index = i
                from app.core.db import save_firmware_profile
                save_firmware_profile(
                    device_id=device_id,
                    template_table=profile.template_table or "templatev10",
                    template_body_index=profile.template_body_index if profile.template_body_index is not None else 0,
                    authorize_body_index=i,
                )
                return 1, None
            except Exception as ex:
                last_err = str(ex)

        self.logger.error(
            "[DeviceSync] Pin=%s userauthorize FAILED all patterns: bitmask=%d err=%s",
            pin, door_bitmask, last_err,
        )
        return 0, last_err or "userauthorize: no compatible field pattern worked"

    def _push_templates(
        self,
        sdk: PullSDK,
        *,
        pin: str,
        templates: List[Dict[str, Any]],
        device_id: int,
    ) -> Tuple[int, List[str]]:
        """Push fingerprint templates to device.

        Tries the cached (table, body_index) combo first for each template (1 SDK call).
        Falls back to the full retry loop on cache miss or if the cached combo fails.
        Caches the winning combo on first successful discovery for the session.
        """
        failed_fp_errs: List[str] = []
        ok = 0

        def try_set(table: str, body: str) -> bool:
            """Attempt SDK call. Returns True on success, False on any exception."""
            try:
                sdk.set_device_data(table=table, data=body + "\r\n", options="")
                return True
            except Exception:
                return False

        profile = self._get_firmware_profile(device_id)

        for t in templates:
            fid = int(t.get("fingerId"))
            tv = int(t.get("templateVersion") or 10)
            size = int(t.get("templateSize") or 0)
            tpl = _safe_template_text(str(t.get("templateData") or ""))

            if not tpl:
                continue

            preferred_tables = ["templatev10", "template"] if tv >= 10 else ["template", "templatev10"]

            bodies = [
                lambda fid=fid, size=size, tpl=tpl: f"Pin={pin}\tFingerID={fid}\tValid=1\tSize={size}\tTemplate={tpl}",
                lambda fid=fid, size=size, tpl=tpl: f"Pin={pin}\tFingerID={fid}\tValid=1\tSize={size}\tTmp={tpl}",
                lambda fid=fid, tpl=tpl: f"Pin={pin}\tFingerID={fid}\tValid=1\tTemplate={tpl}",
                lambda fid=fid, size=size, tpl=tpl: f"Pin={pin}\tFingerID={fid}\tSize={size}\tTemplate={tpl}",
                lambda fid=fid, tpl=tpl: f"Pin={pin}\tFingerID={fid}\tTemplate={tpl}",
            ]

            pushed = False

            # L1: try cached combo (1 SDK call)
            if profile.template_table is not None and profile.template_body_index is not None:
                cached_body = bodies[profile.template_body_index]()
                if try_set(profile.template_table, cached_body):
                    ok += 1
                    pushed = True
                else:
                    # Cached combo failed — clear and fall through to retry loop
                    self.logger.warning(
                        "[DeviceSync] Pin=%s FingerID=%d cached template combo (%s, idx=%d) failed — "
                        "clearing firmware cache for device_id=%d",
                        pin, fid, profile.template_table, profile.template_body_index, device_id,
                    )
                    profile.template_table = None
                    profile.template_body_index = None
                    from app.core.db import clear_firmware_profile
                    clear_firmware_profile(device_id=device_id)

            # L2: retry loop (runs on cache miss or after cache clear)
            if not pushed:
                for table in preferred_tables:
                    for i, bfn in enumerate(bodies):
                        if try_set(table, bfn()):
                            pushed = True
                            ok += 1
                            # Cache winning combo
                            profile.template_table = table
                            profile.template_body_index = i
                            from app.core.db import save_firmware_profile
                            save_firmware_profile(
                                device_id=device_id,
                                template_table=table,
                                template_body_index=i,
                                authorize_body_index=profile.authorize_body_index
                                    if profile.authorize_body_index is not None else 0,
                            )
                            break
                    if pushed:
                        break

            if not pushed:
                failed_fp_errs.append(f"FingerID={fid}: failed to push template (no compatible schema/table)")

        return ok, failed_fp_errs

    def _delete_pin_if_exists(self, *, sdk: PullSDK, pin: str, device_pins: Set[str]) -> bool:
        if pin not in device_pins:
            return False

        if not sdk.supports_delete_device_data():
            self.logger.warning(f"[DeviceSync] DeleteDeviceData not available. Cannot delete Pin={pin}")
            return False

        cond = f"Pin={pin}"

        try:
            sdk.delete_device_data(table="templatev10", data=cond, options="")
        except Exception as ex:
            self.logger.debug(f"[DeviceSync] Delete templatev10 Pin={pin} ignored: {ex}")

        try:
            sdk.delete_device_data(table="template", data=cond, options="")
        except Exception as ex:
            self.logger.debug(f"[DeviceSync] Delete template Pin={pin} ignored: {ex}")

        try:
            sdk.delete_device_data(table="userauthorize", data=cond, options="")
        except Exception as ex:
            self.logger.debug(f"[DeviceSync] Delete userauthorize Pin={pin} ignored: {ex}")

        try:
            sdk.delete_device_data(table="user", data=cond, options="")
        except Exception as ex:
            self.logger.warning(f"[DeviceSync] Delete user Pin={pin} ignored: {ex}")
            return False
        return True

    def _delete_pin_unconditional(self, *, sdk: PullSDK, pin: str) -> bool:
        """
        Delete a pin from ALL tables WITHOUT consulting device_pins first.
        ZKTeco DeleteDeviceData is idempotent — deleting a non-existent record
        returns success (or a benign error) on all known firmware versions.

        Use this for pins_to_sync pre-delete (ensures clean insert even when
        device_pins is stale or the read step returned an empty set).
        Do NOT use for the stale-pins pass — use _delete_pin_if_exists there so
        that we confirm the pin is on the device before issuing SDK calls.
        """
        cond = f"Pin={pin}"
        for table in ("templatev10", "template"):
            try:
                sdk.delete_device_data(table=table, data=cond, options="")
            except Exception as ex:
                self.logger.debug(
                    "[DeviceSync] _delete_pin_unconditional %s Pin=%s (non-fatal): %s", table, pin, ex)
        try:
            sdk.delete_device_data(table="userauthorize", data=cond, options="")
        except Exception as ex:
            self.logger.debug(
                "[DeviceSync] _delete_pin_unconditional userauthorize Pin=%s (non-fatal): %s", pin, ex)
        try:
            sdk.delete_device_data(table="user", data=cond, options="")
            return True
        except Exception as ex:
            self.logger.warning(
                "[DeviceSync] _delete_pin_unconditional user Pin=%s FAILED: %s", pin, ex)
            return False

    def _delete_auth_and_templates_best_effort(self, *, sdk: PullSDK, pin: str) -> None:
        if not sdk.supports_delete_device_data():
            return

        cond = f"Pin={pin}"
        try:
            sdk.delete_device_data(table="templatev10", data=cond, options="")
        except Exception:
            pass
        try:
            sdk.delete_device_data(table="template", data=cond, options="")
        except Exception:
            pass
        try:
            sdk.delete_device_data(table="userauthorize", data=cond, options="")
        except Exception:
            pass

    def _compute_desired_hash(
        self,
        *,
        pin: str,
        user: Dict[str, Any],
        door_bitmask: int,
        templates: List[Dict[str, Any]],
        authorize_timezone_id: int,
    ) -> str:
        full_name = _safe_one_line(user.get("fullName") or "") or f"U{pin}"
        card = _pin_str(user.get("firstCardId") or "")
        doors_norm = str(door_bitmask)
        tz = int(authorize_timezone_id or 1)

        tpl_parts: List[str] = []
        for t in templates or []:
            try:
                fid = int(t.get("fingerId"))
            except Exception:
                continue
            tv = int(t.get("templateVersion") or 10)
            ts = int(t.get("templateSize") or 0)
            td = _safe_template_text(str(t.get("templateData") or ""))
            if not td:
                continue
            tpl_parts.append(f"{fid}:{tv}:{ts}:{td}")
        tpl_blob = "|".join(tpl_parts)

        payload = (
            f"pin={pin}\nname={full_name}\ncard={card}\n"
            f"doors={doors_norm}\nauthorizeTimezoneId={tz}\n"
            f"templates={tpl_blob}\n"
        )
        return _sha1_hex(payload)

    def build_device_sync_fingerprint(
        self,
        *,
        device: Dict[str, Any],
        users: List[Dict[str, Any]],
        local_fp_index: Dict[str, List[Any]] | None = None,
    ) -> Tuple[str, int]:
        normalized_device = self._normalize_device(device if isinstance(device, dict) else {})
        default_door_id = self._default_authorize_door_id()
        door_ids, door_bitmask, authorize_timezone_id, fingerprint_enabled = self._resolve_push_context(
            device=normalized_device,
            default_door_id=default_door_id,
        )
        desired = self._filter_users_for_device(
            users=users,
            device=normalized_device,
            default_door_id=default_door_id,
        )

        if local_fp_index is None:
            local_fp_index = {}
            try:
                recs = list_fingerprints()
                for r in recs:
                    pin = _pin_str(getattr(r, "pin", "") or "")
                    if not pin:
                        continue
                    local_fp_index.setdefault(pin, []).append(r)
            except Exception:
                local_fp_index = {}

        policy = str(normalized_device.get("pushingToDevicePolicy") or "").strip().upper()
        allowed_memberships = _norm_int_list(normalized_device.get("allowedMemberships") or [])
        fingerprint_parts = [
            f"allowedMemberships={','.join(str(v) for v in allowed_memberships)}",
            f"doorIds={','.join(str(v) for v in door_ids)}",
            f"doorBitmask={door_bitmask}",
            f"authorizeTimezoneId={authorize_timezone_id}",
            f"policy={policy}",
            f"fingerprintEnabled={1 if fingerprint_enabled else 0}",
        ]

        for pin in sorted(desired):
            user = desired.get(pin)
            if not isinstance(user, dict):
                continue
            templates = self._collect_templates_for_pin(
                user=user,
                pin=pin,
                local_fp_index=local_fp_index,
                fingerprint_enabled=fingerprint_enabled,
            )
            fingerprint_parts.append(
                self._compute_desired_hash(
                    pin=pin,
                    user=user,
                    door_bitmask=door_bitmask,
                    templates=templates,
                    authorize_timezone_id=authorize_timezone_id,
                )
            )

        payload = "\n".join(fingerprint_parts)
        return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest(), len(desired)

    def _sync_one_device(
        self,
        *,
        device: Dict[str, Any],
        users: List[Dict[str, Any]],
        local_fp_index: Dict[str, List[Any]],
        default_door_id: int,
        changed_ids: set | None = None,
        sync_run_id: int | None = None,
        sdk: PullSDK | None = None,
    ) -> None:
        dev_id = device.get("id")
        dev_name = device.get("name") or ""
        ip = (device.get("ipAddress") or "").strip()
        port = _to_int(device.get("portNumber"), default=4370) or 4370
        pwd = device.get("password") or ""
        batch_id: int | None = None
        batch_started_iso: str | None = None
        batch_started_perf = time.perf_counter()
        pins_sorted: List[str] = []
        pin_outcomes: Dict[str, Dict[str, Any]] = {}
        batch_error: str | None = None

        door_ids, door_bitmask, authorize_timezone_id, fingerprint_enabled = self._resolve_push_context(
            device=device,
            default_door_id=default_door_id,
        )

        if dev_id is None:
            self.logger.warning(f"[DeviceSync] Skip device name={dev_name!r}: missing id")
            return
        did = int(_to_int(dev_id, default=0) or 0)
        if did <= 0:
            self.logger.warning(f"[DeviceSync] Skip device name={dev_name!r}: invalid id={dev_id!r}")
            return

        if not ip:
            self.logger.warning(f"[DeviceSync] Skip device id={dev_id} name={dev_name!r}: missing ipAddress")
            return

        # P1: resolve effective push policy for this device
        policy = self._resolve_push_policy(device)

        desired = self._filter_users_for_device(users=users, device=device, default_door_id=default_door_id)
        desired_pins = set(desired.keys())

        known_server_pins: Set[str] = set()
        for u in users or []:
            p = _pin_str(u.get("activeMembershipId"))
            if p and p.isdigit():
                known_server_pins.add(p)

        prev_state = list_device_sync_hashes_and_status(device_id=did)
        # Also keep a simple hash dict for backward compat with prune logic
        prev_hashes = {p: h for p, (h, _ok) in prev_state.items()}
        deletion_only_delta = changed_ids is not None and len(changed_ids) == 0

        pins_to_sync: Set[str] = set()
        desired_hashes: Dict[str, str] = {}
        templates_for_sync: Dict[str, List[Dict[str, Any]]] = {}

        for pin, u in desired.items():
            templates = self._collect_templates_for_pin(
                user=u, pin=pin, local_fp_index=local_fp_index,
                fingerprint_enabled=fingerprint_enabled,
            )
            dh = self._compute_desired_hash(
                pin=pin,
                user=u,
                door_bitmask=door_bitmask,
                templates=templates,
                authorize_timezone_id=authorize_timezone_id,
            )
            desired_hashes[pin] = dh
            prev_hash, prev_ok = prev_state.get(pin, ("", True))
            # Sync if: hash changed OR previous attempt failed
            if prev_hash != dh or not prev_ok:
                pins_to_sync.add(pin)
                templates_for_sync[pin] = templates

        # Delta hint: when the backend reported only a subset of users changed,
        # prune pins_to_sync to those users + any with a failed/missing prev sync.
        # Stale-pin deletion is unaffected (uses desired_pins, not pins_to_sync).
        # Skip delta pruning for FULL_REPLACE - that policy always pushes everything.
        if deletion_only_delta and policy != _PUSH_POLICY_FULL_REPLACE:
            # Deletion-only deltas should only remove stale pins; they should not
            # retry or re-push the full desired roster.
            pins_to_sync = set()
            templates_for_sync = {}
        elif changed_ids is not None and policy != _PUSH_POLICY_FULL_REPLACE:
            pins_to_sync = {
                pin for pin in pins_to_sync
                if (
                    int(pin) in changed_ids          # changed per backend delta
                    or not prev_state.get(pin, ("", True))[0]   # no stored hash (new)
                    or not prev_state.get(pin, ("", True))[1]   # previous push failed
                )
            }

        self.logger.info(
            f"[DeviceSync] Device id={dev_id} name={dev_name!r} ip={ip}:{port} "
            f"desired={len(desired_pins)} to_sync={len(pins_to_sync)} "
            f"door_bitmask={door_bitmask} doorIds={door_ids} tz={authorize_timezone_id} policy={policy}"
        )

        batch_started_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
        batch_id = insert_push_batch(
            sync_run_id=sync_run_id,
            device_id=did,
            device_name=dev_name or f"Device {did}",
            policy=policy,
            status="IN_PROGRESS",
            created_at=batch_started_iso,
        )

        disconnect_when_done = sdk is None
        if sdk is None:
            sdk = PullSDK(self.cfg.plcomm_dll_path, logger=self.logger)
        try:
            if disconnect_when_done:
                import time as _time

                t_connect = _time.time()
                connect_timeout_ms = self._resolve_connect_timeout_ms(device)
                self.logger.info(
                    "[DeviceSync] Device id=%s name=%r connecting: ip=%s port=%s timeout_ms=%s",
                    dev_id,
                    dev_name,
                    ip,
                    port,
                    connect_timeout_ms,
                )
                sdk.connect(
                    ip=ip,
                    port=int(port),
                    timeout_ms=connect_timeout_ms,
                    password=str(pwd),
                )
                connect_ms = (_time.time() - t_connect) * 1000
                self.logger.info(
                    "[DeviceSync] Device id=%s name=%r connected OK: connect_ms=%.0f", dev_id, dev_name, connect_ms
                )

            rows = sdk.get_device_data_rows(
                table="user",
                fields="Pin",
                filter_expr="",
                options="",
                initial_size=self._sdk_read_initial_bytes(),  # ✅ backend-driven knob
            )
            device_pins: Set[str] = set()
            for r in rows:
                p = _pin_str(r.get("Pin") or r.get("pin") or "")
                if p:
                    device_pins.add(p)

            # F-011: Drift detection — desired pins missing from device despite having a stored hash
            # indicate external removal. Force re-sync for those pins.
            # In delta mode skip drift check for unchanged users; they'll be caught on the next full sync.
            for pin in desired_pins:
                if pin not in device_pins and prev_hashes.get(pin) and pin not in pins_to_sync:
                    if changed_ids is not None and int(pin) not in changed_ids:
                        continue  # skip drift detection for unchanged users in delta mode
                    self.logger.info(
                        f"[DeviceSync] Device id={dev_id} Pin={pin}: "
                        f"not on device but hash stored — external removal detected, forcing re-sync"
                    )
                    pins_to_sync.add(pin)
                    if pin not in templates_for_sync:
                        u = desired.get(pin)
                        if isinstance(u, dict):
                            templates_for_sync[pin] = self._collect_templates_for_pin(
                                user=u, pin=pin, local_fp_index=local_fp_index,
                                fingerprint_enabled=fingerprint_enabled,
                            )

            # stale pins: only delete pins that are known-from-server but no longer desired for this device
            tracked_server_pins = set(known_server_pins) | set(prev_state.keys())
            stale_pins = sorted([p for p in device_pins if p in tracked_server_pins and p not in desired_pins])
            self.logger.info(
                "[DeviceSync] Device id=%s: device_pins=%d desired=%d to_sync=%d "
                "stale=%d drift_resynced=%d door_bitmask=%d",
                dev_id, len(device_pins), len(desired_pins), len(pins_to_sync),
                len(stale_pins),
                sum(1 for p in desired_pins if p not in device_pins and prev_hashes.get(p)),
                door_bitmask,
            )

            # ── P1: Policy-driven nuke decision ──────────────────────────────
            # FULL_REPLACE  → always clear all tables (policy mandate).
            # ADDITIVE_ONLY → never delete anything; skip stale-pin removal too.
            # INCREMENTAL   → heuristic nuke when deleting > keeping (optimization).
            if policy == _PUSH_POLICY_FULL_REPLACE:
                nuke_mode = True
                pins_to_sync = set(desired.keys())  # push entire roster
                stale_pins = []                      # tables will be cleared anyway
                self.logger.info(
                    "[DeviceSync] Device id=%s: FULL_REPLACE policy — "
                    "clearing all tables, pushing all %d members",
                    dev_id, len(pins_to_sync),
                )
            elif policy == _PUSH_POLICY_ADDITIVE_ONLY:
                nuke_mode = False
                _ignored_stale = len(stale_pins)
                stale_pins = []  # never remove stale pins in ADDITIVE_ONLY
                if _ignored_stale > 0:
                    self.logger.info(
                        "[DeviceSync] Device id=%s: ADDITIVE_ONLY policy — "
                        "%d stale pin(s) left on device intentionally",
                        dev_id, _ignored_stale,
                    )
            else:
                # INCREMENTAL: heuristic nuke-and-repave
                nuke_mode = (
                    False if deletion_only_delta
                    else len(stale_pins) > len(desired_pins) and len(stale_pins) > 10
                )
            if nuke_mode:
                self.logger.info(
                    "[DeviceSync] Device id=%s: NUKE-AND-REPAVE — clearing %d stale, re-pushing %d desired",
                    dev_id, len(stale_pins), len(desired_pins),
                )
                # Template tables are optional (templatev10 vs template depends on firmware).
                # Best-effort clear — don't abort nuke if these fail.
                for tbl in ("templatev10", "template"):
                    try:
                        sdk.clear_device_table(table=tbl)
                    except PullSDKError:
                        self.logger.debug("[DeviceSync] Device id=%s: clear %s skipped (table may not exist)", dev_id, tbl)
                # Critical tables: userauthorize then user. Abort nuke if these fail.
                for tbl in ("userauthorize", "user"):
                    try:
                        sdk.clear_device_table(table=tbl)
                    except PullSDKError as ex:
                        self.logger.warning("[DeviceSync] Device id=%s: clear %s failed: %s — falling back to individual delete", dev_id, tbl, ex)
                        nuke_mode = False
                        break
                if nuke_mode:
                    # Device is now empty — push ALL desired users
                    pins_to_sync = set(desired_pins)
                    stale_pins = []
                    device_pins = set()
                    # Collect templates for pins that weren't in the original pins_to_sync
                    for pin in desired_pins:
                        if pin not in templates_for_sync:
                            u = desired.get(pin)
                            if isinstance(u, dict):
                                templates_for_sync[pin] = self._collect_templates_for_pin(
                                    user=u, pin=pin, local_fp_index=local_fp_index,
                                    fingerprint_enabled=fingerprint_enabled,
                                )

            # ── Delete stale pins (skipped when nuke mode cleared everything) ──
            deleted = 0
            for p in stale_pins:
                try:
                    if self._delete_pin_if_exists(sdk=sdk, pin=p, device_pins=device_pins):
                        deleted += 1
                    delete_device_sync_state(device_id=did, pin=p)
                    try:
                        delete_device_mirror_pin(device_id=did, pin=p)
                    except Exception:
                        pass
                except Exception as ex:
                    self.logger.warning(f"[DeviceSync] Delete stale Pin={p} failed: {ex}")

            pushed_users = 0
            pushed_templates = 0
            warn_templates_users = 0
            ok_synced = 0
            failed_synced = 0

            # Expose live progress for the frontend banner.
            self._set_progress(
                deviceName=dev_name or "",
                deviceId=did,
                current=0,
                total=len(pins_to_sync),
            )

            # ── Batch push: user + authorize rows in chunks of 50 ──────────
            # In nuke mode the device is clear — no pre-delete needed.
            # In normal mode we pre-delete pins individually before batch push.
            use_batch = nuke_mode or len(pins_to_sync) > 5
            pins_sorted = sorted(pins_to_sync)

            if use_batch and pins_sorted:
                # P0 fix: Unconditional delete-before-insert for each changed pin.
                # _delete_pin_unconditional does NOT check device_pins first — it
                # always issues the SDK delete, which is idempotent on all ZKTeco
                # firmware (deleting a non-existent pin is a no-op, not an error).
                # This prevents the silent-failure where firmware returns rc=0 on a
                # duplicate-pin insert (appearing to succeed but keeping the old CardNo).
                if not nuke_mode:
                    predelete_progress_cap = max(0, len(pins_sorted) - 1)
                    predelete_progress_step = max(1, len(pins_sorted) // 100)
                    for idx, pin in enumerate(pins_sorted, start=1):
                        self._delete_pin_unconditional(sdk=sdk, pin=pin)
                        if (
                            predelete_progress_cap > 0
                            and (idx == len(pins_sorted) or idx % predelete_progress_step == 0)
                        ):
                            # Batch sync can spend a long time deleting/replacing rows
                            # before the final save-state phase completes.
                            self._set_progress(current=min(predelete_progress_cap, idx))

                # Phase A: Batch push user rows
                # Use cached name_supported flag to skip Name field on firmware that rejects it.
                profile = self._get_firmware_profile(int(dev_id) if dev_id is not None else 0)
                use_name = profile.name_supported is not False  # True or None (unknown) → include Name

                user_rows = []
                pin_to_user = {}
                for pin in pins_sorted:
                    u = desired.get(pin)
                    if not isinstance(u, dict):
                        continue
                    full_name = _safe_one_line(u.get("fullName") or "") or f"U{pin}"
                    card = _pin_str(u.get("firstCardId") or "")
                    card_valid = card if (card and card.isdigit()) else ""
                    pairs = [f"Pin={pin}"]
                    if use_name:
                        pairs.append(f"Name={full_name}")
                    if card_valid:
                        pairs.append(f"CardNo={card_valid}")
                    user_rows.append("\t".join(pairs))
                    pin_to_user[pin] = u

                if user_rows:
                    ok_u, failed_u = sdk.set_device_data_batch(table="user", rows=user_rows, chunk_size=50)
                    pushed_users = ok_u

                    if not failed_u and profile.name_supported is None and use_name:
                        # Name field accepted — cache this discovery
                        profile.name_supported = True
                        self._save_firmware_profile(profile, int(dev_id) if dev_id is not None else 0)
                        self.logger.info("[DeviceSync] Device id=%s: Name field supported — cached", dev_id)

                    if failed_u and use_name:
                        # Name field likely rejected (rc=-101). Retry WITHOUT Name and cache the result.
                        self.logger.warning(
                            "[DeviceSync] Device id=%s: %d user rows failed with Name field, "
                            "retrying without Name", dev_id, len(failed_u))
                        retry_rows = []
                        for row in failed_u:
                            parts = {p.split("=", 1)[0]: p.split("=", 1)[1]
                                     for p in row.split("\t") if "=" in p}
                            rp = [f"Pin={parts.get('Pin', '')}"]
                            if parts.get("CardNo"):
                                rp.append(f"CardNo={parts['CardNo']}")
                            retry_rows.append("\t".join(rp))
                        ok_r, failed_r = sdk.set_device_data_batch(table="user", rows=retry_rows, chunk_size=50)
                        pushed_users += ok_r
                        if ok_r > 0:
                            # Confirmed: Name field not supported on this firmware
                            profile.name_supported = False
                            self._save_firmware_profile(profile, int(dev_id) if dev_id is not None else 0)
                            self.logger.info(
                                "[DeviceSync] Device id=%s: Name field NOT supported — cached (won't retry next time)",
                                dev_id)
                        if failed_r:
                            # Even without Name, some rows failed — try individual with force-delete
                            for row in failed_r:
                                pin = _batch_row_field(row, "Pin")
                                card_valid = _batch_row_field(row, "CardNo")
                                if not pin:
                                    continue
                                try:
                                    self._delete_pin_if_exists(sdk=sdk, pin=pin, device_pins=device_pins)
                                    mp = [f"Pin={pin}"]
                                    if card_valid:
                                        mp.append(f"CardNo={card_valid}")
                                    sdk.set_device_data(table="user", data="\t".join(mp) + "\r\n", options="")
                                    pushed_users += 1
                                except Exception as ex:
                                    pin_outcomes[pin] = {
                                        "full_name": _safe_one_line((pin_to_user.get(pin) or {}).get("fullName") or "") or f"U{pin}",
                                        "status": "FAILED",
                                        "error_message": str(ex),
                                        "duration_ms": 0,
                                    }
                                    self.logger.warning(
                                        "[DeviceSync] Device id=%s Pin=%s force-delete retry FAILED: %s",
                                        dev_id, pin, ex)
                    elif failed_u and not use_name:
                        # Already using minimal fields but still failing — individual force-delete
                        for row in failed_u:
                            pin = _batch_row_field(row, "Pin")
                            card_valid = _batch_row_field(row, "CardNo")
                            if not pin:
                                continue
                            try:
                                self._delete_pin_if_exists(sdk=sdk, pin=pin, device_pins=device_pins)
                                mp = [f"Pin={pin}"]
                                if card_valid:
                                    mp.append(f"CardNo={card_valid}")
                                sdk.set_device_data(table="user", data="\t".join(mp) + "\r\n", options="")
                                pushed_users += 1
                            except Exception as ex:
                                pin_outcomes[pin] = {
                                    "full_name": _safe_one_line((pin_to_user.get(pin) or {}).get("fullName") or "") or f"U{pin}",
                                    "status": "FAILED",
                                    "error_message": str(ex),
                                    "duration_ms": 0,
                                }
                                self.logger.warning(
                                    "[DeviceSync] Device id=%s Pin=%s force-delete retry FAILED: %s",
                                    dev_id, pin, ex)

                # Phase B: Batch push authorize rows
                # Discover firmware profile if not cached (push 1 pin individually first)
                profile = self._get_firmware_profile(int(dev_id) if dev_id is not None else 0)
                if profile.authorize_body_index is None and pins_sorted:
                    # No cached pattern — discover by pushing first user individually
                    first_pin = pins_sorted[0]
                    self._push_userauthorize(
                        sdk, pin=first_pin, door_bitmask=door_bitmask,
                        authorize_timezone_id=int(authorize_timezone_id),
                        device_id=int(dev_id) if dev_id is not None else 0,
                    )
                    profile = self._get_firmware_profile(int(dev_id) if dev_id is not None else 0)
                    remaining_pins = pins_sorted[1:]
                else:
                    remaining_pins = pins_sorted

                if profile.authorize_body_index is not None and remaining_pins:
                    tz = int(authorize_timezone_id)
                    patterns = [
                        lambda p: f"Pin={p}\tAuthorizeTimezoneId={tz}\tAuthorizeDoorId={door_bitmask}",
                        lambda p: f"Pin={p}\tAuthorizeDoorId={door_bitmask}\tAuthorizeTimezoneId={tz}",
                        lambda p: f"Pin={p}\tDoorID={door_bitmask}\tTimeZoneID={tz}",
                        lambda p: f"Pin={p}\tDoorID={door_bitmask}\tTimeZone={tz}",
                    ]
                    pattern_fn = patterns[profile.authorize_body_index]
                    auth_rows = [pattern_fn(p) for p in remaining_pins if desired.get(p)]
                    if auth_rows:
                        ok_a, failed_a = sdk.set_device_data_batch(
                            table="userauthorize", rows=auth_rows, chunk_size=50)
                        if failed_a:
                            for row in failed_a:
                                pin = _batch_row_field(row, "Pin")
                                if not pin:
                                    continue
                                pin_outcomes[pin] = {
                                    "full_name": _safe_one_line((desired.get(pin) or {}).get("fullName") or "") or f"U{pin}",
                                    "status": "FAILED",
                                    "error_message": "authorize batch failed",
                                    "duration_ms": 0,
                                }
                            self.logger.warning(
                                "[DeviceSync] Device id=%s: %d authorize rows failed in batch", dev_id, len(failed_a))
                elif remaining_pins:
                    # No cached pattern available — fall back to per-pin authorize
                    for pin in remaining_pins:
                        try:
                            self._push_userauthorize(
                                sdk, pin=pin, door_bitmask=door_bitmask,
                                authorize_timezone_id=int(authorize_timezone_id),
                                device_id=int(dev_id) if dev_id is not None else 0,
                            )
                        except Exception as ex:
                            pin_outcomes[pin] = {
                                "full_name": _safe_one_line((desired.get(pin) or {}).get("fullName") or "") or f"U{pin}",
                                "status": "FAILED",
                                "error_message": str(ex),
                                "duration_ms": 0,
                            }
                            self.logger.warning(f"[DeviceSync] Device id={dev_id} Pin={pin} authorize FAILED: {ex}")

                # Phase C: Push templates individually (binary data — too large to batch)
                for pin in pins_sorted:
                    templates = templates_for_sync.get(pin) or []
                    if templates:
                        try:
                            ok_count, errs = self._push_templates(
                                sdk, pin=pin, templates=templates,
                                device_id=int(dev_id) if dev_id is not None else 0)
                            pushed_templates += ok_count
                            if errs:
                                warn_templates_users += 1
                                self.logger.warning(
                                    f"[DeviceSync] Device id={dev_id} Pin={pin} template errors ({len(errs)}): "
                                    f"{errs[:5]}{'...' if len(errs) > 5 else ''}")
                        except Exception as ex:
                            warn_templates_users += 1
                            self.logger.warning(f"[DeviceSync] Device id={dev_id} Pin={pin} template FAILED: {ex}")

                # Phase D: Save device sync state + write-through mirror for all pushed pins.
                # Build all state rows first (pure Python), then flush to DB in ONE batch
                # transaction instead of one DbWriter round-trip per pin (N pins × ~2ms =
                # ~2.5s serialised queue wait for a 1277-member club with 2 devices).
                _batch_state_rows: list[tuple[str, str | None, bool, str | None]] = []
                for pin in pins_sorted:
                    u = desired.get(pin)
                    if u:
                        _u_name = _safe_one_line(u.get("fullName") or "") or f"U{pin}"
                        _u_card = _pin_str(u.get("firstCardId") or "")
                        _u_fps = len(templates_for_sync.get(pin) or [])
                        pin_error = pin_outcomes.get(pin, {}).get("error_message")
                        pin_ok = not pin_error
                        _batch_state_rows.append((
                            pin,
                            desired_hashes.get(pin) or "",
                            pin_ok,
                            None if pin_ok else str(pin_error),
                        ))
                        pin_outcomes[pin] = {
                            "full_name": _u_name,
                            "status": "SUCCESS" if pin_ok else "FAILED",
                            "error_message": None if pin_ok else str(pin_error),
                            "duration_ms": 0,
                        }
                        if pin_ok:
                            ok_synced += 1
                        else:
                            failed_synced += 1
                        # P7: update device content mirror (write-through)
                        try:
                            upsert_device_mirror_pin(
                                device_id=did, pin=pin,
                                full_name=_u_name, card_no=_u_card or None,
                                door_bitmask=door_bitmask,
                                authorize_tz_id=int(authorize_timezone_id),
                                fp_count=_u_fps, push_ok=pin_ok,
                            )
                        except Exception:
                            pass
                # Single DbWriter transaction for all N pins (replaces N round-trips).
                if _batch_state_rows:
                    try:
                        save_device_sync_state_batch(device_id=did, rows=_batch_state_rows)
                    except Exception as _batch_err:
                        self.logger.warning(
                            "[DeviceSync] Device id=%s save_device_sync_state_batch failed "
                            "(%d rows): %s", dev_id, len(_batch_state_rows), _batch_err
                        )
                self._set_progress(current=ok_synced)
                self.logger.info(
                    "[DeviceSync] Device id=%s batch push complete: users=%d auth=%d templates=%d",
                    dev_id, pushed_users, len(pins_sorted), pushed_templates,
                )

            else:
                # ── Per-pin push (small sync ≤5 pins, or batch not applicable) ──
                for pin in pins_sorted:
                    u = desired.get(pin)
                    if not isinstance(u, dict):
                        continue

                    pin_started_perf = time.perf_counter()
                    full_name = _safe_one_line(u.get("fullName") or "") or f"U{pin}"
                    card = _pin_str(u.get("firstCardId") or "")
                    templates = templates_for_sync.get(pin) or []

                    self.logger.debug(
                        "[DeviceSync] Device id=%s syncing Pin=%s name=%r card=%r templates=%d",
                        dev_id, pin, full_name, card, len(templates),
                    )

                    try:
                        # P0 fix: unconditional delete — never rely on device_pins
                        # being accurate (it may be empty/stale if the read failed or
                        # returned no rows). See _delete_pin_unconditional docstring.
                        self._delete_pin_unconditional(sdk=sdk, pin=pin)

                        card_valid = card if (card and card.isdigit()) else ""
                        if card and not card_valid:
                            self.logger.warning(
                                "[DeviceSync] Device id=%s Pin=%s CardNo=%r is not numeric — skipping CardNo",
                                dev_id, pin, card,
                            )

                        _did = int(dev_id) if dev_id is not None else 0
                        _profile = self._get_firmware_profile(_did)
                        _use_name = _profile.name_supported is not False
                        pairs = [f"Pin={pin}"]
                        if _use_name:
                            pairs.append(f"Name={full_name}")
                        if card_valid:
                            pairs.append(f"CardNo={card_valid}")
                        _user_data = "\t".join(pairs) + "\r\n"
                        try:
                            sdk.set_device_data(table="user", data=_user_data, options="")
                            if _profile.name_supported is None and _use_name:
                                _profile.name_supported = True
                                self._save_firmware_profile(_profile, _did)
                        except PullSDKError as _set_err:
                            if "rc=-101" not in str(_set_err):
                                raise
                            self.logger.warning(
                                "[DeviceSync] Device id=%s Pin=%s SetDeviceData rc=-101 "
                                "— force-delete + retry without Name", dev_id, pin)
                            self._delete_auth_and_templates_best_effort(sdk=sdk, pin=pin)
                            try:
                                sdk.delete_device_data(table="user", data=f"Pin={pin}", options="")
                            except Exception:
                                pass
                            minimal_pairs = [f"Pin={pin}"]
                            if card_valid:
                                minimal_pairs.append(f"CardNo={card_valid}")
                            sdk.set_device_data(table="user", data="\t".join(minimal_pairs) + "\r\n", options="")
                            if _use_name and _profile.name_supported is None:
                                _profile.name_supported = False
                                self._save_firmware_profile(_profile, _did)
                                self.logger.info(
                                    "[DeviceSync] Device id=%s: Name field NOT supported — cached", dev_id)
                        pushed_users += 1

                        auth_complete = True
                        try:
                            auth_ok_count, auth_err = self._push_userauthorize(
                                sdk, pin=pin, door_bitmask=door_bitmask,
                                authorize_timezone_id=int(authorize_timezone_id),
                                device_id=int(dev_id) if dev_id is not None else 0,
                            )
                            if auth_err:
                                auth_complete = (auth_ok_count == len(door_ids))
                                self.logger.warning(
                                    f"[DeviceSync] Device id={dev_id} Pin={pin} authorize "
                                    f"{'PARTIAL' if not auth_complete else 'warn'}: "
                                    f"{auth_ok_count}/{len(door_ids)} doors — {auth_err}")
                        except Exception as ex:
                            auth_complete = False
                            self.logger.warning(f"[DeviceSync] Device id={dev_id} Pin={pin} authorize FAILED: {ex}")

                        if templates:
                            ok_count, errs = self._push_templates(
                                sdk, pin=pin, templates=templates,
                                device_id=int(dev_id) if dev_id is not None else 0)
                            pushed_templates += ok_count
                            if errs:
                                warn_templates_users += 1
                                self.logger.warning(
                                    f"[DeviceSync] Device id={dev_id} Pin={pin} template errors ({len(errs)}): "
                                    f"{errs[:5]}{'...' if len(errs) > 5 else ''}")

                        if auth_complete:
                            save_device_sync_state(
                                device_id=did, pin=pin,
                                desired_hash=desired_hashes.get(pin) or "",
                                ok=True, error=None,
                            )
                            pin_outcomes[pin] = {
                                "full_name": full_name,
                                "status": "SUCCESS",
                                "error_message": None,
                                "duration_ms": int((time.perf_counter() - pin_started_perf) * 1000),
                            }
                            ok_synced += 1
                            # P7: write-through device content mirror
                            try:
                                upsert_device_mirror_pin(
                                    device_id=did, pin=pin,
                                    full_name=full_name, card_no=card or None,
                                    door_bitmask=door_bitmask,
                                    authorize_tz_id=int(authorize_timezone_id),
                                    fp_count=len(templates), push_ok=True,
                                )
                            except Exception:
                                pass
                        else:
                            save_device_sync_state(
                                device_id=did, pin=pin,
                                desired_hash=desired_hashes.get(pin) or "",
                                ok=False, error=auth_err or "authorize incomplete",
                            )
                            pin_outcomes[pin] = {
                                "full_name": full_name,
                                "status": "FAILED",
                                "error_message": auth_err or "authorize incomplete",
                                "duration_ms": int((time.perf_counter() - pin_started_perf) * 1000),
                            }
                            failed_synced += 1
                            # P7: record failed push in mirror so dashboard can show drift
                            try:
                                upsert_device_mirror_pin(
                                    device_id=did, pin=pin,
                                    full_name=full_name, card_no=card or None,
                                    door_bitmask=door_bitmask,
                                    authorize_tz_id=int(authorize_timezone_id),
                                    fp_count=len(templates), push_ok=False,
                                )
                            except Exception:
                                pass
                        self._set_progress(current=ok_synced + failed_synced)

                    except Exception as ex:
                        failed_synced += 1
                        self._set_progress(current=ok_synced + failed_synced)
                        save_device_sync_state(
                            device_id=did, pin=pin,
                            desired_hash=None, ok=False, error=str(ex),
                        )
                        pin_outcomes[pin] = {
                            "full_name": full_name,
                            "status": "FAILED",
                            "error_message": str(ex),
                            "duration_ms": int((time.perf_counter() - pin_started_perf) * 1000),
                        }
                        self.logger.warning(
                            "[DeviceSync] Device id=%s Pin=%s sync FAILED: %s", dev_id, pin, ex)

            pruned = prune_device_sync_state(device_id=did, keep_pins=desired_pins)

            # ── Write door timing to controller firmware ──
            # Without this, the C3 keeps its factory/old defaults and the
            # turnstile relay stays active too long (allows a second person).
            presets = device.get("doorPresets") or []
            for p in presets:
                if not isinstance(p, dict):
                    continue
                dn = p.get("doorNumber") or p.get("door_number")
                ps = p.get("pulseSeconds") or p.get("pulse_seconds")
                if dn is not None and ps is not None and int(ps) > 0:
                    param_str = f"Door{int(dn)}Drivertime={int(ps)}"
                    try:
                        sdk.set_device_param(items=param_str)
                        self.logger.info(
                            "[DeviceSync] Device id=%s SetDeviceParam %s OK",
                            dev_id, param_str,
                        )
                    except Exception as ex:
                        self.logger.warning(
                            "[DeviceSync] Device id=%s SetDeviceParam %s failed: %s",
                            dev_id, param_str, ex,
                        )

            # [Anti-fraud] Push DoorIntertime (Punch Interval) to C3 controller.
            # DoorXIntertime=N prevents the same card from being accepted on
            # door X within N seconds (range 0-255). This is the correct C3
            # parameter for re-entry prevention — NOT AntiPassback (which is
            # about in/out tracking). Failure is non-fatal — the software
            # AntiFraudGuard and ULTRA _card_cooldown remain backup enforcers.
            _af_card = bool(device.get("anti_fraude_card", True))
            _af_duration = min(int(device.get("anti_fraude_duration") or 30), 255)
            _af_params = []
            if _af_card and _af_duration > 0:
                for p in presets:
                    if not isinstance(p, dict):
                        continue
                    dn = p.get("doorNumber") or p.get("door_number")
                    if dn is not None:
                        _af_params.append(f"Door{int(dn)}Intertime={_af_duration}")
            _af_param = ",".join(_af_params) if _af_params else "AntiPassback=0"
            try:
                sdk.set_device_param(items=_af_param)
                self.logger.info(
                    "[DeviceSync] Device id=%s anti-fraud param OK (%s)",
                    dev_id, _af_param,
                )
            except Exception as _af_ex:
                self.logger.warning(
                    "[DeviceSync] Device id=%s anti-passback param FAILED (non-fatal): %s",
                    dev_id, _af_ex,
                )

            self.logger.info(
                f"[DeviceSync] Device id={dev_id} name={dev_name!r} DONE: stale_deleted={deleted} synced_ok={ok_synced} synced_fail={failed_synced} pushed_users={pushed_users} pushed_templates={pushed_templates} warn_templates_users={warn_templates_users} state_pruned={pruned}"
            )

        except Exception as ex:
            batch_error = str(ex)
            raise
        finally:
            if batch_id is not None:
                if batch_error and pins_sorted:
                    for pin in pins_sorted:
                        if pin not in pin_outcomes:
                            pin_outcomes[pin] = {
                                "full_name": _safe_one_line((desired.get(pin) or {}).get("fullName") or "") or f"U{pin}",
                                "status": "FAILED",
                                "error_message": batch_error,
                                "duration_ms": 0,
                            }
                # Batch all pin history rows in one DbWriter transaction
                # (replaces N individual insert_push_pin round-trips).
                _pin_batch_rows = [
                    (
                        pin,
                        pin_outcomes[pin].get("full_name"),
                        "UPSERT",
                        pin_outcomes[pin].get("status") or "FAILED",
                        pin_outcomes[pin].get("error_message"),
                        int(pin_outcomes[pin].get("duration_ms") or 0),
                    )
                    for pin in sorted(pin_outcomes.keys())
                ]
                if _pin_batch_rows:
                    try:
                        insert_push_pin_batch(batch_id=batch_id, rows=_pin_batch_rows)
                    except Exception as _pin_batch_err:
                        self.logger.warning(
                            "[DeviceSync] Device id=%s insert_push_pin_batch failed "
                            "(%d rows): %s", dev_id, len(_pin_batch_rows), _pin_batch_err
                        )
                pins_attempted = len(pins_sorted)
                pins_success = sum(1 for outcome in pin_outcomes.values() if outcome.get("status") == "SUCCESS")
                pins_failed = max(pins_attempted - pins_success, 0)
                duration_ms = int((time.perf_counter() - batch_started_perf) * 1000)
                if batch_error and pins_success == 0:
                    batch_status = "FAILED"
                elif batch_error or pins_failed > 0:
                    batch_status = "PARTIAL" if pins_success > 0 else "FAILED"
                else:
                    batch_status = "SUCCESS"
                update_push_batch(
                    id=batch_id,
                    pins_attempted=pins_attempted,
                    pins_success=pins_success,
                    pins_failed=pins_failed,
                    status=batch_status,
                    duration_ms=duration_ms,
                    error_message=batch_error,
                )
                if batch_status == "SUCCESS":
                    self._emit_feedback_event(
                        "device_push_success",
                        {
                            "syncRunId": sync_run_id,
                            "batchId": batch_id,
                            "deviceId": did,
                            "deviceName": dev_name,
                        },
                    )
            if disconnect_when_done:
                try:
                    sdk.disconnect()
                except Exception:
                    pass

    def _sync_all_devices(
        self,
        *,
        cache,
        changed_ids: set | None = None,
        sync_run_id: int | None = None,
    ) -> None:
        if not cache:
            self.logger.info("[DeviceSync] No cache -> skip")
            return

        # Users are already normalized to payload-ish dicts by db.load_sync_cache()
        users = getattr(cache, "users", []) or []

        # Devices may be snake_case rows (from normalized table) OR camelCase (fallback payload)
        devices_raw = getattr(cache, "devices", []) or []
        devices = [self._normalize_device(d) for d in devices_raw if isinstance(d, dict)]

        if not devices:
            self._actor_registry.update_devices([])
            self.logger.info("[DeviceSync] No devices in cache -> skip")
            return

        device_mode_devices: List[Dict[str, Any]] = []
        for d in devices:
            dev_id = d.get("id")
            dev_name = d.get("name", "")
            if not _boolish(d.get("active"), default=True):
                self.logger.info(
                    "[DeviceSync] Skip device id=%s name=%r: active=False", dev_id, dev_name
                )
                continue
            if not _boolish(d.get("accessDevice"), default=True):
                self.logger.info(
                    "[DeviceSync] Skip device id=%s name=%r: accessDevice=False", dev_id, dev_name
                )
                continue

            # Only sync DEVICE-mode devices; AGENT-mode devices are handled by AgentRealtimeEngine
            adm = str(d.get("accessDataMode", "DEVICE")).strip().upper()
            if adm != "DEVICE":
                self.logger.info(
                    "[DeviceSync] Skip device id=%s name=%r: accessDataMode=%r (not DEVICE)",
                    dev_id, dev_name, adm,
                )
                continue

            device_mode_devices.append(d)

        self.logger.info(
            "[DeviceSync] device_mode_devices to sync: %d", len(device_mode_devices)
        )

        self._actor_registry.update_devices(device_mode_devices)
        if not device_mode_devices:
            return

        normalized_changed_ids = (
            None
            if changed_ids is None
            else {
                int(member_id)
                for member_id in changed_ids
                if member_id is not None
            }
        )
        if normalized_changed_ids is not None and not normalized_changed_ids:
            self._set_progress(running=False, current=0, total=0)
            self.logger.info("[DeviceSync] delta sync no-op: changed_ids empty -> skip actor dispatch")
            return

        local_fp_index: Dict[str, List[Any]] = {}
        uses_fingerprints = any(
            _boolish(
                d.get("fingerprintEnabled", d.get("fingerprint_enabled")),
                default=False,
            )
            for d in device_mode_devices
        )
        if uses_fingerprints:
            try:
                recs = list_fingerprints()
                for r in recs:
                    pin = _pin_str(getattr(r, "pin", "") or "")
                    if not pin:
                        continue
                    local_fp_index.setdefault(pin, []).append(r)
            except Exception:
                local_fp_index = {}

        default_door_id = self._default_authorize_door_id()
        self._set_actor_dispatch_context(
            users=list(users),
            local_fp_index=local_fp_index,
            default_door_id=default_door_id,
            sync_run_id=sync_run_id,
        )
        self.logger.info(
            "[DeviceSync] _sync_all_devices: total_devices=%d users=%d fp_index_pins=%d "
            "default_door_id=%s changed_ids=%s",
            len(device_mode_devices),
            len(users),
            len(local_fp_index),
            default_door_id,
            len(normalized_changed_ids) if normalized_changed_ids is not None else "all",
        )

        device_ids = {
            int(d.get("id"))
            for d in device_mode_devices
            if d.get("id") is not None
        }
        if normalized_changed_ids is None:
            dispatched = self._actor_registry.enqueue_full_reconcile(device_ids=device_ids)
        else:
            dispatched = self._actor_registry.enqueue_targeted_sync(
                device_ids=device_ids,
                member_ids=set(normalized_changed_ids),
            )
        self._set_progress(running=True, current=0, total=dispatched)
        self.logger.info(
            "[DeviceSync] dispatched actor sync to %d device workers (changed_ids=%s)",
            dispatched,
            len(normalized_changed_ids) if normalized_changed_ids is not None else "all",
        )

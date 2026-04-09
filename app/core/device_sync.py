# monclub_access_python/app/core/device_sync.py
from __future__ import annotations

import concurrent.futures
import hashlib
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple

from app.core.db import (
    list_fingerprints,
    list_device_sync_hashes,
    list_device_sync_hashes_and_status,
    save_device_sync_state,
    delete_device_sync_state,
    prune_device_sync_state,
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


class DeviceSyncEngine:
    """
    Synchronizes ZKTeco controllers (PullSDK) from cached backend payload.

    IMPORTANT CHANGE (Mar 2026):
    - accessDataMode is PER DEVICE.
    - This engine only syncs devices where accessDataMode == DEVICE.
    - Global defaults (default_authorize_door_id, sdk_read_initial_bytes, etc.) come from
      GymAccessSoftwareSettingsDto cached in SQLite, via settings_reader.get_backend_global_settings().
    """

    def __init__(self, *, cfg, logger):
        self.cfg = cfg
        self.logger = logger
        self._run_lock = threading.Lock()
        self._running = False
        self._progress_cond = threading.Condition()
        self._progress_seq = 0
        # Live progress readable by the status API (dict value assignments are
        # atomic under CPython GIL — safe across ThreadPoolExecutor workers).
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

    def run_blocking(self, *, cache, source: str = "timer",
                     changed_ids: set | None = None) -> bool:
        with self._run_lock:
            if self._running:
                self.logger.info(f"[DeviceSync] Skip ({source}): already running")
                return False
            self._running = True

        try:
            self._sync_all_devices(cache=cache, changed_ids=changed_ids)
            return True
        except Exception as e:
            self.logger.exception(f"[DeviceSync] Failed: {e}")
            return True
        finally:
            with self._run_lock:
                self._running = False

    # ---------------- internal ----------------

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

    def _resolve_push_context(
        self,
        *,
        device: Dict[str, Any],
        default_door_id: int,
    ) -> Tuple[List[int], int, int, bool]:
        authorize_timezone_id = _to_int(device.get("authorizeTimezoneId"), default=1) or 1
        if authorize_timezone_id < 1:
            authorize_timezone_id = 1

        fingerprint_enabled = _boolish(
            device.get("fingerprintEnabled") or device.get("fingerprint_enabled"),
            default=False,
        )

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

            # NEW (from backend/device DTO)
            "authorizeTimezoneId": int(tz_id),
            "pushingToDevicePolicy": pushing_policy,
            "doorPresets": list(g("doorPresets", "door_presets", default=None) or []),

            # Anti-fraud settings (per-device)
            "anti_fraude_card":     _boolish(g("anti_fraude_card",    "antiFraudeCard",    default=True), True),
            "anti_fraude_qr_code":  _boolish(g("anti_fraude_qr_code", "antiFraudeQrCode",  default=True), True),
            "anti_fraude_duration": _to_int(g("anti_fraude_duration", "antiFraudeDuration", default=30), default=30) or 30,
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
    ) -> None:
        dev_id = device.get("id")
        dev_name = device.get("name") or ""
        ip = (device.get("ipAddress") or "").strip()
        port = _to_int(device.get("portNumber"), default=4370) or 4370
        pwd = device.get("password") or ""

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
        if changed_ids is not None:
            pins_to_sync = {
                pin for pin in pins_to_sync
                if (
                    int(pin) in changed_ids          # changed per backend delta
                    or not prev_state.get(pin, ("", True))[0]   # no stored hash (new)
                    or not prev_state.get(pin, ("", True))[1]   # previous push failed
                )
            }

        _policy_str = str(device.get("pushingToDevicePolicy") or "ALL").strip().upper()
        self.logger.info(
            f"[DeviceSync] Device id={dev_id} name={dev_name!r} ip={ip}:{port} "
            f"desired={len(desired_pins)} to_sync={len(pins_to_sync)} "
            f"door_bitmask={door_bitmask} doorIds={door_ids} tz={authorize_timezone_id} policy={_policy_str}"
        )

        sdk = PullSDK(self.cfg.plcomm_dll_path, logger=self.logger)
        try:
            import time as _time
            t_connect = _time.time()
            self.logger.info(
                "[DeviceSync] Device id=%s name=%r connecting: ip=%s port=%s", dev_id, dev_name, ip, port
            )
            sdk.connect(
                ip=ip,
                port=int(port),
                timeout_ms=int(getattr(self.cfg, "timeout_ms", 5000) or 5000),
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
            stale_pins = sorted([p for p in device_pins if p in known_server_pins and p not in desired_pins])
            self.logger.info(
                "[DeviceSync] Device id=%s: device_pins=%d desired=%d to_sync=%d "
                "stale=%d drift_resynced=%d door_bitmask=%d",
                dev_id, len(device_pins), len(desired_pins), len(pins_to_sync),
                len(stale_pins),
                sum(1 for p in desired_pins if p not in device_pins and prev_hashes.get(p)),
                door_bitmask,
            )

            # ── Nuke-and-repave: when more users need deleting than keeping,
            #    it's faster to clear all tables and re-push desired users. ──
            nuke_mode = len(stale_pins) > len(desired_pins) and len(stale_pins) > 10
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
                # Pre-delete (only in non-nuke mode) to avoid rc=-101 on insert-only firmware
                if not nuke_mode:
                    for pin in pins_sorted:
                        self._delete_pin_if_exists(sdk=sdk, pin=pin, device_pins=device_pins)

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
                                pin = ""
                                card_valid = ""
                                for part in row.split("\t"):
                                    if part.startswith("Pin="):
                                        pin = part[4:]
                                    elif part.startswith("CardNo="):
                                        card_valid = part[7:]
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
                                    self.logger.warning(
                                        "[DeviceSync] Device id=%s Pin=%s force-delete retry FAILED: %s",
                                        dev_id, pin, ex)
                    elif failed_u and not use_name:
                        # Already using minimal fields but still failing — individual force-delete
                        for row in failed_u:
                            pin = ""
                            card_valid = ""
                            for part in row.split("\t"):
                                if part.startswith("Pin="):
                                    pin = part[4:]
                                elif part.startswith("CardNo="):
                                    card_valid = part[7:]
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

                # Phase D: Save device sync state for all pushed pins
                for pin in pins_sorted:
                    if desired.get(pin):
                        save_device_sync_state(
                            device_id=did, pin=pin,
                            desired_hash=desired_hashes.get(pin) or "",
                            ok=True, error=None,
                        )
                        ok_synced += 1
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

                    full_name = _safe_one_line(u.get("fullName") or "") or f"U{pin}"
                    card = _pin_str(u.get("firstCardId") or "")
                    templates = templates_for_sync.get(pin) or []

                    self.logger.debug(
                        "[DeviceSync] Device id=%s syncing Pin=%s name=%r card=%r templates=%d",
                        dev_id, pin, full_name, card, len(templates),
                    )

                    try:
                        self._delete_pin_if_exists(sdk=sdk, pin=pin, device_pins=device_pins)

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
                            ok_synced += 1
                        else:
                            save_device_sync_state(
                                device_id=did, pin=pin,
                                desired_hash=desired_hashes.get(pin) or "",
                                ok=False, error=auth_err or "authorize incomplete",
                            )
                            failed_synced += 1
                        self._set_progress(current=ok_synced + failed_synced)

                    except Exception as ex:
                        failed_synced += 1
                        self._set_progress(current=ok_synced + failed_synced)
                        save_device_sync_state(
                            device_id=did, pin=pin,
                            desired_hash=None, ok=False, error=str(ex),
                        )
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

            # [Anti-fraud] Push hardware anti-passback parameter to ZKTeco controller.
            # AntiPassback=1 + AntiPassbackTime enables card-level hardware dedup.
            # NOTE: Parameter names are for C3-200/C3-400 series; verify against
            # the PullSDK reference for other models. Failure is non-fatal — the
            # software AntiFraudGuard remains the primary enforcer in all modes.
            _af_card = bool(device.get("anti_fraude_card", True))
            _af_duration = int(device.get("anti_fraude_duration") or 30)
            _af_param = (
                f"AntiPassback=1&AntiPassbackTime={_af_duration}"
                if _af_card else "AntiPassback=0"
            )
            try:
                sdk.set_device_param(items=_af_param)
                self.logger.info(
                    "[DeviceSync] Device id=%s anti-passback param OK (%s)",
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

        finally:
            try:
                sdk.disconnect()
            except Exception:
                pass

    def _sync_all_devices(self, *, cache, changed_ids: set | None = None) -> None:
        if not cache:
            self.logger.info("[DeviceSync] No cache -> skip")
            return

        # Users are already normalized to payload-ish dicts by db.load_sync_cache()
        users = getattr(cache, "users", []) or []

        # Devices may be snake_case rows (from normalized table) OR camelCase (fallback payload)
        devices_raw = getattr(cache, "devices", []) or []
        devices = [self._normalize_device(d) for d in devices_raw if isinstance(d, dict)]

        local_fp_index: Dict[str, List[Any]] = {}
        try:
            recs = list_fingerprints()
            for r in recs:
                pin = _pin_str(getattr(r, "pin", "") or "")
                if not pin:
                    continue
                local_fp_index.setdefault(pin, []).append(r)
        except Exception:
            local_fp_index = {}

        if not devices:
            self.logger.info("[DeviceSync] No devices in cache -> skip")
            return

        default_door_id = self._default_authorize_door_id()
        self.logger.info(
            "[DeviceSync] _sync_all_devices: total_devices=%d users=%d fp_index_pins=%d "
            "default_door_id=%s changed_ids=%s",
            len(devices), len(users), len(local_fp_index), default_door_id,
            len(changed_ids) if changed_ids is not None else "all",
        )

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

        # F-008: Run device syncs in parallel (max_workers=4, safe bounded parallelism)
        self._set_progress(running=True)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                futures = {
                    executor.submit(
                        self._sync_one_device,
                        device=dev,
                        users=users,
                        local_fp_index=local_fp_index,
                        default_door_id=default_door_id,
                        changed_ids=changed_ids,
                    ): dev
                    for dev in device_mode_devices
                }
                for future in concurrent.futures.as_completed(futures):
                    dev = futures[future]
                    dev_id = dev.get("id")
                    dev_name = dev.get("name", "")
                    try:
                        future.result()
                        self.logger.info(
                            "[DeviceSync] device id=%s name=%r sync future completed OK", dev_id, dev_name
                        )
                    except PullSDKError as ex:
                        self.logger.warning(
                            "[DeviceSync] device id=%s name=%r sync FAILED (PullSDK): %s",
                            dev_id, dev_name, ex,
                        )
                    except Exception as e:
                        self.logger.error(
                            "[DeviceSync] device id=%s name=%r sync FAILED (unexpected): %s",
                            dev_id, dev_name, e,
                        )
        finally:
            self._set_progress(
                running=False,
                deviceName="",
                deviceId=None,
                current=0,
                total=0,
            )

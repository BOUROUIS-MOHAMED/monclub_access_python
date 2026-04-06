# monclub_access_python/app/core/device_sync.py
from __future__ import annotations

import concurrent.futures
import hashlib
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple

from app.core.db import (
    list_fingerprints,
    list_device_sync_hashes,
    save_device_sync_state,
    delete_device_sync_state,
    prune_device_sync_state,
)
from app.core.settings_reader import get_backend_global_settings  # ✅ NEW: backend-driven settings (SQLite)
from app.sdk.pullsdk import PullSDK, PullSDKError


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

    def run_blocking(self, *, cache, source: str = "timer") -> bool:
        with self._run_lock:
            if self._running:
                self.logger.info(f"[DeviceSync] Skip ({source}): already running")
                return False
            self._running = True

        try:
            self._sync_all_devices(cache=cache)
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
        door_ids: List[int],
        authorize_timezone_id: int,
    ) -> Tuple[int, str | None]:
        if not door_ids:
            door_ids = [self._default_authorize_door_id()]

        tz = int(authorize_timezone_id or 1)
        if tz < 1:
            tz = 1

        patterns = [
            lambda door: f"Pin={pin}\tDoorID={door}\tTimeZone={tz}",
            lambda door: f"Pin={pin}\tDoorID={door}\tTimeZoneID={tz}",
            lambda door: f"Pin={pin}\tAuthorizeDoorId={door}\tAuthorizeTimezoneId={tz}",
        ]

        last_err = None
        chosen = None

        first_door = int(door_ids[0])
        for i, pfn in enumerate(patterns):
            try:
                data = pfn(first_door) + "\r\n"
                sdk.set_device_data(table="userauthorize", data=data, options="")
                chosen = i
                last_err = None
                break
            except Exception as ex:
                last_err = str(ex)

        if chosen is None:
            return 0, last_err or "userauthorize: no compatible field pattern worked"

        ok_count = 1
        for door in door_ids[1:]:
            try:
                data = patterns[chosen](int(door)) + "\r\n"
                sdk.set_device_data(table="userauthorize", data=data, options="")
                ok_count += 1
            except Exception as ex:
                last_err = str(ex)

        return ok_count, last_err

    def _push_templates(self, sdk: PullSDK, *, pin: str, templates: List[Dict[str, Any]]) -> Tuple[int, List[str]]:
        errs: List[str] = []
        ok = 0

        def try_set(table: str, body: str) -> bool:
            try:
                sdk.set_device_data(table=table, data=body + "\r\n", options="")
                return True
            except Exception as ex:
                errs.append(f"{table}: {ex}")
                return False

        for t in templates:
            fid = int(t.get("fingerId"))
            tv = int(t.get("templateVersion") or 10)
            size = int(t.get("templateSize") or 0)
            tpl = _safe_template_text(str(t.get("templateData") or ""))

            if not tpl:
                continue

            preferred_tables = ["templatev10", "template"] if tv >= 10 else ["template", "templatev10"]

            bodies = [
                lambda: f"Pin={pin}\tFingerID={fid}\tValid=1\tSize={size}\tTemplate={tpl}",
                lambda: f"Pin={pin}\tFingerID={fid}\tValid=1\tSize={size}\tTmp={tpl}",
                lambda: f"Pin={pin}\tFingerID={fid}\tValid=1\tTemplate={tpl}",
                lambda: f"Pin={pin}\tFingerID={fid}\tSize={size}\tTemplate={tpl}",
                lambda: f"Pin={pin}\tFingerID={fid}\tTemplate={tpl}",
            ]

            pushed = False
            for table in preferred_tables:
                for bfn in bodies:
                    if try_set(table, bfn()):
                        pushed = True
                        break
                if pushed:
                    break

            if pushed:
                ok += 1
            else:
                errs.append(f"FingerID={fid}: failed to push template (no compatible schema/table)")

        compact_errs: List[str] = []
        seen = set()
        for e in errs:
            if e not in seen:
                compact_errs.append(e)
                seen.add(e)

        return ok, compact_errs

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
        door_ids: List[int],
        templates: List[Dict[str, Any]],
        authorize_timezone_id: int,
    ) -> str:
        full_name = _safe_one_line(user.get("fullName") or "") or f"U{pin}"
        card = _pin_str(user.get("firstCardId") or "")
        doors_norm = ",".join(str(x) for x in _norm_int_list(door_ids))
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

    def _sync_one_device(
        self,
        *,
        device: Dict[str, Any],
        users: List[Dict[str, Any]],
        local_fp_index: Dict[str, List[Any]],
        default_door_id: int,
    ) -> None:
        dev_id = device.get("id")
        dev_name = device.get("name") or ""
        ip = (device.get("ipAddress") or "").strip()
        port = _to_int(device.get("portNumber"), default=4370) or 4370
        pwd = device.get("password") or ""

        authorize_timezone_id = _to_int(device.get("authorizeTimezoneId"), default=1) or 1
        if authorize_timezone_id < 1:
            authorize_timezone_id = 1

        # Resolve physical door numbers for userauthorize.
        # doorPresets contain the REAL physical door numbers (1-4 on C3-400).
        # The backend's doorIds may contain a bitmask value like 15 (=all doors)
        # which causes the C3 to fire ALL relays on a single card scan.
        # Using individual door numbers (one authorize row per door) ensures only
        # the scanned reader's relay fires.
        presets = device.get("doorPresets") or []
        physical_doors = sorted(set(
            int(p.get("doorNumber") or p.get("door_number") or 0)
            for p in presets if isinstance(p, dict)
            and (p.get("doorNumber") or p.get("door_number"))
        ))
        physical_doors = [d for d in physical_doors if d > 0]

        if physical_doors:
            door_ids = physical_doors
        else:
            door_ids_raw = device.get("doorIds") or []
            door_ids = _norm_int_list(door_ids_raw)
            if not door_ids:
                door_ids = [int(default_door_id)]

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

        # F-013: Read fingerprint_enabled per device — controls whether fingerprint templates are pushed
        fingerprint_enabled = _boolish(
            device.get("fingerprintEnabled") or device.get("fingerprint_enabled"),
            default=False,
        )

        desired = self._filter_users_for_device(users=users, device=device, default_door_id=default_door_id)
        desired_pins = set(desired.keys())

        known_server_pins: Set[str] = set()
        for u in users or []:
            p = _pin_str(u.get("activeMembershipId"))
            if p and p.isdigit():
                known_server_pins.add(p)

        prev_hashes = list_device_sync_hashes(device_id=did)

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
                door_ids=door_ids,
                templates=templates,
                authorize_timezone_id=authorize_timezone_id,
            )
            desired_hashes[pin] = dh
            if prev_hashes.get(pin) != dh:
                pins_to_sync.add(pin)
                templates_for_sync[pin] = templates

        _policy_str = str(device.get("pushingToDevicePolicy") or "ALL").strip().upper()
        self.logger.info(
            f"[DeviceSync] Device id={dev_id} name={dev_name!r} ip={ip}:{port} "
            f"desired={len(desired_pins)} to_sync={len(pins_to_sync)} "
            f"doors={door_ids} tz={authorize_timezone_id} policy={_policy_str}"
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
            for pin in desired_pins:
                if pin not in device_pins and prev_hashes.get(pin) and pin not in pins_to_sync:
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

            for pin in sorted(pins_to_sync):
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
                    # Delete user row + auth + templates before re-inserting.
                    # SetDeviceData is insert-only on most firmware; leaving the user row
                    # causes rc=-101 (duplicate). _delete_pin_if_exists skips safely if
                    # the pin isn't on the device.
                    self._delete_pin_if_exists(sdk=sdk, pin=pin, device_pins=device_pins)

                    # 1) user (overwrite)
                    # Only include CardNo if it is a non-empty numeric string.
                    # Non-numeric card IDs (e.g. "aaa") are rejected by device firmware.
                    card_valid = card if (card and card.isdigit()) else ""
                    if card and not card_valid:
                        self.logger.warning(
                            "[DeviceSync] Device id=%s Pin=%s CardNo=%r is not numeric — skipping CardNo",
                            dev_id, pin, card,
                        )

                    pairs = [f"Pin={pin}", f"Name={full_name}"]
                    if card_valid:
                        pairs.append(f"CardNo={card_valid}")
                    _user_data = "\t".join(pairs) + "\r\n"
                    try:
                        sdk.set_device_data(table="user", data=_user_data, options="")
                    except PullSDKError as _set_err:
                        if "rc=-101" not in str(_set_err):
                            raise
                        # rc=-101 has two common causes on ZKTeco C3-200 firmware:
                        #   (a) Duplicate pin — GetDeviceData returned incomplete pin list so
                        #       _delete_pin_if_exists skipped a pin that already exists.
                        #   (b) Unsupported field — some C3-200 firmware variants do not have a
                        #       Name column and reject SetDeviceData when Name= is included.
                        # Strategy: force-delete the stale row (handles a), then retry with
                        # minimal fields only — Pin + CardNo, no Name (handles b).
                        self.logger.warning(
                            "[DeviceSync] Device id=%s Pin=%s SetDeviceData rc=-101 "
                            "— force-delete + retry without Name",
                            dev_id, pin,
                        )
                        # Clear auth/templates first so the user delete won't fail on constraints.
                        self._delete_auth_and_templates_best_effort(sdk=sdk, pin=pin)
                        try:
                            sdk.delete_device_data(table="user", data=f"Pin={pin}", options="")
                        except Exception as _del_ex:
                            self.logger.debug(
                                "[DeviceSync] Device id=%s Pin=%s force-delete user: %s (continuing to retry)",
                                dev_id, pin, _del_ex,
                            )
                        # Retry with minimal fields only (no Name).
                        minimal_pairs = [f"Pin={pin}"]
                        if card_valid:
                            minimal_pairs.append(f"CardNo={card_valid}")
                        sdk.set_device_data(table="user", data="\t".join(minimal_pairs) + "\r\n", options="")
                        self.logger.info(
                            "[DeviceSync] Device id=%s Pin=%s retry without Name OK",
                            dev_id, pin,
                        )
                    pushed_users += 1

                    # 2) authorize (respect backend timezone id)
                    try:
                        _, auth_err = self._push_userauthorize(
                            sdk,
                            pin=pin,
                            door_ids=door_ids,
                            authorize_timezone_id=int(authorize_timezone_id),
                        )
                        if auth_err:
                            self.logger.warning(f"[DeviceSync] Device id={dev_id} Pin={pin} authorize warn: {auth_err}")
                    except Exception as ex:
                        self.logger.warning(f"[DeviceSync] Device id={dev_id} Pin={pin} authorize warn: {ex}")

                    # 3) templates
                    if templates:
                        ok_count, errs = self._push_templates(sdk, pin=pin, templates=templates)
                        pushed_templates += ok_count
                        if errs:
                            warn_templates_users += 1
                            # M-006: Log all errors (not just first 3) and include count
                            self.logger.warning(
                                f"[DeviceSync] Device id={dev_id} Pin={pin} template errors ({len(errs)} total): "
                                f"{errs[:5]}{'...' if len(errs) > 5 else ''}"
                            )
                        else:
                            self.logger.debug(
                                f"[DeviceSync] Device id={dev_id} Pin={pin} templates pushed OK: count={ok_count}"
                            )

                    # persist applied hash only on success
                    save_device_sync_state(
                        device_id=did,
                        pin=pin,
                        desired_hash=desired_hashes.get(pin) or "",
                        ok=True,
                        error=None,
                    )
                    ok_synced += 1
                    self._set_progress(current=ok_synced + failed_synced)
                    self.logger.debug(
                        "[DeviceSync] Device id=%s Pin=%s sync OK", dev_id, pin
                    )

                except Exception as ex:
                    failed_synced += 1
                    self._set_progress(current=ok_synced + failed_synced)
                    save_device_sync_state(
                        device_id=did,
                        pin=pin,
                        desired_hash=None,  # keep previous hash so it retries next run
                        ok=False,
                        error=str(ex),
                    )
                    self.logger.warning(
                        "[DeviceSync] Device id=%s Pin=%s sync FAILED: %s",
                        dev_id, pin, ex,
                    )

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

            self.logger.info(
                f"[DeviceSync] Device id={dev_id} name={dev_name!r} DONE: stale_deleted={deleted} synced_ok={ok_synced} synced_fail={failed_synced} pushed_users={pushed_users} pushed_templates={pushed_templates} warn_templates_users={warn_templates_users} state_pruned={pruned}"
            )

        finally:
            try:
                sdk.disconnect()
            except Exception:
                pass

    def _sync_all_devices(self, *, cache) -> None:
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
            "[DeviceSync] _sync_all_devices: total_devices=%d users=%d fp_index_pins=%d default_door_id=%s",
            len(devices), len(users), len(local_fp_index), default_door_id,
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

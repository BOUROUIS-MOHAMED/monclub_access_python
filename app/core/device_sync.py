# monclub_access_python/app/core/device_sync.py
from __future__ import annotations

import hashlib
import threading
from datetime import datetime
from typing import Any, Dict, List, Set, Tuple

from app.core.db import (
    list_fingerprints,
    list_device_sync_hashes,
    save_device_sync_state,
    delete_device_sync_state,
    prune_device_sync_state,
)
from app.sdk.pullsdk import PullSDK, PullSDKError

# Fallback if a device has no doorIds configured
DEFAULT_AUTHORIZE_DOOR_ID = 15


def _parse_dt_any(s: str) -> datetime | None:
    if not s:
        return None
    s = str(s).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1]
    try:
        return datetime.fromisoformat(s)
    except Exception:
        pass
    try:
        if len(s) == 10 and s[4] == "-" and s[7] == "-":
            return datetime.fromisoformat(s + "T00:00:00")
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
        out.append(int(xi))
    out = sorted(set(out))
    return out


class DeviceSyncEngine:
    """
    Synchronizes ZKTeco controllers (PullSDK) from cached backend payload.

    Incremental rules:
    - Compute a per-device+pin desired_hash based on what we actually write (user+authorize+templates).
    - Compare with last applied desired_hash stored in SQLite.
    - Only touch pins whose desired_hash changed or is new.
    - Stale pins removal stays "safe": delete only pins that are known-from-server but no longer desired for this device.
    """

    def __init__(self, *, cfg, logger):
        self.cfg = cfg
        self.logger = logger
        self._run_lock = threading.Lock()
        self._running = False

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
        if adm not in ("DEVICE", "AGENT"):
            adm = "DEVICE"

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
        }

    def _filter_users_for_device(self, *, users: List[Dict[str, Any]], device: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """
        Returns dict(pin -> user).
        Filters:
        - allowedMemberships (if provided) uses user.membershipId
        - validFrom/validTo (if provided)
        - pin must be digits (controllers expect numeric Pin)
        """
        allowed_raw = device.get("allowedMemberships") or []
        allowed_set: Set[int] = set()
        for x in allowed_raw:
            xi = _to_int(x, default=None)
            if xi is not None:
                allowed_set.add(int(xi))

        door_ids = device.get("doorIds") or []
        if not door_ids:
            door_ids = [DEFAULT_AUTHORIZE_DOOR_ID]
        device["doorIds"] = door_ids

        now = datetime.now()
        out: Dict[str, Dict[str, Any]] = {}

        for u in users or []:
            if not isinstance(u, dict):
                continue

            pin = _pin_str(u.get("activeMembershipId"))
            if not pin:
                continue

            if not pin.isdigit():
                continue

            mid = _to_int(u.get("membershipId"), default=None)
            if allowed_set and (mid is None or int(mid) not in allowed_set):
                continue

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
    ) -> List[Dict[str, Any]]:
        """
        Priority:
          1) user['fingerprints'] from cache
          2) local SQLite fingerprints table (newest per finger_id)
        Output items:
          { fingerId:int, templateVersion:int, templateData:str, templateSize:int }
        """
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
                tv_i = int(getattr(r, "template_version"))
            except Exception:
                tv_i = 10
            try:
                ts_i = int(getattr(r, "template_size"))
            except Exception:
                ts_i = len(td)
            best_local[fid_i] = {
                "fingerId": fid_i,
                "templateVersion": tv_i,
                "templateData": td,
                "templateSize": ts_i,
            }

        return [best_local[k] for k in sorted(best_local.keys())]

    def _push_userauthorize(self, sdk: PullSDK, *, pin: str, door_ids: List[int]) -> Tuple[int, str | None]:
        if not door_ids:
            door_ids = [DEFAULT_AUTHORIZE_DOOR_ID]

        patterns = [
            lambda door: f"Pin={pin}\tDoorID={door}\tTimeZone=1",
            lambda door: f"Pin={pin}\tDoorID={door}\tTimeZoneID=1",
            lambda door: f"Pin={pin}\tAuthorizeDoorId={door}\tAuthorizeTimezoneId=1",
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

        sdk.delete_device_data(table="user", data=cond, options="")
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
    ) -> str:
        full_name = _safe_one_line(user.get("fullName") or "") or f"U{pin}"
        card = _pin_str(user.get("firstCardId") or "")
        doors_norm = ",".join(str(x) for x in _norm_int_list(door_ids))

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

        payload = f"pin={pin}\nname={full_name}\ncard={card}\ndoors={doors_norm}\ntemplates={tpl_blob}\n"
        return _sha1_hex(payload)

    def _sync_one_device(
        self,
        *,
        device: Dict[str, Any],
        users: List[Dict[str, Any]],
        local_fp_index: Dict[str, List[Any]],
    ) -> None:
        dev_id = device.get("id")
        dev_name = device.get("name") or ""
        ip = (device.get("ipAddress") or "").strip()
        port = _to_int(device.get("portNumber"), default=4370) or 4370
        pwd = device.get("password") or ""

        door_ids_raw = device.get("doorIds") or []
        door_ids = _norm_int_list(door_ids_raw)
        if not door_ids:
            door_ids = [DEFAULT_AUTHORIZE_DOOR_ID]

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

        desired = self._filter_users_for_device(users=users, device=device)
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
            templates = self._collect_templates_for_pin(user=u, pin=pin, local_fp_index=local_fp_index)
            dh = self._compute_desired_hash(pin=pin, user=u, door_ids=door_ids, templates=templates)
            desired_hashes[pin] = dh
            if prev_hashes.get(pin) != dh:
                pins_to_sync.add(pin)
                templates_for_sync[pin] = templates

        self.logger.info(
            f"[DeviceSync] Device id={dev_id} name={dev_name!r} ip={ip}:{port} desired={len(desired_pins)} to_sync={len(pins_to_sync)} doors={door_ids}"
        )

        sdk = PullSDK(self.cfg.plcomm_dll_path, logger=self.logger)
        try:
            sdk.connect(
                ip=ip,
                port=int(port),
                timeout_ms=int(getattr(self.cfg, "timeout_ms", 5000) or 5000),
                password=str(pwd),
            )

            rows = sdk.get_device_data_rows(
                table="user",
                fields="Pin",
                filter_expr="",
                options="",
                initial_size=1_048_576,
            )
            device_pins: Set[str] = set()
            for r in rows:
                p = _pin_str(r.get("Pin") or r.get("pin") or "")
                if p:
                    device_pins.add(p)

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

            for pin in sorted(pins_to_sync):
                u = desired.get(pin)
                if not isinstance(u, dict):
                    continue

                full_name = _safe_one_line(u.get("fullName") or "") or f"U{pin}"
                card = _pin_str(u.get("firstCardId") or "")
                templates = templates_for_sync.get(pin) or []

                try:
                    # reduce lockout window: do NOT delete user row for refresh
                    self._delete_auth_and_templates_best_effort(sdk=sdk, pin=pin)

                    # 1) user (overwrite)
                    pairs = [f"Pin={pin}", f"Name={full_name}"]
                    if card:
                        pairs.append(f"CardNo={card}")
                    sdk.set_device_data(table="user", data="\t".join(pairs) + "\r\n", options="")
                    pushed_users += 1

                    # 2) authorize
                    try:
                        _, auth_err = self._push_userauthorize(sdk, pin=pin, door_ids=door_ids)
                        if auth_err:
                            self.logger.debug(f"[DeviceSync] Pin={pin} authorize warn: {auth_err}")
                    except Exception as ex:
                        self.logger.debug(f"[DeviceSync] Pin={pin} authorize warn: {ex}")

                    # 3) templates
                    if templates:
                        ok_count, errs = self._push_templates(sdk, pin=pin, templates=templates)
                        pushed_templates += ok_count
                        if errs:
                            warn_templates_users += 1
                            self.logger.debug(f"[DeviceSync] Pin={pin} template warnings: {errs[:3]}")

                    # persist applied hash only on success
                    save_device_sync_state(
                        device_id=did,
                        pin=pin,
                        desired_hash=desired_hashes.get(pin) or "",
                        ok=True,
                        error=None,
                    )
                    ok_synced += 1

                except Exception as ex:
                    failed_synced += 1
                    save_device_sync_state(
                        device_id=did,
                        pin=pin,
                        desired_hash=None,  # keep previous hash so it retries next run
                        ok=False,
                        error=str(ex),
                    )
                    self.logger.warning(f"[DeviceSync] Pin={pin} sync failed: {ex}")

            pruned = prune_device_sync_state(device_id=did, keep_pins=desired_pins)

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

        users = getattr(cache, "users", []) or []
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

        for d in devices:
            if not _boolish(d.get("active"), default=True):
                continue
            if not _boolish(d.get("accessDevice"), default=True):
                continue
            # Only sync DEVICE-mode devices; AGENT-mode devices are handled by AgentRealtimeEngine
            if d.get("accessDataMode", "DEVICE") != "DEVICE":
                self.logger.debug(f"[DeviceSync] Skip device id={d.get('id')} name={d.get('name')!r}: accessDataMode={d.get('accessDataMode')}")
                continue
            try:
                self._sync_one_device(device=d, users=users, local_fp_index=local_fp_index)
            except PullSDKError as ex:
                self.logger.warning(f"[DeviceSync] Device id={d.get('id')} sync failed (PullSDK): {ex}")
            except Exception as ex:
                self.logger.exception(f"[DeviceSync] Device id={d.get('id')} sync failed: {ex}")

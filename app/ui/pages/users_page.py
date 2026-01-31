# monclub_access_python/app/ui/pages/users_page.py
from __future__ import annotations

import threading
import tkinter as tk
from tkinter import ttk, messagebox

from app.core.db import list_fingerprints, get_fingerprint, load_sync_cache
from app.core.utils import safe_int, from_b64, from_hex
from app.sdk.pullsdk import PullSDK, PullSDKError


def build_tab_kv(pairs: list[tuple[str, str]]) -> str:
    return "\t".join([f"{k}={v}" for k, v in pairs])


class UsersPage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.sdk: PullSDK | None = None
        self._connected_to: str = ""  # display label of selected device

        # cached devices selector
        self._device_display_to_obj: dict[str, dict] = {}
        self.var_target_device = tk.StringVar(value="")

        # Top connect
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=10)

        # Device picker (from saved devices in sync cache)
        ttk.Label(top, text="Target device:").pack(side="left")
        self.cmb_target_device = ttk.Combobox(
            top,
            textvariable=self.var_target_device,
            width=52,
            state="readonly",
        )
        self.cmb_target_device.pack(side="left", padx=(8, 10))
        self.cmb_target_device["values"] = []
        self.cmb_target_device.bind("<<ComboboxSelected>>", self._on_target_device_changed)

        ttk.Button(top, text="Reload devices", command=self.reload_devices).pack(side="left", padx=(0, 12))

        ttk.Button(top, text="Connect", command=self.connect).pack(side="left", padx=(0, 8))
        ttk.Button(top, text="Disconnect", command=self.disconnect).pack(side="left", padx=(0, 8))

        self.lbl = ttk.Label(top, text="Not connected.")
        self.lbl.pack(side="left", padx=12)

        # Form
        form = ttk.LabelFrame(self, text="Add / update user (Card + optional Fingerprint)")
        form.pack(fill="x", padx=10, pady=10)

        self.var_card = tk.StringVar()
        self.var_pin = tk.StringVar()
        self.var_name = tk.StringVar()
        self.var_group = tk.StringVar(value="0")
        self.var_pass = tk.StringVar()
        self.var_super = tk.StringVar(value="0")
        self.var_start = tk.StringVar(value="")
        self.var_end = tk.StringVar(value="")

        self.var_tz = tk.StringVar(value="1")
        self.var_door = tk.StringVar(value="15")

        r = 0
        r = self._row(form, r, "CardNo (decimal):", self.var_card)
        r = self._row(form, r, "Pin / UserID (<= 8 digits) (ENTER = derived from CardNo):", self.var_pin)
        r = self._row(form, r, "Name (no commas):", self.var_name)
        r = self._row(form, r, "Group (default 0):", self.var_group)
        r = self._row(form, r, "Password (optional):", self.var_pass, show="*")
        r = self._row(form, r, "SuperAuthorize (0/1):", self.var_super)
        r = self._row(form, r, "StartTime (yyyyMMdd) blank=auto:", self.var_start)
        r = self._row(form, r, "EndTime (yyyyMMdd) blank=auto:", self.var_end)
        r = self._row(form, r, "AuthorizeTimezoneId (default 1):", self.var_tz)
        r = self._row(form, r, "AuthorizeDoorId (default 15):", self.var_door)

        # Fingerprint picker
        fp_box = ttk.Frame(form)
        fp_box.grid(row=r, column=0, columnspan=3, sticky="ew", padx=10, pady=(6, 10))
        ttk.Label(fp_box, text="Fingerprint from local DB (optional):").pack(side="left")
        self.var_fp = tk.StringVar(value="")
        self.fp_combo = ttk.Combobox(fp_box, textvariable=self.var_fp, values=[], width=70, state="readonly")
        self.fp_combo.pack(side="left", padx=10)
        ttk.Button(fp_box, text="Refresh", command=self.refresh_fp_list).pack(side="left")

        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=10, pady=6)

        ttk.Button(btns, text="Push user (Card + Authorize)", command=self.push_user_card_only).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(btns, text="Push user + Fingerprint", command=self.push_user_with_fingerprint).pack(
            side="left", padx=(0, 8)
        )

        self.refresh_fp_list()
        self.reload_devices()

    # ---------------- device selector ----------------

    def _device_display(self, d: dict) -> str:
        def _get(obj, *names, default=None):
            if obj is None:
                return default
            if isinstance(obj, dict):
                for n in names:
                    if n in obj:
                        return obj.get(n)
                return default
            for n in names:
                if hasattr(obj, n):
                    return getattr(obj, n)
            return default

        name = str(_get(d, "deviceName", "name", "DeviceName", default="") or "").strip()
        platform = str(_get(d, "platform", "Platform", default="") or "").strip()

        ip = str(_get(d, "ip", "ipAddress", "IPAddress", "ip_address", "deviceIp", "host", default="") or "").strip()
        port = str(_get(d, "port", "Port", "tcpPort", "devicePort", default="") or "").strip()

        left = name or platform or "device"
        mid = platform if platform and platform.lower() not in (left or "").lower() else ""
        addr = ""
        if ip:
            addr = ip + (f":{port}" if port else "")
        parts = [p for p in [left, mid, addr] if p]
        return " | ".join(parts) if parts else str(d)

    def _select_best_device_display(self, values: list[str]) -> str:
        cur = (self.var_target_device.get() or "").strip()
        if cur and cur in values:
            return cur

        # Prefer your common test device markers if present
        for v in values:
            vv = v.lower()
            if "asp 460" in vv or "zem560_inbio" in vv:
                return v

        return values[0] if values else ""

    def reload_devices(self):
        cache = load_sync_cache()
        devs = []
        if cache:
            # best-effort: cache can be dict or object
            if isinstance(cache, dict):
                devs = cache.get("devices") or []
            else:
                devs = getattr(cache, "devices", []) or []

        values: list[str] = []
        mapping: dict[str, dict] = {}

        if isinstance(devs, list):
            for d in devs:
                if not isinstance(d, dict):
                    try:
                        d = dict(d.__dict__)
                    except Exception:
                        continue
                disp = self._device_display(d)
                if not disp:
                    continue
                if disp in mapping:
                    continue
                values.append(disp)
                mapping[disp] = d

        self._device_display_to_obj = mapping
        self.cmb_target_device["values"] = values
        chosen = self._select_best_device_display(values)
        self.var_target_device.set(chosen)

    def _get_selected_device(self) -> dict | None:
        key = (self.var_target_device.get() or "").strip()
        if not key:
            return None
        return self._device_display_to_obj.get(key)

    def _parse_int(self, v, default: int) -> int:
        try:
            return int(str(v).strip())
        except Exception:
            return default

    def _resolve_target_conn(self) -> tuple[str, int, int, str, str]:
        """
        Returns (ip, port, timeout_ms, password, label)
        Falls back to app.cfg if device info is missing.
        """
        d = self._get_selected_device()

        ip = str(getattr(self.app.cfg, "ip", "") or "").strip()
        port = self._parse_int(getattr(self.app.cfg, "port", 0) or 0, 0)
        timeout_ms = self._parse_int(getattr(self.app.cfg, "timeout_ms", 3000) or 3000, 3000)
        password = str(getattr(self.app.cfg, "password", "") or "")
        label = "(config device)"

        if d:
            label = self._device_display(d)

            ip2 = d.get("ip") or d.get("ipAddress") or d.get("IPAddress") or d.get("ip_address") or d.get("host")
            if ip2:
                ip = str(ip2).strip()

            port2 = d.get("port") or d.get("Port") or d.get("tcpPort") or d.get("devicePort")
            if port2 is not None and str(port2).strip() != "":
                port = self._parse_int(port2, port)

            pw2 = d.get("commPassword") or d.get("CommPassword") or d.get("password") or d.get("passwd") or d.get("Passwd")
            if pw2 is not None and str(pw2).strip() != "":
                password = str(pw2)

            t2 = d.get("timeoutMs") or d.get("timeout_ms") or d.get("timeout")
            if t2 is not None and str(t2).strip() != "":
                timeout_ms = self._parse_int(t2, timeout_ms)

        return ip, port, timeout_ms, password, label

    def _require_device_selected_or_warn(self) -> bool:
        if self.cmb_target_device["values"]:
            if not self._get_selected_device():
                messagebox.showwarning("Device", "Please select a device from the saved devices list.")
                return False
        return True

    def _on_target_device_changed(self, _evt=None):
        # If already connected, disconnect (avoid pushing to wrong device by accident)
        try:
            if self.sdk:
                self.disconnect()
        except Exception:
            pass

    # ---------------- UI helpers ----------------

    def _row(self, parent, row, label, var, show=None):
        parent.columnconfigure(1, weight=1)
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=10, pady=3)
        e = ttk.Entry(parent, textvariable=var, show=show)
        e.grid(row=row, column=1, sticky="ew", padx=10, pady=3)
        return row + 1

    # ---------------- connect/disconnect ----------------

    def connect(self):
        if not self._require_device_selected_or_warn():
            return

        try:
            ip, port, timeout_ms, password, label = self._resolve_target_conn()

            self.sdk = PullSDK(self.app.cfg.plcomm_dll_path, logger=self.app.logger)
            self.sdk.connect(
                ip=ip,
                port=port,
                timeout_ms=timeout_ms,
                password=password,
            )
            self._connected_to = label
            self.lbl.config(text=f"Connected to {label} ({ip}:{port})")
        except Exception as e:
            messagebox.showerror("Connect failed", str(e))
            self.app.logger.exception("Connect failed")

    def disconnect(self):
        try:
            if self.sdk:
                self.sdk.disconnect()
            self.sdk = None
            self._connected_to = ""
            self.lbl.config(text="Disconnected.")
        except Exception as e:
            messagebox.showerror("Disconnect failed", str(e))

    # ---------------- fingerprints ----------------

    def refresh_fp_list(self):
        fps = list_fingerprints()
        values = [
            f"#{f.id} | {f.created_at} | pin={f.pin} | card={f.card_no} | finger={f.finger_id} | v{f.template_version} | {f.label}"
            for f in fps
        ]
        self.fp_combo["values"] = values
        if values and not self.var_fp.get():
            self.var_fp.set(values[0])

    def _require_sdk(self) -> PullSDK:
        if not self.sdk:
            raise RuntimeError("Connect to controller first.")
        return self.sdk

    # ---------------- business logic ----------------

    @staticmethod
    def _derive_pin_8_from_card(cardno: str) -> str:
        """
        Derive a pin (<= 8 digits) from CardNo:
        - if <= 8 digits => use as-is
        - if > 8 digits => last 8 digits
        """
        c = (cardno or "").strip()
        if not c.isdigit():
            raise ValueError("CardNo must be numeric.")
        if len(c) <= 8:
            return c
        return c[-8:]

    def _normalize_pin_8(self, pin_raw: str, cardno: str) -> str:
        p = (pin_raw or "").strip()

        # If user entered a pin: must be numeric and <= 8 digits
        if p:
            if not p.isdigit():
                raise ValueError("Pin must be numeric (<= 8 digits).")
            if len(p) > 8:
                raise ValueError("Pin must be <= 8 digits.")
            return p

        # If empty: derive from CardNo
        pin = self._derive_pin_8_from_card(cardno)
        self.app.logger.info(f"Pin was empty -> derived Pin={pin} from CardNo={cardno}")
        return pin

    def _normalize_inputs(self):
        card = self.var_card.get().strip()
        if not card.isdigit():
            raise ValueError("CardNo must be numeric.")

        pin = self._normalize_pin_8(self.var_pin.get(), card)

        name = (self.var_name.get().strip() or "").replace(",", " ")
        group = safe_int(self.var_group.get().strip(), 0)
        password = self.var_pass.get()
        super_auth = 1 if self.var_super.get().strip() == "1" else 0

        # Auto start/end like your script
        import datetime as dt

        today = dt.datetime.now()
        start = self.var_start.get().strip() or (today - dt.timedelta(days=1)).strftime("%Y%m%d")
        end = self.var_end.get().strip() or (today + dt.timedelta(days=7)).strftime("%Y%m%d")

        tz = safe_int(self.var_tz.get().strip(), 1)
        if tz <= 0:
            tz = 1
        door = safe_int(self.var_door.get().strip(), 15)
        if door < 0:
            door = 15

        return card, pin, name, group, password, super_auth, start, end, tz, door

    def _find_all_pins_by_cardno(self, sdk: PullSDK, cardno: str) -> list[str]:
        # Mimic your PowerShell: read full user table and find matching CardNo, then update all pins.
        rows = sdk.get_device_data_rows(table="user", fields="*", filter_expr="", options="")
        pins = []
        for r in rows:
            c = (r.get("CardNo") or r.get("cardno") or "").strip()
            if c == cardno:
                p = (r.get("Pin") or r.get("pin") or "").strip()
                if p and p not in pins:
                    pins.append(p)
        return pins

    def push_user_card_only(self):
        self._push(with_fingerprint=False)

    def push_user_with_fingerprint(self):
        self._push(with_fingerprint=True)

    def _push(self, with_fingerprint: bool):
        try:
            sdk = self._require_sdk()
            card, pin_input, name, group, password, super_auth, start, end, tz, door = self._normalize_inputs()
        except Exception as e:
            messagebox.showerror("Invalid input", str(e))
            return

        fp_id = None
        fp_rec = None
        if with_fingerprint:
            # parse selected fingerprint ID from string like "#12 | ..."
            sel = self.var_fp.get().strip()
            if not sel.startswith("#"):
                messagebox.showerror("Fingerprint", "Select a fingerprint from DB first (or refresh list).")
                return
            try:
                fp_id = int(sel.split("|")[0].replace("#", "").strip())
                fp_rec = get_fingerprint(fp_id)
                if not fp_rec:
                    raise ValueError("Fingerprint record not found.")
            except Exception as e:
                messagebox.showerror("Fingerprint", str(e))
                return

        def work():
            try:
                # Determine target pins: update all pins that share CardNo; else create new
                pins = self._find_all_pins_by_cardno(sdk, card)
                if not pins:
                    pins = [pin_input]
                    self.app.logger.info(f"No existing CardNo={card} found. Will create Pin={pin_input}")
                else:
                    self.app.logger.info(f"Found CardNo={card} existing pins={pins}. Will update all.")

                # upsert user + authorize
                for pin in pins:
                    user_pairs = [
                        ("CardNo", card),
                        ("Pin", pin),
                        ("Password", password),
                        ("Group", str(group)),
                        ("StartTime", start),
                        ("EndTime", end),
                        ("SuperAuthorize", str(super_auth)),
                    ]
                    if name:
                        user_pairs.append(("Name", name))
                    sdk.set_device_data(table="user", data=build_tab_kv(user_pairs))

                for pin in pins:
                    auth_pairs = [
                        ("Pin", pin),
                        ("AuthorizeTimezoneId", str(tz)),
                        ("AuthorizeDoorId", str(door)),
                    ]
                    sdk.set_device_data(table="userauthorize", data=build_tab_kv(auth_pairs))

                # optional fingerprint push
                if with_fingerprint and fp_rec:
                    self._push_fingerprint_templates(sdk, pins, fp_rec)

                self.app.logger.info("Push finished OK.")
                self.after(0, lambda: messagebox.showinfo("Success", "User pushed successfully."))
            except Exception as e:
                self.app.logger.exception("Push failed")
                self.after(0, lambda: messagebox.showerror("Push failed", str(e)))

        threading.Thread(target=work, daemon=True).start()

    def _push_fingerprint_templates(self, sdk: PullSDK, pins: list[str], fp_rec):
        """
        Push fingerprint to panel.
        IMPORTANT: You must confirm the panel expects base64/hex in Template field
        by reading back an enrolled template from the same panel first.
        """
        # Decode template from DB record
        if fp_rec.template_encoding == "hex":
            tpl_bytes = from_hex(fp_rec.template_data)
            tpl_text = fp_rec.template_data  # already hex string
        else:
            tpl_bytes = from_b64(fp_rec.template_data)
            tpl_text = fp_rec.template_data  # base64 string

        size = len(tpl_bytes)

        # Choose table
        if self.app.cfg.template_version == 10:
            table = "templatev10"
        else:
            # Many devices use "template" for older engines; adjust if your panel uses another table
            table = "template"

        for pin in pins:
            pairs = [
                ("Size", str(size)),
                ("UID", "0"),
                ("Pin", str(pin)),
                ("FingerID", str(fp_rec.finger_id)),
                ("Valid", "1"),
                ("Template", tpl_text),
                ("Resverd", "0"),
                ("EndTag", "1"),
            ]
            sdk.set_device_data(table=table, data=build_tab_kv(pairs))

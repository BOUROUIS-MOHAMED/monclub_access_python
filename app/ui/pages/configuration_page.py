from __future__ import annotations

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Dict, List, Optional, Tuple

from app.core.db import list_sync_devices, get_sync_device
from app.sdk.pullsdk import PullSDK
from app.sdk.zkfinger import ZKFinger


def _safe_int(s: str, default: int) -> int:
    try:
        x = int(str(s).strip())
        return x
    except Exception:
        return default


class ConfigurationPage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        self.columnconfigure(1, weight=1)

        self._devices: List[Dict] = []
        self._device_display_to_id: Dict[str, int] = {}

        r = 0

        # -------------------------
        # NEW: Select device from MonClub sync list
        # -------------------------
        ttk.Label(self, text="Select device from MonClub (last sync)", font=("Segoe UI", 12, "bold")).grid(
            row=r, column=0, sticky="w", padx=10, pady=(10, 5), columnspan=3
        )
        r += 1

        self.var_selected_device = tk.StringVar(value="")
        ttk.Label(self, text="Device:").grid(row=r, column=0, sticky="w", padx=10, pady=4)

        self.cmb_devices = ttk.Combobox(self, textvariable=self.var_selected_device, values=[], state="readonly")
        self.cmb_devices.grid(row=r, column=1, sticky="ew", padx=10, pady=4)
        self.cmb_devices.bind("<<ComboboxSelected>>", lambda _e: self.on_apply_selected_device())

        tools = ttk.Frame(self)
        tools.grid(row=r, column=2, sticky="w", padx=10, pady=4)
        ttk.Button(tools, text="Reload devices", command=self.reload_devices).pack(side="left", padx=(0, 8))
        ttk.Button(tools, text="Apply", command=self.on_apply_selected_device).pack(side="left", padx=(0, 0))
        r += 1

        self.lbl_devices_hint = ttk.Label(self, text="Devices: 0 (sync first to load devices list)", foreground="#444")
        self.lbl_devices_hint.grid(row=r, column=0, columnspan=3, sticky="w", padx=10, pady=(0, 10))
        r += 1

        # -------------------------
        # Controller fields
        # -------------------------
        ttk.Label(self, text="Controller connection (active device)", font=("Segoe UI", 12, "bold")).grid(
            row=r, column=0, sticky="w", padx=10, pady=(10, 5), columnspan=3
        )
        r += 1

        self.var_ip = tk.StringVar(value=self.app.cfg.ip)
        self.var_port = tk.StringVar(value=str(self.app.cfg.port))
        self.var_timeout = tk.StringVar(value=str(self.app.cfg.timeout_ms))
        self.var_passwd = tk.StringVar(value=self.app.cfg.password)

        r = self._row_entry(r, "IP address:", self.var_ip)
        r = self._row_entry(r, "Port:", self.var_port)
        r = self._row_entry(r, "Timeout (ms):", self.var_timeout)
        r = self._row_entry(r, "Comm password:", self.var_passwd, show="*")

        # -------------------------
        # Fingerprint template settings
        # -------------------------
        ttk.Label(self, text="Fingerprint template settings", font=("Segoe UI", 12, "bold")).grid(
            row=r, column=0, sticky="w", padx=10, pady=(16, 5), columnspan=3
        )
        r += 1

        self.var_tpl_ver = tk.StringVar(value=str(self.app.cfg.template_version))
        self.var_tpl_enc = tk.StringVar(value=self.app.cfg.template_encoding)

        ttk.Label(self, text="Template version (9/10):").grid(row=r, column=0, sticky="w", padx=10, pady=4)
        ttk.Combobox(self, textvariable=self.var_tpl_ver, values=["9", "10"], width=10, state="readonly").grid(
            row=r, column=1, sticky="w", padx=10, pady=4
        )
        r += 1

        ttk.Label(self, text="Template encoding:").grid(row=r, column=0, sticky="w", padx=10, pady=4)
        ttk.Combobox(self, textvariable=self.var_tpl_enc, values=["base64", "hex"], width=10, state="readonly").grid(
            row=r, column=1, sticky="w", padx=10, pady=4
        )
        r += 1

        # -------------------------
        # DLL paths
        # -------------------------
        ttk.Label(self, text="DLL paths", font=("Segoe UI", 12, "bold")).grid(
            row=r, column=0, sticky="w", padx=10, pady=(16, 5), columnspan=3
        )
        r += 1

        self.var_plcomm = tk.StringVar(value=self.app.cfg.plcomm_dll_path)
        self.var_zkfp = tk.StringVar(value=self.app.cfg.zkfp_dll_path)

        r = self._row_path(r, "plcommpro.dll path:", self.var_plcomm)
        r = self._row_path(r, "zkfp.dll path:", self.var_zkfp)

        # -------------------------
        # MonClub API settings
        # -------------------------
        ttk.Label(self, text="MonClub API settings", font=("Segoe UI", 12, "bold")).grid(
            row=r, column=0, sticky="w", padx=10, pady=(16, 5), columnspan=3
        )
        r += 1

        self.var_api_login = tk.StringVar(value=self.app.cfg.api_login_url)
        self.var_api_sync = tk.StringVar(value=self.app.cfg.api_sync_url)
        self.var_sync_interval = tk.StringVar(value=str(self.app.cfg.sync_interval_sec))
        self.var_max_login_age = tk.StringVar(value=str(self.app.cfg.max_login_age_minutes))
        self.var_login_email = tk.StringVar(value=self.app.cfg.login_email or "")

        r = self._row_entry(r, "Login URL:", self.var_api_login)
        r = self._row_entry(r, "Sync URL:", self.var_api_sync)
        r = self._row_entry(r, "Sync interval (sec):", self.var_sync_interval)
        r = self._row_entry(r, "Max login age (minutes):", self.var_max_login_age)
        r = self._row_entry(r, "Remembered login email:", self.var_login_email)

        # -------------------------
        # Buttons
        # -------------------------
        ttk.Label(self, text="Tools", font=("Segoe UI", 12, "bold")).grid(
            row=r, column=0, sticky="w", padx=10, pady=(16, 5), columnspan=3
        )
        r += 1

        btns = ttk.Frame(self)
        btns.grid(row=r, column=0, columnspan=3, sticky="w", padx=10, pady=6)
        ttk.Button(btns, text="Save config", command=self.on_save).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Sync now (fetch devices/users)", command=self.on_sync_now).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Check PullSDK DLL", command=self.check_pullsdk).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Check ZKFinger DLL", command=self.check_zkfinger).pack(side="left", padx=(0, 8))

        r += 1
        self.lbl_status = ttk.Label(self, text="Status: ready", foreground="#444")
        self.lbl_status.grid(row=r, column=0, columnspan=3, sticky="w", padx=10, pady=8)

        # initial load of devices list + select current config selection (if any)
        self.reload_devices()

    def _row_entry(self, r, label, var, show=None):
        ttk.Label(self, text=label).grid(row=r, column=0, sticky="w", padx=10, pady=4)
        e = ttk.Entry(self, textvariable=var, show=show)
        e.grid(row=r, column=1, sticky="ew", padx=10, pady=4, columnspan=2)
        return r + 1

    def _row_path(self, r, label, var):
        ttk.Label(self, text=label).grid(row=r, column=0, sticky="w", padx=10, pady=4)
        e = ttk.Entry(self, textvariable=var)
        e.grid(row=r, column=1, sticky="ew", padx=10, pady=4)
        ttk.Button(self, text="Browse", command=lambda: self._browse_dll(var)).grid(
            row=r, column=2, sticky="w", padx=10, pady=4
        )
        return r + 1

    def _browse_dll(self, var):
        p = filedialog.askopenfilename(title="Select DLL", filetypes=[("DLL files", "*.dll"), ("All files", "*.*")])
        if p:
            var.set(p)

    # -------------------------
    # NEW: devices list selection logic
    # -------------------------
    def reload_devices(self):
        self._devices = list_sync_devices() or []
        self._device_display_to_id = {}

        values: List[str] = []
        for d in self._devices:
            did = d.get("id")
            name = (d.get("name") or "").strip() or "Unnamed device"
            ip = (d.get("ip_address") or "").strip()
            port = (d.get("port_number") or "").strip()
            model = (d.get("model") or "").strip()

            label = f"[{did}] {name}"
            parts = []
            if ip:
                parts.append(ip)
            if port:
                parts.append(f":{port}")
            if parts:
                label += " - " + "".join(parts)
            if model:
                label += f" - {model}"

            if did is None:
                continue
            try:
                did_int = int(did)
            except Exception:
                continue

            values.append(label)
            self._device_display_to_id[label] = did_int

        self.cmb_devices["values"] = values
        self.lbl_devices_hint.config(text=f"Devices: {len(values)} (from local sync cache)")

        # restore selection from config if possible
        sel_id = getattr(self.app.cfg, "selected_device_id", None)
        if sel_id is not None:
            try:
                sel_id = int(sel_id)
            except Exception:
                sel_id = None

        if sel_id is not None and values:
            for label in values:
                if self._device_display_to_id.get(label) == sel_id:
                    self.var_selected_device.set(label)
                    break
        else:
            # keep current combobox value if exists; otherwise empty
            if not self.var_selected_device.get():
                self.var_selected_device.set("")

    def on_apply_selected_device(self):
        label = (self.var_selected_device.get() or "").strip()
        if not label:
            self.lbl_status.config(text="Status: no device selected")
            return

        did = self._device_display_to_id.get(label)
        if not did:
            self.lbl_status.config(text="Status: invalid device selection")
            return

        d = get_sync_device(did)
        if not d:
            self.lbl_status.config(text="Status: device not found in cache (sync again)")
            return

        ip = (d.get("ip_address") or "").strip()
        port = (d.get("port_number") or "").strip()
        passwd = d.get("password") or ""

        if not ip:
            messagebox.showwarning("Device selection", "Selected device has no ipAddress in API payload.")
            return

        # Apply to controller connection fields (used by other pages)
        self.var_ip.set(ip)
        self.var_port.set(str(_safe_int(port, 4370)))
        self.var_passwd.set(str(passwd))
        self.lbl_status.config(text=f"Status: applied device [{did}] ✅ (IP/Port/Password filled)")

        # Also update config object in memory (not persisted until Save config)
        try:
            self.app.cfg.selected_device_id = int(did)
        except Exception:
            self.app.cfg.selected_device_id = None

    def on_sync_now(self):
        # best effort: call app.request_sync_now (exists in your MainApp)
        try:
            self.app.request_sync_now()
            self.lbl_status.config(text="Status: sync requested ✅ (wait 1-2 sec then Reload devices)")
        except Exception:
            self.lbl_status.config(text="Status: sync requested (manual reload)")
        # do not block; user can press Reload devices

    # -------------------------
    # Save config
    # -------------------------
    def on_save(self):
        try:
            # keep selection if chosen
            label = (self.var_selected_device.get() or "").strip()
            if label:
                did = self._device_display_to_id.get(label)
                if did:
                    self.app.cfg.selected_device_id = int(did)

            self.app.cfg.ip = self.var_ip.get().strip()
            self.app.cfg.port = int(self.var_port.get().strip())
            self.app.cfg.timeout_ms = int(self.var_timeout.get().strip())
            self.app.cfg.password = self.var_passwd.get()

            self.app.cfg.template_version = int(self.var_tpl_ver.get())
            self.app.cfg.template_encoding = self.var_tpl_enc.get().strip()

            self.app.cfg.plcomm_dll_path = self.var_plcomm.get().strip()
            self.app.cfg.zkfp_dll_path = self.var_zkfp.get().strip()

            self.app.cfg.api_login_url = self.var_api_login.get().strip()
            self.app.cfg.api_sync_url = self.var_api_sync.get().strip()

            self.app.cfg.sync_interval_sec = int(self.var_sync_interval.get().strip())
            self.app.cfg.max_login_age_minutes = int(self.var_max_login_age.get().strip())

            self.app.cfg.login_email = self.var_login_email.get().strip()

            self.app.persist_config()

            # re-arm timer if app has it
            try:
                self.app.reschedule_sync_timer()
            except Exception:
                pass

            self.lbl_status.config(text="Status: config saved ✅")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def check_pullsdk(self):
        self.on_save()
        try:
            sdk = PullSDK(self.app.cfg.plcomm_dll_path, logger=self.app.logger)
            sdk.load()
            self.lbl_status.config(text="Status: PullSDK DLL loaded ✅")
        except Exception as e:
            self.lbl_status.config(text=f"Status: PullSDK DLL FAILED ❌ ({e})")
            self.app.logger.exception("PullSDK check failed")

    def check_zkfinger(self):
        self.on_save()
        try:
            z = ZKFinger(self.app.cfg.zkfp_dll_path, logger=self.app.logger)
            z.load()
            self.lbl_status.config(text="Status: ZKFinger DLL loaded ✅ (functions may be partial)")
        except Exception as e:
            self.lbl_status.config(text=f"Status: ZKFinger DLL FAILED ❌ ({e})")
            self.app.logger.exception("ZKFinger check failed")

# monclub_access_python/app/ui/pages/configuration_page.py
from __future__ import annotations

import hashlib
import os
import re
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from typing import Dict, List, Optional, Tuple

from app.core.db import (
    list_sync_devices,
    get_sync_device,
    list_device_door_presets,
    create_device_door_preset,
    update_device_door_preset,
    delete_device_door_preset,
)
from app.sdk.pullsdk import PullSDK
from app.sdk.zkfinger import ZKFinger


def _safe_int(s: str, default: int) -> int:
    try:
        return int(str(s).strip())
    except Exception:
        return default


def _safe_str(v, default: str = "") -> str:
    if v is None:
        return default
    try:
        return str(v)
    except Exception:
        return default


def _normalize_device_dict(d) -> Dict:
    if d is None:
        return {}
    if isinstance(d, dict):
        return d
    try:
        return dict(d)
    except Exception:
        pass
    try:
        return dict(d.__dict__)
    except Exception:
        return {}


def _device_label(d: Dict) -> Optional[Tuple[str, int]]:
    did = d.get("id")
    if did is None:
        return None
    try:
        did_int = int(did)
    except Exception:
        return None

    name = (_safe_str(d.get("name") or "").strip() or "Unnamed device")
    ip = _safe_str(d.get("ip_address") or d.get("ipAddress") or d.get("ip") or "").strip()
    port = _safe_str(d.get("port_number") or d.get("portNumber") or d.get("port") or "").strip()
    model = _safe_str(d.get("model") or "").strip()

    label = f"[{did_int}] {name}"
    if ip:
        label += f" - {ip}"
        if port:
            label += f":{port}"
    if model:
        label += f" - {model}"

    return label, did_int


class _Scrollable(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        self.canvas = tk.Canvas(self, highlightthickness=0, borderwidth=0)
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)

        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.vsb.grid(row=0, column=1, sticky="ns")

        self.inner = ttk.Frame(self.canvas)
        self._win_id = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")

        self.inner.bind("<Configure>", self._on_inner_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

    def _on_inner_configure(self, _e):
        try:
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        except Exception:
            pass

    def _on_canvas_configure(self, e):
        try:
            self.canvas.itemconfigure(self._win_id, width=e.width)
        except Exception:
            pass

    def yview_scroll_units(self, units: int):
        try:
            self.canvas.yview_scroll(units, "units")
        except Exception:
            pass


class ConfigurationPage(ttk.Frame):
    _ADV_HASH = "e6535fb1fa8a0b2590d68c8fa411c359e4753f7a09fea7456056c28f2db4eea1"

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        self._advanced_unlocked = False
        self._advanced_visible = False

        self._devices: List[Dict] = []
        self._device_display_to_id: Dict[str, int] = {}

        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        self._scroll = _Scrollable(self)
        self._scroll.grid(row=0, column=0, sticky="nsew")

        self.content = self._scroll.inner
        self.content.columnconfigure(1, weight=1)

        self.var_selected_device = tk.StringVar(value="")
        self.cmb_devices: ttk.Combobox

        try:
            is_dev = bool(self.app.is_device_mode())
        except Exception:
            is_dev = (str(getattr(self.app.cfg, "data_mode", "DEVICE")).strip().upper() == "DEVICE")
        self.var_mode_device_data = tk.BooleanVar(value=is_dev)

        # realtime engine global toggle (AGENT mode)
        self.var_agent_rt_enabled = tk.BooleanVar(value=bool(getattr(self.app.cfg, "agent_realtime_enabled", True)))

        self.var_preset_device = tk.StringVar(value="")
        self.var_preset_name = tk.StringVar(value="")
        self.var_preset_door = tk.StringVar(value="1")
        self.var_preset_pulse = tk.StringVar(value="3")
        self._selected_preset_id: Optional[int] = None

        self.var_timeout = tk.StringVar(value=str(getattr(self.app.cfg, "device_timeout_ms", 5000)))

        self.var_local_enabled = tk.BooleanVar(value=bool(getattr(self.app.cfg, "local_api_enabled", True)))
        self.var_local_host = tk.StringVar(value=_safe_str(getattr(self.app.cfg, "local_api_host", "127.0.0.1")))
        self.var_local_port = tk.StringVar(value=str(getattr(self.app.cfg, "local_api_port", 8788)))

        self.var_sync_interval = tk.StringVar(value=str(getattr(self.app.cfg, "sync_interval_sec", 60)))
        self.var_max_login_age = tk.StringVar(value=str(getattr(self.app.cfg, "max_login_age_minutes", 60)))
        self.var_device_sync_enabled = tk.BooleanVar(value=bool(getattr(self.app.cfg, "device_sync_enabled", True)))

        self.var_tray_enabled = tk.BooleanVar(value=bool(getattr(self.app.cfg, "tray_enabled", True)))
        self.var_minimize_on_close = tk.BooleanVar(value=bool(getattr(self.app.cfg, "minimize_to_tray_on_close", True)))
        self.var_start_minimized = tk.BooleanVar(value=bool(getattr(self.app.cfg, "start_minimized_to_tray", False)))

        self.var_log_level = tk.StringVar(value=_safe_str(getattr(self.app.cfg, "log_level", "DEBUG") or "DEBUG"))

        self.var_tpl_ver = tk.StringVar(value=str(getattr(self.app.cfg, "template_version", 10)))
        self.var_tpl_enc = tk.StringVar(value=_safe_str(getattr(self.app.cfg, "template_encoding", "base64")))

        self.var_plcomm = tk.StringVar(value=_safe_str(getattr(self.app.cfg, "plcomm_dll_path", r".\plcommpro.dll")))
        self.var_zkfp = tk.StringVar(value=_safe_str(getattr(self.app.cfg, "zkfp_dll_path", r".\libzkfp.dll")))

        self.var_api_login = tk.StringVar(value=_safe_str(getattr(self.app.cfg, "api_login_url", "") or ""))
        self.var_api_sync = tk.StringVar(value=_safe_str(getattr(self.app.cfg, "api_sync_url", "") or ""))
        self.var_api_create_fp = tk.StringVar(value=_safe_str(getattr(self.app.cfg, "api_create_user_fingerprint_url", "") or ""))

        r = 0

        header = ttk.Frame(self.content)
        header.grid(row=r, column=0, columnspan=3, sticky="ew", padx=10, pady=(10, 6))
        header.columnconfigure(0, weight=1)

        ttk.Label(header, text="Configuration", font=("Segoe UI", 13, "bold")).grid(row=0, column=0, sticky="w")

        self.btn_adv = ttk.Button(header, text="Advanced settings", command=self._unlock_advanced)
        self.btn_adv.grid(row=0, column=1, sticky="e")
        r += 1

        ttk.Label(self.content, text="Device (main)", font=("Segoe UI", 12, "bold")).grid(
            row=r, column=0, sticky="w", padx=10, pady=(8, 4), columnspan=3
        )
        r += 1

        self.lbl_active_device = ttk.Label(self.content, text="", foreground="#444")
        self.lbl_active_device.grid(row=r, column=0, columnspan=3, sticky="w", padx=10, pady=(0, 6))
        r += 1

        self.adv_frame = ttk.LabelFrame(self.content, text="Advanced")
        self.adv_frame.grid(row=r, column=0, columnspan=3, sticky="ew", padx=10, pady=(10, 8))
        self.adv_frame.columnconfigure(1, weight=1)
        r += 1

        adv_head = ttk.Frame(self.adv_frame)
        adv_head.grid(row=0, column=0, columnspan=3, sticky="ew", padx=10, pady=(8, 0))
        adv_head.columnconfigure(0, weight=1)

        ttk.Label(adv_head, text="Advanced settings", font=("Segoe UI", 11, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Button(adv_head, text="Close", command=self._on_close_advanced).grid(row=0, column=1, sticky="e")

        ar = 1

        ttk.Label(self.adv_frame, text="Data mode", font=("Segoe UI", 11, "bold")).grid(
            row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=(10, 6)
        )
        ar += 1

        ttk.Checkbutton(
            self.adv_frame,
            text="In device data (controllers + device logs pull/push)",
            variable=self.var_mode_device_data,
        ).grid(row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=(4, 2))
        ar += 1

        ttk.Label(
            self.adv_frame,
            text="OFF = In agent data (backend pull + local cache + realtime RTLog)",
            foreground="#444",
        ).grid(row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=(0, 8))
        ar += 1

        ttk.Checkbutton(
            self.adv_frame,
            text="Enable realtime engine in AGENT mode",
            variable=self.var_agent_rt_enabled,
        ).grid(row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=(0, 8))
        ar += 1

        ttk.Separator(self.adv_frame).grid(row=ar, column=0, columnspan=3, sticky="ew", padx=10, pady=10)
        ar += 1

        ttk.Label(self.adv_frame, text="Main device (from locally saved device list)", font=("Segoe UI", 11, "bold")).grid(
            row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=(0, 6)
        )
        ar += 1

        ttk.Label(self.adv_frame, text="Device:").grid(row=ar, column=0, sticky="w", padx=10, pady=4)

        self.cmb_devices = ttk.Combobox(self.adv_frame, textvariable=self.var_selected_device, values=[], state="readonly")
        self.cmb_devices.grid(row=ar, column=1, sticky="ew", padx=10, pady=4)

        tools = ttk.Frame(self.adv_frame)
        tools.grid(row=ar, column=2, sticky="w", padx=10, pady=4)
        ttk.Button(tools, text="Reload devices", command=self.reload_devices).pack(side="left", padx=(0, 8))
        ttk.Button(tools, text="Apply", command=self.on_apply_selected_device).pack(side="left")
        ar += 1

        self.lbl_devices_hint = ttk.Label(self.adv_frame, text="Devices: 0 (sync first to load devices list)", foreground="#444")
        self.lbl_devices_hint.grid(row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=(0, 10))
        ar += 1

        ttk.Separator(self.adv_frame).grid(row=ar, column=0, columnspan=3, sticky="ew", padx=10, pady=10)
        ar += 1

        ttk.Label(self.adv_frame, text="Door control presets (per device)", font=("Segoe UI", 11, "bold")).grid(
            row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=(0, 6)
        )
        ar += 1

        preset_box = ttk.Frame(self.adv_frame)
        preset_box.grid(row=ar, column=0, columnspan=3, sticky="ew", padx=10, pady=(0, 8))
        preset_box.columnconfigure(1, weight=1)
        ar += 1

        ttk.Label(preset_box, text="Device:").grid(row=0, column=0, sticky="w", pady=4)
        self.cmb_preset_device = ttk.Combobox(preset_box, textvariable=self.var_preset_device, values=[], state="readonly")
        self.cmb_preset_device.grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=4)
        self.cmb_preset_device.bind("<<ComboboxSelected>>", self._on_preset_device_changed)

        self.lbl_preset_count = ttk.Label(preset_box, text="Presets: 0 / 10", foreground="#444")
        self.lbl_preset_count.grid(row=0, column=2, sticky="w", padx=(10, 0))

        form = ttk.LabelFrame(self.adv_frame, text="Add / Edit preset")
        form.grid(row=ar, column=0, columnspan=3, sticky="ew", padx=10, pady=(0, 8))
        form.columnconfigure(1, weight=1)
        ar += 1

        ttk.Label(form, text="Door name:").grid(row=0, column=0, sticky="w", padx=10, pady=4)
        ttk.Entry(form, textvariable=self.var_preset_name).grid(row=0, column=1, sticky="ew", padx=10, pady=4, columnspan=2)

        ttk.Label(form, text="Door number:").grid(row=1, column=0, sticky="w", padx=10, pady=4)
        ttk.Entry(form, textvariable=self.var_preset_door, width=8).grid(row=1, column=1, sticky="w", padx=10, pady=4)

        ttk.Label(form, text="Pulse seconds:").grid(row=2, column=0, sticky="w", padx=10, pady=4)
        ttk.Entry(form, textvariable=self.var_preset_pulse, width=8).grid(row=2, column=1, sticky="w", padx=10, pady=4)

        preset_btns = ttk.Frame(form)
        preset_btns.grid(row=3, column=0, columnspan=3, sticky="w", padx=10, pady=(6, 10))

        ttk.Button(preset_btns, text="New", command=self._preset_clear).pack(side="left", padx=(0, 8))
        ttk.Button(preset_btns, text="Save", command=self._preset_save).pack(side="left", padx=(0, 8))
        ttk.Button(preset_btns, text="Delete selected", command=self._preset_delete_selected).pack(side="left")

        list_box = ttk.LabelFrame(self.adv_frame, text="Saved presets for selected device")
        list_box.grid(row=ar, column=0, columnspan=3, sticky="nsew", padx=10, pady=(0, 6))
        list_box.columnconfigure(0, weight=1)
        list_box.rowconfigure(0, weight=1)
        ar += 1

        self.lst_presets = tk.Listbox(list_box, height=7)
        self.lst_presets.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=10)
        self.lst_presets.bind("<<ListboxSelect>>", self._on_preset_selected)

        sb = ttk.Scrollbar(list_box, orient="vertical", command=self.lst_presets.yview)
        sb.grid(row=0, column=1, sticky="ns", padx=(0, 10), pady=10)
        self.lst_presets.configure(yscrollcommand=sb.set)

        self._preset_rows: List[Dict] = []

        ttk.Separator(self.adv_frame).grid(row=ar, column=0, columnspan=3, sticky="ew", padx=10, pady=10)
        ar += 1

        ttk.Label(self.adv_frame, text="PullSDK connection", font=("Segoe UI", 11, "bold")).grid(
            row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=(0, 6)
        )
        ar += 1
        ar = self._row_entry_adv(ar, "Timeout (ms):", self.var_timeout)

        ttk.Separator(self.adv_frame).grid(row=ar, column=0, columnspan=3, sticky="ew", padx=10, pady=10)
        ar += 1

        ttk.Label(self.adv_frame, text="Local API (dashboard -> this PC)", font=("Segoe UI", 11, "bold")).grid(
            row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=(0, 6)
        )
        ar += 1

        ttk.Checkbutton(self.adv_frame, text="Enable Local API server", variable=self.var_local_enabled).grid(
            row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=(4, 8)
        )
        ar += 1

        ar = self._row_entry_adv(ar, "Host:", self.var_local_host)
        ar = self._row_entry_adv(ar, "Port:", self.var_local_port)

        ttk.Separator(self.adv_frame).grid(row=ar, column=0, columnspan=3, sticky="ew", padx=10, pady=10)
        ar += 1

        ttk.Label(self.adv_frame, text="Sync & Access rules", font=("Segoe UI", 11, "bold")).grid(
            row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=(0, 6)
        )
        ar += 1

        ar = self._row_entry_adv(ar, "Sync interval (sec):", self.var_sync_interval)
        ar = self._row_entry_adv(ar, "Max login age (minutes):", self.var_max_login_age)

        ttk.Checkbutton(
            self.adv_frame, text="Enable device sync engine (final behavior)", variable=self.var_device_sync_enabled
        ).grid(row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=(4, 8))
        ar += 1

        ttk.Separator(self.adv_frame).grid(row=ar, column=0, columnspan=3, sticky="ew", padx=10, pady=10)
        ar += 1

        ttk.Label(self.adv_frame, text="Tray behavior (Windows)", font=("Segoe UI", 11, "bold")).grid(
            row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=(0, 6)
        )
        ar += 1

        ttk.Checkbutton(self.adv_frame, text="Enable tray icon", variable=self.var_tray_enabled).grid(
            row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=2
        )
        ar += 1
        ttk.Checkbutton(self.adv_frame, text="Minimize to tray on close", variable=self.var_minimize_on_close).grid(
            row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=2
        )
        ar += 1
        ttk.Checkbutton(self.adv_frame, text="Start minimized to tray", variable=self.var_start_minimized).grid(
            row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=(2, 8)
        )
        ar += 1

        ttk.Separator(self.adv_frame).grid(row=ar, column=0, columnspan=3, sticky="ew", padx=10, pady=10)
        ar += 1

        ttk.Label(self.adv_frame, text="Logging", font=("Segoe UI", 11, "bold")).grid(
            row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=(0, 6)
        )
        ar += 1

        ttk.Label(self.adv_frame, text="Log level:").grid(row=ar, column=0, sticky="w", padx=10, pady=4)
        ttk.Combobox(
            self.adv_frame,
            textvariable=self.var_log_level,
            values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            width=10,
            state="readonly",
        ).grid(row=ar, column=1, sticky="w", padx=10, pady=4)
        ar += 1

        ttk.Separator(self.adv_frame).grid(row=ar, column=0, columnspan=3, sticky="ew", padx=10, pady=10)
        ar += 1

        ttk.Label(self.adv_frame, text="Fingerprint template settings", font=("Segoe UI", 11, "bold")).grid(
            row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=(0, 6)
        )
        ar += 1

        ttk.Label(self.adv_frame, text="Template version (9/10):").grid(row=ar, column=0, sticky="w", padx=10, pady=4)
        ttk.Combobox(self.adv_frame, textvariable=self.var_tpl_ver, values=["9", "10"], width=10, state="readonly").grid(
            row=ar, column=1, sticky="w", padx=10, pady=4
        )
        ar += 1

        ttk.Label(self.adv_frame, text="Template encoding:").grid(row=ar, column=0, sticky="w", padx=10, pady=4)
        ttk.Combobox(self.adv_frame, textvariable=self.var_tpl_enc, values=["base64", "hex"], width=10, state="readonly").grid(
            row=ar, column=1, sticky="w", padx=10, pady=4
        )
        ar += 1

        ttk.Separator(self.adv_frame).grid(row=ar, column=0, columnspan=3, sticky="ew", padx=10, pady=10)
        ar += 1

        ttk.Label(self.adv_frame, text="DLL paths", font=("Segoe UI", 11, "bold")).grid(
            row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=(0, 6)
        )
        ar += 1

        ar = self._row_path_adv(ar, "plcommpro.dll path:", self.var_plcomm)
        ar = self._row_path_adv(ar, "zkfp.dll path:", self.var_zkfp)

        ttk.Separator(self.adv_frame).grid(row=ar, column=0, columnspan=3, sticky="ew", padx=10, pady=10)
        ar += 1

        ttk.Label(self.adv_frame, text="MonClub API settings", font=("Segoe UI", 11, "bold")).grid(
            row=ar, column=0, columnspan=3, sticky="w", padx=10, pady=(0, 6)
        )
        ar += 1

        ar = self._row_entry_adv(ar, "Login URL:", self.var_api_login)
        ar = self._row_entry_adv(ar, "Sync URL:", self.var_api_sync)
        ar = self._row_entry_adv(ar, "Create fingerprint URL:", self.var_api_create_fp)

        self._set_advanced_visible(False)

        ttk.Label(self.content, text="Tools", font=("Segoe UI", 12, "bold")).grid(
            row=r, column=0, sticky="w", padx=10, pady=(16, 5), columnspan=3
        )
        r += 1

        btns = ttk.Frame(self.content)
        btns.grid(row=r, column=0, columnspan=3, sticky="w", padx=10, pady=6)
        ttk.Button(btns, text="Save config", command=self.on_save).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Sync now (fetch devices/users)", command=self.on_sync_now).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Check PullSDK DLL", command=self.check_pullsdk).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Check ZKFinger DLL", command=self.check_zkfinger).pack(side="left", padx=(0, 8))

        r += 1
        self.lbl_status = ttk.Label(self.content, text="Status: ready", foreground="#444")
        self.lbl_status.grid(row=r, column=0, columnspan=3, sticky="w", padx=10, pady=8)

        self.reload_devices()
        self._refresh_active_device_summary()

        self._bind_mousewheel_recursive(self.content)
        self._sync_adv_button_state()

    def _sync_adv_button_state(self):
        try:
            if not self._advanced_unlocked:
                self.btn_adv.config(text="Advanced settings", state="normal")
            else:
                self.btn_adv.config(
                    text=("Hide advanced" if self._advanced_visible else "Show advanced"),
                    state="normal",
                )
        except Exception:
            pass

    def _on_close_advanced(self):
        self._set_advanced_visible(False)

    def _unlock_advanced(self):
        if self._advanced_unlocked:
            self._set_advanced_visible(not bool(self._advanced_visible))
            return

        pw = simpledialog.askstring("Advanced settings", "Enter password:", show="*")
        if pw is None:
            return

        h = hashlib.sha256(pw.encode("utf-8", errors="ignore")).hexdigest()
        if h != self._ADV_HASH:
            messagebox.showerror("Advanced settings", "Wrong password.")
            return

        self._advanced_unlocked = True
        self._set_advanced_visible(True)

    def _set_advanced_visible(self, visible: bool):
        self._advanced_visible = bool(visible)
        try:
            if self._advanced_visible:
                self.adv_frame.grid()
            else:
                self.adv_frame.grid_remove()
        except Exception:
            pass
        self._sync_adv_button_state()

    def _bind_mousewheel_recursive(self, widget):
        widget.bind("<MouseWheel>", self._on_mousewheel, add="+")
        widget.bind("<Button-4>", self._on_mousewheel_linux_up, add="+")
        widget.bind("<Button-5>", self._on_mousewheel_linux_down, add="+")
        for ch in widget.winfo_children():
            self._bind_mousewheel_recursive(ch)

    def _on_mousewheel(self, e):
        delta = int(getattr(e, "delta", 0) or 0)
        if delta == 0:
            return
        units = -1 * (delta // 120)
        if units == 0:
            units = -1 if delta > 0 else 1
        self._scroll.yview_scroll_units(units)

    def _on_mousewheel_linux_up(self, _e):
        self._scroll.yview_scroll_units(-1)

    def _on_mousewheel_linux_down(self, _e):
        self._scroll.yview_scroll_units(1)

    def _row_entry_adv(self, r, label, var, show=None):
        ttk.Label(self.adv_frame, text=label).grid(row=r, column=0, sticky="w", padx=10, pady=4)
        e = ttk.Entry(self.adv_frame, textvariable=var, show=show)
        e.grid(row=r, column=1, sticky="ew", padx=10, pady=4, columnspan=2)
        return r + 1

    def _row_path_adv(self, r, label, var):
        ttk.Label(self.adv_frame, text=label).grid(row=r, column=0, sticky="w", padx=10, pady=4)
        e = ttk.Entry(self.adv_frame, textvariable=var)
        e.grid(row=r, column=1, sticky="ew", padx=10, pady=4)
        ttk.Button(self.adv_frame, text="Browse", command=lambda: self._browse_dll(var)).grid(
            row=r, column=2, sticky="w", padx=10, pady=4
        )
        return r + 1

    def _browse_dll(self, var):
        p = filedialog.askopenfilename(title="Select DLL", filetypes=[("DLL files", "*.dll"), ("All files", "*.*")])
        if p:
            var.set(p)

    def _refresh_active_device_summary(self):
        try:
            mode_device = bool(self.var_mode_device_data.get())
        except Exception:
            mode_device = (str(getattr(self.app.cfg, "data_mode", "DEVICE")).strip().upper() == "DEVICE")

        if not mode_device:
            self.lbl_active_device.config(text="Mode: AGENT data — realtime RTLog engine is available in Agent realtime tab.")
            return

        did = getattr(self.app.cfg, "selected_device_id", None)
        if did is None:
            self.lbl_active_device.config(text="Main device: (none selected)  — unlock Advanced settings to select one")
            return

        d = get_sync_device(int(did))
        dd = _normalize_device_dict(d)
        name = (_safe_str(dd.get("name") or "").strip() or "Unnamed device")
        ip = _safe_str(dd.get("ip_address") or dd.get("ipAddress") or dd.get("ip") or "").strip()
        port = _safe_str(dd.get("port_number") or dd.get("portNumber") or dd.get("port") or "").strip()

        if ip:
            s = f"Main device: [{int(did)}] {name} — {ip}{(':' + port) if port else ''}"
        else:
            s = f"Main device: [{int(did)}] {name} — (missing IP in saved device)"
        self.lbl_active_device.config(text=s)

    def reload_devices(self):
        self._devices = list_sync_devices() or []
        self._device_display_to_id = {}

        values: List[str] = []
        for d0 in self._devices:
            d = _normalize_device_dict(d0)
            out = _device_label(d)
            if not out:
                continue
            label, did_int = out
            values.append(label)
            self._device_display_to_id[label] = did_int

        self.cmb_devices["values"] = values
        self.cmb_preset_device["values"] = values
        self.lbl_devices_hint.config(text=f"Devices: {len(values)} (from local sync cache)")

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
            if not self.var_selected_device.get():
                self.var_selected_device.set(values[0] if values else "")

        if sel_id is not None and values:
            found = False
            for label in values:
                if self._device_display_to_id.get(label) == sel_id:
                    self.var_preset_device.set(label)
                    found = True
                    break
            if not found and values:
                self.var_preset_device.set(values[0])
        else:
            if not self.var_preset_device.get():
                self.var_preset_device.set(values[0] if values else "")

        self._preset_reload()

    def on_apply_selected_device(self):
        label = (self.var_selected_device.get() or "").strip()
        if not label:
            self.lbl_status.config(text="Status: no device selected")
            return

        did = self._device_display_to_id.get(label)
        if did is None:
            self.lbl_status.config(text="Status: invalid device selection")
            return

        d = get_sync_device(did)
        dd = _normalize_device_dict(d)
        ip = _safe_str(dd.get("ip_address") or dd.get("ipAddress") or dd.get("ip") or "").strip()
        if not ip:
            messagebox.showwarning("Device selection", "Selected device has no IP in saved data.")
            return

        try:
            self.app.cfg.selected_device_id = int(did)
        except Exception:
            self.app.cfg.selected_device_id = None

        self._refresh_active_device_summary()
        self.lbl_status.config(text=f"Status: main device set to [{did}] ✅")

    def _get_selected_preset_device_id(self) -> Optional[int]:
        label = (self.var_preset_device.get() or "").strip()
        if not label:
            return None
        did = self._device_display_to_id.get(label)
        if did is None:
            return None
        return int(did)

    def _on_preset_device_changed(self, _evt=None):
        self._preset_clear()
        self._preset_reload()

    def _preset_reload(self):
        self.lst_presets.delete(0, "end")
        self._preset_rows = []
        self._selected_preset_id = None

        did = self._get_selected_preset_device_id()
        if did is None:
            self.lbl_preset_count.config(text="Presets: 0 / 10")
            return

        try:
            presets = list_device_door_presets(did)
        except Exception as e:
            self.lbl_preset_count.config(text="Presets: 0 / 10")
            messagebox.showerror("Door presets", str(e))
            return

        self.lbl_preset_count.config(text=f"Presets: {len(presets)} / 10")

        for p in presets:
            row = {
                "id": int(p.id),
                "device_id": int(p.device_id),
                "door_number": int(p.door_number),
                "pulse_seconds": int(p.pulse_seconds),
                "door_name": str(p.door_name),
            }
            self._preset_rows.append(row)
            self.lst_presets.insert(
                "end",
                f"#{row['id']} | {row['door_name']} | door={row['door_number']} | pulse={row['pulse_seconds']}s",
            )

    def _preset_clear(self):
        self._selected_preset_id = None
        self.var_preset_name.set("")
        self.var_preset_door.set("1")
        self.var_preset_pulse.set("3")
        try:
            self.lst_presets.selection_clear(0, "end")
        except Exception:
            pass

    def _on_preset_selected(self, _evt=None):
        try:
            sel = self.lst_presets.curselection()
            if not sel:
                return
            idx = int(sel[0])
            if idx < 0 or idx >= len(self._preset_rows):
                return
            row = self._preset_rows[idx]
            self._selected_preset_id = int(row["id"])
            self.var_preset_name.set(str(row["door_name"]))
            self.var_preset_door.set(str(row["door_number"]))
            self.var_preset_pulse.set(str(row["pulse_seconds"]))
        except Exception:
            pass

    def _preset_save(self):
        did = self._get_selected_preset_device_id()
        if did is None:
            messagebox.showerror("Door presets", "Select a device first.")
            return

        name = (self.var_preset_name.get() or "").strip()
        door = _safe_int(self.var_preset_door.get(), 1)
        pulse = _safe_int(self.var_preset_pulse.get(), 3)

        if not name:
            messagebox.showerror("Door presets", "Door name is required.")
            return
        if door < 1:
            messagebox.showerror("Door presets", "Door number must be >= 1.")
            return
        if pulse < 1 or pulse > 60:
            messagebox.showerror("Door presets", "Pulse seconds must be between 1 and 60.")
            return

        try:
            if self._selected_preset_id is None:
                create_device_door_preset(device_id=did, door_number=door, pulse_seconds=pulse, door_name=name)
            else:
                update_device_door_preset(
                    preset_id=int(self._selected_preset_id),
                    device_id=did,
                    door_number=door,
                    pulse_seconds=pulse,
                    door_name=name,
                )
        except Exception as e:
            messagebox.showerror("Door presets", str(e))
            return

        self._preset_reload()
        self._preset_clear()

    def _preset_delete_selected(self):
        if self._selected_preset_id is None:
            return
        if not messagebox.askyesno("Door presets", "Delete selected preset?"):
            return
        try:
            delete_device_door_preset(int(self._selected_preset_id))
        except Exception as e:
            messagebox.showerror("Door presets", str(e))
            return
        self._preset_reload()
        self._preset_clear()

    def on_sync_now(self):
        try:
            self.app.request_sync_now()
            self.lbl_status.config(text="Status: sync requested ✅ (wait 1-2 sec then Reload devices)")
        except Exception:
            self.lbl_status.config(text="Status: sync requested (manual reload)")

    def on_save(self):
        try:
            login_url = (self.var_api_login.get() or "").strip()
            sync_url = (self.var_api_sync.get() or "").strip()
            create_fp_url = (self.var_api_create_fp.get() or "").strip()

            if login_url and not login_url.startswith(("http://", "https://")):
                messagebox.showerror("Validation", "Login URL must start with http:// or https://")
                return
            if sync_url and not sync_url.startswith(("http://", "https://")):
                messagebox.showerror("Validation", "Sync URL must start with http:// or https://")
                return
            if create_fp_url and not create_fp_url.startswith(("http://", "https://")):
                messagebox.showerror("Validation", "Create fingerprint URL must start with http:// or https://")
                return

            local_host = (self.var_local_host.get() or "").strip()
            if local_host and local_host.lower() != "localhost":
                ip_pattern = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
                match = ip_pattern.match(local_host)
                if not match:
                    messagebox.showerror("Validation", "Local API host must be a valid IP address or 'localhost'")
                    return
                for i in range(1, 5):
                    octet = int(match.group(i))
                    if octet < 0 or octet > 255:
                        messagebox.showerror("Validation", f"Invalid IP address octet: {octet}")
                        return

            plcomm_path = (self.var_plcomm.get() or "").strip()
            zkfp_path = (self.var_zkfp.get() or "").strip()

            if plcomm_path and not os.path.exists(plcomm_path):
                if not messagebox.askyesno("Warning", "plcommpro.dll path does not exist. Continue anyway?"):
                    return
            if zkfp_path and not os.path.exists(zkfp_path):
                if not messagebox.askyesno("Warning", "zkfp.dll path does not exist. Continue anyway?"):
                    return

            # selected main device (optional)
            label = (self.var_selected_device.get() or "").strip()
            if label:
                did = self._device_display_to_id.get(label)
                if did is not None:
                    self.app.cfg.selected_device_id = int(did)

            self.app.cfg.data_mode = "DEVICE" if bool(self.var_mode_device_data.get()) else "AGENT"
            self.app.cfg.agent_realtime_enabled = bool(self.var_agent_rt_enabled.get())

            self.app.cfg.device_timeout_ms = _safe_int(self.var_timeout.get().strip(), 5000)

            self.app.cfg.local_api_enabled = bool(self.var_local_enabled.get())
            self.app.cfg.local_api_host = (self.var_local_host.get() or "").strip() or "127.0.0.1"
            self.app.cfg.local_api_port = _safe_int(self.var_local_port.get().strip(), 8788)

            self.app.cfg.sync_interval_sec = max(10, _safe_int(self.var_sync_interval.get().strip(), 60))
            self.app.cfg.max_login_age_minutes = max(1, _safe_int(self.var_max_login_age.get().strip(), 60))
            self.app.cfg.device_sync_enabled = bool(self.var_device_sync_enabled.get())

            self.app.cfg.tray_enabled = bool(self.var_tray_enabled.get())
            self.app.cfg.minimize_to_tray_on_close = bool(self.var_minimize_on_close.get())
            self.app.cfg.start_minimized_to_tray = bool(self.var_start_minimized.get())

            self.app.cfg.log_level = (self.var_log_level.get() or "DEBUG").strip().upper()

            self.app.cfg.template_version = _safe_int(self.var_tpl_ver.get().strip(), 10)
            self.app.cfg.template_encoding = (self.var_tpl_enc.get().strip() or "base64").strip().lower()

            self.app.cfg.plcomm_dll_path = plcomm_path
            self.app.cfg.zkfp_dll_path = zkfp_path

            self.app.cfg.api_login_url = login_url
            self.app.cfg.api_sync_url = sync_url
            self.app.cfg.api_create_user_fingerprint_url = create_fp_url

            self.app.persist_config()

            try:
                self.app.reschedule_sync_timer()
            except Exception:
                pass

            try:
                self.app.restart_local_api_server()
            except Exception:
                pass

            try:
                self.app.apply_mode_from_config()
            except Exception:
                pass

            self._refresh_active_device_summary()
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

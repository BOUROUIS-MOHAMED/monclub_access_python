# monclub_access_python/app/ui/pages/device_info_page.py

from __future__ import annotations

import json
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk, messagebox, simpledialog
from typing import Dict, List, Optional

from app.sdk.pullsdk import PullSDK


def _parse_params_text(raw: str) -> Dict[str, str]:
    """
    PullSDK GetDeviceParam often returns:
      "Key=Value,Key2=Value2"
    Sometimes with newlines. We'll support both.
    """
    out: Dict[str, str] = {}
    if not raw:
        return out

    s = raw.strip()
    if not s:
        return out

    # Normalize separators
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    parts: List[str] = []
    for line in s.split("\n"):
        line = line.strip()
        if not line:
            continue
        # sometimes a line contains comma-separated pairs
        parts.extend([p.strip() for p in line.split(",") if p.strip()])

    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k:
                out[k] = v
        else:
            # fallback if no '='
            out[p] = ""

    return out


class DeviceInfoPage(ttk.Frame):
    """
    Shows device configuration/info using PullSDK GetDeviceParam + some counts.

    Behavior:
    - User selects a device from locally-saved device list.
    - Each refresh opens a temporary PullSDK connection to that selected device.
    - No auto-connect (no refresh on init).
    """

    DEFAULT_ITEMS = (
        # Common-ish fields across ZKTeco firmwares (some may return empty)
        "DeviceName,SerialNumber,ProductTime,FirmwareVersion,Platform,DeviceType,LockCount,ReaderCount,DoorCount,"
        "IPAddress,NetMask,Gateway,DHCP,MAC,CommPassword,TimeZone,ACFun,PhotoFunOn,FaceFunOn,FPFunOn,"
        "AlgVer,FPAlgVer,FaceAlgVer,~DeviceName,~SerialNumber,~FirmwareVersion,~Platform,~DeviceType"
    )

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        # devices (loaded from local cache)
        self._devices: list[dict] = []
        self._device_labels: list[str] = []
        self._device_label_to_device: dict[str, dict] = {}
        self._selected_device: dict | None = None

        # items (multi-select) state
        self._items_selection_mode: str = "default"  # default | list | custom
        self._items_selected: list[str] = []
        self._items_custom: list[str] = []

        # ---------- Top bar ----------
        top = ttk.Frame(self)
        top.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 6))
        top.columnconfigure(3, weight=1)

        ttk.Label(top, text="Device:").grid(row=0, column=0, sticky="w")

        self.var_device = tk.StringVar(value="")
        self.cb_device = ttk.Combobox(top, textvariable=self.var_device, values=[], width=45, state="readonly")
        self.cb_device.grid(row=0, column=1, sticky="w", padx=(8, 10))
        self.cb_device.bind("<<ComboboxSelected>>", self._on_device_selected)

        ttk.Button(top, text="Reload devices", command=self.reload_devices).grid(row=0, column=2, sticky="w")

        ttk.Button(top, text="Refresh device info", command=self.refresh).grid(row=0, column=3, sticky="w", padx=(12, 0))

        self.lbl_status = ttk.Label(top, text="Status: ready (select device then refresh)")
        self.lbl_status.grid(row=0, column=4, sticky="e", padx=(12, 0))

        ttk.Button(top, text="Copy raw to clipboard", command=self.copy_raw).grid(row=0, column=5, sticky="e", padx=(12, 0))

        # ---------- Items (multi-select dropdown) ----------
        items_row = ttk.Frame(self)
        items_row.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 8))
        items_row.columnconfigure(1, weight=1)

        ttk.Label(items_row, text="GetDeviceParam items:").grid(row=0, column=0, sticky="w")

        self.var_items_display = tk.StringVar(value="Default set")
        self.items_btn = ttk.Menubutton(items_row, textvariable=self.var_items_display, width=50)
        self.items_menu = tk.Menu(self.items_btn, tearoff=False)
        self.items_btn["menu"] = self.items_menu
        self.items_btn.grid(row=0, column=1, sticky="w", padx=10)

        ttk.Label(items_row, text="(multi-select)").grid(row=0, column=2, sticky="w")

        # ---------- Paned view ----------
        pw = ttk.Panedwindow(self, orient="horizontal")
        pw.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0, 10))

        # Left: Key/Value tree
        left = ttk.Frame(pw)
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(left, columns=("key", "value"), show="headings", height=24)
        self.tree.heading("key", text="Key")
        self.tree.heading("value", text="Value")
        self.tree.column("key", width=260, anchor="w")
        self.tree.column("value", width=520, anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew")

        y = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        y.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=y.set)

        pw.add(left, weight=3)

        # Right: raw + counts
        right = ttk.Frame(pw)
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        ttk.Label(right, text="Raw / extra info").grid(row=0, column=0, sticky="w", pady=(0, 6))

        self.txt = tk.Text(right, height=10)
        self.txt.grid(row=1, column=0, sticky="nsew")

        y2 = ttk.Scrollbar(right, orient="vertical", command=self.txt.yview)
        y2.grid(row=1, column=1, sticky="ns")
        self.txt.configure(yscrollcommand=y2.set)

        pw.add(right, weight=2)

        self._last_raw = ""

        # init device list + items menu (NO auto refresh)
        self.reload_devices()
        self._rebuild_items_menu()

    # ---------------- Devices loading (same idea as DevicePage) ----------------

    def _devices_cache_path(self) -> Path:
        cfg = getattr(self.app, "cfg", None)
        if cfg:
            for attr in ("devices_cache_path", "devices_path"):
                p = getattr(cfg, attr, None)
                if p:
                    return Path(p)

            data_dir = getattr(cfg, "data_dir", None)
            if data_dir:
                return Path(data_dir) / "devices.json"

        return Path("devices.json")

    def _normalize_device(self, raw: dict) -> dict:
        def pick(*keys, default=None):
            for k in keys:
                if k in raw and raw[k] not in (None, ""):
                    return raw[k]
            return default

        name = str(pick("name", "deviceName", "device_name", "title", default="(unnamed)"))
        platform = pick("platform", "devicePlatform", "device_platform", "platForm", default="")

        ip = str(pick("ip", "ipAddress", "ip_address", "host", "address", default="")).strip()
        port = pick("port", "tcpPort", "tcp_port", default=4370)
        password = str(pick("password", "passwd", "commPassword", "comm_password", "devicePassword", default="") or "")
        timeout_ms = pick("timeout_ms", "timeoutMs", "timeout", default=5000)

        try:
            port_i = int(port)
        except Exception:
            port_i = 4370
        try:
            timeout_i = int(timeout_ms)
        except Exception:
            timeout_i = 5000

        return {
            "name": name,
            "platform": str(platform or ""),
            "ip": ip,
            "port": port_i,
            "password": password,
            "timeout_ms": timeout_i,
            **{k: v for k, v in raw.items() if k not in {"name", "platform", "ip", "port", "password", "timeout_ms"}},
        }

    def _device_label(self, d: dict) -> str:
        name = (d.get("name") or "").strip() or "(unnamed)"
        platform = (d.get("platform") or "").strip()
        ip = (d.get("ip") or "").strip()
        port = d.get("port")
        parts = [name]
        if platform:
            parts.append(platform)
        if ip:
            parts.append(f"{ip}:{port}")
        return " | ".join(parts)

    def reload_devices(self):
        self._devices = []
        self._device_labels = []
        self._device_label_to_device = {}
        self._selected_device = None

        # 1) best case: app already exposes saved devices
        src = None
        if hasattr(self.app, "devices") and isinstance(getattr(self.app, "devices"), list):
            src = getattr(self.app, "devices")
        elif hasattr(self.app, "get_saved_devices") and callable(getattr(self.app, "get_saved_devices")):
            try:
                src = self.app.get_saved_devices()
            except Exception:
                src = None

        # 2) fallback: local file
        if not src:
            p = self._devices_cache_path()
            if p.exists():
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                    if isinstance(data, dict) and isinstance(data.get("devices"), list):
                        src = data["devices"]
                    elif isinstance(data, list):
                        src = data
                except Exception as e:
                    self.app.logger.exception("Failed reading devices cache")
                    messagebox.showwarning("Devices", f"Failed to read devices cache:\n{p}\n\n{e}")

        src = src or []

        for item in src:
            if not isinstance(item, dict):
                continue
            d = self._normalize_device(item)
            label = self._device_label(d)
            self._devices.append(d)
            self._device_labels.append(label)
            self._device_label_to_device[label] = d

        # fallback entry: current config
        cfg = getattr(self.app, "cfg", None)
        if cfg and getattr(cfg, "ip", None):
            fallback = {
                "name": "Current config",
                "platform": getattr(cfg, "platform", "") or "",
                "ip": getattr(cfg, "ip", ""),
                "port": getattr(cfg, "port", 4370),
                "password": getattr(cfg, "password", "") or "",
                "timeout_ms": getattr(cfg, "timeout_ms", 5000),
            }
            label = self._device_label(fallback)
            if label not in self._device_label_to_device:
                self._devices.append(fallback)
                self._device_labels.append(label)
                self._device_label_to_device[label] = fallback

        self.cb_device["values"] = self._device_labels

        # auto-select your test device if found (NO auto connect)
        preferred = None
        for lab, dev in self._device_label_to_device.items():
            if (dev.get("name") or "").strip().lower() == "asp 460" and (dev.get("platform") or "").strip().lower() == "zem560_inbio":
                preferred = lab
                break

        if preferred:
            self.var_device.set(preferred)
            self._selected_device = self._device_label_to_device.get(preferred)
        elif self._device_labels:
            self.var_device.set(self._device_labels[0])
            self._selected_device = self._device_label_to_device.get(self._device_labels[0])
        else:
            self.var_device.set("")
            self._selected_device = None

        self.lbl_status.config(text="Status: ready (select device then refresh)")

    def _on_device_selected(self, _evt=None):
        label = (self.var_device.get() or "").strip()
        self._selected_device = self._device_label_to_device.get(label)

    # ---------------- Items multi-select ----------------

    def _default_items_list(self) -> list[str]:
        return [x.strip() for x in (self.DEFAULT_ITEMS or "").split(",") if x.strip()]

    def _items_string(self) -> str:
        if self._items_selection_mode == "default":
            return self.DEFAULT_ITEMS
        if self._items_selection_mode == "custom":
            return ",".join([x.strip() for x in self._items_custom if str(x).strip()])
        # list mode
        return ",".join([x.strip() for x in self._items_selected if str(x).strip()])

    def _update_items_display(self):
        if self._items_selection_mode == "default":
            self.var_items_display.set("Default set")
            return
        if self._items_selection_mode == "custom":
            if not self._items_custom:
                self.var_items_display.set("Custom (empty → default)")
            elif len(self._items_custom) <= 3:
                self.var_items_display.set("Custom: " + ", ".join(self._items_custom))
            else:
                self.var_items_display.set(f"Custom: {self._items_custom[0]}, {self._items_custom[1]}, {self._items_custom[2]} (+{len(self._items_custom)-3})")
            return

        # list mode
        if not self._items_selected:
            self.var_items_display.set("Selected (empty → default)")
        elif len(self._items_selected) <= 3:
            self.var_items_display.set(", ".join(self._items_selected))
        else:
            self.var_items_display.set(f"{self._items_selected[0]}, {self._items_selected[1]}, {self._items_selected[2]} (+{len(self._items_selected)-3})")

    def _rebuild_items_menu(self):
        self.items_menu.delete(0, "end")

        default_var = tk.BooleanVar(value=(self._items_selection_mode == "default"))
        self._item_vars: dict[str, tk.BooleanVar] = {}

        def set_default():
            self._items_selection_mode = "default"
            self._items_selected = []
            self._items_custom = []
            default_var.set(True)
            for v in self._item_vars.values():
                v.set(False)
            self._update_items_display()

        def changed_any():
            if default_var.get():
                default_var.set(False)

            selected = [k for k, v in self._item_vars.items() if v.get()]
            if not selected:
                # empty -> treat as default (but keep UX clear)
                self._items_selection_mode = "default"
                self._items_selected = []
                self._items_custom = []
                default_var.set(True)
            else:
                self._items_selection_mode = "list"
                self._items_selected = selected
                self._items_custom = []
            self._update_items_display()

        def custom_items():
            current = ""
            if self._items_selection_mode == "custom":
                current = ",".join(self._items_custom)
            elif self._items_selection_mode == "list":
                current = ",".join(self._items_selected)

            s = simpledialog.askstring(
                "Custom GetDeviceParam items",
                "Enter items (comma separated):",
                initialvalue=current or self.DEFAULT_ITEMS,
            )
            if s is None:
                return
            parts = [p.strip() for p in s.replace("\t", ",").replace(";", ",").split(",") if p.strip()]
            if not parts:
                set_default()
                return

            self._items_selection_mode = "custom"
            self._items_custom = parts
            self._items_selected = []
            default_var.set(False)
            for v in self._item_vars.values():
                v.set(False)
            self._update_items_display()

        # Default set
        self.items_menu.add_checkbutton(label="Default set", variable=default_var, command=set_default)
        self.items_menu.add_separator()

        # Individual items (from DEFAULT_ITEMS list)
        for it in self._default_items_list():
            v = tk.BooleanVar(value=False)
            self._item_vars[it] = v
            self.items_menu.add_checkbutton(label=it, variable=v, command=changed_any)

        self.items_menu.add_separator()
        self.items_menu.add_command(label="Custom...", command=custom_items)

        # restore state
        if self._items_selection_mode == "default":
            set_default()
        elif self._items_selection_mode == "list":
            default_var.set(False)
            for k in self._items_selected:
                if k in self._item_vars:
                    self._item_vars[k].set(True)
            self._update_items_display()
        elif self._items_selection_mode == "custom":
            default_var.set(False)
            self._update_items_display()
        else:
            set_default()

    # ---------------- UI helpers ----------------

    def copy_raw(self):
        raw = self._last_raw or ""
        self.clipboard_clear()
        self.clipboard_append(raw)
        self.lbl_status.config(text="Status: raw copied ✅")

    def _tree_clear(self):
        for iid in self.tree.get_children():
            self.tree.delete(iid)

    def _tree_set(self, kv: Dict[str, str]):
        self._tree_clear()
        for k in sorted(kv.keys(), key=lambda x: x.lower()):
            self.tree.insert("", "end", values=(k, kv.get(k, "")))

    # ---------------- Refresh logic ----------------

    def refresh(self):
        dev = self._selected_device
        if not dev:
            messagebox.showwarning("Device Info", "Please select a device first.")
            return

        items = (self._items_string() or "").strip()
        if not items:
            items = self.DEFAULT_ITEMS

        ip = str(dev.get("ip") or "").strip()
        port = int(dev.get("port") or 4370)
        timeout_ms = int(dev.get("timeout_ms") or 5000)
        password = str(dev.get("password") or "")
        platform = str(dev.get("platform") or "").strip() or None

        if not ip:
            messagebox.showerror("Device Info", "Selected device has no IP.")
            return

        self.lbl_status.config(text="Status: loading...")
        self.txt.delete("1.0", "end")
        self.txt.insert("end", "Loading device info...\n")

        def work():
            sdk = None
            try:
                sdk = PullSDK(self.app.cfg.plcomm_dll_path, logger=self.app.logger)
                sdk.connect(
                    ip=ip,
                    port=port,
                    timeout_ms=timeout_ms,
                    password=password,
                    platform=platform,
                )

                # 1) GetDeviceParam
                raw = ""
                params: Dict[str, str] = {}
                if sdk.supports_get_device_param():
                    raw = sdk.get_device_param(items=items, initial_size=65536)
                    params = _parse_params_text(raw)
                else:
                    raw = "(GetDeviceParam not available in this plcommpro.dll build)\n"
                    params = {}

                # 2) Some counts (best-effort; may return -1 if not supported)
                counts_lines: List[str] = []
                tables_to_count = [
                    "user",
                    "userauthorize",
                    "transaction",
                    "rtlog",
                    "timezone",
                    "holiday",
                    "templatev10",
                    "templatev9",
                ]
                for t in tables_to_count:
                    try:
                        c = sdk.get_device_data_count(table=t)
                        if c >= 0:
                            counts_lines.append(f"- {t}: {c}")
                    except Exception:
                        pass

                label = self._device_label(dev)

                def apply():
                    self._last_raw = raw

                    self._tree_set(params)

                    self.txt.delete("1.0", "end")
                    self.txt.insert("end", "=== Connection ===\n")
                    self.txt.insert("end", f"{label}\n")
                    self.txt.insert("end", f"timeout={timeout_ms}ms\n\n")

                    self.txt.insert("end", "=== Counts (if supported) ===\n")
                    if counts_lines:
                        self.txt.insert("end", "\n".join(counts_lines) + "\n\n")
                    else:
                        self.txt.insert("end", "(counts not available)\n\n")

                    self.txt.insert("end", "=== Raw GetDeviceParam ===\n")
                    self.txt.insert("end", raw if raw else "(empty)\n")

                    self.lbl_status.config(text=f"Status: loaded ✅ | params={len(params)}")

                self.after(0, apply)

            except Exception as e:
                msg = str(e)

                def apply_err():
                    self.lbl_status.config(text="Status: failed ❌")
                    self.txt.delete("1.0", "end")
                    self.txt.insert("end", f"ERROR: {msg}\n")
                    messagebox.showerror("Device Info", msg)

                self.after(0, apply_err)
            finally:
                try:
                    if sdk:
                        sdk.disconnect()
                except Exception:
                    pass

        threading.Thread(target=work, daemon=True).start()

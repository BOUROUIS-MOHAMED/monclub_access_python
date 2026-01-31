# monclub_access_python/app/ui/pages/device_page.py
from __future__ import annotations

import json
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk, messagebox, simpledialog

from app.core.db import list_sync_devices, list_device_door_presets
from app.core.utils import dict_union_keys
from app.sdk.pullsdk import PullSDK


TABLES = [
    ("User", "user"),
    ("UserAuthorize", "userauthorize"),
    ("Holiday", "holiday"),
    ("Timezone", "timezone"),
    ("Transaction", "transaction"),
    ("FirstCard", "firstcard"),
    ("MultiCard", "multicard"),
    ("InOutFun", "inoutfun"),
    ("TemplateV10", "templatev10"),
]

DEFAULT_TABLE_FIELDS: dict[str, list[str]] = {
    "user": [
        "PIN",
        "Name",
        "CardNo",
        "Password",
        "Privilege",
        "Group",
        "TimeZone",
        "Verify",
        "ViceCard",
        "StartTime",
        "EndTime",
    ],
    "userauthorize": [
        "PIN",
        "DoorID",
        "AuthorizeDoorId",
        "TimeZone",
        "TimeZoneID",
        "StartTime",
        "EndTime",
        "PassType",
        "Valid",
    ],
    "holiday": [
        "HolidayID",
        "HolidayName",
        "StartTime",
        "EndTime",
        "HolidayType",
    ],
    "timezone": [
        "TimezoneID",
        "TimezoneName",
        "SunTime",
        "MonTime",
        "TueTime",
        "WedTime",
        "ThuTime",
        "FriTime",
        "SatTime",
    ],
    "transaction": [
        "CardNo",
        "PIN",
        "VerifyMode",
        "DoorID",
        "EventType",
        "InOutState",
        "Time",
        "WorkCode",
    ],
    "firstcard": [
        "DoorID",
        "PIN",
        "CardNo",
        "StartTime",
        "EndTime",
    ],
    "multicard": [
        "DoorID",
        "GroupID",
        "PIN",
        "CardNo",
        "StartTime",
        "EndTime",
    ],
    "inoutfun": [
        "FunOn",
        "FunMode",
        "FunParam1",
        "FunParam2",
    ],
    "templatev10": [
        "PIN",
        "FingerID",
        "Size",
        "Valid",
        "Template",
    ],
}


class DevicePage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.sdk: PullSDK | None = None

        self._render_token = 0

        # devices
        self._devices: list[dict] = []
        self._device_labels: list[str] = []
        self._device_label_to_device: dict[str, dict] = {}
        self._selected_device: dict | None = None

        # presets
        self._door_presets: list[dict] = []

        # fields selection state (per table)
        self._table_fields_options: dict[str, list[str]] = {k: list(v) for k, v in DEFAULT_TABLE_FIELDS.items()}
        self._fields_selection_by_table: dict[str, dict] = {}  # {"mode": "all"|"list"|"custom", "fields":[...]}

        # ---- Top controls
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=10)

        # Device selector row
        dev_row = ttk.Frame(top)
        dev_row.pack(fill="x")

        ttk.Label(dev_row, text="Device:").pack(side="left", padx=(0, 5))
        self.var_device = tk.StringVar(value="")
        self.cb_device = ttk.Combobox(dev_row, textvariable=self.var_device, values=[], width=55, state="readonly")
        self.cb_device.pack(side="left")
        self.cb_device.bind("<<ComboboxSelected>>", self._on_device_selected)

        ttk.Button(dev_row, text="Reload devices", command=self.reload_devices).pack(side="left", padx=(10, 0))
        ttk.Button(dev_row, text="Connect", command=self.connect).pack(side="left", padx=(10, 0))
        ttk.Button(dev_row, text="Disconnect", command=self.disconnect).pack(side="left", padx=(8, 0))

        # Table/filters row
        tbl_row = ttk.Frame(top)
        tbl_row.pack(fill="x", pady=(10, 0))

        ttk.Label(tbl_row, text="Table:").pack(side="left", padx=(0, 5))
        self.var_table = tk.StringVar(value=TABLES[0][1])
        self.cb_table = ttk.Combobox(
            tbl_row, textvariable=self.var_table, values=[t[1] for t in TABLES], width=18, state="readonly"
        )
        self.cb_table.pack(side="left")
        self.cb_table.bind("<<ComboboxSelected>>", self._on_table_changed)

        ttk.Label(tbl_row, text="Fields:").pack(side="left", padx=(20, 5))
        self.var_fields_display = tk.StringVar(value="*")
        self.fields_btn = ttk.Menubutton(tbl_row, textvariable=self.var_fields_display, width=28)
        self.fields_menu = tk.Menu(self.fields_btn, tearoff=False)
        self.fields_btn["menu"] = self.fields_menu
        self.fields_btn.pack(side="left")

        ttk.Label(tbl_row, text="Filter:").pack(side="left", padx=(20, 5))
        self.var_filter = tk.StringVar(value="")
        ttk.Entry(tbl_row, textvariable=self.var_filter, width=28).pack(side="left")

        ttk.Label(tbl_row, text="Max rows:").pack(side="left", padx=(20, 5))
        self.var_max_rows = tk.StringVar(value="10000")
        self.cb_max_rows = ttk.Combobox(
            tbl_row, textvariable=self.var_max_rows, values=["all", "1000", "5000", "10000"], width=8, state="readonly"
        )
        self.cb_max_rows.pack(side="left")

        ttk.Button(tbl_row, text="Fetch", command=self.fetch).pack(side="left", padx=(20, 0))

        # ---- Door controls row
        door = ttk.LabelFrame(self, text="Door Control (PullSDK ControlDevice)")
        door.pack(fill="x", padx=10, pady=(0, 10))

        # presets area
        presets_frame = ttk.Frame(door)
        presets_frame.pack(fill="x", padx=10, pady=(8, 4))
        presets_frame.columnconfigure(0, weight=1)

        self.lbl_presets = ttk.Label(presets_frame, text="Quick opens: (select a device)")
        self.lbl_presets.grid(row=0, column=0, sticky="w")

        self.presets_buttons_wrap = ttk.Frame(door)
        self.presets_buttons_wrap.pack(fill="x", padx=10, pady=(0, 8))
        self.presets_buttons_wrap.columnconfigure(0, weight=1)

        # manual controls (kept)
        drow = ttk.Frame(door)
        drow.pack(fill="x", padx=10, pady=(0, 8))

        ttk.Label(drow, text="Door #:").pack(side="left")
        self.var_door = tk.StringVar(value="1")
        ttk.Entry(drow, textvariable=self.var_door, width=6).pack(side="left", padx=(6, 14))

        ttk.Label(drow, text="Pulse seconds:").pack(side="left")
        self.var_pulse = tk.StringVar(value="3")
        ttk.Entry(drow, textvariable=self.var_pulse, width=6).pack(side="left", padx=(6, 14))

        ttk.Button(drow, text="Pulse Open", command=self.door_pulse_open).pack(side="left", padx=(0, 8))

        self.lbl_info = ttk.Label(self, text="Not connected.")
        self.lbl_info.pack(fill="x", padx=10)

        # Treeview
        self.tree = ttk.Treeview(self, columns=("__dummy__",), show="headings", height=22)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

        y = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        y.place(in_=self.tree, relx=1.0, rely=0, relheight=1.0, anchor="ne")
        self.tree.configure(yscrollcommand=y.set)

        # init device list + fields menu
        self.reload_devices()
        self._rebuild_fields_menu(self.var_table.get().strip())

    # ---------------- Devices loading ----------------

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

        did = pick("id", "deviceId", "device_id", default=None)

        name = str(pick("name", "deviceName", "device_name", "title", default="(unnamed)"))
        model = str(pick("model", "platform", "devicePlatform", "device_platform", "platForm", default="") or "").strip()

        ip = str(pick("ip", "ipAddress", "ip_address", "host", "address", default="")).strip()
        port = pick("port", "portNumber", "port_number", "port_number_str", "tcpPort", "tcp_port", default=4370)
        password = str(pick("password", "commPassword", "comm_password", "passwd", "devicePassword", default="") or "")
        timeout_ms = pick("timeout_ms", "timeoutMs", "timeout", default=5000)

        try:
            port_i = int(str(port).strip())
        except Exception:
            port_i = 4370
        try:
            timeout_i = int(str(timeout_ms).strip())
        except Exception:
            timeout_i = 5000

        out = {
            "id": did,
            "name": name,
            "model": model,
            "ip": ip,
            "port": port_i,
            "password": password,
            "timeout_ms": timeout_i,
        }
        for k, v in raw.items():
            if k not in out:
                out[k] = v
        return out

    def _device_label(self, d: dict) -> str:
        did = d.get("id")
        name = (d.get("name") or "").strip() or "(unnamed)"
        model = (d.get("model") or "").strip()
        ip = (d.get("ip") or "").strip()
        port = d.get("port")

        parts = []
        if did not in (None, ""):
            try:
                parts.append(f"[{int(did)}] {name}")
            except Exception:
                parts.append(f"[{did}] {name}")
        else:
            parts.append(name)

        if model:
            parts.append(model)
        if ip:
            parts.append(f"{ip}:{port}")
        return " | ".join(parts)

    def reload_devices(self):
        self._devices = []
        self._device_labels = []
        self._device_label_to_device = {}
        self._selected_device = None

        # 1) primary: local sync cache (SQLite)
        src = []
        try:
            src = list_sync_devices() or []
        except Exception:
            src = []

        # 2) fallback: app already exposes devices
        if not src:
            if hasattr(self.app, "devices") and isinstance(getattr(self.app, "devices"), list):
                src = getattr(self.app, "devices")
            elif hasattr(self.app, "get_saved_devices") and callable(getattr(self.app, "get_saved_devices")):
                try:
                    src = self.app.get_saved_devices()
                except Exception:
                    src = []

        # 3) fallback: local file
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
                    src = []

        for item in (src or []):
            if not isinstance(item, dict):
                continue
            d = self._normalize_device(item)
            label = self._device_label(d)
            self._devices.append(d)
            self._device_labels.append(label)
            self._device_label_to_device[label] = d

        # optional fallback entry from cfg
        cfg = getattr(self.app, "cfg", None)
        if cfg and getattr(cfg, "ip", None):
            fallback = {
                "id": getattr(cfg, "selected_device_id", None),
                "name": "Current config",
                "model": getattr(cfg, "platform", "") or "",
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

        if self._device_labels:
            self.var_device.set(self._device_labels[0])
            self._selected_device = self._device_label_to_device.get(self._device_labels[0])
        else:
            self.var_device.set("")
            self._selected_device = None

        self._refresh_door_presets()

    def _on_device_selected(self, _evt=None):
        label = (self.var_device.get() or "").strip()
        self._selected_device = self._device_label_to_device.get(label)
        self._refresh_door_presets()

    # ---------------- Door presets UI ----------------

    def _selected_device_id(self) -> int | None:
        d = self._selected_device or {}
        did = d.get("id")
        if did in (None, ""):
            return None
        try:
            return int(did)
        except Exception:
            return None

    def _refresh_door_presets(self):
        # clear buttons
        for w in list(self.presets_buttons_wrap.winfo_children()):
            try:
                w.destroy()
            except Exception:
                pass

        did = self._selected_device_id()
        if did is None:
            self._door_presets = []
            self.lbl_presets.config(text="Quick opens: (selected device has no id, presets disabled)")
            return

        try:
            presets = list_device_door_presets(did)
            self._door_presets = [
                {
                    "id": int(p.id),
                    "device_id": int(p.device_id),
                    "door_number": int(p.door_number),
                    "pulse_seconds": int(p.pulse_seconds),
                    "door_name": str(p.door_name),
                }
                for p in presets
            ]
        except Exception as e:
            self._door_presets = []
            self.lbl_presets.config(text=f"Quick opens: failed to load presets ({e})")
            return

        if not self._door_presets:
            self.lbl_presets.config(text="Quick opens: no presets saved for this device (configure in Configuration page)")
            return

        self.lbl_presets.config(text=f"Quick opens: {len(self._door_presets)} preset(s)")

        # create buttons (up to 10)
        max_cols = 2
        r = 0
        c = 0

        for p in self._door_presets[:10]:
            title = f"Open {p['door_name']} [{p['door_number']}]"
            btn = ttk.Button(
                self.presets_buttons_wrap,
                text=title,
                command=lambda door=p["door_number"], sec=p["pulse_seconds"]: self._door_preset_open(door, sec),
            )
            btn.grid(row=r, column=c, sticky="ew", padx=4, pady=4)

            c += 1
            if c >= max_cols:
                c = 0
                r += 1

        for col in range(max_cols):
            self.presets_buttons_wrap.columnconfigure(col, weight=1)

    def _door_preset_open(self, door: int, sec: int):
        try:
            sdk = self._require_sdk()
            if not sdk.supports_control_device():
                messagebox.showerror("Door", "ControlDevice not available in this plcommpro.dll build.")
                return
        except Exception as e:
            messagebox.showerror("Door", str(e))
            return

        door = int(door)
        sec = int(sec)
        if door < 1:
            door = 1
        if sec < 1:
            sec = 1
        if sec > 60:
            sec = 60

        def work():
            try:
                rc = sdk.door_pulse_open(door=door, seconds=sec)
                self.after(0, lambda: messagebox.showinfo("Door", f"Pulse Open door={door} sec={sec} -> rc={rc}"))
            except Exception as e:
                self.app.logger.exception("Preset pulse open failed")
                msg = str(e)
                self.after(0, lambda: messagebox.showerror("Door", msg))

        threading.Thread(target=work, daemon=True).start()

    # ---------------- Fields multi-select ----------------

    def _on_table_changed(self, _evt=None):
        table = (self.var_table.get() or "").strip()
        self._rebuild_fields_menu(table)

    def _get_table_field_options(self, table: str) -> list[str]:
        opts = self._table_fields_options.get(table)
        if not opts:
            return ["PIN", "CardNo", "Name", "Time", "DoorID", "VerifyMode"]
        seen = set()
        out = []
        for x in opts:
            x = str(x).strip()
            if x and x not in seen:
                out.append(x)
                seen.add(x)
        return out

    def _save_fields_selection(self, table: str, mode: str, fields: list[str] | None):
        self._fields_selection_by_table[table] = {"mode": mode, "fields": list(fields or [])}

    def _load_fields_selection(self, table: str) -> dict:
        return self._fields_selection_by_table.get(table, {"mode": "all", "fields": []})

    def _rebuild_fields_menu(self, table: str):
        self.fields_menu.delete(0, "end")

        selection = self._load_fields_selection(table)
        mode = selection.get("mode", "all")
        selected_fields = selection.get("fields", []) or []

        self._fields_all_var = tk.BooleanVar(value=(mode == "all"))
        self._field_vars: dict[str, tk.BooleanVar] = {}

        def set_all():
            self._fields_all_var.set(True)
            for v in self._field_vars.values():
                v.set(False)
            self._save_fields_selection(table, "all", [])
            self._update_fields_display(table)

        def any_field_changed():
            if self._fields_all_var.get():
                self._fields_all_var.set(False)

            chosen = [k for k, v in self._field_vars.items() if v.get()]
            if not chosen:
                self._save_fields_selection(table, "all", [])
                self._fields_all_var.set(True)
            else:
                self._save_fields_selection(table, "list", chosen)
            self._update_fields_display(table)

        def custom_fields():
            current = self._load_fields_selection(table)
            default_text = ""
            if current.get("mode") in ("list", "custom"):
                default_text = ",".join(current.get("fields") or [])
            s = simpledialog.askstring("Custom fields", "Enter fields (comma separated):", initialvalue=default_text)
            if s is None:
                return
            parts = [p.strip() for p in s.replace("\t", ",").replace(";", ",").split(",") if p.strip()]
            if not parts:
                set_all()
                return
            self._fields_all_var.set(False)
            for v in self._field_vars.values():
                v.set(False)
            self._save_fields_selection(table, "custom", parts)
            self._update_fields_display(table)

        self.fields_menu.add_checkbutton(label="All (*)", variable=self._fields_all_var, command=set_all)
        self.fields_menu.add_separator()

        for f in self._get_table_field_options(table):
            v = tk.BooleanVar(value=False)
            self._field_vars[f] = v
            self.fields_menu.add_checkbutton(label=f, variable=v, command=any_field_changed)

        self.fields_menu.add_separator()
        self.fields_menu.add_command(label="Custom...", command=custom_fields)

        if mode == "all":
            set_all()
        elif mode in ("list", "custom"):
            self._fields_all_var.set(False)
            for f in selected_fields:
                if f in self._field_vars:
                    self._field_vars[f].set(True)
            self._update_fields_display(table)
        else:
            set_all()

    def _get_fields_string(self, table: str) -> str:
        selection = self._load_fields_selection(table)
        mode = selection.get("mode", "all")
        if mode == "all":
            return "*"

        fields = selection.get("fields") or []
        if not fields:
            return "*"
        return "\t".join(fields)

    def _update_fields_display(self, table: str):
        selection = self._load_fields_selection(table)
        mode = selection.get("mode", "all")
        fields = selection.get("fields") or []

        if mode == "all" or not fields:
            self.var_fields_display.set("*")
            return

        if len(fields) <= 3:
            self.var_fields_display.set(", ".join(fields))
        else:
            self.var_fields_display.set(f"{fields[0]}, {fields[1]}, {fields[2]} (+{len(fields) - 3})")

    # ---------------- helpers ----------------

    def _require_sdk(self) -> PullSDK:
        if not self.sdk:
            raise RuntimeError("Connect first.")
        return self.sdk

    def _parse_int(self, s: str, default: int) -> int:
        try:
            return int((s or "").strip())
        except Exception:
            return default

    def _parse_max_rows(self) -> int:
        s = (self.var_max_rows.get() or "").strip().lower()
        if s == "all":
            return 0
        try:
            n = int(s)
            if n < 0:
                return 10000
            return n
        except Exception:
            return 10000

    def _parse_door(self) -> int:
        door = self._parse_int(self.var_door.get(), 1)
        if door < 1:
            door = 1
        return door

    def _parse_pulse_seconds(self) -> int:
        sec = self._parse_int(self.var_pulse.get(), 3)
        if sec < 1:
            sec = 1
        if sec > 60:
            sec = 60
        return sec

    # ---------------- connect/disconnect ----------------

    def connect(self):
        dev = self._selected_device
        if not dev:
            messagebox.showwarning("Connect", "Select a device first.")
            return

        ip = (dev.get("ip") or "").strip()
        port = int(dev.get("port") or 4370)
        timeout_ms = int(dev.get("timeout_ms") or 5000)
        password = str(dev.get("password") or "")
        model = str(dev.get("model") or "").strip()

        if not ip:
            messagebox.showerror("Connect failed", "Selected device has no IP.")
            return

        try:
            if self.sdk:
                try:
                    self.sdk.disconnect()
                except Exception:
                    pass
                self.sdk = None

            self.sdk = PullSDK(self.app.cfg.plcomm_dll_path, logger=self.app.logger)
            # keep previous behavior: platform is optional; using model as best-effort tag
            self.sdk.connect(ip=ip, port=port, timeout_ms=timeout_ms, password=password, platform=(model or None))

            label = self._device_label(dev)
            self.lbl_info.config(text=f"Connected: {label}")
        except Exception as e:
            messagebox.showerror("Connect failed", str(e))
            self.app.logger.exception("Connect failed")

    def disconnect(self):
        try:
            if self.sdk:
                self.sdk.disconnect()
            self.sdk = None
            self.lbl_info.config(text="Disconnected.")
        except Exception as e:
            messagebox.showerror("Disconnect failed", str(e))

    # ---------------- Door actions ----------------

    def door_pulse_open(self):
        try:
            sdk = self._require_sdk()
            if not sdk.supports_control_device():
                messagebox.showerror("Door", "ControlDevice not available in this plcommpro.dll build.")
                return
            door = self._parse_door()
            sec = self._parse_pulse_seconds()
        except Exception as e:
            messagebox.showerror("Door", str(e))
            return

        def work():
            try:
                rc = sdk.door_pulse_open(door=door, seconds=sec)
                self.after(0, lambda: messagebox.showinfo("Door", f"Pulse Open door={door} sec={sec} -> rc={rc}"))
            except Exception as e:
                self.app.logger.exception("Pulse open failed")
                msg = str(e)
                self.after(0, lambda: messagebox.showerror("Door", msg))

        threading.Thread(target=work, daemon=True).start()

    # ---------------- Table fetch / render ----------------

    def fetch(self):
        if not self.sdk:
            messagebox.showwarning("Not connected", "Connect first.")
            return

        table = (self.var_table.get() or "").strip()
        fields = self._get_fields_string(table)
        flt = (self.var_filter.get() or "").strip()
        max_rows = self._parse_max_rows()

        def work():
            try:
                cnt = self.sdk.get_device_data_count(table=table)
                rows = self.sdk.get_device_data_rows(table=table, fields=fields, filter_expr=flt)

                if rows:
                    keys = dict_union_keys(rows)
                    if keys:
                        self._table_fields_options[table] = list(keys)

                self.app.logger.info(f"Fetched table={table} count_hint={cnt} rows={len(rows)} fields={fields}")
                self.after(0, lambda: self._render(rows, table, cnt, max_rows))
                self.after(0, lambda: self._rebuild_fields_menu(table))
            except Exception as e:
                self.app.logger.exception("Fetch failed")
                msg = str(e)
                self.after(0, lambda m=msg: messagebox.showerror("Fetch failed", m))

        threading.Thread(target=work, daemon=True).start()

    def _render(self, rows, table: str, count_hint: int, max_rows: int):
        self._render_token += 1
        token = self._render_token

        for c in self.tree["columns"]:
            self.tree.heading(c, text="")
        self.tree.delete(*self.tree.get_children())

        if not rows:
            self.lbl_info.config(text=f"{table}: 0 rows (count hint={count_hint})")
            self.tree["columns"] = ("empty",)
            self.tree.heading("empty", text="(empty)")
            self.tree.column("empty", width=800, anchor="w")
            return

        cols = dict_union_keys(rows)
        self.tree["columns"] = cols

        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=140, anchor="w")

        total = len(rows)
        display_rows = rows if max_rows == 0 else rows[:max_rows]

        target = len(display_rows)
        self.lbl_info.config(text=f"{table}: loading {target} / {total} rows (count hint={count_hint}) ...")

        chunk_size = 300

        def insert_chunk(i: int):
            if token != self._render_token:
                return

            end = min(i + chunk_size, target)
            for r in display_rows[i:end]:
                vals = [r.get(c, "") for c in cols]
                self.tree.insert("", "end", values=vals)

            if end < target:
                if end % (chunk_size * 5) == 0 or end == chunk_size:
                    self.lbl_info.config(text=f"{table}: loading {end} / {target} (total {total}) ...")
                self.after(1, lambda: insert_chunk(end))
            else:
                shown = target
                self.lbl_info.config(text=f"{table}: showing {shown} / {total} rows (count hint={count_hint})")

        insert_chunk(0)

# monclub_access_python/app/ui/pages/local_db_page.py
from __future__ import annotations

import json
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Dict, List, Any

from app.core.db import (
    load_sync_cache,
    list_fingerprints,
    list_device_door_presets,
    load_auth_token,
    list_sync_gym_access_credentials,
    list_device_sync_pins,
    load_agent_rtlog_state,
    # Database connection for direct queries
    get_conn
)
from app.sdk.pullsdk import PullSDK, PullSDKError
from app.ui.pages.enroll_page import EnrollFingerprintPopup

# Force authorize door to a fixed door id
AUTHORIZE_DOOR_ID = 15


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


def _to_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return []


def _str(v) -> str:
    if v is None:
        return ""
    return str(v)


def _json_compact(v) -> str:
    try:
        return json.dumps(v, ensure_ascii=False)
    except Exception:
        return str(v)


def _pin_str(v) -> str:
    """
    IMPORTANT: Do NOT normalize pins (no digit extraction, no int conversion).
    We keep the pin EXACT as a string (device expects that).
    """
    if v is None:
        return ""
    return str(v).strip()


def _safe_one_line(s: str) -> str:
    if not s:
        return ""
    # Avoid breaking SetDeviceData format (TAB and CRLF are separators)
    return s.replace("\t", " ").replace("\r", " ").replace("\n", " ").strip()


def _safe_template_text(s: str) -> str:
    """
    Template values should not contain whitespace separators.
    """
    if not s:
        return ""
    return s.replace("\r", "").replace("\n", "").replace("\t", "").strip()


def _fp_summary(fp: dict) -> str:
    """
    compact cell text for a fingerprint dto
    """
    if not isinstance(fp, dict):
        return ""
    fid = fp.get("fingerId")
    ver = fp.get("templateVersion")
    enabled = fp.get("enabled")
    label = fp.get("label") or ""
    ok = "✅" if bool(enabled) else "⛔"
    parts = []
    if fid is not None:
        parts.append(f"F{fid}")
    if ver is not None:
        parts.append(f"v{ver}")
    if label:
        parts.append(label)
    parts.append(ok)
    return " ".join(parts)


def _truncate_text(text: str, max_len: int = 100) -> str:
    """Truncate text for display"""
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def _format_bytes(size: int) -> str:
    """Format bytes to human readable string"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{size:.1f}TB"


class LocalDatabasePage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        self._cached_users: list[dict] = []
        self._cached_memberships: list[dict] = []
        self._cached_devices: list[dict] = []
        self._cached_infras: list[dict] = []
        self._cached_gym_access_credentials: list[dict] = []
        self._cached_fingerprints: list[dict] = []
        self._cached_door_presets: list[dict] = []
        self._cached_rtlog_states: list[dict] = []
        self._cached_device_sync_state: list[dict] = []
        self._cached_access_history: list[dict] = []
        self._cached_auth_state: list[dict] = []

        self._pushed_check_seq = 0  # used to ignore outdated background results

        # map tree item -> user dict (for ENROLL click and PUSH click)
        self._user_item_map: dict[str, dict] = {}

        # device users dropdown (for delete)
        self._device_users_seq = 0
        self._device_users_rows: list[dict] = []
        self._device_users_display_to_pin: dict[str, str] = {}

        # target device selector (from cached devices)
        self._device_display_to_obj: dict[str, dict] = {}
        self.var_target_device = tk.StringVar(value="")

        # Create main container with scrollable notebook
        main_container = ttk.Frame(self)
        main_container.pack(fill="both", expand=True)

        # Add canvas and scrollbar for the notebook
        canvas = tk.Canvas(main_container)
        scrollbar = ttk.Scrollbar(main_container, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        top = ttk.Frame(scrollable_frame)
        top.pack(fill="x", padx=10, pady=10)

        # Control buttons
        control_frame = ttk.Frame(top)
        control_frame.pack(side="left", fill="x", expand=True)

        ttk.Button(control_frame, text="Refresh All", command=self.refresh_all, width=15).pack(side="left", padx=(0, 8))
        ttk.Button(control_frame, text="Sync Now", command=self._sync_now_and_refresh, width=15).pack(side="left",
                                                                                                      padx=(0, 8))
        ttk.Button(control_frame, text="Export All", command=self._export_all_data, width=15).pack(side="left",
                                                                                                   padx=(0, 8))
        ttk.Button(control_frame, text="Stats", command=self._show_stats, width=15).pack(side="left")

        self.lbl = ttk.Label(top, text="Local Database: Ready")
        self.lbl.pack(side="left", padx=12)

        # Right side: target device combobox
        right = ttk.Frame(top)
        right.pack(side="right")

        ttk.Label(right, text="Target device:").pack(side="left")
        self.cmb_target_device = ttk.Combobox(
            right,
            textvariable=self.var_target_device,
            width=52,
            state="readonly",
        )
        self.cmb_target_device.pack(side="left", padx=(8, 0))
        self.cmb_target_device["values"] = []
        self.cmb_target_device.bind("<<ComboboxSelected>>", self._on_target_device_changed)

        # Create notebook with all tabs
        self.nb = ttk.Notebook(scrollable_frame)
        self.nb.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Create all tabs
        self._create_tabs()

        # Users tab specific controls
        self._setup_users_tab_controls()

        # Bind tab change event
        self.nb.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        self.refresh_all()
        self._sync_device_tools_state()

    def _create_tabs(self):
        """Create all database table tabs"""
        # Sync Cache Tabs
        self.tab_meta = ttk.Frame(self.nb)
        self.tab_users = ttk.Frame(self.nb)
        self.tab_memberships = ttk.Frame(self.nb)
        self.tab_devices = ttk.Frame(self.nb)
        self.tab_infras = ttk.Frame(self.nb)
        self.tab_gym_access_credentials = ttk.Frame(self.nb)

        # Local Database Tabs
        self.tab_fingerprints = ttk.Frame(self.nb)
        self.tab_door_presets = ttk.Frame(self.nb)
        self.tab_rtlog_state = ttk.Frame(self.nb)
        self.tab_device_sync = ttk.Frame(self.nb)
        self.tab_access_history = ttk.Frame(self.nb)
        self.tab_auth_state = ttk.Frame(self.nb)
        self.tab_database_info = ttk.Frame(self.nb)

        # Add tabs to notebook
        self.nb.add(self.tab_meta, text="📊 Meta & Cache")
        self.nb.add(self.tab_users, text="👥 Users")
        self.nb.add(self.tab_memberships, text="📋 Memberships")
        self.nb.add(self.tab_devices, text="🔧 Devices")
        self.nb.add(self.tab_infras, text="🏢 Infrastructures")
        self.nb.add(self.tab_gym_access_credentials, text="🔑 Gym Access Creds")
        self.nb.add(self.tab_fingerprints, text="🖐️ Fingerprints")
        self.nb.add(self.tab_door_presets, text="🚪 Door Presets")
        self.nb.add(self.tab_rtlog_state, text="📈 RTLog State")
        self.nb.add(self.tab_device_sync, text="🔄 Device Sync")
        self.nb.add(self.tab_access_history, text="📜 Access History")
        self.nb.add(self.tab_auth_state, text="🔐 Auth State")
        self.nb.add(self.tab_database_info, text="💾 Database Info")

        # Create trees for all tabs
        self._create_tab_trees()

    def _create_tab_trees(self):
        """Create treeviews for all tabs"""
        # Meta tab - Text widget for raw JSON
        self.meta_text = tk.Text(self.tab_meta, height=20, wrap="word")
        scrollbar = ttk.Scrollbar(self.tab_meta, command=self.meta_text.yview)
        self.meta_text.configure(yscrollcommand=scrollbar.set)
        self.meta_text.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y")

        # Users tree (special handling for ENROLL/PUSHED)
        self.tree_users = self._make_tree(self.tab_users, height=25)
        self.tree_users.bind("<Button-1>", self._on_users_tree_click, add=True)

        # Generic trees for other tabs
        self.tree_memberships = self._make_tree(self.tab_memberships)
        self.tree_devices = self._make_tree(self.tab_devices)
        self.tree_infras = self._make_tree(self.tab_infras)
        self.tree_gym_access_credentials = self._make_tree(self.tab_gym_access_credentials)
        self.tree_fingerprints = self._make_tree(self.tab_fingerprints)
        self.tree_door_presets = self._make_tree(self.tab_door_presets)
        self.tree_rtlog_state = self._make_tree(self.tab_rtlog_state)
        self.tree_device_sync = self._make_tree(self.tab_device_sync)
        self.tree_access_history = self._make_tree(self.tab_access_history, height=20)
        self.tree_auth_state = self._make_tree(self.tab_auth_state)

        # Database info tab - multi-column text
        self.db_info_text = tk.Text(self.tab_database_info, height=20, wrap="word")
        db_scrollbar = ttk.Scrollbar(self.tab_database_info, command=self.db_info_text.yview)
        self.db_info_text.configure(yscrollcommand=db_scrollbar.set)
        self.db_info_text.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        db_scrollbar.pack(side="right", fill="y")

    def _setup_users_tab_controls(self):
        """Setup controls for users tab"""
        # Users tab header + controls
        self.users_top = ttk.Frame(self.tab_users)
        self.users_top.pack(fill="x", padx=10, pady=(10, 0))

        self.btn_refresh_pushed = ttk.Button(
            self.users_top,
            text="Refresh PUSHED Status",
            command=self.refresh_users_pushed_status,
        )
        self.btn_refresh_pushed.pack(side="left", padx=(0, 10))

        self.btn_push_selected = ttk.Button(
            self.users_top,
            text="Push Selected User",
            command=self.push_selected_user,
        )
        self.btn_push_selected.pack(side="left", padx=(0, 10))

        self.users_hint = ttk.Label(self.users_top, text="")
        self.users_hint.pack(side="left")

        self.lbl_push = ttk.Label(self.tab_users, text="", foreground="#1a7f37")
        self.lbl_push.pack(anchor="w", padx=10, pady=(6, 0))

        # Device delete controls
        self.device_tools = ttk.LabelFrame(self.tab_users, text="Device Users Management")
        self.device_tools.pack(fill="x", padx=10, pady=(10, 0))

        self.device_tools_row = ttk.Frame(self.device_tools)
        self.device_tools_row.pack(fill="x", padx=10, pady=8)

        self.btn_load_device_users = ttk.Button(
            self.device_tools_row, text="Load Device Users", command=self.load_device_users
        )
        self.btn_load_device_users.pack(side="left", padx=(0, 10))

        ttk.Label(self.device_tools_row, text="Select User:").pack(side="left")
        self.var_device_user = tk.StringVar(value="")
        self.cmb_device_users = ttk.Combobox(self.device_tools_row, textvariable=self.var_device_user, width=50)
        self.cmb_device_users.pack(side="left", padx=8)
        self.cmb_device_users["values"] = []

        self.btn_delete_device_user = ttk.Button(
            self.device_tools_row, text="Delete Selected", command=self.delete_selected_device_user
        )
        self.btn_delete_device_user.pack(side="left", padx=(8, 0))

        self.lbl_device_users = ttk.Label(self.device_tools, text="Not loaded.")
        self.lbl_device_users.pack(anchor="w", padx=10, pady=(0, 8))

    # ---------------- Mode gate ----------------
    def _is_device_mode(self) -> bool:
        """
        Returns True when we have at least one DEVICE-mode device,
        so PullSDK controller tools remain accessible.
        Works in DEVICE_ONLY, MIXED, or legacy fallback.
        """
        try:
            mode = self.app.get_access_global_mode()
            return mode in ("DEVICE_ONLY", "MIXED")
        except Exception:
            pass
        try:
            return bool(self.app.is_device_mode())
        except Exception:
            return (str(getattr(self.app.cfg, "data_mode", "DEVICE")).strip().upper() == "DEVICE")

    def _sync_device_tools_state(self):
        """
        Disable controller actions when not in DEVICE mode.
        """
        enabled = self._is_device_mode()
        state = "normal" if enabled else "disabled"
        try:
            self.btn_refresh_pushed.config(state=state)
        except Exception:
            pass
        try:
            self.btn_push_selected.config(state=state)
        except Exception:
            pass
        try:
            self.btn_load_device_users.config(state=state)
        except Exception:
            pass
        try:
            self.btn_delete_device_user.config(state=state)
        except Exception:
            pass

    # ---------------- Target device helpers ----------------
    def _device_display(self, d: dict) -> str:
        name = _str(_get(d, "deviceName", "name", "DeviceName", default="")).strip()
        platform = _str(_get(d, "platform", "Platform", default="")).strip()

        ip = _str(_get(d, "ip", "ipAddress", "IPAddress", "ip_address", "deviceIp", "host", default="")).strip()
        port = _str(_get(d, "port", "Port", "tcpPort", "devicePort", default="")).strip()

        left = name or platform or "device"
        mid = platform if platform and platform.lower() not in (left or "").lower() else ""
        addr = ""
        if ip:
            addr = ip + (f":{port}" if port else "")
        parts = [p for p in [left, mid, addr] if p]
        return " | ".join(parts) if parts else _json_compact(d)

    def _select_best_device_display(self, values: list[str]) -> str:
        """
        Prefer the current selection if still valid, else auto-select:
        - device name contains 'asp 460' OR platform contains 'zem560_inbio'
        - else first item
        """
        cur = (self.var_target_device.get() or "").strip()
        if cur and cur in values:
            return cur

        for v in values:
            vv = v.lower()
            if "asp 460" in vv or "zem560_inbio" in vv:
                return v

        return values[0] if values else ""

    def _update_target_device_selector(self):
        values: list[str] = []
        mapping: dict[str, dict] = {}

        for d in (self._cached_devices or []):
            if not isinstance(d, dict):
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

    def _resolve_target_conn(self) -> tuple[str, int, int, str]:
        """
        Returns (ip, port, timeout_ms, password) for the selected device.
        If no device selected/available, fall back to app.cfg values.
        """
        d = self._get_selected_device()

        # defaults from config (fallback)
        ip = str(getattr(self.app.cfg, "ip", "") or "").strip()
        port = self._parse_int(getattr(self.app.cfg, "port", 0) or 0, 0)
        timeout_ms = self._parse_int(getattr(self.app.cfg, "timeout_ms", 3000) or 3000, 3000)
        password = str(getattr(self.app.cfg, "password", "") or "")

        if d:
            ip2 = _str(_get(d, "ip", "ipAddress", "IPAddress", "ip_address", "deviceIp", "host", default="")).strip()
            if ip2:
                ip = ip2

            port2 = _get(d, "port", "Port", "tcpPort", "devicePort", default=None)
            if port2 is not None and str(port2).strip() != "":
                port = self._parse_int(port2, port)

            pw2 = _get(d, "commPassword", "CommPassword", "password", "passwd", "Passwd", default=None)
            if pw2 is not None and str(pw2).strip() != "":
                password = str(pw2)

            t2 = _get(d, "timeoutMs", "timeout_ms", "timeout", default=None)
            if t2 is not None and str(t2).strip() != "":
                timeout_ms = self._parse_int(t2, timeout_ms)

        return ip, port, timeout_ms, password

    def _require_selected_device_or_warn(self) -> bool:
        """
        Gate all controller connections by DEVICE mode.
        """
        if not self._is_device_mode():
            messagebox.showwarning("Device mode", "Device mode is OFF. Controller connection is disabled.")
            return False

        if self._cached_devices:
            if not self._get_selected_device():
                messagebox.showwarning("Device", "Please select a target device first.")
                return False
        return True

    def _on_target_device_changed(self, _evt=None):
        # Reset device users dropdown (since it's device-specific)
        try:
            self._device_users_seq += 1
            self._device_users_rows = []
            self._device_users_display_to_pin = {}
            self.cmb_device_users["values"] = []
            self.var_device_user.set("")
            self.lbl_device_users.config(text="Not loaded.")
        except Exception:
            pass

        # Refresh PUSHED state only in DEVICE mode
        if self._is_device_mode():
            try:
                self.refresh_users_pushed_status()
            except Exception:
                pass

    # ---------------- Basic UI helpers ----------------
    def _sync_now_and_refresh(self):
        try:
            self.app.request_sync_now()
        except Exception:
            pass
        self.after(700, self.refresh_all)

    def _on_tab_changed(self, _evt=None):
        self._sync_device_tools_state()
        try:
            sel = self.nb.select()
            if sel == str(self.tab_users) and self._is_device_mode():
                self.refresh_users_pushed_status()
        except Exception:
            pass

    def _make_tree(self, parent, height: int = 24) -> ttk.Treeview:
        container = ttk.Frame(parent)
        container.pack(fill="both", expand=True)

        tree = ttk.Treeview(container, columns=("__dummy__",), show="headings", height=height, selectmode="browse")
        tree.pack(side="left", fill="both", expand=True)

        y = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
        y.pack(side="right", fill="y")
        tree.configure(yscrollcommand=y.set)

        # Add horizontal scrollbar
        x = ttk.Scrollbar(container, orient="horizontal", command=tree.xview)
        x.pack(side="bottom", fill="x")
        tree.configure(xscrollcommand=x.set)

        return tree

    def _clear_tree(self, tree: ttk.Treeview):
        for c in tree["columns"]:
            tree.heading(c, text="")
        tree.delete(*tree.get_children())

    def _render_tree_generic(self, tree: ttk.Treeview, rows: list[dict], max_rows: int = 1000):
        self._clear_tree(tree)

        if not rows:
            tree["columns"] = ("empty",)
            tree.heading("empty", text="(empty)")
            tree.column("empty", width=1000, anchor="w")
            tree.insert("", "end", values=("No data available.",))
            return

        # Limit rows for performance
        display_rows = rows[:max_rows]

        cols: list[str] = []
        seen = set()
        for r in display_rows[:50]:  # Sample first 50 rows for columns
            for k in r.keys():
                if k not in seen:
                    cols.append(k)
                    seen.add(k)

        tree["columns"] = cols
        for c in cols:
            tree.heading(c, text=c)
            # Auto-size columns based on content
            tree.column(c, width=min(200, max(80, len(c) * 8)), anchor="w")

        for r in display_rows:
            vals = []
            for c in cols:
                v = r.get(c, "")
                if isinstance(v, (dict, list)):
                    v = _json_compact(v)
                    v = _truncate_text(v, 80)
                elif isinstance(v, str) and len(v) > 100:
                    v = _truncate_text(v, 100)
                vals.append("" if v is None else str(v))
            tree.insert("", "end", values=vals)

        if len(rows) > max_rows:
            tree.insert("", "end", values=[f"... and {len(rows) - max_rows} more rows"])

    def _normalize_list(self, lst):
        out = []
        for x in lst:
            if isinstance(x, dict):
                out.append(x)
            else:
                try:
                    out.append(dict(x.__dict__))
                except Exception:
                    out.append({"value": str(x)})
        return out

    def _cached_user_device_pin(self, u: dict) -> str:
        """
        Pin used on controller MUST be the activeMembershipId.
        Fallback to membershipId if activeMembershipId is missing.
        """
        pin = _get(u, "activeMembershipId", "active_membership_id", "membershipId", "membership_id", default=None)
        return _pin_str(pin)

    def _resolve_current_device_door_ids(self) -> list[int]:
        """
        Force authorize door to a fixed door id.
        """
        return [int(AUTHORIZE_DOOR_ID)]

    def _collect_user_templates(self, u: dict, pin: str) -> list[dict]:
        """
        Collect fingerprint templates for pushing.
        Priority:
          1) user['fingerprints'] from sync cache (if templateData exists)
          2) local SQLite fingerprints table (by pin) as fallback
        Output items:
          { fingerId:int, templateVersion:int, templateData:str, templateSize:int }
        """
        out: list[dict] = []

        fps = u.get("fingerprints")
        if isinstance(fps, list):
            for fp in fps:
                if not isinstance(fp, dict):
                    continue
                if fp.get("enabled") is False:
                    continue
                fid = fp.get("fingerId")
                ver = fp.get("templateVersion")
                td = fp.get("templateData")
                ts = fp.get("templateSize")
                if fid is None or td is None:
                    continue
                try:
                    fid_i = int(str(fid).strip())
                except Exception:
                    continue
                try:
                    ver_i = int(str(ver).strip()) if ver is not None else 10
                except Exception:
                    ver_i = 10
                try:
                    ts_i = int(str(ts).strip()) if ts is not None else len(str(td))
                except Exception:
                    ts_i = len(str(td))
                td_s = _safe_template_text(str(td))
                if not td_s:
                    continue
                out.append(
                    {
                        "fingerId": fid_i,
                        "templateVersion": ver_i,
                        "templateData": td_s,
                        "templateSize": ts_i,
                    }
                )

        if out:
            best: dict[int, dict] = {}
            for x in out:
                best[int(x["fingerId"])] = x
            return [best[k] for k in sorted(best.keys())]

        try:
            recs = list_fingerprints()
        except Exception:
            recs = []

        best_local: dict[int, dict] = {}
        for r in recs:
            rp = _pin_str(getattr(r, "pin", ""))
            if not rp or rp != pin:
                continue
            try:
                fid_i = int(getattr(r, "finger_id"))
            except Exception:
                continue
            td = _safe_template_text(getattr(r, "template_data", "") or "")
            if not td:
                continue
            try:
                ver_i = int(getattr(r, "template_version"))
            except Exception:
                ver_i = 10
            try:
                ts_i = int(getattr(r, "template_size"))
            except Exception:
                ts_i = len(td)
            best_local[fid_i] = {
                "fingerId": fid_i,
                "templateVersion": ver_i,
                "templateData": td,
                "templateSize": ts_i,
            }

        return [best_local[k] for k in sorted(best_local.keys())]

    def _render_users_tree(self, users_rows: list[dict]):
        """
        Users:
        - Adds ENROLL + PUSHED
        - Adds PIN_USED (Pin=ActiveMembershipId) column
        - Adds FP1..FPn columns (based on max fingerprints count)
        """
        tree = self.tree_users
        self._clear_tree(tree)
        self._user_item_map = {}

        if not users_rows:
            tree["columns"] = ("empty",)
            tree.heading("empty", text="(empty)")
            tree.column("empty", width=1000, anchor="w")
            tree.insert("", "end", values=("No cached users.",))
            self.users_hint.config(text="")
            return

        max_fps = 0
        for u in users_rows:
            fps = u.get("fingerprints") or []
            if isinstance(fps, list):
                max_fps = max(max_fps, len(fps))

        fp_cols = [f"FP{i + 1}" for i in range(max_fps)]

        if max_fps == 0:
            self.users_hint.config(text="No fingerprints columns (empty for all users)")
        else:
            self.users_hint.config(text=f"Fingerprints columns: {max_fps}")

        preferred = [
            "ENROLL",
            "PUSHED",
            "PIN_USED",
            "userId",
            "activeMembershipId",
            "membershipId",
            "fullName",
            "phone",
            "email",
            "validFrom",
            "validTo",
            "firstCardId",
            "secondCardId",
        ]

        seen = set()
        all_cols: list[str] = []
        for r in users_rows[:400]:
            for k in r.keys():
                if k == "fingerprints":
                    continue
                if k not in seen:
                    all_cols.append(k)
                    seen.add(k)

        ordered: list[str] = []
        for c in preferred:
            if (c in seen or c in ("ENROLL", "PUSHED", "PIN_USED")) and c not in ordered:
                ordered.append(c)

        for c in all_cols:
            if c not in ordered and c not in fp_cols:
                ordered.append(c)

        ordered += fp_cols

        if "ENROLL" not in ordered:
            ordered.insert(0, "ENROLL")
        if "PUSHED" not in ordered:
            ordered.insert(1, "PUSHED")
        if "PIN_USED" not in ordered:
            ordered.insert(2, "PIN_USED")

        tree["columns"] = ordered

        for c in ordered:
            tree.heading(c, text=c)
            if c == "ENROLL":
                w = 90
            elif c == "PUSHED":
                w = 90
            elif c == "PIN_USED":
                w = 130
            elif c.startswith("FP"):
                w = 160
            else:
                w = 190
            tree.column(c, width=w, anchor="w")

        for u in users_rows[:5000]:
            row = dict(u)
            row["ENROLL"] = "Enroll"
            row["PIN_USED"] = self._cached_user_device_pin(u)

            fps = row.pop("fingerprints", None)
            if not isinstance(fps, list):
                fps = []

            for i, col in enumerate(fp_cols):
                row[col] = _fp_summary(fps[i]) if i < len(fps) else ""

            vals = []
            for c in ordered:
                v = row.get(c, "")
                if isinstance(v, (dict, list)):
                    v = _json_compact(v)
                vals.append("" if v is None else str(v))

            item_id = tree.insert("", "end", values=vals)
            self._user_item_map[item_id] = dict(u)

    def _on_users_tree_click(self, event):
        tree = self.tree_users
        region = tree.identify("region", event.x, event.y)
        if region != "cell":
            return

        col = tree.identify_column(event.x)  # '#1'...
        row = tree.identify_row(event.y)
        if not row or not col:
            return

        try:
            idx = int(col.replace("#", "")) - 1
            col_name = tree["columns"][idx]
        except Exception:
            return

        if col_name != "ENROLL":
            return

        u = self._user_item_map.get(row)
        if not u:
            return

        def after_saved():
            try:
                self.app.request_sync_now()
            except Exception:
                pass
            self.after(900, self.refresh_all)

        EnrollFingerprintPopup(self.winfo_toplevel(), self.app, u, on_saved=after_saved)

    # -------------------- PUSH: user + authorize + templates --------------------
    def _push_userauthorize(self, sdk: PullSDK, *, pin: str, door_ids: list[int]) -> tuple[int, str | None]:
        if not door_ids:
            door_ids = [AUTHORIZE_DOOR_ID]

        patterns = [
            lambda door: f"Pin={pin}\tDoorID={door}\tTimeZone=1",
            lambda door: f"Pin={pin}\tDoorID={door}\tTimeZoneID=1",
            lambda door: f"Pin={pin}\tAuthorizeDoorId={door}\tAuthorizeTimezoneId=1",
        ]

        last_err = None
        chosen = None

        first_door = door_ids[0]
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
                data = patterns[chosen](door) + "\r\n"
                sdk.set_device_data(table="userauthorize", data=data, options="")
                ok_count += 1
            except Exception as ex:
                last_err = str(ex)

        return ok_count, last_err

    def _push_templates(self, sdk: PullSDK, *, pin: str, templates: list[dict]) -> tuple[int, list[str]]:
        errs: list[str] = []
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
            ver = int(t.get("templateVersion") or 10)
            size = int(t.get("templateSize") or 0)
            tpl = _safe_template_text(str(t.get("templateData") or ""))

            if not tpl:
                continue

            preferred_tables = ["templatev10", "template"] if ver >= 10 else ["template", "templatev10"]

            bodies = [
                lambda: f"Pin={pin}\tFingerID={fid}\tValid=1\tSize={size}\tTemplate={tpl}",
                lambda: f"Pin={pin}\tFingerID={fid}\tValid=1\tSize={size}\tTmp={tpl}",
                lambda: f"Pin={pin}\tFingerID={fid}\tValid=1\tSize={size}\tTemplate={tpl}",
                lambda: f"Pin={pin}\tFingerID={fid}\tSize={size}\tTemplate={tpl}",
                lambda: f"Pin={pin}\tFingerID={fid}\tTemplate={tpl}",
            ]

            pushed = False
            for table in preferred_tables:
                for bfn in bodies:
                    body = bfn()
                    if try_set(table, body):
                        pushed = True
                        break
                if pushed:
                    break

            if pushed:
                ok += 1
            else:
                errs.append(f"FingerID={fid}: failed to push template (no compatible schema/table)")

        compact_errs = []
        seen = set()
        for e in errs:
            if e not in seen:
                compact_errs.append(e)
                seen.add(e)

        return ok, compact_errs

    def push_selected_user(self):
        if not self._require_selected_device_or_warn():
            return

        sel = self.tree_users.selection()
        if not sel:
            messagebox.showwarning("Push user", "Select a user row first.")
            return

        item_id = sel[0]
        u = self._user_item_map.get(item_id)
        if not u:
            messagebox.showerror("Push user", "Selected row is invalid.")
            return

        pin = self._cached_user_device_pin(u)
        if not pin:
            messagebox.showerror(
                "Push user",
                "This user has no ActiveMembershipId in cache.\nCannot push to device.",
            )
            return

        if not pin.isdigit():
            messagebox.showerror(
                "Push user",
                f"ActiveMembershipId is not numeric: {pin}\nController Pin usually must be digits only.",
            )
            return

        name = _safe_one_line(_pin_str(_get(u, "fullName", "name", default=""))) or f"U{pin}"
        card = _pin_str(_get(u, "firstCardId", "cardNo", "card", "CardNo", default=""))

        templates = self._collect_user_templates(u, pin)
        door_ids = self._resolve_current_device_door_ids()

        d = self._get_selected_device()
        dev_label = self._device_display(d) if d else "(config device)"
        ip, port, timeout_ms, password = self._resolve_target_conn()

        ok = messagebox.askyesno(
            "Push user",
            "Push this user to device?\n\n"
            f"Target device = {dev_label}\n"
            f"Target ip:port = {ip}:{port}\n"
            f"PIN (ActiveMembershipId) = {pin}\n"
            f"Name = {name}\n"
            f"Card = {card or '(none)'}\n"
            f"Authorize doors = {door_ids}\n"
            f"Templates to push = {len(templates)}",
        )
        if not ok:
            return

        self.lbl_push.config(text=f"Pushing user... Pin={pin}", foreground="#1a7f37")

        def work():
            err: str | None = None
            auth_info = ""
            fp_info = ""
            fp_errs: list[str] = []

            try:
                sdk = PullSDK(self.app.cfg.plcomm_dll_path, logger=self.app.logger)
                sdk.connect(ip=ip, port=port, timeout_ms=timeout_ms, password=password)

                pairs = [f"Pin={pin}", f"Name={name}"]
                if card:
                    pairs.append(f"CardNo={card}")
                data_user = "\t".join(pairs) + "\r\n"
                sdk.set_device_data(table="user", data=data_user, options="")

                try:
                    pushed_auth_count, auth_err = self._push_userauthorize(sdk, pin=pin, door_ids=door_ids)
                    if auth_err:
                        auth_info = f"Authorize: {pushed_auth_count} written (warn: {auth_err})"
                    else:
                        auth_info = f"Authorize: {pushed_auth_count} written ✅"
                except Exception as ex:
                    auth_info = f"Authorize: failed (warn: {ex})"

                if templates:
                    pushed_fp_count, fp_errs = self._push_templates(sdk, pin=pin, templates=templates)
                    if fp_errs:
                        fp_info = f"Templates: {pushed_fp_count}/{len(templates)} pushed (some failed)"
                    else:
                        fp_info = f"Templates: {pushed_fp_count}/{len(templates)} pushed ✅"
                else:
                    fp_info = "Templates: none found in cache/local DB"

            except Exception as ex:
                err = str(ex)
                try:
                    self.app.logger.exception(f"Push user failed: {ex}")
                except Exception:
                    pass
            finally:
                try:
                    if "sdk" in locals() and sdk:
                        sdk.disconnect()
                except Exception:
                    pass

            def apply():
                if err:
                    self.lbl_push.config(text=f"Push failed: {err}", foreground="#b00020")
                    messagebox.showerror("Push user", f"Push failed:\n{err}")
                    return

                msg = (
                    "User pushed to device.\n\n"
                    f"Target: {dev_label}\n"
                    f"Target ip:port: {ip}:{port}\n"
                    f"PIN used: {pin}\n"
                    f"{auth_info}\n"
                    f"{fp_info}\n"
                )

                if fp_errs:
                    extra = "\n".join(fp_errs[:6])
                    if len(fp_errs) > 6:
                        extra += f"\n... ({len(fp_errs) - 6} more)"
                    msg += "\nFingerprint push warnings:\n" + extra

                self.lbl_push.config(text=f"Pushed ✅  Pin={pin}", foreground="#1a7f37")
                messagebox.showinfo("Push user", msg)
                self.refresh_users_pushed_status()

            self.after(0, apply)

        threading.Thread(target=work, daemon=True).start()

    # -------------------- load device users for delete dropdown --------------------
    def load_device_users(self):
        if not self._require_selected_device_or_warn():
            return

        self._device_users_seq += 1
        seq = self._device_users_seq

        self.lbl_device_users.config(text="Loading device users...")
        self._device_users_rows = []
        self._device_users_display_to_pin = {}
        self.cmb_device_users["values"] = []

        d = self._get_selected_device()
        dev_label = self._device_display(d) if d else "(config device)"
        ip, port, timeout_ms, password = self._resolve_target_conn()

        def work():
            rows: list[dict] = []
            err_text: str | None = None

            try:
                sdk = PullSDK(self.app.cfg.plcomm_dll_path, logger=self.app.logger)
                sdk.connect(ip=ip, port=port, timeout_ms=timeout_ms, password=password)
                rows = sdk.get_device_data_rows(
                    table="user",
                    fields="Pin;Name;CardNo",
                    filter_expr="",
                    options="",
                    initial_size=1_048_576,
                )
            except Exception as ex:
                err_text = str(ex)
                rows = []
                try:
                    if "sdk" in locals() and sdk:
                        rows = sdk.get_device_data_rows(
                            table="user",
                            fields="Pin",
                            filter_expr="",
                            options="",
                            initial_size=1_048_576,
                        )
                        err_text = err_text + " (fallback: Pin-only OK)"
                except Exception as ex2:
                    err_text = err_text + f" (fallback failed: {ex2})"
            finally:
                try:
                    if "sdk" in locals() and sdk:
                        sdk.disconnect()
                except Exception:
                    pass

            def apply():
                if seq != self._device_users_seq:
                    return

                self._device_users_rows = rows

                values: list[str] = []
                mapping: dict[str, str] = {}

                for r in rows:
                    pin_raw = _pin_str(r.get("Pin") or r.get("pin") or "")
                    if not pin_raw:
                        continue

                    name = _pin_str(r.get("Name") or r.get("name") or "")
                    card = _pin_str(r.get("CardNo") or r.get("cardno") or r.get("Card") or "")

                    parts = [pin_raw]
                    if name:
                        parts.append(name)
                    if card:
                        parts.append(card)
                    disp = " | ".join(parts)

                    values.append(disp)
                    mapping[disp] = pin_raw

                self._device_users_display_to_pin = mapping
                self.cmb_device_users["values"] = values

                if values:
                    self.var_device_user.set(values[0])
                    msg = f"Loaded {len(values)} device users from: {dev_label}"
                    if err_text:
                        msg += f"  Note: {err_text}"
                    self.lbl_device_users.config(text=msg)
                else:
                    self.var_device_user.set("")
                    msg = f"No device users loaded from: {dev_label}"
                    if err_text:
                        msg += f"  Error: {err_text}"
                    self.lbl_device_users.config(text=msg)

            self.after(0, apply)

        threading.Thread(target=work, daemon=True).start()

    def delete_selected_device_user(self):
        if not self._require_selected_device_or_warn():
            return

        sel = (self.var_device_user.get() or "").strip()
        if not sel:
            messagebox.showwarning("Delete user", "Please load and select a user first.")
            return

        pin = self._device_users_display_to_pin.get(sel)
        if not pin:
            pin = _pin_str(sel.split("|")[0])

        if not pin:
            messagebox.showerror("Delete user", f"Could not parse Pin from selection: {sel}")
            return

        d = self._get_selected_device()
        dev_label = self._device_display(d) if d else "(config device)"
        ip, port, timeout_ms, password = self._resolve_target_conn()

        ok = messagebox.askyesno(
            "Delete user",
            f"Target device: {dev_label}\n"
            f"Target ip:port: {ip}:{port}\n\n"
            f"Delete Pin={pin} from device?\n\nThis will delete from:\n- templatev10/template\n- userauthorize\n- user",
        )
        if not ok:
            return

        self.lbl_device_users.config(text=f"Deleting Pin={pin} ...")

        def work():
            err: str | None = None
            try:
                sdk = PullSDK(self.app.cfg.plcomm_dll_path, logger=self.app.logger)
                sdk.connect(ip=ip, port=port, timeout_ms=timeout_ms, password=password)

                cond = f"Pin={pin}"

                try:
                    if sdk.supports_delete_device_data():
                        sdk.delete_device_data(table="templatev10", data=cond, options="")
                    else:
                        raise PullSDKError("DeleteDeviceData not available")
                except Exception as ex:
                    self.app.logger.warning(f"Delete templatev10 failed (ignored): {ex}")

                try:
                    if sdk.supports_delete_device_data():
                        sdk.delete_device_data(table="template", data=cond, options="")
                except Exception as ex:
                    self.app.logger.warning(f"Delete template failed (ignored): {ex}")

                try:
                    if sdk.supports_delete_device_data():
                        sdk.delete_device_data(table="userauthorize", data=cond, options="")
                    else:
                        raise PullSDKError("DeleteDeviceData not available")
                except Exception as ex:
                    self.app.logger.warning(f"Delete userauthorize failed (ignored): {ex}")

                if sdk.supports_delete_device_data():
                    sdk.delete_device_data(table="user", data=cond, options="")
                else:
                    raise PullSDKError("DeleteDeviceData not available in this DLL build.")

            except Exception as ex:
                err = str(ex)
                try:
                    self.app.logger.exception(f"Delete user failed: {ex}")
                except Exception:
                    pass
            finally:
                try:
                    if "sdk" in locals() and sdk:
                        sdk.disconnect()
                except Exception:
                    pass

            def apply():
                if err:
                    self.lbl_device_users.config(text=f"Delete failed: {err}")
                    messagebox.showerror("Delete user", f"Delete failed:\n{err}")
                else:
                    self.lbl_device_users.config(text=f"Deleted Pin={pin} ✅")
                    self.load_device_users()
                    self.refresh_users_pushed_status()

            self.after(0, apply)

        threading.Thread(target=work, daemon=True).start()

    # -------------------- Database query helpers --------------------
    def _query_table(self, table_name: str, limit: int = 1000) -> List[Dict[str, Any]]:
        """Query any table from the database"""
        try:
            with get_conn() as conn:
                cursor = conn.execute(f"SELECT * FROM {table_name} LIMIT ?", (limit,))
                columns = [description[0] for description in cursor.description]
                rows = []
                for row in cursor.fetchall():
                    rows.append(dict(zip(columns, row)))
                return rows
        except Exception as e:
            self.app.logger.error(f"Error querying table {table_name}: {e}")
            return []

    def _get_database_info(self) -> Dict[str, Any]:
        """Get database schema information"""
        info = {}
        try:
            with get_conn() as conn:
                # Get all tables
                tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
                info["tables"] = [table[0] for table in tables]

                # Get table sizes
                table_sizes = {}
                for table in info["tables"]:
                    count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    table_sizes[table] = count
                info["table_sizes"] = table_sizes

                # Get database size
                import os
                from app.core.utils import DB_PATH
                if os.path.exists(DB_PATH):
                    info["db_size"] = _format_bytes(os.path.getsize(DB_PATH))
                else:
                    info["db_size"] = "Unknown"

        except Exception as e:
            info["error"] = str(e)
        return info

    # -------------------- New feature methods --------------------
    def _export_all_data(self):
        """Export all database tables to JSON file"""
        try:
            from tkinter import filedialog
            import os

            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                initialfile="monclub_database_export.json"
            )

            if not filename:
                return

            export_data = {}

            # Export all tables
            tables = [
                "sync_cache", "sync_meta", "sync_users", "sync_memberships",
                "sync_devices", "sync_infrastructures", "sync_gym_access_credentials",
                "fingerprints", "device_door_presets", "agent_rtlog_state",
                "access_history", "device_sync_state", "auth_state"
            ]

            for table in tables:
                export_data[table] = self._query_table(table, limit=10000)

            # Add metadata
            export_data["_metadata"] = {
                "export_date": self.app.core.utils.now_iso(),
                "app_version": getattr(self.app.cfg, "version", "unknown"),
                "total_records": sum(len(export_data[t]) for t in tables)
            }

            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2)

            messagebox.showinfo("Export Complete", f"Database exported to:\n{filename}")

        except Exception as e:
            messagebox.showerror("Export Failed", f"Error during export:\n{str(e)}")

    def _show_stats(self):
        """Show database statistics"""
        try:
            info = self._get_database_info()

            stats_text = "📊 DATABASE STATISTICS\n"
            stats_text += "=" * 50 + "\n\n"

            if "error" in info:
                stats_text += f"Error: {info['error']}\n"
                return

            stats_text += f"Database Size: {info.get('db_size', 'Unknown')}\n"
            stats_text += f"Number of Tables: {len(info.get('tables', []))}\n\n"

            stats_text += "TABLE SIZES:\n"
            stats_text += "-" * 30 + "\n"

            table_sizes = info.get('table_sizes', {})
            for table in sorted(table_sizes.keys()):
                count = table_sizes[table]
                stats_text += f"{table:<25} : {count:>6} records\n"

            # Show in messagebox
            messagebox.showinfo("Database Statistics", stats_text)

        except Exception as e:
            messagebox.showerror("Statistics Error", f"Error getting statistics:\n{str(e)}")

    # -------------------- Refresh all data --------------------
    def refresh_all(self):
        """Refresh data from all database tables"""
        self._sync_device_tools_state()

        # Load sync cache
        cache = load_sync_cache()

        # Update status label
        mode_txt = "DEVICE" if self._is_device_mode() else "AGENT"
        self.lbl.config(text=f"Local Database: Refreshing... | Mode: {mode_txt}")

        def load_data():
            """Load data in background thread"""
            try:
                # 1. Load sync cache data
                if cache:
                    contract_status = _get(cache, "contract_status", "contractStatus", default=None)
                    contract_end_date = _get(cache, "contract_end_date", "contractEndDate", default="")
                    last_sync_at = _get(cache, "last_sync_at", "lastSyncAt", "saved_at", "savedAt", default="")

                    users = self._normalize_list(_to_list(_get(cache, "users", default=[])))
                    memberships = self._normalize_list(_to_list(_get(cache, "membership", "memberships", default=[])))
                    devices = self._normalize_list(_to_list(_get(cache, "devices", default=[])))
                    infrastructures = self._normalize_list(
                        _to_list(_get(cache, "infrastructures", "infrastructure", default=[])))
                    gym_access_credentials = list_sync_gym_access_credentials()
                else:
                    contract_status = None
                    contract_end_date = ""
                    last_sync_at = ""
                    users = []
                    memberships = []
                    devices = []
                    infrastructures = []
                    gym_access_credentials = []

                # 2. Load other database tables
                fingerprints = list_fingerprints()
                door_presets = []
                rtlog_states = []
                device_sync_state = []
                access_history = []
                auth_state = []

                try:
                    # Convert fingerprints to dicts
                    fps_dicts = []
                    for fp in fingerprints:
                        if hasattr(fp, '__dict__'):
                            fps_dicts.append(fp.__dict__)
                        elif isinstance(fp, dict):
                            fps_dicts.append(fp)

                    # Load door presets (all devices)
                    with get_conn() as conn:
                        rows = conn.execute(
                            "SELECT * FROM device_door_presets ORDER BY device_id, door_number").fetchall()
                        door_presets = [dict(row) for row in rows]

                        # Load rtlog states
                        rows = conn.execute("SELECT * FROM agent_rtlog_state").fetchall()
                        rtlog_states = [dict(row) for row in rows]

                        # Load device sync state
                        rows = conn.execute("SELECT * FROM device_sync_state").fetchall()
                        device_sync_state = [dict(row) for row in rows]

                        # Load access history (limited)
                        rows = conn.execute(
                            "SELECT * FROM access_history ORDER BY created_at DESC LIMIT 500").fetchall()
                        access_history = [dict(row) for row in rows]

                        # Load auth state
                        rows = conn.execute("SELECT * FROM auth_state").fetchall()
                        auth_state = [dict(row) for row in rows]

                except Exception as e:
                    self.app.logger.error(f"Error loading database tables: {e}")

                # 3. Get database info
                db_info = self._get_database_info()

                # Update UI in main thread
                def update_ui():
                    # Update caches
                    self._cached_users = users
                    self._cached_memberships = memberships
                    self._cached_devices = devices
                    self._cached_infras = infrastructures
                    self._cached_gym_access_credentials = gym_access_credentials
                    self._cached_fingerprints = fps_dicts
                    self._cached_door_presets = door_presets
                    self._cached_rtlog_states = rtlog_states
                    self._cached_device_sync_state = device_sync_state
                    self._cached_access_history = access_history
                    self._cached_auth_state = auth_state

                    # Update target device selector
                    self._update_target_device_selector()

                    # Update Meta tab
                    self.meta_text.delete("1.0", "end")
                    if cache:
                        self.meta_text.insert("end", f"contractStatus: {_str(contract_status)}\n")
                        self.meta_text.insert("end", f"contractEndDate: {_str(contract_end_date)}\n")
                        if last_sync_at:
                            self.meta_text.insert("end", f"lastSyncAt: {_str(last_sync_at)}\n")
                        self.meta_text.insert("end", "\n")

                        # Show raw cache
                        self.meta_text.insert("end", "Sync Cache Content:\n")
                        self.meta_text.insert("end", "=" * 40 + "\n")
                        cache_dict = {
                            "users_count": len(users),
                            "memberships_count": len(memberships),
                            "devices_count": len(devices),
                            "infrastructures_count": len(infrastructures),
                            "gym_access_credentials_count": len(gym_access_credentials)
                        }
                        self.meta_text.insert("end", json.dumps(cache_dict, indent=2, ensure_ascii=False))
                    else:
                        self.meta_text.insert("end",
                                              "No cached getSyncData yet.\nClick 'Sync now' or wait for the timer.\n")

                    # Update Users tab
                    users_with_unknown = []
                    for u in users:
                        uu = dict(u)
                        uu["PUSHED"] = "?"
                        users_with_unknown.append(uu)
                    self._render_users_tree(users_with_unknown)

                    # Update other sync cache tabs
                    self._render_tree_generic(self.tree_memberships, memberships)
                    self._render_tree_generic(self.tree_devices, devices)
                    self._render_tree_generic(self.tree_infras, infrastructures)
                    self._render_tree_generic(self.tree_gym_access_credentials, gym_access_credentials)

                    # Update local database tabs
                    self._render_tree_generic(self.tree_fingerprints, fps_dicts)
                    self._render_tree_generic(self.tree_door_presets, door_presets)
                    self._render_tree_generic(self.tree_rtlog_state, rtlog_states)
                    self._render_tree_generic(self.tree_device_sync, device_sync_state)
                    self._render_tree_generic(self.tree_access_history, access_history)
                    self._render_tree_generic(self.tree_auth_state, auth_state)

                    # Update Database Info tab
                    self.db_info_text.delete("1.0", "end")
                    if "error" not in db_info:
                        self.db_info_text.insert("end", "📊 DATABASE OVERVIEW\n")
                        self.db_info_text.insert("end", "=" * 50 + "\n\n")

                        self.db_info_text.insert("end", f"Database Size: {db_info.get('db_size', 'Unknown')}\n")
                        self.db_info_text.insert("end", f"Total Tables: {len(db_info.get('tables', []))}\n\n")

                        self.db_info_text.insert("end", "TABLE SUMMARY:\n")
                        self.db_info_text.insert("end", "-" * 40 + "\n")

                        table_sizes = db_info.get('table_sizes', {})
                        for table in sorted(table_sizes.keys()):
                            count = table_sizes[table]
                            self.db_info_text.insert("end", f"• {table:<30}: {count:>6} records\n")

                        self.db_info_text.insert("end", "\n\n")
                        self.db_info_text.insert("end", "ALL TABLES:\n")
                        self.db_info_text.insert("end", "-" * 40 + "\n")

                        for i, table in enumerate(sorted(db_info.get('tables', [])), 1):
                            self.db_info_text.insert("end", f"{i:2}. {table}\n")
                    else:
                        self.db_info_text.insert("end", f"Error: {db_info.get('error')}")

                    # Update status label
                    td = self._get_selected_device()
                    td_label = self._device_display(td) if td else "(no device)"

                    total_records = (
                            len(users) + len(memberships) + len(devices) + len(infrastructures) +
                            len(gym_access_credentials) + len(fps_dicts) + len(door_presets) +
                            len(rtlog_states) + len(device_sync_state) + len(access_history) + len(auth_state)
                    )

                    self.lbl.config(
                        text=(
                            f"Local Database ✅ | "
                            f"Total Records: {total_records} | "
                            f"Target: {td_label} | "
                            f"Mode: {mode_txt}"
                        )
                    )

                    # Refresh PUSHED status if in device mode
                    if users and self._is_device_mode():
                        self.refresh_users_pushed_status()

                self.after(0, update_ui)

            except Exception as e:
                self.app.logger.error(f"Error in refresh_all: {e}")

                def show_error():
                    messagebox.showerror("Refresh Error", f"Error refreshing data:\n{str(e)}")
                    self.lbl.config(text="Local Database: Error refreshing")

                self.after(0, show_error)

        # Start loading in background thread
        threading.Thread(target=load_data, daemon=True).start()

    def refresh_users_pushed_status(self):
        """
        Background:
        - Connect to selected device (ONLY in DEVICE mode)
        - Get device users list (Pin)
        - Compare to cached users by ActiveMembershipId
          EXACT STRING compare (NO normalization)
        Update users tree with PUSHED column:
          ? if connection failed / mode off
          ✔️ if exists
          ❌ if not
        """
        if not self._cached_users:
            return

        if not self._is_device_mode():
            users_out: list[dict] = []
            for u in self._cached_users:
                uu = dict(u)
                uu["PUSHED"] = "?"
                users_out.append(uu)
            self._render_users_tree(users_out)
            return

        if not self._require_selected_device_or_warn():
            return

        self._pushed_check_seq += 1
        seq = self._pushed_check_seq

        ip, port, timeout_ms, password = self._resolve_target_conn()

        def work():
            dev_pins: set[str] | None = None
            try:
                sdk = PullSDK(self.app.cfg.plcomm_dll_path, logger=self.app.logger)
                sdk.connect(ip=ip, port=port, timeout_ms=timeout_ms, password=password)
                dev_rows = sdk.get_device_data_rows(
                    table="user",
                    fields="Pin",
                    filter_expr="",
                    options="",
                    initial_size=1048576,
                )
                pins = set()
                for r in dev_rows:
                    p = _pin_str(r.get("Pin") or r.get("pin") or "")
                    if p:
                        pins.add(p)
                dev_pins = pins
            except Exception as ex:
                dev_pins = None
                try:
                    self.app.logger.exception(f"Local DB PUSHED check failed: {ex}")
                except Exception:
                    pass
            finally:
                try:
                    if "sdk" in locals() and sdk:
                        sdk.disconnect()
                except Exception:
                    pass

            def apply():
                if seq != self._pushed_check_seq:
                    return

                users_out: list[dict] = []
                for u in self._cached_users:
                    pin = self._cached_user_device_pin(u)

                    if dev_pins is None:
                        pushed = "?"
                    else:
                        pushed = "✔️" if (pin and pin in dev_pins) else "❌"

                    uu = dict(u)
                    uu["PUSHED"] = pushed
                    users_out.append(uu)

                self._render_users_tree(users_out)

            self.after(0, apply)

        threading.Thread(target=work, daemon=True).start()
from __future__ import annotations

import json
import threading
import tkinter as tk
from tkinter import ttk

from app.core.db import load_sync_cache
from app.sdk.pullsdk import PullSDK
from app.ui.pages.enroll_page import EnrollFingerprintPopup


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


def _pin_to_int(v) -> int | None:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    digits = "".join(ch for ch in s if ch.isdigit())
    if not digits:
        return None
    try:
        return int(digits)
    except Exception:
        return None


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


class LocalDatabasePage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        self._cached_users: list[dict] = []
        self._cached_memberships: list[dict] = []
        self._cached_devices: list[dict] = []
        self._cached_infras: list[dict] = []

        self._pushed_check_seq = 0  # used to ignore outdated background results

        # map tree item -> user dict (for ENROLL click)
        self._user_item_map: dict[str, dict] = {}

        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=10)

        ttk.Button(top, text="Refresh", command=self.refresh_all).pack(side="left", padx=(0, 8))
        ttk.Button(top, text="Sync now", command=self._sync_now_and_refresh).pack(side="left", padx=(0, 8))
        self.lbl = ttk.Label(top, text="Local DB: ready")
        self.lbl.pack(side="left", padx=12)

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_meta = ttk.Frame(self.nb)
        self.tab_users = ttk.Frame(self.nb)
        self.tab_memberships = ttk.Frame(self.nb)
        self.tab_devices = ttk.Frame(self.nb)
        self.tab_infras = ttk.Frame(self.nb)

        self.nb.add(self.tab_meta, text="Meta")
        self.nb.add(self.tab_users, text="Users")
        self.nb.add(self.tab_memberships, text="Memberships")
        self.nb.add(self.tab_devices, text="Devices")
        self.nb.add(self.tab_infras, text="Infrastructures")

        # Meta widgets
        self.meta_text = tk.Text(self.tab_meta, height=12)
        self.meta_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Users tab header + tree
        self.users_top = ttk.Frame(self.tab_users)
        self.users_top.pack(fill="x", padx=10, pady=(10, 0))

        ttk.Button(self.users_top, text="Refresh PUSHED status", command=self.refresh_users_pushed_status).pack(
            side="left", padx=(0, 10)
        )
        self.users_hint = ttk.Label(self.users_top, text="")
        self.users_hint.pack(side="left")

        self.tree_users = self._make_tree(self.tab_users)

        # Other trees
        self.tree_memberships = self._make_tree(self.tab_memberships)
        self.tree_devices = self._make_tree(self.tab_devices)
        self.tree_infras = self._make_tree(self.tab_infras)

        # click handler for ENROLL column
        self.tree_users.bind("<Button-1>", self._on_users_tree_click, add=True)

        # When switching tabs -> if Users tab, refresh PUSHED status
        self.nb.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        self.refresh_all()

    def _sync_now_and_refresh(self):
        try:
            self.app.request_sync_now()
        except Exception:
            pass
        self.after(700, self.refresh_all)

    def _on_tab_changed(self, _evt=None):
        try:
            sel = self.nb.select()
            if sel == str(self.tab_users):
                self.refresh_users_pushed_status()
        except Exception:
            pass

    def _make_tree(self, parent) -> ttk.Treeview:
        container = ttk.Frame(parent)
        container.pack(fill="both", expand=True)

        tree = ttk.Treeview(container, columns=("__dummy__",), show="headings", height=24)
        tree.pack(side="left", fill="both", expand=True)

        y = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
        y.pack(side="right", fill="y")
        tree.configure(yscrollcommand=y.set)
        return tree

    def _clear_tree(self, tree: ttk.Treeview):
        for c in tree["columns"]:
            tree.heading(c, text="")
        tree.delete(*tree.get_children())

    def _render_tree_generic(self, tree: ttk.Treeview, rows: list[dict]):
        self._clear_tree(tree)

        if not rows:
            tree["columns"] = ("empty",)
            tree.heading("empty", text="(empty)")
            tree.column("empty", width=1000, anchor="w")
            tree.insert("", "end", values=("No cached rows.",))
            return

        cols: list[str] = []
        seen = set()
        for r in rows[:400]:
            for k in r.keys():
                if k not in seen:
                    cols.append(k)
                    seen.add(k)

        tree["columns"] = cols
        for c in cols:
            tree.heading(c, text=c)
            tree.column(c, width=190, anchor="w")

        for r in rows[:5000]:
            vals = []
            for c in cols:
                v = r.get(c, "")
                if isinstance(v, (dict, list)):
                    v = _json_compact(v)
                vals.append("" if v is None else str(v))
            tree.insert("", "end", values=vals)

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

    def _render_users_tree(self, users_rows: list[dict]):
        """
        Users:
        - Adds ENROLL + PUSHED
        - Adds FP1..FPn columns (based on max fingerprints count)
        - Fixes missing user data by keeping the normalized keys (userId/membershipId/fullName...)
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

        # compute max fingerprints count
        max_fps = 0
        for u in users_rows:
            fps = u.get("fingerprints") or []
            if isinstance(fps, list):
                max_fps = max(max_fps, len(fps))

        fp_cols = [f"FP{i+1}" for i in range(max_fps)]

        if max_fps == 0:
            self.users_hint.config(text="No fingerprints columns (empty for all users)")
        else:
            self.users_hint.config(text=f"Fingerprints columns: {max_fps}")

        # preferred order first
        preferred = [
            "ENROLL",
            "PUSHED",
            "userId",
            "membershipId",
            "fullName",
            "phone",
            "email",
            "validFrom",
            "validTo",
            "firstCardId",
            "secondCardId",
        ]

        # union keys excluding raw fingerprints list (we expand it)
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
            if c in seen and c not in ordered:
                ordered.append(c)

        # add remaining non-fp columns
        for c in all_cols:
            if c not in ordered and c not in fp_cols:
                ordered.append(c)

        # append fingerprints cols at the end
        ordered += fp_cols

        # ensure ENROLL + PUSHED always exist
        if "ENROLL" not in ordered:
            ordered.insert(0, "ENROLL")
        if "PUSHED" not in ordered:
            ordered.insert(1, "PUSHED")

        tree["columns"] = ordered

        for c in ordered:
            tree.heading(c, text=c)
            if c == "ENROLL":
                w = 90
            elif c == "PUSHED":
                w = 90
            elif c.startswith("FP"):
                w = 160
            else:
                w = 190
            tree.column(c, width=w, anchor="w")

        # insert rows
        for u in users_rows[:5000]:
            # build row dict -> expand fingerprints
            row = dict(u)
            row["ENROLL"] = "Enroll"

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
            self._user_item_map[item_id] = dict(u)  # store original normalized user dict

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
            # re-sync then refresh UI
            try:
                self.app.request_sync_now()
            except Exception:
                pass
            self.after(900, self.refresh_all)

        EnrollFingerprintPopup(self.winfo_toplevel(), self.app, u, on_saved=after_saved)

    def refresh_all(self):
        cache = load_sync_cache()

        if not cache:
            self.meta_text.delete("1.0", "end")
            self.meta_text.insert("end", "No cached getSyncData yet.\nClick 'Sync now' or wait for the timer.\n")
            self._render_users_tree([])
            self._render_tree_generic(self.tree_memberships, [])
            self._render_tree_generic(self.tree_devices, [])
            self._render_tree_generic(self.tree_infras, [])
            self.lbl.config(text="Local DB: no sync cache yet")
            return

        # Meta
        contract_status = _get(cache, "contract_status", "contractStatus", default=None)
        contract_end_date = _get(cache, "contract_end_date", "contractEndDate", default="")
        last_sync_at = _get(cache, "last_sync_at", "lastSyncAt", "saved_at", "savedAt", default="")

        self.meta_text.delete("1.0", "end")
        self.meta_text.insert("end", f"contractStatus: {_str(contract_status)}\n")
        self.meta_text.insert("end", f"contractEndDate: {_str(contract_end_date)}\n")
        if last_sync_at:
            self.meta_text.insert("end", f"lastSyncAt: {_str(last_sync_at)}\n")
        self.meta_text.insert("end", "\n")

        users = self._normalize_list(_to_list(_get(cache, "users", default=[])))
        memberships = self._normalize_list(_to_list(_get(cache, "membership", "memberships", default=[])))
        devices = self._normalize_list(_to_list(_get(cache, "devices", default=[])))
        infrastructures = self._normalize_list(_to_list(_get(cache, "infrastructures", "infrastructure", default=[])))

        self._cached_users = users
        self._cached_memberships = memberships
        self._cached_devices = devices
        self._cached_infras = infrastructures

        # Render Users with placeholder PUSHED='?'
        users_with_unknown = []
        for u in users:
            uu = dict(u)
            uu["PUSHED"] = "?"
            users_with_unknown.append(uu)

        self._render_users_tree(users_with_unknown)
        self._render_tree_generic(self.tree_memberships, memberships)
        self._render_tree_generic(self.tree_devices, devices)
        self._render_tree_generic(self.tree_infras, infrastructures)

        self.lbl.config(
            text=f"Local DB ✅ | users={len(users)} memberships={len(memberships)} devices={len(devices)} infrastructures={len(infrastructures)}"
        )

        if users:
            self.refresh_users_pushed_status()

    def refresh_users_pushed_status(self):
        """
        Background:
        - Connect to device
        - Get device users list (Pin)
        - Compare to cached users by userId (numeric compare => works even if device pins are 8-digit padded)
        Update users tree with PUSHED column:
          ? if connection failed
          ✔️ if exists
          ❌ if not
        """
        if not self._cached_users:
            return

        self._pushed_check_seq += 1
        seq = self._pushed_check_seq

        def work():
            dev_pin_ints: set[int] | None = None
            try:
                sdk = PullSDK(self.app.cfg.plcomm_dll_path, logger=self.app.logger)
                sdk.connect(
                    ip=self.app.cfg.ip,
                    port=self.app.cfg.port,
                    timeout_ms=self.app.cfg.timeout_ms,
                    password=self.app.cfg.password,
                )
                dev_rows = sdk.get_device_data_rows(
                    table="user",
                    fields="Pin",
                    filter_expr="",
                    options="",
                    initial_size=1_048_576,
                )
                pins_ints = set()
                for r in dev_rows:
                    p = (r.get("Pin") or r.get("pin") or "").strip()
                    pi = _pin_to_int(p)
                    if pi is not None:
                        pins_ints.add(pi)
                dev_pin_ints = pins_ints
            except Exception as ex:
                dev_pin_ints = None
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
                    uid = _get(u, "userId", "userid", "id", "user_id", default=None)
                    uid_int = _pin_to_int(uid)

                    if dev_pin_ints is None:
                        pushed = "?"
                    else:
                        pushed = "✔️" if (uid_int is not None and uid_int in dev_pin_ints) else "❌"

                    uu = dict(u)
                    uu["PUSHED"] = pushed
                    users_out.append(uu)

                self._render_users_tree(users_out)

            self.after(0, apply)

        threading.Thread(target=work, daemon=True).start()

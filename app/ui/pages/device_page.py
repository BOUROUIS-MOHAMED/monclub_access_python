from __future__ import annotations

import threading
import tkinter as tk
from tkinter import ttk, messagebox

from app.core.utils import dict_union_keys
from app.sdk.pullsdk import PullSDK, PullSDKError


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


class DevicePage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.sdk: PullSDK | None = None

        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=10)

        ttk.Button(top, text="Connect", command=self.connect).pack(side="left", padx=(0, 8))
        ttk.Button(top, text="Disconnect", command=self.disconnect).pack(side="left", padx=(0, 8))

        ttk.Label(top, text="Table:").pack(side="left", padx=(20, 5))
        self.var_table = tk.StringVar(value=TABLES[0][1])
        cb = ttk.Combobox(top, textvariable=self.var_table, values=[t[1] for t in TABLES], width=18, state="readonly")
        cb.pack(side="left")

        ttk.Label(top, text="Fields:").pack(side="left", padx=(20, 5))
        self.var_fields = tk.StringVar(value="*")
        ttk.Entry(top, textvariable=self.var_fields, width=18).pack(side="left")

        ttk.Label(top, text="Filter:").pack(side="left", padx=(20, 5))
        self.var_filter = tk.StringVar(value="")
        ttk.Entry(top, textvariable=self.var_filter, width=28).pack(side="left")

        ttk.Button(top, text="Fetch", command=self.fetch).pack(side="left", padx=(20, 0))

        self.lbl_info = ttk.Label(self, text="Not connected.")
        self.lbl_info.pack(fill="x", padx=10)

        # Treeview
        self.tree = ttk.Treeview(self, columns=("__dummy__",), show="headings", height=22)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

        y = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        y.place(in_=self.tree, relx=1.0, rely=0, relheight=1.0, anchor="ne")
        self.tree.configure(yscrollcommand=y.set)

    def connect(self):
        try:
            self.sdk = PullSDK(self.app.cfg.plcomm_dll_path, logger=self.app.logger)
            self.sdk.connect(
                ip=self.app.cfg.ip,
                port=self.app.cfg.port,
                timeout_ms=self.app.cfg.timeout_ms,
                password=self.app.cfg.password,
            )
            self.lbl_info.config(text=f"Connected to {self.app.cfg.ip}:{self.app.cfg.port}")
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

    def fetch(self):
        if not self.sdk:
            messagebox.showwarning("Not connected", "Connect first.")
            return

        table = self.var_table.get().strip()
        fields = self.var_fields.get().strip() or "*"
        flt = self.var_filter.get().strip()

        def work():
            try:
                cnt = self.sdk.get_device_data_count(table=table)
                rows = self.sdk.get_device_data_rows(table=table, fields=fields, filter_expr=flt)
                self.app.logger.info(f"Fetched table={table} count_hint={cnt} rows={len(rows)}")
                self.after(0, lambda: self._render(rows, table, cnt))
            except Exception as e:
                self.app.logger.exception("Fetch failed")
                self.after(0, lambda: messagebox.showerror("Fetch failed", str(e)))

        threading.Thread(target=work, daemon=True).start()

    def _render(self, rows, table: str, count_hint: int):
        # clear
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

        for r in rows[:5000]:  # safeguard
            vals = [r.get(c, "") for c in cols]
            self.tree.insert("", "end", values=vals)

        self.lbl_info.config(text=f"{table}: showing {min(len(rows),5000)} / {len(rows)} rows (count hint={count_hint})")

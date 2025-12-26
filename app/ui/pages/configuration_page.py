from __future__ import annotations

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from app.sdk.pullsdk import PullSDK, PullSDKError
from app.sdk.zkfinger import ZKFinger


class ConfigurationPage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        self.columnconfigure(1, weight=1)

        # Controller fields
        ttk.Label(self, text="Controller connection", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky="w", padx=10, pady=(10, 5), columnspan=3)

        self.var_ip = tk.StringVar(value=self.app.cfg.ip)
        self.var_port = tk.StringVar(value=str(self.app.cfg.port))
        self.var_timeout = tk.StringVar(value=str(self.app.cfg.timeout_ms))
        self.var_passwd = tk.StringVar(value=self.app.cfg.password)

        self._row_entry(1, "IP address:", self.var_ip)
        self._row_entry(2, "Port:", self.var_port)
        self._row_entry(3, "Timeout (ms):", self.var_timeout)
        self._row_entry(4, "Comm password:", self.var_passwd, show="*")

        # Template settings
        ttk.Label(self, text="Fingerprint template settings", font=("Segoe UI", 12, "bold")).grid(row=5, column=0, sticky="w", padx=10, pady=(16, 5), columnspan=3)

        self.var_tpl_ver = tk.StringVar(value=str(self.app.cfg.template_version))
        self.var_tpl_enc = tk.StringVar(value=self.app.cfg.template_encoding)

        ttk.Label(self, text="Template version (9/10):").grid(row=6, column=0, sticky="w", padx=10, pady=4)
        ttk.Combobox(self, textvariable=self.var_tpl_ver, values=["9", "10"], width=10, state="readonly").grid(row=6, column=1, sticky="w", padx=10, pady=4)

        ttk.Label(self, text="Template encoding:").grid(row=7, column=0, sticky="w", padx=10, pady=4)
        ttk.Combobox(self, textvariable=self.var_tpl_enc, values=["base64", "hex"], width=10, state="readonly").grid(row=7, column=1, sticky="w", padx=10, pady=4)

        # DLL paths
        ttk.Label(self, text="DLL paths", font=("Segoe UI", 12, "bold")).grid(row=8, column=0, sticky="w", padx=10, pady=(16, 5), columnspan=3)

        self.var_plcomm = tk.StringVar(value=self.app.cfg.plcomm_dll_path)
        self.var_zkfp = tk.StringVar(value=self.app.cfg.zkfp_dll_path)

        self._row_path(9, "plcommpro.dll path:", self.var_plcomm)
        self._row_path(10, "zkfp.dll path:", self.var_zkfp)

        # Checker
        ttk.Label(self, text="DLL checker", font=("Segoe UI", 12, "bold")).grid(row=11, column=0, sticky="w", padx=10, pady=(16, 5), columnspan=3)

        btns = ttk.Frame(self)
        btns.grid(row=12, column=0, columnspan=3, sticky="w", padx=10, pady=6)
        ttk.Button(btns, text="Save config", command=self.on_save).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Check PullSDK DLL", command=self.check_pullsdk).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Check ZKFinger DLL", command=self.check_zkfinger).pack(side="left", padx=(0, 8))

        self.lbl_status = ttk.Label(self, text="Status: ready", foreground="#444")
        self.lbl_status.grid(row=13, column=0, columnspan=3, sticky="w", padx=10, pady=8)

    def _row_entry(self, r, label, var, show=None):
        ttk.Label(self, text=label).grid(row=r, column=0, sticky="w", padx=10, pady=4)
        e = ttk.Entry(self, textvariable=var, show=show)
        e.grid(row=r, column=1, sticky="ew", padx=10, pady=4, columnspan=2)

    def _row_path(self, r, label, var):
        ttk.Label(self, text=label).grid(row=r, column=0, sticky="w", padx=10, pady=4)
        e = ttk.Entry(self, textvariable=var)
        e.grid(row=r, column=1, sticky="ew", padx=10, pady=4)
        ttk.Button(self, text="Browse", command=lambda: self._browse_dll(var)).grid(row=r, column=2, sticky="w", padx=10, pady=4)

    def _browse_dll(self, var):
        p = filedialog.askopenfilename(title="Select DLL", filetypes=[("DLL files", "*.dll"), ("All files", "*.*")])
        if p:
            var.set(p)

    def on_save(self):
        try:
            self.app.cfg.ip = self.var_ip.get().strip()
            self.app.cfg.port = int(self.var_port.get().strip())
            self.app.cfg.timeout_ms = int(self.var_timeout.get().strip())
            self.app.cfg.password = self.var_passwd.get()

            self.app.cfg.template_version = int(self.var_tpl_ver.get())
            self.app.cfg.template_encoding = self.var_tpl_enc.get().strip()

            self.app.cfg.plcomm_dll_path = self.var_plcomm.get().strip()
            self.app.cfg.zkfp_dll_path = self.var_zkfp.get().strip()

            self.app.persist_config()
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

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import ttk, messagebox

from app.api.monclub_api import ApiEndpoints, MonClubApi
from app.core.db import save_auth_token


class LoginPage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        card = ttk.Frame(self, padding=20)
        card.grid(row=0, column=0, sticky="nsew")
        card.columnconfigure(1, weight=1)

        ttk.Label(card, text="MonClub Access - Login", font=("Segoe UI", 16, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 16)
        )

        self.var_email = tk.StringVar(value=self.app.cfg.login_email or "")
        self.var_password = tk.StringVar(value="")

        ttk.Label(card, text="Email:").grid(row=1, column=0, sticky="w", pady=6)
        ttk.Entry(card, textvariable=self.var_email, width=40).grid(row=1, column=1, sticky="ew", pady=6)

        ttk.Label(card, text="Password:").grid(row=2, column=0, sticky="w", pady=6)
        ttk.Entry(card, textvariable=self.var_password, show="*", width=40).grid(row=2, column=1, sticky="ew", pady=6)

        btns = ttk.Frame(card)
        btns.grid(row=3, column=0, columnspan=2, sticky="w", pady=(16, 0))

        ttk.Button(btns, text="Login", command=self.login).pack(side="left", padx=(0, 10))
        ttk.Button(btns, text="Close", command=self.app.destroy).pack(side="left")

        self.lbl = ttk.Label(card, text="Status: please login")
        self.lbl.grid(row=4, column=0, columnspan=2, sticky="w", pady=(16, 0))

        info = ttk.Label(
            card,
            text=(
                "Note:\n"
                "• Token is stored locally (encrypted on Windows via DPAPI) and used as Bearer token.\n"
                "• getSyncData does NOT send gymId (backend should resolve gym from token).\n"
            ),
            foreground="#555",
        )
        info.grid(row=5, column=0, columnspan=2, sticky="w", pady=(12, 0))

    def _api(self) -> MonClubApi:
        endpoints = ApiEndpoints(
            login_url=self.app.cfg.api_login_url,
            sync_url=self.app.cfg.api_sync_url,
            create_user_fingerprint_url=self.app.cfg.api_create_user_fingerprint_url,  # ✅ FIX
        )
        return MonClubApi(endpoints=endpoints, logger=self.app.logger)

    def login(self):
        email = self.var_email.get().strip()
        password = self.var_password.get()

        if not email or not password:
            messagebox.showerror("Login", "Email and password are required.")
            return

        self.app.cfg.login_email = email
        self.app.persist_config()

        self.lbl.config(text="Status: logging in...")

        def work():
            try:
                api = self._api()
                token = api.login(email=email, password=password)
                save_auth_token(email=email, token=token)

                self.app.logger.info("Login OK: token saved.")
                self.after(0, lambda: self._on_login_ok(email))
                self.app.request_sync_now()
            except Exception as ex:
                msg = str(ex)
                self.app.logger.exception("Login failed")
                self.after(0, lambda m=msg: messagebox.showerror("Login failed", m))
                self.after(0, lambda: self.lbl.config(text="Status: login failed ❌"))

        threading.Thread(target=work, daemon=True).start()

    def _on_login_ok(self, email: str):
        self.lbl.config(text=f"Status: logged in ✅ ({email})")
        messagebox.showinfo("Login", "Login success. Token saved securely.")
        self.app.evaluate_access_and_redirect()

from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class RestrictedPage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        header = ttk.Frame(self, padding=18)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)

        ttk.Label(header, text="Access Restricted", font=("Segoe UI", 16, "bold")).grid(
            row=0, column=0, sticky="w"
        )

        body = ttk.Frame(self, padding=(18, 0, 18, 18))
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)

        self.txt = tk.Text(body, height=12, wrap="word")
        self.txt.grid(row=0, column=0, sticky="nsew", pady=(10, 10))
        self.txt.insert("end", "No restriction reason yet.\n")
        self.txt.config(state="disabled")

        btns = ttk.Frame(body)
        btns.grid(row=1, column=0, sticky="w")

        ttk.Button(btns, text="Login", command=self.go_login).pack(side="left", padx=(0, 10))
        ttk.Button(btns, text="Close App", command=self.app.destroy).pack(side="left")

    def set_reasons(self, reasons: list[str]):
        self.txt.config(state="normal")
        self.txt.delete("1.0", "end")

        if not reasons:
            self.txt.insert("end", "No restriction.\n")
        else:
            self.txt.insert("end", "You cannot use the application right now for the following reason(s):\n\n")
            for r in reasons:
                self.txt.insert("end", f"• {r}\n")

        self.txt.config(state="disabled")

    def go_login(self):
        # For safety: force token removal and go login
        self.app.force_login()

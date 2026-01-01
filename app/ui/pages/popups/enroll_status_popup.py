from __future__ import annotations

import threading
import tkinter as tk
from tkinter import ttk
from typing import Optional


class EnrollStatusPopup(tk.Toplevel):
    """
    Small status UI shown on the PC when dashboard triggers enrollment.
    """

    def __init__(self, parent, *, title: str = "Enrollment"):
        super().__init__(parent)
        self.title(title)
        self.geometry("720x420")
        self.resizable(True, True)

        self.cancel_event = threading.Event()

        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        header.columnconfigure(0, weight=1)

        self.var_step = tk.StringVar(value="Starting...")
        ttk.Label(header, textvariable=self.var_step, font=("Segoe UI", 12, "bold")).grid(
            row=0, column=0, sticky="w"
        )

        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 8))
        self.progress.start(10)

        body = ttk.Frame(self)
        body.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 8))
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)

        self.txt = tk.Text(body, height=12, wrap="word")
        self.txt.grid(row=0, column=0, sticky="nsew")
        self.txt.configure(state="disabled")

        sb = ttk.Scrollbar(body, command=self.txt.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.txt.configure(yscrollcommand=sb.set)

        footer = ttk.Frame(self)
        footer.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 12))
        footer.columnconfigure(0, weight=1)

        self.btn_cancel = ttk.Button(footer, text="Cancel", command=self.cancel)
        self.btn_cancel.grid(row=0, column=0, sticky="w")

        self.btn_close = ttk.Button(footer, text="Close", command=self._close)
        self.btn_close.grid(row=0, column=1, sticky="e")

        self.protocol("WM_DELETE_WINDOW", self.cancel)

    def cancel(self) -> None:
        self.cancel_event.set()
        try:
            self.btn_cancel.configure(state="disabled")
        except Exception:
            pass
        self.set_step("Cancelling... (wait)")

    def _close(self) -> None:
        # let the worker decide; closing UI doesn't stop the device unless canceled
        try:
            self.destroy()
        except Exception:
            pass

    def set_step(self, s: str) -> None:
        self.after(0, lambda: self.var_step.set(s))

    def log(self, line: str) -> None:
        def _write():
            self.txt.configure(state="normal")
            self.txt.insert("end", line.rstrip() + "\n")
            self.txt.see("end")
            self.txt.configure(state="disabled")

        self.after(0, _write)

    def success(self, msg: str) -> None:
        self.set_step(msg)
        self.log(msg)
        try:
            self.progress.stop()
        except Exception:
            pass

    def fail(self, msg: str) -> None:
        self.set_step("❌ " + msg)
        self.log("ERROR: " + msg)
        try:
            self.progress.stop()
        except Exception:
            pass

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from pathlib import Path

from app.core.utils import LOG_DIR


class LogsPage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=10)

        ttk.Button(top, text="Open log file location", command=self.open_log_dir).pack(side="left", padx=(0, 8))
        ttk.Button(top, text="Clear screen", command=self.clear).pack(side="left", padx=(0, 8))

        self.txt = tk.Text(self, wrap="none")
        self.txt.pack(fill="both", expand=True, padx=10, pady=10)

        y = ttk.Scrollbar(self, orient="vertical", command=self.txt.yview)
        y.pack(side="right", fill="y")
        self.txt.configure(yscrollcommand=y.set)

    def append_log(self, line: str):
        self.txt.insert("end", line + "\n")
        self.txt.see("end")

    def clear(self):
        self.txt.delete("1.0", "end")

    def open_log_dir(self):
        # Windows only
        try:
            import os
            os.startfile(str(Path(LOG_DIR)))
        except Exception:
            pass

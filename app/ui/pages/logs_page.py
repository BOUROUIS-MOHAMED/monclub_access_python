# monclub_access_python/app/ui/pages/logs_page.py
# app/ui/pages/logs_page.py
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from pathlib import Path

from app.core.utils import LOG_DIR


def _extract_level(line: str) -> str:
    """
    Expected format: "%(asctime)s | %(levelname)s | %(message)s"
    """
    try:
        parts = line.split("|", 2)
        if len(parts) >= 2:
            lvl = parts[1].strip().upper()
            if lvl:
                return lvl
    except Exception:
        pass
    return "INFO"


class LogsPage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        self._buffer: list[tuple[str, str]] = []  # (LEVEL, LINE)
        self._max_lines = 20000

        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=10)

        ttk.Button(top, text="Open log file location", command=self.open_log_dir).pack(side="left", padx=(0, 8))
        ttk.Button(top, text="Clear screen", command=self.clear).pack(side="left", padx=(0, 14))

        ttk.Label(top, text="Type:").pack(side="left")
        self.var_level = tk.StringVar(value="ALL")
        self.cmb_level = ttk.Combobox(
            top,
            textvariable=self.var_level,
            state="readonly",
            width=12,
            values=["ALL", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        )
        self.cmb_level.pack(side="left", padx=(6, 8))
        self.cmb_level.bind("<<ComboboxSelected>>", lambda _e: self._rerender())

        self.lbl_count = ttk.Label(top, text="0 lines")
        self.lbl_count.pack(side="left", padx=10)

        self.txt = tk.Text(self, wrap="none")
        self.txt.pack(fill="both", expand=True, padx=10, pady=10)

        y = ttk.Scrollbar(self, orient="vertical", command=self.txt.yview)
        y.pack(side="right", fill="y")
        self.txt.configure(yscrollcommand=y.set)

    def _passes_filter(self, level: str) -> bool:
        want = (self.var_level.get() or "ALL").strip().upper()
        if want in ("", "ALL"):
            return True
        return level == want

    def _update_count_label(self):
        try:
            self.lbl_count.config(text=f"{len(self._buffer)} lines")
        except Exception:
            pass

    def _rerender(self):
        self.txt.delete("1.0", "end")
        for lvl, line in self._buffer:
            if self._passes_filter(lvl):
                self.txt.insert("end", line + "\n")
        self.txt.see("end")
        self._update_count_label()

    def append_log(self, line: str):
        lvl = _extract_level(line)

        self._buffer.append((lvl, line))
        if len(self._buffer) > self._max_lines:
            # drop oldest chunk
            drop = max(500, self._max_lines // 10)
            self._buffer = self._buffer[drop:]

        if self._passes_filter(lvl):
            self.txt.insert("end", line + "\n")
            self.txt.see("end")

        self._update_count_label()

    def clear(self):
        self._buffer = []
        self.txt.delete("1.0", "end")
        self._update_count_label()

    def open_log_dir(self):
        # Windows only
        try:
            import os
            os.startfile(str(Path(LOG_DIR)))
        except Exception:
            pass

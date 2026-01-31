# monclub_access_python/app/ui/pages/card_page.py
from __future__ import annotations

import time
import tkinter as tk
from tkinter import ttk, messagebox


class CardPage(ttk.Frame):
    """
    ZK9500 RFID scan page.

    Many ZK9500 RFID modules behave like a USB keyboard:
    they "type" the Card ID into the focused input and often send Enter.
    This page captures that stream, extracts the card id, and shows it.
    """

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        self.var_card = tk.StringVar(value="")
        self.var_status = tk.StringVar(value="Click inside the box below, then scan your card.")
        self.var_auto_copy = tk.BooleanVar(value=True)
        self.var_auto_send_to_enroll = tk.BooleanVar(value=False)

        self._buffer = ""
        self._last_key_ts = 0.0
        self._idle_job = None

        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=10)

        ttk.Label(top, text="RFID Card Scan (ZK9500)", font=("Segoe UI", 13, "bold")).pack(side="left")
        ttk.Label(top, textvariable=self.var_status).pack(side="left", padx=12)

        box = ttk.LabelFrame(self, text="Scan your RFID card (focus stays here)")
        box.pack(fill="x", padx=10, pady=10)

        row = ttk.Frame(box)
        row.pack(fill="x", padx=10, pady=10)

        ttk.Label(row, text="Live input:").pack(side="left")

        self.entry = ttk.Entry(row, width=60)
        self.entry.pack(side="left", padx=10, fill="x", expand=True)

        ttk.Button(row, text="Focus", command=self._focus).pack(side="left", padx=(6, 0))
        ttk.Button(row, text="Clear", command=self.clear).pack(side="left", padx=(6, 0))

        out = ttk.Frame(box)
        out.pack(fill="x", padx=10, pady=(0, 10))

        ttk.Label(out, text="Last Card ID:").pack(side="left")
        self.out_card = ttk.Entry(out, textvariable=self.var_card, width=40, state="readonly")
        self.out_card.pack(side="left", padx=10)

        ttk.Button(out, text="Copy", command=self.copy_to_clipboard).pack(side="left", padx=(6, 0))
        ttk.Button(out, text="Send to Enroll", command=self.send_to_enroll).pack(side="left", padx=(6, 0))

        opts = ttk.Frame(box)
        opts.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Checkbutton(opts, text="Auto-copy to clipboard", variable=self.var_auto_copy).pack(side="left")
        ttk.Checkbutton(opts, text="Auto-send to Enroll page CardNo field", variable=self.var_auto_send_to_enroll).pack(
            side="left", padx=15
        )

        hist = ttk.LabelFrame(self, text="History")
        hist.pack(fill="both", expand=True, padx=10, pady=10)

        self.listbox = tk.Listbox(hist, height=12)
        self.listbox.pack(fill="both", expand=True, padx=10, pady=10)

        # Bind keystrokes on the entry
        self.entry.bind("<Key>", self._on_key)

        # Initial focus
        self.after(250, self._focus)

    # Called by MainApp on tab selection
    def on_tab_selected(self):
        self.after(50, self._focus)

    def _focus(self):
        try:
            self.entry.focus_set()
            self.entry.selection_range(0, "end")
            self.var_status.set("Ready. Scan your card now...")
        except Exception:
            pass

    def clear(self):
        self._buffer = ""
        self.var_card.set("")
        try:
            self.entry.delete(0, "end")
        except Exception:
            pass
        self.var_status.set("Cleared. Scan your card now...")
        self._cancel_idle_timer()

    def _cancel_idle_timer(self):
        if self._idle_job is not None:
            try:
                self.after_cancel(self._idle_job)
            except Exception:
                pass
            self._idle_job = None

    def _restart_idle_timer(self):
        self._cancel_idle_timer()
        # If the scanner doesn't send Enter, treat 250ms of silence as end-of-scan
        self._idle_job = self.after(250, self._finalize_if_buffered)

    def _finalize_if_buffered(self):
        self._idle_job = None
        if self._buffer.strip():
            self._finalize(self._buffer)

    def _on_key(self, event):
        # Most scanners end with Enter. Handle that.
        if event.keysym in ("Return", "KP_Enter"):
            self._finalize(self._buffer)
            return "break"

        # Allow Esc to clear quickly
        if event.keysym == "Escape":
            self.clear()
            return "break"

        # Ignore control keys
        ch = event.char
        if not ch:
            return "break"

        # Append printable characters
        if ch.isprintable():
            self._buffer += ch
            self._last_key_ts = time.time()
            self.entry.delete(0, "end")
            self.entry.insert(0, self._buffer)
            self.var_status.set(f"Scanning... ({len(self._buffer)} chars)")
            self._restart_idle_timer()
            return "break"

        return "break"

    def _finalize(self, raw: str):
        self._cancel_idle_timer()
        raw = (raw or "").strip()

        if not raw:
            self.var_status.set("No data received. Make sure the input box is focused.")
            return

        # You can add cleaning rules here if your scanner sends prefixes/suffixes.
        card_id = raw

        self.var_card.set(card_id)
        self.listbox.insert(0, f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {card_id}")
        self.var_status.set(f"Card captured ✅  ({len(card_id)} chars)")

        # reset buffer + live entry
        self._buffer = ""
        try:
            self.entry.delete(0, "end")
        except Exception:
            pass

        if self.var_auto_copy.get():
            self.copy_to_clipboard(silent=True)

        if self.var_auto_send_to_enroll.get():
            self.send_to_enroll(silent=True)

        # Log
        try:
            self.app.logger.info("RFID scan: card_id=%s", card_id)
        except Exception:
            pass

    def copy_to_clipboard(self, silent: bool = False):
        card_id = self.var_card.get().strip()
        if not card_id:
            if not silent:
                messagebox.showwarning("Copy", "No card id to copy.")
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(card_id)
            if not silent:
                messagebox.showinfo("Copy", "Card id copied to clipboard.")
        except Exception as e:
            if not silent:
                messagebox.showerror("Copy failed", str(e))

    def send_to_enroll(self, silent: bool = False):
        card_id = self.var_card.get().strip()
        if not card_id:
            if not silent:
                messagebox.showwarning("Send", "No card id to send.")
            return

        try:
            # EnrollPage has var_card, so we fill it
            if hasattr(self.app, "page_enroll") and hasattr(self.app.page_enroll, "var_card"):
                self.app.page_enroll.var_card.set(card_id)

            # Switch to the enroll tab
            if hasattr(self.app, "nb") and hasattr(self.app, "page_enroll"):
                idx = self.app.nb.index(self.app.page_enroll)
                self.app.nb.select(idx)

            if not silent:
                messagebox.showinfo("Send", "Card id sent to Enroll page.")
        except Exception as e:
            if not silent:
                messagebox.showerror("Send failed", str(e))

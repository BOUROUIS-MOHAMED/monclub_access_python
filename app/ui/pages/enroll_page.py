from __future__ import annotations

import threading
import tkinter as tk
from tkinter import ttk, messagebox

from app.core.db import insert_fingerprint, list_fingerprints, delete_fingerprint
from app.core.utils import to_b64, to_hex, safe_int
from app.sdk.zkfinger import ZKFinger, ZKFingerError


class EnrollPage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.zk: ZKFinger | None = None
        self.zk_open = False

        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=10)

        ttk.Button(top, text="Load/Init ZK9500", command=self.init_scanner).pack(side="left", padx=(0, 8))
        ttk.Button(top, text="Open device", command=self.open_device).pack(side="left", padx=(0, 8))
        ttk.Button(top, text="Close device", command=self.close_device).pack(side="left", padx=(0, 8))

        self.lbl = ttk.Label(top, text="Scanner: not initialized")
        self.lbl.pack(side="left", padx=12)

        form = ttk.LabelFrame(self, text="Enroll fingerprint (ZK9500) and save to local SQLite")
        form.pack(fill="x", padx=10, pady=10)

        self.var_label = tk.StringVar(value="member")
        self.var_pin = tk.StringVar(value="")
        self.var_card = tk.StringVar(value="")
        self.var_finger_id = tk.StringVar(value="0")

        r = 0
        r = self._row(form, r, "Label (optional):", self.var_label)
        r = self._row(form, r, "Pin (optional but recommended):", self.var_pin)
        r = self._row(form, r, "CardNo (optional):", self.var_card)
        r = self._row(form, r, "FingerID (0..9):", self.var_finger_id)

        btns = ttk.Frame(form)
        btns.grid(row=r, column=0, columnspan=3, sticky="w", padx=10, pady=10)
        ttk.Button(btns, text="Enroll 3 samples", command=self.enroll).pack(side="left", padx=(0, 8))

        # List saved
        box = ttk.LabelFrame(self, text="Saved fingerprints (SQLite)")
        box.pack(fill="both", expand=True, padx=10, pady=10)

        self.listbox = tk.Listbox(box, height=12)
        self.listbox.pack(fill="both", expand=True, padx=10, pady=10)

        actions = ttk.Frame(box)
        actions.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(actions, text="Refresh list", command=self.refresh).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Delete selected", command=self.delete_selected).pack(side="left", padx=(0, 8))

        self.refresh()

    def _row(self, parent, row, label, var):
        parent.columnconfigure(1, weight=1)
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=10, pady=3)
        e = ttk.Entry(parent, textvariable=var)
        e.grid(row=row, column=1, sticky="ew", padx=10, pady=3)
        return row + 1

    def init_scanner(self):
        try:
            self.zk = ZKFinger(self.app.cfg.zkfp_dll_path, logger=self.app.logger)
            self.zk.init()
            cnt = self.zk.get_device_count()
            self.lbl.config(text=f"Scanner initialized ✅ | devices={cnt}")
        except Exception as e:
            self.app.logger.exception("Scanner init failed")
            messagebox.showerror("Init failed", str(e))

    def open_device(self):
        if not self.zk:
            messagebox.showwarning("Scanner", "Init scanner first.")
            return
        try:
            self.zk.open_device(0)
            self.zk_open = True
            self.lbl.config(text="Scanner opened ✅")
        except Exception as e:
            self.app.logger.exception("Open device failed")
            messagebox.showerror("Open failed", str(e))

    def close_device(self):
        try:
            if self.zk:
                self.zk.close_device()
            self.zk_open = False
            self.lbl.config(text="Scanner closed.")
        except Exception as e:
            messagebox.showerror("Close failed", str(e))

    def enroll(self):
        if not self.zk or not self.zk_open:
            messagebox.showwarning("Scanner", "Init + open device first.")
            return

        label = self.var_label.get().strip()
        pin = self.var_pin.get().strip()
        card = self.var_card.get().strip()
        finger_id = safe_int(self.var_finger_id.get().strip(), 0)
        if finger_id < 0 or finger_id > 9:
            messagebox.showerror("FingerID", "FingerID must be between 0 and 9.")
            return

        tpl_ver = int(self.app.cfg.template_version)
        enc = self.app.cfg.template_encoding

        def work():
            try:
                tpl_bytes = self.zk.enroll_3_samples()
                if enc == "hex":
                    tpl_text = to_hex(tpl_bytes)
                else:
                    tpl_text = to_b64(tpl_bytes)

                rec_id = insert_fingerprint(
                    label=label,
                    pin=pin,
                    card_no=card,
                    finger_id=finger_id,
                    template_version=tpl_ver,
                    template_encoding=enc,
                    template_data=tpl_text,
                    template_size=len(tpl_bytes),
                )
                self.app.logger.info(f"Fingerprint enrolled and saved id={rec_id} bytes={len(tpl_bytes)} enc={enc} v={tpl_ver}")
                self.after(0, lambda: (self.refresh(), messagebox.showinfo("Saved", f"Fingerprint saved to SQLite with id={rec_id}")))
            except Exception as e:
                self.app.logger.exception("Enroll failed")
                self.after(0, lambda: messagebox.showerror("Enroll failed", str(e)))

        threading.Thread(target=work, daemon=True).start()

    def refresh(self):
        self.listbox.delete(0, "end")
        for f in list_fingerprints():
            self.listbox.insert("end", f"#{f.id} | {f.created_at} | pin={f.pin} | card={f.card_no} | finger={f.finger_id} | v{f.template_version} | {f.template_encoding} | size={f.template_size} | {f.label}")

    def delete_selected(self):
        sel = self.listbox.curselection()
        if not sel:
            return
        txt = self.listbox.get(sel[0])
        if not txt.startswith("#"):
            return
        fp_id = int(txt.split("|")[0].replace("#", "").strip())
        if messagebox.askyesno("Delete", f"Delete fingerprint id={fp_id}?"):
            delete_fingerprint(fp_id)
            self.refresh()

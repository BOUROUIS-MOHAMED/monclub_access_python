from __future__ import annotations

import threading
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Any, Callable, Dict, Optional

from app.core.db import insert_fingerprint, list_fingerprints, delete_fingerprint, load_auth_token
from app.core.utils import to_b64, to_hex, safe_int
from app.api.monclub_api import MonClubApi, ApiEndpoints, MonClubApiError
from app.sdk.zkfinger import ZKFinger, ZKFingerError


def _is_8_digits_pin(s: str) -> bool:
    return s.isdigit() and len(s) == 8


def _encoding_to_backend(enc: str) -> str:
    e = (enc or "").strip().lower()
    return "HEX" if e == "hex" else "BASE64"


class EnrollFingerprintPopup(tk.Toplevel):
    """
    Popup used from Users list:
    - Enroll on ZK9500 (3 samples)
    - Save directly to backend: /manager/userFingerprint/create
    """

    def __init__(self, parent, app, user: Dict[str, Any], on_saved: Optional[Callable[[], None]] = None):
        super().__init__(parent)
        self.app = app
        self.user = dict(user or {})
        self.on_saved = on_saved

        self.zk: ZKFinger | None = None
        self.zk_open = False

        self.title("Enroll fingerprint")
        self.geometry("980x520")

        # ---- top controls
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=10)

        ttk.Button(top, text="Load/Init ZK9500", command=self.init_scanner).pack(side="left", padx=(0, 8))
        ttk.Button(top, text="Open device", command=self.open_device).pack(side="left", padx=(0, 8))
        ttk.Button(top, text="Close device", command=self.close_device).pack(side="left", padx=(0, 8))

        self.lbl = ttk.Label(top, text="Scanner: not initialized")
        self.lbl.pack(side="left", padx=12)

        # ---- target user
        target = ttk.LabelFrame(self, text="Target user (backend save)")
        target.pack(fill="x", padx=10, pady=(0, 10))

        self._target_full_name = ttk.Label(target, text=f"Full name: {self.user.get('fullName') or '-'}")
        self._target_full_name.pack(anchor="w", padx=10, pady=2)

        self._target_user_id = ttk.Label(target, text=f"userId: {self.user.get('userId')}")
        self._target_user_id.pack(anchor="w", padx=10, pady=2)

        self._target_membership_id = ttk.Label(
            target, text=f"membershipId (activeMembershipId): {self.user.get('membershipId')}"
        )
        self._target_membership_id.pack(anchor="w", padx=10, pady=2)

        # ---- enroll form
        form = ttk.LabelFrame(self, text="Enroll fingerprint (ZK9500) → Save to backend")
        form.pack(fill="x", padx=10, pady=10)

        self.var_label = tk.StringVar(value="member")
        self.var_finger_id = tk.StringVar(value="0")
        self.var_enabled = tk.BooleanVar(value=True)

        r = 0
        r = self._row(form, r, "Label (optional):", self.var_label)
        r = self._row(form, r, "FingerID (0..9):", self.var_finger_id)

        chk = ttk.Checkbutton(form, text="Enabled", variable=self.var_enabled)
        chk.grid(row=r, column=0, columnspan=3, sticky="w", padx=10, pady=8)
        r += 1

        btns = ttk.Frame(form)
        btns.grid(row=r, column=0, columnspan=3, sticky="w", padx=10, pady=10)
        ttk.Button(btns, text="Enroll 3 samples", command=self.enroll_and_save).pack(side="left", padx=(0, 8))

        self.status = ttk.Label(self, text="")
        self.status.pack(fill="x", padx=10, pady=(0, 10))

        # close handling
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _row(self, parent, row, label, var):
        parent.columnconfigure(1, weight=1)
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=10, pady=3)
        e = ttk.Entry(parent, textvariable=var)
        e.grid(row=row, column=1, sticky="ew", padx=10, pady=3)
        return row + 1

    def _set_status(self, s: str):
        self.after(0, lambda: self.status.config(text=s))

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

    def enroll_and_save(self):
        if not self.zk or not self.zk_open:
            messagebox.showwarning("Scanner", "Init + open device first.")
            return

        active_membership_id = self.user.get("membershipId")
        if active_membership_id is None or str(active_membership_id).strip() == "":
            messagebox.showerror("User", "This user has no membershipId (activeMembershipId). Can't save fingerprint.")
            return

        finger_id = safe_int(self.var_finger_id.get().strip(), 0)
        if finger_id < 0 or finger_id > 9:
            messagebox.showerror("FingerID", "FingerID must be between 0 and 9.")
            return

        label = (self.var_label.get() or "").strip()
        enabled = bool(self.var_enabled.get())

        tpl_ver = int(self.app.cfg.template_version)
        enc_cfg = self.app.cfg.template_encoding  # base64/hex
        enc_backend = _encoding_to_backend(enc_cfg)

        tok = load_auth_token()
        if not tok or not tok.token:
            messagebox.showerror("Auth", "Not logged in. Please login first (token missing).")
            return

        api = MonClubApi(
            ApiEndpoints(
                login_url=self.app.cfg.api_login_url,
                sync_url=self.app.cfg.api_sync_url,
                create_user_fingerprint_url=self.app.cfg.api_create_user_fingerprint_url,
            ),
            logger=self.app.logger,
        )

        def work():
            try:
                self._set_status("Waiting for finger (sample 1/3)...")

                tpl_bytes = self.zk.enroll_3_samples(
                    progress_cb=lambda msg: self._set_status(msg)
                )

                if enc_cfg == "hex":
                    tpl_text = to_hex(tpl_bytes)
                else:
                    tpl_text = to_b64(tpl_bytes)

                payload = {
                    "activeMembershipId": int(active_membership_id),
                    "fingerId": int(finger_id),
                    "templateVersion": int(tpl_ver),
                    "templateEncoding": enc_backend,  # "HEX" or "BASE64"
                    "templateData": tpl_text,
                    "label": label,
                    "enabled": bool(enabled),
                }

                self._set_status("Saving to backend...")
                resp = api.create_user_fingerprint(token=tok.token, payload=payload)

                self.app.logger.info("createUserFingerprint OK -> %s", resp)
                self._set_status("Saved ✅")

                def done():
                    messagebox.showinfo("Saved", "Fingerprint enrolled and saved to backend ✅")
                    if self.on_saved:
                        try:
                            self.on_saved()
                        except Exception:
                            pass
                    # keep window open (user might enroll another finger)
                self.after(0, done)

            except (ZKFingerError, MonClubApiError) as e:
                self.app.logger.exception("Enroll+save failed")
                msg = str(e)
                self.after(0, lambda: messagebox.showerror("Enroll failed", msg))
                self._set_status("")
            except Exception as e:
                self.app.logger.exception("Enroll+save failed (unexpected)")
                msg = str(e)
                self.after(0, lambda: messagebox.showerror("Enroll failed", msg))
                self._set_status("")

        threading.Thread(target=work, daemon=True).start()

    def _on_close(self):
        try:
            self.close_device()
        except Exception:
            pass
        self.destroy()


class EnrollPage(ttk.Frame):
    """
    Your existing enroll tab (still saves to local SQLite).
    Added: PIN must be 8 digits if provided.
    """
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
        r = self._row(form, r, "Pin (8 digits if provided):", self.var_pin)
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

        if pin and not _is_8_digits_pin(pin):
            messagebox.showerror("Pin", "Pin must be exactly 8 digits (numbers only).")
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
                msg = str(e)
                self.after(0, lambda m=msg: messagebox.showerror("Enroll failed", m))

        threading.Thread(target=work, daemon=True).start()

    def refresh(self):
        self.listbox.delete(0, "end")
        for f in list_fingerprints():
            self.listbox.insert(
                "end",
                f"#{f.id} | {f.created_at} | pin={f.pin} | card={f.card_no} | finger={f.finger_id} | v{f.template_version} | {f.template_encoding} | size={f.template_size} | {f.label}",
            )

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

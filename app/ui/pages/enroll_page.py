# monclub_access_python/app/ui/pages/enroll_page.py
from __future__ import annotations

import threading
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Any, Callable, Dict, Optional, List
import traceback

from app.core.db import (
    insert_fingerprint,
    list_fingerprints,
    delete_fingerprint,
    load_auth_token,
)
from app.core.utils import to_b64, to_hex, safe_int
from app.api.monclub_api import MonClubApi, ApiEndpoints, MonClubApiError
from app.sdk.zkfinger import ZKFinger, ZKFingerError


# ----------------------------
# helpers
# ----------------------------

def _is_max_8_digits_pin(s: str) -> bool:
    return s.isdigit() and len(s) <= 8


def _encoding_to_backend(enc: str) -> str:
    e = (enc or "").strip().lower()
    return "HEX" if e == "hex" else "BASE64"


def _pick_active_membership_id(user: Dict[str, Any]) -> Optional[int]:
    v = user.get("activeMembershipId")
    if v is None or str(v).strip() == "":
        v = user.get("membershipId")
    if v is None or str(v).strip() == "":
        return None
    try:
        return int(v)
    except Exception:
        return None


def _friendly_error(err: Exception) -> Dict[str, Any]:
    """
    Returns a friendly error payload for normal users + advice lines.
    """
    raw = str(err) or err.__class__.__name__
    low = raw.lower()

    title = "Fingerprint device error"
    msg = "The fingerprint reader could not be started."
    advice: List[str] = [
        "Unplug and plug the fingerprint reader again.",
        "Close the app and open it again.",
        "If the problem persists, contact the MonClub support team.",
    ]

    # No device / not detected
    if "no devices detected" in low or "no device connected" in low or "count=0" in low or "rc=-3" in low:
        title = "Fingerprint reader not detected"
        msg = "The fingerprint reader is not detected by the computer."
        advice = [
            "Check the USB cable and try another USB port.",
            "Make sure the reader driver is installed.",
            "Close the app and open it again.",
            "If the problem persists, contact the MonClub support team.",
        ]
        return {"title": title, "message": msg, "advice": advice}

    # Init algorithm library failed (common in your logs)
    if "zkfpm_init" in low and "rc=-1" in low or "failed to initialize the algorithm library" in low or "rc=-1" in low:
        title = "Fingerprint engine failed to start"
        msg = "The fingerprint engine could not be initialized on this computer."
        advice = [
            "Make sure the correct fingerprint driver is installed for this reader.",
            "Ensure all required SDK files are present in the app SDK folder.",
            "Restart the computer, then retry.",
            "If the problem persists, contact the MonClub support team.",
        ]
        return {"title": title, "message": msg, "advice": advice}

    # Open device failed
    if "open" in low and ("device" in low or "zkfpm_opendevice" in low or "null handle" in low):
        title = "Failed to open the fingerprint reader"
        msg = "The fingerprint reader was detected but could not be opened."
        advice = [
            "Unplug the reader and plug it again.",
            "Close other apps that might use the same reader.",
            "Restart the computer, then retry.",
            "If the problem persists, contact the MonClub support team.",
        ]
        return {"title": title, "message": msg, "advice": advice}

    # Default
    return {"title": title, "message": msg, "advice": advice}


# ----------------------------
# UI blocks (loading + error)
# ----------------------------

class _LoadingView(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.columnconfigure(0, weight=1)

        self.var_title = tk.StringVar(value="Starting fingerprint device...")
        self.var_desc = tk.StringVar(value="Please wait.")

        lbl_title = ttk.Label(self, textvariable=self.var_title, font=("Segoe UI", 12, "bold"))
        lbl_title.grid(row=0, column=0, sticky="w", padx=12, pady=(12, 6))

        lbl_desc = ttk.Label(self, textvariable=self.var_desc, wraplength=760, justify="left")
        lbl_desc.grid(row=1, column=0, sticky="w", padx=12, pady=(0, 10))

        self.pb = ttk.Progressbar(self, mode="indeterminate")
        self.pb.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 12))

    def set_text(self, title: str, desc: str):
        self.var_title.set(title or "")
        self.var_desc.set(desc or "")

    def start(self):
        try:
            self.pb.start(10)
        except Exception:
            pass

    def stop(self):
        try:
            self.pb.stop()
        except Exception:
            pass


class _ErrorView(ttk.Frame):
    def __init__(self, parent, *, on_retry: Callable[[], None], on_close: Optional[Callable[[], None]] = None):
        super().__init__(parent)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        self.on_retry = on_retry
        self.on_close = on_close

        self.var_title = tk.StringVar(value="Fingerprint device error")
        self.var_msg = tk.StringVar(value="The fingerprint reader could not be started.")
        self._details_visible = False
        self._details_text = ""

        lbl_title = ttk.Label(self, textvariable=self.var_title, font=("Segoe UI", 12, "bold"))
        lbl_title.grid(row=0, column=0, sticky="w", padx=12, pady=(12, 6))

        lbl_msg = ttk.Label(self, textvariable=self.var_msg, wraplength=760, justify="left")
        lbl_msg.grid(row=1, column=0, sticky="w", padx=12, pady=(0, 8))

        self.advice_box = ttk.LabelFrame(self, text="What you can do")
        self.advice_box.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 10))
        self.advice_box.columnconfigure(0, weight=1)

        self._advice_labels: List[ttk.Label] = []
        for i in range(4):
            lbl = ttk.Label(self.advice_box, text="", wraplength=740, justify="left")
            lbl.grid(row=i, column=0, sticky="w", padx=10, pady=2)
            self._advice_labels.append(lbl)

        # buttons
        btns = ttk.Frame(self)
        btns.grid(row=4, column=0, sticky="ew", padx=12, pady=(0, 10))
        btns.columnconfigure(0, weight=1)

        self.btn_retry = ttk.Button(btns, text="Retry", command=self.on_retry)
        self.btn_retry.grid(row=0, column=0, sticky="w")

        self.btn_details = ttk.Button(btns, text="Show details", command=self._toggle_details)
        self.btn_details.grid(row=0, column=1, sticky="w", padx=(10, 0))

        if self.on_close:
            self.btn_close = ttk.Button(btns, text="Close", command=self.on_close)
            self.btn_close.grid(row=0, column=2, sticky="e")
        else:
            self.btn_close = None

        # details area (hidden initially)
        self.details_frame = ttk.LabelFrame(self, text="Technical details")
        self.details_frame.grid(row=3, column=0, sticky="nsew", padx=12, pady=(0, 10))
        self.details_frame.columnconfigure(0, weight=1)
        self.details_frame.rowconfigure(0, weight=1)

        self.txt = tk.Text(self.details_frame, height=10, wrap="word")
        self.txt.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=10)
        self.txt.configure(state="disabled")

        sb = ttk.Scrollbar(self.details_frame, command=self.txt.yview)
        sb.grid(row=0, column=1, sticky="ns", padx=(0, 10), pady=10)
        self.txt.configure(yscrollcommand=sb.set)

        # hide by default
        self.details_frame.grid_remove()

    def set_error(self, *, title: str, message: str, advice_lines: List[str], details: str):
        self.var_title.set(title or "Fingerprint device error")
        self.var_msg.set(message or "")
        self._details_text = details or ""

        # show up to 4 advice lines
        for i, lbl in enumerate(self._advice_labels):
            txt = advice_lines[i] if i < len(advice_lines) else ""
            if txt:
                lbl.configure(text=f"• {txt}")
            else:
                lbl.configure(text="")

        # refresh details content if visible
        if self._details_visible:
            self._render_details()

    def _render_details(self):
        self.txt.configure(state="normal")
        self.txt.delete("1.0", "end")
        self.txt.insert("end", self._details_text.strip() + "\n")
        self.txt.see("1.0")
        self.txt.configure(state="disabled")

    def _toggle_details(self):
        self._details_visible = not self._details_visible
        if self._details_visible:
            self.btn_details.configure(text="Hide details")
            self.details_frame.grid()
            self._render_details()
        else:
            self.btn_details.configure(text="Show details")
            self.details_frame.grid_remove()


# ----------------------------
# Popup: enroll + save to backend
# ----------------------------

class EnrollFingerprintPopup(tk.Toplevel):
    """
    Popup from Users list:
    - Auto init + open ZK9500 on show
    - Auto close + terminate on exit
    - Enroll (3 samples) and save to backend
    """

    def __init__(self, parent, app, user: Dict[str, Any], on_saved: Optional[Callable[[], None]] = None):
        super().__init__(parent)
        self.app = app
        self.user = dict(user or {})
        self.on_saved = on_saved

        self.zk: ZKFinger | None = None
        self.zk_open = False
        self._zk_lock = threading.RLock()

        self._opening_thread: Optional[threading.Thread] = None
        self._open_seq = 0
        self._lifecycle_cancel = threading.Event()

        self.title("Enroll fingerprint")
        self.geometry("980x560")
        self.minsize(900, 520)

        # root layout
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        header.columnconfigure(0, weight=1)

        self.var_header = tk.StringVar(value="Fingerprint reader")
        self.var_status = tk.StringVar(value="Starting...")
        ttk.Label(header, textvariable=self.var_header, font=("Segoe UI", 12, "bold")).grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(header, textvariable=self.var_status).grid(row=1, column=0, sticky="w", pady=(2, 0))

        self.btn_close_top = ttk.Button(header, text="Close", command=self._on_close)
        self.btn_close_top.grid(row=0, column=1, rowspan=2, sticky="e")

        body = ttk.Frame(self)
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)

        # views
        self.view_loading = _LoadingView(body)
        self.view_error = _ErrorView(body, on_retry=self._retry_open, on_close=self._on_close)
        self.view_content = ttk.Frame(body)

        for w in (self.view_loading, self.view_error, self.view_content):
            w.grid(row=0, column=0, sticky="nsew")

        self._build_content()

        self._set_mode_loading("Starting fingerprint device...", "Initializing fingerprint reader.")
        self.after(60, self._ensure_open_async)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # -------- content UI --------

    def _build_content(self):
        self.view_content.columnconfigure(0, weight=1)
        self.view_content.rowconfigure(2, weight=1)

        target = ttk.LabelFrame(self.view_content, text="Target user (backend save)")
        target.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 10))
        target.columnconfigure(0, weight=1)

        ttk.Label(target, text=f"Full name: {self.user.get('fullName') or '-'}").grid(row=0, column=0, sticky="w", padx=10, pady=2)
        ttk.Label(target, text=f"userId: {self.user.get('userId')}").grid(row=1, column=0, sticky="w", padx=10, pady=2)
        ttk.Label(target, text=f"activeMembershipId: {self.user.get('activeMembershipId')}").grid(row=2, column=0, sticky="w", padx=10, pady=2)
        ttk.Label(target, text=f"membershipId (plan): {self.user.get('membershipId')}").grid(row=3, column=0, sticky="w", padx=10, pady=2)

        form = ttk.LabelFrame(self.view_content, text="Enroll fingerprint (ZK9500) → Save to backend")
        form.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        form.columnconfigure(1, weight=1)

        self.var_label = tk.StringVar(value="member")
        self.var_finger_id = tk.StringVar(value="0")
        self.var_enabled = tk.BooleanVar(value=True)

        ttk.Label(form, text="Label (optional):").grid(row=0, column=0, sticky="w", padx=10, pady=4)
        ttk.Entry(form, textvariable=self.var_label).grid(row=0, column=1, sticky="ew", padx=10, pady=4)

        ttk.Label(form, text="FingerID (0..9):").grid(row=1, column=0, sticky="w", padx=10, pady=4)
        ttk.Entry(form, textvariable=self.var_finger_id).grid(row=1, column=1, sticky="ew", padx=10, pady=4)

        ttk.Checkbutton(form, text="Enabled", variable=self.var_enabled).grid(
            row=2, column=0, columnspan=2, sticky="w", padx=10, pady=(4, 8)
        )

        btns = ttk.Frame(form)
        btns.grid(row=3, column=0, columnspan=2, sticky="w", padx=10, pady=(0, 10))
        ttk.Button(btns, text="Enroll 3 samples", command=self.enroll_and_save).pack(side="left")

        self.status = ttk.Label(self.view_content, text="")
        self.status.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))

    # -------- state views --------

    def _show_view(self, which: str):
        self.view_loading.grid_remove()
        self.view_error.grid_remove()
        self.view_content.grid_remove()

        if which == "loading":
            self.view_loading.grid()
        elif which == "error":
            self.view_error.grid()
        else:
            self.view_content.grid()

    def _set_mode_loading(self, title: str, desc: str):
        self.var_status.set("Starting...")
        self.view_loading.set_text(title, desc)
        self.view_loading.start()
        self._show_view("loading")

    def _set_mode_ready(self):
        self.view_loading.stop()
        self.var_status.set("Connected")
        self._show_view("content")

    def _set_mode_error(self, err: Exception, diagnostics: str, tb: str):
        self.view_loading.stop()
        self.var_status.set("Error")

        fr = _friendly_error(err)
        details = (
            "Error:\n"
            f"{repr(err)}\n\n"
            "Traceback:\n"
            f"{tb.strip()}\n\n"
            "Diagnostics:\n"
            f"{(diagnostics or '').strip()}\n"
        )
        self.view_error.set_error(
            title=fr["title"],
            message=fr["message"],
            advice_lines=fr["advice"],
            details=details,
        )
        self._show_view("error")

    def _post_error(self, err: Exception, diagnostics: str, tb: str) -> None:
        self.after(0, lambda err=err, diag=diagnostics, tb=tb: self._set_mode_error(err, diag, tb))

    # -------- device lifecycle --------

    def _dispose_scanner_locked(self):
        if not self.zk:
            self.zk_open = False
            return
        try:
            self.zk.close_device()
        except Exception:
            pass
        try:
            self.zk.terminate()
        except Exception:
            pass
        self.zk = None
        self.zk_open = False

    def _dispose_scanner(self):
        with self._zk_lock:
            self._dispose_scanner_locked()

    def _retry_open(self):
        if self._lifecycle_cancel.is_set():
            return
        self._ensure_open_async()

    def _ensure_open_async(self):
        if self._lifecycle_cancel.is_set():
            return

        with self._zk_lock:
            if self.zk and self.zk_open:
                self._set_mode_ready()
                return

        if self._opening_thread and self._opening_thread.is_alive():
            return

        self._open_seq += 1
        seq = self._open_seq

        self._set_mode_loading("Opening fingerprint device...", "Initializing SDK and opening device 0")

        def work():
            try:
                if self._lifecycle_cancel.is_set() or seq != self._open_seq:
                    return

                with self._zk_lock:
                    self._dispose_scanner_locked()

                    self.zk = ZKFinger(self.app.cfg.zkfp_dll_path, logger=self.app.logger)

                    diag = ""
                    try:
                        diag = self.zk.diagnostics()
                        self.app.logger.info("ZKFinger diagnostics (auto-open popup):\n%s", diag)
                    except Exception:
                        diag = ""

                    self.zk.init()
                    cnt = self.zk.get_device_count()
                    if cnt <= 0:
                        raise ZKFingerError(f"No devices detected (count={cnt}).")

                    self.zk.open_device(0)
                    self.zk_open = True

                if self._lifecycle_cancel.is_set() or seq != self._open_seq:
                    return

                self.after(0, self._set_mode_ready)

            except Exception as e:
                self.app.logger.exception("Auto init/open failed (popup)")
                tb = traceback.format_exc()

                diag2 = ""
                try:
                    if self.zk:
                        diag2 = self.zk.diagnostics()
                except Exception:
                    diag2 = ""

                if self._lifecycle_cancel.is_set() or seq != self._open_seq:
                    return
                self._post_error(e, diag2, tb)

        self._opening_thread = threading.Thread(target=work, daemon=True)
        self._opening_thread.start()

    # -------- enroll flow --------

    def _set_status(self, s: str):
        self.after(0, lambda: self.status.config(text=s or ""))

    def enroll_and_save(self):
        if not self.zk or not self.zk_open:
            messagebox.showerror("Fingerprint reader", "The fingerprint reader is not ready. Retry opening it.")
            return

        active_membership_id = _pick_active_membership_id(self.user)
        if active_membership_id is None:
            messagebox.showerror(
                "User",
                "This user has no activeMembershipId. The backend must send it (or your cache is outdated).",
            )
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

                with self._zk_lock:
                    if not self.zk:
                        raise ZKFingerError("Scanner not initialized.")
                    tpl_bytes = self.zk.enroll_3_samples(progress_cb=lambda msg: self._set_status(msg))

                tpl_text = to_hex(tpl_bytes) if enc_cfg == "hex" else to_b64(tpl_bytes)

                payload = {
                    "activeMembershipId": int(active_membership_id),
                    "fingerId": int(finger_id),
                    "templateVersion": int(tpl_ver),
                    "templateEncoding": enc_backend,
                    "templateData": tpl_text,
                    "label": label,
                    "enabled": bool(enabled),
                }

                self._set_status("Saving to backend...")
                resp = api.create_user_fingerprint(token=tok.token, payload=payload)

                self.app.logger.info("createUserFingerprint OK -> %s", resp)
                self._set_status("Saved")

                def done():
                    messagebox.showinfo("Saved", "Fingerprint enrolled and saved to backend.")
                    if self.on_saved:
                        try:
                            self.on_saved()
                        except Exception:
                            pass

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

    # -------- close --------

    def _on_close(self):
        self._lifecycle_cancel.set()
        try:
            self._open_seq += 1
        except Exception:
            pass
        try:
            self._dispose_scanner()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass


# ----------------------------
# Tab Page: enroll + save to local SQLite
# ----------------------------

class EnrollPage(ttk.Frame):
    """
    Enroll tab:
    - Auto init + open when the tab is shown (mapped)
    - Auto close when tab is hidden (unmapped)
    - Only shows fields after the device is open
    """

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        self.zk: ZKFinger | None = None
        self.zk_open = False
        self._zk_lock = threading.RLock()

        self._opening_thread: Optional[threading.Thread] = None
        self._open_seq = 0
        self._lifecycle_cancel = threading.Event()

        # root views
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        self.view_loading = _LoadingView(self)
        self.view_error = _ErrorView(self, on_retry=self._retry_open, on_close=None)
        self.view_content = ttk.Frame(self)

        for w in (self.view_loading, self.view_error, self.view_content):
            w.grid(row=0, column=0, sticky="nsew")

        self._build_content()

        self._set_mode_loading("Starting fingerprint device...", "Initializing fingerprint reader.")
        self.view_loading.start()

        # Auto open/close based on visibility
        self.bind("<Map>", self._on_map)
        self.bind("<Unmap>", self._on_unmap)

    # -------- content UI --------

    def _build_content(self):
        self.view_content.columnconfigure(0, weight=1)
        self.view_content.rowconfigure(2, weight=1)

        header = ttk.Frame(self.view_content)
        header.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        header.columnconfigure(0, weight=1)

        self.var_header = tk.StringVar(value="Fingerprint reader")
        self.var_status = tk.StringVar(value="Connected")
        ttk.Label(header, textvariable=self.var_header, font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(header, textvariable=self.var_status).grid(row=1, column=0, sticky="w", pady=(2, 0))

        form = ttk.LabelFrame(self.view_content, text="Enroll fingerprint (ZK9500) and save to local SQLite")
        form.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        form.columnconfigure(1, weight=1)

        self.var_label = tk.StringVar(value="member")
        self.var_pin = tk.StringVar(value="")
        self.var_card = tk.StringVar(value="")
        self.var_finger_id = tk.StringVar(value="0")

        ttk.Label(form, text="Label (optional):").grid(row=0, column=0, sticky="w", padx=10, pady=4)
        ttk.Entry(form, textvariable=self.var_label).grid(row=0, column=1, sticky="ew", padx=10, pady=4)

        ttk.Label(form, text="Pin (optional, <= 8 digits):").grid(row=1, column=0, sticky="w", padx=10, pady=4)
        ttk.Entry(form, textvariable=self.var_pin).grid(row=1, column=1, sticky="ew", padx=10, pady=4)

        ttk.Label(form, text="CardNo (optional):").grid(row=2, column=0, sticky="w", padx=10, pady=4)
        ttk.Entry(form, textvariable=self.var_card).grid(row=2, column=1, sticky="ew", padx=10, pady=4)

        ttk.Label(form, text="FingerID (0..9):").grid(row=3, column=0, sticky="w", padx=10, pady=4)
        ttk.Entry(form, textvariable=self.var_finger_id).grid(row=3, column=1, sticky="ew", padx=10, pady=4)

        btns = ttk.Frame(form)
        btns.grid(row=4, column=0, columnspan=2, sticky="w", padx=10, pady=(0, 10))
        ttk.Button(btns, text="Enroll 3 samples", command=self.enroll).pack(side="left")

        self.status = ttk.Label(self.view_content, text="")
        self.status.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 8))

        # List saved
        box = ttk.LabelFrame(self.view_content, text="Saved fingerprints (SQLite)")
        box.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0, 10))
        box.columnconfigure(0, weight=1)
        box.rowconfigure(0, weight=1)

        self.listbox = tk.Listbox(box, height=12)
        self.listbox.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=10)

        sb = ttk.Scrollbar(box, command=self.listbox.yview)
        sb.grid(row=0, column=1, sticky="ns", padx=(0, 10), pady=10)
        self.listbox.configure(yscrollcommand=sb.set)

        actions = ttk.Frame(box)
        actions.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 10))
        ttk.Button(actions, text="Refresh list", command=self.refresh).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Delete selected", command=self.delete_selected).pack(side="left")

    # -------- state views --------

    def _show_view(self, which: str):
        self.view_loading.grid_remove()
        self.view_error.grid_remove()
        self.view_content.grid_remove()

        if which == "loading":
            self.view_loading.grid()
        elif which == "error":
            self.view_error.grid()
        else:
            self.view_content.grid()

    def _set_mode_loading(self, title: str, desc: str):
        self.var_status.set("Starting...")
        self.view_loading.set_text(title, desc)
        self.view_loading.start()
        self._show_view("loading")

    def _set_mode_ready(self):
        self.view_loading.stop()
        self.var_status.set("Connected")
        self._show_view("content")
        self.refresh()

    def _set_mode_error(self, err: Exception, diagnostics: str, tb: str):
        self.view_loading.stop()
        self.var_status.set("Error")

        fr = _friendly_error(err)
        details = (
            "Error:\n"
            f"{repr(err)}\n\n"
            "Traceback:\n"
            f"{tb.strip()}\n\n"
            "Diagnostics:\n"
            f"{(diagnostics or '').strip()}\n"
        )
        self.view_error.set_error(
            title=fr["title"],
            message=fr["message"],
            advice_lines=fr["advice"],
            details=details,
        )
        self._show_view("error")

    def _post_error(self, err: Exception, diagnostics: str, tb: str) -> None:
        self.after(0, lambda err=err, diag=diagnostics, tb=tb: self._set_mode_error(err, diag, tb))

    # -------- visibility hooks --------

    def _on_map(self, _evt=None):
        # entering tab/page
        if self._lifecycle_cancel.is_set():
            self._lifecycle_cancel.clear()
        self._ensure_open_async()

    def _on_unmap(self, _evt=None):
        # leaving tab/page
        self._lifecycle_cancel.set()
        try:
            self._open_seq += 1
        except Exception:
            pass
        try:
            self._dispose_scanner()
        except Exception:
            pass

    # -------- device lifecycle --------

    def _dispose_scanner_locked(self):
        if not self.zk:
            self.zk_open = False
            return
        try:
            self.zk.close_device()
        except Exception:
            pass
        try:
            self.zk.terminate()
        except Exception:
            pass
        self.zk = None
        self.zk_open = False

    def _dispose_scanner(self):
        with self._zk_lock:
            self._dispose_scanner_locked()

    def _retry_open(self):
        if self._lifecycle_cancel.is_set():
            self._lifecycle_cancel.clear()
        self._ensure_open_async()

    def _ensure_open_async(self):
        if self._lifecycle_cancel.is_set():
            return

        with self._zk_lock:
            if self.zk and self.zk_open:
                self._set_mode_ready()
                return

        if self._opening_thread and self._opening_thread.is_alive():
            return

        self._open_seq += 1
        seq = self._open_seq

        self._set_mode_loading("Opening fingerprint device...", "Initializing SDK and opening device 0")

        def work():
            try:
                if self._lifecycle_cancel.is_set() or seq != self._open_seq:
                    return

                with self._zk_lock:
                    self._dispose_scanner_locked()

                    self.zk = ZKFinger(self.app.cfg.zkfp_dll_path, logger=self.app.logger)

                    diag = ""
                    try:
                        diag = self.zk.diagnostics()
                        self.app.logger.info("ZKFinger diagnostics (auto-open page):\n%s", diag)
                    except Exception:
                        diag = ""

                    self.zk.init()
                    cnt = self.zk.get_device_count()
                    if cnt <= 0:
                        raise ZKFingerError(f"No devices detected (count={cnt}).")

                    self.zk.open_device(0)
                    self.zk_open = True

                if self._lifecycle_cancel.is_set() or seq != self._open_seq:
                    return

                self.after(0, self._set_mode_ready)

            except Exception as e:
                self.app.logger.exception("Auto init/open failed (page)")
                tb = traceback.format_exc()

                diag2 = ""
                try:
                    if self.zk:
                        diag2 = self.zk.diagnostics()
                except Exception:
                    diag2 = ""

                if self._lifecycle_cancel.is_set() or seq != self._open_seq:
                    return
                self._post_error(e, diag2, tb)

        self._opening_thread = threading.Thread(target=work, daemon=True)
        self._opening_thread.start()

    # -------- enroll (sqlite) --------

    def _set_status(self, s: str):
        self.after(0, lambda: self.status.config(text=s or ""))

    def enroll(self):
        if not self.zk or not self.zk_open:
            messagebox.showerror("Fingerprint reader", "The fingerprint reader is not ready. Retry opening it.")
            return

        label = self.var_label.get().strip()
        pin = self.var_pin.get().strip()
        card = self.var_card.get().strip()

        finger_id = safe_int(self.var_finger_id.get().strip(), 0)
        if finger_id < 0 or finger_id > 9:
            messagebox.showerror("FingerID", "FingerID must be between 0 and 9.")
            return

        if pin and not _is_max_8_digits_pin(pin):
            messagebox.showerror("Pin", "Pin must be numeric and <= 8 digits.")
            return

        tpl_ver = int(self.app.cfg.template_version)
        enc = self.app.cfg.template_encoding

        def work():
            try:
                self._set_status("Waiting for finger (sample 1/3)...")

                with self._zk_lock:
                    if not self.zk:
                        raise ZKFingerError("Scanner not initialized.")
                    tpl_bytes = self.zk.enroll_3_samples(progress_cb=lambda msg: self._set_status(msg))

                tpl_text = to_hex(tpl_bytes) if enc == "hex" else to_b64(tpl_bytes)

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

                self.app.logger.info(
                    "Fingerprint enrolled and saved id=%s bytes=%s enc=%s v=%s",
                    rec_id, len(tpl_bytes), enc, tpl_ver
                )

                def done():
                    self._set_status("")
                    self.refresh()
                    messagebox.showinfo("Saved", f"Fingerprint saved to SQLite with id={rec_id}")

                self.after(0, done)

            except Exception as e:
                self.app.logger.exception("Enroll failed")
                msg = str(e)
                self.after(0, lambda m=msg: messagebox.showerror("Enroll failed", m))
                self._set_status("")

        threading.Thread(target=work, daemon=True).start()

    def refresh(self):
        self.listbox.delete(0, "end")
        for f in list_fingerprints():
            self.listbox.insert(
                "end",
                f"#{f.id} | {f.created_at} | pin={f.pin} | card={f.card_no} | finger={f.finger_id} | "
                f"v{f.template_version} | {f.template_encoding} | size={f.template_size} | {f.label}",
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

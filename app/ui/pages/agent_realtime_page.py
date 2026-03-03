# app/ui/pages/agent_realtime_page.py
from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Any, Dict, Optional
import os
import time

from app.core.realtime_agent import ImageCache, NotificationRequest
from app.core.utils import DB_PATH, ensure_dirs


def _safe_int(v: Any, default: int) -> int:
    try:
        return int(str(v).strip())
    except Exception:
        return default


def _safe_float(v: Any, default: float) -> float:
    try:
        return float(str(v).strip())
    except Exception:
        return default


def _safe_str(v: Any, default: str = "") -> str:
    if v is None:
        return default
    try:
        return str(v)
    except Exception:
        return default


# =========================
# NEW: Tk Popup Manager
# =========================
class PopupManager:
    """
    Shows in-app popups at top-right of the screen.
    Larger than winotify; supports bigger image.
    Auto-destroys after duration seconds.
    """
    def __init__(self, root: tk.Misc, *, get_settings: callable):
        self.root = root
        self.get_settings = get_settings

        self._popups: list[tk.Toplevel] = []
        self._images_keepalive: list[Any] = []

        # image cache (same idea as winotify cache)
        try:
            ensure_dirs()
        except Exception:
            pass
        base_dir = os.path.dirname(DB_PATH) if DB_PATH else os.getcwd()
        cache_dir = os.path.join(base_dir, "cache", "images")

        try:
            gs = get_settings() or {}
        except Exception:
            gs = {}

        self._img_cache = ImageCache(
            cache_dir=cache_dir,
            enabled=bool(gs.get("image_cache_enabled", True)),
            timeout_sec=float(gs.get("image_cache_timeout_sec", 2.0)),
            max_bytes=int(gs.get("image_cache_max_bytes", 5 * 1024 * 1024)),
            max_files=int(gs.get("image_cache_max_files", 1000)),
            prune_every_n=200,
        )

        # Try Pillow for robust JPG/PNG/WebP support
        self._pil_ok = False
        self._PIL_Image = None
        self._PIL_ImageTk = None
        try:
            from PIL import Image, ImageTk  # type: ignore
            self._PIL_Image = Image
            self._PIL_ImageTk = ImageTk
            self._pil_ok = True
        except Exception:
            self._pil_ok = False

    def _reposition(self) -> None:
        # Stack popups downward from top-right
        margin = 12
        gap = 10

        sw = self.root.winfo_screenwidth()


        # fixed larger popup size
        w = 620
        h = 250

        x = max(0, sw - w - margin)
        y = margin

        alive = []
        for p in self._popups:
            try:
                if not p.winfo_exists():
                    continue
                p.geometry(f"{w}x{h}+{x}+{y}")
                y += h + gap
                alive.append(p)
            except Exception:
                continue

        self._popups = alive

        # Avoid unbounded keepalive list (keep last ~50 images)
        if len(self._images_keepalive) > 50:
            self._images_keepalive = self._images_keepalive[-50:]

    def _load_photo(self, image_path_or_url: str, size_px: int = 140):
        """
        Returns a Tk-compatible image object (PhotoImage or ImageTk.PhotoImage),
        or None if cannot load.
        """
        s = (image_path_or_url or "").strip()
        if not s:
            return None

        local_path = self._img_cache.resolve(s)
        if not local_path or not os.path.exists(local_path):
            # if user passed local path (already) but cache refused, try direct
            if os.path.exists(s) and os.path.isfile(s):
                local_path = s
            else:
                return None

        # Pillow path (best)
        if self._pil_ok and self._PIL_Image and self._PIL_ImageTk:
            try:
                img = self._PIL_Image.open(local_path)
                img = img.convert("RGBA")
                img = img.resize((int(size_px), int(size_px)))
                tk_img = self._PIL_ImageTk.PhotoImage(img)
                return tk_img
            except Exception:
                return None

        # Tkinter PhotoImage fallback (PNG/GIF only typically)
        try:
            tk_img = tk.PhotoImage(file=local_path)
            return tk_img
        except Exception:
            return None

    def show(self, title: str, message: str, image_path: str) -> None:
        try:
            gs = self.get_settings() or {}
        except Exception:
            gs = {}

        if not bool(gs.get("popup_enabled", True)):
            return

        duration = float(gs.get("popup_duration_sec", 3.0))
        if duration <= 0:
            duration = 3.0

        # Create borderless top-level
        top = tk.Toplevel(self.root)
        top.overrideredirect(True)
        top.attributes("-topmost", True)

        # Background frame
        outer = tk.Frame(top, bg="#111111", bd=0, highlightthickness=1, highlightbackground="#333333")
        outer.pack(fill="both", expand=True)

        # Layout: image (left) + texts (right)
        left = tk.Frame(outer, bg="#111111")
        left.pack(side="left", fill="y", padx=12, pady=12)

        right = tk.Frame(outer, bg="#111111")
        right.pack(side="left", fill="both", expand=True, padx=(0, 12), pady=12)

        # Image (big)
        img_obj = self._load_photo(image_path, size_px=250)
        if img_obj is not None:
            self._images_keepalive.append(img_obj)  # prevent GC
            lbl_img = tk.Label(left, image=img_obj, bg="#111111")
            lbl_img.pack()
        else:
            # placeholder
            ph = tk.Canvas(left, width=250, height=250, bg="#1a1a1a", highlightthickness=1, highlightbackground="#333333")
            ph.create_text(250, 250, text="No Image", fill="#777777")
            ph.pack()

        # Title
        lbl_title = tk.Label(
            right,
            text=_safe_str(title, ""),
            fg="#ffffff",
            bg="#111111",
            font=("TkDefaultFont", 11, "bold"),
            anchor="w",
            justify="left",
        )
        lbl_title.pack(fill="x", pady=(2, 6))

        # Message (wrap)
        msg_txt = _safe_str(message, "")
        if len(msg_txt) > 500:
            msg_txt = msg_txt[:500] + "..."

        lbl_msg = tk.Label(
            right,
            text=msg_txt,
            fg="#dddddd",
            bg="#111111",
            font=("TkDefaultFont", 9),
            anchor="nw",
            justify="left",
            wraplength=340,
        )
        lbl_msg.pack(fill="both", expand=True)

        # Small close button (top-right of popup)
        btn_close = tk.Label(outer, text="✕", fg="#bbbbbb", bg="#111111", cursor="hand2", font=("TkDefaultFont", 10, "bold"))
        btn_close.place(relx=1.0, x=-10, y=8, anchor="ne")
        btn_close.bind("<Button-1>", lambda e: self._destroy_popup(top))

        # Track, position, auto-destroy
        self._popups.insert(0, top)
        self._reposition()

        top.after(int(duration * 1000), lambda: self._destroy_popup(top))

    def _destroy_popup(self, top: tk.Toplevel) -> None:
        try:
            if top.winfo_exists():
                top.destroy()
        except Exception:
            pass
        self._reposition()


class AgentRealtimePage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        # ========== GLOBAL CONTROLS ==========
        top = ttk.LabelFrame(self, text="Agent realtime (RTLog) - Global Settings")
        top.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        top.columnconfigure(6, weight=1)

        self.var_enabled = tk.BooleanVar(value=bool(getattr(self.app.cfg, "agent_realtime_enabled", True)))
        g = self.app.cfg.get_agent_global()

        # Existing settings
        self.var_rate = tk.StringVar(value=str(g.get("notification_rate_limit_per_minute", 30)))
        self.var_dedupe = tk.StringVar(value=str(g.get("notification_dedupe_window_sec", 30)))
        self.var_retention = tk.StringVar(value=str(g.get("history_retention_days", 30)))
        self.var_queue_max = tk.StringVar(value=str(g.get("event_queue_max", 5000)))
        self.var_deciders = tk.StringVar(value=str(g.get("decision_workers", 1)))

        # Additional settings
        self.var_notify_queue_max = tk.StringVar(value=str(g.get("notification_queue_max", 2000)))
        self.var_history_queue_max = tk.StringVar(value=str(g.get("history_queue_max", 5000)))
        self.var_decision_ema_alpha = tk.StringVar(value=str(g.get("decision_ema_alpha", 0.2)))

        # Service enable/disable switches
        self.var_notification_service_enabled = tk.BooleanVar(value=bool(g.get("notification_service_enabled", True)))
        self.var_history_service_enabled = tk.BooleanVar(value=bool(g.get("history_service_enabled", True)))

        # Image cache settings
        self.var_img_cache_enabled = tk.BooleanVar(value=bool(g.get("image_cache_enabled", True)))
        self.var_img_cache_timeout = tk.StringVar(value=str(g.get("image_cache_timeout_sec", 2.0)))
        self.var_img_cache_max_bytes = tk.StringVar(value=str(g.get("image_cache_max_bytes", 5242880)))  # 5MB
        self.var_img_cache_max_files = tk.StringVar(value=str(g.get("image_cache_max_files", 1000)))

        # NEW: Popup settings
        self.var_popup_enabled = tk.BooleanVar(value=bool(g.get("popup_enabled", True)))
        self.var_popup_duration = tk.StringVar(value=str(g.get("popup_duration_sec", 3.0)))

        ttk.Checkbutton(top, text="Enable realtime engine in AGENT mode", variable=self.var_enabled).grid(
            row=0, column=0, sticky="w", padx=10, pady=6, columnspan=3
        )

        # Row 1: Notification settings
        ttk.Label(top, text="Toasts/min:").grid(row=1, column=0, sticky="w", padx=10, pady=4)
        ttk.Entry(top, textvariable=self.var_rate, width=10).grid(row=1, column=1, sticky="w", pady=4)

        ttk.Label(top, text="Dedupe sec:").grid(row=1, column=2, sticky="w", padx=(20, 10), pady=4)
        ttk.Entry(top, textvariable=self.var_dedupe, width=10).grid(row=1, column=3, sticky="w", pady=4)

        ttk.Label(top, text="History days:").grid(row=1, column=4, sticky="w", padx=(20, 10), pady=4)
        ttk.Entry(top, textvariable=self.var_retention, width=10).grid(row=1, column=5, sticky="w", pady=4)

        # Row 2: Queue and thread settings
        ttk.Label(top, text="Event queue max:").grid(row=2, column=0, sticky="w", padx=10, pady=4)
        ttk.Entry(top, textvariable=self.var_queue_max, width=10).grid(row=2, column=1, sticky="w", pady=4)

        ttk.Label(top, text="Decision threads:").grid(row=2, column=2, sticky="w", padx=(20, 10), pady=4)
        ttk.Entry(top, textvariable=self.var_deciders, width=10).grid(row=2, column=3, sticky="w", pady=4)

        ttk.Label(top, text="EMA alpha:").grid(row=2, column=4, sticky="w", padx=(20, 10), pady=4)
        ttk.Entry(top, textvariable=self.var_decision_ema_alpha, width=10).grid(row=2, column=5, sticky="w", pady=4)

        # Row 3: Additional queue settings and service switches
        ttk.Label(top, text="Notify queue max:").grid(row=3, column=0, sticky="w", padx=10, pady=4)
        ttk.Entry(top, textvariable=self.var_notify_queue_max, width=10).grid(row=3, column=1, sticky="w", pady=4)

        ttk.Label(top, text="History queue max:").grid(row=3, column=2, sticky="w", padx=(20, 10), pady=4)
        ttk.Entry(top, textvariable=self.var_history_queue_max, width=10).grid(row=3, column=3, sticky="w", pady=4)

        ttk.Checkbutton(top, text="Enable notification service", variable=self.var_notification_service_enabled).grid(
            row=3, column=4, sticky="w", padx=(20, 0), pady=4, columnspan=2
        )

        ttk.Checkbutton(top, text="Enable history service", variable=self.var_history_service_enabled).grid(
            row=4, column=4, sticky="w", padx=(20, 0), pady=4, columnspan=2
        )

        # Row 4/5: Popup settings (NEW)
        ttk.Checkbutton(top, text="Enable in-app popup (top-right)", variable=self.var_popup_enabled).grid(
            row=4, column=0, sticky="w", padx=10, pady=4, columnspan=2
        )
        ttk.Label(top, text="Popup seconds:").grid(row=4, column=2, sticky="w", padx=(20, 10), pady=4)
        ttk.Entry(top, textvariable=self.var_popup_duration, width=10).grid(row=4, column=3, sticky="w", pady=4)

        # Row 6: Image cache settings
        ttk.Checkbutton(top, text="Image cache enabled", variable=self.var_img_cache_enabled).grid(
            row=5, column=0, sticky="w", padx=10, pady=4, columnspan=2
        )

        ttk.Label(top, text="Cache timeout (s):").grid(row=5, column=2, sticky="w", padx=(20, 10), pady=4)
        ttk.Entry(top, textvariable=self.var_img_cache_timeout, width=10).grid(row=5, column=3, sticky="w", pady=4)

        ttk.Label(top, text="Max file size (bytes):").grid(row=6, column=0, sticky="w", padx=10, pady=4)
        ttk.Entry(top, textvariable=self.var_img_cache_max_bytes, width=10).grid(row=6, column=1, sticky="w", pady=4)

        ttk.Label(top, text="Max cached files:").grid(row=6, column=2, sticky="w", padx=(20, 10), pady=4)
        ttk.Entry(top, textvariable=self.var_img_cache_max_files, width=10).grid(row=6, column=3, sticky="w", pady=4)

        # Buttons
        btns = ttk.Frame(top)
        btns.grid(row=7, column=0, columnspan=6, sticky="w", padx=10, pady=(8, 10))
        ttk.Button(btns, text="Save settings", command=self._save_global).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Start", command=self._start).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Stop", command=self._stop).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Refresh devices", command=self._refresh).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="🔔 Test Notification", command=self._test_notification).pack(side="left")

        # ========== RUNTIME SUMMARY ==========
        mid = ttk.LabelFrame(self, text="Runtime Status")
        mid.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 6))
        mid.columnconfigure(1, weight=1)

        status_frame = ttk.Frame(mid)
        status_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=6)
        status_frame.columnconfigure(3, weight=1)

        ttk.Label(status_frame, text="Engine:").grid(row=0, column=0, sticky="w")
        self.lbl_state = ttk.Label(status_frame, text="-", foreground="#444", font=("TkDefaultFont", 9, "bold"))
        self.lbl_state.grid(row=0, column=1, sticky="w", padx=(5, 20))

        ttk.Label(status_frame, text="Event Queue:").grid(row=0, column=2, sticky="w")
        self.lbl_event_queue = ttk.Label(status_frame, text="-", foreground="#444")
        self.lbl_event_queue.grid(row=0, column=3, sticky="w", padx=(5, 20))

        ttk.Label(status_frame, text="Avg Decision:").grid(row=0, column=4, sticky="w")
        self.lbl_avg_decision = ttk.Label(status_frame, text="-", foreground="#444")
        self.lbl_avg_decision.grid(row=0, column=5, sticky="w", padx=(5, 0))

        services_frame = ttk.Frame(mid)
        services_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 6))

        ttk.Label(services_frame, text="Services:").grid(row=0, column=0, sticky="w")

        self.lbl_notif_service = ttk.Label(services_frame, text="Notifications: -", foreground="#666")
        self.lbl_notif_service.grid(row=0, column=1, sticky="w", padx=(5, 15))

        self.lbl_history_service = ttk.Label(services_frame, text="History: -", foreground="#666")
        self.lbl_history_service.grid(row=0, column=2, sticky="w", padx=(0, 15))

        self.lbl_decision_service = ttk.Label(services_frame, text="Decision workers: -", foreground="#666")
        self.lbl_decision_service.grid(row=0, column=3, sticky="w")

        # ========== DEVICES TABLE ==========
        box = ttk.LabelFrame(self, text="Devices status")
        box.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 10))
        box.columnconfigure(0, weight=1)
        box.rowconfigure(0, weight=1)

        cols = (
            "deviceId",
            "name",
            "enabled",
            "connected",
            "lastEventAt",
            "lastError",
            "polls",
            "events",
            "pollEma",
            "cmdEma",
            "reconnectCount",
        )
        self.tree = ttk.Treeview(box, columns=cols, show="headings", height=14)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, anchor="w", width=100)

        self.tree.column("deviceId", width=80)
        self.tree.column("name", width=220)
        self.tree.column("enabled", width=60)
        self.tree.column("connected", width=80)
        self.tree.column("lastEventAt", width=170)
        self.tree.column("lastError", width=260)
        self.tree.column("polls", width=60)
        self.tree.column("events", width=60)
        self.tree.column("pollEma", width=90)
        self.tree.column("cmdEma", width=90)
        self.tree.column("reconnectCount", width=110)

        self.tree.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=10)
        sb = ttk.Scrollbar(box, orient="vertical", command=self.tree.yview)
        sb.grid(row=0, column=1, sticky="ns", padx=(0, 10), pady=10)
        self.tree.configure(yscrollcommand=sb.set)

        # ========== DEVICE HISTORY TABLE ==========
        history_box = ttk.LabelFrame(self, text="Recent Access Events (Last 10)")
        history_box.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0, 10))
        history_box.columnconfigure(0, weight=1)
        history_box.rowconfigure(0, weight=1)

        hist_cols = (
            "timestamp",
            "deviceId",
            "cardNo",
            "allowed",
            "reason",
            "pollMs",
            "decisionMs",
        )
        self.history_tree = ttk.Treeview(history_box, columns=hist_cols, show="headings", height=10)
        for c in hist_cols:
            self.history_tree.heading(c, text=c)
            self.history_tree.column(c, anchor="w", width=100)

        self.history_tree.column("timestamp", width=170)
        self.history_tree.column("deviceId", width=80)
        self.history_tree.column("cardNo", width=120)
        self.history_tree.column("allowed", width=70)
        self.history_tree.column("reason", width=200)
        self.history_tree.column("pollMs", width=80)
        self.history_tree.column("decisionMs", width=100)

        self.history_tree.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=10)
        hist_sb = ttk.Scrollbar(history_box, orient="vertical", command=self.history_tree.yview)
        hist_sb.grid(row=0, column=1, sticky="ns", padx=(0, 10), pady=10)
        self.history_tree.configure(yscrollcommand=hist_sb.set)

        # ========== ACTIONS ==========
        act = ttk.Frame(self)
        act.grid(row=4, column=0, sticky="ew", padx=10, pady=(0, 12))
        ttk.Button(act, text="Enable selected", command=lambda: self._set_selected_enabled(True)).pack(side="left", padx=(0, 8))
        ttk.Button(act, text="Disable selected", command=lambda: self._set_selected_enabled(False)).pack(side="left", padx=(0, 8))
        ttk.Button(act, text="Edit selected", command=self._edit_selected).pack(side="left", padx=(0, 8))
        ttk.Button(act, text="Clear history view", command=self._clear_history_view).pack(side="left")
        ttk.Button(act, text="Refresh history", command=self._refresh_history).pack(side="left", padx=(8, 0))

        self._rows: Dict[int, str] = {}
        self._history_events: list = []

        # NEW: popup manager (uses app root)
        # parent.winfo_toplevel() should be the root window in most apps
        root = self.winfo_toplevel()
        self._popup_mgr = PopupManager(root, get_settings=self.app.cfg.get_agent_global)

        self._tick()

    def _engine(self):
        return getattr(self.app, "_agent_engine", None)

    def _save_global(self):
        try:
            # agent_realtime_enabled is a LOCAL toggle (kept in config.json)
            self.app.cfg.agent_realtime_enabled = bool(self.var_enabled.get())
            self.app.persist_config()
            self.app.apply_realtime_agent_from_config()

            # Refresh displayed values from backend SQLite cache
            g = self.app.cfg.get_agent_global()
            self.var_rate.set(str(g.get("notification_rate_limit_per_minute", 30)))
            self.var_dedupe.set(str(g.get("notification_dedupe_window_sec", 30)))
            self.var_retention.set(str(g.get("history_retention_days", 30)))
            self.var_queue_max.set(str(g.get("event_queue_max", 5000)))
            self.var_deciders.set(str(g.get("decision_workers", 1)))
            self.var_notify_queue_max.set(str(g.get("notification_queue_max", 5000)))
            self.var_history_queue_max.set(str(g.get("history_queue_max", 5000)))
            self.var_decision_ema_alpha.set(str(g.get("decision_ema_alpha", 0.2)))
            self.var_notification_service_enabled.set(bool(g.get("notification_service_enabled", True)))
            self.var_history_service_enabled.set(bool(g.get("history_service_enabled", True)))
            self.var_img_cache_enabled.set(bool(g.get("image_cache_enabled", True)))
            self.var_img_cache_timeout.set(str(g.get("image_cache_timeout_sec", 2.0)))
            self.var_img_cache_max_bytes.set(str(g.get("image_cache_max_bytes", 5242880)))
            self.var_img_cache_max_files.set(str(g.get("image_cache_max_files", 1000)))

            messagebox.showinfo(
                "Settings",
                "Agent enabled/disabled toggle saved.\n\n"
                "Note: global settings (queues, notification limits, history retention, "
                "image cache, etc.) are now managed from the backend dashboard and are "
                "read-only here. Values have been refreshed from cache.",
            )
        except Exception as e:
            messagebox.showerror("Save settings", str(e))

    def _start(self):
        self._save_global()
        try:
            self.app.start_realtime_agent()
        except Exception as e:
            messagebox.showerror("Start", str(e))

    def _stop(self):
        try:
            self.app.stop_realtime_agent()
        except Exception as e:
            messagebox.showerror("Stop", str(e))

    def _refresh(self):
        try:
            eng = self._engine()
            if eng:
                eng.refresh_devices()
        except Exception:
            pass

    def _test_notification(self):
        try:
            eng = self._engine()
            if not eng:
                messagebox.showwarning("Test Notification", "Engine not initialized. Please start the agent first.")
                return

            if not eng.is_running():
                messagebox.showwarning("Test Notification", "Engine not running. Please start the agent first.")
                return

            g = self.app.cfg.get_agent_global()
            if not bool(g.get("notification_service_enabled", True)):
                messagebox.showwarning("Test Notification", "Notification service is disabled. Enable it in settings first.")
                return

            notif_service = getattr(eng, "_notif", None)
            if not notif_service:
                messagebox.showerror("Test Notification", "Notification service not found.")
                return

            if not notif_service.is_alive():
                messagebox.showwarning("Test Notification", "Notification service is not running.")
                return

            timestamp = time.strftime("%H:%M:%S")
            # Use a test image if you want:
            test_image = "https://res.cloudinary.com/dp0bb09le/image/upload/v1769470307/23/images/profile/1769470307336_logo_arena400300.png"

            req = NotificationRequest(
                event_id=f"test-{timestamp}",
                title="🔔 Test Notification",
                message=f"Test popup + winotify at {timestamp} ✅",
                image_path=test_image,
            )

            notify_q = getattr(eng, "_notify_q", None)
            popup_q = getattr(eng, "_popup_q", None)

            if not notify_q or not popup_q:
                messagebox.showerror("Test Notification", "Notification queues not found (notify_q/popup_q).")
                return

            try:
                notify_q.put(req, timeout=0.5)  # winotify
            except Exception:
                pass
            try:
                popup_q.put(req, timeout=0.5)   # in-app popup
            except Exception:
                pass

            messagebox.showinfo("Test Notification", f"Queued test notification at {timestamp}.")
        except Exception as e:
            messagebox.showerror("Test Notification", f"Error: {e}")

    def _selected_device_id(self) -> Optional[int]:
        sel = self.tree.selection()
        if not sel:
            return None
        iid = sel[0]
        vals = self.tree.item(iid, "values") or []
        if not vals:
            return None
        try:
            return int(vals[0])
        except Exception:
            return None

    def _set_selected_enabled(self, enabled: bool):
        did = self._selected_device_id()
        if did is None:
            return

        # Device enabled/disabled is controlled by backend (active + accessDevice).
        # This only temporarily toggles the local worker until next refresh.
        eng = self._engine()
        if eng:
            try:
                eng.set_device_enabled(did, enabled)
            except Exception:
                pass

    def _edit_selected(self):
        did = self._selected_device_id()
        if did is None:
            messagebox.showinfo("Edit device", "Please select a device first.")
            return
        DeviceSettingsDialog(self, self.app, did)

    def _clear_history_view(self):
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        self._history_events.clear()

    def _refresh_history(self):
        try:
            from app.core.db import get_recent_access_history

            history = get_recent_access_history(limit=10)
            self._clear_history_view()

            for record in history:
                self.history_tree.insert("", "end", values=(
                    record.event_time,
                    record.device_id,
                    record.card_no,
                    "✓" if record.allowed else "✗",
                    record.reason[:30] + "..." if len(record.reason) > 30 else record.reason,
                    f"{record.poll_ms:.1f}",
                    f"{record.decision_ms:.1f}"
                ))
        except Exception as e:
            self.app.logger.error(f"Failed to refresh history: {e}")

    # NEW: consume popup queue and show popups (UI thread)
    def _drain_popup_queue(self) -> None:
        eng = self._engine()
        if not eng or not eng.is_running():
            return

        try:
            g = self.app.cfg.get_agent_global()
        except Exception:
            g = {}

        if not bool(g.get("popup_enabled", True)):
            return

        popup_q = getattr(eng, "_popup_q", None)
        if not popup_q:
            return

        # Drain quickly (non-blocking)
        for _ in range(10):
            try:
                r = popup_q.get_nowait()
            except Exception:
                break

            if isinstance(r, NotificationRequest):
                try:
                    self._popup_mgr.show(r.title, r.message, r.image_path or "")
                except Exception:
                    pass

    def _tick(self):
        eng = self._engine()
        running = bool(eng and eng.is_running())

        if running:
            self.lbl_state.config(text="Running", foreground="#008800")
        else:
            self.lbl_state.config(text="Stopped", foreground="#cc0000")

        event_qd = 0
        avg_dec = 0.0
        if eng and running:
            try:
                event_qd = eng.get_queue_depth()
            except Exception:
                event_qd = 0
            try:
                avg_dec = float(eng.get_avg_decision_ms())
            except Exception:
                avg_dec = 0.0

        self.lbl_event_queue.config(text=f"{event_qd}")
        self.lbl_avg_decision.config(text=f"{avg_dec:.1f} ms")

        # Drain popups (NEW)
        try:
            self._drain_popup_queue()
        except Exception:
            pass

        # Update service status
        if eng and running:
            try:
                g = self.app.cfg.get_agent_global()
                notif_enabled_in_config = bool(g.get("notification_service_enabled", True))
                hist_enabled_in_config = bool(g.get("history_service_enabled", True))

                notif_service = getattr(eng, "_notif", None)
                if notif_service and notif_enabled_in_config:
                    notif_alive = notif_service.is_alive()
                    notif_status = "✓ Active" if notif_alive else "✗ Stopped"
                    notif_color = "#008800" if notif_alive else "#cc0000"
                    self.lbl_notif_service.config(text=f"Notifications: {notif_status}", foreground=notif_color)
                elif not notif_enabled_in_config:
                    self.lbl_notif_service.config(text="Notifications: Disabled", foreground="#999")
                else:
                    self.lbl_notif_service.config(text="Notifications: -", foreground="#666")

                hist_service = getattr(eng, "_hist", None)
                if hist_service and hist_enabled_in_config:
                    hist_alive = hist_service.is_alive()
                    hist_status = "✓ Active" if hist_alive else "✗ Stopped"
                    hist_color = "#008800" if hist_alive else "#cc0000"
                    self.lbl_history_service.config(text=f"History: {hist_status}", foreground=hist_color)
                elif not hist_enabled_in_config:
                    self.lbl_history_service.config(text="History: Disabled", foreground="#999")
                else:
                    self.lbl_history_service.config(text="History: -", foreground="#666")

                deciders = getattr(eng, "_deciders", [])
                active_count = sum(1 for d in deciders if d.is_alive())
                total_count = len(deciders)
                worker_status = f"{active_count}/{total_count} active"
                worker_color = "#008800" if active_count == total_count else "#cc6600"
                self.lbl_decision_service.config(text=f"Decision workers: {worker_status}", foreground=worker_color)
            except Exception:
                self.lbl_notif_service.config(text="Notifications: -", foreground="#666")
                self.lbl_history_service.config(text="History: -", foreground="#666")
                self.lbl_decision_service.config(text="Decision workers: -", foreground="#666")
        else:
            self.lbl_notif_service.config(text="Notifications: -", foreground="#666")
            self.lbl_history_service.config(text="History: -", foreground="#666")
            self.lbl_decision_service.config(text="Decision workers: -", foreground="#666")

        # Device status snapshot
        snap = {}
        if eng and running:
            try:
                snap = eng.get_status_snapshot()
            except Exception:
                snap = {}

        existing_ids = set(self._rows.keys())
        incoming_ids = set(int(k) for k in snap.keys())

        for did in list(existing_ids - incoming_ids):
            iid = self._rows.get(did)
            if iid:
                try:
                    self.tree.delete(iid)
                except Exception:
                    pass
            self._rows.pop(did, None)

        for did in sorted(incoming_ids):
            r = snap.get(did, {})

            last_event_at = r.get("lastEventAt", 0.0)
            if last_event_at > 0:
                from datetime import datetime
                last_event_str = datetime.fromtimestamp(last_event_at).strftime("%Y-%m-%d %H:%M:%S")
            else:
                last_event_str = ""

            vals = (
                did,
                _safe_str(r.get("name"), ""),
                "✓" if bool(r.get("enabled", True)) else "✗",
                "✓" if bool(r.get("connected", False)) else "✗",
                last_event_str,
                _safe_str(r.get("lastError"), ""),
                str(int(r.get("polls") or 0)),
                str(int(r.get("events") or 0)),
                f"{float(r.get('pollEma') or 0.0):.1f}",
                f"{float(r.get('cmdEma') or 0.0):.1f}",
                str(int(r.get("reconnects") or 0)),
            )

            if did not in self._rows:
                iid = self.tree.insert("", "end", values=vals)
                self._rows[did] = iid
            else:
                iid = self._rows[did]
                try:
                    self.tree.item(iid, values=vals)
                except Exception:
                    pass

        self.after(250, self._tick)


class DeviceSettingsDialog(tk.Toplevel):
    def __init__(self, parent, app, device_id: int):
        super().__init__(parent)
        self.app = app
        self.device_id = int(device_id)

        self.title(f"Device settings - deviceId={self.device_id}")
        self.geometry("560x780")
        self.resizable(False, False)

        s = self.app.cfg.get_agent_device_settings(self.device_id)

        self.var_enabled = tk.BooleanVar(value=bool(s.get("enabled", True)))
        self.var_adaptive = tk.BooleanVar(value=bool(s.get("adaptive_sleep", True)))

        self.var_busy_min = tk.StringVar(value=str(s.get("busy_sleep_min_ms", 0)))
        self.var_busy_max = tk.StringVar(value=str(s.get("busy_sleep_max_ms", 50)))
        self.var_empty_min = tk.StringVar(value=str(s.get("empty_sleep_min_ms", 200)))
        self.var_empty_max = tk.StringVar(value=str(s.get("empty_sleep_max_ms", 500)))
        self.var_backoff_factor = tk.StringVar(value=str(s.get("empty_backoff_factor", 1.35)))
        self.var_backoff_max = tk.StringVar(value=str(s.get("empty_backoff_max_ms", 2000)))

        self.var_timeout = tk.StringVar(value=str(s.get("timeout_ms", int(self.app.cfg.device_timeout_ms))))
        self.var_rtlog_table = tk.StringVar(value=_safe_str(s.get("rtlog_table", "rtlog")))

        self.var_door_entry = tk.StringVar(value=str(s.get("door_entry_id", 1)))
        self.var_pulse_ms = tk.StringVar(value=str(s.get("pulse_time_ms", 3000)))

        self.var_save_history = tk.BooleanVar(value=bool(s.get("save_history", True)))
        self.var_notifications = tk.BooleanVar(value=bool(s.get("show_notifications", True)))

        self.var_replay_sec = tk.StringVar(value=str(s.get("replay_block_window_seconds", 10)))
        self.var_lru_size = tk.StringVar(value=str(s.get("replay_lru_size", 2000)))
        self.var_cmd_timeout = tk.StringVar(value=str(s.get("cmd_timeout_ms", 4000)))

        self.var_poll_ema_alpha = tk.StringVar(value=str(s.get("poll_ema_alpha", 0.2)))
        self.var_cmd_ema_alpha = tk.StringVar(value=str(s.get("cmd_ema_alpha", 0.2)))

        self.var_totp_enabled = tk.BooleanVar(value=bool(s.get("totp_enabled", True)))
        self.var_totp_digits = tk.StringVar(value=str(s.get("totp_digits", 8)))
        self.var_totp_period = tk.StringVar(value=str(s.get("totp_period_seconds", 30)))
        self.var_totp_drift = tk.StringVar(value=str(s.get("totp_drift_steps", 1)))
        self.var_totp_max_past = tk.StringVar(value=str(s.get("totp_max_past_age_seconds", 32)))
        self.var_totp_max_future = tk.StringVar(value=str(s.get("totp_max_future_skew_seconds", 3)))
        self.var_totp_prefix = tk.StringVar(value=str(s.get("totp_prefix", "9")))

        self.var_rfid_enabled = tk.BooleanVar(value=bool(s.get("rfid_enabled", True)))
        self.var_rfid_digits = tk.StringVar(value=str(s.get("rfid_digits", 8)))

        canvas = tk.Canvas(self, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True, padx=12, pady=12)
        scrollbar.pack(side="right", fill="y", pady=12)

        frm = scrollable_frame
        r = 0

        ttk.Label(frm, text="Basic Settings", font=("TkDefaultFont", 10, "bold")).grid(
            row=r, column=0, sticky="w", pady=(0, 4), columnspan=2
        )
        r += 1

        ttk.Checkbutton(frm, text="Enabled", variable=self.var_enabled).grid(row=r, column=0, sticky="w", pady=4)
        r += 1

        ttk.Checkbutton(frm, text="Adaptive sleep", variable=self.var_adaptive).grid(row=r, column=0, sticky="w", pady=4)
        r += 1

        ttk.Separator(frm).grid(row=r, column=0, columnspan=2, sticky="ew", pady=10)
        r += 1

        ttk.Label(frm, text="Sleep & Polling Settings", font=("TkDefaultFont", 10, "bold")).grid(
            row=r, column=0, sticky="w", pady=(0, 4), columnspan=2
        )
        r += 1

        def row_entry(label: str, var: tk.StringVar):
            nonlocal r
            ttk.Label(frm, text=label).grid(row=r, column=0, sticky="w", pady=4)
            ttk.Entry(frm, textvariable=var, width=18).grid(row=r, column=1, sticky="w", pady=4, padx=(10, 0))
            r += 1

        row_entry("Busy sleep min (ms)", self.var_busy_min)
        row_entry("Busy sleep max (ms)", self.var_busy_max)
        row_entry("Empty sleep min (ms)", self.var_empty_min)
        row_entry("Empty sleep max (ms)", self.var_empty_max)
        row_entry("Empty backoff factor", self.var_backoff_factor)
        row_entry("Empty backoff max (ms)", self.var_backoff_max)

        ttk.Separator(frm).grid(row=r, column=0, columnspan=2, sticky="ew", pady=10)
        r += 1

        ttk.Label(frm, text="Connection Settings", font=("TkDefaultFont", 10, "bold")).grid(
            row=r, column=0, sticky="w", pady=(0, 4), columnspan=2
        )
        r += 1

        row_entry("Timeout (ms)", self.var_timeout)
        row_entry("RTLog table", self.var_rtlog_table)

        ttk.Separator(frm).grid(row=r, column=0, columnspan=2, sticky="ew", pady=10)
        r += 1

        ttk.Label(frm, text="Door Control", font=("TkDefaultFont", 10, "bold")).grid(
            row=r, column=0, sticky="w", pady=(0, 4), columnspan=2
        )
        r += 1

        row_entry("Entry door id", self.var_door_entry)
        row_entry("Pulse time (ms)", self.var_pulse_ms)
        row_entry("Command timeout (ms)", self.var_cmd_timeout)

        ttk.Separator(frm).grid(row=r, column=0, columnspan=2, sticky="ew", pady=10)
        r += 1

        ttk.Label(frm, text="Features", font=("TkDefaultFont", 10, "bold")).grid(
            row=r, column=0, sticky="w", pady=(0, 4), columnspan=2
        )
        r += 1

        ttk.Checkbutton(frm, text="Save history", variable=self.var_save_history).grid(row=r, column=0, sticky="w", pady=4)
        r += 1
        ttk.Checkbutton(frm, text="Show notifications", variable=self.var_notifications).grid(row=r, column=0, sticky="w", pady=4)
        r += 1

        ttk.Separator(frm).grid(row=r, column=0, columnspan=2, sticky="ew", pady=10)
        r += 1

        ttk.Label(frm, text="Replay Protection", font=("TkDefaultFont", 10, "bold")).grid(
            row=r, column=0, sticky="w", pady=(0, 4), columnspan=2
        )
        r += 1

        row_entry("Replay window (sec)", self.var_replay_sec)
        row_entry("Replay LRU size", self.var_lru_size)

        ttk.Separator(frm).grid(row=r, column=0, columnspan=2, sticky="ew", pady=10)
        r += 1

        ttk.Label(frm, text="Performance Tracking (EMA)", font=("TkDefaultFont", 10, "bold")).grid(
            row=r, column=0, sticky="w", pady=(0, 4), columnspan=2
        )
        r += 1

        row_entry("Poll time EMA alpha", self.var_poll_ema_alpha)
        row_entry("Command time EMA alpha", self.var_cmd_ema_alpha)

        ttk.Separator(frm).grid(row=r, column=0, columnspan=2, sticky="ew", pady=10)
        r += 1

        ttk.Label(frm, text="TOTP/RFID Settings", font=("TkDefaultFont", 10, "bold")).grid(
            row=r, column=0, sticky="w", pady=(0, 4), columnspan=2
        )
        r += 1

        ttk.Checkbutton(frm, text="Enable TOTP verification", variable=self.var_totp_enabled).grid(
            row=r, column=0, sticky="w", pady=4, columnspan=2
        )
        r += 1

        row_entry("TOTP digits", self.var_totp_digits)
        row_entry("TOTP period (sec)", self.var_totp_period)
        row_entry("TOTP drift steps", self.var_totp_drift)
        row_entry("Max past age (sec)", self.var_totp_max_past)
        row_entry("Max future skew (sec)", self.var_totp_max_future)
        row_entry("TOTP prefix", self.var_totp_prefix)

        ttk.Checkbutton(frm, text="Enable RFID verification", variable=self.var_rfid_enabled).grid(
            row=r, column=0, sticky="w", pady=4, columnspan=2
        )
        r += 1

        row_entry("RFID digits", self.var_rfid_digits)

        btns = ttk.Frame(frm)
        btns.grid(row=r, column=0, columnspan=2, sticky="w", pady=(14, 0))
        ttk.Button(btns, text="Close", command=self.destroy).pack(side="left")
        r += 1

        # Read-only notice
        ttk.Label(frm, text="ℹ Device settings are read-only (managed from backend dashboard).",
                  foreground="#666", wraplength=500).grid(row=r, column=0, columnspan=2, sticky="w", pady=(8, 0))

    def _save(self):
        """
        DEPRECATED (Mar 2026): device settings are now READ-ONLY from backend.
        """
        messagebox.showinfo(
            "Read-only",
            "Device settings are now managed from the backend dashboard.\n\n"
            "This dialog shows current cached values for reference only.",
        )

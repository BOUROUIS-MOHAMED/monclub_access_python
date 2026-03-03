# monclub_access_python/app/ui/app.py
from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from app.api.monclub_api import ApiEndpoints, MonClubApi
from app.api.local_access_api import LocalAccessApiServer
from app.core.arch import platform_summary, require_32bit_python_for_32bit_dll
from app.core.config import load_config, save_config
from app.core.db import (
    init_db,
    load_auth_token,
    clear_auth_token,
    load_sync_cache,
    save_sync_cache,
)
from app.core.logger import setup_logging
from app.core.update_manager import UpdateManager, UpdateStatus
from app.core.utils import (
    APP_NAME,
    ensure_dirs,
    to_b64,
    to_hex,
    resolve_resource_path,
    add_windows_dll_search_paths,
)

from app.core.device_sync import DeviceSyncEngine
from app.core.realtime_agent import AgentRealtimeEngine

from app.ui.tray import TrayController

from app.ui.pages.configuration_page import ConfigurationPage
from app.ui.pages.device_page import DevicePage
from app.ui.pages.users_page import UsersPage
from app.ui.pages.enroll_page import EnrollPage
from app.ui.pages.logs_page import LogsPage

from app.ui.pages.login_page import LoginPage
from app.ui.pages.restricted_page import RestrictedPage
from app.ui.pages.local_db_page import LocalDatabasePage

from app.ui.pages.device_info_page import DeviceInfoPage
from app.ui.pages.popups.enroll_status_popup import EnrollStatusPopup
from app.ui.pages.agent_realtime_page import AgentRealtimePage

from app.sdk.zkfinger import ZKFinger, ZKFingerError


def _parse_dt_any(s: str) -> datetime | None:
    if not s:
        return None
    s = str(s).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1]
    try:
        return datetime.fromisoformat(s)
    except Exception:
        pass
    try:
        if len(s) == 10 and s[4] == "-" and s[7] == "-":
            return datetime.fromisoformat(s + "T00:00:00")
    except Exception:
        pass
    return None


def _encoding_to_backend(enc: str) -> str:
    e = (enc or "").strip().lower()
    return "HEX" if e == "hex" else "BASE64"


class MainApp(tk.Tk):
    """
    IMPORTANT CHANGE (Mar 2026):
    - "mode" is no longer global (no cfg.data_mode driving UI/engines).
    - accessDataMode is PER DEVICE (DEVICE/AGENT) from backend cache (SQLite).
    - Therefore: UI shows BOTH device + agent tabs, and engines run based on per-device filtering
      (device_sync.py filters DEVICE devices; realtime_agent.py filters AGENT devices).
    """

    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1250x780")

        # Add DLL search paths ASAP (Windows/Python 3.8+)
        try:
            add_windows_dll_search_paths()
        except Exception:
            pass

        ensure_dirs()
        init_db()

        self.log_queue: "queue.Queue[str]" = queue.Queue()
        self.cfg = load_config()

        # Resolve SDK DLLs robustly (dev + frozen + stale-absolute handling)
        try:
            self.cfg.plcomm_dll_path = self._resolve_sdk_dll(self.cfg.plcomm_dll_path)
            self.cfg.zkfp_dll_path = self._resolve_sdk_dll(self.cfg.zkfp_dll_path)
        except Exception as e:
            messagebox.showerror(
                "SDK resource error",
                f"Failed to resolve required SDK DLLs.\n\n{e}\n\nPlatform: {platform_summary()}",
            )
            raise

        # Enforce 32-bit requirement for 32-bit DLLs
        try:
            require_32bit_python_for_32bit_dll(self.cfg.plcomm_dll_path)
        except Exception as e:
            messagebox.showerror("Architecture error", f"{e}\n\nPlatform: {platform_summary()}")
            raise

        self.logger = setup_logging(self.cfg.log_level, ui_queue=self.log_queue)
        self.logger.info("App started.")
        self.logger.info(f"Platform: {platform_summary()}")
        self.logger.info("Data root is managed by app.core.utils (ProgramData/LocalAppData).")
        self.logger.info(f"PullSDK DLL: {self.cfg.plcomm_dll_path}")
        self.logger.info(f"ZKFP DLL  : {self.cfg.zkfp_dll_path}")

        self._update_manager = UpdateManager(app=self, cfg=self.cfg, logger=self.logger, api_factory=self._api)
        self._update_status: Optional[UpdateStatus] = None

        self._sync_after_id: str | None = None
        self._local_api: Optional[LocalAccessApiServer] = None

        self._enroll_state_lock = threading.Lock()
        self._enroll_running: bool = False

        self._device_sync_engine = DeviceSyncEngine(cfg=self.cfg, logger=self.logger)

        # realtime agent engine (per-device AGENT mode)
        self._agent_engine = AgentRealtimeEngine(cfg=self.cfg, logger=self.logger)

        self._tray: Optional[TrayController] = None

        # must be re-entrant (apply_realtime_agent_from_config calls start/stop which also lock)
        self._agent_lock = threading.RLock()

        # track which "root" view is currently shown to avoid tab forcing on every sync
        self._active_view: str = "unknown"  # "login" | "restricted" | "app" | "unknown"

        self.container = ttk.Frame(self)
        self.container.pack(fill="both", expand=True)
        self.container.rowconfigure(0, weight=1)
        self.container.columnconfigure(0, weight=1)

        self.screen_app = ttk.Frame(self.container)
        self.screen_app.grid(row=0, column=0, sticky="nsew")
        self.screen_app.rowconfigure(0, weight=1)
        self.screen_app.columnconfigure(0, weight=1)

        nb = ttk.Notebook(self.screen_app)
        nb.grid(row=0, column=0, sticky="nsew")
        self.nb = nb

        # Global overlay buttons (visible on login/restricted/app)
        # Update button (shown when update is available, not only when downloaded)
        self._update_btn = ttk.Button(self, text="⬇ Download", command=self._on_click_update)
        self._update_btn.place(relx=1.0, x=-12, y=8, anchor="ne")
        self._update_btn.place_forget()

        # Logout button (shown when logged-in, hidden on login)
        self._logout_btn = ttk.Button(self, text="⎋ Logout", command=self._on_click_logout)
        self._logout_btn.place(relx=1.0, x=-120, y=8, anchor="ne")  # left of update button
        self._logout_btn.place_forget()

        self.page_config = ConfigurationPage(nb, app=self)
        self.page_device = DevicePage(nb, app=self)
        self.page_device_info = DeviceInfoPage(nb, app=self)
        self.page_users = UsersPage(nb, app=self)
        self.page_agent_rt = AgentRealtimePage(nb, app=self)
        self.page_enroll = EnrollPage(nb, app=self)
        self.page_local_db = LocalDatabasePage(nb, app=self)
        self.page_logs = LogsPage(nb, app=self)

        # NEW: tabs are no longer rebuilt from a global mode (DEVICE/AGENT).
        self._tabs_built: bool = False
        self._rebuild_tabs_from_mode()  # kept name for backward compatibility

        self.page_login = LoginPage(self.container, app=self)
        self.page_login.grid(row=0, column=0, sticky="nsew")

        self.page_restricted = RestrictedPage(self.container, app=self)
        self.page_restricted.grid(row=0, column=0, sticky="nsew")

        self.protocol("WM_DELETE_WINDOW", self._on_close_app)

        self.after(200, self._poll_logs)
        self.after(400, self.start_local_api_server)
        self.after(500, self.reschedule_sync_timer)

        # NEW: run update check at app startup (if token exists)
        self.after(650, lambda: self._ensure_update_manager_started(check_now=True))

        self.after(700, self.evaluate_access_and_redirect)
        self.after(800, self._start_tray_if_enabled)

        if bool(getattr(self.cfg, "start_minimized_to_tray", False)):
            self.after(1200, self.hide_to_tray)

    # ---------------- Update Manager bootstrap ----------------
    def _ensure_update_manager_started(self, *, check_now: bool) -> None:
        """
        Start update checks when a saved token exists.
        Stop when no token exists (logout / first install).
        """
        try:
            auth = load_auth_token()
            tok = getattr(auth, "token", None) if auth else None
            tok = str(tok or "").strip()
            if tok:
                # check_now=True only at startup (or if you explicitly want)
                self._update_manager.start(token=tok, check_now=check_now)
            else:
                self._update_manager.stop()
        except Exception:
            pass

    # ---------------- Update UI hooks (called by UpdateManager) ----------------
    def on_update_status_changed(self, st: UpdateStatus) -> None:
        # called on UI thread
        self._update_status = st

        # Show button whenever update is available (downloaded OR not).
        # Text/state adapts to downloading vs ready.
        try:
            update_available = bool(getattr(st, "update_available", False))
            downloaded = bool(getattr(st, "downloaded", False))
            downloading = bool(getattr(st, "downloading", False))

            # progress may be named differently across implementations; keep robust
            progress = getattr(st, "progress", None)
            if progress is None:
                progress = getattr(st, "download_progress", None)
            if progress is None:
                progress = getattr(st, "progress_percent", None)

            if update_available:
                if downloaded:
                    self._update_btn.configure(text="⬆ Update")
                    try:
                        self._update_btn.state(["!disabled"])
                    except Exception:
                        pass
                else:
                    if downloading:
                        txt = "⬇ Downloading…"
                        try:
                            if progress is not None:
                                txt = f"⬇ Downloading… {int(progress)}%"
                        except Exception:
                            pass
                        self._update_btn.configure(text=txt)
                        try:
                            self._update_btn.state(["disabled"])
                        except Exception:
                            pass
                    else:
                        self._update_btn.configure(text="⬇ Download")
                        try:
                            self._update_btn.state(["!disabled"])
                        except Exception:
                            pass

                self._update_btn.place(relx=1.0, x=-12, y=8, anchor="ne")
                try:
                    self._update_btn.lift()
                except Exception:
                    pass
            else:
                self._update_btn.place_forget()
        except Exception:
            pass

    def on_update_ready(self, st: UpdateStatus) -> None:
        # one-time notification per releaseId (handled by manager too)
        try:
            rid = str((st.latest_release or {}).get("releaseId") or "")
            messagebox.showinfo(
                "Update ready",
                f"A new update is ready.\n\nRelease: {rid}\n\nClick ⬆ Update to restart and install.",
            )
        except Exception:
            pass

    def on_update_error(self, msg: str) -> None:
        # silent-ish: log only; don’t spam messageboxes
        try:
            self.logger.warning("[Update] %s", msg)
        except Exception:
            pass

    def _request_update_download_best_effort(self) -> bool:
        """
        Try common method names across possible UpdateManager implementations.
        Returns True if we successfully invoked a callable.
        """
        um = getattr(self, "_update_manager", None)
        if not um:
            return False

        for name in (
            "request_download",
            "start_download",
            "download_update",
            "download_latest",
            "download_if_needed",
            "ensure_download",
            "begin_download",
            "trigger_download",
        ):
            fn = getattr(um, name, None)
            if callable(fn):
                try:
                    fn()
                    return True
                except Exception:
                    return False
        return False

    def _on_click_update(self):
        st = self._update_status
        if not st or not bool(getattr(st, "update_available", False)):
            return

        downloaded = bool(getattr(st, "downloaded", False))
        downloading = bool(getattr(st, "downloading", False))

        if downloading and not downloaded:
            return

        if not downloaded:
            ok = messagebox.askyesno("Download update", "An update is available.\n\nDownload it now?")
            if not ok:
                return

            started = self._request_update_download_best_effort()
            if started:
                try:
                    self.logger.info("[Update] Download requested by user.")
                except Exception:
                    pass
                try:
                    messagebox.showinfo("Update", "Downloading update in the background…")
                except Exception:
                    pass
            else:
                messagebox.showinfo(
                    "Update",
                    "An update is available.\n\nIt will be downloaded automatically, or your updater doesn't expose a manual download trigger.",
                )
            return

        rid = ""
        try:
            rid = str((st.latest_release or {}).get("releaseId") or "")
        except Exception:
            rid = ""

        ok = messagebox.askyesno(
            "Install update",
            f"A new update is ready ({rid}).\n\nRestart MonClub Access to install it now?",
        )
        if not ok:
            return

        try:
            self._update_manager.launch_updater_and_exit()
        except Exception as e:
            messagebox.showerror("Update failed", str(e))
            return

        self.quit_app()

    # ---------------- Logout ----------------
    def _refresh_logout_btn(self) -> None:
        """Show logout button when a token exists (even if restricted)."""
        try:
            auth = load_auth_token()
            logged_in = bool(auth and getattr(auth, "token", None))
            if logged_in:
                self._logout_btn.place(relx=1.0, x=-120, y=8, anchor="ne")
                try:
                    self._logout_btn.lift()
                except Exception:
                    pass
            else:
                self._logout_btn.place_forget()
        except Exception:
            pass

    def _on_click_logout(self) -> None:
        auth = load_auth_token()
        if not auth or not getattr(auth, "token", None):
            self._refresh_logout_btn()
            return

        ok = messagebox.askyesno(
            "Logout",
            "Logout from this PC?\n\nThis will remove the saved token and return you to the login screen.",
        )
        if not ok:
            return

        try:
            self.stop_realtime_agent()
        except Exception:
            pass

        try:
            clear_auth_token()
        except Exception:
            pass

        # stop update checks too (no token anymore)
        try:
            self._update_manager.stop()
        except Exception:
            pass

        # Optional best-effort: clear cached sync (safe if db layer doesn't accept None)
        try:
            save_sync_cache(None)  # if not supported, exception is caught
        except Exception:
            pass

        try:
            self.logger.info("Logout OK: token cleared.")
        except Exception:
            pass

        self._refresh_logout_btn()
        self.evaluate_access_and_redirect()

    def _resolve_sdk_dll(self, configured_path: str) -> str:
        """
        Resolve a DLL path using resolve_resource_path(). Also handles cases where the config
        contains an old absolute path that no longer exists (user moved the folder).
        """
        s = (configured_path or "").strip()
        if not s:
            raise FileNotFoundError("Empty DLL path in config")

        # 1) Try as-is
        try:
            return str(resolve_resource_path(s, must_exist=True))
        except Exception:
            pass

        # 2) If it looks like an absolute path but is stale, retry by filename only
        name = Path(s).name
        try:
            return str(resolve_resource_path(name, must_exist=True))
        except Exception as e:
            raise FileNotFoundError(f"Could not resolve DLL '{s}'. Tried by name '{name}' as well. ({e})")

    # Make Tkinter callback exceptions visible (instead of "hang / no response" feeling)
    def report_callback_exception(self, exc, val, tb):
        try:
            if hasattr(self, "logger") and self.logger:
                self.logger.exception("Unhandled UI exception", exc_info=(exc, val, tb))
        except Exception:
            pass
        try:
            messagebox.showerror("Unhandled UI error", str(val))
        except Exception:
            pass

    # ---------------- Per-device mode helpers (NEW) ----------------
    def get_access_mode_summary(self) -> Dict[str, int]:
        """
        Returns counts based on cached devices (SQLite sync cache).
        DEVICE/AGENT is now per device (GymDeviceDto.accessDataMode).
        """
        cache = load_sync_cache()
        devices = getattr(cache, "devices", []) if cache else []
        dev = 0
        ag = 0
        unk = 0
        for d in devices or []:
            if not isinstance(d, dict):
                continue
            m = str(d.get("accessDataMode") or "").strip().upper()
            if m == "DEVICE":
                dev += 1
            elif m == "AGENT":
                ag += 1
            else:
                unk += 1
        return {"DEVICE": dev, "AGENT": ag, "UNKNOWN": unk}

    def get_access_global_mode(self) -> str:
        s = self.get_access_mode_summary()
        has_dev = s["DEVICE"] > 0
        has_ag = s["AGENT"] > 0
        if has_dev and has_ag:
            return "MIXED"
        if has_dev:
            return "DEVICE_ONLY"
        if has_ag:
            return "AGENT_ONLY"
        return "UNKNOWN"

    # Legacy helper (kept so older pages don’t crash).
    # True ONLY when the gym has DEVICE devices and no AGENT devices.
    def is_device_mode(self) -> bool:
        return self.get_access_global_mode() == "DEVICE_ONLY"

    # ---------------- Tab helpers ----------------
    def _tab_id_present(self, tab_id: str) -> bool:
        try:
            return tab_id in set(self.nb.tabs())
        except Exception:
            return False

    def _is_tab_present(self, widget: ttk.Frame) -> bool:
        try:
            return str(widget) in set(self.nb.tabs())
        except Exception:
            return False

    def _safe_select_default_tab(self) -> None:
        # Prefer Device tab if present, else Configuration.
        try:
            if self._is_tab_present(self.page_device):
                self.nb.select(self.page_device)
                return
        except Exception:
            pass
        try:
            if self._is_tab_present(self.page_config):
                self.nb.select(self.page_config)
                return
        except Exception:
            pass

    def apply_mode_from_config(self) -> None:
        """
        Backward compatible entrypoint used by some pages.
        Previously: rebuilt tabs based on cfg.data_mode.
        Now: tabs are fixed; only start/stop realtime engine based on auth + restrictions + cfg.agent_realtime_enabled.
        """
        # keep current tab selection if still valid after rebuild
        current_tab: Optional[str] = None
        try:
            current_tab = self.nb.select()
        except Exception:
            current_tab = None

        try:
            self._rebuild_tabs_from_mode()
        except Exception:
            pass

        try:
            if current_tab and self._tab_id_present(current_tab):
                pass
            else:
                self._safe_select_default_tab()
        except Exception:
            pass

        self.apply_realtime_agent_from_config()

    def _rebuild_tabs_from_mode(self) -> None:
        """
        Name preserved for backward compatibility.
        Tabs are ALWAYS shown now (since mode is per device).
        """
        if self._tabs_built:
            return
        self._tabs_built = True

        try:
            for tab_id in list(self.nb.tabs()):
                self.nb.forget(tab_id)
        except Exception:
            pass

        self.nb.add(self.page_config, text="1) Configuration")
        self.nb.add(self.page_device, text="2) Device")
        self.nb.add(self.page_device_info, text="3) Device Info")
        self.nb.add(self.page_agent_rt, text="4) Agent realtime")
        self.nb.add(self.page_users, text="5) Users")
        self.nb.add(self.page_enroll, text="6) Enroll")
        self.nb.add(self.page_local_db, text="7) Local DB")
        self.nb.add(self.page_logs, text="8) Logs")

        try:
            self.logger.info("UI mode: MIXED (tabs are always visible; mode is per device).")
        except Exception:
            pass

        # default tab selection
        try:
            self._safe_select_default_tab()
        except Exception:
            pass

    # ---------------- Utilities ----------------
    def _poll_logs(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                try:
                    self.page_logs.append_log(msg)
                except Exception:
                    pass
        except Exception:
            pass
        self.after(200, self._poll_logs)

    def _start_tray_if_enabled(self):
        if not bool(getattr(self.cfg, "tray_enabled", True)):
            return
        try:
            self._tray = TrayController(app=self, logger=self.logger)
            self._tray.start()
        except Exception as e:
            self.logger.warning(f"Tray init failed: {e}")
            self._tray = None

    def hide_to_tray(self):
        try:
            if self._tray and self._tray.available:
                self.withdraw()
                self.logger.info("Window hidden to tray (app still running).")
        except Exception:
            pass

    def show_from_tray(self):
        try:
            self.deiconify()
            self.lift()
        except Exception:
            pass

    def quit_app(self):
        try:
            self.stop_realtime_agent()
        except Exception:
            pass
        try:
            self.stop_local_api_server()
        except Exception:
            pass
        try:
            self._update_manager.stop()
        except Exception:
            pass
        try:
            if self._tray:
                self._tray.stop()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass

    def _on_close_app(self):
        if bool(getattr(self.cfg, "tray_enabled", True)) and bool(getattr(self.cfg, "minimize_to_tray_on_close", True)):
            if self._tray and self._tray.available:
                self.hide_to_tray()
                return
        self.quit_app()

    def persist_config(self):
        save_config(self.cfg)
        self.logger.info("Config saved to config.json (ProgramData/LocalAppData data root).")

    def show_app(self):
        if not load_auth_token():
            self.show_login()
            return
        self._active_view = "app"
        self.screen_app.tkraise()

    def show_login(self):
        try:
            self.stop_realtime_agent()
        except Exception:
            pass
        # no token => no updates
        try:
            self._update_manager.stop()
        except Exception:
            pass
        self._active_view = "login"
        self.page_login.tkraise()

    def show_restricted(self):
        if not load_auth_token():
            self.show_login()
            return
        try:
            self.stop_realtime_agent()
        except Exception:
            pass
        self._active_view = "restricted"
        self.page_restricted.tkraise()

    def force_login(self):
        clear_auth_token()
        self._refresh_logout_btn()
        try:
            self._update_manager.stop()
        except Exception:
            pass
        self.show_login()

    def clear_auth(self):
        clear_auth_token()
        self._refresh_logout_btn()
        try:
            self._update_manager.stop()
        except Exception:
            pass

    # ---------------- Local API server ----------------
    def start_local_api_server(self):
        enabled = bool(getattr(self.cfg, "local_api_enabled", True))
        if not enabled:
            self.logger.info("Local API disabled in config.")
            return

        host = str(getattr(self.cfg, "local_api_host", "127.0.0.1") or "127.0.0.1")
        port = int(getattr(self.cfg, "local_api_port", 8788) or 8788)

        if self._local_api:
            if self._local_api.host == host and self._local_api.port == port:
                return
            self.stop_local_api_server()

        try:
            self._local_api = LocalAccessApiServer(app=self, host=host, port=port)
            self._local_api.start()
        except Exception as e:
            self.logger.exception("Failed to start Local API: %s", e)

    def stop_local_api_server(self):
        if self._local_api:
            try:
                self._local_api.stop()
            except Exception:
                pass
        self._local_api = None

    def restart_local_api_server(self):
        self.stop_local_api_server()
        self.start_local_api_server()

    def get_local_api_health(self) -> Dict[str, Any]:
        auth = load_auth_token()
        reasons = self._restriction_reasons()
        summary = self.get_access_mode_summary()
        return {
            "ok": True,
            "loggedIn": bool(auth and auth.token),
            "restricted": bool(reasons),
            "reasons": reasons,
            "mode": self.get_access_global_mode(),
            "modeSummary": summary,
            "host": str(getattr(self.cfg, "local_api_host", "127.0.0.1")),
            "port": int(getattr(self.cfg, "local_api_port", 8788)),
        }

    # ---------------- API helpers ----------------
    def _api(self) -> MonClubApi:
        login_url = getattr(self.cfg, "api_login_url", "http://localhost:5000/api/v1/public/access/v1/gym/login")
        sync_url = getattr(
            self.cfg,
            "api_sync_url",
            "http://localhost:5000/api/v1/manager/gym/access/v1/users/get_gym_users",
        )
        create_fp_url = getattr(
            self.cfg,
            "api_create_user_fingerprint_url",
            "http://localhost:5000/api/v1/manager/userFingerprint/create",
        )
        latest_release_url = (
            getattr(self.cfg, "api_latest_release_url", None)
            or getattr(self.cfg, "latest_release_url", None)
            or getattr(self.cfg, "update_latest_release_url", None)
            or getattr(self.cfg, "releases_url", None)
            or "http://localhost:5000/api/v1/public/access/v1/latest_release"
        )

        endpoints = ApiEndpoints(
            login_url=login_url,
            sync_url=sync_url,
            create_user_fingerprint_url=create_fp_url,
            latest_release_url=str(latest_release_url),
        )
        return MonClubApi(endpoints=endpoints, logger=self.logger)

    # ---------------- Sync timer ----------------
    def request_sync_now(self):
        self.after(50, self._sync_tick)

    def reschedule_sync_timer(self):
        if self._sync_after_id is not None:
            try:
                self.after_cancel(self._sync_after_id)
            except Exception:
                pass
            self._sync_after_id = None

        interval_cfg = getattr(self.cfg, "sync_interval_sec", 60)
        interval = int(max(10, int(interval_cfg)))
        self._sync_after_id = self.after(interval * 1000, self._sync_tick)
        self.logger.info(f"Sync scheduled every {interval} sec")

    def _sync_tick(self):
        self.reschedule_sync_timer()

        auth = load_auth_token()
        if not auth:
            self.logger.debug("Sync skipped: no token (not logged in).")
            self.after(0, self.evaluate_access_and_redirect)
            return

        def work():
            try:
                api = self._api()
                data = api.get_sync_data(token=auth.token)
                save_sync_cache(data)
                self.logger.info("getSyncData OK: cache updated.")
                try:
                    self.after(0, self.page_local_db.refresh_all)
                except Exception:
                    pass
            except Exception as ex:
                self.logger.exception(f"getSyncData failed: {ex} (using cached data if available)")

            # Device sync (DEVICE-mode devices only) – engine will filter internally (after you update device_sync.py)
            try:
                if bool(getattr(self.cfg, "device_sync_enabled", True)):
                    reasons = self._restriction_reasons()
                    if reasons:
                        self.logger.warning("[DeviceSync] Skipped: restricted: " + " | ".join(reasons[:3]))
                    else:
                        cache = load_sync_cache()
                        if cache:
                            self._device_sync_engine.run_blocking(cache=cache, source="timer")
                        else:
                            self.logger.info("[DeviceSync] Skipped: no cache yet")
                else:
                    self.logger.debug("[DeviceSync] Skipped: device sync disabled.")
            except Exception as ex:
                self.logger.exception(f"[DeviceSync] Unexpected error: {ex}")

            # Realtime agent refresh (AGENT-mode devices only) – engine will filter internally (after you update realtime_agent.py)
            try:
                if self._agent_engine.is_running():
                    self._agent_engine.refresh_devices()
            except Exception:
                pass

            self.after(0, self.evaluate_access_and_redirect)

        threading.Thread(target=work, daemon=True).start()

    # ---------------- Access rules ----------------
    def _restriction_reasons(self) -> list[str]:
        reasons: list[str] = []

        auth = load_auth_token()
        if not auth:
            return reasons

        dt_login = _parse_dt_any(auth.last_login_at)
        max_age_cfg = getattr(self.cfg, "max_login_age_minutes", 60)

        if dt_login is None:
            reasons.append("Last login date missing/invalid. Please login again.")
        else:
            age = datetime.now() - dt_login
            if age > timedelta(minutes=int(max_age_cfg)):
                reasons.append(f"Last login is older than {int(max_age_cfg)} minutes. Please login again.")

        cache = load_sync_cache()
        if cache:
            contract_status = getattr(cache, "contract_status", getattr(cache, "contractStatus", None))
            contract_end_date = getattr(cache, "contract_end_date", getattr(cache, "contractEndDate", None))

            if contract_status is False:
                reasons.append("Contract status is FALSE (contractStatus=false).")

            end_dt = _parse_dt_any(str(contract_end_date or ""))
            if end_dt is not None and datetime.now() > end_dt:
                reasons.append(f"Contract expired (contractEndDate={contract_end_date}).")
        else:
            self.logger.warning("No sync cache yet (contract checks cannot be evaluated offline).")

        return reasons

    def evaluate_access_and_redirect(self):
        was_in_app = (self._active_view == "app")

        auth = load_auth_token()
        self._refresh_logout_btn()

        if not auth:
            # ensure updates stopped (no token)
            try:
                self._update_manager.stop()
            except Exception:
                pass
            self.show_login()
            return

        # ensure updater keeps running with current token (NO forced check here)
        try:
            self._ensure_update_manager_started(check_now=False)
        except Exception:
            pass

        reasons = self._restriction_reasons()
        if reasons:
            self.page_restricted.set_reasons(reasons)
            self.show_restricted()
            return

        self.page_restricted.set_reasons([])
        self.show_app()

        # only auto-select a tab when entering the app view (login/restricted -> app)
        if not was_in_app:
            try:
                if self._is_tab_present(self.page_device):
                    self.nb.select(self.page_device)
                else:
                    self._safe_select_default_tab()
            except Exception:
                pass

        self.apply_realtime_agent_from_config()

    # ---------------- Realtime agent engine control ----------------
    def apply_realtime_agent_from_config(self) -> None:
        """
        No global mode anymore.
        Start realtime engine if:
          - logged in
          - not restricted
          - cfg.agent_realtime_enabled is true
        The engine itself will filter devices by accessDataMode=AGENT from SQLite cache.
        """
        with self._agent_lock:
            try:
                auth = load_auth_token()
                if not auth or not getattr(auth, "token", None):
                    self.stop_realtime_agent()
                    return

                if not bool(getattr(self.cfg, "agent_realtime_enabled", True)):
                    self.stop_realtime_agent()
                    return

                if self._restriction_reasons():
                    self.stop_realtime_agent()
                    return

                self.start_realtime_agent()
            except Exception:
                pass

    def start_realtime_agent(self) -> None:
        with self._agent_lock:
            if self._agent_engine.is_running():
                return
            self._agent_engine.start()

    def stop_realtime_agent(self) -> None:
        with self._agent_lock:
            if self._agent_engine.is_running():
                self._agent_engine.stop()

    # ---------------- Remote enroll (Dashboard -> PC) ----------------
    def begin_remote_enroll(
        self, *, user_id: str, finger_id: str, full_name: str = "", device: str = "zk9500"
    ) -> Dict[str, Any]:
        dev = (device or "zk9500").strip().lower()
        if dev not in ("zk9500", "zkfinger", "zkfp"):
            return {"ok": False, "status": 400, "error": f"Unsupported device='{device}'. Use device=zk9500"}

        try:
            uid = int(str(user_id).strip())
        except Exception:
            return {"ok": False, "status": 400, "error": "Invalid user id. Use ?id=<number>"}

        try:
            fid = int(str(finger_id).strip())
        except Exception:
            return {"ok": False, "status": 400, "error": "Invalid fingerId. Use ?fingerId=<number>"}

        if fid < 0 or fid > 9:
            return {"ok": False, "status": 400, "error": "fingerId must be between 0 and 9"}

        with self._enroll_state_lock:
            if self._enroll_running:
                return {"ok": False, "status": 409, "error": "Enroll already running on this PC"}
            self._enroll_running = True

        self.after(0, lambda: self._start_remote_enroll(uid, fid, full_name, dev))
        return {"ok": True, "message": "Enroll started on PC", "userId": uid, "fingerId": fid, "device": dev}

    def _start_remote_enroll(self, user_id: int, finger_id: int, full_name: str, device: str):
        try:
            title = f"Enroll (dashboard) - userId={user_id} fingerId={finger_id}"
            pop = EnrollStatusPopup(self, title=title)
            pop.log("Triggered by dashboard ✅")
            t = threading.Thread(
                target=self._remote_enroll_worker,
                args=(pop, user_id, finger_id, full_name, device),
                daemon=True,
            )
            t.start()
        except Exception as e:
            with self._enroll_state_lock:
                self._enroll_running = False
            messagebox.showerror("Enroll failed", str(e))

    def _find_user_membership(self, user_id: int) -> Tuple[Optional[int], Optional[Dict[str, Any]]]:
        cache = load_sync_cache()
        if not cache:
            return None, None
        users = getattr(cache, "users", []) or []
        for u in users:
            try:
                if not (isinstance(u, dict) and int(u.get("userId") or -1) == int(user_id)):
                    continue
            except Exception:
                continue

            am_id = u.get("activeMembershipId")
            if am_id is None or str(am_id).strip() == "":
                am_id = u.get("membershipId")

            try:
                return int(am_id) if am_id is not None and str(am_id).strip() != "" else None, u
            except Exception:
                return None, u

        return None, None

    def _remote_enroll_worker(
        self, pop: EnrollStatusPopup, user_id: int, finger_id: int, full_name: str, device: str
    ):
        zk: Optional[ZKFinger] = None
        try:
            pop.set_step("Checking login...")
            auth = load_auth_token()
            if not auth or not auth.token:
                pop.fail("Not logged in on this PC. Open the desktop app and login first.")
                return

            pop.set_step("Checking contract / restrictions...")
            reasons = self._restriction_reasons()
            if reasons:
                pop.log("Restricted ❌")
                for r in reasons:
                    pop.log("- " + r)
                pop.fail("Access restricted. Fix restrictions then retry.")
                return
            pop.log("Contract OK ✅")

            pop.set_step("Resolving active membership...")
            active_membership_id, user_obj = self._find_user_membership(user_id)
            if active_membership_id is None:
                pop.log("User not found in cache or missing activeMembershipId. Trying to sync now...")
                try:
                    api = self._api()
                    data = api.get_sync_data(token=auth.token)
                    save_sync_cache(data)
                    pop.log("Sync OK ✅")
                except Exception as e:
                    pop.fail(f"Sync failed: {e}")
                    return

                active_membership_id, user_obj = self._find_user_membership(user_id)

            if active_membership_id is None:
                pop.fail("User has no activeMembershipId. Cannot save fingerprint.")
                return

            if user_obj and not full_name:
                full_name = str(user_obj.get("fullName") or "").strip()

            pop.set_step("Initializing scanner (ZK9500)...")
            zk = ZKFinger(self.cfg.zkfp_dll_path, logger=self.logger)
            zk.init()
            pop.log("Scanner initialized ✅")

            pop.set_step("Opening device...")
            zk.open_device(0)
            pop.log("Device opened ✅")

            pop.set_step("Enrollment...")
            tpl_bytes = zk.enroll_3_samples(
                progress_cb=lambda msg: (pop.set_step(msg), pop.log(msg)),
                cancel_event=pop.cancel_event,
            )

            if pop.cancel_event.is_set():
                pop.fail("Cancelled.")
                return

            pop.set_step("Encoding template...")
            tpl_ver = int(self.cfg.template_version)
            enc_cfg = (self.cfg.template_encoding or "base64").strip().lower()
            enc_backend = _encoding_to_backend(enc_cfg)

            if enc_cfg == "hex":
                tpl_text = to_hex(tpl_bytes)
            else:
                tpl_text = to_b64(tpl_bytes)

            pop.set_step("Saving to backend...")
            payload = {
                "activeMembershipId": int(active_membership_id),
                "fingerId": int(finger_id),
                "templateVersion": int(tpl_ver),
                "templateEncoding": enc_backend,
                "templateData": tpl_text,
                "label": "dashboard",
                "enabled": True,
            }

            api = self._api()
            resp = api.create_user_fingerprint(token=auth.token, payload=payload)
            self.logger.info("createUserFingerprint OK -> %s", resp)

            pop.success("✅ Done. Fingerprint saved to backend.")
            try:
                messagebox.showinfo("Enroll", "Fingerprint enrolled and saved to backend ✅")
            except Exception:
                pass

        except (ZKFingerError,) as e:
            pop.fail(str(e))
            self.logger.exception("Remote enroll failed")
        except Exception as e:
            pop.fail(str(e))
            self.logger.exception("Remote enroll failed (unexpected)")
        finally:
            try:
                if zk:
                    pop.set_step("Closing device...")
                    zk.close_device()
                    zk.terminate()
                    pop.log("Device closed ✅")
            except Exception:
                pass

            with self._enroll_state_lock:
                self._enroll_running = False


def run_app():
    # Also safe to call here (in case entrypoint imports happen before MainApp())
    try:
        add_windows_dll_search_paths()
    except Exception:
        pass

    app = MainApp()
    app.mainloop()
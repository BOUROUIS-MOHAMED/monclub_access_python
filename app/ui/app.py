from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta

from app.api.monclub_api import ApiEndpoints, MonClubApi
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
from app.core.utils import ensure_dirs

from app.ui.pages.configuration_page import ConfigurationPage
from app.ui.pages.device_page import DevicePage
from app.ui.pages.users_page import UsersPage
from app.ui.pages.enroll_page import EnrollPage
from app.ui.pages.logs_page import LogsPage

from app.ui.pages.login_page import LoginPage
from app.ui.pages.restricted_page import RestrictedPage
from app.ui.pages.local_db_page import LocalDatabasePage

# ✅ NEW PAGE
from app.ui.pages.device_info_page import DeviceInfoPage


def _parse_dt_any(s: str) -> datetime | None:
    if not s:
        return None
    s = s.strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1]
    # try ISO
    try:
        return datetime.fromisoformat(s)
    except Exception:
        pass
    # try date only
    try:
        if len(s) == 10 and s[4] == "-" and s[7] == "-":
            return datetime.fromisoformat(s + "T00:00:00")
    except Exception:
        pass
    return None


class MainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ZK Turnstile Manager (PullSDK + ZK9500)")
        self.geometry("1250x780")

        ensure_dirs()
        init_db()

        self.log_queue: "queue.Queue[str]" = queue.Queue()
        self.cfg = load_config()

        # Enforce 32-bit python (because DLL is 32-bit)
        try:
            require_32bit_python_for_32bit_dll(self.cfg.plcomm_dll_path)
        except Exception as e:
            messagebox.showerror("Architecture error", f"{e}\n\nPlatform: {platform_summary()}")
            raise

        self.logger = setup_logging(self.cfg.log_level, ui_queue=self.log_queue)
        self.logger.info("App started.")
        self.logger.info(f"Platform: {platform_summary()}")

        self._sync_after_id: str | None = None

        # -------------------------
        # Full-screen router layout
        # -------------------------
        self.container = ttk.Frame(self)
        self.container.pack(fill="both", expand=True)
        self.container.rowconfigure(0, weight=1)
        self.container.columnconfigure(0, weight=1)

        # Screen: APP (Notebook)
        self.screen_app = ttk.Frame(self.container)
        self.screen_app.grid(row=0, column=0, sticky="nsew")
        self.screen_app.rowconfigure(0, weight=1)
        self.screen_app.columnconfigure(0, weight=1)

        nb = ttk.Notebook(self.screen_app)
        nb.grid(row=0, column=0, sticky="nsew")
        self.nb = nb

        self.page_config = ConfigurationPage(nb, app=self)
        self.page_device = DevicePage(nb, app=self)
        self.page_users = UsersPage(nb, app=self)
        self.page_enroll = EnrollPage(nb, app=self)
        self.page_local_db = LocalDatabasePage(nb, app=self)
        self.page_logs = LogsPage(nb, app=self)

        # ✅ NEW: device info/config page
        self.page_device_info = DeviceInfoPage(nb, app=self)

        nb.add(self.page_config, text="1) Configuration")
        nb.add(self.page_device, text="2) Device")
        nb.add(self.page_device_info, text="3) Device Info")  # NEW TAB
        nb.add(self.page_users, text="4) Users")
        nb.add(self.page_enroll, text="5) Enroll")
        nb.add(self.page_local_db, text="6) Local DB")
        nb.add(self.page_logs, text="7) Logs")

        # Screen: LOGIN (full page)
        self.page_login = LoginPage(self.container, app=self)
        self.page_login.grid(row=0, column=0, sticky="nsew")

        # Screen: RESTRICTED (full page)
        self.page_restricted = RestrictedPage(self.container, app=self)
        self.page_restricted.grid(row=0, column=0, sticky="nsew")

        # Start background work
        self.after(200, self._poll_logs)
        self.after(500, self.reschedule_sync_timer)
        self.after(700, self.evaluate_access_and_redirect)

    # ---------------- Utilities ----------------

    def _poll_logs(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.page_logs.append_log(msg)
        except Exception:
            pass
        self.after(200, self._poll_logs)

    def persist_config(self):
        save_config(self.cfg)
        self.logger.info("Config saved to data/config.json")

    def show_app(self):
        # Hard guard: if no token => ALWAYS login
        if not load_auth_token():
            self.show_login()
            return
        self.screen_app.tkraise()

    def show_login(self):
        self.page_login.tkraise()

    def show_restricted(self):
        # If token is missing, restricted is not meaningful -> login
        if not load_auth_token():
            self.show_login()
            return
        self.page_restricted.tkraise()

    def force_login(self):
        clear_auth_token()
        self.show_login()

    def clear_auth(self):
        clear_auth_token()

    # ---------------- API helpers ----------------

    def _api(self) -> MonClubApi:
        # Backward-safe defaults if config.json is old
        login_url = getattr(self.cfg, "api_login_url", "https://monclubwigo.tn/api/v1/public/access/v1/gym/login")
        sync_url = getattr(
            self.cfg,
            "api_sync_url",
            "https://monclubwigo.tn/api/v1/manager/gym/access/v1/users/get_gym_users",
        )

        # ✅ FIX: ApiEndpoints now expects create_user_fingerprint_url too
        create_fp_url = getattr(
            self.cfg,
            "api_create_user_fingerprint_url",
            "https://monclubwigo.tn/api/v1/manager/userFingerprint/create",
        )

        endpoints = ApiEndpoints(
            login_url=login_url,
            sync_url=sync_url,
            create_user_fingerprint_url=create_fp_url,
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
        # schedule next first (continuous)
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

                # refresh Local DB page automatically
                try:
                    self.after(0, self.page_local_db.refresh_all)
                except Exception:
                    pass
            except Exception as ex:
                self.logger.exception(f"getSyncData failed: {ex} (using cached data if available)")
            finally:
                self.after(0, self.evaluate_access_and_redirect)

        threading.Thread(target=work, daemon=True).start()

    # ---------------- Access rules ----------------

    def _restriction_reasons(self) -> list[str]:
        reasons: list[str] = []

        auth = load_auth_token()
        if not auth:
            # IMPORTANT: no token => login page, not restricted page
            return reasons

        # last login age check (required)
        dt_login = _parse_dt_any(auth.last_login_at)
        max_age_cfg = getattr(self.cfg, "max_login_age_minutes", 60)

        if dt_login is None:
            reasons.append("Last login date missing/invalid. Please login again.")
        else:
            age = datetime.now() - dt_login
            if age > timedelta(minutes=int(max_age_cfg)):
                reasons.append(f"Last login is older than {int(max_age_cfg)} minutes. Please login again.")

        # contract checks (only if we have cached sync)
        cache = load_sync_cache()
        if cache:
            contract_status = None
            contract_end_date = None

            if isinstance(cache, dict):
                contract_status = cache.get("contractStatus", cache.get("contract_status"))
                contract_end_date = cache.get("contractEndDate", cache.get("contract_end_date"))
            else:
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
        auth = load_auth_token()

        # RULE: if there is NO token => ALWAYS go to login
        if not auth:
            self.show_login()
            return

        reasons = self._restriction_reasons()
        if reasons:
            self.page_restricted.set_reasons(reasons)
            self.show_restricted()
            return

        # allowed
        self.page_restricted.set_reasons([])
        self.show_app()
        try:
            self.nb.select(self.page_device)
        except Exception:
            pass


def run_app():
    app = MainApp()
    app.mainloop()

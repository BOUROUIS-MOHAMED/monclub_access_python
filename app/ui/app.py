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
from app.core.utils import ensure_dirs, to_b64, to_hex

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
from app.sdk.zkfinger import ZKFinger, ZKFingerError


def _parse_dt_any(s: str) -> datetime | None:
    if not s:
        return None
    s = s.strip()
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
    def __init__(self):
        super().__init__()
        self.title("ZK Turnstile Manager (PullSDK + ZK9500)")
        self.geometry("1250x780")

        ensure_dirs()
        init_db()

        self.log_queue: "queue.Queue[str]" = queue.Queue()
        self.cfg = load_config()

        # Enforce 32-bit python (because DLLs are usually 32-bit)
        try:
            require_32bit_python_for_32bit_dll(self.cfg.plcomm_dll_path)
        except Exception as e:
            messagebox.showerror("Architecture error", f"{e}\n\nPlatform: {platform_summary()}")
            raise

        self.logger = setup_logging(self.cfg.log_level, ui_queue=self.log_queue)
        self.logger.info("App started.")
        self.logger.info(f"Platform: {platform_summary()}")

        self._sync_after_id: str | None = None

        # Local API server
        self._local_api: Optional[LocalAccessApiServer] = None

        # Remote enroll state
        self._enroll_state_lock = threading.Lock()
        self._enroll_running: bool = False

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

        self.page_device_info = DeviceInfoPage(nb, app=self)

        nb.add(self.page_config, text="1) Configuration")
        nb.add(self.page_device, text="2) Device")
        nb.add(self.page_device_info, text="3) Device Info")
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

        # Close hook
        self.protocol("WM_DELETE_WINDOW", self._on_close_app)

        # Start background work
        self.after(200, self._poll_logs)
        self.after(400, self.start_local_api_server)
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

    def _on_close_app(self):
        try:
            self.stop_local_api_server()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass

    def persist_config(self):
        save_config(self.cfg)
        self.logger.info("Config saved to data/config.json")

    def show_app(self):
        if not load_auth_token():
            self.show_login()
            return
        self.screen_app.tkraise()

    def show_login(self):
        self.page_login.tkraise()

    def show_restricted(self):
        if not load_auth_token():
            self.show_login()
            return
        self.page_restricted.tkraise()

    def force_login(self):
        clear_auth_token()
        self.show_login()

    def clear_auth(self):
        clear_auth_token()

    # ---------------- Local API server ----------------

    def start_local_api_server(self):
        enabled = bool(getattr(self.cfg, "local_api_enabled", True))
        if not enabled:
            self.logger.info("Local API disabled in config.")
            return

        host = str(getattr(self.cfg, "local_api_host", "127.0.0.1") or "127.0.0.1")
        port = int(getattr(self.cfg, "local_api_port", 8788) or 8788)

        # restart if host/port changed
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
        return {
            "ok": True,
            "loggedIn": bool(auth and auth.token),
            "restricted": bool(reasons),
            "reasons": reasons,
            "host": str(getattr(self.cfg, "local_api_host", "127.0.0.1")),
            "port": int(getattr(self.cfg, "local_api_port", 8788)),
        }

    # ---------------- API helpers ----------------

    def _api(self) -> MonClubApi:
        login_url = getattr(self.cfg, "api_login_url", "https://monclubwigo.tn/api/v1/public/access/v1/gym/login")
        sync_url = getattr(
            self.cfg,
            "api_sync_url",
            "https://monclubwigo.tn/api/v1/manager/gym/access/v1/users/get_gym_users",
        )
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
            finally:
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
        auth = load_auth_token()
        if not auth:
            self.show_login()
            return

        reasons = self._restriction_reasons()
        if reasons:
            self.page_restricted.set_reasons(reasons)
            self.show_restricted()
            return

        self.page_restricted.set_reasons([])
        self.show_app()
        try:
            self.nb.select(self.page_device)
        except Exception:
            pass

    # ---------------- Remote enroll (Dashboard -> PC) ----------------

    def begin_remote_enroll(self, *, user_id: str, finger_id: str, full_name: str = "", device: str = "zk9500") -> Dict[str, Any]:
        """
        Called by LocalAccessApiServer handler thread.
        Must return fast (do NOT block).
        """
        # Only support zk9500 for now
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

        # Schedule UI + worker on main thread
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
            if isinstance(u, dict) and int(u.get("userId") or -1) == int(user_id):
                mid = u.get("membershipId")
                try:
                    return int(mid) if mid is not None and str(mid).strip() != "" else None, u
                except Exception:
                    return None, u
        return None, None

    def _remote_enroll_worker(self, pop: EnrollStatusPopup, user_id: int, finger_id: int, full_name: str, device: str):
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

            # Make sure ZK dll path exists
            pop.set_step("Checking DLL...")

            pop.log(f"DLL OK")

            # Ensure we can resolve membershipId (activeMembershipId)
            pop.set_step("Resolving user membership...")
            active_membership_id, user_obj = self._find_user_membership(user_id)
            if active_membership_id is None:
                pop.log("User not found in cache or missing membershipId. Trying to sync now...")
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
                pop.fail("User has no membershipId (activeMembershipId). Cannot save fingerprint.")
                return

            if user_obj and not full_name:
                full_name = str(user_obj.get("fullName") or "").strip()

            pop.log(f"userId={user_id}")
            pop.log(f"activeMembershipId={active_membership_id}")
            pop.log(f"fullName={full_name or '-'}")

            # Start scanner
            pop.set_step("Initializing scanner (ZK9500)...")
            zk = ZKFinger(self.cfg.zkfp_dll_path, logger=self.logger)
            zk.init()
            pop.log("Scanner initialized ✅")

            pop.set_step("Opening device...")
            zk.open_device(0)
            pop.log("Device opened ✅")

            # Enroll (3 samples)
            pop.set_step("Enrollment...")
            tpl_bytes = zk.enroll_3_samples(
                progress_cb=lambda msg: (pop.set_step(msg), pop.log(msg)),
                cancel_event=pop.cancel_event,
            )

            if pop.cancel_event.is_set():
                pop.fail("Cancelled.")
                return

            # Encode
            pop.set_step("Encoding template...")
            tpl_ver = int(self.cfg.template_version)
            enc_cfg = (self.cfg.template_encoding or "base64").strip().lower()
            enc_backend = _encoding_to_backend(enc_cfg)

            if enc_cfg == "hex":
                tpl_text = to_hex(tpl_bytes)
            else:
                tpl_text = to_b64(tpl_bytes)

            # Save to backend
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
            # Always close device
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
    app = MainApp()
    app.mainloop()

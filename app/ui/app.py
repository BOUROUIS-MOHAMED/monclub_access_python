from __future__ import annotations

import queue
import tkinter as tk
from tkinter import ttk, messagebox

from app.core.arch import platform_summary, require_32bit_python_for_32bit_dll
from app.core.config import load_config, save_config
from app.core.db import init_db
from app.core.logger import setup_logging
from app.core.utils import ensure_dirs
from app.ui.pages.configuration_page import ConfigurationPage
from app.ui.pages.device_page import DevicePage
from app.ui.pages.users_page import UsersPage
from app.ui.pages.enroll_page import EnrollPage
from app.ui.pages.logs_page import LogsPage


class MainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ZK Turnstile Manager (PullSDK + ZK9500)")
        self.geometry("1250x750")

        ensure_dirs()
        init_db()

        self.log_queue: "queue.Queue[str]" = queue.Queue()
        self.cfg = load_config()

        # Enforce 32-bit python (because user said DLL is 32-bit)
        try:
            require_32bit_python_for_32bit_dll(self.cfg.plcomm_dll_path)
        except Exception as e:
            messagebox.showerror("Architecture error", f"{e}\n\nPlatform: {platform_summary()}")
            raise

        self.logger = setup_logging(self.cfg.log_level, ui_queue=self.log_queue)
        self.logger.info("App started.")
        self.logger.info(f"Platform: {platform_summary()}")

        # Notebook pages
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        self.page_config = ConfigurationPage(nb, app=self)
        self.page_device = DevicePage(nb, app=self)
        self.page_users = UsersPage(nb, app=self)
        self.page_enroll = EnrollPage(nb, app=self)
        self.page_logs = LogsPage(nb, app=self)

        nb.add(self.page_config, text="1) Configuration")
        nb.add(self.page_device, text="2) Device")
        nb.add(self.page_users, text="3) Users")
        nb.add(self.page_enroll, text="4) Enroll")
        nb.add(self.page_logs, text="5) Logs")

        # Poll log queue
        self.after(200, self._poll_logs)

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


def run_app():
    app = MainApp()
    app.mainloop()

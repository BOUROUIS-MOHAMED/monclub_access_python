"""Standalone TV desktop shell for Phase 3 process extraction."""

from __future__ import annotations

import os
import queue
import threading
import time
from typing import Any, Dict

from shared.api.monclub_api import MonClubApi
from shared.logging import setup_logging
from shared.runtime_support import add_windows_dll_search_paths, ensure_dirs
from shared.tauri_launcher import kill_tauri_ui, launch_tauri_ui
from tv.api import LocalTvApiServerV2, ensure_tv_local_schema, schedule_tv_shell_startup, start_tv_runtime
from tv.config import (
    build_tv_api_endpoints,
    get_tv_config_status,
    load_tv_app_config,
    load_tv_config,
    save_tv_app_config,
)
from tv.auth_bridge import load_tv_auth_for_runtime
from tv.store import get_tv_storage_status
from tv.update_runtime import TvUpdateManager, UpdateStatus


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


class TvApp:
    """Headless TV backend with its own local API server and Tauri shell."""

    def __init__(self) -> None:
        try:
            add_windows_dll_search_paths()
        except Exception:
            pass

        ensure_dirs()
        ensure_tv_local_schema()

        self.log_queue: "queue.Queue[str]" = queue.Queue()
        self.cfg = load_tv_app_config()
        self.logger = setup_logging(getattr(self.cfg, "log_level", "DEBUG"), self.log_queue)
        self.logger.info("TV app started.")
        try:
            config_status = get_tv_config_status()
            self.logger.info(
                "TV config: %s (legacyExists=%s migratedAt=%s)",
                config_status.get("liveConfigPath"),
                config_status.get("legacyConfigExists"),
                config_status.get("migratedFromLegacyAt"),
            )
        except Exception:
            self.logger.exception("Failed to read TV config status")
        try:
            storage_status = get_tv_storage_status()
            self.logger.info(
                "TV live DB: %s (migration=%s)",
                storage_status.get("liveDbPath"),
                storage_status.get("migrationState"),
            )
        except Exception:
            self.logger.exception("Failed to read TV storage status")

        self._scheduled = []
        self._sched_id_counter = 0
        self._sched_lock = threading.Lock()
        self._stop_event = threading.Event()

        self._local_api = None
        self._tauri_process = None
        self._update_manager = TvUpdateManager(app=self, cfg=self.cfg, logger=self.logger, api_factory=self._api)
        self._update_status: UpdateStatus | None = None

        schedule_tv_shell_startup(self)

    def after(self, delay_ms: int, callback) -> int:
        with self._sched_lock:
            self._sched_id_counter += 1
            sid = self._sched_id_counter
            target = time.monotonic() + delay_ms / 1000.0
            self._scheduled.append((target, sid, callback))
        return sid

    def after_cancel(self, sid: int) -> None:
        with self._sched_lock:
            self._scheduled = [(t, i, c) for t, i, c in self._scheduled if i != sid]

    def mainloop(self) -> None:
        while not self._stop_event.is_set():
            now = time.monotonic()
            to_run = []
            with self._sched_lock:
                remaining = []
                for t, sid, cb in self._scheduled:
                    if t <= now:
                        to_run.append(cb)
                    else:
                        remaining.append((t, sid, cb))
                self._scheduled = remaining

            for cb in to_run:
                try:
                    cb()
                except Exception:
                    self.logger.exception("Scheduled TV callback error")

            self._stop_event.wait(timeout=0.05)

    def destroy(self) -> None:
        try:
            self._update_manager.stop()
        except Exception:
            pass
        self._stop_event.set()

    def quit(self) -> None:
        try:
            self._update_manager.stop()
        except Exception:
            pass
        self._stop_event.set()

    def _effective_local_api_bind(self) -> tuple[str, int]:
        tv_cfg = load_tv_config(self.cfg)
        host = os.environ.get("MONCLUB_TV_LOCAL_API_HOST", str(tv_cfg.local_api_host or "127.0.0.1")).strip() or "127.0.0.1"
        port = _safe_int(os.environ.get("MONCLUB_TV_LOCAL_API_PORT"), int(tv_cfg.local_api_port or 8789))
        if port <= 0:
            port = 8789
        return host, port

    def _api(self) -> MonClubApi:
        return MonClubApi(endpoints=build_tv_api_endpoints(self.cfg), logger=self.logger)

    def _ensure_update_manager_started(self, *, check_now: bool) -> None:
        try:
            auth = load_tv_auth_for_runtime()
            tok = getattr(auth, "token", None) if auth else None
            tok = str(tok or "").strip()
            if tok and bool(getattr(self.cfg, "update_enabled", True)):
                self._update_manager.start(token=tok, check_now=check_now)
            else:
                self._update_manager.stop()
        except Exception:
            self.logger.exception("Failed to start TV update manager")

    def on_update_status_changed(self, st: UpdateStatus) -> None:
        self._update_status = st

    def on_update_ready(self, st: UpdateStatus) -> None:
        try:
            rid = str((st.latest_release or {}).get("releaseId") or "")
            self.logger.info("[TV Update] Update ready: releaseId=%s", rid)
        except Exception:
            pass

    def on_update_error(self, msg: str) -> None:
        try:
            self.logger.warning("[TV Update] %s", msg)
        except Exception:
            pass

    def persist_config(self) -> None:
        save_tv_app_config(self.cfg)
        self.logger.info("TV config saved to tv/config.json.")

    def restart_local_api_server(self) -> None:
        self.stop_local_api_server()
        self.start_local_api_server()

    def _launch_tauri_ui(self) -> None:
        _host, port = self._effective_local_api_bind()
        self._tauri_process = launch_tauri_ui(
            role="tv",
            api_port=port,
            logger=self.logger,
            existing_process=self._tauri_process,
        )

    def _kill_tauri_ui(self) -> None:
        kill_tauri_ui(self._tauri_process, role="tv", logger=self.logger)
        self._tauri_process = None

    def start_local_api_server(self) -> None:
        host, port = self._effective_local_api_bind()
        if self._local_api:
            if self._local_api.host == host and self._local_api.port == port:
                return
            self.stop_local_api_server()

        self._local_api = LocalTvApiServerV2(app=self, host=host, port=port)
        self._local_api.start()
        start_tv_runtime(self, trigger_source="TV_LOCAL_API_START")
        self.logger.info("TV local API started on %s:%s", host, port)

    def stop_local_api_server(self) -> None:
        if self._local_api:
            try:
                self._local_api.stop()
            except Exception:
                pass
        self._local_api = None

    def get_local_api_health(self) -> Dict[str, Any]:
        host, port = self._effective_local_api_bind()
        return {
            "ok": True,
            "role": "tv",
            "host": host,
            "port": port,
            "uiRunning": bool(self._tauri_process and self._tauri_process.poll() is None),
        }

    def quit_app(self) -> None:
        try:
            self._update_manager.stop()
        except Exception:
            pass
        try:
            self._kill_tauri_ui()
        except Exception:
            pass
        try:
            self.stop_local_api_server()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass

# app/core/optional_content_sync.py
"""
Background scheduler that periodically fetches optional content
(upcoming events, products, active deals) from the backend and stores
the results in the local SQLite tables managed by db.py.

The scheduler runs as a daemon thread and never touches the main-thread UI.
Start it once at application startup via OptionalContentSyncScheduler.start().
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)

# ── module-level singleton guard ──────────────────────────────────────────────
_scheduler_started = False
_scheduler_lock = threading.Lock()


class OptionalContentSyncScheduler:
    """
    Daemon thread that:
      1. Deletes past events from the local cache.
      2. Reads stored version markers.
      3. Calls POST /manager/gym/access/v1/content/sync with those markers.
      4. Applies whichever sections the server says have changed.
      5. Sleeps until the next configured interval (default 60 min).
    """

    _INITIAL_DELAY_SEC: float = 30.0   # wait after process start
    _MIN_INTERVAL_SEC: int = 60 * 60   # hard floor: 1 hour
    _DEFAULT_INTERVAL_SEC: int = 60 * 60

    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    def start(self) -> None:
        global _scheduler_started
        with _scheduler_lock:
            if _scheduler_started:
                _log.debug("[OptionalContentSync] Already started — skipping.")
                return
            _scheduler_started = True

        self._thread = threading.Thread(
            target=self._run,
            name="optional-content-sync",
            daemon=True,
        )
        self._thread.start()
        _log.info("[OptionalContentSync] Scheduler started (initial delay %.0fs).", self._INITIAL_DELAY_SEC)

    def stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------------
    def _run(self) -> None:
        # initial delay — let the rest of the app start up first
        if self._stop_event.wait(timeout=self._INITIAL_DELAY_SEC):
            return

        while not self._stop_event.is_set():
            try:
                self._sync_once()
            except Exception as exc:
                _log.warning("[OptionalContentSync] Unexpected error during sync: %s", exc, exc_info=True)

            interval = self._get_interval_sec()
            _log.debug("[OptionalContentSync] Next sync in %.0f min.", interval / 60)
            self._stop_event.wait(timeout=interval)

    # ------------------------------------------------------------------
    def _get_interval_sec(self) -> int:
        try:
            from app.core.settings_reader import get_backend_global_settings
            gs = get_backend_global_settings()
            minutes = int(gs.get("optional_data_sync_delay_minutes") or 60)
            return max(self._MIN_INTERVAL_SEC, minutes * 60)
        except Exception:
            return self._DEFAULT_INTERVAL_SEC

    def _get_api(self):
        """Return a MonClubApi instance built from Access config + token."""
        from access.config import build_access_api_endpoints
        from app.api.monclub_api import MonClubApi
        from app.core.db import load_auth_token

        token = load_auth_token()
        if not token:
            raise RuntimeError("No auth token stored — skipping optional content sync.")

        endpoints = build_access_api_endpoints()
        api = MonClubApi(endpoints=endpoints, logger=_log)
        return api, token

    # ------------------------------------------------------------------
    def _sync_once(self) -> None:
        from app.core.db import (
            delete_passed_optional_events,
            get_optional_sync_state,
            replace_optional_deals,
            replace_optional_events,
            replace_optional_products,
            save_optional_sync_state,
        )

        _log.info("[OptionalContentSync] Starting sync cycle.")

        # 1. Delete events that have already passed
        try:
            delete_passed_optional_events()
        except Exception as exc:
            _log.warning("[OptionalContentSync] Failed to delete passed events: %s", exc)

        # 2. Load stored version markers
        try:
            state = get_optional_sync_state()
        except Exception as exc:
            _log.warning("[OptionalContentSync] Failed to read sync state: %s", exc)
            state = {}

        events_ver: Optional[str] = state.get("events_last_version_at") or None
        products_ver: Optional[str] = state.get("products_last_version_at") or None
        deals_ver: Optional[str] = state.get("deals_last_version_at") or None

        # 3. Call backend
        try:
            api, token = self._get_api()
        except RuntimeError as exc:
            _log.info("[OptionalContentSync] %s", exc)
            return

        try:
            resp: Dict[str, Any] = api.get_optional_content_sync(
                token=token,
                events_last_version_at=events_ver,
                products_last_version_at=products_ver,
                deals_last_version_at=deals_ver,
            )
        except Exception as exc:
            _log.warning("[OptionalContentSync] API call failed: %s", exc)
            return

        # 4. Apply changed sections
        refresh_events: bool = bool(resp.get("refreshEvents", False))
        refresh_products: bool = bool(resp.get("refreshProducts", False))
        refresh_deals: bool = bool(resp.get("refreshDeals", False))

        new_events_ver: Optional[str] = resp.get("eventsVersionAt") or events_ver
        new_products_ver: Optional[str] = resp.get("productsVersionAt") or products_ver
        new_deals_ver: Optional[str] = resp.get("dealsVersionAt") or deals_ver

        if refresh_events:
            events: List[Dict[str, Any]] = resp.get("events") or []
            try:
                replace_optional_events(events)
                _log.info("[OptionalContentSync] Replaced %d upcoming events.", len(events))
            except Exception as exc:
                _log.warning("[OptionalContentSync] Failed to store events: %s", exc)

        if refresh_products:
            products: List[Dict[str, Any]] = resp.get("products") or []
            try:
                replace_optional_products(products)
                _log.info("[OptionalContentSync] Replaced %d products.", len(products))
            except Exception as exc:
                _log.warning("[OptionalContentSync] Failed to store products: %s", exc)

        if refresh_deals:
            deals: List[Dict[str, Any]] = resp.get("deals") or []
            try:
                replace_optional_deals(deals)
                _log.info("[OptionalContentSync] Replaced %d deals.", len(deals))
            except Exception as exc:
                _log.warning("[OptionalContentSync] Failed to store deals: %s", exc)

        # 5. Persist updated version markers (only overwrite sections that refreshed)
        try:
            save_optional_sync_state(
                events_last_version_at=new_events_ver if refresh_events else None,
                products_last_version_at=new_products_ver if refresh_products else None,
                deals_last_version_at=new_deals_ver if refresh_deals else None,
                update_events=refresh_events,
                update_products=refresh_products,
                update_deals=refresh_deals,
            )
        except Exception as exc:
            _log.warning("[OptionalContentSync] Failed to save sync state: %s", exc)

        _log.info(
            "[OptionalContentSync] Sync cycle done — events=%s, products=%s, deals=%s.",
            refresh_events, refresh_products, refresh_deals,
        )


# ── module-level convenience ──────────────────────────────────────────────────

_default_scheduler: Optional[OptionalContentSyncScheduler] = None


def get_optional_content_sync_scheduler() -> OptionalContentSyncScheduler:
    global _default_scheduler
    if _default_scheduler is None:
        _default_scheduler = OptionalContentSyncScheduler()
    return _default_scheduler

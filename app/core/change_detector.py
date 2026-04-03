"""ChangeDetectorService — polls the backend for member data changes and triggers sync."""
from __future__ import annotations

import threading
import logging
from datetime import datetime
from typing import Callable, Optional, Any

try:
    import requests as _requests
except ImportError:
    _requests = None  # type: ignore

_MEMBERS_VERSION_PATH = "/api/v1/manager/gym/access/v1/members-version"


class ChangeDetectorService:
    """
    Background thread that polls the backend members-version endpoint every
    `poll_interval` seconds. If `lastModifiedAt` increases, triggers an
    immediate device sync via `app.request_sync_now`.

    Constructor args:
        app                 MainApp instance (must have .after() and .request_sync_now)
        backend_base_url    Root URL e.g. "https://monclubwigo.tn"
        get_token_fn        Callable[[], str] — returns current JWT (called each poll)
        re_login_fn         Callable[[], str | None] — re-login and return new token, or None on failure
        gym_id              int — gym to check
        poll_interval       float — seconds between polls (default 45)
        cfg                 app config object (unused directly, available for subclasses)
        logger              stdlib logger
    """

    def __init__(
        self,
        *,
        app: Any,
        backend_base_url: str,
        get_token_fn: Callable[[], str],
        re_login_fn: Callable[[], Optional[str]],
        gym_id: int,
        poll_interval: float = 45.0,
        cfg: Any = None,
        logger: Any = None,
    ) -> None:
        self._app = app
        self._backend_base_url = backend_base_url.rstrip("/")
        self._get_token = get_token_fn
        self._re_login = re_login_fn
        self._gym_id = gym_id
        self._poll_interval = poll_interval
        self._cfg = cfg
        self._logger = logger or logging.getLogger(__name__)
        self._last_known_version: Optional[object] = None  # datetime after first poll
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background polling thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="ChangeDetectorService",
            daemon=True,
        )
        self._thread.start()
        self._logger.info(
            "[ChangeDetector] Started (interval=%.0fs, gymId=%s)",
            self._poll_interval,
            self._gym_id,
        )

    def stop(self) -> None:
        """Signal the polling loop to exit."""
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception as exc:
                self._logger.exception("[ChangeDetector] Unexpected error: %s", exc)
            self._stop_event.wait(timeout=self._poll_interval)

    def _poll_once(self) -> None:
        if _requests is None:
            self._logger.warning(
                "[ChangeDetector] 'requests' library not available — skipping poll"
            )
            return

        url = f"{self._backend_base_url}{_MEMBERS_VERSION_PATH}"
        token = self._get_token()
        if not token:
            self._logger.warning("[ChangeDetector] No auth token available — skipping poll")
            return
        headers = {"Authorization": f"Bearer {token}"}

        self._logger.debug("[ChangeDetector] polling: url=%s gymId=%s", url, self._gym_id)

        try:
            resp = _requests.get(url, headers=headers, timeout=10)
        except _requests.RequestException as exc:
            self._logger.warning("[ChangeDetector] Network error: %s", exc)
            return

        self._logger.debug("[ChangeDetector] response: status=%s", resp.status_code)

        if resp.status_code == 401:
            self._logger.info("[ChangeDetector] 401 — attempting re-login")
            new_token = self._re_login()
            if not new_token:
                self._logger.error(
                    "[ChangeDetector] Re-login failed — auto-sync disabled. "
                    "Restart the Access app."
                )
                self.stop()
                return
            self._logger.info("[ChangeDetector] re-login OK, retrying poll")
            try:
                resp = _requests.get(
                    url,
                    headers={"Authorization": f"Bearer {new_token}"},
                    timeout=10,
                )
            except _requests.RequestException as exc:
                self._logger.warning(
                    "[ChangeDetector] Retry after re-login failed: %s", exc
                )
                return

        if resp.status_code != 200:
            self._logger.warning(
                "[ChangeDetector] Unexpected status %s from members-version (url=%s)",
                resp.status_code, url,
            )
            return

        try:
            data = resp.json()
            version = str(data.get("lastModifiedAt", ""))
        except Exception as exc:
            self._logger.warning("[ChangeDetector] Failed to parse response: %s", exc)
            return

        if not version:
            self._logger.warning("[ChangeDetector] response has no lastModifiedAt field: %s", data)
            return

        # Parse as datetime for correct comparison (avoids fragile string comparison
        # that breaks if Jackson serializes fractional seconds inconsistently)
        try:
            parsed_version = datetime.fromisoformat(version)
        except (ValueError, TypeError) as exc:
            self._logger.warning(
                "[ChangeDetector] Cannot parse lastModifiedAt '%s': %s", version, exc
            )
            return

        if self._last_known_version is None:
            # First successful poll — set baseline, no sync
            self._last_known_version = parsed_version
            self._logger.info("[ChangeDetector] Baseline set: lastModifiedAt=%s", version)
            return

        if parsed_version > self._last_known_version:
            self._logger.info(
                "[ChangeDetector] Change detected! old=%s new=%s — triggering sync",
                self._last_known_version.isoformat(), version,
            )
            self._last_known_version = parsed_version
            try:
                self._app.after(0, self._app.request_sync_now)
            except Exception as exc:
                self._logger.warning(
                    "[ChangeDetector] Failed to schedule sync: %s", exc
                )
        else:
            self._logger.debug(
                "[ChangeDetector] no change: lastModifiedAt=%s (known=%s)",
                version, self._last_known_version.isoformat(),
            )

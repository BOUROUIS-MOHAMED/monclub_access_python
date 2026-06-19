"""LogSyncRequestPoller — periodically pulls "flush my logs" requests from the backend.

When the dashboard's "Sync logs now" button can't hit the local API directly
(dashboard opened from a different machine, CORS blocked, browser refused
the loopback call), it falls back to inserting an `AccessLogSyncRequest`
row on the backend with status=PENDING. This thread polls every ~10 min,
claims any pending row (PENDING → TRIGGERED), runs the flush, and reports
back (TRIGGERED → COMPLETED / FAILED).

Design notes
------------
* Thread lifecycle mirrors ChangeDetectorService: a daemon thread woken by
  ``threading.Event``. The thread is intentionally cheap — one HTTP call per
  poll, returns 204 on the (usual) "no pending request" path.
* No retry storm: failures back off to 5 min, recovering to 10 min on the
  next success.
* All errors are swallowed and logged — this thread must never crash the
  app, since it's a non-critical convenience path.
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Optional

try:
    import requests as _requests
except ImportError:
    _requests = None  # type: ignore


_PENDING_PATH = "/api/v1/gym/access/logs/sync-request/pending"
_ACK_PATH_FMT = "/api/v1/gym/access/logs/sync-request/{id}/ack"
_COMPLETE_PATH_FMT = "/api/v1/gym/access/logs/sync-request/{id}/complete"

DEFAULT_POLL_INTERVAL_SEC = 600.0  # 10 min
FAILURE_BACKOFF_SEC = 300.0        # 5 min after a transient error


class LogSyncRequestPoller:
    def __init__(
        self,
        *,
        backend_base_url: str,
        get_token_fn: Callable[[], str],
        flush_fn: Callable[[], dict],
        poll_interval: float = DEFAULT_POLL_INTERVAL_SEC,
        logger: Optional[Any] = None,
    ) -> None:
        self._backend_base_url = backend_base_url.rstrip("/")
        self._get_token = get_token_fn
        self._flush_fn = flush_fn
        self._poll_interval = float(poll_interval)
        self._logger = logger or logging.getLogger(__name__)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------ #
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="LogSyncRequestPoller",
            daemon=True,
        )
        self._thread.start()
        self._logger.info(
            "[LogSyncPoller] started (interval=%.0fs)", self._poll_interval
        )

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------------ #
    def _run_loop(self) -> None:
        while not self._stop.is_set():
            wait = self._poll_interval
            try:
                if not self._poll_once():
                    wait = FAILURE_BACKOFF_SEC
            except Exception as exc:
                self._logger.debug("[LogSyncPoller] poll error: %s", exc, exc_info=True)
                wait = FAILURE_BACKOFF_SEC
            self._stop.wait(timeout=wait)

    # Returns True on success (whether or not a request was processed),
    # False on transient errors that warrant a backoff.
    def _poll_once(self) -> bool:
        if _requests is None:
            return False
        token = self._get_token()
        if not token:
            # No login yet — don't poll. Re-check on next interval.
            return True

        headers = {"Authorization": f"Bearer {token}"}
        try:
            resp = _requests.get(
                self._backend_base_url + _PENDING_PATH,
                headers=headers,
                timeout=15,
            )
        except _requests.RequestException as exc:
            self._logger.debug("[LogSyncPoller] /pending network error: %s", exc)
            return False

        if resp.status_code == 204:
            return True  # nothing pending
        if resp.status_code == 401:
            # Token expired; let the next change_detector cycle refresh.
            self._logger.debug("[LogSyncPoller] /pending returned 401 — token may be stale")
            return True
        if resp.status_code != 200:
            self._logger.debug("[LogSyncPoller] /pending HTTP %d", resp.status_code)
            return False

        try:
            payload = resp.json()
        except Exception:
            self._logger.warning("[LogSyncPoller] /pending returned non-JSON body")
            return False

        req_id = payload.get("id")
        if not isinstance(req_id, int):
            self._logger.warning("[LogSyncPoller] /pending missing id; payload=%r", payload)
            return False

        self._logger.info("[LogSyncPoller] picked up sync request id=%s", req_id)

        # Ack — best-effort. If the ack fails we still attempt the flush; the
        # request just stays PENDING and we'll process it next tick.
        try:
            ack_resp = _requests.post(
                self._backend_base_url + _ACK_PATH_FMT.format(id=req_id),
                headers=headers,
                timeout=15,
            )
            if ack_resp.status_code >= 300:
                self._logger.warning(
                    "[LogSyncPoller] ack id=%s HTTP %d body=%s",
                    req_id, ack_resp.status_code, ack_resp.text[:200],
                )
        except _requests.RequestException as exc:
            self._logger.warning("[LogSyncPoller] ack id=%s network error: %s", req_id, exc)

        # Do the flush — this is the actual work.
        ok = True
        err_msg = ""
        uploaded_keys = ""
        try:
            result = self._flush_fn() or {}
            uploaded_keys = ",".join(result.get("pendingNow") or [])
            self._logger.info(
                "[LogSyncPoller] flush done id=%s rotated=%s pending=%s",
                req_id, result.get("rotated"), uploaded_keys,
            )
        except Exception as exc:
            ok = False
            err_msg = str(exc)
            self._logger.warning("[LogSyncPoller] flush failed id=%s: %s", req_id, exc)

        # Complete — best-effort. Failure here just leaves the row in
        # TRIGGERED and the reaper will eventually mark it FAILED.
        try:
            _requests.post(
                self._backend_base_url + _COMPLETE_PATH_FMT.format(id=req_id),
                headers=headers,
                json={"ok": ok, "uploadedObjectKeys": uploaded_keys, "errorMessage": err_msg},
                timeout=15,
            )
        except _requests.RequestException as exc:
            self._logger.warning("[LogSyncPoller] complete id=%s network error: %s", req_id, exc)

        return True

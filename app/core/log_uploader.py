"""Log upload queue — marker-file based, zero impact on turnstile path."""
from __future__ import annotations

import gzip
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Callable

_handler_logger = logging.getLogger(__name__)

# Must match the same pattern as HalfDaySizeRotatingFileHandler
_LOG_FILE_RE = re.compile(r"^app-(\d{4}-\d{2}-\d{2})-(am|pm)(?:\.(\d+))?\.log$")

# Retry backoff intervals (seconds) indexed by attempt count; last value is the cap.
_BACKOFF_SECONDS = [0, 120, 240, 480, 960, 3600]


class LogUploadQueue:
    """
    Background daemon that uploads finalized log files to the backend via
    presigned R2 URLs. Uses marker files for state — no SQLite, no DB.

    Files are never touched by this class while the logger is actively writing to them.

    The ``on_log_rotated`` callback (``register_pending``) does a single atomic
    file rename and returns in <1 ms — safe to call synchronously from the
    logging handler lock.
    """

    def __init__(
        self,
        log_dir: Path,
        get_token: Callable[[], object | None],
        get_upload_url: Callable[[], str | None],
    ) -> None:
        self.log_dir = Path(log_dir)
        self._get_token = get_token
        self._get_upload_url = get_upload_url
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # In-memory: maps marker path string → monotonic time of last attempt.
        # Enforces backoff without writing to disk. Reset on restart (intentional:
        # conservative policy is to retry immediately after restart).
        self._last_attempt: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_pending(self, log_path: Path) -> None:
        """Called by on_log_rotated when a log file is finalized.

        Creates {log_path}.pending atomically. Content = "0" (retry count).
        Idempotent: does not overwrite an existing .pending file.
        """
        marker = Path(str(log_path) + ".pending")
        if marker.exists():
            return  # already registered, don't reset retry count
        tmp = Path(str(marker) + ".tmp")
        try:
            tmp.write_text("0", encoding="utf-8")
            tmp.rename(marker)
        except OSError as e:
            _handler_logger.warning(
                "LogUploadQueue: failed to create .pending for %s: %s", log_path.name, e
            )

    def scan_orphans(self) -> None:
        """Called once at startup to recover files orphaned by a hard crash.

        Any .log file that matches the naming pattern, is not the currently
        active file, and has no .uploaded or .failed sibling gets a .pending
        marker created for it.
        """
        active_name = self._active_log_name()
        try:
            for path in self.log_dir.iterdir():
                if not path.is_file():
                    continue
                if not _LOG_FILE_RE.match(path.name):
                    continue
                if path.name == active_name:
                    continue
                if Path(str(path) + ".uploaded").exists():
                    continue
                if Path(str(path) + ".failed").exists():
                    continue
                self.register_pending(path)
        except OSError as e:
            _handler_logger.warning("LogUploadQueue: scan_orphans error: %s", e)

    def start(self) -> None:
        """Start the background daemon thread."""
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._upload_loop,
            name="log-uploader",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the background thread to stop (used in tests)."""
        self._stop.set()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _active_log_name(self) -> str:
        """Return the filename of the currently active log (not yet rotated)."""
        import datetime as dt
        now = dt.datetime.now()
        period = "am" if now.hour < 12 else "pm"
        return f"app-{now.date().isoformat()}-{period}.log"

    def _read_retry_count(self, marker: Path) -> int:
        try:
            return max(0, int(marker.read_text(encoding="utf-8").strip()))
        except Exception:
            return 0

    def _write_retry_count(self, marker: Path, count: int) -> None:
        tmp = Path(str(marker) + ".tmp")
        try:
            tmp.write_text(str(count), encoding="utf-8")
            os.replace(tmp, marker)
        except OSError as e:
            _handler_logger.warning(
                "LogUploadQueue: failed to write retry count to %s: %s", marker.name, e
            )

    def _backoff_for(self, attempt: int) -> int:
        """Return seconds to wait before the next attempt."""
        if attempt < len(_BACKOFF_SECONDS):
            return _BACKOFF_SECONDS[attempt]
        return _BACKOFF_SECONDS[-1]

    def _upload_loop(self) -> None:
        """Main loop: scan for .pending markers and process them."""
        while not self._stop.is_set():
            self._process_pending_files()
            self._stop.wait(timeout=60)

    def _process_pending_files(self) -> None:
        try:
            markers = list(self.log_dir.glob("*.pending"))
        except OSError:
            return
        for marker in markers:
            if self._stop.is_set():
                break
            self._handle_marker(marker)

    def _handle_marker(self, marker: Path) -> None:
        log_path = Path(str(marker)[: -len(".pending")])

        # If the .log file is gone (deleted by cleanup), abandon this marker.
        if not log_path.exists():
            _handler_logger.warning(
                "LogUploadQueue: %s deleted before upload; removing .pending", log_path.name
            )
            try:
                marker.unlink(missing_ok=True)
                self._last_attempt.pop(str(marker), None)
            except OSError:
                pass
            return

        retry_count = self._read_retry_count(marker)

        # Enforce backoff: skip if not enough time has passed since last attempt.
        now_mono = time.monotonic()
        required_wait = self._backoff_for(retry_count)
        last = self._last_attempt.get(str(marker), 0.0)
        if retry_count > 0 and (now_mono - last) < required_wait:
            return  # too soon; wait for the next loop cycle

        try:
            compressed = self._compress(log_path)
        except OSError as e:
            _handler_logger.warning("LogUploadQueue: cannot read %s: %s", log_path.name, e)
            return

        self._last_attempt[str(marker)] = time.monotonic()
        success = self._upload(log_path.name, compressed)
        if success:
            try:
                marker.unlink(missing_ok=True)
                self._last_attempt.pop(str(marker), None)
                Path(str(log_path) + ".uploaded").touch()
            except OSError:
                pass
            _handler_logger.info("LogUploadQueue: uploaded %s", log_path.name)
        else:
            new_count = retry_count + 1
            self._write_retry_count(marker, new_count)
            backoff = self._backoff_for(new_count)
            _handler_logger.debug(
                "LogUploadQueue: upload failed for %s (attempt %d), next retry in %ds",
                log_path.name, new_count, backoff,
            )

    def _compress(self, log_path: Path) -> bytes:
        data = log_path.read_bytes()
        return gzip.compress(data, compresslevel=6)

    def _upload(self, filename: str, compressed: bytes) -> bool:
        """Two-step upload: get presigned URL, then PUT directly to R2."""
        token_state = self._get_token()
        if token_state is None:
            _handler_logger.debug("LogUploadQueue: no auth token, skipping upload")
            return False

        # Support both raw str token and AuthTokenState object
        token = token_state.token if hasattr(token_state, "token") else str(token_state)
        if not token:
            return False

        presign_url = self._get_upload_url()
        if not presign_url:
            _handler_logger.debug("LogUploadQueue: no upload URL configured, skipping")
            return False

        try:
            import requests

            # Step 1: request presigned URL
            resp = requests.post(
                presign_url,
                json={"filename": filename},
                headers={"Authorization": f"Bearer {token}"},
                timeout=20,
            )
            if resp.status_code < 200 or resp.status_code >= 300:
                _handler_logger.warning(
                    "LogUploadQueue: presign request failed HTTP %d for %s",
                    resp.status_code, filename,
                )
                return False

            data = resp.json()
            put_url = data["url"]
            put_headers = dict(data.get("headers") or {})
            put_headers.setdefault("Content-Type", "application/gzip")

            # Step 2: PUT directly to R2
            put_resp = requests.put(put_url, data=compressed, headers=put_headers, timeout=120)
            if put_resp.status_code < 200 or put_resp.status_code >= 300:
                _handler_logger.warning(
                    "LogUploadQueue: R2 PUT failed HTTP %d for %s",
                    put_resp.status_code, filename,
                )
                return False

            return True

        except Exception as e:
            _handler_logger.warning("LogUploadQueue: upload error for %s: %s", filename, e)
            return False

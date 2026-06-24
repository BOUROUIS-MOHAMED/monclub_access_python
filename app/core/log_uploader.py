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

# Must match the same pattern as HalfDaySizeRotatingFileHandler (logger._LOG_FILE_RE).
# Accepts legacy am/pm names and current hourly-window (from-HH-to-HH) names.
_LOG_FILE_RE = re.compile(
    r"^app-(\d{4}-\d{2}-\d{2})-(?:am|pm|from-\d{2}-to-\d{2})(?:\.(\d+))?\.log$"
)

# Retry backoff intervals (seconds) indexed by attempt count; last value is the cap.
_BACKOFF_SECONDS = [0, 120, 240, 480, 960, 3600]

# After this many failed attempts, give up on a file. It moves from .pending to
# .failed so the cleanup sweep can remove it eventually. Without this, a single
# unreadable file or an auth misconfiguration could keep the .pending marker
# alive forever and prevent the disk-cleanup loop from purging the log
# (logger._cleanup_old_logs skips files with a .pending sibling).
MAX_RETRY_COUNT = 20


class LogUploadQueue:
    """
    Background daemon that uploads finalized log files to the backend via
    presigned upload credentials (Cloudinary POST_MULTIPART or R2 PUT).
    Uses marker files for state — no SQLite, no DB.

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
        # Wake event lets external callers (the /logs/flush endpoint, the
        # sync-request poller) interrupt the 60 s upload-loop sleep so a
        # freshly-rotated file goes out within seconds instead of up to a
        # minute later.
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        # In-memory: maps marker path string → monotonic time of last attempt.
        # Enforces backoff without writing to disk. Reset on restart (intentional:
        # conservative policy is to retry immediately after restart).
        self._last_attempt: dict[str, float] = {}
        # Optional zero-arg callable wired in by the app (see app/ui/app.py)
        # that triggers the rotating file handler's _rotate_active_file under
        # its own lock. We don't import the handler here — keep this module
        # decoupled from app.core.logger.
        self._rotate_fn: Callable[[], None] | None = None

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
            os.replace(str(tmp), str(marker))
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
                # .failed: reserved for manual operator intervention — drop a .failed file
                # alongside a .log to permanently skip uploading that file.
                # (No code creates .failed automatically; the retry loop is indefinite.)
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
        self._wake.set()

    def set_rotate_fn(self, fn: Callable[[], None] | None) -> None:
        """Inject a callable that force-rotates the currently active half-day log.

        The app wires this to ``HalfDaySizeRotatingFileHandler._rotate_active_file``
        (called under the handler's logging lock). ``flush_now()`` invokes it so
        the in-flight log file becomes a finalized sibling that ``register_pending``
        / ``scan_orphans`` will queue for upload.
        """
        self._rotate_fn = fn

    def wake(self) -> None:
        """Interrupt the upload loop's sleep so it processes pending markers now."""
        self._wake.set()

    def flush_now(self) -> dict:
        """Force-rotate the currently active log and kick the upload loop.

        Returns a small dict the local API surfaces back to the dashboard:
            {
              "rotated":      True/False — whether the rotate callback ran,
              "activeBefore": "app-2026-05-11-from-08-to-09.log",
              "pendingNow":   ["app-2026-05-11-from-08-to-09.1.log", ...]  # filenames
            }

        Idempotent: calling twice in a row just re-scans orphans the second time.
        Cheap: rotate + scan + wake completes in single-digit milliseconds.
        """
        active_before = self._active_log_name()
        rotated = False
        if self._rotate_fn is not None:
            try:
                self._rotate_fn()
                rotated = True
            except Exception as exc:
                _handler_logger.warning("LogUploadQueue: flush rotate failed: %s", exc)
        # In case rotation didn't fire (e.g. file was already empty) we still
        # sweep — there may be other orphans from a previous boot.
        try:
            self.scan_orphans()
        except Exception:
            pass
        self._wake.set()
        try:
            pending_now = sorted(
                p.name[: -len(".pending")]
                for p in self.log_dir.glob("*.pending")
            )
        except OSError:
            pending_now = []
        return {
            "rotated":      rotated,
            "activeBefore": active_before,
            "pendingNow":   pending_now,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _active_log_name(self) -> str:
        """Return the filename of the currently active log (not yet rotated).

        Derived from the logger's window scheme so the two never drift — if they
        did, scan_orphans could queue the live file for upload mid-write.
        """
        import datetime as dt
        from app.core.logger import active_log_name_for
        return active_log_name_for(dt.datetime.now())

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
            # Wait up to 60 s OR until something pokes the wake event
            # (flush_now, sync-request poller, stop). Clear afterwards so
            # only NEW pokes wake us next cycle.
            self._wake.wait(timeout=60)
            self._wake.clear()

    def _process_pending_files(self) -> None:
        try:
            markers = list(self.log_dir.glob("*.pending"))
        except OSError:
            return
        for marker in markers:
            if self._stop.is_set():
                break
            self._handle_marker(marker)

    def _is_ready(self) -> bool:
        """True only when we can actually attempt an upload (auth token + upload
        URL both present).

        When not ready — logged out, or the presign URL isn't configured yet —
        we must NOT treat the marker as a failed attempt. Counting it would burn
        the file's retry budget and, after MAX_RETRY_COUNT, permanently mark a
        perfectly good log .failed (then cleanup purges it unsent). That is the
        bug that lost logs when log_presign_url defaulted to "" — uploads were
        never even attempted, yet files marched to .failed.
        """
        token_state = self._get_token()
        token = token_state.token if hasattr(token_state, "token") else token_state
        if not token:
            return False
        if not (self._get_upload_url() or "").strip():
            return False
        return True

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

        # Not ready (no token / no upload URL): defer WITHOUT counting a retry,
        # so a config gap or logged-out window can't push good logs to .failed.
        if not self._is_ready():
            _handler_logger.debug(
                "LogUploadQueue: deferring %s — not ready (missing auth token or upload URL)",
                log_path.name,
            )
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
            if new_count >= MAX_RETRY_COUNT:
                # Give up: convert .pending → .failed so cleanup can purge the
                # log eventually and we stop wasting bandwidth on a doomed file.
                try:
                    marker.unlink(missing_ok=True)
                    Path(str(log_path) + ".failed").touch()
                    self._last_attempt.pop(str(marker), None)
                except OSError:
                    pass
                _handler_logger.error(
                    "LogUploadQueue: giving up on %s after %d attempts — marked .failed",
                    log_path.name, new_count,
                )
                return
            self._write_retry_count(marker, new_count)
            backoff = self._backoff_for(new_count)
            _handler_logger.debug(
                "LogUploadQueue: upload failed for %s (attempt %d/%d), next retry in %ds",
                log_path.name, new_count, MAX_RETRY_COUNT, backoff,
            )

    def _compress(self, log_path: Path) -> bytes:
        data = log_path.read_bytes()
        return gzip.compress(data, compresslevel=6)

    def _upload(self, filename: str, compressed: bytes) -> bool:
        """Two-step upload: get presigned credentials, then upload directly to storage.

        Supports two upload methods returned by the backend:
          - POST_MULTIPART  — Cloudinary (default). Sends multipart/form-data with
                              the signed formFields + the gzip file.
          - PUT             — Cloudflare R2 / S3-compatible. Sends raw bytes with
                              the provided headers.
        """
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

            # Step 1: request upload credentials from the backend
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
            upload_url = data["url"]
            method = data.get("method", "PUT").upper()
            form_fields = dict(data.get("formFields") or {})
            extra_headers = dict(data.get("headers") or {})

            # Step 2: upload directly to storage
            if method == "POST_MULTIPART":
                # Cloudinary: multipart/form-data POST with signed fields + file
                files = {
                    "file": (filename + ".gz", compressed, "application/gzip"),
                }
                upload_resp = requests.post(
                    upload_url,
                    files=files,
                    data=form_fields,
                    timeout=120,
                )
            else:
                # R2 / S3-compatible: raw PUT with Content-Type header
                extra_headers.setdefault("Content-Type", "application/gzip")
                upload_resp = requests.put(
                    upload_url,
                    data=compressed,
                    headers=extra_headers,
                    timeout=120,
                )

            if upload_resp.status_code < 200 or upload_resp.status_code >= 300:
                # The presign URL has a TTL (R2: 30 min, Cloudinary: signed
                # params). If the local upload step happens long after the
                # presign (e.g. flaky network kept us in backoff for an hour),
                # the storage side returns 401/403/`SignatureDoesNotMatch`.
                # Surface that explicitly so we know to re-presign rather than
                # blaming the local network.
                presign_expired = upload_resp.status_code in (401, 403)
                hint = " (presign URL likely expired — will re-presign on retry)" if presign_expired else ""
                _handler_logger.warning(
                    "LogUploadQueue: storage upload failed HTTP %d for %s (method=%s)%s",
                    upload_resp.status_code, filename, method, hint,
                )
                return False

            return True

        except Exception as e:
            _handler_logger.warning("LogUploadQueue: upload error for %s: %s", filename, e)
            return False

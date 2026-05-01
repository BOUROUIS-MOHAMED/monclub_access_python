# monclub_access_python/app/core/logger.py
from __future__ import annotations

import datetime as dt
import logging
import queue
import re
from pathlib import Path
from typing import Callable, Optional

from app.core.utils import LOG_DIR, ensure_dirs

_handler_logger = logging.getLogger(__name__)

LOG_MAX_BYTES = 50 * 1024 * 1024
LOG_RETENTION_DAYS = 7
_LOG_FILE_RE = re.compile(r"^app-(\d{4}-\d{2}-\d{2})-(am|pm)(?:\.(\d+))?\.log$")
_STALE_MARKER_CUTOFF_DAYS = 30


class TkQueueHandler(logging.Handler):
    """
    Logging handler that pushes formatted log lines into a queue for Tkinter UI consumption.
    """
    def __init__(self, q: "queue.Queue[str]"):
        super().__init__()
        self.q = q

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            self.q.put_nowait(msg)
        except Exception:
            pass


class HalfDaySizeRotatingFileHandler(logging.FileHandler):
    """Write dated AM/PM logs and rotate each half-day file by size."""

    def __init__(
        self,
        log_dir: str | Path,
        *,
        max_bytes: int = LOG_MAX_BYTES,
        retention_days: int = LOG_RETENTION_DAYS,
        encoding: str = "utf-8",
        now_func: Callable[[], dt.datetime] | None = None,
        on_log_rotated: Callable[[Path], None] | None = None,
    ) -> None:
        self.log_dir = Path(log_dir).resolve()
        self.max_bytes = int(max_bytes)
        self.retention_days = max(1, int(retention_days))
        self.now_func = now_func or dt.datetime.now
        self._last_cleanup_date: dt.date | None = None
        self.on_log_rotated = on_log_rotated
        # NOTE: callback is invoked synchronously under the handler lock — must return quickly.
        # Design: register_pending() does a single atomic file rename (<1 ms); this is safe.

        self.log_dir.mkdir(parents=True, exist_ok=True)
        now = self.now_func()
        self._cleanup_if_needed(now.date())
        super().__init__(str(self._path_for(now)), mode="a", encoding=encoding, delay=True)

    @staticmethod
    def _period_for(when: dt.datetime) -> str:
        return "am" if when.hour < 12 else "pm"

    def _path_for(self, when: dt.datetime) -> Path:
        return self.log_dir / f"app-{when.date().isoformat()}-{self._period_for(when)}.log"

    def _set_active_path(self, path: Path) -> None:
        if self.stream:
            self.stream.flush()
            self.stream.close()
            self.stream = None
        self.baseFilename = str(path)

    def _switch_if_needed(self, now: dt.datetime) -> None:
        path = self._path_for(now)
        if Path(self.baseFilename) != path:
            old_path = Path(self.baseFilename)      # capture BEFORE overwrite
            self._set_active_path(path)             # closes stream, updates baseFilename
            if self.on_log_rotated and old_path.exists():
                try:
                    self.on_log_rotated(old_path)
                except Exception as _cb_exc:
                    # Callback errors must not disrupt the logging system.
                    _handler_logger.debug("on_log_rotated callback raised: %s", _cb_exc)

    def _formatted_record_size(self, record: logging.LogRecord) -> int:
        text = self.format(record) + self.terminator
        return len(text.encode(self.encoding or "utf-8", errors="replace"))

    def _active_file_size(self) -> int:
        if self.stream:
            self.stream.flush()
        try:
            return Path(self.baseFilename).stat().st_size
        except FileNotFoundError:
            return 0

    def _should_rotate(self, record: logging.LogRecord) -> bool:
        if self.max_bytes <= 0:
            return False
        current_size = self._active_file_size()
        if current_size <= 0:
            return False
        return current_size + self._formatted_record_size(record) > self.max_bytes

    def _next_suffix_path(self, source: Path) -> Path:
        suffix_index = 1
        while True:
            candidate = source.with_name(f"{source.stem}.{suffix_index}{source.suffix}")
            if not candidate.exists():
                return candidate
            suffix_index += 1

    def _rotate_active_file(self) -> None:
        source = Path(self.baseFilename)
        if self.stream:
            self.stream.flush()
            self.stream.close()
            self.stream = None
        try:
            if not source.exists() or source.stat().st_size <= 0:
                return
            dest = self._next_suffix_path(source)
            source.rename(dest)                     # rename must succeed first
            if self.on_log_rotated:
                try:
                    self.on_log_rotated(dest)       # called with RENAMED destination
                except Exception as _cb_exc:
                    # Callback errors must not disrupt the logging system.
                    _handler_logger.debug("on_log_rotated callback raised: %s", _cb_exc)
        except OSError:
            return                                  # do NOT call callback on failure

    def _cleanup_if_needed(self, today: dt.date) -> None:
        if self._last_cleanup_date == today:
            return
        self._cleanup_old_logs(today)
        self._last_cleanup_date = today

    def _cleanup_old_logs(self, today: dt.date) -> None:
        cutoff = today - dt.timedelta(days=self.retention_days - 1)
        stale_cutoff = today - dt.timedelta(days=_STALE_MARKER_CUTOFF_DAYS)

        for path in self.log_dir.iterdir():
            if not path.is_file():
                continue

            # Clean up stale .uploaded and .failed markers (30-day retention)
            if path.suffix in (".uploaded", ".failed"):
                stem = path.stem  # e.g. "app-2020-01-01-am.log"
                m = _LOG_FILE_RE.match(stem)
                if m:
                    try:
                        log_date = dt.date.fromisoformat(m.group(1))
                        if log_date < stale_cutoff:
                            path.unlink(missing_ok=True)
                    except (ValueError, OSError):
                        pass
                continue

            # Only process .log files matched by the pattern
            match = _LOG_FILE_RE.match(path.name)
            if not match:
                continue
            try:
                log_date = dt.date.fromisoformat(match.group(1))
            except ValueError:
                continue
            if log_date >= cutoff:
                continue

            # Skip if a .pending sibling exists (upload not yet done)
            if Path(str(path) + ".pending").exists():
                continue

            try:
                path.unlink()
            except OSError:
                continue

    def emit(self, record: logging.LogRecord) -> None:
        try:
            now = self.now_func()
            self._cleanup_if_needed(now.date())
            self._switch_if_needed(now)
            if self._should_rotate(record):
                self._rotate_active_file()
            super().emit(record)
        except Exception:
            self.handleError(record)


def setup_logging(level: str = "DEBUG", ui_queue: Optional["queue.Queue[str]"] = None) -> logging.Logger:
    ensure_dirs()
    logger = logging.getLogger("zkapp")
    logger.setLevel(getattr(logging, level.upper(), logging.DEBUG))
    logger.propagate = False

    # avoid duplicate handlers on reload
    if logger.handlers:
        return logger

    file_handler = HalfDaySizeRotatingFileHandler(LOG_DIR)
    file_handler.setLevel(getattr(logging, level.upper(), logging.DEBUG))
    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    console = logging.StreamHandler()
    console.setLevel(getattr(logging, level.upper(), logging.DEBUG))
    console.setFormatter(fmt)
    logger.addHandler(console)

    if ui_queue is not None:
        qh = TkQueueHandler(ui_queue)
        qh.setLevel(getattr(logging, level.upper(), logging.DEBUG))
        qh.setFormatter(fmt)
        logger.addHandler(qh)

    return logger

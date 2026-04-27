# monclub_access_python/app/core/logger.py
from __future__ import annotations

import datetime as dt
import logging
import queue
import re
from pathlib import Path
from typing import Callable, Optional

from app.core.utils import LOG_DIR, ensure_dirs


LOG_MAX_BYTES = 50 * 1024 * 1024
LOG_RETENTION_DAYS = 7
_LOG_FILE_RE = re.compile(r"^app-(\d{4}-\d{2}-\d{2})-(am|pm)(?:\.(\d+))?\.log$")


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
    ) -> None:
        self.log_dir = Path(log_dir).resolve()
        self.max_bytes = int(max_bytes)
        self.retention_days = max(1, int(retention_days))
        self.now_func = now_func or dt.datetime.now
        self._last_cleanup_date: dt.date | None = None

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
            self._set_active_path(path)

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
            source.rename(self._next_suffix_path(source))
        except OSError:
            return

    def _cleanup_if_needed(self, today: dt.date) -> None:
        if self._last_cleanup_date == today:
            return
        self._cleanup_old_logs(today)
        self._last_cleanup_date = today

    def _cleanup_old_logs(self, today: dt.date) -> None:
        cutoff = today - dt.timedelta(days=self.retention_days - 1)
        for path in self.log_dir.iterdir():
            if not path.is_file():
                continue
            match = _LOG_FILE_RE.match(path.name)
            if not match:
                continue
            try:
                log_date = dt.date.fromisoformat(match.group(1))
            except ValueError:
                continue
            if log_date >= cutoff:
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

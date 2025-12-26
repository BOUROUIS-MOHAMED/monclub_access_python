from __future__ import annotations

import logging
import queue
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from app.core.utils import LOG_DIR, ensure_dirs


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


def setup_logging(level: str = "DEBUG", ui_queue: Optional["queue.Queue[str]"] = None) -> logging.Logger:
    ensure_dirs()
    logger = logging.getLogger("zkapp")
    logger.setLevel(getattr(logging, level.upper(), logging.DEBUG))
    logger.propagate = False

    # avoid duplicate handlers on reload
    if logger.handlers:
        return logger

    log_path = Path(LOG_DIR) / "app.log"

    file_handler = RotatingFileHandler(str(log_path), maxBytes=5_000_000, backupCount=5, encoding="utf-8")
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

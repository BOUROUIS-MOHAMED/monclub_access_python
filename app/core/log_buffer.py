"""
Lightweight log buffer — replaces the Tkinter LogsPage._buffer
for headless operation. The local API SSE stream reads from this.
"""
from __future__ import annotations
import threading
from typing import List, Tuple


class LogBuffer:
    """Thread-safe ring buffer for log lines (level, text)."""

    def __init__(self, max_lines: int = 5000):
        self._buffer: List[Tuple[str, str]] = []
        self._lock = threading.Lock()
        self._max_lines = max_lines

    def append_log(self, level: str, line: str) -> None:
        with self._lock:
            self._buffer.append((level, line))
            if len(self._buffer) > self._max_lines:
                self._buffer = self._buffer[-self._max_lines:]

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()

    def snapshot(self) -> List[Tuple[str, str]]:
        with self._lock:
            return list(self._buffer)

    def __len__(self) -> int:
        with self._lock:
            return len(self._buffer)


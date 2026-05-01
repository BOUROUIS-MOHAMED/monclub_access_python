"""Tests for on_log_rotated callback in HalfDaySizeRotatingFileHandler."""
from __future__ import annotations

import datetime as dt
import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.core.logger import HalfDaySizeRotatingFileHandler


def _make_handler(tmp_path: Path, callback=None, *, max_bytes: int = 1024) -> HalfDaySizeRotatingFileHandler:
    h = HalfDaySizeRotatingFileHandler(
        tmp_path,
        max_bytes=max_bytes,
        retention_days=7,
        on_log_rotated=callback,
    )
    fmt = logging.Formatter("%(message)s")
    h.setFormatter(fmt)
    return h


def _emit(h: HalfDaySizeRotatingFileHandler, msg: str, when: dt.datetime) -> None:
    record = logging.LogRecord("test", logging.DEBUG, "", 0, msg, (), None)
    h.now_func = lambda: when
    h.emit(record)


class TestOnLogRotatedCallback:
    def test_callback_receives_old_path_on_time_rotation(self, tmp_path):
        """Switching from AM to PM must call the callback with the AM log path."""
        captured = []
        h = _make_handler(tmp_path, callback=captured.append)

        am = dt.datetime(2026, 5, 1, 9, 0)
        _emit(h, "hello am", am)

        pm = dt.datetime(2026, 5, 1, 13, 0)
        _emit(h, "hello pm", pm)  # triggers time rotation

        h.close()
        assert len(captured) == 1
        assert captured[0].name == "app-2026-05-01-am.log"

    def test_callback_receives_dest_path_on_size_rotation(self, tmp_path):
        """Exceeding max_bytes must call the callback with the renamed file path."""
        captured = []
        h = _make_handler(tmp_path, callback=captured.append, max_bytes=10)

        now = dt.datetime(2026, 5, 1, 9, 0)
        _emit(h, "a" * 20, now)  # forces size rotation
        _emit(h, "b", now)

        h.close()
        assert len(captured) >= 1
        # renamed file has .1 suffix
        assert ".1" in captured[0].name

    def test_callback_not_called_when_no_rotation(self, tmp_path):
        """No rotation → callback is never called."""
        captured = []
        h = _make_handler(tmp_path, callback=captured.append)

        now = dt.datetime(2026, 5, 1, 9, 0)
        _emit(h, "x", now)
        _emit(h, "y", now)

        h.close()
        assert captured == []

    def test_callback_none_is_safe(self, tmp_path):
        """on_log_rotated=None must not raise when rotation happens."""
        h = _make_handler(tmp_path, callback=None)
        am = dt.datetime(2026, 5, 1, 9, 0)
        pm = dt.datetime(2026, 5, 1, 13, 0)
        _emit(h, "x", am)
        _emit(h, "y", pm)  # time rotation, no callback
        h.close()

    def test_callback_not_called_on_failed_size_rotation(self, tmp_path, monkeypatch):
        """If rename raises OSError, callback must NOT be called."""
        captured = []
        h = _make_handler(tmp_path, callback=captured.append, max_bytes=10)

        now = dt.datetime(2026, 5, 1, 9, 0)
        # First emit seeds the file with data (size was 0, no rotation yet)
        _emit(h, "a" * 20, now)

        # Now the file has content; next emit will trigger _should_rotate.
        # Apply the monkeypatch AFTER the first write so the file exists.
        def failing_rename(self_path, target):
            raise OSError("disk full")

        monkeypatch.setattr(Path, "rename", failing_rename)
        _emit(h, "b" * 5, now)   # triggers size rotation → rename fails → no callback

        h.close()
        assert captured == []

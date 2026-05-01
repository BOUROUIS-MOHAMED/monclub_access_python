"""Tests for LogUploadQueue."""
from __future__ import annotations

import datetime as dt
import gzip
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from app.core.log_uploader import LogUploadQueue


def _make_queue(tmp_path: Path, get_token=None, get_url=None) -> LogUploadQueue:
    get_token = get_token or (lambda: "test-token")
    get_url = get_url or (lambda: "https://api.example.com/api/v1/gym/access/logs/presign")
    return LogUploadQueue(log_dir=tmp_path, get_token=get_token, get_upload_url=get_url)


class TestRegisterPending:
    def test_creates_pending_marker(self, tmp_path):
        """register_pending creates {path}.pending with content '0'."""
        log = tmp_path / "app-2026-05-01-am.log"
        log.write_text("log content")

        q = _make_queue(tmp_path)
        q.register_pending(log)

        marker = Path(str(log) + ".pending")
        assert marker.exists()
        assert marker.read_text().strip() == "0"

    def test_atomic_write_no_tmp_left_over(self, tmp_path):
        """No .pending.tmp file should remain after register_pending."""
        log = tmp_path / "app-2026-05-01-am.log"
        log.write_text("x")

        q = _make_queue(tmp_path)
        q.register_pending(log)

        tmp_marker = Path(str(log) + ".pending.tmp")
        assert not tmp_marker.exists()

    def test_idempotent_does_not_reset_count(self, tmp_path):
        """Calling register_pending twice must not overwrite an existing .pending."""
        log = tmp_path / "app-2026-05-01-am.log"
        log.write_text("x")

        q = _make_queue(tmp_path)
        q.register_pending(log)

        marker = Path(str(log) + ".pending")
        marker.write_text("3")  # simulate 3 prior retries

        q.register_pending(log)  # second call
        assert marker.read_text().strip() == "3"  # must not be reset to 0

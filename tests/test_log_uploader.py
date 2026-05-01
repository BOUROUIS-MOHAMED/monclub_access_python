"""Tests for LogUploadQueue."""
from __future__ import annotations

import gzip
from pathlib import Path
from unittest.mock import MagicMock, patch

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


class TestScanOrphans:
    # Fixtures use past dates (e.g. 2026-04-30) so _active_log_name()
    # (which returns today's AM/PM filename) never matches them.
    # This avoids date-sensitive test failures without mocking the clock.
    def _write_log(self, path: Path, content: str = "log") -> None:
        path.write_text(content)

    def test_creates_pending_for_untracked_log(self, tmp_path):
        """An untracked rotated log gets a .pending marker."""
        log = tmp_path / "app-2026-04-30-pm.log"
        self._write_log(log)

        q = _make_queue(tmp_path)
        q.scan_orphans()

        assert Path(str(log) + ".pending").exists()

    def test_skips_already_pending(self, tmp_path):
        """A log with an existing .pending marker is not re-registered."""
        log = tmp_path / "app-2026-04-30-pm.log"
        self._write_log(log)
        marker = Path(str(log) + ".pending")
        marker.write_text("3")  # 3 previous retries

        q = _make_queue(tmp_path)
        q.scan_orphans()

        assert marker.read_text().strip() == "3"  # count not reset

    def test_skips_uploaded_logs(self, tmp_path):
        """A log with .uploaded marker is skipped."""
        log = tmp_path / "app-2026-04-29-am.log"
        self._write_log(log)
        Path(str(log) + ".uploaded").touch()

        q = _make_queue(tmp_path)
        q.scan_orphans()

        assert not Path(str(log) + ".pending").exists()

    def test_skips_failed_logs(self, tmp_path):
        """A log with .failed marker is skipped."""
        log = tmp_path / "app-2026-04-29-am.log"
        self._write_log(log)
        Path(str(log) + ".failed").touch()

        q = _make_queue(tmp_path)
        q.scan_orphans()

        assert not Path(str(log) + ".pending").exists()

    def test_skips_non_log_files(self, tmp_path):
        """Files that don't match the log pattern are skipped."""
        junk = tmp_path / "config.json"
        junk.write_text("{}")

        q = _make_queue(tmp_path)
        q.scan_orphans()

        assert not Path(str(junk) + ".pending").exists()


class TestHandleMarker:
    def test_removes_pending_when_log_missing(self, tmp_path):
        """If the .log file is gone, .pending is deleted and no upload is attempted."""
        log = tmp_path / "app-2026-04-28-am.log"
        marker = Path(str(log) + ".pending")
        marker.write_text("0")

        uploaded_calls = []
        q = _make_queue(tmp_path)
        q._upload = lambda name, data: uploaded_calls.append(name) or True

        q._handle_marker(marker)

        assert not marker.exists()           # .pending removed
        assert uploaded_calls == []          # upload never attempted

    def test_successful_upload_creates_uploaded_and_removes_pending(self, tmp_path):
        """Successful upload deletes .pending and creates .uploaded."""
        log = tmp_path / "app-2026-04-28-am.log"
        log.write_text("log line\n" * 100)
        marker = Path(str(log) + ".pending")
        marker.write_text("0")

        q = _make_queue(tmp_path)
        q._upload = lambda name, data: True  # mock success

        q._handle_marker(marker)

        assert not marker.exists()
        assert Path(str(log) + ".uploaded").exists()

    def test_failed_upload_increments_retry_count(self, tmp_path):
        """Failed upload increments the count stored in .pending."""
        log = tmp_path / "app-2026-04-28-am.log"
        log.write_text("data")
        marker = Path(str(log) + ".pending")
        marker.write_text("2")

        q = _make_queue(tmp_path)
        q._upload = lambda name, data: False  # mock failure

        q._handle_marker(marker)

        assert marker.exists()
        assert marker.read_text().strip() == "3"

    def test_compressed_data_is_valid_gzip(self, tmp_path):
        """Data passed to _upload is valid gzip content."""
        log = tmp_path / "app-2026-04-28-am.log"
        original = b"log line\n" * 50
        log.write_bytes(original)
        marker = Path(str(log) + ".pending")
        marker.write_text("0")

        received = []
        q = _make_queue(tmp_path)
        q._upload = lambda name, data: received.append(data) or True

        q._handle_marker(marker)

        assert len(received) == 1
        assert gzip.decompress(received[0]) == original


class TestUpload:
    def _make_token_state(self, token="tok"):
        state = MagicMock()
        state.token = token
        return state

    def test_returns_false_when_no_token(self, tmp_path):
        q = _make_queue(tmp_path, get_token=lambda: None)
        assert q._upload("app-2026-05-01-am.log", b"data") is False

    def test_returns_false_when_no_url(self, tmp_path):
        q = _make_queue(tmp_path, get_url=lambda: "")
        assert q._upload("app-2026-05-01-am.log", b"data") is False

    def test_two_step_upload_success(self, tmp_path):
        """Happy path: presign returns URL, PUT succeeds."""
        state = self._make_token_state("mytoken")
        q = _make_queue(tmp_path, get_token=lambda: state)

        presign_resp = MagicMock()
        presign_resp.status_code = 200
        presign_resp.json.return_value = {
            "url": "https://r2.example.com/put-here",
            "method": "PUT",
            "headers": {"Content-Type": "application/gzip"},
        }

        put_resp = MagicMock()
        put_resp.status_code = 200

        with patch("requests.post", return_value=presign_resp) as mock_post, \
             patch("requests.put", return_value=put_resp) as mock_put:
            result = q._upload("app-2026-05-01-am.log", b"\x1f\x8b\x08data")

        assert result is True
        mock_post.assert_called_once()
        post_args = mock_post.call_args
        assert post_args.kwargs["json"] == {"filename": "app-2026-05-01-am.log"}
        assert "Bearer mytoken" in post_args.kwargs["headers"]["Authorization"]

        mock_put.assert_called_once()
        put_args = mock_put.call_args
        assert put_args.kwargs["data"] == b"\x1f\x8b\x08data"

    def test_returns_false_on_presign_http_error(self, tmp_path):
        state = self._make_token_state()
        q = _make_queue(tmp_path, get_token=lambda: state)

        presign_resp = MagicMock()
        presign_resp.status_code = 500

        with patch("requests.post", return_value=presign_resp):
            result = q._upload("app-2026-05-01-am.log", b"data")

        assert result is False

    def test_returns_false_on_r2_put_error(self, tmp_path):
        state = self._make_token_state()
        q = _make_queue(tmp_path, get_token=lambda: state)

        presign_resp = MagicMock()
        presign_resp.status_code = 200
        presign_resp.json.return_value = {"url": "https://r2.example.com/x", "headers": {}}

        put_resp = MagicMock()
        put_resp.status_code = 403

        with patch("requests.post", return_value=presign_resp), \
             patch("requests.put", return_value=put_resp):
            result = q._upload("app-2026-05-01-am.log", b"data")

        assert result is False

    def test_returns_false_on_network_exception(self, tmp_path):
        state = self._make_token_state()
        q = _make_queue(tmp_path, get_token=lambda: state)

        with patch("requests.post", side_effect=ConnectionError("offline")):
            result = q._upload("app-2026-05-01-am.log", b"data")

        assert result is False

    def test_accepts_plain_string_token(self, tmp_path):
        """get_token may return a plain string instead of AuthTokenState."""
        q = _make_queue(tmp_path, get_token=lambda: "plain-token")

        presign_resp = MagicMock()
        presign_resp.status_code = 200
        presign_resp.json.return_value = {"url": "https://r2.example.com/x", "headers": {}}

        put_resp = MagicMock()
        put_resp.status_code = 200

        with patch("requests.post", return_value=presign_resp), \
             patch("requests.put", return_value=put_resp):
            result = q._upload("app-2026-05-01-am.log", b"data")

        assert result is True

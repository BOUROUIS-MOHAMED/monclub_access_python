"""Tests for ChangeDetectorService."""
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from app.core.change_detector import ChangeDetectorService

_V1 = "2026-04-02T10:00:00"
_V2 = "2026-04-02T11:00:00"
_DT1 = datetime.fromisoformat(_V1)
_DT2 = datetime.fromisoformat(_V2)


@pytest.fixture
def mock_app():
    app = MagicMock()
    app.after = MagicMock()
    return app


@pytest.fixture
def mock_logger():
    return MagicMock()


def make_service(mock_app, mock_logger, backend_base_url="http://test.local"):
    return ChangeDetectorService(
        app=mock_app,
        backend_base_url=backend_base_url,
        get_token_fn=lambda: "test-jwt-token",
        re_login_fn=lambda: "new-jwt-token",
        gym_id=42,
        poll_interval=0.05,  # fast for tests
        cfg=MagicMock(),
        logger=mock_logger,
    )


class TestChangeDetectorInitialPoll:
    def test_first_poll_sets_baseline_without_triggering_sync(self, mock_app, mock_logger):
        """On first successful poll, stores version as datetime but does NOT trigger sync."""
        svc = make_service(mock_app, mock_logger)

        with patch("app.core.change_detector._requests") as mock_requests:
            mock_requests.RequestException = Exception
            mock_requests.get.return_value = MagicMock(
                status_code=200,
                json=lambda: {"gymId": 42, "lastModifiedAt": _V1},
            )
            svc._poll_once()

        mock_app.after.assert_not_called()
        assert svc._last_known_version == _DT1  # stored as datetime, not string


class TestChangeDetectorSubsequentPolls:
    def test_unchanged_version_does_not_trigger_sync(self, mock_app, mock_logger):
        svc = make_service(mock_app, mock_logger)
        svc._last_known_version = _DT1  # seed as datetime

        with patch("app.core.change_detector._requests") as mock_requests:
            mock_requests.RequestException = Exception
            mock_requests.get.return_value = MagicMock(
                status_code=200,
                json=lambda: {"gymId": 42, "lastModifiedAt": _V1},
            )
            svc._poll_once()

        mock_app.after.assert_not_called()

    def test_newer_version_triggers_sync(self, mock_app, mock_logger):
        svc = make_service(mock_app, mock_logger)
        svc._last_known_version = _DT1  # seed as datetime

        with patch("app.core.change_detector._requests") as mock_requests:
            mock_requests.RequestException = Exception
            mock_requests.get.return_value = MagicMock(
                status_code=200,
                json=lambda: {"gymId": 42, "lastModifiedAt": _V2},
            )
            svc._poll_once()

        mock_app.after.assert_called_once_with(0, mock_app.request_sync_now)
        assert svc._last_known_version == _DT2  # updated to newer datetime


class TestChangeDetectorAuth:
    def test_401_triggers_relogin_and_retry(self, mock_app, mock_logger):
        svc = make_service(mock_app, mock_logger)
        svc._last_known_version = _DT1  # seed as datetime

        responses = [
            MagicMock(status_code=401),
            MagicMock(
                status_code=200,
                json=lambda: {"gymId": 42, "lastModifiedAt": _V2},
            ),
        ]

        with patch("app.core.change_detector._requests") as mock_requests:
            mock_requests.RequestException = Exception
            mock_requests.get.side_effect = responses
            svc._poll_once()

        # Should have triggered sync after re-login
        mock_app.after.assert_called_once()

    def test_network_error_logs_warning_and_does_not_crash(self, mock_app, mock_logger):
        svc = make_service(mock_app, mock_logger)

        with patch("app.core.change_detector._requests") as mock_requests:
            mock_requests.RequestException = Exception
            mock_requests.get.side_effect = Exception("timeout")
            svc._poll_once()  # must not raise

        mock_logger.warning.assert_called()
        mock_app.after.assert_not_called()

from __future__ import annotations

import unittest

from app.api.monclub_api import ApiEndpoints, MonClubApi, MonClubApiHttpError
from app.core.app_const import API_LOGIN_URL
from tv.config import build_tv_api_endpoints


class _DummyLogger:
    def info(self, *args, **kwargs) -> None:
        pass

    def warning(self, *args, **kwargs) -> None:
        pass


class _DummyResponse:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text


class _DummySession:
    def __init__(self, response: _DummyResponse) -> None:
        self._response = response

    def post(self, *args, **kwargs) -> _DummyResponse:
        return self._response


class AuthReconnectTests(unittest.TestCase):
    def test_tv_api_endpoints_include_login_url(self) -> None:
        endpoints = build_tv_api_endpoints()
        self.assertEqual(endpoints.login_url, API_LOGIN_URL)

    def test_login_invalid_credentials_returns_friendly_message(self) -> None:
        api = MonClubApi(
            endpoints=ApiEndpoints(
                login_url="https://example.test/login",
                sync_url="",
                create_user_fingerprint_url="",
                latest_release_url="",
            ),
            logger=_DummyLogger(),
        )
        api._session = _DummySession(
            _DummyResponse(
                401,
                '{"status":false,"errorMsg":"Invalid email or password","code":"UNAUTHORIZED","details":{"path":"/api/v1/public/access/v1/gym/login"}}',
            )
        )

        with self.assertRaises(MonClubApiHttpError) as exc:
            api.login(email="user@example.com", password="wrong-password")

        self.assertEqual(exc.exception.status_code, 401)
        self.assertEqual(str(exc.exception), "Email ou mot de passe incorrect.")


if __name__ == "__main__":
    unittest.main()

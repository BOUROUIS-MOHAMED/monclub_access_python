from __future__ import annotations

import random
import string
from dataclasses import dataclass
from typing import Any, Dict

import requests


@dataclass
class ApiEndpoints:
    login_url: str
    sync_url: str
    create_user_fingerprint_url: str


class MonClubApiError(RuntimeError):
    pass


def _rand_alnum(n: int = 8) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


class MonClubApi:
    def __init__(self, endpoints: ApiEndpoints, logger):
        self.endpoints = endpoints
        self.logger = logger
        self._session = requests.Session()

    def login(self, *, email: str, password: str, timeout: int = 15) -> str:
        url = (self.endpoints.login_url or "").strip()
        if not url:
            raise MonClubApiError("Login URL is empty (check Configuration).")

        payload = {"email": email, "password": password}

        self.logger.info("API login -> %s", url)
        try:
            r = self._session.post(url, json=payload, timeout=timeout)
        except Exception as e:
            raise MonClubApiError(f"Login request failed: {e}") from e

        if r.status_code < 200 or r.status_code >= 300:
            txt = (r.text or "").strip()
            raise MonClubApiError(f"Login failed: HTTP {r.status_code} -> {txt[:300]}")

        token = (r.text or "").strip()
        if not token:
            raise MonClubApiError("Login response is empty (no token returned).")

        return token

    def get_sync_data(self, *, token: str, timeout: int = 20) -> Dict[str, Any]:
        url = (self.endpoints.sync_url or "").strip()
        if not url:
            raise MonClubApiError("Sync URL is empty (check Configuration).")

        params = {"lastCheckTimeStamp": _rand_alnum(8)}
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

        self.logger.info("API getSyncData -> %s (gymId removed)", url)
        try:
            r = self._session.get(url, params=params, headers=headers, timeout=timeout)
        except Exception as e:
            raise MonClubApiError(f"getSyncData request failed: {e}") from e

        if r.status_code < 200 or r.status_code >= 300:
            txt = (r.text or "").strip()
            raise MonClubApiError(f"getSyncData failed: HTTP {r.status_code} -> {txt[:400]}")

        try:
            data = r.json()
        except Exception as e:
            raise MonClubApiError(f"getSyncData returned non-JSON response: {e} -> {(r.text or '')[:300]}") from e

        if not isinstance(data, dict):
            raise MonClubApiError("getSyncData JSON is not an object/dict.")

        return data

    def create_user_fingerprint(self, *, token: str, payload: Dict[str, Any], timeout: int = 25) -> Dict[str, Any]:
        url = (self.endpoints.create_user_fingerprint_url or "").strip()
        if not url:
            raise MonClubApiError("Create fingerprint URL is empty (check Configuration).")

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

        self.logger.info("API createUserFingerprint -> %s", url)
        try:
            r = self._session.post(url, json=payload, headers=headers, timeout=timeout)
        except Exception as e:
            raise MonClubApiError(f"createUserFingerprint request failed: {e}") from e

        if r.status_code < 200 or r.status_code >= 300:
            txt = (r.text or "").strip()
            raise MonClubApiError(f"createUserFingerprint failed: HTTP {r.status_code} -> {txt[:500]}")

        try:
            data = r.json()
        except Exception:
            # backend may return plain text sometimes
            data = {"raw": (r.text or "").strip()}

        if not isinstance(data, dict):
            return {"raw": data}
        return data

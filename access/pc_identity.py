"""Per-installation identity and heartbeat support for MonClub Access."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import socket
import threading
import time
from typing import Any, Callable, Mapping
import uuid

import requests

from app.core.secure_store import SecureStoreError, protect_bytes, unprotect_bytes


_log = logging.getLogger(__name__)
DEFAULT_REQUEST_TIMEOUT_SECONDS = 10
TOKEN_REFRESH_LEAD_SECONDS = 60 * 60


@dataclass(frozen=True)
class PcCredentials:
    pc_uuid: str
    pc_secret: str


class PcCredentialStore:
    """Store one PC credential pair as a single DPAPI-protected file."""

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        protect: Callable[[bytes], bytes] = protect_bytes,
        unprotect: Callable[[bytes], bytes] = unprotect_bytes,
    ) -> None:
        if path is None:
            from access.storage import get_access_storage_paths

            path = get_access_storage_paths().data_dir / "pc_identity.dat"
        self.path = Path(path)
        self._protect = protect
        self._unprotect = unprotect

    def load(self) -> PcCredentials | None:
        if not self.path.is_file():
            return None
        try:
            protected = self.path.read_bytes()
            plain = self._unprotect(protected)
            payload = json.loads(plain.decode("utf-8"))
            pc_uuid = str(payload.get("pcUuid") or "").strip()
            pc_secret = str(payload.get("pcSecret") or "").strip()
            if not pc_uuid or not pc_secret:
                return None
            return PcCredentials(pc_uuid=pc_uuid, pc_secret=pc_secret)
        except Exception as exc:
            _log.warning("PC credential store is unreadable; returning first-run state: %s", exc)
            return None

    def save(self, credentials: PcCredentials) -> None:
        if not credentials.pc_uuid.strip() or not credentials.pc_secret.strip():
            raise ValueError("Both pcUuid and pcSecret are required")

        plain = json.dumps(
            {"pcUuid": credentials.pc_uuid, "pcSecret": credentials.pc_secret},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        protected = self._protect(plain)
        if not protected or protected == plain:
            raise SecureStoreError("DPAPI did not produce a protected credential blob")

        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self.path.with_name(f"{self.path.name}.tmp")
        try:
            temporary_path.write_bytes(protected)
            os.replace(temporary_path, self.path)
        finally:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


class PcIdentityApiError(RuntimeError):
    def __init__(
        self,
        *,
        status_code: int,
        code: str,
        message: str,
        details: Mapping[str, Any] | None = None,
        retry_after_seconds: int | None = None,
    ) -> None:
        super().__init__(message or code or f"HTTP {status_code}")
        self.status_code = int(status_code)
        self.code = str(code or "")
        self.details = dict(details or {})
        self.retry_after_seconds = retry_after_seconds


def _error_fields(payload: Any) -> tuple[str, str, dict[str, Any]]:
    if not isinstance(payload, dict):
        return "", str(payload or ""), {}
    nested_error = payload.get("error")
    nested = nested_error if isinstance(nested_error, dict) else {}
    code = str(
        payload.get("code")
        or payload.get("errorCode")
        or nested.get("code")
        or nested.get("errorCode")
        or ""
    ).strip()
    message_value = payload.get("message") or nested.get("message")
    if not message_value and isinstance(nested_error, str):
        message_value = nested_error
    message = str(message_value or code or "Backend request failed")
    details_value = payload.get("details") or nested.get("details")
    details = dict(details_value) if isinstance(details_value, dict) else {}
    return code, message, details


def _retry_after_seconds(headers: Mapping[str, Any]) -> int | None:
    value = str(headers.get("Retry-After") or "").strip()
    if not value:
        return None
    try:
        return max(0, int(float(value)))
    except (TypeError, ValueError):
        return None


class PcIdentityApiClient:
    def __init__(
        self,
        *,
        base_url: str,
        session: Any | None = None,
        timeout_seconds: int = DEFAULT_REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        self._base_url = str(base_url).rstrip("/")
        self._session = session or requests.Session()
        self._timeout_seconds = max(1, int(timeout_seconds))

    def _request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        kwargs: dict[str, Any] = {"headers": headers, "timeout": self._timeout_seconds}
        if payload is not None:
            kwargs["json"] = dict(payload)
        response = self._session.request(method, f"{self._base_url}/api/v1{path}", **kwargs)
        try:
            body = response.json()
        except Exception:
            body = {}
        if not (200 <= int(response.status_code) < 300):
            code, message, details = _error_fields(body)
            raise PcIdentityApiError(
                status_code=int(response.status_code),
                code=code,
                message=message,
                details=details,
                retry_after_seconds=_retry_after_seconds(response.headers),
            )
        if not isinstance(body, dict):
            raise PcIdentityApiError(
                status_code=int(response.status_code),
                code="ACCESS_PC_INVALID_RESPONSE",
                message="Backend returned an invalid PC identity response",
            )
        return body

    def list_pcs(self, *, gym_token: str) -> dict[str, Any]:
        return self._request("GET", "/manager/gym/access/v1/pcs", token=gym_token)

    def register_pc(
        self,
        *,
        gym_token: str,
        name: str,
        mac: str | None = None,
        hostname: str | None = None,
        app_version: str | None = None,
    ) -> dict[str, Any]:
        payload = {"name": name}
        optional = {"mac": mac, "hostname": hostname, "appVersion": app_version}
        payload.update({key: value for key, value in optional.items() if value})
        return self._request(
            "POST",
            "/manager/gym/access/v1/pcs/register",
            token=gym_token,
            payload=payload,
        )

    def adopt_pc(self, *, gym_token: str, pc_id: int) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/manager/gym/access/v1/pcs/{int(pc_id)}/adopt",
            token=gym_token,
            payload={},
        )

    def revoke_pc(self, *, gym_token: str, pc_id: int) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/manager/gym/access/v1/pcs/{int(pc_id)}/revoke",
            token=gym_token,
            payload={},
        )

    def mint_token(self, credentials: PcCredentials) -> dict[str, Any]:
        return self._request(
            "POST",
            "/public/access/v1/pc/token",
            payload={"pcUuid": credentials.pc_uuid, "pcSecret": credentials.pc_secret},
        )

    def send_heartbeat(self, *, pc_token: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        return self._request(
            "POST",
            "/public/access/v1/pc/heartbeat",
            token=pc_token,
            payload=payload,
        )


def _default_hostname() -> str:
    try:
        return socket.gethostname().strip()
    except Exception:
        return ""


def _default_mac() -> str:
    try:
        value = uuid.getnode()
        return ":".join(f"{value:012X}"[index : index + 2] for index in range(0, 12, 2))
    except Exception:
        return ""


def _iso_utc(epoch_seconds: float | None) -> str | None:
    if epoch_seconds is None:
        return None
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat().replace("+00:00", "Z")


class PcIdentityService:
    def __init__(
        self,
        *,
        credential_store: Any,
        api_client: Any,
        gym_token_provider: Callable[[], Any],
        app_version_provider: Callable[[], str] = lambda: "",
        hostname_provider: Callable[[], str] = _default_hostname,
        mac_provider: Callable[[], str] = _default_mac,
        heartbeat_payload_provider: Callable[[], Mapping[str, Any]] = lambda: {},
        clock: Callable[[], float] = time.time,
        logger: logging.Logger = _log,
    ) -> None:
        self._store = credential_store
        self._api = api_client
        self._gym_token_provider = gym_token_provider
        self._app_version_provider = app_version_provider
        self._hostname_provider = hostname_provider
        self._mac_provider = mac_provider
        self._heartbeat_payload_provider = heartbeat_payload_provider
        self._clock = clock
        self._logger = logger
        self._lock = threading.RLock()
        self._credentials: PcCredentials | None = self._store.load()
        self._pc_token: str | None = None
        self._token_expires_at: float | None = None
        self._state = "active" if self._credentials else "first_run"
        self._last_heartbeat_at: float | None = None
        self._last_error: str | None = None

    def _gym_token(self) -> str:
        value = self._gym_token_provider()
        token = str(getattr(value, "token", value) or "").strip()
        if not token:
            raise PcIdentityApiError(
                status_code=401,
                code="ACCESS_PC_GYM_AUTH_REQUIRED",
                message="Gym authentication is required",
            )
        return token

    @staticmethod
    def _credentials_from_response(payload: Mapping[str, Any]) -> PcCredentials:
        credentials = PcCredentials(
            pc_uuid=str(payload.get("pcUuid") or "").strip(),
            pc_secret=str(payload.get("pcSecret") or "").strip(),
        )
        if not credentials.pc_uuid or not credentials.pc_secret:
            raise PcIdentityApiError(
                status_code=502,
                code="ACCESS_PC_INVALID_RESPONSE",
                message="Backend omitted PC credentials",
            )
        return credentials

    def list_pcs(self) -> dict[str, Any]:
        return self._api.list_pcs(gym_token=self._gym_token())

    def register(self, *, name: str) -> dict[str, Any]:
        normalized_name = str(name or "").strip()
        if not normalized_name:
            raise ValueError("PC name is required")
        payload = self._api.register_pc(
            gym_token=self._gym_token(),
            name=normalized_name,
            mac=self._mac_provider() or None,
            hostname=self._hostname_provider() or None,
            app_version=self._app_version_provider() or None,
        )
        return self._accept_credentials(payload)

    def adopt(self, *, pc_id: int) -> dict[str, Any]:
        payload = self._api.adopt_pc(gym_token=self._gym_token(), pc_id=int(pc_id))
        return self._accept_credentials(payload)

    def _accept_credentials(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        credentials = self._credentials_from_response(payload)
        self._store.save(credentials)
        with self._lock:
            self._credentials = credentials
            self._pc_token = None
            self._token_expires_at = None
            self._state = "active"
            self._last_error = None
        try:
            self.ensure_token()
        except Exception as exc:
            self._logger.warning("PC registered but first token mint failed: %s", exc)
        result = dict(payload)
        result["tokenReady"] = bool(self._pc_token)
        return result

    def ensure_token(self) -> str | None:
        with self._lock:
            if self._state in {"revoked", "invalid_credentials", "invalid_token"}:
                return None
            credentials = self._credentials
            if credentials is None:
                self._state = "first_run"
                return None
            now = self._clock()
            if (
                self._pc_token
                and self._token_expires_at is not None
                and now < self._token_expires_at - TOKEN_REFRESH_LEAD_SECONDS
            ):
                return self._pc_token
            try:
                response = self._api.mint_token(credentials)
                token = str(response.get("token") or "").strip()
                expires_in = int(response.get("expiresInSeconds") or 0)
                if not token or expires_in <= 0:
                    raise PcIdentityApiError(
                        status_code=502,
                        code="ACCESS_PC_INVALID_RESPONSE",
                        message="Backend returned an invalid PC token",
                    )
                self._pc_token = token
                self._token_expires_at = now + expires_in
                self._state = "active"
                self._last_error = None
                return token
            except PcIdentityApiError as exc:
                if exc.code == "ACCESS_PC_REVOKED":
                    self._state = "revoked"
                elif exc.code == "ACCESS_PC_INVALID_CREDENTIALS":
                    self._state = "invalid_credentials"
                self._last_error = str(exc)
                raise

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "registered": self._credentials is not None,
                "state": self._state,
                "pcUuid": self._credentials.pc_uuid if self._credentials else None,
                "tokenReady": bool(self._pc_token),
                "tokenExpiresAt": _iso_utc(self._token_expires_at),
                "lastHeartbeatAt": _iso_utc(self._last_heartbeat_at),
                "lastError": self._last_error,
            }


__all__ = [
    "DEFAULT_REQUEST_TIMEOUT_SECONDS",
    "PcCredentialStore",
    "PcCredentials",
    "PcIdentityApiClient",
    "PcIdentityApiError",
    "PcIdentityService",
    "SecureStoreError",
    "TOKEN_REFRESH_LEAD_SECONDS",
]

"""HTTP client for the v2 PC routes (backend main c7d4b532, ``/api/v1/public/access/v2/pc/**``).

* Auth: ``Authorization: Bearer <PC token>`` (the token of ``/public/access/v1/pc/token``).
* Success: the raw DTO (no envelope). Failure: ``{status:false, errorMsg, code, details}``.
* **The server switched v2 off** only when a 404 carries that envelope with ``code ==
  "NOT_FOUND"`` (the unmapped-route answer every v2 route gives while
  ``monclub.access.v2.commands.enabled`` is false). A proxy's HTML 404, a 5xx, a TLS or network
  error are "unreachable": the caller keeps what it knew. Reading one of those as "off" would
  turn a reader into a driver of every turnstile.
* 429: every call backs off for ``Retry-After`` (default 60 s) — the ``access-pc`` bucket is
  keyed on the remote address, which the backend's own config comment says is the TLS
  terminator, i.e. possibly one budget for the whole fleet [COMMENT only].
* ``sentAt`` (P2c-2 writes) is stamped from the corrected server clock at EACH attempt, never
  stored with a queued body; a 409 ``CLOCK_SKEW`` is a clock sample and the write is sent once
  more.
* Every ``serverTime`` in an answer is a clock sample when the gym's UTC offset is known (REST
  times are Tunis local, without an offset).
"""
from __future__ import annotations

import time
from typing import Any, Callable, Dict, Optional

import requests

from app.core.v2 import timefmt
from app.core.v2.server_clock import ServerClock

API_PREFIX = "/api/v1/public/access/v2/pc"
DEFAULT_TIMEOUT_SEC = 10.0
DEFAULT_RATE_LIMIT_BACKOFF_SEC = 60.0


class V2ApiError(Exception):
    def __init__(self, status: int, code: str, message: str = "", *, details: Any = None,
                 retry_after: Optional[float] = None, backend: bool = False) -> None:
        super().__init__(f"{status} {code}: {message}".strip())
        self.status = int(status)
        self.code = str(code or "")
        self.message = str(message or "")
        self.details = details if isinstance(details, dict) else {}
        self.retry_after = retry_after
        self.backend = bool(backend)

    @property
    def switched_off(self) -> bool:
        return self.status == 404 and self.backend and self.code == "NOT_FOUND"

    @property
    def unreachable(self) -> bool:
        return not self.backend and self.code in ("UNREACHABLE", "BAD_RESPONSE")


def _retry_after(headers) -> Optional[float]:
    try:
        raw = str((headers or {}).get("Retry-After") or "").strip()
    except Exception:
        return None
    if raw.isascii() and raw.isdigit() and len(raw) < 9:
        return float(int(raw))
    return None


def _certifi_bundle() -> Any:
    try:
        import certifi
        return certifi.where()
    except Exception:
        return True


class V2Api:
    def __init__(
        self,
        *,
        base_url: str,
        token_provider: Callable[[], Optional[str]],
        session: Any = None,
        clock: Optional[ServerClock] = None,
        app_version: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SEC,
    ) -> None:
        self._base = str(base_url).rstrip("/") + API_PREFIX
        self._token_provider = token_provider
        self._session = session if session is not None else requests.Session()
        self.clock = clock if clock is not None else ServerClock()
        self._app_version = str(app_version or "")
        self._timeout = float(timeout)
        self._backoff_until = 0.0
        # The same wall clock the ServerClock reads, so a sample and ``now()`` agree.
        self._wall = getattr(self.clock, "_wall", time.time)
        self._mono = time.monotonic
        self._verify = _certifi_bundle()

    # ------------------------------------------------------------------ core
    def _headers(self, token: str, with_body: bool) -> Dict[str, str]:
        h = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
        if with_body:
            h["Content-Type"] = "application/json"
        if self._app_version:
            h["X-MonClub-Access-Version"] = self._app_version[:64]
        return h

    def _request(self, method: str, path: str, *, params: Optional[Dict[str, Any]] = None,
                 body: Optional[Dict[str, Any]] = None, stamp_sent_at: bool = False,
                 timeout: Optional[float] = None) -> Dict[str, Any]:
        attempts = 2 if stamp_sent_at else 1
        for attempt in range(attempts):
            try:
                return self._send(method, path, params=params, body=body,
                                  stamp_sent_at=stamp_sent_at, timeout=timeout)
            except V2ApiError as exc:
                if stamp_sent_at and exc.code == "CLOCK_SKEW" and attempt + 1 < attempts:
                    continue    # _send already took the refusal's serverTime as a sample
                raise
        raise AssertionError("unreachable")

    def _send(self, method, path, *, params, body, stamp_sent_at, timeout) -> Dict[str, Any]:
        if self._mono() < self._backoff_until:
            raise V2ApiError(429, "LOCAL_BACKOFF", "rate limited: waiting for Retry-After")
        try:
            token = self._token_provider()
        except Exception as exc:
            raise V2ApiError(0, "NO_PC_TOKEN", str(exc))
        if not token:
            raise V2ApiError(0, "NO_PC_TOKEN", "no PC token (PC not registered or revoked)")
        payload = None
        if body is not None:
            payload = dict(body)
            if stamp_sent_at:
                payload["sentAt"] = timefmt.format_utc(self.clock.now())
        kw: Dict[str, Any] = {"headers": self._headers(token, payload is not None),
                              "timeout": float(timeout or self._timeout), "verify": self._verify}
        if params:
            kw["params"] = {k: v for k, v in params.items() if v is not None}
        if payload is not None:
            kw["json"] = payload
        sent = self._wall()
        try:
            resp = self._session.request(method, self._base + path, **kw)
        except Exception as exc:
            raise V2ApiError(0, "UNREACHABLE", f"{type(exc).__name__}: {exc}")
        recv = self._wall()
        status = int(getattr(resp, "status_code", 0) or 0)
        try:
            data = resp.json()
        except Exception:
            data = None
        if 200 <= status < 300:
            if not isinstance(data, dict):
                raise V2ApiError(status, "BAD_RESPONSE", "not a JSON object")
            self._sample(data.get("serverTime"), sent, recv, source=f"rest:{path.split('/')[1]}")
            return data
        backend = isinstance(data, dict) and data.get("status") is False and bool(data.get("code"))
        code = str(data.get("code")) if backend else ("UNREACHABLE" if status >= 500 or status == 404 else f"HTTP_{status}")
        message = str(data.get("errorMsg") or "") if backend else f"HTTP {status}"
        details = data.get("details") if backend else None
        err = V2ApiError(status, code, message, details=details,
                         retry_after=_retry_after(getattr(resp, "headers", None)), backend=backend)
        if status == 429:
            wait = err.retry_after if err.retry_after is not None else DEFAULT_RATE_LIMIT_BACKOFF_SEC
            self._backoff_until = self._mono() + max(1.0, float(wait))
        if backend and code == "CLOCK_SKEW":
            self._sample((details or {}).get("serverTime"), sent, recv, source="clock_skew")
        raise err

    def _sample(self, server_time, sent, recv, *, source: str) -> None:
        if not isinstance(server_time, str):
            return
        epoch = timefmt.to_epoch(server_time, default_offset_sec=self.clock.utc_offset)
        if epoch is not None:
            self.clock.add_sample(epoch, sent, recv, source=source)

    # ------------------------------------------------------------------ commands (P2b)
    def pending(self) -> Dict[str, Any]:
        return self._request("GET", "/commands/pending")

    def claim(self, command_id: str, claim_token: str) -> Dict[str, Any]:
        return self._request("POST", f"/commands/{command_id}/claim", body={"claimToken": claim_token})

    def progress(self, command_id: str, claim_token: str, progress: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("POST", f"/commands/{command_id}/progress",
                             body={"claimToken": claim_token, "progress": progress})

    def result(self, command_id: str, claim_token: str, outcome: str, code: Optional[str],
               detail: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        return self._request("POST", f"/commands/{command_id}/result",
                             body={"claimToken": claim_token, "outcome": outcome, "code": code,
                                   "detail": detail})

    def request_command(self, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("POST", "/commands", body=body)

    # ------------------------------------------------------------------ assignment (P2c-1)
    def assignment(self) -> Dict[str, Any]:
        return self._request("GET", "/assignment")

    def release(self, gym_device_id: int, generation: int) -> Dict[str, Any]:
        return self._request("POST", "/assignment/release",
                             body={"gymDeviceId": int(gym_device_id), "generation": int(generation)})

    def read_back(self, gym_device_id: int, generation: int) -> Dict[str, Any]:
        return self._request("POST", "/assignment/read-back",
                             body={"gymDeviceId": int(gym_device_id), "generation": int(generation)})

    def reader_door_history(self, before_id: Optional[int] = None, limit: int = 50) -> Dict[str, Any]:
        return self._request("GET", "/reader/door-history", params={"beforeId": before_id, "limit": int(limit)})

    # ------------------------------------------------------------------ ownership (P2c-2)
    def ownership_page(self, gym_device_id: int, after_id: int = 0, limit: int = 500) -> Dict[str, Any]:
        return self._request("GET", "/ownership", params={"gymDeviceId": int(gym_device_id),
                                                          "afterId": int(after_id), "limit": int(limit)})

    def ownership_upload(self, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("POST", "/ownership/upload", body=body, stamp_sent_at=True)

    def ownership_wiped(self, gym_device_id: int, generation: int, wiped_at_epoch: float) -> Dict[str, Any]:
        return self._request("POST", "/ownership/wiped", stamp_sent_at=True,
                             body={"gymDeviceId": int(gym_device_id), "generation": int(generation),
                                   "wipedAt": timefmt.format_utc(wiped_at_epoch)})

    def turnstile_problems(self, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("POST", "/turnstile-problems", body=body, stamp_sent_at=True)

from __future__ import annotations

import importlib
from pathlib import Path
import sys
from types import SimpleNamespace
import threading

import pytest


def _identity_module():
    return importlib.import_module("access.pc_identity")


def test_secure_store_refuses_plaintext_when_dpapi_is_unavailable(monkeypatch) -> None:
    from app.core import secure_store

    monkeypatch.setattr(secure_store, "_IS_WIN", False)

    with pytest.raises(Exception):
        secure_store.protect_bytes(b"pc-secret")


def test_credentials_round_trip_as_one_protected_blob(tmp_path: Path) -> None:
    identity = _identity_module()
    destination = tmp_path / "pc_identity.dat"
    store = identity.PcCredentialStore(
        destination,
        protect=lambda value: b"sealed:" + value[::-1],
        unprotect=lambda value: value.removeprefix(b"sealed:")[::-1],
    )
    credentials = identity.PcCredentials(pc_uuid="uuid-a", pc_secret="secret-a")

    store.save(credentials)

    assert store.load() == credentials
    stored_bytes = destination.read_bytes()
    assert b"uuid-a" not in stored_bytes
    assert b"secret-a" not in stored_bytes


def test_replacing_credentials_overwrites_the_complete_pair(tmp_path: Path) -> None:
    identity = _identity_module()
    store = identity.PcCredentialStore(
        tmp_path / "pc_identity.dat",
        protect=lambda value: value[::-1],
        unprotect=lambda value: value[::-1],
    )
    store.save(identity.PcCredentials(pc_uuid="old-uuid", pc_secret="old-secret"))

    replacement = identity.PcCredentials(pc_uuid="new-uuid", pc_secret="new-secret")
    store.save(replacement)

    assert store.load() == replacement


@pytest.mark.parametrize("contents", [None, b"not-a-protected-document"])
def test_missing_or_unreadable_credentials_return_first_run_state(
    tmp_path: Path,
    contents: bytes | None,
) -> None:
    identity = _identity_module()
    destination = tmp_path / "pc_identity.dat"
    if contents is not None:
        destination.write_bytes(contents)
    store = identity.PcCredentialStore(
        destination,
        protect=lambda value: value,
        unprotect=lambda _value: (_ for _ in ()).throw(identity.SecureStoreError("unreadable")),
    )

    assert store.load() is None


def test_failed_protection_never_writes_a_plaintext_secret(tmp_path: Path) -> None:
    identity = _identity_module()
    destination = tmp_path / "pc_identity.dat"
    store = identity.PcCredentialStore(
        destination,
        protect=lambda _value: (_ for _ in ()).throw(identity.SecureStoreError("failed")),
        unprotect=lambda value: value,
    )

    with pytest.raises(identity.SecureStoreError):
        store.save(identity.PcCredentials(pc_uuid="uuid-a", pc_secret="secret-a"))

    assert not destination.exists()


class _FakeResponse:
    def __init__(self, status_code: int, payload, *, headers=None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        self.text = "" if payload is None else str(payload)

    def json(self):
        return self._payload


class _RecordingSession:
    def __init__(self, responses) -> None:
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


def test_api_client_uses_the_pc_contract_urls_and_credentials() -> None:
    identity = _identity_module()
    session = _RecordingSession(
        [
            _FakeResponse(200, {"pcs": []}),
            _FakeResponse(201, {"id": 1, "pcUuid": "uuid-a", "pcSecret": "secret-a"}),
            _FakeResponse(200, {"id": 2, "pcUuid": "uuid-b", "pcSecret": "secret-b"}),
            _FakeResponse(200, {"token": "pc-token", "expiresInSeconds": 86400}),
        ]
    )
    client = identity.PcIdentityApiClient(base_url="https://backend.example", session=session)

    client.list_pcs(gym_token="gym-token")
    client.register_pc(
        gym_token="gym-token",
        name="Accueil",
        mac="AA:BB",
        hostname="RECEPTION-1",
        app_version="1.4.32",
    )
    client.adopt_pc(gym_token="gym-token", pc_id=2)
    client.mint_token(identity.PcCredentials(pc_uuid="uuid-b", pc_secret="secret-b"))

    assert [call[0:2] for call in session.calls] == [
        ("GET", "https://backend.example/api/v1/manager/gym/access/v1/pcs"),
        ("POST", "https://backend.example/api/v1/manager/gym/access/v1/pcs/register"),
        ("POST", "https://backend.example/api/v1/manager/gym/access/v1/pcs/2/adopt"),
        ("POST", "https://backend.example/api/v1/public/access/v1/pc/token"),
    ]
    assert session.calls[0][2]["headers"]["Authorization"] == "Bearer gym-token"
    assert session.calls[1][2]["json"] == {
        "name": "Accueil",
        "mac": "AA:BB",
        "hostname": "RECEPTION-1",
        "appVersion": "1.4.32",
    }
    assert session.calls[3][2]["json"] == {"pcUuid": "uuid-b", "pcSecret": "secret-b"}
    assert "Authorization" not in session.calls[3][2]["headers"]
    assert all(call[2]["timeout"] == 10 for call in session.calls)


def test_api_client_preserves_cap_reached_details() -> None:
    identity = _identity_module()
    session = _RecordingSession(
        [
            _FakeResponse(
                409,
                {
                    "code": "ACCESS_PC_CAP_REACHED",
                    "message": "cap reached",
                    "details": {"cap": 2, "activeCount": 2},
                },
            )
        ]
    )
    client = identity.PcIdentityApiClient(base_url="https://backend.example", session=session)

    with pytest.raises(identity.PcIdentityApiError) as caught:
        client.register_pc(gym_token="gym-token", name="Accueil")

    assert caught.value.status_code == 409
    assert caught.value.code == "ACCESS_PC_CAP_REACHED"
    assert caught.value.details == {"cap": 2, "activeCount": 2}


class _MemoryStore:
    def __init__(self, credentials=None) -> None:
        self.credentials = credentials
        self.saved = []

    def load(self):
        return self.credentials

    def save(self, credentials) -> None:
        self.credentials = credentials
        self.saved.append(credentials)


class _ServiceApi:
    def __init__(self) -> None:
        self.registered = {
            "id": 11,
            "pcUuid": "registered-uuid",
            "pcSecret": "registered-secret",
            "name": "Accueil",
            "status": "ACTIVE",
        }
        self.adopted = {
            "id": 22,
            "pcUuid": "adopted-uuid",
            "pcSecret": "adopted-secret",
            "name": "Réception",
            "status": "ACTIVE",
        }
        self.minted = []

    def register_pc(self, **_kwargs):
        return self.registered

    def adopt_pc(self, **_kwargs):
        return self.adopted

    def mint_token(self, credentials):
        self.minted.append(credentials)
        return {"token": f"token-{len(self.minted)}", "expiresInSeconds": 86400}


def test_registration_stores_credentials_and_mints_first_token() -> None:
    identity = _identity_module()
    store = _MemoryStore()
    api = _ServiceApi()
    service = identity.PcIdentityService(
        credential_store=store,
        api_client=api,
        gym_token_provider=lambda: "gym-token",
        app_version_provider=lambda: "1.4.32",
        hostname_provider=lambda: "RECEPTION-1",
        mac_provider=lambda: "AA:BB",
    )

    result = service.register(name="Accueil")

    expected = identity.PcCredentials("registered-uuid", "registered-secret")
    assert store.saved == [expected]
    assert api.minted == [expected]
    assert result["tokenReady"] is True
    assert service.status()["state"] == "active"


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows DPAPI integration")
def test_registration_round_trips_through_the_real_secure_store(tmp_path: Path) -> None:
    identity = _identity_module()
    destination = tmp_path / "pc_identity.dat"
    api = _ServiceApi()
    service = identity.PcIdentityService(
        credential_store=identity.PcCredentialStore(destination),
        api_client=api,
        gym_token_provider=lambda: "gym-token",
    )

    service.register(name="Accueil")

    assert identity.PcCredentialStore(destination).load() == identity.PcCredentials(
        "registered-uuid",
        "registered-secret",
    )
    assert b"registered-secret" not in destination.read_bytes()


def test_takeover_replaces_stored_credentials_and_mints_for_the_new_pair() -> None:
    identity = _identity_module()
    old = identity.PcCredentials("old-uuid", "old-secret")
    store = _MemoryStore(old)
    api = _ServiceApi()
    service = identity.PcIdentityService(
        credential_store=store,
        api_client=api,
        gym_token_provider=lambda: "gym-token",
    )

    result = service.adopt(pc_id=22)

    replacement = identity.PcCredentials("adopted-uuid", "adopted-secret")
    assert store.saved == [replacement]
    assert store.credentials == replacement
    assert api.minted == [replacement]
    assert result["pcUuid"] == "adopted-uuid"


def test_token_is_refreshed_one_hour_before_expiry() -> None:
    identity = _identity_module()
    now = [1_000.0]
    credentials = identity.PcCredentials("uuid-a", "secret-a")
    store = _MemoryStore(credentials)
    api = _ServiceApi()
    service = identity.PcIdentityService(
        credential_store=store,
        api_client=api,
        gym_token_provider=lambda: "gym-token",
        clock=lambda: now[0],
    )

    assert service.ensure_token() == "token-1"
    now[0] += 86400 - 3601
    assert service.ensure_token() == "token-1"
    now[0] += 2
    assert service.ensure_token() == "token-2"
    assert api.minted == [credentials, credentials]


def test_no_credentials_is_a_first_run_state() -> None:
    identity = _identity_module()
    service = identity.PcIdentityService(
        credential_store=_MemoryStore(),
        api_client=SimpleNamespace(),
        gym_token_provider=lambda: "gym-token",
    )

    assert service.status() == {
        "registered": False,
        "state": "first_run",
        "pcUuid": None,
        "tokenReady": False,
        "tokenExpiresAt": None,
        "lastHeartbeatAt": None,
        "lastError": None,
    }


class _HeartbeatApi(_ServiceApi):
    def __init__(self, heartbeat_results) -> None:
        super().__init__()
        self.heartbeat_results = list(heartbeat_results)
        self.heartbeats = []

    def send_heartbeat(self, *, pc_token, payload):
        self.heartbeats.append((pc_token, payload))
        result = self.heartbeat_results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def _api_error(identity, *, status=401, code, retry_after=None):
    return identity.PcIdentityApiError(
        status_code=status,
        code=code,
        message=code,
        retry_after_seconds=retry_after,
    )


def test_revoked_pc_stops_heartbeating() -> None:
    identity = _identity_module()
    api = _HeartbeatApi([_api_error(identity, code="ACCESS_PC_REVOKED")])
    service = identity.PcIdentityService(
        credential_store=_MemoryStore(identity.PcCredentials("uuid-a", "secret-a")),
        api_client=api,
        gym_token_provider=lambda: "gym-token",
        heartbeat_payload_provider=lambda: {"appVersion": "1.4.32", "turnstiles": []},
    )

    assert service.heartbeat_once() is False
    assert service.status()["state"] == "revoked"
    assert service.heartbeat_once() is False
    assert len(api.heartbeats) == 1


def test_two_consecutive_invalid_pc_tokens_stop_heartbeating() -> None:
    identity = _identity_module()
    invalid = lambda: _api_error(identity, code="ACCESS_PC_TOKEN_INVALID")
    api = _HeartbeatApi([invalid(), invalid()])
    service = identity.PcIdentityService(
        credential_store=_MemoryStore(identity.PcCredentials("uuid-a", "secret-a")),
        api_client=api,
        gym_token_provider=lambda: "gym-token",
        heartbeat_payload_provider=lambda: {"appVersion": "1.4.32", "turnstiles": []},
    )

    assert service.heartbeat_once() is False
    assert service.status()["state"] == "active"
    assert service.heartbeat_once() is False
    assert service.status()["state"] == "invalid_token"
    assert service.heartbeat_once() is False
    assert len(api.heartbeats) == 2
    assert len(api.minted) == 2


def test_heartbeat_respects_retry_after_without_raising() -> None:
    identity = _identity_module()
    now = [1_000.0]
    api = _HeartbeatApi(
        [
            _api_error(identity, status=429, code="RATE_LIMITED", retry_after=120),
            {"turnstilesStored": False},
        ]
    )
    service = identity.PcIdentityService(
        credential_store=_MemoryStore(identity.PcCredentials("uuid-a", "secret-a")),
        api_client=api,
        gym_token_provider=lambda: "gym-token",
        heartbeat_payload_provider=lambda: {"appVersion": "1.4.32", "turnstiles": []},
        clock=lambda: now[0],
    )

    assert service.heartbeat_once() is False
    now[0] += 119
    assert service.heartbeat_once() is False
    assert len(api.heartbeats) == 1
    now[0] += 1
    assert service.heartbeat_once() is True
    assert len(api.heartbeats) == 2


def test_network_failure_is_swallowed_and_retried_later() -> None:
    identity = _identity_module()
    api = _HeartbeatApi([OSError("offline"), {"turnstilesStored": False}])
    service = identity.PcIdentityService(
        credential_store=_MemoryStore(identity.PcCredentials("uuid-a", "secret-a")),
        api_client=api,
        gym_token_provider=lambda: "gym-token",
        heartbeat_payload_provider=lambda: {"appVersion": "1.4.32", "turnstiles": []},
    )

    assert service.heartbeat_once() is False
    assert service.status()["state"] == "active"
    assert service.heartbeat_once() is True


def test_heartbeat_payload_uses_existing_version_sync_and_worker_snapshots(monkeypatch) -> None:
    identity = _identity_module()
    cached = SimpleNamespace(
        devices=[
            {"id": 1, "accessDataMode": "AGENT"},
            {"id": 2, "accessDataMode": "ULTRA"},
            {"id": 3, "accessDataMode": "DEVICE"},
        ]
    )
    monkeypatch.setattr("app.core.db.peek_sync_cache", lambda: cached)
    app = SimpleNamespace(
        _last_sync_at="2026-09-06T10:00:00Z",
        _last_sync_ok=True,
        _update_manager=SimpleNamespace(get_current_version=lambda: "1.4.32"),
        _agent_engine=SimpleNamespace(
            get_status_snapshot=lambda: {1: {"connected": True}}
        ),
        _ultra_engine=SimpleNamespace(
            get_status=lambda: {
                "devices": {"2": {"connected": False, "failed_pins": ["4", "9"]}}
            }
        ),
    )

    assert identity.build_heartbeat_payload(app) == {
        "appVersion": "1.4.32",
        "lastSyncAt": "2026-09-06T10:00:00Z",
        "lastSyncOk": True,
        "turnstiles": [
            {"gymDeviceId": 1, "reachable": True, "failedPins": 0, "mode": "AGENT"},
            {"gymDeviceId": 2, "reachable": False, "failedPins": 2, "mode": "ULTRA"},
            {"gymDeviceId": 3, "reachable": False, "failedPins": 0, "mode": "DEVICE"},
        ],
    }


def test_heartbeat_worker_is_a_dedicated_daemon_with_five_minute_default() -> None:
    identity = _identity_module()
    called = threading.Event()
    service = SimpleNamespace(heartbeat_once=lambda: called.set())
    worker = identity.PcHeartbeatWorker(service=service)

    worker.start()
    try:
        assert called.wait(timeout=1)
        assert worker.interval_seconds == 300
        assert worker.thread_name == "pc-heartbeat"
        assert worker.is_daemon is True
    finally:
        worker.stop(timeout=1)

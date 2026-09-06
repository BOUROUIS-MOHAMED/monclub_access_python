from __future__ import annotations

import importlib
from pathlib import Path
from types import SimpleNamespace

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

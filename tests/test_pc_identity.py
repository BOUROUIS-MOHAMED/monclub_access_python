from __future__ import annotations

import importlib
from pathlib import Path

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

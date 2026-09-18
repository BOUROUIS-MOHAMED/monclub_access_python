"""The credential diff must write a grant-only change.

The backend rebuilds ``grantedActiveMembershipIds`` on every request and never stores it
on the credential row, so a member who renews (a new ActiveMembership id) arrives with the
same id, secret, flags and timestamps and only new grants. Its credentials token digests
the sorted grants, so that change is delivered. ``_sync_gym_access_credentials_rows`` used
to diff only the scalar columns, so it was dropped and the PC kept the old id: QR scans
passed only through the account second chance (``in_roster_by_account``) and reported the
old ``activeMembershipId``.

Grants are compared as a set, like the backend token: neither of its grant queries has an
ORDER BY, so an order-only difference must not rewrite every row on every sync. The stored
list keeps the order the backend sent (``verify_totp`` walks it in order).
"""

from __future__ import annotations

import time

import pytest

from app.core import access_verification as av
from tests.test_totp_index import _code_for, _settings

_CREDS_ONLY = {"members": False, "devices": False, "credentials": True, "settings": False}


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    data_root = tmp_path / "data-root"
    data_root.mkdir()
    monkeypatch.setenv("MONCLUB_ACCESS_DATA_ROOT", str(data_root))
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "grants.db"), raising=False)
    db_module.init_db()
    yield db_module
    if hasattr(db_module, "_shutdown_db_writer_for_tests"):
        db_module._shutdown_db_writer_for_tests()


def _cred(account_id: int, grants, *, secret_hex: str | None = None) -> dict:
    return {
        "id": account_id + 1,
        "gymId": 58,
        "accountId": account_id,
        "secretHex": secret_hex or f"{account_id:040x}",
        "enabled": True,
        "rotatedAt": None,
        "createdAt": "2026-04-01T00:00:00",
        "updatedAt": "2026-04-01T00:00:00",
        "grantedActiveMembershipIds": list(grants),
    }


def _sync(db, creds) -> dict:
    return db.save_sync_cache_delta(
        {"gymAccessCredentials": creds, "contractStatus": True, "contractEndDate": "2026-12-31"},
        _CREDS_ONLY,
    )["credentials"]


def _grants_by_account(db) -> dict:
    return {c["accountId"]: c["grantedActiveMembershipIds"] for c in db.list_sync_gym_access_credentials()}


def test_a_grant_only_change_is_written(db):
    _sync(db, [_cred(5001, [101]), _cred(5002, [202]), _cred(5003, [303])])

    # 5002 renewed: same credential row, only the granted membership id changed.
    summary = _sync(db, [_cred(5001, [101]), _cred(5002, [909]), _cred(5003, [303])])

    assert _grants_by_account(db) == {5001: [101], 5002: [909], 5003: [303]}
    assert summary["mode"] == "delta" and summary["upserted"] == 1 and summary["deleted"] == 0


def test_an_identical_resync_writes_nothing(db):
    creds = [_cred(5001, [101]), _cred(5002, [202, 203])]
    _sync(db, creds)

    summary = _sync(db, creds)

    assert summary["upserted"] == 0 and summary["deleted"] == 0


def test_the_same_grants_in_another_order_write_nothing(db):
    _sync(db, [_cred(5001, [101, 102, 103])])

    summary = _sync(db, [_cred(5001, [103, 101, 102])])

    assert summary["upserted"] == 0
    # The stored list is what the backend sent, never re-sorted.
    assert _grants_by_account(db) == {5001: [101, 102, 103]}


def test_a_changed_grant_set_is_stored_in_the_order_sent(db):
    _sync(db, [_cred(5001, [101, 102])])

    summary = _sync(db, [_cred(5001, [909, 101])])

    assert summary["upserted"] == 1
    assert _grants_by_account(db) == {5001: [909, 101]}


@pytest.mark.parametrize("stored, incoming, changed", [
    ("[101]", "[101]", False),
    ("[101, 102]", "[102, 101]", False),       # order only
    ('["101"]', "[101]", False),               # same id, verify_totp reads both the same
    (None, "[]", False),                       # a NULL column reads as no grants
    ("[101]", "[909]", True),
    ("[101]", "[101, 909]", True),
    ("[101, 909]", "[909]", True),
    ("not json", "[101]", True),               # unparseable: write
    ('["x", 101]', "[101]", True),             # a bad entry is not skipped: write
])
def test_grants_compare_as_a_set_and_write_when_in_doubt(stored, incoming, changed):
    import app.core.db as db_module

    assert db_module._sync_credential_grants_changed(stored, incoming) is changed


def test_a_grant_only_change_is_written_on_the_fast_patch_merge_path(db):
    _sync(db, [_cred(5001, [101]), _cred(5002, [202])])

    db.apply_fast_patch_bundle({
        "schemaVersion": 1,
        "bundleId": "bundle-grants",
        "gymId": 58,
        "generatedAt": "2026-09-18T12:00:00Z",
        "items": [{
            "itemId": "CREDENTIALS-None-r1",
            "kind": "SECTION_REPLACE",
            "entityType": "CREDENTIALS",
            "entityId": None,
            "revision": "2026-09-18T12:00:00Z",
            "payload": {"mergeMode": "UPSERT_ONLY", "gymAccessCredentials": [_cred(5002, [909])]},
            "impact": {},
        }],
        "requiresReconcile": True,
    })

    assert _grants_by_account(db) == {5001: [101], 5002: [909]}


def test_a_renewed_member_scans_in_on_the_new_membership_after_the_next_sync(db):
    # Member list after the renewal: new membership 909, same main account 5002.
    users_by_am = {909: {"activeMembershipId": 909, "userId": 7909, "fullName": "M909",
                         "mainAccountId": 5002}}
    s = _settings(totp_roster_check_mode="enforce")
    renewed = _cred(5002, [909])
    _sync(db, [_cred(5002, [202])])

    _sync(db, [renewed])

    now = time.time()
    r = av.verify_totp(
        scanned=_code_for(renewed, s, now), settings=s,
        creds_payload=db.list_sync_gym_access_credentials(),
        users_by_am=users_by_am, users_by_card={}, now_unix=now,
    )
    assert r["allowed"] is True and r["rosterCheck"] == av.ROSTER_IN
    assert r["activeMembershipId"] == 909 and r["user"]["userId"] == 7909

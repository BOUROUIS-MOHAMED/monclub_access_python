"""Tests for delta user cache operations in db.py."""
import json
import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()
    return db_module


def _make_user(am_id=1, user_id=100, full_name="Alice Smith", card="12345"):
    return {
        "activeMembershipId": am_id,
        "userId": user_id,
        "membershipId": 50,
        "fullName": full_name,
        "phone": "0600000000",
        "email": "alice@example.com",
        "validFrom": "2026-01-01",
        "validTo": "2026-12-31",
        "firstCardId": card,
        "secondCardId": None,
        "image": None,
        "fingerprints": [],
        "faceId": None,
        "accountUsernameId": None,
        "qrCodePayload": None,
        "birthday": None,
        "imageSource": None,
        "userImageStatus": None,
    }


def test_upsert_users_inserts_new_user(db):
    """Upserting a user that doesn't exist inserts it."""
    db.upsert_delta_users([_make_user(am_id=1)])
    ids = db.get_all_cached_user_am_ids()
    assert 1 in ids


def test_upsert_users_updates_existing_user(db):
    """Upserting a user that already exists updates their data."""
    db.upsert_delta_users([_make_user(am_id=1, full_name="Alice Smith")])
    db.upsert_delta_users([_make_user(am_id=1, full_name="Alice Updated")])
    # Should still be 1 row
    ids = db.get_all_cached_user_am_ids()
    assert len([i for i in ids if i == 1]) == 1


def test_upsert_users_handles_multiple_users(db):
    """Multiple users can be upserted in one call."""
    db.upsert_delta_users([_make_user(am_id=1), _make_user(am_id=2), _make_user(am_id=3)])
    ids = db.get_all_cached_user_am_ids()
    assert {1, 2, 3}.issubset(set(ids))


def test_delete_users_by_am_ids_removes_entries(db):
    """Users with specified AM IDs are removed from cache."""
    db.upsert_delta_users([_make_user(am_id=1), _make_user(am_id=2), _make_user(am_id=3)])
    db.delete_users_by_am_ids({2, 3})
    ids = set(db.get_all_cached_user_am_ids())
    assert 1 in ids
    assert 2 not in ids
    assert 3 not in ids


def test_delete_users_by_am_ids_ignores_missing_ids(db):
    """Deleting IDs that don't exist doesn't raise errors."""
    db.upsert_delta_users([_make_user(am_id=1)])
    db.delete_users_by_am_ids({999, 1000})  # these don't exist
    ids = db.get_all_cached_user_am_ids()
    assert 1 in ids


def test_get_all_cached_user_am_ids_returns_empty_when_no_users(db):
    """Returns empty collection when no users cached."""
    ids = db.get_all_cached_user_am_ids()
    assert len(ids) == 0


# ── save_sync_cache_delta delta mode ─────────────────────────────────────

def _make_sync_data(users, delta_mode=False, valid_ids=None):
    return {
        "users": users,
        "membersDeltaMode": delta_mode,
        "validMemberIds": valid_ids,
        "devices": [],
        "gymAccessCredentials": [],
        "infrastructures": [],
        "membership": [],
        "contractStatus": True,
        "contractEndDate": "2026-12-31",
        "accessSoftwareSettings": {},
    }


def _make_credential(*, cred_id: int, account_id: int, gym_id: int = 58, secret_hex: str = "abc123", granted_ids=None):
    return {
        "id": cred_id,
        "gymId": gym_id,
        "accountId": account_id,
        "secretHex": secret_hex,
        "enabled": True,
        "rotatedAt": f"2026-04-{cred_id:02d}T00:00:00",
        "createdAt": f"2026-04-{cred_id:02d}T00:00:00",
        "updatedAt": f"2026-04-{cred_id:02d}T00:00:00",
        "grantedActiveMembershipIds": list(granted_ids or [account_id]),
    }


def test_save_sync_cache_delta_full_mode_replaces_all_users(db):
    """Full mode (membersDeltaMode=False) replaces all users in cache."""
    # Pre-populate cache with 3 users
    db.upsert_delta_users([_make_user(am_id=i, user_id=i+100) for i in [1, 2, 3]])

    data = _make_sync_data(users=[_make_user(am_id=10, user_id=110), _make_user(am_id=11, user_id=111)])
    db.save_sync_cache_delta(data, {"members": True, "devices": False,
                                    "credentials": False, "settings": False})

    ids = set(db.get_all_cached_user_am_ids())
    assert ids == {10, 11}  # replaced, not merged


def test_save_sync_cache_delta_delta_mode_upserts_changed_and_deletes_removed(db):
    """Delta mode upserts changed users and removes ones not in validMemberIds."""
    # Pre-populate: users 1, 2, 3
    db.upsert_delta_users([_make_user(am_id=i, user_id=i+100) for i in [1, 2, 3]])

    # Backend says: user 1 changed (new name), user 3 valid but unchanged (not in users[]),
    # user 2 is no longer valid. validMemberIds=[1,3]
    data = _make_sync_data(
        users=[_make_user(am_id=1, user_id=101, full_name="Updated Name")],
        delta_mode=True,
        valid_ids=[1, 3],
    )
    db.save_sync_cache_delta(data, {"members": True, "devices": False,
                                    "credentials": False, "settings": False})

    ids = set(db.get_all_cached_user_am_ids())
    assert 1 in ids     # updated
    assert 3 in ids     # kept (was in validMemberIds, not in changed list)
    assert 2 not in ids  # deleted (not in validMemberIds)


def test_save_sync_cache_delta_delta_mode_with_no_changes_deletes_removed(db):
    """Delta mode with empty users[] only deletes members absent from validMemberIds."""
    db.upsert_delta_users([_make_user(am_id=i, user_id=i+100) for i in [1, 2, 3]])

    # No changes, but user 3 expired
    data = _make_sync_data(users=[], delta_mode=True, valid_ids=[1, 2])
    db.save_sync_cache_delta(data, {"members": True, "devices": False,
                                    "credentials": False, "settings": False})

    ids = set(db.get_all_cached_user_am_ids())
    assert {1, 2}.issubset(ids)
    assert 3 not in ids


def test_save_sync_cache_delta_credentials_refresh_preserves_unchanged_rowids(db):
    initial = _make_sync_data(users=[], delta_mode=True, valid_ids=[])
    initial["gymAccessCredentials"] = [
        _make_credential(cred_id=2, account_id=20, secret_hex="remove-me"),
        _make_credential(cred_id=1, account_id=10, secret_hex="keep-me"),
    ]
    db.save_sync_cache_delta(
        initial,
        {"members": False, "devices": False, "credentials": True, "settings": False},
    )

    with db.get_conn() as conn:
        keep_rowid_before = conn.execute(
            "SELECT rowid FROM sync_gym_access_credentials WHERE gym_id=? AND account_id=?",
            (58, 10),
        ).fetchone()[0]

    refreshed = _make_sync_data(users=[], delta_mode=True, valid_ids=[])
    refreshed["gymAccessCredentials"] = [
        _make_credential(cred_id=1, account_id=10, secret_hex="keep-me"),
        _make_credential(cred_id=3, account_id=30, secret_hex="new-one"),
    ]
    db.save_sync_cache_delta(
        refreshed,
        {"members": False, "devices": False, "credentials": True, "settings": False},
    )

    with db.get_conn() as conn:
        keep_rowid_after = conn.execute(
            "SELECT rowid FROM sync_gym_access_credentials WHERE gym_id=? AND account_id=?",
            (58, 10),
        ).fetchone()[0]
        keys = {
            tuple(row)
            for row in conn.execute(
                "SELECT gym_id, account_id FROM sync_gym_access_credentials ORDER BY account_id"
            ).fetchall()
        }

    assert keep_rowid_after == keep_rowid_before
    assert keys == {(58, 10), (58, 30)}

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


def test_save_sync_cache_delta_skips_settings_and_memberships_when_refresh_settings_false(db):
    initial = _make_sync_data(users=[], delta_mode=True, valid_ids=[])
    initial["accessSoftwareSettings"] = {
        "gymId": 58,
        "accessServerHost": "127.0.0.1",
        "accessServerPort": 8080,
        "accessServerEnabled": True,
        "createdAt": "2026-04-12T00:00:00Z",
        "updatedAt": "2026-04-12T00:00:00Z",
    }
    initial["membership"] = [
        {"id": 7, "title": "Gold", "description": "Initial", "price": 99.0, "durationInDays": 30},
    ]
    db.save_sync_cache_delta(
        initial,
        {"members": False, "devices": False, "credentials": False, "settings": True},
    )

    with db.get_conn() as conn:
        settings_before = tuple(
            conn.execute(
                "SELECT access_server_host, access_server_port, updated_at FROM sync_access_software_settings WHERE id=1"
            ).fetchone()
        )
        memberships_before = [
            tuple(row)
            for row in conn.execute(
                "SELECT id, title, description, price, duration_in_days FROM sync_memberships"
            ).fetchall()
        ]

    delta = _make_sync_data(users=[], delta_mode=True, valid_ids=[])
    delta["accessSoftwareSettings"] = {
        "gymId": 58,
        "accessServerHost": "10.10.10.10",
        "accessServerPort": 9090,
        "accessServerEnabled": True,
        "createdAt": "2026-04-13T00:00:00Z",
        "updatedAt": "2026-04-13T00:00:00Z",
    }
    delta["membership"] = [
        {"id": 8, "title": "Platinum", "description": "Changed", "price": 199.0, "durationInDays": 60},
    ]
    db.save_sync_cache_delta(
        delta,
        {"members": False, "devices": False, "credentials": True, "settings": False},
    )

    with db.get_conn() as conn:
        settings_after = tuple(
            conn.execute(
                "SELECT access_server_host, access_server_port, updated_at FROM sync_access_software_settings WHERE id=1"
            ).fetchone()
        )
        memberships_after = [
            tuple(row)
            for row in conn.execute(
                "SELECT id, title, description, price, duration_in_days FROM sync_memberships"
            ).fetchall()
        ]

    assert settings_after == settings_before
    assert memberships_after == memberships_before


def test_apply_member_shadow_delta_updates_and_deletes_in_one_pass(db):
    db.upsert_member_shadow(users=[_make_user(am_id=1, full_name="Alice Smith"), _make_user(am_id=2, full_name="Bob")])

    deleted = db.apply_member_shadow_delta(
        users=[_make_user(am_id=1, full_name="Alice Updated")],
        valid_member_ids=[1],
    )

    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT active_membership_id, full_name FROM member_shadow ORDER BY active_membership_id"
        ).fetchall()

    assert deleted == [2]
    assert [tuple(row) for row in rows] == [(1, "Alice Updated")]


# ── delta-mode empty-validMemberIds guard (H-006 mirror) ─────────────────
#
# WHY THIS BLOCK EXISTS
# ---------------------
# The delta branch deleted every cached member whenever the backend sent
# `membersDeltaMode: true` with `validMemberIds: []` -- `valid_ids is not None`
# is true for an empty list, so `ids_to_remove` became the whole local roster.
# `access_verification.verify_card` admits a card purely because its row is
# present in `sync_users`, so an emptied table is a total door lockout at the
# gym until a successful full refresh. The full-replace branch has refused this
# shape since H-006 (`users == []` against a cache of > 10 rows); the delta
# branch never got the same guard. These tests pin the mirrored policy.

def _seed(db, count, first=1):
    ids = list(range(first, first + count))
    db.upsert_delta_users([_make_user(am_id=i, user_id=i + 100) for i in ids])
    return set(ids)


_MEMBERS_ONLY = {"members": True, "devices": False, "credentials": False, "settings": False}


def test_delta_empty_valid_ids_refuses_to_clear_a_populated_roster(db):
    """membersDeltaMode=True + validMemberIds=[] against > 10 cached rows is a backend
    error, not a gym that lost every member. Refuse the delete."""
    seeded = _seed(db, 11)

    data = _make_sync_data(users=[], delta_mode=True, valid_ids=[])
    db.save_sync_cache_delta(data, _MEMBERS_ONLY)

    assert set(db.get_all_cached_user_am_ids()) == seeded


def test_delta_empty_valid_ids_refusal_reports_zero_deleted_in_the_profile(db):
    """The refusal must not lie in the write profile: members_deleted is what was
    actually removed (0), and the would-have-been count lands in its own key."""
    _seed(db, 11)

    db.save_sync_cache_delta(_make_sync_data(users=[], delta_mode=True, valid_ids=[]), _MEMBERS_ONLY)
    profile = db.get_last_db_write_profile("save_sync_cache_delta")

    assert profile["members_deleted"] == 0
    assert profile["members_delete_refused"] is True
    assert profile["members_delete_refused_count"] == 11


def test_delta_empty_valid_ids_still_clears_a_roster_at_the_threshold(db):
    """A gym can legitimately have no members. The full branch draws that line at
    `> 10`; exactly 10 rows still clears, so the two branches read as one policy."""
    _seed(db, 10)

    db.save_sync_cache_delta(_make_sync_data(users=[], delta_mode=True, valid_ids=[]), _MEMBERS_ONLY)
    profile = db.get_last_db_write_profile("save_sync_cache_delta")

    assert set(db.get_all_cached_user_am_ids()) == set()
    assert profile["members_deleted"] == 10
    assert profile["members_delete_refused"] is False
    assert profile["members_delete_refused_count"] == 0


def test_delta_non_empty_valid_ids_deletes_exactly_the_absent_ids(db):
    """The healthy path is untouched: the guard only reads `valid_set` emptiness."""
    _seed(db, 12)

    data = _make_sync_data(users=[], delta_mode=True, valid_ids=[2, 4, 6, 8, 10, 12])
    db.save_sync_cache_delta(data, _MEMBERS_ONLY)
    profile = db.get_last_db_write_profile("save_sync_cache_delta")

    assert set(db.get_all_cached_user_am_ids()) == {2, 4, 6, 8, 10, 12}
    assert profile["members_deleted"] == 6
    assert profile["members_delete_refused"] is False


def test_delta_non_empty_valid_ids_mass_delete_is_not_refused(db):
    """No ratio guard: 1 valid id against 12 cached rows still deletes 11. Refusing a
    legitimate mass revocation would keep ex-members' cards admitted (verify_card
    allows on table presence alone) -- fail-open, the wrong direction."""
    _seed(db, 12)

    db.save_sync_cache_delta(_make_sync_data(users=[], delta_mode=True, valid_ids=[7]), _MEMBERS_ONLY)
    profile = db.get_last_db_write_profile("save_sync_cache_delta")

    assert set(db.get_all_cached_user_am_ids()) == {7}
    assert profile["members_deleted"] == 11
    assert profile["members_delete_refused"] is False


def test_delta_empty_valid_ids_refusal_still_commits_the_rest_of_the_write(db):
    """Refusing the delete must skip ONLY the delete. Unlike the full branch (which has
    nothing left to do and returns early), the delta branch still owes devices,
    credentials, settings, memberships and infrastructures the same transaction."""
    seeded = _seed(db, 11)

    data = _make_sync_data(users=[], delta_mode=True, valid_ids=[])
    data["devices"] = [{"id": 9, "name": "Turnstile A"}]
    data["gymAccessCredentials"] = [_make_credential(cred_id=1, account_id=10)]
    data["infrastructures"] = [{"id": 3, "name": "Main", "gymAgent": {}}]
    data["membership"] = [{"id": 7, "title": "Gold", "description": "d", "price": 99.0,
                           "durationInDays": 30}]
    data["accessSoftwareSettings"] = {
        "gymId": 58, "accessServerHost": "10.0.0.5", "accessServerPort": 8080,
        "accessServerEnabled": True, "createdAt": "2026-09-06T00:00:00Z",
        "updatedAt": "2026-09-06T00:00:00Z",
    }
    db.save_sync_cache_delta(
        data, {"members": True, "devices": True, "credentials": True, "settings": True}
    )

    assert set(db.get_all_cached_user_am_ids()) == seeded  # delete refused
    with db.get_conn() as conn:
        def _count(table):
            return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

        assert _count("sync_devices") == 1
        assert _count("sync_gym_access_credentials") == 1
        assert _count("sync_infrastructures") == 1
        assert _count("sync_memberships") == 1
        host = conn.execute(
            "SELECT access_server_host FROM sync_access_software_settings WHERE id=1"
        ).fetchone()[0]
    assert host == "10.0.0.5"


def test_delta_empty_valid_ids_refusal_keeps_upserted_members(db):
    """A payload that upserts members AND sends validMemberIds=[] contradicts itself.
    The guard must not let the just-written rows be deleted either."""
    _seed(db, 11)

    data = _make_sync_data(
        users=[_make_user(am_id=99, user_id=199, full_name="New Member")],
        delta_mode=True,
        valid_ids=[],
    )
    db.save_sync_cache_delta(data, _MEMBERS_ONLY)
    profile = db.get_last_db_write_profile("save_sync_cache_delta")

    ids = set(db.get_all_cached_user_am_ids())
    assert 99 in ids
    assert len(ids) == 12
    assert profile["members_upserted"] == 1
    assert profile["members_delete_refused"] is True


# ── shadow delta empty-validMemberIds guard (H-006 mirror, twin of the block above) ──
#
# WHY THIS BLOCK EXISTS
# ---------------------
# `apply_member_shadow_delta` had the identical shape the block above pins for
# `save_sync_cache_delta`: its write body opens on `normalized_valid_ids is not None`,
# which is TRUE for an empty set, so `membersDeltaMode: true` + `validMemberIds: []`
# collected every shadow row for deletion and emptied the table.
#
# Unlike `sync_users`, `member_shadow` is NEVER a door decision — it is a change
# detection cache read only by db.py and app.py (grep: no other non-test module).
# The cost of an emptied shadow is that the next FULL member refresh re-flags the whole
# roster as `new`, not a lockout. The guard exists so the two mirrors refuse on the SAME
# input rather than diverging: after the fix above, a malformed response left sync_users
# intact and still emptied member_shadow.


def _seed_shadow(db, count, first=1):
    ids = list(range(first, first + count))
    db.upsert_member_shadow(users=[_make_user(am_id=i, user_id=i + 100) for i in ids])
    return set(ids)


def _shadow_ids(db):
    with db.get_conn() as conn:
        return {
            int(row["active_membership_id"])
            for row in conn.execute("SELECT active_membership_id FROM member_shadow").fetchall()
        }


def test_shadow_delta_empty_valid_ids_refuses_to_clear_a_populated_shadow(db):
    """validMemberIds=[] against > 10 shadow rows is a backend error, not a gym that lost
    every member. Refuse the delete, and report nothing deleted to the caller."""
    seeded = _seed_shadow(db, 11)

    deleted = db.apply_member_shadow_delta(users=[], valid_member_ids=[])

    assert _shadow_ids(db) == seeded
    assert deleted == []


def test_shadow_delta_empty_valid_ids_refusal_reports_in_the_write_profile(db):
    """The refusal must be visible. The returned list is what was actually removed (none),
    so the would-have-been blast radius lands in the write profile instead."""
    _seed_shadow(db, 11)

    db.apply_member_shadow_delta(users=[], valid_member_ids=[])
    profile = db.get_last_db_write_profile("apply_member_shadow_delta")

    assert profile["members_delete_refused"] is True
    assert profile["members_delete_refused_count"] == 11


def test_shadow_delta_empty_valid_ids_still_clears_a_shadow_at_the_threshold(db):
    """A gym can legitimately have no members. save_sync_cache_delta draws that line at
    `> _H006_MIN_CACHE_ROWS`; exactly 10 rows still clears, so both mirrors read as one
    policy on one constant."""
    _seed_shadow(db, 10)

    deleted = db.apply_member_shadow_delta(users=[], valid_member_ids=[])
    profile = db.get_last_db_write_profile("apply_member_shadow_delta")

    assert _shadow_ids(db) == set()
    assert sorted(deleted) == list(range(1, 11))
    assert profile["members_delete_refused"] is False
    assert profile["members_delete_refused_count"] == 0


def test_shadow_delta_non_empty_valid_ids_deletes_exactly_the_absent_ids(db):
    """The healthy path is untouched: the guard only reads emptiness of the valid set."""
    _seed_shadow(db, 12)

    deleted = db.apply_member_shadow_delta(users=[], valid_member_ids=[2, 4, 6, 8, 10, 12])
    profile = db.get_last_db_write_profile("apply_member_shadow_delta")

    assert _shadow_ids(db) == {2, 4, 6, 8, 10, 12}
    assert sorted(deleted) == [1, 3, 5, 7, 9, 11]
    assert profile["members_delete_refused"] is False


def test_shadow_delta_non_empty_valid_ids_mass_delete_is_not_refused(db):
    """No ratio guard, mirroring save_sync_cache_delta: 1 valid id against 12 shadow rows
    still deletes 11. A refused mass revocation would leave stale hashes claiming
    ex-members are already synced, so the device push would skip removing them."""
    _seed_shadow(db, 12)

    deleted = db.apply_member_shadow_delta(users=[], valid_member_ids=[7])
    profile = db.get_last_db_write_profile("apply_member_shadow_delta")

    assert _shadow_ids(db) == {7}
    assert len(deleted) == 11
    assert profile["members_delete_refused"] is False


def test_shadow_delta_empty_valid_ids_refusal_still_upserts_the_incoming_users(db):
    """Refusing the delete must skip ONLY the delete. The incoming users still owe their
    upsert in the same transaction, exactly as save_sync_cache_delta lets the rest of its
    write commit."""
    _seed_shadow(db, 11)

    db.apply_member_shadow_delta(
        users=[_make_user(am_id=3, full_name="Renamed Member")],
        valid_member_ids=[],
    )

    with db.get_conn() as conn:
        name = conn.execute(
            "SELECT full_name FROM member_shadow WHERE active_membership_id=3"
        ).fetchone()["full_name"]

    assert name == "Renamed Member"
    assert len(_shadow_ids(db)) == 11


def test_shadow_delta_none_valid_ids_deletes_nothing_and_does_not_report_a_refusal(db):
    """`valid_member_ids=None` means the response carried no validMemberIds at all: there
    is no delete to make, so there is no refusal to report either."""
    seeded = _seed_shadow(db, 11)

    deleted = db.apply_member_shadow_delta(
        users=[_make_user(am_id=3, full_name="Renamed Member")],
        valid_member_ids=None,
    )
    profile = db.get_last_db_write_profile("apply_member_shadow_delta")

    assert _shadow_ids(db) == seeded
    assert deleted == []
    assert profile["members_delete_refused"] is False
    assert profile["members_delete_refused_count"] == 0


def test_both_mirrors_refuse_the_same_malformed_response_together(db):
    """The point of the guard. One malformed response (membersDeltaMode + empty
    validMemberIds) reaches BOTH tables in the same sync iteration -- app.py calls
    save_sync_cache_delta (~line 2342) and _apply_member_shadow_sync (~line 2419) off the
    same payload. Before this fix sync_users survived and member_shadow did not. This test
    fails if the two thresholds ever drift apart."""
    seeded_users = _seed(db, 11)
    seeded_shadow = _seed_shadow(db, 11)

    data = _make_sync_data(users=[], delta_mode=True, valid_ids=[])
    db.save_sync_cache_delta(data, _MEMBERS_ONLY)
    db.apply_member_shadow_delta(users=[], valid_member_ids=[])

    assert set(db.get_all_cached_user_am_ids()) == seeded_users
    assert _shadow_ids(db) == seeded_shadow

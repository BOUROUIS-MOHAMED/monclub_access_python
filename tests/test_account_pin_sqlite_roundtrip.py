"""mainAccountId must survive the SQLite member cache, through the REAL db functions.

WHY THIS FILE EXISTS
--------------------
The account-pin derivation (device_sync._filter_users_for_device) was tested only with raw
dicts. In the field every roster row reaches the engines through ``sync_users``, and until
this change no sync_users writer stored ``mainAccountId`` and ``_coerce_user_row_to_payload``
never read it back -- so the account pin, the collapse and the account index were inert on
every installed client while every test passed.

These tests drive each production write path -- ``save_sync_cache`` (full replace),
``save_sync_cache_delta`` FULL mode (the per-row diff) and DELTA mode, ``upsert_delta_users``,
``apply_fast_patch_bundle`` -- then read back through ``load_sync_cache`` /
``list_sync_users_by_active_membership_ids`` (both ``_coerce_user_row_to_payload``) into
``_filter_users_for_device``, and assert the pin under both schemes. They also cover a legacy
database that goes through ``_rebuild_sync_users_without_legacy_fingerprint``, an old database
that gains the column through ``init_db``, and the ONE forced full member refresh that fills it.

The members are the production collision: Ali's main_account.id (5) is Sonia's
active_membership.id (5).
"""
from __future__ import annotations

import sqlite3
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from app.core.device_sync import DeviceSyncEngine


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "roundtrip.db"), raising=False)
    db_module.init_db()
    # load_sync_cache answers None until sync_meta exists, which any real gym has from its
    # first sync. Write it with a members-less delta so every writer below is read back
    # through the same load_sync_cache the engines use.
    db_module.save_sync_cache_delta(
        _payload([]), {"members": False, "devices": False, "credentials": False, "settings": False},
    )
    db_module.invalidate_sync_cache(clear_cached=True)
    yield db_module
    db_module.invalidate_sync_cache(clear_cached=True)
    if hasattr(db_module, "_shutdown_db_writer_for_tests"):
        db_module._shutdown_db_writer_for_tests()


def _member(am_id, user_id, account_id, name, **extra) -> Dict[str, Any]:
    u = {
        "activeMembershipId": am_id,
        "userId": user_id,
        "mainAccountId": account_id,
        "membershipId": 7,
        "fullName": name,
        "phone": "0600000000",
        "email": f"u{user_id}@example.com",
        "validFrom": "2026-01-01T00:00:00",
        "validTo": "2026-12-31T00:00:00",
        "firstCardId": str(1000 + user_id),
        "secondCardId": None,
        "image": None,
        "fingerprints": [],
        "faceId": None,
        "accountUsernameId": None,
        "qrCodePayload": None,
        "birthday": None,
        "imageSource": None,
        "userImageStatus": None,
        "userProfileImage": None,
    }
    u.update(extra)
    return u


def _ali(**kw):
    return _member(31000, 900, 5, "Ali", **kw)


def _sonia(**kw):
    return _member(5, 901, 777, "Sonia", **kw)


def _payload(users, *, delta=False, valid_ids=None) -> Dict[str, Any]:
    return {
        "users": users,
        "membersDeltaMode": delta,
        "validMemberIds": valid_ids,
        "devices": [],
        "gymAccessCredentials": [],
        "infrastructures": [],
        "membership": [],
        "contractStatus": True,
        "contractEndDate": "2026-12-31",
        "accessSoftwareSettings": {},
    }


_MEMBERS_ONLY = {"members": True, "devices": False, "credentials": False, "settings": False}


def _write_full_replace(db, users):
    db.save_sync_cache(_payload(users))


def _write_delta_full_mode(db, users):
    db.save_sync_cache_delta(_payload(users), _MEMBERS_ONLY)


def _write_delta_mode(db, users):
    ids = [u["activeMembershipId"] for u in users]
    db.save_sync_cache_delta(_payload(users, delta=True, valid_ids=ids), _MEMBERS_ONLY)


def _write_upsert_delta_users(db, users):
    db.upsert_delta_users(users)


def _write_fast_patch(db, users):
    db.apply_fast_patch_bundle({
        "bundleId": "bundle-roundtrip",
        "generatedAt": "2026-09-12T10:00:00",
        "items": [
            {"kind": "ENTITY_UPSERT", "entityType": "ACTIVE_MEMBERSHIP",
             "entityId": u["activeMembershipId"], "revision": "2026-09-12T10:00:00",
             "payload": {"member": u}}
            for u in users
        ],
    })


WRITERS = {
    "save_sync_cache": _write_full_replace,
    "save_sync_cache_delta:full": _write_delta_full_mode,
    "save_sync_cache_delta:delta": _write_delta_mode,
    "upsert_delta_users": _write_upsert_delta_users,
    "apply_fast_patch_bundle": _write_fast_patch,
}


def _cached_users(db) -> List[Dict[str, Any]]:
    """The roster the engines read (load_sync_cache), cross-checked against the paged
    direct query -- both project rows through _coerce_user_row_to_payload."""
    paged, _total = db.list_sync_users_page(limit=0, offset=0)
    db.invalidate_sync_cache(clear_cached=True)
    cache = db.load_sync_cache()
    if cache is None:                    # a database with no sync_meta row yet
        return paged
    users = [u for u in (cache.users or []) if isinstance(u, dict)]
    assert sorted((u["activeMembershipId"], u["mainAccountId"]) for u in users) == \
        sorted((u["activeMembershipId"], u["mainAccountId"]) for u in paged)
    return users


def _pins(users, scheme) -> Dict[str, str]:
    out = DeviceSyncEngine(cfg=SimpleNamespace(), logger=None)._filter_users_for_device(
        users=users, device={"doorIds": [1], "pinScheme": scheme}, default_door_id=1,
    )
    return {pin: u["fullName"] for pin, u in out.items()}


@pytest.mark.parametrize("writer", sorted(WRITERS))
def test_every_writer_round_trips_main_account_id_into_the_pin(db, writer):
    WRITERS[writer](db, [_ali(), _sonia()])

    users = _cached_users(db)
    assert {u["activeMembershipId"]: u["mainAccountId"] for u in users} == {31000: 5, 5: 777}

    assert _pins(users, "ACCOUNT") == {"5": "Ali", "777": "Sonia"}, (
        "under ACCOUNT the pin is the person: Ali is 5 -- the number that is Sonia's "
        "membership id -- and Sonia is 777"
    )
    assert _pins(users, "MEMBERSHIP") == {"31000": "Ali", "5": "Sonia"}, (
        "under MEMBERSHIP nothing changes"
    )

    targeted = db.list_sync_users_by_active_membership_ids([31000])
    assert [u["mainAccountId"] for u in targeted] == [5]
    assert {u["fullName"] for u in db.list_sync_users_by_main_account_ids([5])} == {"Ali"}
    assert db.get_main_account_ids_for_memberships([31000, 5]) == {31000: 5, 5: 777}


def test_the_full_refresh_diff_updates_a_row_whose_only_change_is_main_account_id(db):
    """The exact shape of the upgrade: rows cached without the field, then a FULL refresh
    that carries it. If main_account_id were not in the diffed column tuple the rows would
    compare equal and stay NULL forever."""
    _write_delta_full_mode(db, [_ali(mainAccountId=None), _sonia(mainAccountId=None)])
    stats: Dict[str, Any] = {}
    DeviceSyncEngine(cfg=SimpleNamespace(), logger=None)._filter_users_for_device(
        users=_cached_users(db), device={"doorIds": [1], "pinScheme": "ACCOUNT"},
        default_door_id=1, stats_out=stats,
    )
    assert stats["withheld_missing_account"] == 2

    _write_delta_full_mode(db, [_ali(), _sonia()])
    profile = db.get_last_db_write_profile("save_sync_cache_delta")
    assert profile["members_updated"] == 2 and profile["members_inserted"] == 0

    assert _pins(_cached_users(db), "ACCOUNT") == {"5": "Ali", "777": "Sonia"}


def test_the_link_survives_the_member_row_being_deleted(db):
    """A revocation deletes the sync_users row before the device worker acts on it. Under
    ACCOUNT the worker still has to name the person's pin."""
    _write_delta_mode(db, [_ali(), _sonia()])
    db.save_sync_cache_delta(_payload([], delta=True, valid_ids=[5]), _MEMBERS_ONLY)

    assert db.list_sync_users_by_active_membership_ids([31000]) == []
    assert db.get_main_account_ids_for_memberships([31000]) == {31000: 5}


# ── schema migrations ───────────────────────────────────────────────────────────────────

_PRE_CHANGE_SYNC_USERS = """
    CREATE TABLE sync_users (
        user_id INTEGER, active_membership_id INTEGER, membership_id INTEGER,
        full_name TEXT, phone TEXT, email TEXT, valid_from TEXT, valid_to TEXT,
        first_card_id TEXT, second_card_id TEXT, image TEXT, fingerprints_json TEXT,
        face_id TEXT, account_username_id TEXT, qr_code_payload TEXT, birthday TEXT,
        image_source TEXT, user_image_status TEXT, user_profile_image TEXT
    )
"""

_LEGACY_SYNC_USERS = """
    CREATE TABLE sync_users (
        user_id INTEGER, active_membership_id INTEGER, membership_id INTEGER,
        full_name TEXT, phone TEXT, email TEXT, valid_from TEXT, valid_to TEXT,
        first_card_id TEXT, second_card_id TEXT, image TEXT, fingerprint TEXT,
        face_id TEXT, account_username_id TEXT, qr_code_payload TEXT
    )
"""


def _seed(path, create_sql):
    conn = sqlite3.connect(str(path))
    conn.execute(create_sql)
    conn.execute(
        "INSERT INTO sync_users (user_id, active_membership_id, membership_id, full_name) "
        "VALUES (900, 31000, 7, 'Ali')"
    )
    conn.execute("CREATE TABLE sync_version_tokens (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.executemany(
        "INSERT INTO sync_version_tokens (key, value) VALUES (?, ?)",
        [("membersVersion", "1080:2026-09-12T09:00:00:5:x"),
         ("membersUpdatedAfter", "2026-09-12T09:00:00"),
         ("devicesVersion", "2:2026-09-01")],
    )
    conn.commit()
    conn.close()


def _columns(db) -> List[str]:
    with db.get_conn() as conn:
        return [r[1] for r in conn.execute("PRAGMA table_info(sync_users)").fetchall()]


@pytest.fixture
def old_db(tmp_path, monkeypatch):
    import app.core.db as db_module

    path = tmp_path / "old.db"
    monkeypatch.setattr(db_module, "_DB_PATH", str(path), raising=False)
    db_module.invalidate_sync_cache(clear_cached=True)
    yield db_module, path
    db_module.invalidate_sync_cache(clear_cached=True)
    if hasattr(db_module, "_shutdown_db_writer_for_tests"):
        db_module._shutdown_db_writer_for_tests()


def test_an_old_database_gains_the_column_and_forces_one_full_member_refresh(old_db):
    db, path = old_db
    _seed(path, _PRE_CHANGE_SYNC_USERS)

    db.init_db()

    assert "main_account_id" in _columns(db)
    tokens = db.load_version_tokens()
    assert "membersVersion" not in tokens and "membersUpdatedAfter" not in tokens, (
        "the cached rows are all NULL and the backend's membersVersion does not change "
        "because a client upgraded -- without dropping it they would stay NULL"
    )
    assert tokens.get("devicesVersion") == "2:2026-09-01", "other sections keep their tokens"

    # The pre-existing row survived and reads back with no person yet.
    [row] = db.list_sync_users_by_active_membership_ids([31000])
    assert row["mainAccountId"] is None


def test_the_forced_refresh_actually_reaches_the_backend_request_in_full_mode(old_db):
    """Evidence that it TRIGGERS, not merely that a row was deleted: the tokens the sync tick
    loads are what MonClubApi.get_sync_data sends, and without membersVersion /
    membersUpdatedAfter the request asks for the FULL member list."""
    db, path = old_db
    _seed(path, _PRE_CHANGE_SYNC_USERS)
    db.init_db()

    from app.api.monclub_api import MonClubApi
    from app.core.sync_scope import apply_trigger_hint_to_version_tokens

    sent: Dict[str, Any] = {}

    class _Resp:
        status_code = 200
        text = "{}"

        @staticmethod
        def json():
            return {}

    api = MonClubApi.__new__(MonClubApi)
    api.endpoints = SimpleNamespace(sync_url="https://backend.invalid/manager/gym/access/v1/sync")
    api.logger = SimpleNamespace(info=lambda *a, **k: None, debug=lambda *a, **k: None,
                                 warning=lambda *a, **k: None)
    api._session = SimpleNamespace(get=lambda url, params, headers, timeout: (sent.update(params), _Resp)[1])

    version_tokens = apply_trigger_hint_to_version_tokens(db.load_version_tokens(), None)
    api.get_sync_data(token="t", version_tokens=version_tokens)

    assert "membersVersion" not in sent and "membersUpdatedAfter" not in sent
    assert sent.get("devicesVersion") == "2:2026-09-01"

    # The backend's FULL answer then fills the column through the per-row diff.
    db.save_sync_cache_delta(_payload([_ali()]), _MEMBERS_ONLY)
    [row] = db.list_sync_users_by_active_membership_ids([31000])
    assert row["mainAccountId"] == 5


def test_the_refresh_is_forced_once_not_on_every_start(old_db):
    db, path = old_db
    _seed(path, _PRE_CHANGE_SYNC_USERS)
    db.init_db()
    db.save_version_tokens({"membersVersion": "1080:new", "membersUpdatedAfter": "2026-09-12T10:00:00"})

    db.init_db()

    tokens = db.load_version_tokens()
    assert tokens.get("membersVersion") == "1080:new"
    assert tokens.get("membersUpdatedAfter") == "2026-09-12T10:00:00"


def test_the_column_and_the_token_drop_commit_together(old_db):
    """A crash between the two must not leave the column added with the tokens intact --
    that state never forces the refresh again."""
    db, path = old_db
    _seed(path, _PRE_CHANGE_SYNC_USERS)

    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    assert db._ensure_main_account_id_column(conn) is True
    conn.rollback()                      # the "crash": nothing committed
    conn.close()

    conn = sqlite3.connect(str(path))
    cols = [r[1] for r in conn.execute("PRAGMA table_info(sync_users)").fetchall()]
    keys = {r[0] for r in conn.execute("SELECT key FROM sync_version_tokens").fetchall()}
    conn.close()
    assert "main_account_id" not in cols
    assert {"membersVersion", "membersUpdatedAfter"} <= keys


def test_a_legacy_database_is_rebuilt_without_losing_a_column(old_db):
    """_rebuild_sync_users_without_legacy_fingerprint re-creates sync_users from a hardcoded
    column list. Every column a writer names must exist after init_db -- including
    main_account_id -- or the next member write fails."""
    db, path = old_db
    _seed(path, _LEGACY_SYNC_USERS)

    db.init_db()

    cols = _columns(db)
    assert "fingerprint" not in cols
    for col in ("fingerprints_json", "birthday", "image_source", "user_image_status",
                "user_profile_image", "main_account_id"):
        assert col in cols, f"{col} was dropped by the legacy rebuild"
    assert "membersVersion" not in db.load_version_tokens()

    [row] = db.list_sync_users_by_active_membership_ids([31000])
    assert row["fullName"] == "Ali"

    for write in (_write_delta_full_mode, _write_upsert_delta_users):
        write(db, [_ali(), _sonia()])
        assert _pins(_cached_users(db), "ACCOUNT") == {"5": "Ali", "777": "Sonia"}


def test_the_rebuild_keeps_a_main_account_id_that_is_already_there(tmp_path):
    """Belt and braces: the rebuild's column list names main_account_id, so even a table
    that somehow carries both the legacy column and the new one keeps its people."""
    import app.core.db as db_module

    conn = sqlite3.connect(str(tmp_path / "both.db"))
    conn.row_factory = sqlite3.Row
    conn.execute(_LEGACY_SYNC_USERS)
    conn.execute("ALTER TABLE sync_users ADD COLUMN main_account_id INTEGER")
    conn.execute("INSERT INTO sync_users (user_id, active_membership_id, main_account_id) "
                 "VALUES (900, 31000, 5)")
    db_module._rebuild_sync_users_without_legacy_fingerprint(conn)
    got = conn.execute("SELECT main_account_id FROM sync_users").fetchone()[0]
    conn.close()
    assert got == 5

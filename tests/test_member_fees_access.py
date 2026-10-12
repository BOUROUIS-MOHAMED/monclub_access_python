"""Member fees F3c: a member's fee lines and the gym's feeDueSoonDays survive the SQLite cache,
through the REAL db functions (guide §3.12).

Contract (backend member fees F3 §1b): a users[] row may carry
``fees: [{name, dueDate, required, paid}]`` -- only fees not cancelled, not paused, not settled;
absent or null when the member has none. The PC stores them in ``sync_users.fees_json`` and hands
them back through ``_coerce_user_row_to_payload`` as ``fees`` (a list, [] when none). The gym's
``accessSoftwareSettings.feeDueSoonDays`` lands in ``sync_access_software_settings.fee_due_soon_days``.

The writers are the five production paths ``test_account_pin_sqlite_roundtrip.py`` drives.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List

import pytest

CASIER = {"name": "Casier", "dueDate": "2026-10-12", "required": False, "paid": True}
BADGE = {"name": "Carte badge", "dueDate": "2026-10-01", "required": True, "paid": False}


def _payload(users, *, delta=False, valid_ids=None, settings=None) -> Dict[str, Any]:
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
        "accessSoftwareSettings": settings if settings is not None else {},
    }


_NOTHING = {"members": False, "devices": False, "credentials": False, "settings": False}
_MEMBERS_ONLY = {"members": True, "devices": False, "credentials": False, "settings": False}
_SETTINGS_ONLY = {"members": False, "devices": False, "credentials": False, "settings": True}


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "fees.db"), raising=False)
    db_module.init_db()
    # sync_meta must exist for load_sync_cache, as on any gym after its first sync.
    db_module.save_sync_cache_delta(_payload([]), _NOTHING)
    db_module.invalidate_sync_cache(clear_cached=True)
    yield db_module
    db_module.invalidate_sync_cache(clear_cached=True)
    if hasattr(db_module, "_shutdown_db_writer_for_tests"):
        db_module._shutdown_db_writer_for_tests()


def _member(am_id, user_id, name, **extra) -> Dict[str, Any]:
    u = {
        "activeMembershipId": am_id, "userId": user_id, "mainAccountId": 9000 + user_id,
        "membershipId": 7, "fullName": name, "phone": None, "email": None,
        "validFrom": "2026-01-01T00:00:00", "validTo": "2026-12-31T00:00:00",
        "firstCardId": str(1000 + user_id), "secondCardId": None, "image": None,
        "fingerprints": [], "faceId": None, "accountUsernameId": None, "qrCodePayload": None,
        "birthday": None, "imageSource": None, "userImageStatus": None, "userProfileImage": None,
    }
    u.update(extra)
    return u


def _ali(**kw):
    return _member(31000, 900, "Ali", **kw)


def _sonia(**kw):
    return _member(5, 901, "Sonia", **kw)


def _write_full_replace(db, users):
    db.save_sync_cache(_payload(users))


def _write_delta_full_mode(db, users):
    db.save_sync_cache_delta(_payload(users), _MEMBERS_ONLY)


def _write_delta_mode(db, users):
    ids = [u["activeMembershipId"] for u in users]
    db.save_sync_cache_delta(_payload(users, delta=True, valid_ids=ids), _MEMBERS_ONLY)


def _write_upsert_delta_users(db, users):
    db.upsert_delta_users(users)


_PATCH_SEQ = [0]


def _write_fast_patch(db, users):
    # A new bundle id and a later revision on every call: apply_fast_patch_bundle ignores a
    # bundle it has seen and an item whose revision is not newer than the stored one.
    _PATCH_SEQ[0] += 1
    n = _PATCH_SEQ[0]
    revision = f"2026-10-11T10:{n // 60:02d}:{n % 60:02d}"
    db.apply_fast_patch_bundle({
        "bundleId": f"bundle-fees-{n}",
        "generatedAt": revision,
        "items": [
            {"kind": "ENTITY_UPSERT", "entityType": "ACTIVE_MEMBERSHIP",
             "entityId": u["activeMembershipId"], "revision": revision,
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


def _fees_by_member(db) -> Dict[int, List[Dict[str, Any]]]:
    rows = db.list_sync_users_by_active_membership_ids([31000, 5])
    return {int(r["activeMembershipId"]): r["fees"] for r in rows}


def _stored_fees_json(db, am_id):
    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT fees_json FROM sync_users WHERE active_membership_id = ?", (am_id,),
        ).fetchone()
    return row[0]


# ── the pure helpers ───────────────────────────────────────────────────────────────────────

def test_the_encoder_cleans_sorts_and_stores_null_for_no_fee():
    import app.core.db as db_module

    enc = db_module._member_fees_json
    assert enc({}) is None
    assert enc({"fees": None}) is None
    assert enc({"fees": []}) is None
    assert enc({"fees": [{"name": " "}, "x", None, 3]}) is None
    assert enc({"fees": [{"name": " Casier ", "dueDate": [2026, 10, 12], "required": True,
                          "paid": "yes"}]}) == \
        '[{"name":"Casier","dueDate":"2026-10-12","required":true,"paid":false}]'
    assert enc({"fees": [CASIER, BADGE]}) == enc({"fees": [BADGE, CASIER]}), "order-free"


def test_the_decoder_reads_a_stored_text_and_never_raises():
    import app.core.db as db_module

    dec = db_module._member_fees_list
    assert dec('[{"name":"Casier","dueDate":"2026-10-12T00:00:00"}]') == \
        [{"name": "Casier", "dueDate": "2026-10-12", "required": False, "paid": False}]
    assert dec("not json") == []
    assert dec('{"name": "Casier"}') == []
    assert dec(None) == []
    assert dec([{"name": "Casier", "dueDate": "12/10/2026"}])[0]["dueDate"] is None
    coerce = db_module._coerce_user_row_to_payload
    assert coerce({"fees_json": None})["fees"] == []
    assert coerce({"fees": [CASIER]})["fees"] == [CASIER], "a raw backend row (legacy cache path)"


# ── every write path ───────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("writer", sorted(WRITERS))
def test_every_writer_stores_the_fee_lines_and_reads_them_back(db, writer):
    WRITERS[writer](db, [_ali(fees=[CASIER, BADGE]), _sonia()])

    got = _fees_by_member(db)
    assert got[31000] == [BADGE, CASIER], "every field kept, sorted by name"
    assert got[5] == [], "a member without fees reads back as no fees"
    assert _stored_fees_json(db, 5) is None, "no fee line = NULL, the payload stays small"

    db.invalidate_sync_cache(clear_cached=True)
    cache = db.load_sync_cache()
    by_am = {int(u["activeMembershipId"]): u for u in cache.users if isinstance(u, dict)}
    assert by_am[31000]["fees"] == [BADGE, CASIER], "the engines' roster carries them too"


def test_the_full_refresh_updates_a_row_whose_only_change_is_its_fees(db):
    """A fee paid at the desk changes nothing but the fee line. If fees_json were not in the
    diffed column tuple the row would compare equal and keep showing "impayé"."""
    _write_delta_full_mode(db, [_ali(fees=[BADGE])])
    paid = dict(BADGE, paid=True, dueDate="2026-11-01")
    _write_delta_full_mode(db, [_ali(fees=[paid])])

    profile = db.get_last_db_write_profile("save_sync_cache_delta")
    assert profile["members_updated"] == 1 and profile["members_inserted"] == 0
    assert _fees_by_member(db)[31000] == [paid]


def test_the_same_fees_in_another_order_do_not_rewrite_the_row(db):
    _write_delta_full_mode(db, [_ali(fees=[CASIER, BADGE])])
    _write_delta_full_mode(db, [_ali(fees=[BADGE, CASIER])])

    profile = db.get_last_db_write_profile("save_sync_cache_delta")
    assert profile["members_unchanged"] == 1 and profile["members_updated"] == 0


def test_a_fee_that_disappears_from_the_payload_clears_the_line(db):
    """Settled or paused fees leave the payload (contract §1b): the row must forget them."""
    for writer in (_write_delta_mode, _write_fast_patch, _write_upsert_delta_users):
        writer(db, [_ali(fees=[BADGE])])
        assert _fees_by_member(db)[31000] == [BADGE]
        writer(db, [_ali()])
        assert _fees_by_member(db)[31000] == [], writer.__name__


# ── feeDueSoonDays ─────────────────────────────────────────────────────────────────────────

def test_fee_due_soon_days_is_stored_and_read_back(db):
    db.save_sync_cache_delta(_payload([], settings={"gymId": 58, "feeDueSoonDays": 14}), _SETTINGS_ONLY)
    assert db.load_sync_access_software_settings()["feeDueSoonDays"] == 14

    db.save_sync_cache(_payload([], settings={"gymId": 58, "feeDueSoonDays": 3}))
    assert db.load_sync_access_software_settings()["feeDueSoonDays"] == 3


def test_the_reader_clamps_like_the_backend_and_defaults_to_seven():
    from app.core.settings_reader import normalize_global_settings as norm

    assert norm({})["fee_due_soon_days"] == 7
    assert norm({"feeDueSoonDays": None})["fee_due_soon_days"] == 7
    assert norm({"feeDueSoonDays": 14})["fee_due_soon_days"] == 14
    assert norm({"feeDueSoonDays": 0})["fee_due_soon_days"] == 1
    assert norm({"feeDueSoonDays": 90})["fee_due_soon_days"] == 30


# ── the upgrade: one forced refresh of members and settings ───────────────────────────────

_OLD_SYNC_USERS = """
    CREATE TABLE sync_users (
        user_id INTEGER, active_membership_id INTEGER, membership_id INTEGER,
        full_name TEXT, phone TEXT, email TEXT, valid_from TEXT, valid_to TEXT,
        first_card_id TEXT, second_card_id TEXT, image TEXT, fingerprints_json TEXT,
        face_id TEXT, account_username_id TEXT, qr_code_payload TEXT, birthday TEXT,
        image_source TEXT, user_image_status TEXT, user_profile_image TEXT, main_account_id INTEGER
    )
"""


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


def _seed_pre_fees_database(path):
    """A database written by the client before F3c: main_account_id already there, no fees_json,
    a settings row without fee_due_soon_days, and the four section tokens of a synced PC."""
    conn = sqlite3.connect(str(path))
    conn.execute(_OLD_SYNC_USERS)
    conn.execute(
        "INSERT INTO sync_users (user_id, active_membership_id, membership_id, full_name, "
        "main_account_id) VALUES (900, 31000, 7, 'Ali', 9900)"
    )
    conn.execute("CREATE TABLE sync_access_software_settings (id INTEGER PRIMARY KEY CHECK (id=1), gym_id INTEGER)")
    conn.execute("INSERT INTO sync_access_software_settings (id, gym_id) VALUES (1, 58)")
    conn.execute("CREATE TABLE sync_version_tokens (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.executemany(
        "INSERT INTO sync_version_tokens (key, value) VALUES (?, ?)",
        [("membersVersion", "1080:x"), ("membersUpdatedAfter", "2026-10-10T09:00:00"),
         ("devicesVersion", "2:2026-10-01"), ("settingsVersion", "s-1")],
    )
    conn.commit()
    conn.close()


def test_an_upgraded_database_gains_both_columns_and_refetches_members_and_settings_once(old_db):
    db, path = old_db
    _seed_pre_fees_database(path)

    db.init_db()

    tokens = db.load_version_tokens()
    assert "membersVersion" not in tokens and "membersUpdatedAfter" not in tokens, (
        "the backend's membersVersion does not move because a client upgraded: without the drop "
        "every cached member would show no fee until something else re-sent the row"
    )
    assert "settingsVersion" not in tokens, "same for feeDueSoonDays"
    assert tokens.get("devicesVersion") == "2:2026-10-01", "other sections keep their tokens"
    [row] = db.list_sync_users_by_active_membership_ids([31000])
    assert row["fullName"] == "Ali" and row["fees"] == []
    assert db.load_sync_access_software_settings()["feeDueSoonDays"] is None

    db.save_version_tokens({"membersVersion": "1081:y", "settingsVersion": "s-2"})
    db.init_db()
    tokens = db.load_version_tokens()
    assert tokens.get("membersVersion") == "1081:y" and tokens.get("settingsVersion") == "s-2", (
        "ONE-SHOT: the next start keeps the tokens"
    )


def test_the_helper_drops_only_the_named_tokens_and_only_once():
    import app.core.db as db_module

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE t (a INTEGER)")
    conn.execute("CREATE TABLE sync_version_tokens (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.executemany("INSERT INTO sync_version_tokens VALUES (?, ?)",
                     [("membersVersion", "m"), ("membersUpdatedAfter", "u"), ("devicesVersion", "d")])

    def keys():
        return {r[0] for r in conn.execute("SELECT key FROM sync_version_tokens").fetchall()}

    helper = db_module._ensure_column_forcing_refresh
    assert helper(conn, "t", "b", "b TEXT", ("membersVersion", "membersUpdatedAfter")) is True
    assert keys() == {"devicesVersion"}
    assert "b" in {r[1] for r in conn.execute("PRAGMA table_info(t)").fetchall()}

    conn.execute("INSERT INTO sync_version_tokens VALUES ('membersVersion', 'm2')")
    assert helper(conn, "t", "b", "b TEXT", ("membersVersion",)) is False, "one-shot"
    assert helper(conn, "missing", "b", "b TEXT", ("devicesVersion",)) is False, "no table, no drop"
    assert keys() == {"devicesVersion", "membersVersion"}
    conn.close()


def test_the_column_and_the_token_drop_commit_together(old_db):
    """A crash between the DELETE and the ALTER must not leave the column added with the tokens
    intact -- that state would never force the refresh again (same claim as guide §3.2d)."""
    db, path = old_db
    _seed_pre_fees_database(path)

    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    assert db._ensure_column_forcing_refresh(
        conn, "sync_users", "fees_json", "fees_json TEXT", db._MEMBER_VERSION_TOKEN_KEYS,
    ) is True
    conn.rollback()                      # the "crash": nothing committed
    conn.close()

    conn = sqlite3.connect(str(path))
    cols = [r[1] for r in conn.execute("PRAGMA table_info(sync_users)").fetchall()]
    keys = {r[0] for r in conn.execute("SELECT key FROM sync_version_tokens").fetchall()}
    conn.close()
    assert "fees_json" not in cols
    assert {"membersVersion", "membersUpdatedAfter"} <= keys

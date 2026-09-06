"""FULL member refresh (membersDeltaMode=False) is a per-row diff of sync_users.

WHY THIS FILE EXISTS
--------------------
`save_sync_cache_delta` full-replace mode used to hash the whole table and, whenever the
hash differed, run ``DELETE FROM sync_users`` + a re-INSERT of every row: 4765 ms for
934 rows on the OXYGENE_FIT PC (2026-08-30 log), most of it re-writing ~2 MB of
fingerprint templates that had not changed. That path runs on every FULL refresh against
a populated cache: the manual-mode "Sync data" click, the 22:00 daily sync, hard reset.

It is now a per-row diff keyed on the PAIR ``(user_id, active_membership_id)`` (the
partial UNIQUE index ``uq_sync_users_uid_amid``): new keys are inserted, changed rows are
updated in place, identical rows are untouched, and keys absent from the payload are
deleted. The delete step MUST derive from the incoming key set, because the backend sends
``validMemberIds = null`` in full mode.

FAILURE MODE THESE TESTS GUARD: a wrong delete-absent (or a missed one) leaves an
ex-member's card admitted at the turnstile (access_verification reads this table) and
their pin in every device roster. Every test patches ``app.core.db._DB_PATH`` to a temp
file.
"""

from __future__ import annotations

import json

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "test.db"), raising=False)
    db_module.init_db()
    yield db_module
    if hasattr(db_module, "_shutdown_db_writer_for_tests"):
        db_module._shutdown_db_writer_for_tests()


_REFRESH = {"members": True, "devices": False, "credentials": False, "settings": False}

_TEMPLATE_A = {"id": 1, "fingerId": 0, "templateVersion": 10, "templateEncoding": "BASE64",
               "templateData": "AAAA" * 200, "templateSize": 800, "enabled": True}
_TEMPLATE_B = {"id": 2, "fingerId": 1, "templateVersion": 10, "templateEncoding": "BASE64",
               "templateData": "BBBB" * 200, "templateSize": 800, "enabled": True}


def _user(am_id, user_id, *, name="Alice", card="1000", membership_id=50, fps=None, **extra):
    u = {
        "activeMembershipId": am_id,
        "userId": user_id,
        "membershipId": membership_id,
        "fullName": name,
        "phone": "0600000000",
        "email": f"u{user_id}@example.com",
        "validFrom": "2026-01-01",
        "validTo": "2026-12-31",
        "firstCardId": card,
        "secondCardId": None,
        "image": None,
        "fingerprints": fps if fps is not None else [],
        "faceId": None,
        "accountUsernameId": None,
        "qrCodePayload": None,
        "birthday": None,
        "imageSource": None,
        "userImageStatus": None,
        # NOTE: no "userProfileImage" key on purpose -- the backend may omit it, and the
        # old whole-table hash compared that omission ('') against the stored NULL.
    }
    u.update(extra)
    return u


def _full_payload(users):
    """What the backend sends in full mode: membersDeltaMode=False, validMemberIds=null."""
    return {
        "users": users,
        "membersDeltaMode": False,
        "validMemberIds": None,
        "devices": [],
        "gymAccessCredentials": [],
        "infrastructures": [],
        "membership": [],
        "contractStatus": True,
        "contractEndDate": "2026-12-31",
        "accessSoftwareSettings": {},
    }


def _refresh(db, users):
    db.save_sync_cache_delta(_full_payload(users), _REFRESH)
    return db.get_last_db_write_profile("save_sync_cache_delta")


def _rows(db) -> dict:
    """{(user_id, active_membership_id): {rowid, name, card, fps}} -- NULL keys included."""
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT rowid, user_id, active_membership_id, full_name, first_card_id, "
            "fingerprints_json, membership_id FROM sync_users"
        ).fetchall()
    out = {}
    for r in rows:
        key = (r[1], r[2])
        assert key not in out or key[0] is None or key[1] is None, f"duplicate key {key}"
        out.setdefault(key, []).append({
            "rowid": r[0], "name": r[3], "card": r[4],
            "fps": json.loads(r[5] or "[]"), "membership_id": r[6],
        })
    return out


def _one(rows, key):
    assert len(rows[key]) == 1, f"expected one row for {key}, got {rows[key]}"
    return rows[key][0]


def _counters(profile) -> dict:
    return {
        k: profile[k]
        for k in ("members_inserted", "members_updated", "members_unchanged",
                  "members_deleted", "members_null_key_rows")
    }


# --------------------------------------------------------------------------- basics

def test_first_full_refresh_inserts_everything(db):
    profile = _refresh(db, [_user(1, 100), _user(2, 200), _user(3, 300)])

    assert set(_rows(db)) == {(100, 1), (200, 2), (300, 3)}
    assert _counters(profile) == {
        "members_inserted": 3, "members_updated": 0, "members_unchanged": 0,
        "members_deleted": 0, "members_null_key_rows": 0,
    }
    for key in ("members_existing_fetch_ms", "members_diff_ms", "members_write_ms", "members_delete_ms"):
        assert float(profile[key]) >= 0.0


def test_unchanged_rows_are_untouched_and_keep_their_rowid(db):
    users = [_user(1, 100, fps=[_TEMPLATE_A]), _user(2, 200), _user(3, 300)]
    _refresh(db, users)
    before = _rows(db)

    profile = _refresh(db, users)

    after = _rows(db)
    assert after == before
    assert _counters(profile) == {
        "members_inserted": 0, "members_updated": 0, "members_unchanged": 3,
        "members_deleted": 0, "members_null_key_rows": 0,
    }


def test_changed_row_is_rewritten_in_place_others_untouched(db):
    _refresh(db, [_user(1, 100), _user(2, 200, card="2000"), _user(3, 300)])
    before = _rows(db)

    profile = _refresh(db, [_user(1, 100), _user(2, 200, card="2000-NEW", name="Bob"), _user(3, 300)])

    after = _rows(db)
    assert _counters(profile)["members_updated"] == 1
    assert _counters(profile)["members_unchanged"] == 2
    assert _one(after, (200, 2))["card"] == "2000-NEW"
    assert _one(after, (200, 2))["name"] == "Bob"
    assert _one(after, (200, 2))["rowid"] == _one(before, (200, 2))["rowid"], "UPDATE in place"
    assert _one(after, (100, 1)) == _one(before, (100, 1))
    assert _one(after, (300, 3)) == _one(before, (300, 3))


def test_template_change_alone_is_detected(db):
    """The MB2000 push reads templates from this table: a re-enrolled finger must land."""
    _refresh(db, [_user(1, 100, fps=[_TEMPLATE_A])])
    before = _rows(db)

    profile = _refresh(db, [_user(1, 100, fps=[_TEMPLATE_A, _TEMPLATE_B])])

    after = _rows(db)
    assert _counters(profile)["members_updated"] == 1
    assert [f["fingerId"] for f in _one(after, (100, 1))["fps"]] == [0, 1]
    assert _one(after, (100, 1))["rowid"] == _one(before, (100, 1))["rowid"]


# --------------------------------------------------------------------------- delete-absent

def test_absent_row_is_deleted_from_the_incoming_key_set_not_valid_member_ids(db):
    """Full mode carries validMemberIds=null; the ex-member must still disappear."""
    _refresh(db, [_user(1, 100, card="1001"), _user(2, 200, card="2002"), _user(3, 300, card="3003")])
    before = _rows(db)

    payload = _full_payload([_user(1, 100, card="1001"), _user(3, 300, card="3003")])
    assert payload["validMemberIds"] is None
    db.save_sync_cache_delta(payload, _REFRESH)
    profile = db.get_last_db_write_profile("save_sync_cache_delta")

    after = _rows(db)
    assert set(after) == {(100, 1), (300, 3)}
    assert _counters(profile)["members_deleted"] == 1
    assert _counters(profile)["members_unchanged"] == 2
    assert _one(after, (100, 1))["rowid"] == _one(before, (100, 1))["rowid"]
    assert _one(after, (300, 3))["rowid"] == _one(before, (300, 3))["rowid"]
    # The turnstile-relevant view: the ex-member's card no longer resolves.
    cards = {u["firstCardId"] for u in db.list_sync_users()}
    assert "2002" not in cards


def test_user_with_superseded_and_current_membership_keeps_both_rows(db):
    """The backend ships both rows for such members; keying on user_id alone would
    collapse them and drop the current membership's card."""
    both = [_user(1, 100, card="OLD", membership_id=50), _user(2, 100, card="NEW", membership_id=51)]
    _refresh(db, both)
    assert set(_rows(db)) == {(100, 1), (100, 2)}

    profile = _refresh(db, both)
    assert _counters(profile)["members_unchanged"] == 2
    assert _counters(profile)["members_deleted"] == 0

    # Once the backend stops sending the superseded row it -- and only it -- goes.
    before = _rows(db)
    profile = _refresh(db, [_user(2, 100, card="NEW", membership_id=51)])
    after = _rows(db)
    assert set(after) == {(100, 2)}
    assert _counters(profile)["members_deleted"] == 1
    assert _one(after, (100, 2))["rowid"] == _one(before, (100, 2))["rowid"]


def test_membership_id_fallback_is_part_of_the_key(db):
    """A member without activeMembershipId is stored with membershipId in that column
    (the INSERT fallback). The diff must key on the STORED value or every refresh would
    insert a duplicate and delete the previous row."""
    _refresh(db, [_user(None, 100, membership_id=50)])
    before = _rows(db)
    assert set(before) == {(100, 50)}

    profile = _refresh(db, [_user(None, 100, membership_id=50)])

    after = _rows(db)
    assert after == before
    assert _counters(profile)["members_unchanged"] == 1


# --------------------------------------------------------------------------- NULL keys

def test_null_key_rows_are_not_duplicated_across_refreshes(db):
    payload = [
        _user(None, 100, membership_id=None),   # active_membership_id NULL
        _user(7, None),                          # user_id NULL
        _user(2, 200),
    ]
    _refresh(db, payload)
    profile = _refresh(db, payload)
    _refresh(db, payload)

    rows = _rows(db)
    assert len(rows[(100, None)]) == 1
    assert len(rows[(None, 7)]) == 1
    assert len(rows[(200, 2)]) == 1
    with db.get_conn() as conn:
        assert int(conn.execute("SELECT COUNT(*) FROM sync_users").fetchone()[0]) == 3
    # NULL-key rows sit outside the unique index and cannot be diffed: they are
    # rewritten (deleted + re-inserted) on every full refresh, and reported as such.
    assert _counters(profile)["members_null_key_rows"] == 2
    assert _counters(profile)["members_unchanged"] == 1


def test_null_key_rows_absent_from_the_payload_are_dropped(db):
    _refresh(db, [_user(None, 100, membership_id=None), _user(2, 200)])

    _refresh(db, [_user(2, 200)])

    assert set(_rows(db)) == {(200, 2)}


# --------------------------------------------------------------------------- guards

def test_zero_users_guard_refuses_to_clear_a_populated_cache(db):
    """H-006: refreshMembers=True with users=[] against a cache of > 10 rows is a backend
    error, not a gym that lost every member."""
    seed = [_user(i, 100 + i) for i in range(1, 12)]
    _refresh(db, seed)
    before = _rows(db)

    _refresh(db, [])

    assert _rows(db) == before


def test_zero_users_with_a_small_cache_clears_it(db):
    """The documented 'H-006 NOT triggered' path (<= 10 rows) still empties the table."""
    _refresh(db, [_user(1, 100), _user(2, 200)])

    profile = _refresh(db, [])

    assert _rows(db) == {}
    assert _counters(profile)["members_deleted"] == 2


def test_duplicate_key_inside_one_payload_last_wins_single_row(db):
    """INSERT OR REPLACE semantics of the old path: the last occurrence of a key wins."""
    _refresh(db, [_user(1, 100, name="First"), _user(1, 100, name="Last")])

    rows = _rows(db)
    assert set(rows) == {(100, 1)}
    assert _one(rows, (100, 1))["name"] == "Last"


# --------------------------------------------------------------------------- normalisation

def test_values_that_sqlite_stores_identically_compare_equal(db):
    """TEXT-affinity columns hand back str, INTEGER-affinity columns hand back int; the
    payload may carry either. Without normalisation every row would look changed and the
    diff would degrade to a full rewrite."""
    _refresh(db, [_user(1, 100, card="1000", membership_id=50)])
    before = _rows(db)

    profile = _refresh(db, [_user("1", "100", card=1000, membership_id="50")])

    assert _rows(db) == before
    assert _counters(profile) == {
        "members_inserted": 0, "members_updated": 0, "members_unchanged": 1,
        "members_deleted": 0, "members_null_key_rows": 0,
    }


def test_missing_user_profile_image_key_does_not_look_like_a_change(db):
    """The old whole-table hash defaulted a missing userProfileImage to '' but the row
    stored NULL, so the guard never matched and every full refresh rewrote the table."""
    _refresh(db, [_user(1, 100)])  # no userProfileImage key

    profile = _refresh(db, [_user(1, 100)])

    assert _counters(profile)["members_unchanged"] == 1
    assert _counters(profile)["members_updated"] == 0

    profile = _refresh(db, [_user(1, 100, userProfileImage="https://cdn/x.png")])
    assert _counters(profile)["members_updated"] == 1


# --------------------------------------------------------------------------- interop

def test_full_refresh_after_a_delta_upsert_sees_no_change(db):
    """Delta mode still uses INSERT OR REPLACE (new rowid); the full diff keys on the
    pair, not the rowid, so the two modes interoperate."""
    _refresh(db, [_user(1, 100), _user(2, 200)])
    db.upsert_delta_users([_user(2, 200, name="Renamed")])

    profile = _refresh(db, [_user(1, 100), _user(2, 200, name="Renamed")])

    assert _counters(profile)["members_unchanged"] == 2
    assert _counters(profile)["members_updated"] == 0


def test_full_refresh_still_bumps_local_state_generation_when_nothing_changed(db):
    """ULTRA workers reload their (creds, users) cache on a generation bump; the bump is
    unconditional and the diff must not change that."""
    _refresh(db, [_user(1, 100)])
    gen_before = db.get_local_state_generation() if hasattr(db, "get_local_state_generation") else None
    if gen_before is None:
        pytest.skip("no generation getter exposed")

    _refresh(db, [_user(1, 100)])

    assert db.get_local_state_generation() > gen_before


# --------------------------------------------------------------------------- SQL arity

def test_full_refresh_statements_bind_every_column(db):
    """The INSERT/UPDATE are LITERAL statements inside _apply_full_users_refresh (so
    tools/check_sql_arity.py, the release gate, verifies them) and must bind exactly the
    19 values _sync_user_row_values produces, in _SYNC_USER_COLUMNS order (the v1.4.20
    59/57 INSERT is why this is pinned)."""
    import inspect
    import re

    src = inspect.getsource(db._apply_full_users_refresh)
    values = db._sync_user_row_values({})
    assert len(values) == len(db._SYNC_USER_COLUMNS) == 19

    insert = re.search(r"INSERT INTO sync_users\s*\((.*?)\)\s*VALUES\s*\((.*?)\)", src, re.S)
    assert insert, "literal INSERT not found in _apply_full_users_refresh"
    assert [c.strip() for c in insert.group(1).split(",")] == list(db._SYNC_USER_COLUMNS)
    assert insert.group(2).count("?") == 19

    update = re.search(r"UPDATE sync_users SET(.*?)WHERE rowid=\?", src, re.S)
    assert update, "literal UPDATE not found in _apply_full_users_refresh"
    assignments = [a.strip() for a in update.group(1).split(",")]
    assert [a.split("=")[0] for a in assignments] == list(db._SYNC_USER_COLUMNS)
    assert all(a.endswith("=?") for a in assignments)


def test_affinity_normaliser_matches_sqlite_storage_rules(db):
    """The diff compares payload values to stored values after this normalisation; the
    cases here are the ones SQLite's INTEGER/TEXT affinity conversion defines."""
    n = db._sqlite_affinity_norm
    # INTEGER affinity (the three ids)
    assert n(None, integer=True) is None
    assert n(100, integer=True) == 100
    assert n("100", integer=True) == 100
    assert n(" 100 ", integer=True) == 100
    assert n("-7", integer=True) == -7
    assert n(1000.0, integer=True) == 1000
    assert n("1000.0", integer=True) == 1000
    assert n("1e3", integer=True) == 1000
    assert n(1.5, integer=True) == 1.5
    assert n("1.5", integer=True) == 1.5
    assert n("abc", integer=True) == "abc"
    assert n("", integer=True) == ""
    assert n(True, integer=True) == 1
    # TEXT affinity (everything else)
    assert n(None, integer=False) is None
    assert n("x", integer=False) == "x"
    assert n(1000, integer=False) == "1000"
    assert n(True, integer=False) == "1"
    assert n(1.5, integer=False) == "1.5"


def test_numeric_text_ids_do_not_break_the_diff(db):
    """An id that arrives as numeric text must match the stored INTEGER row instead of
    being inserted as a second row (which the UNIQUE index would reject loudly)."""
    # email is pinned: the helper derives it from the id, and "1e3" is not "1000" as text.
    _refresh(db, [_user(1, 1000, card="1000", email="m@example.com")])
    before = _rows(db)

    profile = _refresh(db, [_user("1", "1e3", card="1000", email="m@example.com")])

    assert _rows(db) == before
    assert _counters(profile)["members_unchanged"] == 1


# ── the H-006 refusal must skip ONLY the members section ────────────────────
#
# WHY THIS BLOCK EXISTS
# ---------------------
# The H-006 guard above refuses `users == []` against a cache of > 10 rows by
# `return {"credentials": None}` -- a return out of the whole `_write` callable.
# `_db_writer_loop` commits on a NORMAL return (only a raised exception rolls
# back), so the refusal committed everything that had already run and silently
# skipped every section that sits AFTER the members block in the same function:
# devices (+ door presets), gymAccessCredentials, and infrastructures.
#
# The caller cannot see it: `save_sync_cache_delta` returns None on every path,
# and `app/ui/app.py` runs `if new_tokens: save_version_tokens(new_tokens)`
# unconditionally afterwards. The four refresh flags are independent booleans off
# the backend response, so refreshMembers=True can legitimately arrive alongside
# refreshDevices / refreshCredentials / refreshSettings = True. One response with
# `users: []` therefore preserved the roster (correct) while dropping that same
# response's device, credential and infrastructure updates -- and advanced the
# version tokens, so the backend never resends them. Lost until a full
# token-clearing resync.
#
# `settings` is the sharpest case: it gates TWO sections that sit on opposite
# sides of the members block (settings row + memberships before, infrastructures
# after), so one boolean was half-applied.
#
# Mirrors the delta branch's policy from a0b527a -- skip only the refused
# operation, let the rest of the transaction commit, report the refusal in the
# write profile.

_ALL_SECTIONS = {"members": True, "devices": True, "credentials": True, "settings": True}

_SETTINGS_ROW = {
    "gymId": 58, "accessServerHost": "10.0.0.5", "accessServerPort": 8080,
    "accessServerEnabled": True, "createdAt": "2026-09-06T00:00:00Z",
    "updatedAt": "2026-09-06T00:00:00Z",
}


def _credential(cred_id=1, account_id=10):
    return {
        "id": cred_id, "gymId": 58, "accountId": account_id, "secretHex": "abc123",
        "enabled": True, "rotatedAt": "2026-04-01T00:00:00",
        "createdAt": "2026-04-01T00:00:00", "updatedAt": "2026-04-01T00:00:00",
        "grantedActiveMembershipIds": [account_id],
    }


def _loaded_payload(users):
    """A full-mode payload that also carries every non-members section, as a response
    with all four refresh flags set does."""
    payload = _full_payload(users)
    payload["devices"] = [{"id": 9, "name": "Turnstile A"}]
    payload["gymAccessCredentials"] = [_credential()]
    payload["infrastructures"] = [{"id": 3, "name": "Main", "gymAgent": {}}]
    payload["membership"] = [{"id": 7, "title": "Gold", "description": "d",
                              "price": 99.0, "durationInDays": 30}]
    payload["accessSoftwareSettings"] = dict(_SETTINGS_ROW)
    return payload


def _seed_11(db):
    """11 cached members -- one over _H006_MIN_CACHE_ROWS, so the guard fires. Seeded
    with a members-ONLY refresh, so the other tables are still empty."""
    _refresh(db, [_user(i, 100 + i) for i in range(1, 12)])
    return _rows(db)


def _section_counts(db):
    with db.get_conn() as conn:
        def _n(table):
            return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        return {
            "sync_devices": _n("sync_devices"),
            "sync_gym_access_credentials": _n("sync_gym_access_credentials"),
            "sync_infrastructures": _n("sync_infrastructures"),
            "sync_memberships": _n("sync_memberships"),
        }


def test_zero_users_refusal_still_commits_devices_credentials_infrastructures(db):
    """The refusal must cost the members section and nothing else. Before the fix the
    early return dropped devices, credentials and infrastructures on the floor while
    the same response's version tokens advanced."""
    before = _seed_11(db)

    db.save_sync_cache_delta(_loaded_payload([]), _ALL_SECTIONS)

    assert _rows(db) == before  # the refusal itself still holds
    assert _section_counts(db) == {
        "sync_devices": 1,
        "sync_gym_access_credentials": 1,
        "sync_infrastructures": 1,
        "sync_memberships": 1,
    }


def test_zero_users_refusal_does_not_half_apply_the_settings_refresh(db):
    """`settings` writes the settings row + memberships BEFORE the members block and
    infrastructures AFTER it. The early return committed the first half and skipped
    the second, from a single refreshSettings=True."""
    _seed_11(db)

    db.save_sync_cache_delta(_loaded_payload([]), _ALL_SECTIONS)

    with db.get_conn() as conn:
        host = conn.execute(
            "SELECT access_server_host FROM sync_access_software_settings WHERE id=1"
        ).fetchone()[0]
        infrastructures = conn.execute("SELECT COUNT(*) FROM sync_infrastructures").fetchone()[0]
    assert host == "10.0.0.5"    # committed even before the fix
    assert infrastructures == 1  # skipped before the fix -- the other half of one flag


def test_zero_users_refusal_is_reported_in_the_write_profile(db):
    """The refusal must be visible to whoever reads the profile -- it is the only
    signal that a section of an otherwise-successful sync was declined."""
    _seed_11(db)

    db.save_sync_cache_delta(_loaded_payload([]), _ALL_SECTIONS)
    profile = db.get_last_db_write_profile("save_sync_cache_delta")

    assert profile["members_full_refresh_refused"] is True
    assert profile["members_full_refresh_refused_count"] == 11
    # The per-row diff never ran. Its counters must be ABSENT, not synthesised as
    # zeros: "members_unchanged: 0" would be false -- 11 rows were left untouched.
    assert "members_unchanged" not in profile
    assert "members_deleted" not in profile
    # The sections that DID run still report theirs.
    assert profile["credentials_upserted"] == 1


def test_healthy_full_refresh_reports_no_refusal(db):
    """The flag is written on every full-mode call, so a reader never has to tell
    'not refused' apart from 'key missing'."""
    profile = _refresh(db, [_user(1, 100)])

    assert profile["members_full_refresh_refused"] is False
    assert profile["members_full_refresh_refused_count"] == 0


def test_zero_users_below_the_threshold_clears_and_reports_no_refusal(db):
    """The documented 'H-006 NOT triggered' path (<= 10 rows) is untouched: it clears
    the roster, and it is not a refusal."""
    _refresh(db, [_user(i, 100 + i) for i in range(1, 11)])  # exactly 10

    db.save_sync_cache_delta(_loaded_payload([]), _ALL_SECTIONS)
    profile = db.get_last_db_write_profile("save_sync_cache_delta")

    assert _rows(db) == {}
    assert profile["members_full_refresh_refused"] is False
    assert profile["members_full_refresh_refused_count"] == 0
    assert _counters(profile)["members_deleted"] == 10
    assert _section_counts(db)["sync_devices"] == 1


def test_zero_users_refusal_leaves_the_delta_branch_keys_alone(db):
    """The two branches report separately: a full-mode refusal must not masquerade as
    the delta branch's members_delete_refused, and vice versa."""
    _seed_11(db)

    db.save_sync_cache_delta(_loaded_payload([]), _ALL_SECTIONS)
    profile = db.get_last_db_write_profile("save_sync_cache_delta")

    assert profile["members_delta_mode"] is False
    assert "members_delete_refused" not in profile

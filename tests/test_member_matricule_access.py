"""Member numbers survive cache writes, refreshes and held-row restores."""
import sqlite3

import pytest

from test_member_fees_access import (
    WRITERS, _ali, _seed_pre_fees_database, db, old_db,
)
from test_protocol2_save_and_flip import MEMBERS_ONLY, _flip, _row, _v2


@pytest.mark.parametrize("writer", sorted(WRITERS))
def test_every_writer_round_trips_and_corrects_the_number(db, writer):
    write = WRITERS[writer]
    for number in (42, 43, None):
        write(db, [_ali(matricule=number)])
        [member] = db.list_sync_users_by_active_membership_ids([31000])
        assert member["matricule"] == number
        [row], total, _ = db.list_members_roster()
        assert total == 1 and row["matricule"] == number
        db.invalidate_sync_cache(clear_cached=True)
        assert db.load_sync_cache().users[0]["matricule"] == number


@pytest.mark.parametrize("extra, expected", [
    ({}, None), ({"matricule": None}, None), ({"matricule": "abc"}, None),
    ({"matricule": 0}, None), ({"matricule": -1}, None),
    ({"matricule": True}, None), ({"matricule": False}, None),
    ({"matricule": 42.5}, None), ({"matricule": " 0042 "}, 42),
])
def test_invalid_or_missing_numbers_read_as_null(db, extra, expected):
    WRITERS["save_sync_cache"](db, [_ali(**extra)])
    [member] = db.list_sync_users_by_active_membership_ids([31000])
    assert member["matricule"] == expected


def test_number_only_changes_rewrite_the_cached_row(db):
    write = WRITERS["save_sync_cache_delta:full"]
    write(db, [_ali(matricule=42)])
    write(db, [_ali(matricule=43)])
    assert db.get_last_db_write_profile("save_sync_cache_delta")["members_updated"] == 1
    write(db, [_ali(matricule="0043")])
    assert db.get_last_db_write_profile("save_sync_cache_delta")["members_unchanged"] == 1


def test_protocol2_hold_restore_and_number_correction(db):
    member = _row(2, off=["2026-09-20"], matricule=42)
    db.save_sync_cache_delta(_v2([member]), MEMBERS_ONLY)
    _flip(db, "2026-09-20T07:30:00+01:00")
    with db.get_conn() as conn:
        assert conn.execute("SELECT matricule FROM sync_users_held").fetchone()[0] == 42
    [held], _, _ = db.list_members_roster()
    assert held["matricule"] == 42
    _flip(db, "2026-09-21T07:30:00+01:00")
    [restored] = db.list_sync_users_by_active_membership_ids([2])
    assert restored["matricule"] == 42
    db.save_sync_cache_delta(_v2([dict(member, matricule=43)], delta=True, valid=[2]), MEMBERS_ONLY)
    assert db.list_sync_users_by_active_membership_ids([2])[0]["matricule"] == 43


@pytest.mark.parametrize("has_fees", [False, True])
def test_upgrade_requests_one_full_member_refresh(old_db, has_fees):
    db, path = old_db
    _seed_pre_fees_database(path)
    if has_fees:
        with sqlite3.connect(path) as conn:
            conn.execute("ALTER TABLE sync_users ADD COLUMN fees_json TEXT")
    db.init_db()
    tokens = db.load_version_tokens()
    assert "membersVersion" not in tokens and "membersUpdatedAfter" not in tokens
    assert tokens["devicesVersion"] == "2:2026-10-01"
    assert db.list_sync_users_by_active_membership_ids([31000])[0]["matricule"] is None
    with db.get_conn() as conn:
        for table in ("sync_users", "sync_users_held"):
            assert "matricule" in {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    db.save_version_tokens({"membersVersion": "new", "membersUpdatedAfter": "later"})
    db.init_db()
    tokens = db.load_version_tokens()
    assert tokens["membersVersion"] == "new" and tokens["membersUpdatedAfter"] == "later"


@pytest.mark.parametrize("query, expected", [
    ("42", {31000}), ("0042", {31000}), (" 0042 ", {31000}),
    ("4", {31003}), ("ali", {31000}), ("phone42", {31003}),
])
@pytest.mark.parametrize("approval", [False, True])
def test_member_search_matches_numbers_exactly(db, monkeypatch, query, expected, approval):
    from types import SimpleNamespace
    from app.api.local_access_api_v2 import _handle_members_roster
    from app.core import offline_actions

    members = [_ali(matricule=42)] + [
        dict(_ali(), activeMembershipId=31001 + i, userId=901 + i,
             fullName=f"Member {i}", matricule=number, firstCardId=None,
             phone="phone42" if i == 2 else None)
        for i, number in enumerate((142, 420, 40, 41))
    ]
    WRITERS["save_sync_cache"](db, members)
    monkeypatch.setattr(offline_actions, "staff_enabled", lambda app: approval)
    monkeypatch.setattr(offline_actions, "pending_members", lambda: [])
    monkeypatch.setattr(offline_actions, "uploaded_receipts", lambda: [])
    responses = []
    ctx = SimpleNamespace(
        app=SimpleNamespace(),
        q=lambda *keys, default="": query if keys[0] == "q" else default,
        q_int=lambda *keys, default=0: default,
        send_json=lambda code, data: responses.append((code, data)),
    )
    _handle_members_roster(ctx)
    code, data = responses[0]
    assert code == 200
    matched = {row["activeMembershipId"] for row in data["rows"]}
    if query.strip() == "42":
        expected = expected | {31003}
    assert matched == expected


@pytest.mark.parametrize("number", [None, 42])
def test_popup_number_comes_from_the_member_without_a_lookup(db, monkeypatch, number):
    from app.core.access_types import NotificationRequest
    from app.core.realtime_agent import _popup_payload_from_request
    from app.core.ultra_pc_entry import member_popup_fields

    def no_lookup(*args, **kwargs):
        raise AssertionError("Popup identity must use the member already supplied")

    monkeypatch.setattr(db, "get_conn", no_lookup)
    fields = member_popup_fields(_ali(matricule=number))
    assert fields["user_matricule"] == number
    assert member_popup_fields(None)["user_matricule"] is None
    req = NotificationRequest(event_id="entry", title="Accès", message="", matricule=number)
    assert _popup_payload_from_request(req)["matricule"] == number


def test_number_changes_do_not_change_device_hashes_pins_or_shadow(db):
    from app.core.device_sync import DeviceSyncEngine, derive_member_pin
    from app.core.ultra_engine import _standalone_pin_hash

    before = _ali(matricule=42)
    after = _ali(matricule=43)
    hashes = []
    for member in (before, after):
        hashes.append(DeviceSyncEngine._compute_desired_hash(
            None, pin="31000", user=member, door_bitmask=1,
            templates=[], authorize_timezone_id=1,
        ))
    assert hashes[0] == hashes[1]
    entry = {"pin": "31000", "name": "Ali", "card": "1900"}
    assert _standalone_pin_hash(dict(entry, matricule=42), []) == \
        _standalone_pin_hash(dict(entry, matricule=43), [])
    for scheme in ("MEMBERSHIP", "ACCOUNT"):
        assert derive_member_pin(before, scheme) == derive_member_pin(after, scheme)
    db.upsert_member_shadow(users=[before])
    diff = db.diff_member_shadow(incoming_users=[after], valid_member_ids=[31000])
    assert diff["new"] == [] and diff["modified"] == [] and diff["membership_changed"] == []


@pytest.mark.parametrize("pc_decided", [False, True])
def test_resolved_card_entry_carries_the_number_through_the_popup_queue(db, monkeypatch, pc_decided):
    from app.core import ultra_engine
    from app.core.realtime_agent import _popup_payload_from_request
    from test_ultra_pc_entry import ANNA, ANNA_CARD, _evt, _staff_ids, _worker

    member = dict(ANNA, matricule=42)
    worker = _worker(card_decision="PC" if pc_decided else "DEVICE")
    worker._cached_state = ([], {501: member}, {ANNA_CARD: [member]})
    del worker._enqueue_notification
    monkeypatch.setattr(ultra_engine, "get_membership_brief_index_cached", lambda: {})
    with _staff_ids():
        worker._process_event(_evt(ANNA_CARD, "number-entry", etype=None if pc_decided else 0))
    req = worker._popup_q.get_nowait()
    assert req.allowed is True and req.matricule == 42
    assert _popup_payload_from_request(req)["matricule"] == 42

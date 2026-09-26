"""P3b-1 foundation: the protocol-2 tables, their readers and the person link (real temp SQLite)."""
from __future__ import annotations

import json
import sqlite3

import pytest

import app.core.db as dbmod
from app.core import access_dates as ad


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "p2.db"), raising=False)
    dbmod._shutdown_db_writer_for_tests()
    dbmod.init_db()
    yield dbmod
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


def _user(am, uid, main=None, **extra):
    return {"activeMembershipId": am, "userId": uid, "membershipId": 1, "fullName": f"M{am}",
            "mainAccountId": main, "firstCardId": str(1000 + am), **extra}


def _exec(sql, params=()):
    def _w(conn, _profile):
        conn.execute(sql, params)
    dbmod._run_db_write_sync("test", _w)


def test_init_creates_every_protocol2_table(db):
    with db.get_conn() as conn:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"access_v2_state", "member_access_window", "sync_upcoming_users",
            "sync_upcoming_credentials", "sync_users_held", "member_person_link"} <= names


def test_held_rows_carry_every_sync_users_column(db):
    with db.get_conn() as conn:
        held = set(db._table_columns(conn, "sync_users_held"))
        users = set(db._table_columns(conn, "sync_users"))
    assert set(db._SYNC_USER_COLUMNS) <= held
    assert users <= held, "a sync_users column the held table lacks would be lost on a hold"
    assert set(db._HELD_EXTRA_COLUMNS) <= held


def test_init_is_idempotent(db):
    db.init_db()
    db.init_db()


def test_the_person_link_records_rows_without_a_main_account(db):
    db.upsert_delta_users([_user(11, 501), _user(12, 502, main=9002)])
    assert db.get_member_person_user_ids([11, 12, 99]) == {11: 501, 12: 502}


def test_the_person_link_outlives_the_member_row(db):
    db.upsert_delta_users([_user(11, 501)])
    db.delete_users_by_am_ids([11])
    assert db.get_member_person_user_ids([11]) == {11: 501}


def test_the_person_link_updates_when_only_the_user_changes(db):
    db.upsert_delta_users([_user(11, 501)])
    db.delete_users_by_am_ids([11])
    db.upsert_delta_users([_user(11, 777)])
    assert db.get_member_person_user_ids([11]) == {11: 777}


def test_the_person_link_is_backfilled_from_rows_cached_before_the_upgrade(db):
    db.upsert_delta_users([_user(21, 601)])
    _exec("DELETE FROM member_person_link")
    db.init_db()
    assert db.get_member_person_user_ids([21]) == {21: 601}


def test_a_member_write_survives_a_database_without_the_person_link_table(db):
    _exec("DROP TABLE member_person_link")
    db.upsert_delta_users([_user(31, 701)])          # must not raise or roll back
    assert 31 in set(db.get_all_cached_user_am_ids())


def test_the_state_reader_is_empty_before_any_protocol2_answer(db):
    assert db.get_access_v2_state() == {}
    assert db.clock_state_from_row({}) == ad.ClockState()


def test_the_state_reader_decodes_the_row(db):
    _exec("INSERT INTO access_v2_state (id, trusted, server_today, utc_offset_sec, server_epoch, "
          "skew_sec, floor_date, max_pc_epoch, clock_suspect, capabilities_json) "
          "VALUES (1, 1, '2026-09-19', 3600, 1.5, 2.0, '2026-09-20', 3.5, 1, '[\"upcoming\"]')")
    st = db.get_access_v2_state()
    assert st["trusted"] is True and st["clock_suspect"] is True
    assert st["capabilities"] == ["upcoming"]
    cs = db.clock_state_from_row(st)
    assert cs.server_today.isoformat() == "2026-09-19" and cs.utc_offset_sec == 3600
    assert cs.floor_date.isoformat() == "2026-09-20" and cs.max_pc_epoch == 3.5


def test_the_access_days_snapshot_joins_today_and_upcoming_windows(db):
    _exec("INSERT INTO access_v2_state (id, trusted, applied_date, server_today, horizon_end, grace_days) "
          "VALUES (1, 1, '2026-09-20', '2026-09-19', '2026-09-26', 2)")
    _exec("INSERT INTO member_access_window VALUES (1, '2026-09-01', '2026-09-19', '[]', 0)")
    _exec("INSERT INTO sync_upcoming_users VALUES (3, '{}', '2026-09-20', '2026-10-19', "
          "'[\"2026-09-22\"]', 1, 55)")
    s = db.load_access_days_snapshot()
    assert s.active and s.gym_date.isoformat() == "2026-09-20" and s.grace_days == 2
    assert s.windows[1].access_until.isoformat() == "2026-09-19"
    assert s.windows[3].off_days_beyond_horizon is True
    assert s.upcoming_qr_account == {3: 55}
    assert s.deliverable(3) is True and s.deliverable(1) is True     # 1 kept by the 2-day grace


def test_an_untrusted_state_gives_an_inactive_snapshot(db):
    _exec("INSERT INTO access_v2_state (id, trusted, applied_date) VALUES (1, 0, '2026-09-20')")
    assert db.load_access_days_snapshot().active is False


def test_upcoming_credentials_read_back_disabled_and_marked(db):
    _exec("INSERT INTO sync_upcoming_credentials VALUES (9, 7, 55, 'abcd', 0, NULL, NULL, NULL, '[3]')")
    [c] = db.list_sync_upcoming_credentials()
    assert c["id"] == 9 and c["accountId"] == 55 and c["enabled"] is False
    assert c["grantedActiveMembershipIds"] == [3] and c["notYetValid"] is True


def test_the_member_cache_count_includes_held_rows(db):
    db.upsert_delta_users([_user(41, 801), _user(42, 802)])
    cols = ", ".join(db._SYNC_USER_COLUMNS)
    _exec(f"INSERT INTO sync_users_held ({cols}, held_reason) SELECT {cols}, 'expired' "
          f"FROM sync_users WHERE active_membership_id = 42")
    _exec("DELETE FROM sync_users WHERE active_membership_id = 42")
    assert db.count_sync_users() == 1
    assert db.count_member_cache_rows() == 2

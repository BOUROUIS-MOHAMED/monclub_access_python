"""P3b-1 part B: the save of protocol-2 answers, held rows, the flip job, counts, logout.

Real temp SQLite through the documented ``app.core.db._DB_PATH`` override -- nothing here may
touch the installed database. Payload shapes follow the backend contract
(``ActiveMemberResponseV2``: ``syncMeta``, ``currentWindowsVersion``, ``users[]`` with windows,
``memberWindows``, ``upcoming[]`` + ``upcomingIds`` + ``upcomingCredentials``).
"""
from __future__ import annotations

import json
from datetime import datetime

import pytest

import app.core.db as dbmod

MEMBERS_ONLY = {"members": True, "devices": False, "credentials": False, "settings": False}
NOTHING = {"members": False, "devices": False, "credentials": False, "settings": False}


def _epoch(iso: str) -> float:
    return datetime.fromisoformat(iso).timestamp()


SERVER_EPOCH = _epoch("2026-09-19T10:00:00+01:00")


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "p2b.db"), raising=False)
    dbmod._shutdown_db_writer_for_tests()
    dbmod.init_db()
    yield dbmod
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


# ------------------------------------------------------------------ payloads (backend shapes)
def _meta(today="2026-09-19", horizon_end="2026-09-26", server_time="2026-09-19T10:00:00.000+01:00"):
    return {"protocol": 2, "today": today, "horizonDays": 7, "horizonEnd": horizon_end,
            "serverTime": server_time, "snapshotAt": "2026-09-19T09:59:59.500+01:00",
            "reconcileSec": 600, "capabilities": ["accessWindows", "upcoming", "upcomingCredentials"]}


def _row(am, frm="2026-09-01", until="2026-09-30", off=(), **extra):
    row = {"activeMembershipId": am, "userId": 7000 + am, "membershipId": 3, "fullName": f"M{am}",
           "firstCardId": str(1000 + am), "mainAccountId": 9000 + am,
           "accessFrom": frm, "accessUntil": until, "offDays": list(off)}
    row.update(extra)
    return row


def _window(am, frm="2026-09-01", until="2026-09-30", off=()):
    return {"activeMembershipId": am, "accessFrom": frm, "accessUntil": until, "offDays": list(off)}


def _v2(users, *, delta=False, valid=None, member_windows=(), upcoming=None, upcoming_creds=None,
        windows_version="p2.7.a.b", refresh_members=True, received=SERVER_EPOCH + 2, meta=None):
    d = {"syncMeta": meta or _meta(), "currentWindowsVersion": windows_version,
         "refreshMembers": refresh_members, "membersDeltaMode": delta, "users": list(users),
         "memberWindows": list(member_windows), "_clientReceivedAtEpoch": received}
    if valid is not None:
        d["validMemberIds"] = list(valid)
    if upcoming is not None:
        d["upcoming"] = list(upcoming)
        d["upcomingIds"] = sorted(r["activeMembershipId"] for r in upcoming)
        d["upcomingCredentials"] = list(upcoming_creds or [])
    return d


def _v1(users, *, delta=False, valid=None):
    d = {"refreshMembers": True, "membersDeltaMode": delta, "users": list(users)}
    if valid is not None:
        d["validMemberIds"] = list(valid)
    return d


def _upcoming_cred():
    return {"id": 9, "gymId": 7, "accountId": 55, "secretHex": "ab" * 16, "enabled": False,
            "grantedActiveMembershipIds": [3], "notYetValid": True}


# ------------------------------------------------------------------ readers
def _exec(sql, params=()):
    def _w(conn, _profile):
        conn.execute(sql, params)
    dbmod._run_db_write_sync("test", _w)


def _q(sql, params=()):
    with dbmod.get_conn() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def _ids(table):
    return {r["active_membership_id"] for r in _q(f"SELECT active_membership_id FROM {table}")}


def _windows():
    return {r["active_membership_id"]: (r["access_from"], r["access_until"], json.loads(r["off_days_json"]),
                                        r["off_days_beyond_horizon"])
            for r in _q("SELECT * FROM member_access_window")}


def _user_row(am, table="sync_users"):
    cols = ", ".join(dbmod._SYNC_USER_COLUMNS)
    rows = _q(f"SELECT {cols} FROM {table} WHERE active_membership_id = ?", (am,))
    assert len(rows) == 1, rows
    return rows[0]


def _hold(am, reason="expired"):
    """Move a sync_users row to sync_users_held exactly as the flip does (column for column)."""
    cols = ", ".join(dbmod._SYNC_USER_COLUMNS)
    _exec(f"INSERT INTO sync_users_held ({cols}, held_reason, held_for_date, held_at) "
          f"SELECT {cols}, ?, '2026-09-20', 'x' FROM sync_users WHERE active_membership_id = ?", (reason, am))
    _exec("DELETE FROM sync_users WHERE active_membership_id = ?", (am,))


def _token():
    return dbmod.load_version_tokens().get("windowsVersion")


def _seed_full_v2(db):
    """Today's set 1 (ends 09-19), 2 (frozen 09-20), 5; upcoming 3 from 09-20 (QR account 55)."""
    return db.save_sync_cache_delta(
        _v2([_row(1, until="2026-09-19"), _row(2, off=["2026-09-20"]), _row(5)],
            upcoming=[_row(3, frm="2026-09-20", qrAccountId=55)], upcoming_creds=[_upcoming_cred()]),
        MEMBERS_ONLY,
    )


def _flip(db, iso, grace=0):
    return db.apply_local_date_flips(pc_now_epoch=_epoch(iso), grace_days=grace, source="test")


# ================================================================== the save
def test_a_v2_full_members_section_stores_the_windows_upcoming_lists_token_and_clock(db):
    out = _seed_full_v2(db)
    assert out["protocol2"] == {"protocol": "v2", "reason": None, "trusted": True,
                                "members_section": True, "clock_at_sync": ""}
    st = db.get_access_v2_state()
    assert st["trusted"] is True
    assert st["server_today"] == "2026-09-19" and st["horizon_end"] == "2026-09-26"
    assert st["horizon_days"] == 7 and st["reconcile_sec"] == 600
    assert st["server_time"] == "2026-09-19T10:00:00.000+01:00"
    assert st["snapshot_at"] == "2026-09-19T09:59:59.500+01:00"
    assert st["capabilities"] == ["accessWindows", "upcoming", "upcomingCredentials"]
    assert st["server_epoch"] == pytest.approx(SERVER_EPOCH)
    assert st["utc_offset_sec"] == 3600
    assert st["pc_epoch_at_sync"] == pytest.approx(SERVER_EPOCH + 2)
    assert st["skew_sec"] == pytest.approx(2.0)
    assert st["floor_date"] == "2026-09-19"
    assert st["max_pc_epoch"] == pytest.approx(SERVER_EPOCH + 2)
    # owned by the flip job, untouched by a save
    assert st["applied_date"] is None and st["clock_suspect"] is False and st["grace_days"] == 0
    assert _windows() == {1: ("2026-09-01", "2026-09-19", [], 0),
                          2: ("2026-09-01", "2026-09-30", ["2026-09-20"], 0),
                          5: ("2026-09-01", "2026-09-30", [], 0)}
    [up] = _q("SELECT * FROM sync_upcoming_users")
    assert up["active_membership_id"] == 3 and up["qr_account_id"] == 55
    assert (up["access_from"], up["access_until"]) == ("2026-09-20", "2026-09-30")
    assert json.loads(up["payload_json"]) == _row(3, frm="2026-09-20", qrAccountId=55)
    [c] = db.list_sync_upcoming_credentials()
    assert c["id"] == 9 and c["accountId"] == 55 and c["enabled"] is False
    assert c["grantedActiveMembershipIds"] == [3]
    assert _token() == "p2.7.a.b"
    assert _ids("sync_users") == {1, 2, 5}


def test_upcoming_credentials_are_stored_disabled_in_the_main_credentials_layout(db):
    cred = dict(_upcoming_cred(), enabled=True, rotatedAt="2026-09-01T00:00:00")
    db.save_sync_cache_delta(_v2([_row(5)], upcoming=[_row(3, frm="2026-09-20", qrAccountId=55)],
                                 upcoming_creds=[cred]), MEMBERS_ONLY)
    [r] = _q("SELECT * FROM sync_upcoming_credentials")
    assert r == {"id": 9, "gym_id": 7, "account_id": 55, "secret_hex": "ab" * 16, "enabled": 0,
                 "rotated_at": "2026-09-01T00:00:00", "created_at": None, "updated_at": None,
                 "granted_active_membership_ids_json": "[3]"}
    assert _q("SELECT * FROM sync_gym_access_credentials") == []      # never the main list


def test_a_pc_clock_behind_at_sync_is_measured_and_the_server_time_becomes_the_reference(db):
    out = db.save_sync_cache_delta(_v2([_row(1)], received=SERVER_EPOCH - 600), MEMBERS_ONLY)
    assert out["protocol2"]["clock_at_sync"] == "behind"
    st = db.get_access_v2_state()
    assert st["skew_sec"] == pytest.approx(-600.0)
    assert st["max_pc_epoch"] == pytest.approx(SERVER_EPOCH)


def test_a_v1_answer_keeps_the_lists_but_stops_trusting_them_and_drops_the_token(db):
    _seed_full_v2(db)
    before_windows = _windows()
    out = db.save_sync_cache_delta(_v1([_row(5)], delta=True, valid=[1, 2, 5]), MEMBERS_ONLY)
    assert out["protocol2"]["protocol"] == "v1" and out["protocol2"]["reason"] is None
    assert out["protocol2"]["trusted"] is False
    st = db.get_access_v2_state()
    assert st["trusted"] is False
    assert st["server_today"] == "2026-09-19" and st["floor_date"] == "2026-09-19"  # kept
    assert _token() is None
    assert _windows() == before_windows
    assert _ids("sync_upcoming_users") == {3}


def test_a_v1_answer_on_a_fresh_pc_records_an_untrusted_state(db):
    db.save_sync_cache_delta(_v1([_row(1)]), MEMBERS_ONLY)
    st = db.get_access_v2_state()
    assert st["trusted"] is False and st["server_today"] is None


def test_a_v2_delta_without_upcoming_replaces_the_windows_and_keeps_the_upcoming_list(db):
    _seed_full_v2(db)
    out = db.save_sync_cache_delta(
        _v2([_row(5, until="2026-10-31")], delta=True, valid=[2, 5],
            member_windows=[_window(2, off=["2026-09-20"])], windows_version="p2.7.c.b"),
        MEMBERS_ONLY,
    )
    assert out["protocol2"]["trusted"] is True
    assert _windows() == {2: ("2026-09-01", "2026-09-30", ["2026-09-20"], 0),
                          5: ("2026-09-01", "2026-10-31", [], 0)}
    assert _ids("sync_upcoming_users") == {3}
    assert len(db.list_sync_upcoming_credentials()) == 1
    assert _token() == "p2.7.c.b"
    assert _ids("sync_users") == {2, 5}


def test_a_v2_answer_with_the_members_section_skipped_keeps_every_list(db):
    _seed_full_v2(db)
    before = (_windows(), _ids("sync_upcoming_users"), _ids("sync_users"))
    later = _meta(server_time="2026-09-19T11:00:00.000+01:00")
    out = db.save_sync_cache_delta(
        _v2([], refresh_members=False, meta=later, received=SERVER_EPOCH + 3602), NOTHING)
    assert out["protocol2"]["members_section"] is False and out["protocol2"]["trusted"] is True
    assert (_windows(), _ids("sync_upcoming_users"), _ids("sync_users")) == before
    st = db.get_access_v2_state()
    assert st["trusted"] is True and st["server_time"] == "2026-09-19T11:00:00.000+01:00"
    assert _token() == "p2.7.a.b"


def test_a_malformed_v2_part_is_rejected_whole_like_a_v1_answer(db, monkeypatch):
    _seed_full_v2(db)
    warned = []
    monkeypatch.setattr(dbmod._tel, "warn", lambda name, **f: warned.append((name, f)))
    before_windows = _windows()
    bad = _v2([_row(5)], delta=True, valid=[1, 2, 5], upcoming=[_row(3, frm="2026-09-21")])
    bad["upcomingIds"] = [4]
    out = db.save_sync_cache_delta(bad, MEMBERS_ONLY)
    assert out["protocol2"]["protocol"] == "rejected"
    assert out["protocol2"]["reason"].startswith("upcoming_ids")
    assert db.get_access_v2_state()["trusted"] is False
    assert _token() is None
    assert _windows() == before_windows and _ids("sync_upcoming_users") == {3}
    # Filtered by name: the DbWriter itself warns DB_WRITE_SLOW on a slow job.
    rejected = [f for n, f in warned if n == "SYNC_V2_REJECTED"]
    assert len(rejected) == 1
    assert rejected[0]["reason"].startswith("upcoming_ids")


def test_an_h006_refused_members_section_drops_trust_and_the_token(db):
    db.save_sync_cache_delta(_v2([_row(am) for am in range(1, 13)]), MEMBERS_ONLY)
    assert db.get_access_v2_state()["trusted"] is True
    before_windows = _windows()
    out = db.save_sync_cache_delta(_v2([], delta=True, valid=[], windows_version="p2.7.z.z"), MEMBERS_ONLY)
    assert out["members_delete_refused"] is True
    assert out["protocol2"]["members_section"] is True and out["protocol2"]["trusted"] is False
    assert db.get_access_v2_state()["trusted"] is False
    assert _token() is None
    assert _windows() == before_windows
    assert len(_ids("sync_users")) == 12


def test_an_inconsistent_delta_drops_trust(db):
    _seed_full_v2(db)
    out = db.save_sync_cache_delta(_v2([_row(8)], delta=True, valid=[1, 2, 5]), MEMBERS_ONLY)
    assert out["members_delete_refused"] is True
    assert out["protocol2"]["trusted"] is False and _token() is None


def test_a_failure_inside_the_v2_step_rolls_back_the_whole_save(db, monkeypatch):
    _seed_full_v2(db)
    before = (_ids("sync_users"), _windows(), _token(), db.get_access_v2_state()["server_time"])

    def _boom(*_a, **_k):
        raise RuntimeError("disk full")

    monkeypatch.setattr(dbmod, "_replace_member_access_windows", _boom)
    later = _meta(server_time="2026-09-19T12:00:00.000+01:00")
    with pytest.raises(RuntimeError, match="disk full"):
        db.save_sync_cache_delta(
            _v2([_row(8)], delta=True, valid=[1, 2, 5, 8], windows_version="p2.new", meta=later),
            MEMBERS_ONLY,
        )
    after = (_ids("sync_users"), _windows(), _token(), db.get_access_v2_state()["server_time"])
    assert after == before


# ------------------------------------------------------------------ held rows at a save
def test_a_delta_restores_held_rows_the_server_still_lists_and_drops_the_rest(db):
    _seed_full_v2(db)
    db.save_sync_cache_delta(_v2([_row(6), _row(7)], delta=True, valid=[1, 2, 5, 6, 7]), MEMBERS_ONLY)
    kept = _user_row(2)
    for am in (2, 6, 7):
        _hold(am)
    _exec("DELETE FROM member_account_link WHERE active_membership_id = 2")
    out = db.save_sync_cache_delta(
        _v2([_row(6, fullName="NEW6")], delta=True, valid=[1, 2, 5, 6]), MEMBERS_ONLY)
    assert out["protocol2"]["trusted"] is True
    assert _ids("sync_users") == {1, 2, 5, 6}
    assert _user_row(2) == kept                             # restored column for column
    assert _user_row(6)["full_name"] == "NEW6"              # the incoming row wins
    assert _ids("sync_users_held") == set()                 # 7 left validMemberIds: dropped
    assert db.get_main_account_ids_for_memberships([2]) == {2: 9002}


def test_a_v1_delta_reconciles_held_rows_too(db):
    _seed_full_v2(db)
    _hold(2)
    _hold(5)
    db.save_sync_cache_delta(_v1([], delta=True, valid=[1, 2]), MEMBERS_ONLY)
    assert _ids("sync_users") == {1, 2}
    assert _ids("sync_users_held") == set()


def test_a_full_members_section_drops_every_held_row(db):
    _seed_full_v2(db)
    _hold(2)
    _hold(5)
    db.save_sync_cache_delta(_v2([_row(1), _row(5)]), MEMBERS_ONLY)
    assert _ids("sync_users") == {1, 5}
    assert _ids("sync_users_held") == set()


def test_a_refused_authority_leaves_held_rows_alone(db):
    _seed_full_v2(db)
    _hold(2)
    db.save_sync_cache_delta(_v2([_row(8)], delta=True, valid=[1, 5]), MEMBERS_ONLY)
    assert _ids("sync_users_held") == {2}


def test_a_delta_without_valid_member_ids_is_no_authority_for_held_rows_or_windows(db):
    # The backend always sends validMemberIds in delta mode (GymAccessController, protocol 2);
    # a delta without it proves nothing about the held rows, so they stay and trust drops.
    _seed_full_v2(db)
    _hold(2)
    out = db.save_sync_cache_delta(_v2([_row(5)], delta=True), MEMBERS_ONLY)
    assert out["members_delete_refused"] is False                 # existing behaviour unchanged
    assert _ids("sync_users_held") == {2}
    assert out["protocol2"]["trusted"] is False and _token() is None


def test_a_full_members_section_refused_by_h006_leaves_held_rows_alone(db):
    _seed_five_on_roster_eight_held(db)
    out = db.save_sync_cache_delta(_v2([]), MEMBERS_ONLY)
    assert out["members_delete_refused"] is True
    assert len(_ids("sync_users")) == 5 and len(_ids("sync_users_held")) == 8
    assert out["protocol2"]["trusted"] is False


def test_a_skipped_members_section_leaves_held_rows_alone(db):
    _seed_full_v2(db)
    _hold(2)
    db.save_sync_cache_delta(_v2([], refresh_members=False), NOTHING)
    assert _ids("sync_users_held") == {2}


# ------------------------------------------------------------------ H-006 counts held rows
def _seed_five_on_roster_eight_held(db):
    db.save_sync_cache_delta(_v1([_row(am) for am in range(1, 14)]), MEMBERS_ONLY)
    for am in range(6, 14):
        _hold(am)
    assert len(_ids("sync_users")) == 5 and len(_ids("sync_users_held")) == 8


def test_h006_full_save_counts_held_rows(db):
    _seed_five_on_roster_eight_held(db)
    db.save_sync_cache(_v1([]))
    assert len(_ids("sync_users")) == 5
    assert len(_ids("sync_users_held")) == 8


def test_h006_delta_counts_the_held_rows_it_would_drop(db):
    _seed_five_on_roster_eight_held(db)
    out = db.save_sync_cache_delta(_v1([], delta=True, valid=[]), MEMBERS_ONLY)
    assert out["members_delete_refused"] is True
    assert len(_ids("sync_users")) == 5
    assert len(_ids("sync_users_held")) == 8


def test_h006_full_members_refresh_of_the_delta_writer_counts_held_rows_too(db):
    # save_sync_cache_delta's FULL branch (hard reset, 22:00, manual "Sync data") has the same
    # users == [] guard; 5 on the roster + 8 held is a cache of 13 the empty answer would empty.
    _seed_five_on_roster_eight_held(db)
    out = db.save_sync_cache_delta(_v1([]), MEMBERS_ONLY)
    assert out["members_delete_refused"] is True
    assert len(_ids("sync_users")) == 5
    assert len(_ids("sync_users_held")) == 8


def test_h006_still_lets_a_small_cache_with_no_held_rows_empty(db):
    db.save_sync_cache_delta(_v1([_row(am) for am in range(1, 6)]), MEMBERS_ONLY)
    out = db.save_sync_cache_delta(_v1([], delta=True, valid=[]), MEMBERS_ONLY)
    assert out["members_delete_refused"] is False
    assert _ids("sync_users") == set()


# ------------------------------------------------------------------ save_sync_cache (full replace)
def test_the_full_replace_save_writes_the_protocol_2_parts_with_the_users(db):
    db.save_sync_cache(_v1([_row(1), _row(2)]))
    _hold(2)
    db.save_sync_cache(_v2([_row(1), _row(5)], upcoming=[_row(3, frm="2026-09-20", qrAccountId=55)],
                           upcoming_creds=[_upcoming_cred()]))
    assert _ids("sync_users") == {1, 5}
    assert _ids("sync_users_held") == set()
    assert set(_windows()) == {1, 5}
    assert _ids("sync_upcoming_users") == {3}
    assert len(db.list_sync_upcoming_credentials()) == 1
    assert _token() == "p2.7.a.b"
    st = db.get_access_v2_state()
    assert st["trusted"] is True and st["server_today"] == "2026-09-19"
    assert st["skew_sec"] == pytest.approx(2.0)


def test_the_full_replace_save_refused_by_h006_drops_trust(db):
    db.save_sync_cache(_v2([_row(am) for am in range(1, 13)]))
    assert db.get_access_v2_state()["trusted"] is True
    db.save_sync_cache(_v2([]))
    assert len(_ids("sync_users")) == 12
    assert db.get_access_v2_state()["trusted"] is False
    assert _token() is None


def test_a_v1_full_replace_save_drops_trust(db):
    db.save_sync_cache(_v2([_row(1)]))
    db.save_sync_cache(_v1([_row(1)]))
    assert db.get_access_v2_state()["trusted"] is False and _token() is None


# ------------------------------------------------------------------ logout
def test_logout_clears_the_protocol_2_lists_and_trust_but_keeps_the_clock(db):
    _seed_full_v2(db)
    _hold(2)
    _flip(db, "2026-09-20T07:30:00+01:00")
    db.save_sync_cache(None)
    for table in ("sync_users_held", "member_access_window", "sync_upcoming_users",
                  "sync_upcoming_credentials"):
        assert _q(f"SELECT * FROM {table}") == [], table
    st = db.get_access_v2_state()
    assert st["trusted"] is False
    assert st["server_today"] == "2026-09-19" and st["floor_date"] == "2026-09-20"
    assert st["max_pc_epoch"] == pytest.approx(_epoch("2026-09-20T07:30:00+01:00"))
    assert _token() is None


# ================================================================== the flip
def test_a_flip_on_the_server_day_moves_nothing_and_records_the_day(db):
    _seed_full_v2(db)
    gen = db.get_local_state_generation()
    r = _flip(db, "2026-09-19T12:00:00+01:00")
    assert r["gym_date"] == "2026-09-19" and r["moved"] == 0 and r["skipped"] is None
    assert r["applied_before"] is None and r["trusted"] is True
    assert db.get_access_v2_state()["applied_date"] == "2026-09-19"
    assert db.get_local_state_generation() == gen


def test_power_on_the_next_day_holds_the_expiry_and_the_freeze_and_promotes_the_starter(db):
    _seed_full_v2(db)
    gen = db.get_local_state_generation()
    r = _flip(db, "2026-09-20T07:30:00+01:00")
    assert r["gym_date"] == "2026-09-20" and r["pc_date"] == "2026-09-20"
    assert (r["held"], r["restored"], r["promoted"], r["moved"]) == (2, 0, 1, 3)
    assert r["hold_reasons"] == {"expired": 1, "frozen": 1}
    assert r["starters"] == [3]
    assert _ids("sync_users") == {3, 5}
    held = {h["active_membership_id"]: h for h in _q("SELECT * FROM sync_users_held")}
    assert set(held) == {1, 2}
    assert held[1]["held_reason"] == "expired" and held[2]["held_reason"] == "frozen"
    assert held[1]["held_for_date"] == "2026-09-20" and held[1]["held_at"]
    assert _user_row(3)["full_name"] == "M3"
    assert db.get_main_account_ids_for_memberships([3]) == {3: 9003}
    assert db.get_member_person_user_ids([3]) == {3: 7003}
    assert _ids("sync_upcoming_users") == {3}                # the upcoming list is never changed
    st = db.get_access_v2_state()
    assert st["applied_date"] == "2026-09-20" and st["floor_date"] == "2026-09-20"
    assert db.get_local_state_generation() > gen
    assert db.count_member_cache_rows() == 4


def test_the_freeze_day_is_restored_the_day_after_and_the_expiry_stays_held(db):
    _seed_full_v2(db)
    _flip(db, "2026-09-20T07:30:00+01:00")
    r = _flip(db, "2026-09-21T00:00:05+01:00")
    assert (r["held"], r["restored"], r["promoted"]) == (0, 1, 0)
    assert r["applied_before"] == "2026-09-20"
    assert _ids("sync_users") == {2, 3, 5}
    assert _ids("sync_users_held") == {1}


def test_a_hold_and_restore_round_trip_preserves_every_sync_users_column(db):
    full = _row(2, off=["2026-09-20"], phone="+216 1", email="m2@x.tn", validFrom="2026-09-01",
                validTo="2026-09-30", secondCardId="2222", image="img-b64",
                fingerprints=[{"fingerId": 1, "templateData": "TPL=="}, {"fingerId": 6, "templateData": "X"}],
                faceId="F2", accountUsernameId="user2", qrCodePayload="QR2", birthday="1990-01-02",
                imageSource="S3", userImageStatus="OK", userProfileImage="p.png")
    db.save_sync_cache_delta(_v2([full, _row(5)]), MEMBERS_ONLY)
    before = _user_row(2)
    assert set(before) == set(dbmod._SYNC_USER_COLUMNS) and len(before) == 20
    assert all(v is not None for v in before.values()), before
    _flip(db, "2026-09-20T07:30:00+01:00")
    assert _ids("sync_users") == {5}
    assert _user_row(2, table="sync_users_held") == before
    _flip(db, "2026-09-21T07:30:00+01:00")
    assert _user_row(2) == before
    assert _ids("sync_users_held") == set()


def test_the_generation_moves_only_when_something_moved(db):
    _seed_full_v2(db)
    _flip(db, "2026-09-20T07:30:00+01:00")
    gen = db.get_local_state_generation()
    r = _flip(db, "2026-09-20T15:00:00+01:00")
    assert r["moved"] == 0
    assert db.get_local_state_generation() == gen


def test_an_untrusted_state_moves_nothing(db):
    _seed_full_v2(db)
    db.save_sync_cache_delta(_v1([], delta=True, valid=[1, 2, 5]), MEMBERS_ONLY)
    gen = db.get_local_state_generation()
    r = _flip(db, "2026-09-20T07:30:00+01:00")
    assert r["skipped"] == "untrusted" and r["moved"] == 0 and r["trusted"] is False
    assert _ids("sync_users") == {1, 2, 5} and _ids("sync_users_held") == set()
    assert db.get_local_state_generation() == gen


def test_no_protocol_2_state_moves_nothing_and_writes_nothing(db):
    db.save_sync_cache(_v1([_row(1)]))
    _exec("DELETE FROM access_v2_state")
    r = _flip(db, "2026-09-20T07:30:00+01:00")
    assert r["skipped"] == "no_state" and r["gym_date"] is None and r["moved"] == 0
    assert db.get_access_v2_state() == {}


def test_a_flat_battery_after_a_day_was_applied_neither_rewinds_nor_restores(db):
    _seed_full_v2(db)
    _flip(db, "2026-09-20T07:30:00+01:00")
    r = _flip(db, "2000-01-01T00:05:00+01:00")
    assert r["gym_date"] == "2026-09-20" and r["pc_date"] == "2000-01-01"
    assert r["clock_suspect"] is True and r["clock_reason"] == "behind"
    assert r["moved"] == 0
    assert _ids("sync_users") == {3, 5} and _ids("sync_users_held") == {1, 2}
    st = db.get_access_v2_state()
    assert st["applied_date"] == "2026-09-20" and st["floor_date"] == "2026-09-20"
    assert st["clock_suspect"] is True and st["clock_reason"] == "behind"
    assert st["max_pc_epoch"] == pytest.approx(_epoch("2026-09-20T07:30:00+01:00"))


def test_clock_changed_reports_only_the_transitions(db):
    _seed_full_v2(db)
    assert _flip(db, "2026-09-20T07:30:00+01:00")["clock_changed"] is False
    assert _flip(db, "2000-01-01T00:05:00+01:00")["clock_changed"] is True
    assert _flip(db, "2000-01-01T00:06:00+01:00")["clock_changed"] is False
    r = _flip(db, "2026-09-20T12:00:00+01:00")
    assert r["clock_changed"] is True and r["clock_suspect"] is False and r["clock_reason"] == ""
    st = db.get_access_v2_state()
    assert st["clock_suspect"] is False and not st["clock_reason"]


def test_grace_days_are_persisted_and_honoured(db):
    _seed_full_v2(db)
    r = _flip(db, "2026-09-20T07:30:00+01:00", grace=2)
    assert r["hold_reasons"] == {"frozen": 1}
    assert 1 in _ids("sync_users")
    assert db.get_access_v2_state()["grace_days"] == 2
    assert db.load_access_days_snapshot().grace_days == 2
    r = _flip(db, "2026-09-22T07:30:00+01:00", grace=2)          # 09-19 + 2 days: over
    assert r["hold_reasons"] == {"expired": 1}
    _flip(db, "2026-09-22T08:00:00+01:00", grace=-3)
    assert db.get_access_v2_state()["grace_days"] == 0


def test_a_save_leaves_what_the_flip_owns_and_resets_the_floor(db):
    _seed_full_v2(db)
    _flip(db, "2026-09-20T07:30:00+01:00", grace=1)
    _flip(db, "2000-01-01T00:05:00+01:00", grace=1)
    db.save_sync_cache_delta(_v2([], refresh_members=False, received=SERVER_EPOCH + 5), NOTHING)
    st = db.get_access_v2_state()
    assert st["applied_date"] == "2026-09-20" and st["grace_days"] == 1
    assert st["clock_suspect"] is True and st["clock_reason"] == "behind"
    assert st["floor_date"] == "2026-09-19"
    assert st["max_pc_epoch"] == pytest.approx(SERVER_EPOCH + 5)


def test_gym_date_status_says_when_a_flip_is_needed_without_writing(db):
    assert db.gym_date_status(pc_now_epoch=_epoch("2026-09-19T12:00:00+01:00"))["needs_flip"] is False
    _seed_full_v2(db)
    s = db.gym_date_status(pc_now_epoch=_epoch("2026-09-19T12:00:00+01:00"))
    assert s == {"gym_date": "2026-09-19", "applied_date": None, "suspect": False, "reason": "",
                 "needs_flip": True}
    assert db.get_access_v2_state()["applied_date"] is None          # read-only
    _flip(db, "2026-09-19T12:00:00+01:00")
    assert db.gym_date_status(pc_now_epoch=_epoch("2026-09-19T15:00:00+01:00"))["needs_flip"] is False
    s = db.gym_date_status(pc_now_epoch=_epoch("2026-09-20T00:00:05+01:00"))
    assert s["gym_date"] == "2026-09-20" and s["needs_flip"] is True
    s = db.gym_date_status(pc_now_epoch=_epoch("2000-01-01T00:05:00+01:00"))
    assert s["gym_date"] == "2026-09-19" and s["suspect"] is True and s["needs_flip"] is True

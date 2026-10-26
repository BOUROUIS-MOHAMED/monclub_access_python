import json
from datetime import datetime

import pytest

from app.core import db as dbmod
from tests.test_protocol2_save_and_flip import db, _q, _exec, _ids, _user_row, MEMBERS_ONLY

HOURS = [{"day": "MON", "startMinute": 1320, "durationMinutes": 480}]


def epoch(s):
    return datetime.fromisoformat(s + "+01:00").timestamp()


def row(am=1, **kw):
    return {"activeMembershipId": am, "userId": 7000 + am, "mainAccountId": 9000 + am,
            "fullName": "Member", "accessFrom": "2026-10-01", "accessUntil": "2026-11-30",
            "offDays": [], "offHours": HOURS, "fingerprints": [{"fingerId": 0, "template": "kept"}], **kw}


def payload(users=None, **kw):
    return {"syncMeta": {"protocol": 2, "today": "2026-10-26", "horizonDays": 7,
                        "horizonEnd": "2026-11-02", "serverTime": "2026-10-26T22:00:00+01:00"},
            "currentWindowsVersion": "hours1", "refreshMembers": True, "membersDeltaMode": False,
            "users": [row()] if users is None else users, "memberWindows": [],
            "_clientReceivedAtEpoch": epoch("2026-10-26T22:00:00"), **kw}


def seed(db, **kw):
    db.save_sync_cache_delta(payload(**kw), MEMBERS_ONLY)
    db.apply_local_date_flips(pc_now_epoch=epoch("2026-10-26T23:00:00"), grace_days=0, source="test")


def hold(db, when="2026-10-26T23:00:00"):
    return db.apply_off_hours(pc_now_epoch=epoch(when), source="test")


def test_all_window_sources_roundtrip_and_bad_hours(db):
    seed(db, users=[row(), row(4, offHours="bad"), row(5, offHours=[])],
         memberWindows=[row(2)], upcoming=[row(3, accessFrom="2026-10-27", qrAccountId=3)],
         upcomingIds=[3], upcomingCredentials=[])
    snap = db.load_access_days_snapshot()
    assert all(snap.windows[n].off_hours for n in (1, 2, 3))
    assert all(not snap.windows[n].off_hours for n in (4, 5))
    assert snap.utc_offset_sec == 3600 and not snap.clock_suspect


def test_hold_release_idempotence_and_fingerprints(db):
    seed(db)
    before = _user_row(1)
    assert hold(db)["newly_held"] == [1]
    assert _ids("sync_users") == set() and _ids("off_hours_hold") == {1}
    assert _user_row(1, "sync_users_held") == before
    assert _q("SELECT held_reason FROM sync_users_held")[0]["held_reason"] == "off_hours"
    assert hold(db)["moved"] == 0
    assert hold(db, "2026-10-27T05:55:00")["released"] == [1]
    assert _user_row(1) == before and not _ids("off_hours_hold")
    assert hold(db, "2026-10-27T05:55:00")["moved"] == 0


@pytest.mark.parametrize("status,sql,args", [
    ("expired", "UPDATE member_access_window SET access_until = ?", ("2026-10-25",)),
    ("frozen", "UPDATE member_access_window SET off_days_json = ?", ('["2026-10-26"]',)),
    ("not_started", "UPDATE member_access_window SET access_from = ?", ("2026-10-28",)),
])
def test_off_hours_release_transfers_to_date_without_another_flip(db, status, sql, args):
    seed(db)
    hold(db)
    _exec(sql, args)
    # Date pass cannot restore off-hours rows, even when it sees an invalid date window.
    db.apply_local_date_flips(pc_now_epoch=epoch("2026-10-26T23:01:00"), grace_days=0, source="test")
    assert not _ids("sync_users")
    out = hold(db, "2026-10-27T05:55:00")
    assert out["released_to_date"] == [1] and not out["released"]
    assert _q("SELECT held_reason FROM sync_users_held")[0]["held_reason"] == status
    assert not _ids("off_hours_hold") and not _ids("sync_users")


def test_date_hold_then_hours_hold(db):
    seed(db, users=[row(offDays=["2026-10-26"])])
    assert hold(db)["moved"] == 0
    assert _q("SELECT held_reason FROM sync_users_held")[0]["held_reason"] == "frozen"
    _exec("UPDATE member_access_window SET off_days_json='[]'")
    db.apply_local_date_flips(pc_now_epoch=epoch("2026-10-26T23:02:00"), grace_days=0, source="test")
    assert _ids("sync_users") == {1}
    assert hold(db)["moved"] == 1
    assert _q("SELECT held_reason FROM sync_users_held")[0]["held_reason"] == "off_hours"


def test_full_and_delta_saves_rehold_using_existing_intent(db):
    seed(db)
    hold(db)
    for delta in (False, True):
        db.save_sync_cache_delta(payload(membersDeltaMode=delta, validMemberIds=[1]), MEMBERS_ONLY)
        assert _ids("sync_users") == {1}
        out = hold(db)
        assert not out["newly_held"] and out["retry"] == [1] and out["moved"] == 1
    db.save_sync_cache(None)
    assert not _ids("off_hours_hold") and not db.off_hours_in_play()


@pytest.mark.parametrize("sql", ["UPDATE access_v2_state SET trusted=0",
                                      "UPDATE access_v2_state SET clock_suspect=1",
                                      "UPDATE access_v2_state SET utc_offset_sec=NULL",
                                      "DROP TABLE member_access_window", "DROP TABLE off_hours_hold"])
def test_uncertain_input_releases_every_off_hours_hold(db, sql):
    seed(db)
    hold(db)
    _exec(sql)
    out = hold(db)
    assert not out["active"] and out["released"] == [1]
    assert _ids("sync_users") == {1} and not _ids("sync_users_held")
    if "off_hours_hold" not in sql:
        assert not _ids("off_hours_hold")


def test_fast_patch_forgets_hours_and_intent(db):
    seed(db)
    hold(db)
    db._run_db_write_sync("test", lambda c, p: db._forget_protocol2_membership(c.cursor(), 1))
    assert not _ids("off_hours_hold") and not _ids("sync_users_held")


def test_explicit_fail_open_releases_despite_a_closed_window(db):
    seed(db)
    hold(db)
    out = db.apply_off_hours(pc_now_epoch=epoch("2026-10-26T23:00:00"), source="read_error", force_release=True)
    assert out["released"] == [1] and not out["active"]
    assert _ids("sync_users") == {1} and not _ids("off_hours_hold")

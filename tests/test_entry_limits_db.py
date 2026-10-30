import json
from datetime import datetime

import pytest

from app.core import entry_limits as el
from tests.test_protocol2_save_and_flip import db, _q, _exec, _ids, MEMBERS_ONLY


def epoch(s):
    return datetime.fromisoformat(s + "+01:00").timestamp()


def usage(**kw):
    return {"asOf": None, "listFrom": "2026-11-01T00:00:00", "totalBefore": 0,
            "visits": [], "termStart": "2026-11-01", "termEnd": "2026-11-30", "from": None, **kw}


def row(am=1, **kw):
    return {"activeMembershipId": am, "userId": 7000 + am, "mainAccountId": 9000 + am,
            "fullName": "Member", "accessFrom": "2026-11-01", "accessUntil": "2026-11-30",
            "offDays": [], "entryLimits": {"perDay": 1, "visitMinutes": 180}, "entryUsage": usage(),
            "fingerprints": [{"fingerId": 0, "template": "kept"}], **kw}


def payload(users=None, **kw):
    return {"syncMeta": {"protocol": 2, "today": "2026-11-02", "horizonDays": 7,
                        "horizonEnd": "2026-11-09", "serverTime": "2026-11-02T05:00:00+01:00"},
            "currentWindowsVersion": "limits1", "refreshMembers": True, "membersDeltaMode": False,
            "users": [row()] if users is None else users, "memberWindows": [],
            "_clientReceivedAtEpoch": epoch("2026-11-02T05:00:00"), **kw}


def seed(db, **kw):
    db.save_sync_cache_delta(payload(**kw), MEMBERS_ONLY)
    db.apply_local_date_flips(pc_now_epoch=epoch("2026-11-02T05:00:00"), grace_days=0, source="test")


def hold(db, when="2026-11-02T08:00:00", **kw):
    return db.apply_off_hours(pc_now_epoch=epoch(when), source="test", **kw)


def test_window_sources_roundtrip_limits_and_usage(db):
    seed(db, memberWindows=[row(2)], upcoming=[row(3, accessFrom="2026-11-03", qrAccountId=3)],
         upcomingIds=[3], upcomingCredentials=[])
    with db.get_conn() as conn:
        today, upcoming, qr = db._read_protocol2_windows(conn)
    for w in (today[1], today[2], upcoming[3]):
        assert w.entry_limits == el.parse_limits(row()["entryLimits"])
        assert w.entry_usage == el.parse_usage(usage())
    assert qr == {3: 3}
    stored = _q("SELECT entry_limits_json, entry_usage_json FROM member_access_window WHERE active_membership_id=1")[0]
    assert stored["entry_limits_json"] == json.dumps(row()["entryLimits"], separators=(",", ":"), sort_keys=True)
    assert stored["entry_usage_json"] == json.dumps(usage(), separators=(",", ":"), sort_keys=True)


def test_window_without_limits_stores_null(db):
    r = row()
    r.pop("entryLimits")
    r.pop("entryUsage")
    seed(db, users=[r], upcoming=[dict(r, activeMembershipId=2, accessFrom="2026-11-03")],
         upcomingIds=[2], upcomingCredentials=[])
    for table in ("member_access_window", "sync_upcoming_users"):
        stored = _q(f"SELECT entry_limits_json, entry_usage_json FROM {table}")[0]
        assert stored["entry_limits_json"] is None and stored["entry_usage_json"] is None
    assert db.load_access_days_snapshot().windows[1].entry_limits is None


def test_bad_limit_payload_keeps_dates_and_stores_null(db):
    seed(db, users=[row(entryLimits={"perDay": True}, entryUsage={"visits": "bad"})])
    w = db.load_access_days_snapshot().windows[1]
    assert w.entry_limits is None and w.entry_usage is None


@pytest.mark.parametrize("action", ["logout", "forget"])
def test_hold_reason_is_forgotten(db, action):
    seed(db)
    _exec("INSERT INTO entry_limit_hold (active_membership_id, until_text, reasons) VALUES (?, ?, ?)",
          (1, "2026-11-02T23:55:00", "DAY"))
    if action == "logout":
        db.save_sync_cache(None)
    else:
        db._run_db_write_sync("test", lambda c, p: db._forget_protocol2_membership(c.cursor(), 1))
    assert not _ids("entry_limit_hold")

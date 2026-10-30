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


def add_pass(uid=7001, when="2026-11-02T05:00:00", created="2026-11-02 05:00:00", allowed=1, event="pass1"):
    _exec("INSERT INTO access_history (event_id, user_id, event_time, created_at, allowed) VALUES (?, ?, ?, ?, ?)",
          (event, uid, when, created, allowed))


def test_local_pass_holds_at_visit_end_and_releases_with_lead(db):
    seed(db)
    add_pass()
    assert not hold(db, "2026-11-02T07:59:00")["newly_held"]
    assert _ids("sync_users") == {1} and not _ids("entry_limit_hold")
    out = hold(db)
    assert out["newly_held"] == [1] and out["entry_hold_changed"]
    assert _ids("sync_users_held") == _ids("off_hours_hold") == _ids("entry_limit_hold") == {1}
    assert not _ids("sync_users")
    assert _q("SELECT reasons, until_text FROM entry_limit_hold") == [
        {"reasons": "DAY", "until_text": "2026-11-02T23:55:00"}]
    assert _q("SELECT held_reason FROM sync_users_held")[0]["held_reason"] == "off_hours"
    assert json.loads(_q("SELECT fingerprints_json FROM sync_users_held")[0]["fingerprints_json"])
    assert not hold(db)["entry_hold_changed"]
    assert hold(db, "2026-11-02T23:55:00")["released"] == [1]
    assert _ids("sync_users") == _ids("off_hours_release_pending") == {1}
    assert not _ids("entry_limit_hold") and not _ids("off_hours_hold")


def test_backend_visits_alone_hold(db):
    seed(db, users=[row(entryUsage=usage(visits=["2026-11-02T05:00:00"]))])
    assert hold(db)["newly_held"] == [1]
    assert _ids("entry_limit_hold") == {1}


def test_unlimited_deliverable_second_membership_wins(db):
    seed(db, users=[row(entryUsage=usage(visits=["2026-11-02T05:00:00"])),
                    row(2, userId=7001, entryLimits=None, entryUsage=None)])
    add_pass()
    assert not hold(db)["newly_held"]
    assert _ids("sync_users") == {1, 2} and not _ids("entry_limit_hold")


def test_date_invalid_unlimited_membership_does_not_win(db):
    seed(db, users=[row(entryUsage=usage(visits=["2026-11-02T05:00:00"])),
                    row(2, userId=7001, entryLimits=None, entryUsage=None, offDays=["2026-11-02"])])
    assert hold(db)["newly_held"] == [1]


@pytest.mark.parametrize("sql", ["UPDATE access_v2_state SET trusted=0",
                                 "UPDATE access_v2_state SET clock_suspect=1",
                                 "UPDATE access_v2_state SET utc_offset_sec=NULL"])
def test_uncertain_state_releases_and_clears_reasons(db, sql):
    seed(db, users=[row(entryUsage=usage(visits=["2026-11-02T05:00:00"]))])
    hold(db)
    _exec(sql)
    assert hold(db)["released"] == [1]
    assert _ids("sync_users") == {1}
    assert not _ids("entry_limit_hold") and not _ids("off_hours_hold")


def test_suspect_clock_and_force_release_clear_reasons(db):
    seed(db, users=[row(entryUsage=usage(visits=["2026-11-02T05:00:00"]))])
    hold(db)
    assert hold(db, "2026-11-01T04:00:00")["released"] == [1]
    assert not _ids("entry_limit_hold")
    hold(db)
    assert hold(db, force_release=True)["released"] == [1]
    assert not _ids("entry_limit_hold")


def test_unreadable_history_releases_entry_hold(db, monkeypatch):
    seed(db)
    add_pass()
    hold(db)
    def fail(*args):
        raise OSError("unreadable history")
    monkeypatch.setattr(db, "list_allowed_passes_for_users", fail)
    assert hold(db)["released"] == [1]
    assert not _ids("entry_limit_hold")


def test_entry_rule_exception_keeps_hours_only_plan(db, monkeypatch):
    hours = [{"day": "MON", "startMinute": 420, "durationMinutes": 120}]
    seed(db, users=[row(offHours=hours, entryUsage=usage(visits=["2026-11-02T05:00:00"]))])
    hold(db)
    def fail(*args):
        raise ValueError("invalid rule input")
    monkeypatch.setattr(el, "merged_state", fail)
    out = hold(db)
    assert not out["released"] and not _ids("entry_limit_hold")
    assert _ids("off_hours_hold") == _ids("sync_users_held") == {1}


def test_hours_and_entry_limit_union_stays_held_until_both_clear(db):
    hours = [{"day": "MON", "startMinute": 1320, "durationMinutes": 480}]
    seed(db, users=[row(offHours=hours, entryUsage=usage(visits=["2026-11-02T05:00:00"]))])
    hold(db)
    assert not hold(db, "2026-11-02T23:55:00")["released"]
    assert not _ids("entry_limit_hold") and _ids("off_hours_hold") == {1}
    assert hold(db, "2026-11-03T05:55:00")["released"] == [1]


def test_new_term_window_releases_old_total_hold(db):
    seed(db, users=[row(entryLimits={"total": 1}, entryUsage=usage(visits=["2026-11-02T05:00:00"]))])
    hold(db)
    db.save_sync_cache_delta(payload(users=[row(entryLimits={"total": 1}, entryUsage=usage(
        termStart="2026-11-02", listFrom="2026-11-02T08:00:00"))]), MEMBERS_ONLY)
    assert hold(db)["released"] == [1]
    assert _ids("sync_users") == {1} and not _ids("entry_limit_hold")


def test_no_limits_reads_no_history_and_does_not_rewrite_reason_table(db, monkeypatch):
    seed(db, users=[row(entryLimits=None, entryUsage=None)])
    def forbidden(*args):
        pytest.fail("history must not be read without limits")
    monkeypatch.setattr(db, "list_allowed_passes_for_users", forbidden)
    assert not db.off_hours_in_play()
    out = hold(db)
    assert not out["entry_hold_changed"] and _ids("sync_users") == {1}


def test_history_is_read_before_writer_job(db, monkeypatch):
    import threading
    seed(db)
    add_pass()
    caller = threading.get_ident()
    original = db.list_allowed_passes_for_users
    calls = []
    def read(*args):
        assert threading.get_ident() == caller
        calls.append("read")
        return original(*args)
    monkeypatch.setattr(db, "list_allowed_passes_for_users", read)
    hold(db)
    assert calls == ["read"]


def test_history_times_match_upload_and_filter_allowed_and_created(db):
    from app.core.device_attendance import _normalize_datetime_text
    seed(db)
    add_pass(when="2026-11-02T05:00:00+02:00")
    add_pass(when="junk", event="fallback")
    add_pass(allowed=0, event="refused")
    add_pass(created="2026-10-20 05:00:00", event="old")
    times = db.list_allowed_passes_for_users([7001], "2026-10-30 00:00:00")[7001]
    assert sorted(times) == sorted([
        datetime.fromisoformat(_normalize_datetime_text("2026-11-02T05:00:00+02:00", fallback="2026-11-02 05:00:00")),
        datetime(2026, 11, 2, 5)])
    assert all(t.tzinfo is None for t in times)


def test_history_user_list_is_chunked(db):
    seed(db)
    add_pass(uid=7501)
    result = db.list_allowed_passes_for_users(range(7001, 8002), "2026-10-30 00:00:00")
    assert result[7501] == [datetime(2026, 11, 2, 5)]
    assert len(result) == 1001


def test_failed_reason_rewrite_invalidates_snapshot_without_moving_hours_hold(db):
    from app.core import access_verification as av
    hours = [{"day": "MON", "startMinute": 420, "durationMinutes": 120}]
    seed(db, users=[row(offHours=hours, entryUsage=usage(visits=["2026-11-02T05:00:00"]))])
    hold(db)
    assert av.current_access_days().entry_limit_held == {1}
    generation = db.get_local_state_generation()
    _exec("CREATE TRIGGER reject_entry_reason BEFORE INSERT ON entry_limit_hold "
          "BEGIN SELECT RAISE(FAIL, 'reason write failed'); END")
    _exec("UPDATE member_access_window SET entry_limits_json = ?", ('{"total":1}',))
    out = hold(db)
    assert out["moved"] == 0 and not out["intent_changed"] and out["entry_hold_ids_changed"]
    assert db.get_local_state_generation() > generation
    assert not av.current_access_days().entry_limit_held
    assert _ids("off_hours_hold") == {1} and not _ids("entry_limit_hold")

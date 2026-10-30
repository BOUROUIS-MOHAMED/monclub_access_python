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
    assert _ids("off_hours_release_pending") == {1}
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
    assert not _ids("off_hours_release_pending")


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
                                      "DROP TABLE member_access_window", "DROP TABLE off_hours_hold",
                                      "DROP TABLE off_hours_release_pending", "DROP TABLE off_hours_release_ack"])
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
    assert _ids("off_hours_release_pending") == {1}


@pytest.mark.parametrize("action", ["held_again", "fast_patch", "logout"])
def test_pending_release_is_cancelled_when_no_longer_wanted(db, action):
    seed(db)
    hold(db)
    db.apply_off_hours(pc_now_epoch=epoch("2026-10-26T23:00:00"), source="test", force_release=True)
    assert _ids("off_hours_release_pending") == {1}
    if action == "held_again":
        hold(db)
    elif action == "fast_patch":
        db._run_db_write_sync("test", lambda c, p: db._forget_protocol2_membership(c.cursor(), 1))
    else:
        db.save_sync_cache(None)
    assert not _ids("off_hours_release_pending")
    assert not _ids("off_hours_release_ack")


def test_release_ack_requires_every_owned_ultra_and_ignores_old_generation(db):
    from tests.test_account_pin_device_sites import _pullsdk_device
    seed(db)
    db._run_db_write_sync("test", lambda c, p: [
        db._insert_device_row(c.cursor(), _pullsdk_device(id=did)) for did in (1, 2)])
    for did in (1, 2):
        db.save_device_sync_state(device_id=did, pin="1", desired_hash="h", ok=True, error=None)
    hold(db)
    # The physical hold removes the ownership row, but its durable removal fact remains.
    for did in (1, 2):
        db.clear_device_revocation_state(device_id=did, pin="1")
    hold(db, "2026-10-27T05:55:00")
    token = db.list_off_hours_release_pending()[1]
    db.acknowledge_off_hours_release(active_membership_id=1, device_id=1, queued_at=token)
    assert _ids("off_hours_release_pending") == {1}
    # Simulate loss of all in-memory device state between the acknowledgements.
    db._shutdown_db_writer_for_tests()
    db.acknowledge_off_hours_release(active_membership_id=1, device_id=2, queued_at=token)
    assert not _ids("off_hours_release_pending") and not _ids("off_hours_release_ack")
    hold(db)
    db.apply_off_hours(pc_now_epoch=epoch("2026-10-26T23:00:00"), source="test", force_release=True)
    assert db.list_off_hours_release_pending()[1] != token
    db.acknowledge_off_hours_release(active_membership_id=1, device_id=1, queued_at=token)
    assert _ids("off_hours_release_pending") == {1}


def _release_with_removals(db, devices, removed_ids):
    seed(db)
    db._run_db_write_sync("test", lambda c, p: [db._insert_device_row(c.cursor(), d) for d in devices])
    for d in devices:
        db.save_device_sync_state(device_id=d["id"], pin="1", desired_hash="h", ok=True, error=None)
    hold(db)
    for did in removed_ids:
        db.clear_device_revocation_state(device_id=did, pin="1")
    hold(db, "2026-10-27T05:55:00")
    return db.list_off_hours_release_pending()[1]


def test_out_of_service_device_does_not_block_release_ack(db):
    from tests.test_account_pin_device_sites import _pullsdk_device
    # Device 2 has no worker, so it can never acknowledge; it must not hold the queue open.
    token = _release_with_removals(
        db, [_pullsdk_device(id=1), _pullsdk_device(id=2, active=False)], (1, 2))
    db.acknowledge_off_hours_release(active_membership_id=1, device_id=1, queued_at=token)
    assert not _ids("off_hours_release_pending") and not _ids("off_hours_release_ack")


def test_device_filtering_the_member_out_does_not_block_release_ack(db):
    from tests.test_account_pin_device_sites import _pullsdk_device
    token = _release_with_removals(
        db, [_pullsdk_device(id=1), _pullsdk_device(id=2, allowedMemberships=[424242])], (1, 2))
    db.acknowledge_off_hours_release(active_membership_id=1, device_id=1, queued_at=token)
    assert not _ids("off_hours_release_pending")


def test_stale_removal_before_the_hold_does_not_make_a_device_required(db):
    from tests.test_account_pin_device_sites import _pullsdk_device
    import time
    seed(db)
    devices = [_pullsdk_device(id=1), _pullsdk_device(id=2)]
    db._run_db_write_sync("test", lambda c, p: [db._insert_device_row(c.cursor(), d) for d in devices])
    for d in devices:
        db.save_device_sync_state(device_id=d["id"], pin="1", desired_hash="h", ok=True, error=None)
    # Device 2 lost this pin days ago (an old, unrelated removal that is never pruned).
    db.clear_device_revocation_state(device_id=2, pin="1")
    db._run_db_write_sync("test", lambda c, p: c.execute(
        "UPDATE v2_removal_log SET removed_at = ? WHERE device_id = 2", (time.time() - 3 * 86400,)))
    hold(db)
    db.clear_device_revocation_state(device_id=1, pin="1")
    hold(db, "2026-10-27T05:55:00")
    assert _q("SELECT held_at FROM off_hours_release_pending")[0]["held_at"]
    token = db.list_off_hours_release_pending()[1]
    db.acknowledge_off_hours_release(active_membership_id=1, device_id=1, queued_at=token)
    assert not _ids("off_hours_release_pending")

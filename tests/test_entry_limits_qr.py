from dataclasses import replace
from datetime import date
from unittest.mock import patch

import pytest

from app.core import access_dates as ad, access_verification as av
from app.core.card_decision import decide_qr
from app.core.off_hours import OffWindow
from tests.test_off_hours_qr import check
from tests.test_totp_roster_check import _user
from tests.test_entry_limits_db import db, seed, row, usage, hold
from tests.test_protocol2_save_and_flip import _exec


def snapshot(**kw):
    return ad.AccessDaysSnapshot(True, date(2026, 11, 2), date(2026, 11, 2),
        date(2026, 11, 9), 0, {1: ad.AccessWindow(date(2026, 11, 1), date(2026, 11, 30))},
        utc_offset_sec=3600, entry_limit_held=frozenset({1}), **kw)


@pytest.mark.parametrize("mode", ["trial", "enforce"])
@pytest.mark.parametrize("index", [False, True])
def test_entry_held_member_refused(mode, index):
    result = check("2026-11-02T08:00:00", snap=snapshot(), mode=mode, index=index)
    assert not result["allowed"] and result["reason"] == "ENTRY_LIMIT"


def test_second_open_grant_allows():
    snap = snapshot()
    snap = replace(snap, windows={**snap.windows, 2: snap.windows[1]})
    assert check("2026-11-02T08:00:00", snap=snap, grants=(1, 2))["allowed"]


def test_mixed_hours_and_limits_refused_as_entry_limit():
    snap = snapshot()
    snap = replace(snap, windows={**snap.windows,
        2: replace(snap.windows[1], off_hours=(OffWindow(0, 420, 120),))})
    result = check("2026-11-02T08:00:00", snap=snap, grants=(1, 2))
    assert not result["allowed"] and result["reason"] == "ENTRY_LIMIT"


def test_all_closed_by_hours_keeps_hours_reason():
    snap = snapshot()
    closed = replace(snap.windows[1], off_hours=(OffWindow(0, 420, 120),))
    snap = replace(snap, windows={1: closed, 2: closed})
    assert check("2026-11-02T08:00:00", snap=snap, grants=(1, 2))["reason"] == "OFF_HOURS"


def test_empty_hold_set_does_not_change_result():
    snap = replace(snapshot(), entry_limit_held=frozenset())
    result = check("2026-11-02T08:00:00", snap=snap, users={1: _user(1)}, mode="enforce")
    assert result["allowed"] and result["reason"] == "ALLOW"


def test_date_refusal_keeps_priority():
    snap = snapshot()
    snap = replace(snap, windows={1: replace(snap.windows[1], access_until=date(2026, 11, 1))})
    assert check("2026-11-02T08:00:00", snap=snap, mode="enforce")["reason"] == "DENY_NOT_ALLOWED_TODAY"


@pytest.mark.parametrize("kw", [{"trusted": False}, {"clock_suspect": True}, {"utc_offset_sec": None}])
def test_uncertainty_adds_no_entry_refusal(kw):
    snap = replace(snapshot(), **kw)
    assert check("2026-11-02T08:00:00", snap=snap, users={1: _user(1)}, mode="enforce")["allowed"]


def test_entry_refusal_is_final_for_resilient_and_card_decision():
    refused = {"allowed": False, "reason": "ENTRY_LIMIT", "user": None}
    with patch.object(av, "verify_totp", return_value=refused) as verify:
        result = av.verify_totp_resilient(scanned="123", settings={}, creds_payload=[],
            users_by_am={}, users_by_card={}, scan_epoch=1)
    assert verify.call_count == 1 and result["reason"] == "ENTRY_LIMIT"
    verdict = decide_qr(totp_result=result, settings={}, users_by_am={}, staff_ids=(), guard=None, now=1)
    assert not verdict.allowed and verdict.reason == "ENTRY_LIMIT"


def test_generation_refresh_when_entry_hold_joins_existing_hours_hold(db):
    hours = [{"day": "MON", "startMinute": 420, "durationMinutes": 120}]
    seed(db, users=[row(offHours=hours, entryUsage=usage(visits=["2026-11-02T05:00:00"]))])
    hold(db, "2026-11-02T07:30:00")
    before = av.current_access_days()
    assert not before.entry_limit_held
    generation = db.get_local_state_generation()
    out = hold(db)
    assert out["moved"] == 0 and not out["intent_changed"] and out["entry_hold_changed"]
    assert db.get_local_state_generation() > generation
    fresh = av.current_access_days()
    assert fresh is not before and fresh.entry_limit_held == {1}
    assert check("2026-11-02T08:00:00", snap=fresh)["reason"] == "OFF_HOURS"
    out = hold(db, "2026-11-02T09:00:00")
    assert not out["released"] and out["moved"] == 0
    assert check("2026-11-02T09:00:00", snap=av.current_access_days())["reason"] == "ENTRY_LIMIT"


def test_running_visit_never_entry_refused_then_reset_allows(db):
    seed(db, users=[row(entryUsage=usage(visits=["2026-11-02T05:00:00"]))])
    hold(db, "2026-11-02T07:59:00")
    assert check("2026-11-02T07:59:00", snap=db.load_access_days_snapshot(), users={1: _user(1)})["allowed"]
    hold(db)
    assert check("2026-11-02T08:00:00", snap=db.load_access_days_snapshot())["reason"] == "ENTRY_LIMIT"
    hold(db, "2026-11-02T23:55:00")
    assert check("2026-11-02T23:55:00", snap=av.current_access_days(), users={1: _user(1)})["allowed"]


def test_snapshot_reason_read_error_fails_open(db):
    seed(db)
    _exec("DROP TABLE entry_limit_hold")
    snap = db.load_access_days_snapshot()
    assert snap is not None and not snap.entry_limit_held

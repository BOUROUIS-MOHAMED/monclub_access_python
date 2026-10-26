from dataclasses import replace
from datetime import date, datetime
import random
from unittest.mock import patch

import pytest

from app.core import access_dates as ad, access_verification as av
from app.core.card_decision import decide_qr
from app.core.off_hours import OffWindow
from tests.test_totp_index import _code_for, _settings
from tests.test_totp_roster_check import _cred, _user


def snapshot(**kw):
    return ad.AccessDaysSnapshot(True, date(2026, 10, 26), date(2026, 10, 26),
        date(2026, 11, 2), 0, {1: ad.AccessWindow(date(2026, 10, 1), date(2026, 11, 30),
                                               off_hours=(OffWindow(0, 1320, 480),))},
        utc_offset_sec=3600, **kw)


def check(when="2026-10-26T23:00:00", *, mode="trial", snap=None, users=None, grants=(1,), index=False):
    now = datetime.fromisoformat(when + "+01:00").timestamp()
    cred = _cred(1, list(grants), random.Random(71))
    settings = _settings(totp_roster_check_mode=mode)
    idx = av.build_totp_index([cred], settings, now, margin=1) if index else None
    return av.verify_totp(scanned=_code_for(cred, settings, now), settings=settings,
        creds_payload=[cred], users_by_am={99: _user(99)} if users is None else users, users_by_card={},
        now_unix=now, totp_index=idx, access_days=snap or snapshot(),
        access_days_index=snap or snapshot())


@pytest.mark.parametrize("mode", ["trial", "enforce"])
@pytest.mark.parametrize("index", [False, True])
def test_held_absent_member_denied_in_both_modes_and_index(mode, index):
    result = check(mode=mode, index=index)
    assert not result["allowed"] and result["reason"] == "OFF_HOURS"


@pytest.mark.parametrize("when,allowed", [("2026-10-27T05:57:00", False), ("2026-10-27T06:00:00", True)])
def test_qr_uses_exact_end_even_during_turnstile_lead(when, allowed):
    result = check(when, users={1: _user(1)})
    assert result["allowed"] is allowed
    assert result["reason"] == ("ALLOW" if allowed else "OFF_HOURS")


def test_two_grants_one_open_allows():
    snap = snapshot()
    snap = replace(snap, windows={**snap.windows, 2: replace(snap.windows[1], off_hours=())})
    assert check(snap=snap, grants=(1, 2))["allowed"]


@pytest.mark.parametrize("mode", ["trial", "enforce"])
def test_date_expired_keeps_date_reason(mode):
    snap = snapshot()
    snap = replace(snap, windows={1: replace(snap.windows[1], access_until=date(2026, 10, 25))})
    assert check(snap=snap, mode=mode)["reason"] == "DENY_NOT_ALLOWED_TODAY"


@pytest.mark.parametrize("kw", [{"trusted": False}, {"clock_suspect": True}, {"utc_offset_sec": None},
                                 {"windows": {}}])
def test_uncertain_or_no_hours_never_adds_a_refusal(kw):
    snap = replace(snapshot(), **kw)
    assert check(snap=snap, users={1: _user(1)}, mode="enforce")["allowed"]


def test_resilient_does_not_retry_and_card_decision_preserves_reason():
    refused = {"allowed": False, "reason": "OFF_HOURS", "user": None}
    with patch.object(av, "verify_totp", return_value=refused) as verify:
        result = av.verify_totp_resilient(scanned="123", settings={}, creds_payload=[],
            users_by_am={}, users_by_card={}, scan_epoch=1)
    assert verify.call_count == 1 and result["reason"] == "OFF_HOURS"
    verdict = decide_qr(totp_result=result, settings={}, users_by_am={}, staff_ids=(), guard=None, now=1)
    assert not verdict.allowed and verdict.reason == "OFF_HOURS"


def test_listed_but_expired_membership_keeps_date_priority():
    snap = snapshot()
    snap = replace(snap, windows={1: replace(snap.windows[1], access_until=date(2026, 10, 25))})
    assert check(snap=snap, mode="enforce", users={1: _user(1)})["reason"] == "DENY_NOT_ALLOWED_TODAY"

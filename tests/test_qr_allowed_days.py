"""P3b-1 QR allowed days: a matched QR code opens only on a day one of its memberships may enter.

The date check sits in verify_totp's ALLOW step, after the roster check (guide §3.1b) and from
the same grants and member list -- never in _iter_eligible_totp_creds / build_totp_index, which
the speed index shares. The verdict itself is access_dates.qr_date_verdict (pure, tested in
test_access_dates.py); here: its wiring, the credentials of the gym date (load_local_state),
the cached snapshot, the counters, and both engines end to end.
"""

from __future__ import annotations

import inspect
import pathlib
import random
import time
from datetime import date
from unittest.mock import patch

import pytest

import app.core.db as dbmod
from app.core import access_dates as ad
from app.core import access_verification as av
from tests.test_totp_index import _code_for, _settings, _strip
from tests.test_totp_roster_check import _cred, _ultra_scan, _ultra_worker, _user

GYM = "2026-09-20"
EVE = "2026-09-19"


def _d(s):
    return date.fromisoformat(s)


def _w(frm="2026-09-01", until="2026-09-30", off=()):
    return ad.AccessWindow(_d(frm), _d(until), frozenset(_d(x) for x in off), False)


def _snap(windows=None, *, gym=GYM, trusted=True, qr=None):
    return ad.AccessDaysSnapshot(
        trusted=trusted, gym_date=_d(gym) if gym else None, server_today=_d(GYM),
        horizon_end=_d("2026-09-27"), grace_days=0, windows=windows or {},
        upcoming_qr_account=qr or {},
    )


def _check(code, s, creds, users_by_am, now, snap, *, idx=None, roster_current=True):
    return av.verify_totp(
        scanned=code, settings=s, creds_payload=creds, users_by_am=users_by_am,
        users_by_card={}, now_unix=now, totp_index=idx, roster_current=roster_current,
        access_days=snap,
    )


def _no_date(d):
    return {k: v for k, v in _strip(d).items() if k != "dateCheck"}


@pytest.fixture(autouse=True)
def _fresh_access_days_cache():
    # The snapshot cache is process-wide, keyed on the local-state generation: a snapshot
    # one test loaded must never be what the next test's scan checks against.
    av._reset_access_days_cache_for_tests()
    yield
    av._reset_access_days_cache_for_tests()


@pytest.fixture
def world():
    rng = random.Random(41)
    c = {
        "member": _cred(1, [101], rng),        # listed; its window covers the gym date
        "expired": _cred(2, [202], rng),       # listed; its window ended the day before
        "frozen": _cred(3, [303], rng),        # listed; the gym date is one of its off days
        "several": _cred(4, [401, 402], rng),  # 401 ended (held off the list), 402 current
        "windowless": _cred(5, [505], rng),    # listed with no window (a v1 row / fast patch)
        "renewed": _cred(6, [606], rng),       # stale grant 606 ended; account 5006 listed on 909
        "held": _cred(7, [707], rng),          # ended, and the flip took it off the list
        "stale": _cred(8, [808], rng),         # no window and not listed: not in today's set
    }
    users = {am: _user(am) for am in (101, 202, 303, 402, 505)}
    users[909] = _user(909, mainAccountId=5006)
    windows = {
        101: _w(), 202: _w(until=EVE), 303: _w(off=[GYM]), 401: _w(until=EVE), 402: _w(),
        606: _w(until=EVE), 707: _w(until=EVE), 909: _w(),
    }
    return c, list(c.values()), users, _snap(windows)


# ---------------------------------------------------------------------------
# verify_totp: the verdict, in both roster modes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode", ["trial", "enforce"])
@pytest.mark.parametrize("which", ["expired", "frozen"])
def test_a_listed_member_outside_the_window_is_refused_in_both_modes(world, mode, which):
    c, creds, users, snap = world
    s = _settings(totp_roster_check_mode=mode)
    now = time.time()
    r = _check(_code_for(c[which], s, now), s, creds, users, now, snap)
    assert r["allowed"] is False and r["reason"] == "DENY_NOT_ALLOWED_TODAY"
    assert r["dateCheck"] == "not_today" and r["user"] is None
    assert r["scanMode"] == "QR_TOTP" and r["rosterCheck"] == av.ROSTER_IN
    assert r["rosterCheckMode"] == mode
    # the identification fields a roster refusal carries
    cred = c[which]
    assert r["credId"] == str(cred["id"]) and r["accountId"] == str(cred["accountId"])
    assert r["activeMembershipId"] == cred["grantedActiveMembershipIds"][0]
    assert {"matchedCounter", "ageSeconds", "tookMs"} <= set(r)


def test_an_expired_member_held_off_the_list_is_refused_by_date_in_trial(world):
    # Trial mode allows a not-listed code on the roster check; with trusted windows the
    # date check still refuses it -- its only grant provably ended.
    c, creds, users, snap = world
    s = _settings()
    now = time.time()
    r = _check(_code_for(c["held"], s, now), s, creds, users, now, snap)
    assert r["allowed"] is False and r["reason"] == "DENY_NOT_ALLOWED_TODAY"
    assert r["rosterCheck"] == av.ROSTER_NOT_IN and r["dateCheck"] == "not_today"


def test_enforce_reports_the_roster_refusal_first_and_it_carries_no_date_verdict(world):
    c, creds, users, snap = world
    s = _settings(totp_roster_check_mode="enforce")
    now = time.time()
    r = _check(_code_for(c["held"], s, now), s, creds, users, now, snap)
    assert r["allowed"] is False and r["reason"] == "DENY_NOT_IN_LOCAL_ROSTER"
    assert "dateCheck" not in r


@pytest.mark.parametrize("mode", ["trial", "enforce"])
def test_a_deliverable_grant_opens(world, mode):
    c, creds, users, snap = world
    s = _settings(totp_roster_check_mode=mode)
    now = time.time()
    r = _check(_code_for(c["member"], s, now), s, creds, users, now, snap)
    assert r["allowed"] is True and r["reason"] == "ALLOW" and r["dateCheck"] == "ok"
    assert r["user"] is users[101] and r["activeMembershipId"] == 101


def test_any_deliverable_grant_of_several_is_enough(world):
    c, creds, users, snap = world
    s = _settings(totp_roster_check_mode="enforce")
    now = time.time()
    r = _check(_code_for(c["several"], s, now), s, creds, users, now, snap)
    assert r["allowed"] is True and r["dateCheck"] == "ok"
    assert r["rosterCheck"] == av.ROSTER_IN and r["activeMembershipId"] == 402


def test_a_windowless_listed_row_opens(world):
    c, creds, users, snap = world
    s = _settings(totp_roster_check_mode="enforce")
    now = time.time()
    r = _check(_code_for(c["windowless"], s, now), s, creds, users, now, snap)
    assert r["allowed"] is True and r["dateCheck"] == "ok"


@pytest.mark.parametrize("mode", ["trial", "enforce"])
def test_a_stale_grant_of_a_renewed_member_opens_by_account(world, mode):
    c, creds, users, snap = world
    s = _settings(totp_roster_check_mode=mode)
    now = time.time()
    r = _check(_code_for(c["renewed"], s, now), s, creds, users, now, snap)
    assert r["allowed"] is True and r["rosterCheck"] == av.ROSTER_IN_BY_ACCOUNT
    assert r["dateCheck"] == "ok"
    assert r["activeMembershipId"] == 606 and r["user"] is None      # unchanged allow


def test_a_code_in_neither_the_windows_nor_the_list_is_the_roster_checks_question(world):
    # Review R2 (inverts the part-D rule): a grant with no stored window and no row carries no
    # date the PC knows. Refusing it by date turned trial mode into enforce for exactly the
    # members the roster trial counts -- e.g. a renewal whose stored grants are stale.
    c, creds, users, snap = world
    now = time.time()
    s = _settings()
    r = _check(_code_for(c["stale"], s, now), s, creds, users, now, snap)
    assert r["allowed"] is True and r["rosterCheck"] == av.ROSTER_NOT_IN
    assert r["dateCheck"] == "unchecked"
    s = _settings(totp_roster_check_mode="enforce")
    r = _check(_code_for(c["stale"], s, now), s, creds, users, now, snap)
    assert r["allowed"] is False and r["reason"] == "DENY_NOT_IN_LOCAL_ROSTER"


def test_an_empty_member_list_cannot_refuse_a_windowless_grant(world):
    c, creds, _u, snap = world
    s = _settings(totp_roster_check_mode="enforce")
    now = time.time()
    r = _check(_code_for(c["stale"], s, now), s, creds, {}, now, snap)
    assert r["allowed"] is True and r["rosterCheck"] == av.ROSTER_UNEVALUABLE
    assert r["dateCheck"] == "unchecked"


def test_but_a_window_still_refuses_with_an_empty_member_list(world):
    c, creds, _u, snap = world
    s = _settings(totp_roster_check_mode="enforce")
    now = time.time()
    r = _check(_code_for(c["expired"], s, now), s, creds, {}, now, snap)
    assert r["allowed"] is False and r["reason"] == "DENY_NOT_ALLOWED_TODAY"
    assert r["rosterCheck"] == av.ROSTER_UNEVALUABLE


@pytest.mark.parametrize("mode", ["trial", "enforce"])
def test_a_list_older_than_the_index_that_matched_leaves_a_windowless_grant_unchecked(world, mode):
    c, creds, users, snap = world
    s = _settings(totp_roster_check_mode=mode)
    now = time.time()
    idx = av.build_totp_index(creds, s, now, margin=1)
    r = _check(_code_for(c["stale"], s, now), s, creds, users, now, snap, idx=idx,
               roster_current=False)
    assert r["allowed"] is True and r["rosterCheck"] == av.ROSTER_BEHIND
    assert r["dateCheck"] == "unchecked"


def test_a_windowless_grant_is_unchecked_whatever_the_roster_currency(world):
    # Review R2: the date check no longer judges a grant it has no window for, so the list's
    # currency (the behind rule) cannot change its answer -- on the loop or a stale index.
    c, creds, users, snap = world
    s = _settings()
    now = time.time()
    stale_idx = av.build_totp_index(creds, s, now - 3600, margin=1)   # does not cover now
    for idx in (None, stale_idx):
        for current in (True, False):
            r = _check(_code_for(c["stale"], s, now), s, creds, users, now, snap, idx=idx,
                       roster_current=current)
            assert r["allowed"] is True and r["dateCheck"] == "unchecked"


def test_a_listed_grant_does_not_make_a_behind_list_prove_a_windowless_one_absent(world):
    # grants [A, B]: A has no window and is not listed, B is listed but ended. The list is
    # behind the index that matched: A may be a member newer than the list -> unchecked.
    rng = random.Random(5)
    mixed = _cred(20, [2001, 202], rng)
    c, creds, users, snap = world
    creds = creds + [mixed]
    s = _settings()
    now = time.time()
    idx = av.build_totp_index(creds, s, now, margin=1)
    r = _check(_code_for(mixed, s, now), s, creds, users, now, snap, idx=idx,
               roster_current=False)
    assert r["rosterCheck"] == av.ROSTER_IN
    assert r["allowed"] is True and r["dateCheck"] == "unchecked"


# ---------------------------------------------------------------------------
# No trusted windows: exactly today's behaviour
# ---------------------------------------------------------------------------

_ALLOW_KEYS_BEFORE_P3B1 = {
    "allowed", "reason", "scanMode", "accountId", "credId", "matchedCounter", "ageSeconds",
    "activeMembershipId", "rosterCheck", "rosterCheckMode", "user", "tookMs",
}


@pytest.mark.parametrize("mode", ["trial", "enforce"])
@pytest.mark.parametrize("which", list(
    ["member", "expired", "frozen", "several", "windowless", "renewed", "held", "stale",
     "nomatch"]))
@pytest.mark.parametrize("snap_kind", ["none", "untrusted", "no_applied_date"])
def test_without_trusted_windows_the_result_is_todays(world, mode, which, snap_kind):
    c, creds, users, snap = world
    s = _settings(totp_roster_check_mode=mode)
    now = time.time()
    code = "9" + "0" * 7 if which == "nomatch" else _code_for(c[which], s, now)
    other = {
        "none": None,
        "untrusted": _snap(dict(snap.windows), trusted=False),
        "no_applied_date": _snap(dict(snap.windows), gym=None),
    }[snap_kind]
    today = av.verify_totp(scanned=code, settings=s, creds_payload=creds, users_by_am=users,
                           users_by_card={}, now_unix=now)
    r = _check(code, s, creds, users, now, other)
    assert _no_date(r) == _no_date(today)
    if today.get("allowed") and today.get("scanMode") == "QR_TOTP":
        assert set(today) == _ALLOW_KEYS_BEFORE_P3B1 | {"dateCheck"}
        assert today["dateCheck"] == "unchecked" and r["dateCheck"] == "unchecked"
    else:
        assert r.get("reason") != "DENY_NOT_ALLOWED_TODAY"


# ---------------------------------------------------------------------------
# The speed index: same verdict, and never filtered by date
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode", ["trial", "enforce"])
@pytest.mark.parametrize("which", ["member", "expired", "frozen", "several", "windowless",
                                   "renewed", "held", "stale", "empty_list"])
def test_index_and_loop_reach_the_same_date_verdict(world, mode, which):
    c, creds, users, snap = world
    s = _settings(totp_roster_check_mode=mode)
    now = time.time()
    cred = c["stale" if which == "empty_list" else which]
    roster = {} if which == "empty_list" else users
    idx = av.build_totp_index(creds, s, now, margin=1)
    code = _code_for(cred, s, now)
    loop = _check(code, s, creds, roster, now, snap)
    indexed = _check(code, s, creds, roster, now, snap, idx=idx)
    assert _strip(loop) == _strip(indexed)


def test_the_index_is_blind_to_dates(world):
    c, creds, _u, _snap_ = world
    s = _settings()
    now = time.time()
    only_expired = [c["expired"]]
    idx = av.build_totp_index(only_expired, s, now, margin=1)
    assert idx["credCount"] == 1
    code = _code_for(c["expired"], s, now)[-7:]
    assert [h["credId"] for h in idx["index"][code]] == [str(c["expired"]["id"])]
    assert [e[0] for e in av._iter_eligible_totp_creds(creds)] == [x["id"] for x in creds]
    for fn in (av.build_totp_index, av._iter_eligible_totp_creds):
        assert "access_days" not in inspect.signature(fn).parameters


# ---------------------------------------------------------------------------
# verify_totp_resilient: a date refusal is final, like a roster refusal
# ---------------------------------------------------------------------------

def test_a_date_refusal_does_not_rerun_the_verification(world):
    c, creds, users, snap = world
    s = _settings()
    now = time.time()
    with patch("app.core.access_verification.verify_totp", wraps=av.verify_totp) as spy:
        r = av.verify_totp_resilient(
            scanned=_code_for(c["expired"], s, now), settings=s, creds_payload=creds,
            users_by_am=users, users_by_card={}, scan_epoch=now, access_days=snap,
        )
    assert r["reason"] == "DENY_NOT_ALLOWED_TODAY" and r["clockUsed"] == "scan"
    assert spy.call_count == 1
    assert spy.call_args.kwargs["access_days"] is snap


def test_a_date_refusal_found_on_the_wall_clock_retry_is_the_reported_verdict(world):
    c, creds, users, snap = world
    s = _settings()
    now = time.time()
    with patch("app.core.access_verification.verify_totp", wraps=av.verify_totp) as spy:
        r = av.verify_totp_resilient(
            scanned=_code_for(c["expired"], s, now), settings=s, creds_payload=creds,
            users_by_am=users, users_by_card={}, scan_epoch=now + 300, access_days=snap,
        )
    assert r["allowed"] is False and r["reason"] == "DENY_NOT_ALLOWED_TODAY"
    assert r["dateCheck"] == "not_today" and r["clockUsed"] == "wall"
    assert spy.call_count == 2
    assert all(call.kwargs["access_days"] is snap for call in spy.call_args_list)


def test_resilient_without_access_days_is_todays(world):
    c, creds, users, _snap_ = world
    s = _settings()
    now = time.time()
    r = av.verify_totp_resilient(
        scanned=_code_for(c["expired"], s, now), settings=s, creds_payload=creds,
        users_by_am=users, users_by_card={}, scan_epoch=now,
    )
    assert r["allowed"] is True and r["dateCheck"] == "unchecked"


# ---------------------------------------------------------------------------
# Counting and the [T] line
# ---------------------------------------------------------------------------

def _date_calls(tel):
    return [call for call in tel.call_args_list if call.args and call.args[0] == "QR_DATE_CHECK"]


def test_a_date_refusal_is_counted_and_logged_without_member_identity(world):
    c, creds, users, snap = world
    s = _settings()
    now = time.time()
    r = _check(_code_for(c["expired"], s, now), s, creds, users, now, snap)
    before = av.totp_roster_check_counts()
    with patch("app.core.access_verification._tel.event") as tel:
        av.record_totp_roster_check(r, source="ULTRA:9")
    after = av.totp_roster_check_counts()
    assert after["not_today"] - before["not_today"] == 1
    assert after[av.ROSTER_IN] - before[av.ROSTER_IN] == 1           # its roster verdict too
    [line] = _date_calls(tel)
    assert line.kwargs == {"source": "ULTRA:9", "verdict": "not_today"}


def test_a_trial_date_refusal_of_a_not_listed_code_is_not_a_roster_refusal(world):
    # ``refused`` keeps its meaning: codes the ROSTER check denied (enforce mode).
    c, creds, users, snap = world
    s = _settings()
    now = time.time()
    r = _check(_code_for(c["held"], s, now), s, creds, users, now, snap)
    before = av.totp_roster_check_counts()
    with patch("app.core.access_verification._tel.event") as tel:
        av.record_totp_roster_check(r, source="AGENT:3")
    after = av.totp_roster_check_counts()
    assert after[av.ROSTER_NOT_IN] - before[av.ROSTER_NOT_IN] == 1
    assert after[av.ROSTER_REFUSED] - before[av.ROSTER_REFUSED] == 0
    assert after["not_today"] - before["not_today"] == 1
    assert len(_date_calls(tel)) == 1
    roster_lines = [x for x in tel.call_args_list if x.args[0] == "QR_ROSTER_CHECK"]
    assert roster_lines[0].kwargs["allowed"] is False


def test_an_allowed_scan_logs_no_date_line(world):
    c, creds, users, snap = world
    s = _settings()
    now = time.time()
    r = _check(_code_for(c["member"], s, now), s, creds, users, now, snap)
    before = av.totp_roster_check_counts()
    with patch("app.core.access_verification._tel.event") as tel:
        av.record_totp_roster_check(r)
    assert av.totp_roster_check_counts()["not_today"] == before["not_today"]
    assert _date_calls(tel) == []


def test_the_summary_carries_the_date_refusals(monkeypatch):
    # monkeypatch puts the process-wide "next summary" gate back after the test.
    monkeypatch.setattr(av, "_roster_summary_next_mono", 0.0)
    with patch("app.core.access_verification._tel.event") as tel:
        assert av.maybe_log_totp_roster_summary(now_mono=1.0) is True
    assert tel.call_args.args[0] == "QR_ROSTER_SUMMARY"
    assert tel.call_args.kwargs["not_today"] == av.totp_roster_check_counts()["not_today"]


# ---------------------------------------------------------------------------
# The stored state: load_local_state and the cached snapshot (real temp SQLite)
# ---------------------------------------------------------------------------

@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "qr_days.db"), raising=False)
    dbmod._shutdown_db_writer_for_tests()
    dbmod.init_db()
    yield dbmod
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


def _exec(sql, params=()):
    def _w(conn, _profile):
        conn.execute(sql, params)
    dbmod._run_db_write_sync("test", _w)


def _state(applied, trusted=1):
    _exec("INSERT OR REPLACE INTO access_v2_state (id, trusted, applied_date, server_today, "
          "horizon_end, grace_days) VALUES (1, ?, ?, ?, '2026-09-27', 0)",
          (trusted, applied, EVE))


def _window(am, frm, until):
    _exec("INSERT INTO member_access_window VALUES (?, ?, ?, '[]', 0)", (am, frm, until))


def _upcoming(am, frm, qr_account):
    _exec("INSERT INTO sync_upcoming_users VALUES (?, '{}', ?, '2026-10-19', '[]', 0, ?)",
          (am, frm, qr_account))


def _store_cred(table, cred, enabled):
    _exec(f"INSERT INTO {table} VALUES (?, 1, ?, ?, ?, NULL, NULL, NULL, ?)",
          (cred["id"], cred["accountId"], cred["secretHex"], enabled,
           "[" + ",".join(str(g) for g in cred["grantedActiveMembershipIds"]) + "]"))


def _row(am, main=None):
    return {"activeMembershipId": am, "userId": 7000 + am, "membershipId": 1,
            "fullName": f"M{am}", "mainAccountId": main}


def test_an_upcoming_only_credential_opens_on_its_first_day(db):
    cred = _cred(9, [303], random.Random(3))               # account 5009
    _state(applied=GYM)
    _upcoming(303, GYM, 5009)
    _store_cred("sync_upcoming_credentials", cred, 0)
    db.upsert_delta_users([_row(303)])                      # the flip promoted the row
    creds, users, _cards = av.load_local_state()
    assert [(x["id"], x["enabled"]) for x in creds] == [(9, True)]
    assert db.list_sync_upcoming_credentials()[0]["enabled"] is False   # stored list unchanged
    s = _settings(totp_roster_check_mode="enforce")
    now = time.time()
    r = _check(_code_for(cred, s, now), s, creds, users, now, av.current_access_days())
    assert r["allowed"] is True and r["dateCheck"] == "ok" and r["activeMembershipId"] == 303


def test_but_not_the_day_before(db):
    cred = _cred(9, [303], random.Random(3))
    _state(applied=EVE)
    _upcoming(303, GYM, 5009)
    _store_cred("sync_upcoming_credentials", cred, 0)
    creds, users, _cards = av.load_local_state()
    assert creds == []
    s = _settings()
    now = time.time()
    r = _check(_code_for(cred, s, now), s, creds, users, now, av.current_access_days())
    assert r["allowed"] is False and r["reason"] == "DENY_NO_MATCH"


def test_a_renewal_adds_the_starting_membership_to_the_existing_credential(db):
    cred = _cred(1, [101], random.Random(4))                # account 5001
    _state(applied=GYM)
    _window(101, "2026-08-20", EVE)                         # the old plan ended yesterday
    _upcoming(303, GYM, 5001)                               # the new one starts today
    _store_cred("sync_gym_access_credentials", cred, 1)
    db.upsert_delta_users([_row(303, main=5001)])           # flip: 101 held, 303 promoted
    creds, users, _cards = av.load_local_state()
    assert creds[0]["grantedActiveMembershipIds"] == [101, 303]
    assert db.list_sync_gym_access_credentials()[0]["grantedActiveMembershipIds"] == [101]
    s = _settings(totp_roster_check_mode="enforce")
    now = time.time()
    r = _check(_code_for(cred, s, now), s, creds, users, now, av.current_access_days())
    assert r["allowed"] is True and r["dateCheck"] == "ok"
    assert r["rosterCheck"] == av.ROSTER_IN and r["activeMembershipId"] == 303


def test_untrusted_windows_leave_the_stored_credentials_as_they_are(db):
    cred, up = _cred(1, [101], random.Random(4)), _cred(9, [303], random.Random(3))
    _state(applied=GYM, trusted=0)
    _upcoming(303, GYM, 5001)
    _store_cred("sync_gym_access_credentials", cred, 1)
    _store_cred("sync_upcoming_credentials", up, 0)
    creds, _u, _c = av.load_local_state()
    assert creds == db.list_sync_gym_access_credentials()


@pytest.mark.parametrize("broken", ["load_access_days_snapshot", "list_sync_upcoming_credentials",
                                    "effective_credentials"])
def test_a_failed_date_read_keeps_the_stored_credentials(db, broken):
    cred, up = _cred(1, [101], random.Random(4)), _cred(9, [303], random.Random(3))
    _state(applied=GYM)
    _upcoming(303, GYM, 5001)
    _store_cred("sync_gym_access_credentials", cred, 1)
    _store_cred("sync_upcoming_credentials", up, 0)
    with patch(f"app.core.access_verification.{broken}", side_effect=RuntimeError("boom")):
        creds, _u, _c = av.load_local_state()
    assert creds == db.list_sync_gym_access_credentials()


def test_the_snapshot_is_cached_per_generation(db):
    _state(applied=GYM)
    first = av.current_access_days()
    assert first.active and first.gym_date == _d(GYM)
    _exec("UPDATE access_v2_state SET applied_date = '2026-09-21' WHERE id = 1")
    assert av.current_access_days() is first                # same generation: no reload
    db.bump_local_state_generation()
    second = av.current_access_days()
    assert second.gym_date == _d("2026-09-21")


def test_a_failed_reload_keeps_the_previous_snapshot(db):
    _state(applied=GYM)
    first = av.current_access_days()
    db.bump_local_state_generation()
    with patch("app.core.access_verification.load_access_days_snapshot", return_value=None):
        assert av.current_access_days() is first
    av._reset_access_days_cache_for_tests()
    with patch("app.core.access_verification.load_access_days_snapshot",
               side_effect=RuntimeError("boom")):
        assert av.current_access_days() is None


def test_load_local_state_warms_the_snapshot(db):
    _state(applied=GYM)
    with patch("app.core.access_verification.load_access_days_snapshot",
               wraps=db.load_access_days_snapshot) as spy:
        av.load_local_state()
        snap = av.current_access_days()
    assert spy.call_count == 1 and snap.gym_date == _d(GYM)


def test_the_snapshot_of_one_database_is_never_served_for_another(db, tmp_path, monkeypatch):
    # Tests swap db._DB_PATH at one generation; a snapshot is only reused for its own file.
    _state(applied=GYM)
    assert av.current_access_days().active
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "other.db"), raising=False)
    dbmod._shutdown_db_writer_for_tests()
    dbmod.init_db()
    assert av.current_access_days().active is False


# ---------------------------------------------------------------------------
# Both engines, end to end through the real verifier and the stored snapshot
# ---------------------------------------------------------------------------

@pytest.fixture
def expired_member(db):
    _state(applied=GYM)
    _window(101, "2026-08-20", EVE)
    cred = _cred(1, [101], random.Random(8))
    return cred, [cred], {101: _user(101)}


@pytest.mark.parametrize("mode", ["trial", "enforce"])
def test_ultra_rescue_refuses_an_expired_member(expired_member, mode):
    cred, creds, users = expired_member
    s = {**_settings(), "totp_roster_check_mode": mode}
    worker = _ultra_worker(s, creds, users)
    before = av.totp_roster_check_counts()
    rec = _ultra_scan(worker, _code_for(cred, s, time.time()))
    assert worker._sdk.open_door.called is False
    assert rec.allowed is False and rec.reason == "DENY_NOT_ALLOWED_TODAY"
    assert av.totp_roster_check_counts()["not_today"] - before["not_today"] == 1


def test_ultra_rescue_opens_for_the_member_on_a_day_inside_the_window(expired_member):
    cred, creds, users = expired_member
    _exec("UPDATE member_access_window SET access_until = '2026-09-30'")
    s ={**_settings(), "totp_roster_check_mode": "enforce"}
    worker = _ultra_worker(s, creds, users)
    rec = _ultra_scan(worker, _code_for(cred, s, time.time()))
    worker._sdk.open_door.assert_called_once()
    assert rec.allowed is True


@pytest.mark.parametrize("mode", ["trial", "enforce"])
def test_agent_decision_refuses_an_expired_member(expired_member, mode):
    from tests.test_decision_service_anti_fraud import _make_ds, _make_event as _agent_event
    cred, creds, users = expired_member
    s = {**_settings(), "totp_roster_check_mode": mode,
         "anti_fraude_qr_code": False, "anti_fraude_card": False}
    ds, cmd_bus = _make_ds(settings_override=s)
    code = _code_for(cred, s, time.time())
    before = av.totp_roster_check_counts()

    def _seen():
        return av.totp_roster_check_counts()["not_today"] - before["not_today"]

    with (
        patch("app.core.realtime_agent.access_history_exists", return_value=False),
        patch("app.core.realtime_agent.insert_access_history", return_value=0),
        patch.object(ds, "_load_local_state", return_value=(creds, users, {})),
    ):
        ds.event_queue.put(_agent_event(card_no=code, event_time=""))
        ds.start()
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and _seen() < 1:
            time.sleep(0.01)
        time.sleep(0.2)  # a decision that opened would have reached the door by now
        ds.stop()

    assert _seen() == 1
    assert cmd_bus.open_door.called is False


# ---------------------------------------------------------------------------
# The popup says why
# ---------------------------------------------------------------------------

def test_the_popup_has_a_sentence_for_the_date_refusal():
    tsx = pathlib.Path(__file__).resolve().parents[1] / "tauri-ui" / "src" / "pages" / "PopupWindow.tsx"
    text = tsx.read_text(encoding="utf-8")
    line = next(x for x in text.splitlines() if x.strip().startswith("DENY_NOT_ALLOWED_TODAY:"))
    assert "Abonnement non valable aujourd'hui" in line
    assert "action:" in line     # rule 5: a refusal always says what to do

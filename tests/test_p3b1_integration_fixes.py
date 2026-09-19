"""P3b-1 integration fixes found when parts B (flip) and D (QR days) met.

1. The QR date snapshot is cached per local-state generation, so every change of what it
   describes must bump the generation: a flip that advances the applied gym date without
   moving a row, a change of trust (a v1 answer, a malformed one, a logout), a full replace.
2. A worker's member list and credentials can be one generation older than the current date
   snapshot for the few seconds before its refresh lands. The date verdict must use the
   snapshot of THAT list's generation, or a renewing member whose old plan ended yesterday is
   refused (the old list still names the old plan; the new snapshot says it ended).
"""
from __future__ import annotations

import random
import time
from unittest.mock import patch

import pytest

import app.core.db as dbmod
from app.core import access_verification as av
from tests.test_qr_allowed_days import (
    EVE, GYM, _d, _exec, _state, _upcoming, _window,
)
from tests.test_totp_index import _code_for, _settings
from tests.test_totp_roster_check import _cred, _ultra_scan, _ultra_worker, _user


@pytest.fixture(autouse=True)
def _fresh_access_days_cache():
    av._reset_access_days_cache_for_tests()
    yield
    av._reset_access_days_cache_for_tests()


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "fixes.db"), raising=False)
    dbmod._shutdown_db_writer_for_tests()
    dbmod.init_db()
    yield dbmod
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


def _epoch(iso):
    from datetime import datetime
    return datetime.fromisoformat(iso).timestamp()


def _trusted_state(server_today=EVE, applied=EVE):
    _exec("INSERT OR REPLACE INTO access_v2_state (id, trusted, server_today, horizon_end, "
          "server_time, server_epoch, utc_offset_sec, floor_date, max_pc_epoch, applied_date, "
          "grace_days) VALUES (1, 1, ?, '2026-09-26', '2026-09-19T20:00:00.000+01:00', ?, 3600, ?, ?, ?, 0)",
          (server_today, _epoch("2026-09-19T20:00:00+01:00"), server_today,
           _epoch("2026-09-19T20:00:00+01:00"), applied))


# ---------------------------------------------------------------------------- 1. generation
def test_a_flip_that_only_advances_the_date_bumps_the_generation(db):
    _trusted_state()
    _window(101, "2026-09-01", "2026-09-30")               # nothing to move tomorrow
    db.upsert_delta_users([{"activeMembershipId": 101, "userId": 7101, "membershipId": 1}])
    gen = db.get_local_state_generation()
    out = db.apply_local_date_flips(pc_now_epoch=_epoch("2026-09-20T07:30:00+01:00"),
                                    grace_days=0, source="test")
    assert out["moved"] == 0 and out["gym_date"] == GYM
    assert db.get_local_state_generation() > gen
    assert av.current_access_days().gym_date == _d(GYM)


def test_a_flip_on_the_same_date_moving_nothing_does_not_bump(db):
    _trusted_state()
    db.apply_local_date_flips(pc_now_epoch=_epoch("2026-09-19T21:00:00+01:00"), grace_days=0,
                              source="test")
    gen = db.get_local_state_generation()
    db.apply_local_date_flips(pc_now_epoch=_epoch("2026-09-19T21:05:00+01:00"), grace_days=0,
                              source="test")
    assert db.get_local_state_generation() == gen


def _meta():
    return {"protocol": 2, "today": EVE, "horizonDays": 7, "horizonEnd": "2026-09-26",
            "serverTime": "2026-09-19T20:00:00.000+01:00"}


def test_a_v1_answer_that_drops_trust_bumps_the_generation_even_without_sections(db):
    _trusted_state()
    gen = db.get_local_state_generation()
    db.save_sync_cache_delta({"refreshMembers": False, "users": []},
                             {"members": False, "devices": False, "credentials": False,
                              "settings": False})
    assert db.get_access_v2_state()["trusted"] is False
    assert db.get_local_state_generation() > gen
    assert av.current_access_days().active is False


def test_a_skipped_v2_answer_that_keeps_trust_does_not_bump(db):
    _trusted_state()
    gen = db.get_local_state_generation()
    db.save_sync_cache_delta({"syncMeta": _meta(), "refreshMembers": False, "users": [],
                              "currentWindowsVersion": "p2.7.a.b"},
                             {"members": False, "devices": False, "credentials": False,
                              "settings": False})
    assert db.get_access_v2_state()["trusted"] is True
    assert db.get_local_state_generation() == gen


def test_logout_and_a_full_replace_bump_the_generation(db):
    _trusted_state()
    gen = db.get_local_state_generation()
    db.save_sync_cache(None)
    assert db.get_local_state_generation() > gen
    gen = db.get_local_state_generation()
    db.save_sync_cache({"users": [{"activeMembershipId": 5, "userId": 6, "membershipId": 1}]})
    assert db.get_local_state_generation() > gen


# ---------------------------------------------------------------------------- 2. stale list
def test_the_snapshot_of_an_older_generation_is_served_to_an_older_list(db):
    _trusted_state(applied=EVE)
    gen = db.get_local_state_generation()
    old = av.current_access_days()
    assert old.gym_date == _d(EVE)
    _exec("UPDATE access_v2_state SET applied_date = ? WHERE id = 1", (GYM,))
    db.bump_local_state_generation()
    assert av.current_access_days().gym_date == _d(GYM)                   # the newest
    assert av.current_access_days(max_generation=gen) is old               # the list's own
    assert av.current_access_days(max_generation=gen + 1).gym_date == _d(GYM)


def test_no_snapshot_old_enough_means_no_date_check_not_a_newer_one(db):
    _trusted_state(applied=GYM)
    db.bump_local_state_generation()
    gen = db.get_local_state_generation()
    assert av.current_access_days().gym_date == _d(GYM)
    assert av.current_access_days(max_generation=gen - 1) is None


def test_a_renewing_member_scanned_on_a_list_older_than_the_flip_is_not_refused(db):
    """Old plan 101 ended yesterday; plan 303 of the same account starts today. The worker's
    list and credentials are from BEFORE the flip (grant 101, row 101); the flip's snapshot
    says 101 ended. Before the fix: DENY_NOT_ALLOWED_TODAY in both roster modes."""
    _trusted_state(applied=EVE)
    _window(101, "2026-08-20", EVE)
    _upcoming(303, GYM, 5001)
    cred = _cred(1, [101], random.Random(12))                       # account 5001
    list_gen = db.get_local_state_generation()
    assert av.current_access_days().gym_date == _d(EVE)            # warmed with the list
    # the flip: the day moved, 101 held, 303 promoted -- and the generation bumped
    _exec("UPDATE access_v2_state SET applied_date = ? WHERE id = 1", (GYM,))
    db.bump_local_state_generation()
    for mode in ("trial", "enforce"):
        s = {**_settings(), "totp_roster_check_mode": mode}
        worker = _ultra_worker(s, [cred], {101: _user(101, mainAccountId=5001)})
        worker._cached_state_gen = list_gen                         # the list predates the flip
        with patch.object(worker, "_trigger_bg_cache_refresh", lambda *a, **k: None):
            rec = _ultra_scan(worker, _code_for(cred, s, time.time()))
        assert rec.allowed is True, (mode, rec.reason)
        worker._sdk.open_door.assert_called_once()


def test_a_list_as_new_as_the_flip_still_refuses_an_expired_member(db):
    _trusted_state(applied=GYM)
    _window(101, "2026-08-20", EVE)
    db.bump_local_state_generation()
    cred = _cred(1, [101], random.Random(13))
    s = {**_settings(), "totp_roster_check_mode": "trial"}
    worker = _ultra_worker(s, [cred], {101: _user(101)})
    worker._cached_state_gen = db.get_local_state_generation()
    rec = _ultra_scan(worker, _code_for(cred, s, time.time()))
    assert rec.allowed is False and rec.reason == "DENY_NOT_ALLOWED_TODAY"

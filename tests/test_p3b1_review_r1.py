"""P3b-1 adversarial review, round 1: regressions for the confirmed findings.

1. A fast patch (ENTITY_UPSERT / ENTITY_DELETE of an ACTIVE_MEMBERSHIP) is newer than the stored
   protocol-2 data of that membership. The backend sends an upsert only for a membership
   deliverable today (AccessPatchBundleService.shouldExposeMembership), so the flip must not
   judge the fast-patched row by its stale window: the stored window, upcoming row and held copy
   of that membership are dropped (the row is windowless until the next members section) and so
   is windowsVersion (the stored lists changed), which makes the next sync serve the section.
2. The ULTRA QR rescue bounds the date snapshot by the generation of the data it actually
   matched (the shared index, or its own list at its exact generation) -- not by the generation
   the worker held before the call, which after a flip's cache reset is the pre-flip one.
3. A change of offline_revoke_grace_days is applied by the next precheck trigger, not only when
   the date moves.
4. A flip that moved rows hands the running ULTRA engine a roster reloaded after the flip: the
   cached pre-flip snapshot is dropped, and a load already in flight (it may predate the flip's
   commit) is never installed; a reader that waited for it loads again.

Real temp SQLite through the ``app.core.db._DB_PATH`` override; no network.
"""
from __future__ import annotations

import json
import random
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import app.core.db as dbmod
import app.core.ultra_engine as ue
from app.core import access_verification as av
from app.ui.app import MainApp
from tests.test_p3b1_integration_fixes import _epoch, _trusted_state
from tests.test_protocol2_save_and_flip import (
    MEMBERS_ONLY, _flip, _ids, _row, _seed_full_v2, _token, _v2, _windows,
)
from tests.test_qr_allowed_days import EVE, GYM, _exec, _store_cred
from tests.test_totp_index import _code_for, _settings
from tests.test_totp_roster_check import _cred, _ultra_scan, _ultra_worker


@pytest.fixture(autouse=True)
def _fresh():
    av._reset_access_days_cache_for_tests()
    yield
    av._reset_access_days_cache_for_tests()
    ue._set_shared_local_state(None, -1)
    ue._set_shared_totp_index(None, -1)


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "r1.db"), raising=False)
    dbmod._shutdown_db_writer_for_tests()
    dbmod.init_db()
    yield dbmod
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


# ================================================================== 1. fast patch vs stored windows
def _patch(db, bundle_id, kind, am, member=None, when="2026-09-19T11:00:00Z"):
    item = {"kind": kind, "entityType": "ACTIVE_MEMBERSHIP", "entityId": am, "revision": when}
    if member is not None:
        item["payload"] = {"member": member}
    return db.apply_fast_patch_bundle({"bundleId": bundle_id, "generatedAt": when, "items": [item]})


def _upcoming_ids():
    with dbmod.get_conn() as conn:
        return {int(r[0]) for r in conn.execute("SELECT active_membership_id FROM sync_upcoming_users")}


def test_a_pre_sale_moved_to_today_by_a_fast_patch_is_not_held_by_the_flip(db):
    # 3 is stored upcoming from 2026-09-20; the desk moves its start to today (the 19th).
    _seed_full_v2(db)
    _flip(db, "2026-09-19T10:30:00+01:00")
    _patch(db, "b-up-3", "ENTITY_UPSERT", 3, _row(3, frm="2026-09-19"))
    r = _flip(db, "2026-09-19T11:00:00+01:00")
    assert r["held"] == 0
    assert 3 in _ids("sync_users") and 3 not in _ids("sync_users_held")
    assert 3 not in _upcoming_ids() and 3 not in _windows()
    assert _token() is None                    # the stored lists changed: the next sync serves them


def test_a_same_id_renewal_by_fast_patch_is_not_held_the_next_morning(db):
    # 1's stored window ends on the 19th; the desk renews it at 19:00 (same id, new end); the PC
    # is switched off before any sync and comes back offline on the 20th.
    _seed_full_v2(db)
    _patch(db, "b-renew-1", "ENTITY_UPSERT", 1, _row(1, until="2026-10-19"),
           when="2026-09-19T18:00:00Z")
    r = _flip(db, "2026-09-20T07:30:00+01:00")
    assert 1 in _ids("sync_users") and 1 not in _ids("sync_users_held")
    assert r["hold_reasons"].get("expired", 0) == 0


def test_a_freeze_cancelled_by_fast_patch_is_not_held_on_the_freeze_day(db):
    # 2 is frozen on the 20th (an off day in its window); the desk cancels the freeze that day.
    _seed_full_v2(db)
    _flip(db, "2026-09-20T07:30:00+01:00")
    assert 2 in _ids("sync_users_held")
    _patch(db, "b-unfreeze-2", "ENTITY_UPSERT", 2, _row(2), when="2026-09-20T08:00:00Z")
    assert 2 not in _ids("sync_users_held")             # the fresher row supersedes the held copy
    r = _flip(db, "2026-09-20T08:05:00+01:00")
    assert r["held"] == 0 and 2 in _ids("sync_users")


def test_a_fast_patch_delete_of_a_pre_sale_is_never_promoted_again(db):
    _seed_full_v2(db)
    _patch(db, "b-del-3", "ENTITY_DELETE", 3)
    r = _flip(db, "2026-09-20T07:30:00+01:00")
    assert r["promoted"] == 0 and 3 not in _ids("sync_users")
    assert 3 not in _upcoming_ids() and _token() is None


def test_a_fast_patch_that_forgets_dates_moves_the_generation(db):
    _seed_full_v2(db)
    gen = db.get_local_state_generation()
    _patch(db, "b-up-5", "ENTITY_UPSERT", 5, _row(5, fullName="FRESH"))
    assert db.get_local_state_generation() > gen      # the QR date snapshot reloads


def test_the_next_members_section_brings_the_window_back(db):
    _seed_full_v2(db)
    _patch(db, "b-renew-1", "ENTITY_UPSERT", 1, _row(1, until="2026-10-19"))
    db.save_sync_cache_delta(_v2([_row(1, until="2026-10-19")], delta=True, valid=[1, 2, 5]),
                             MEMBERS_ONLY)
    assert _windows()[1][:2] == ("2026-09-01", "2026-10-19")
    assert _token() == "p2.7.a.b"


def test_a_fast_patch_for_another_entity_keeps_the_windows_version(db):
    _seed_full_v2(db)
    db.apply_fast_patch_bundle({"bundleId": "b-dev", "generatedAt": "2026-09-19T11:00:00Z", "items": [
        {"kind": "ENTITY_DELETE", "entityType": "GYM_DEVICE", "entityId": 77,
         "revision": "2026-09-19T11:00:00Z"}]})
    assert _token() == "p2.7.a.b"


def test_a_fast_patch_for_a_membership_without_stored_dates_keeps_the_windows_version(db):
    _seed_full_v2(db)
    _patch(db, "b-up-99", "ENTITY_UPSERT", 99, _row(99))
    assert _token() == "p2.7.a.b"


# ================================================================== 2. ULTRA rescue snapshot bound
def _person(am, main):
    return {"activeMembershipId": am, "userId": 7000 + am, "membershipId": 1,
            "fullName": f"M{am}", "mainAccountId": main}


def _world(db):
    """Evening of EVE (2026-09-19), trusted: 101 member, 202 ex-member (plan ends EVE),
    303 starter on GYM (upcoming-only account, credential stored disabled)."""
    _trusted_state()
    _exec("INSERT INTO member_access_window VALUES (101, '2026-09-01', '2026-09-30', '[]', 0)")
    _exec("INSERT INTO member_access_window VALUES (202, '2026-08-20', ?, '[]', 0)", (EVE,))
    _exec("INSERT INTO sync_upcoming_users VALUES (303, ?, ?, '2026-10-19', '[]', 0, 5009)",
          (json.dumps(_person(303, 5009)), GYM))
    db.upsert_delta_users([_person(101, 5001), _person(202, 5002)])
    rng = random.Random(99)
    c_member, c_ex, c_starter = _cred(1, [101], rng), _cred(2, [202], rng), _cred(9, [303], rng)
    _store_cred("sync_gym_access_credentials", c_member, 1)
    _store_cred("sync_gym_access_credentials", c_ex, 1)
    _store_cred("sync_upcoming_credentials", c_starter, 0)
    return c_member, c_ex, c_starter


def _run_refresh(worker, target_gen, timeout=10.0):
    """The worker's REAL refresh thread: load, publish the shared list, rebuild the index."""
    worker._trigger_bg_cache_refresh()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        _v, sg = ue._get_shared_local_state()
        _i, ig = ue._get_shared_totp_index()
        if sg >= target_gen and ig >= target_gen:
            break
        time.sleep(0.02)
    worker._stop_evt.set()
    return ue._get_shared_local_state()[1], ue._get_shared_totp_index()[1]


def _two_doors_after_a_flip(db, mode):
    creds = _world(db)
    s = {**_settings(), "totp_roster_check_mode": mode}
    g0 = db.get_local_state_generation()
    state0 = av.load_local_state()
    a = _ultra_worker(s, state0[0], state0[1])
    b = _ultra_worker(s, state0[0], state0[1])
    a._cached_state_gen = b._cached_state_gen = g0
    assert av.current_access_days().gym_date.isoformat() == EVE
    out = db.apply_local_date_flips(pc_now_epoch=_epoch("2026-09-20T07:30:00+01:00"),
                                    grace_days=0, source="test")
    assert out["held"] == 1 and out["promoted"] == 1
    a.reset_fast_patch_caches()            # what the app's flip wiring does to every worker
    b.reset_fast_patch_caches()
    return creds, s, a, b


@pytest.mark.parametrize("mode", ["trial", "enforce"])
def test_the_first_scan_at_the_other_door_after_a_flip_admits_the_starter(db, mode):
    (_m, _ex, c_starter), s, a, b = _two_doors_after_a_flip(db, mode)
    _run_refresh(b, db.get_local_state_generation())          # door B refreshed first
    rec = _ultra_scan(a, _code_for(c_starter, s, time.time()))
    assert rec.allowed is True, rec.reason


def test_the_first_scan_at_the_other_door_after_a_flip_refuses_the_ex_member(db):
    (_m, c_ex, _st), s, a, b = _two_doors_after_a_flip(db, "trial")
    _run_refresh(b, db.get_local_state_generation())
    rec = _ultra_scan(a, _code_for(c_ex, s, time.time()))
    assert rec.allowed is False and rec.reason == "DENY_NOT_ALLOWED_TODAY"


def test_a_quiet_door_still_date_checks_after_later_generations(db):
    (_m, c_ex, _st), s, a, b = _two_doors_after_a_flip(db, "trial")
    for _ in range(4):                     # later syncs, each followed by a snapshot load
        db.bump_local_state_generation()
        av.current_access_days()
    _run_refresh(b, db.get_local_state_generation())
    rec = _ultra_scan(a, _code_for(c_ex, s, time.time()))
    assert rec.allowed is False and rec.reason == "DENY_NOT_ALLOWED_TODAY"


def test_a_door_whose_own_refresh_lags_uses_the_date_of_the_list_and_index_it_checks(db):
    """No flip: 404 frozen today; the desk cancels the freeze; the next sync lists it and bumps.
    Door B refreshed first; door A's own refresh has not landed."""
    _trusted_state(server_today=GYM, applied=GYM)
    _exec("INSERT INTO sync_upcoming_users VALUES (404, ?, '2026-09-01', '2026-09-30', ?, 0, 5004)",
          (json.dumps(_person(404, 5004)), json.dumps([GYM])))
    c_u = _cred(4, [404], random.Random(5))
    _store_cred("sync_gym_access_credentials", c_u, 1)
    s = {**_settings(), "totp_roster_check_mode": "enforce"}
    g0 = db.get_local_state_generation()
    state0 = av.load_local_state()
    a = _ultra_worker(s, state0[0], state0[1])
    b = _ultra_worker(s, state0[0], state0[1])
    a._cached_state_gen = b._cached_state_gen = g0
    assert av.current_access_days().deliverable(404) is False
    _exec("DELETE FROM sync_upcoming_users WHERE active_membership_id = 404")
    _exec("INSERT INTO member_access_window VALUES (404, '2026-09-01', '2026-09-30', '[]', 0)")
    db.upsert_delta_users([_person(404, 5004)])
    db.bump_local_state_generation()
    _run_refresh(b, db.get_local_state_generation())
    with patch.object(a, "_trigger_bg_cache_refresh", lambda *x, **k: None):   # not landed
        rec = _ultra_scan(a, _code_for(c_u, s, time.time()))
    assert rec.allowed is True, rec.reason


# ================================================================== 3. a grace-days change
def test_the_precheck_reports_the_grace_days_it_last_applied(db):
    _seed_full_v2(db)
    db.apply_local_date_flips(pc_now_epoch=_epoch("2026-09-20T07:30:00+01:00"), grace_days=0,
                              source="test")
    st = db.gym_date_status(pc_now_epoch=_epoch("2026-09-20T09:00:00+01:00"))
    assert st["needs_flip"] is False and st["grace_days"] == 0


def _grace_app(db, grace):
    app = object.__new__(MainApp)
    app.logger = MagicMock()
    app.cfg = SimpleNamespace(offline_revoke_grace_days=grace)
    app._stop_event = threading.Event()
    MainApp._init_scheduler(app)
    MainApp._init_date_flip_state(app)
    app._ultra_lock = threading.Lock()
    app._ultra_engine = MagicMock(running=False)
    app._agent_engine = MagicMock()
    app.request_sync_now = MagicMock()
    return app


def test_a_grace_days_change_is_applied_by_the_next_precheck_trigger(db):
    # Offline since the 19th: the start-up flip on the 20th held 1 (ended the 19th). At 09:00 the
    # owner sets 2 grace days; the next tick / heartbeat / sync precheck applies it.
    _seed_full_v2(db)
    app = _grace_app(db, 0)
    app._date_flip_now = lambda: _epoch("2026-09-20T07:30:00+01:00")
    app._apply_date_flips("startup")
    assert 1 in _ids("sync_users_held")
    app.cfg.offline_revoke_grace_days = 2
    app._date_flip_now = lambda: _epoch("2026-09-20T09:00:00+01:00")
    app._maybe_apply_date_flips("heartbeat")
    assert 1 in _ids("sync_users") and 1 not in _ids("sync_users_held")


def test_an_unchanged_grace_setting_does_not_flip_again(db):
    _seed_full_v2(db)
    app = _grace_app(db, 0)
    app._date_flip_now = lambda: _epoch("2026-09-20T07:30:00+01:00")
    app._apply_date_flips("startup")
    app._apply_date_flips = MagicMock()
    app._date_flip_now = lambda: _epoch("2026-09-20T09:00:00+01:00")
    app._maybe_apply_date_flips("heartbeat")
    app._apply_date_flips.assert_not_called()


# ================================================================== 4. the roster ULTRA reloads
def _slow_stale_load(monkeypatch):
    """A background load that reads the database, then stalls until released."""
    real = dbmod._load_sync_cache_db
    started, release = threading.Event(), threading.Event()

    def slow():
        result = real()                       # reads BEFORE the caller's change
        started.set()
        release.wait(5)
        return result

    monkeypatch.setattr(dbmod, "_load_sync_cache_db", slow)
    dbmod.invalidate_sync_cache(clear_cached=True)
    assert dbmod.refresh_sync_cache_async() is True
    assert started.wait(5)
    monkeypatch.setattr(dbmod, "_load_sync_cache_db", real)
    return release


def _cached_ams():
    return {u.get("activeMembershipId") for u in dbmod.load_sync_cache().users}


def test_a_load_in_flight_before_an_invalidation_is_never_installed(db, monkeypatch):
    _seed_full_v2(db)
    release = _slow_stale_load(monkeypatch)
    _exec("DELETE FROM sync_users WHERE active_membership_id = 5")      # a flip's commit ...
    dbmod.invalidate_sync_cache(clear_cached=True)                       # ... and its invalidation
    release.set()                                                        # the stale load lands late
    time.sleep(0.3)
    assert 5 not in _cached_ams()


def test_a_reader_waiting_on_a_discarded_load_loads_again(db, monkeypatch):
    _seed_full_v2(db)
    release = _slow_stale_load(monkeypatch)
    got = {}
    reader = threading.Thread(target=lambda: got.setdefault("ams", _cached_ams()), daemon=True)
    reader.start()                            # waits on the stale load in flight
    time.sleep(0.1)
    _exec("DELETE FROM sync_users WHERE active_membership_id = 5")
    dbmod.invalidate_sync_cache(clear_cached=True)
    release.set()
    reader.join(10)
    assert got["ams"] is not None and 5 not in got["ams"]


def test_a_flip_that_moved_rows_reloads_the_roster_before_asking_ultra(db, monkeypatch):
    _seed_full_v2(db)
    dbmod.load_sync_cache()                   # a warm, pre-flip snapshot
    seen = {}
    app = _grace_app(db, 0)

    def request(**kw):
        seen["ams"] = {u.get("activeMembershipId") for u in dbmod.load_sync_cache().users}
        return True

    app._ultra_engine = SimpleNamespace(running=True, request_sync_now=request,
                                        reset_fast_patch_caches=lambda: None)
    out = app._apply_date_flips("midnight", pc_now=_epoch("2026-09-20T00:00:05+01:00"))
    assert out["held"] >= 1
    assert 1 not in seen["ams"] and 3 in seen["ams"]      # the post-flip roster

"""P3b-1 adversarial review, round 3: regressions for the confirmed findings.

Real temp SQLite through the ``app.core.db._DB_PATH`` override; no network.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import app.core.db as dbmod
from app.ui.app import MainApp
from tests.test_protocol2_save_and_flip import (
    MEMBERS_ONLY, _epoch, _flip, _ids, _meta, _row, _seed_full_v2, _v2, _window,
)


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "r3.db"), raising=False)
    dbmod._shutdown_db_writer_for_tests()
    dbmod.init_db()
    yield dbmod
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


# ================================================================== 1. a promoted row the server drops
def _shadow_sync(data, outcome):
    """The app's revocation source for a sync (MainApp._apply_member_shadow_sync), as work() calls it."""
    app = SimpleNamespace(logger=MagicMock())
    return MainApp._apply_member_shadow_sync(
        app, data=data, refresh=MEMBERS_ONLY, delta_changed_ids=None,
        cache_members_delete_refused=bool(outcome.get("members_delete_refused")),
        authoritative_member_ids=outcome.get("authoritative_member_ids"),
        authoritative_member_ids_valid=bool(outcome.get("authoritative_member_ids_valid", True)),
        accepted_member_user_indexes=outcome.get("accepted_member_user_indexes"),
        accepted_member_ids=outcome.get("accepted_member_ids"),
    )


def test_a_promoted_pre_sale_the_next_sync_drops_is_revoked(db):
    # Review R3: 3 (a pre-sale starting on the 20th) reached sync_users only through the flip, so
    # it was not in member_shadow; the sync that no longer lists it (cancelled offline) produced no
    # revocation and the turnstile kept its pin.
    seed = _v2([_row(1, until="2026-09-19"), _row(2, off=["2026-09-20"]), _row(5)],
               upcoming=[_row(3, frm="2026-09-20", qrAccountId=55)])
    _shadow_sync(seed, db.save_sync_cache_delta(seed, MEMBERS_ONLY) or {})
    r = _flip(db, "2026-09-20T07:30:00+01:00")
    assert r["promoted"] == 1 and 3 in _ids("sync_users")

    morning = _v2([], delta=True, valid=[5], member_windows=[_window(5)], upcoming=[],
                  meta=_meta(today="2026-09-20", horizon_end="2026-09-27",
                             server_time="2026-09-20T09:00:00.000+01:00"),
                  received=_epoch("2026-09-20T09:00:02+01:00"), windows_version="p2.7.c.d")
    out = db.save_sync_cache_delta(morning, MEMBERS_ONLY) or {}
    _changed, revoked = _shadow_sync(morning, out)
    assert 3 not in _ids("sync_users")
    assert 3 in revoked


def test_a_promoted_row_the_next_sync_lists_is_not_revoked(db):
    seed = _v2([_row(1, until="2026-09-19"), _row(5)],
               upcoming=[_row(3, frm="2026-09-20", qrAccountId=55)])
    _shadow_sync(seed, db.save_sync_cache_delta(seed, MEMBERS_ONLY) or {})
    _flip(db, "2026-09-20T07:30:00+01:00")
    morning = _v2([_row(3, frm="2026-09-20")], delta=True, valid=[3, 5],
                  member_windows=[_window(5)], upcoming=[],
                  meta=_meta(today="2026-09-20", horizon_end="2026-09-27",
                             server_time="2026-09-20T09:00:00.000+01:00"),
                  received=_epoch("2026-09-20T09:00:02+01:00"), windows_version="p2.7.c.d")
    _changed, revoked = _shadow_sync(morning, db.save_sync_cache_delta(morning, MEMBERS_ONLY) or {})
    assert 3 not in revoked and 3 in _ids("sync_users")


# ================================================================== 2. a known new pin on a full MB2000
import queue  # noqa: E402

import app.core.device_sync as ds  # noqa: E402
import app.core.telemetry as tel  # noqa: E402
import app.core.ultra_engine as ue  # noqa: E402
from tests.fake_terminal import TerminalZkem  # noqa: E402
from tests.test_standalone_incremental_sync import _make_driver, _worker  # noqa: E402

PERSON, OLD, NEW = 900, 34439, 30001
CAP = 5


class _FullTerm(TerminalZkem):
    """users_free follows the live table; a user not on the terminal is refused when it is full;
    ``status_readable`` False -> GetDeviceStatus fails; ``fail_once`` pins refused once."""

    def __init__(self):
        super().__init__()
        self.status_readable = True
        self.fail_once = set()

    def GetDeviceStatus(self, machine, idx, box):
        self.status = ({11: max(0, CAP - len(self.users)), 10: 1000}
                       if self.status_readable else {})
        return super().GetDeviceStatus(machine, idx, box)

    def SSR_SetUserInfo(self, machine, pin, name, pw, priv, enabled):
        p = str(pin)
        if p in self.fail_once:
            self.fail_once.discard(p)
            self._rec("SSR_SetUserInfo", machine, pin, name, pw, priv, enabled)
            return False
        if p not in self.users and len(self.users) >= CAP:
            self._rec("SSR_SetUserInfo", machine, pin, name, pw, priv, enabled)
            return False
        return super().SSR_SetUserInfo(machine, pin, name, pw, priv, enabled)


def _mrow(am, uid, name="Ali", card=""):
    return {"activeMembershipId": am, "userId": uid, "membershipId": 3, "fullName": name,
            "firstCardId": card, "fingerprints": []}


@pytest.mark.parametrize("variant", ["status_unreadable_first", "transient_then_full"])
def test_a_known_new_pin_on_a_full_terminal_does_not_keep_the_person_held(db, monkeypatch, variant):
    # Review R3: after one attempt that did not land, NEW has a state row or a push intent, and
    # the round-2 dry run counted it as an update needing no slot: the person stayed held, OLD
    # kept the slot and NEW was refused every pass. Base removed OLD first and NEW landed.
    monkeypatch.setattr(ds.DeviceSyncEngine, "_retry_due", staticmethod(lambda **k: True))
    monkeypatch.setattr(tel, "event", lambda *a, **k: None)
    monkeypatch.setattr(tel, "warn", lambda *a, **k: None)
    term = _FullTerm()
    term.add_user(str(OLD), "Ali", "555")
    db.save_device_sync_state_batch(device_id=9, rows=[(str(OLD), "h-old", True, None, "")])
    n_others = 4 if variant == "status_unreadable_first" else 3
    others = [_mrow(30100 + i, 800 + i, f"M{i}", str(9000 + i)) for i in range(n_others)]
    for r in others:
        e = {"pin": str(r["activeMembershipId"]), "name": r["fullName"], "card": r["firstCardId"]}
        term.add_user(e["pin"], e["name"], e["card"])
        db.save_device_sync_state_batch(device_id=9, rows=[
            (e["pin"], ue._standalone_pin_hash(e, []), True, None, "")])
    new_row = _mrow(NEW, PERSON, card="555")
    db.upsert_delta_users([_mrow(OLD, PERSON, card="555")] + [new_row] + others)
    db.delete_users_by_am_ids({OLD})                     # the flip held OLD out
    drv = _make_driver(term)
    term.sink = drv._on_att_event
    w, _cache = _worker(monkeypatch, driver=drv, users=[new_row] + others)
    w._cmd_queue = queue.Queue()
    try:
        for i in range(1, 4):
            if variant == "status_unreadable_first":
                term.status_readable = (i != 1)
            else:
                if i == 1:
                    term.fail_once = {str(NEW)}
                if i == 2:
                    term.add_user("77777", "Foreign", "4242")      # another system enrols
            w.request_full_sync(reason="date-flip", fingerprint_hash="h", revoked_ids=set())
            assert w._drain_full_sync_commands(limit=1) == 1
    finally:
        drv.disconnect()
    assert str(NEW) in term.users and str(OLD) not in term.users


# ================================================================== 3. one sync-cache load at a time
import threading  # noqa: E402
import time  # noqa: E402


@pytest.fixture
def slow_loads(db, monkeypatch):
    """_load_sync_cache_db replaced by a 0.3 s fake that counts concurrent loads."""
    st = {"calls": 0, "live": 0, "max_live": 0}
    lk = threading.Lock()

    def fake_load():
        with lk:
            st["calls"] += 1
            n = st["calls"]
            st["live"] += 1
            st["max_live"] = max(st["max_live"], st["live"])
        try:
            time.sleep(0.3)
            return ("snapshot", n)
        finally:
            with lk:
                st["live"] -= 1

    monkeypatch.setattr(dbmod, "_load_sync_cache_db", fake_load)
    monkeypatch.setattr(dbmod, "_sync_cache_entry", (0.0, ("snapshot", "pre-change")))
    monkeypatch.setattr(dbmod, "_sync_cache_loading", None)

    def drain():
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with lk:
                if st["live"] == 0 and dbmod._sync_cache_loading is None:
                    return
            time.sleep(0.02)

    return st, drain


def test_an_invalidation_during_a_load_does_not_start_a_second_one(slow_loads):
    # Review R3: the round-1 epoch fix released the in-flight marker on every invalidation, so
    # a burst of changes started one concurrent full load per invalidation.
    st, drain = slow_loads
    assert dbmod.refresh_sync_cache_async() is True
    time.sleep(0.05)
    dbmod.invalidate_sync_cache()
    assert dbmod.refresh_sync_cache_async() is False
    drain()
    assert st["max_live"] == 1
    assert st["calls"] == 2                     # the stale load, then ONE follow-up
    assert dbmod.peek_sync_cache() == ("snapshot", 2)


def test_one_moving_save_starts_one_load_at_a_time(slow_loads):
    # The branch's own sequence: the flip's invalidate, the app's clear+refresh, work()'s pair.
    st, drain = slow_loads
    dbmod.invalidate_sync_cache()
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod.refresh_sync_cache_async()
    dbmod.invalidate_sync_cache()
    dbmod.refresh_sync_cache_async()
    drain()
    assert st["max_live"] == 1


def test_a_plain_invalidation_during_a_load_still_serves_the_newer_data(slow_loads):
    st, drain = slow_loads
    dbmod.refresh_sync_cache_async()
    time.sleep(0.05)
    dbmod.invalidate_sync_cache()               # plain: the load in flight is newer than the entry
    time.sleep(0.4)                             # the first load has finished, the follow-up runs
    assert dbmod.peek_sync_cache() == ("snapshot", 1)
    drain()
    assert dbmod.peek_sync_cache() == ("snapshot", 2)


def test_a_clearing_invalidation_during_a_load_never_serves_its_data(slow_loads):
    st, drain = slow_loads
    dbmod.refresh_sync_cache_async()
    time.sleep(0.05)
    dbmod.invalidate_sync_cache(clear_cached=True)      # a date flip: pre-flip data never served
    assert dbmod.load_sync_cache() == ("snapshot", 2)   # waits for the follow-up, not load 1
    drain()
    assert st["max_live"] == 1


# ================================================================== 4. the offline grace is capped
from app.core import access_dates as ad  # noqa: E402
from app.core.config import offline_revoke_grace_days  # noqa: E402


@pytest.mark.parametrize(("raw", "expected"), [
    (0, 0), (3, 3), (-5, 0), (36500, 36500), (36501, 36500), (10 ** 20, 36500), ("7", 7),
    (True, 0), (None, 0), ("x", 0),
])
def test_the_grace_setting_is_normalised_into_its_range(raw, expected):
    assert offline_revoke_grace_days(SimpleNamespace(offline_revoke_grace_days=raw)) == expected
    assert ad.GRACE_DAYS_MAX == 36500


def test_a_grace_beyond_sqlite_integers_neither_fails_the_flip_nor_loops_the_precheck(db):
    # Review R3: 10**20 overflowed SQLite INTEGER when the flip stored grace_days, so every flip
    # failed (DATE_FLIP_FAILED every minute) and the applied day froze.
    _seed_full_v2(db)
    r = db.apply_local_date_flips(pc_now_epoch=_epoch("2026-09-20T07:30:00+01:00"),
                                  grace_days=10 ** 20, source="test")
    assert r["gym_date"] == "2026-09-20" and r["promoted"] == 1
    st = db.gym_date_status(pc_now_epoch=_epoch("2026-09-20T09:00:00+01:00"))
    assert st["grace_days"] == ad.GRACE_DAYS_MAX
    assert st["grace_days"] == offline_revoke_grace_days(SimpleNamespace(offline_revoke_grace_days=10 ** 20))

"""P3b-1 adversarial review, round 4: regressions for the confirmed findings.

Real temp SQLite through the ``app.core.db._DB_PATH`` override; no network.
"""
from __future__ import annotations

import pytest

import app.core.db as dbmod
from tests.test_p3b1_review_r3 import _shadow_sync
from tests.test_protocol2_save_and_flip import (
    MEMBERS_ONLY, _epoch, _flip, _ids, _meta, _row, _v2, _window,
)


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "r4.db"), raising=False)
    dbmod._shutdown_db_writer_for_tests()
    dbmod.init_db()
    yield dbmod
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


def _shadow_has(am):
    with dbmod.get_conn() as c:
        return am in {int(r[0]) for r in c.execute("SELECT active_membership_id FROM member_shadow")}


# ================================================================== 1. an answer of the previous day
def _midnight_then_stale_answer(db, *, delta):
    # D = 2026-09-19: 1 ends on D, 5 ongoing, 3 is a pre-sale starting D+1.
    seed = _v2([_row(1, until="2026-09-19"), _row(5)],
               upcoming=[_row(3, frm="2026-09-20", qrAccountId=55)])
    _shadow_sync(seed, db.save_sync_cache_delta(seed, MEMBERS_ONLY) or {})
    r = _flip(db, "2026-09-20T00:00:05+01:00")               # midnight: 3 promoted, 1 held
    assert r["promoted"] == 1 and 3 in _ids("sync_users")
    # Answered at 23:59:58 on D (today = D), saved just after midnight, then work()'s order:
    # save -> flip("save") -> shadow sync.
    stale = _v2([_row(5)] if not delta else [], delta=delta,
                valid=[1, 5] if delta else None,
                member_windows=([_window(1, until="2026-09-19"), _window(5)] if delta else []),
                upcoming=[_row(3, frm="2026-09-20", qrAccountId=55)],
                meta=_meta(today="2026-09-19", horizon_end="2026-09-26",
                           server_time="2026-09-19T23:59:58.000+01:00"),
                received=_epoch("2026-09-20T00:00:01+01:00"), windows_version="p2.7.x.y")
    if not delta:
        stale["users"] = [_row(1, until="2026-09-19"), _row(5)]
    out = db.save_sync_cache_delta(stale, MEMBERS_ONLY) or {}
    _flip(db, "2026-09-20T00:00:06+01:00")
    return _shadow_sync(stale, out)


@pytest.mark.parametrize("delta", [True, False])
def test_a_previous_day_answer_after_midnight_does_not_revoke_the_promoted_starter(db, delta):
    # Review R4: the flip after the save put 3 back (it is still upcoming on day D) and wrote its
    # shadow row; the shadow sync then deleted that row and returned 3 as revoked -- ULTRA removed
    # the pin of a member the PC admits today.
    _changed, revoked = _midnight_then_stale_answer(db, delta=delta)
    assert 3 in _ids("sync_users")
    assert 3 not in revoked
    assert _shadow_has(3)


def test_a_membership_the_server_really_dropped_is_still_revoked(db):
    seed = _v2([_row(1), _row(5)])
    _shadow_sync(seed, db.save_sync_cache_delta(seed, MEMBERS_ONLY) or {})
    gone = _v2([], delta=True, valid=[5], member_windows=[_window(5)])
    _changed, revoked = _shadow_sync(gone, db.save_sync_cache_delta(gone, MEMBERS_ONLY) or {})
    assert 1 in revoked and not _shadow_has(1)


def test_the_shadow_batch_write_is_timed_again():
    # Review R4: a266f20 left @_tel.timed("SHADOW_DIFF") on the per-row helper.
    assert hasattr(dbmod.upsert_member_shadow, "__wrapped__")
    assert not hasattr(dbmod._upsert_member_shadow_row, "__wrapped__")


# ================================================================== 2. a hold never takes another pin's slot
import queue  # noqa: E402

import app.core.telemetry as tel  # noqa: E402
import app.core.ultra_engine as ue  # noqa: E402
from tests.fake_terminal import TerminalZkem  # noqa: E402
from tests.test_standalone_incremental_sync import _make_driver, _worker  # noqa: E402

CAP = 6
P1, P2, P3 = 901, 902, 903
OLD1, OLD2 = 34439, 34440
NEW1, N, NEW2 = 30001, 30002, 30003


class _NearlyFull(TerminalZkem):
    def GetDeviceStatus(self, machine, idx, box):
        self.status = {11: max(0, CAP - len(self.users)), 10: 1000}
        return super().GetDeviceStatus(machine, idx, box)

    def SSR_SetUserInfo(self, machine, pin, name, pw, priv, enabled):
        if str(pin) not in self.users and len(self.users) >= CAP:
            self._rec("SSR_SetUserInfo", machine, pin, name, pw, priv, enabled)
            return False
        return super().SSR_SetUserInfo(machine, pin, name, pw, priv, enabled)


def _mrow(am, uid, name, card=""):
    return {"activeMembershipId": am, "userId": uid, "membershipId": 3, "fullName": name,
            "firstCardId": card, "fingerprints": []}


def _terminal_with(db, olds, n_others):
    term = _NearlyFull()
    for pin, name, card in olds:
        term.add_user(str(pin), name, card)
        db.save_device_sync_state_batch(device_id=9, rows=[(str(pin), "h-old", True, None, "")])
    others = [_mrow(30100 + i, 800 + i, f"M{i}", str(9000 + i)) for i in range(n_others)]
    for r in others:
        e = {"pin": str(r["activeMembershipId"]), "name": r["fullName"], "card": r["firstCardId"]}
        term.add_user(e["pin"], e["name"], e["card"])
        db.save_device_sync_state_batch(device_id=9, rows=[
            (e["pin"], ue._standalone_pin_hash(e, []), True, None, "")])
    return term, others


def _one_pass(monkeypatch, term, users):
    drv = _make_driver(term)
    term.sink = drv._on_att_event
    w, _cache = _worker(monkeypatch, driver=drv, users=users)
    w._cmd_queue = queue.Queue()
    try:
        w.request_full_sync(reason="date-flip", fingerprint_hash="h", revoked_ids=set())
        assert w._drain_full_sync_commands(limit=1) == 1
    finally:
        drv.disconnect()
    return set(term.users)


def test_a_hold_does_not_take_the_slot_of_a_first_day_starter(db, monkeypatch):
    # Review R4: users_free=1; pending NEW1 (renewal of P1) then N (a starter). The dry run gave
    # NEW1 the slot, P1 was held, and N was refused CAPACITY_FULL. Base removed OLD1 first.
    monkeypatch.setattr(tel, "event", lambda *a, **k: None)
    monkeypatch.setattr(tel, "warn", lambda *a, **k: None)
    term, others = _terminal_with(db, [(OLD1, "Ali", "551")], 4)
    new1, n = _mrow(NEW1, P1, "Ali", "551"), _mrow(N, P3, "Newbie", "553")
    db.upsert_delta_users([_mrow(OLD1, P1, "Ali", "551"), new1, n] + others)
    db.delete_users_by_am_ids({OLD1})
    on = _one_pass(monkeypatch, term, [new1, n] + others)
    assert {str(NEW1), str(N)} <= on and str(OLD1) not in on


def test_a_hold_never_leaves_a_renewing_member_with_neither_pin(db, monkeypatch):
    # Review R4: users_free=1; NEW1 (P1), N, NEW2 (P2). P1 was held, P2 was not (no room in the
    # dry run), OLD2 went first, then NEW1 and N took the two free slots and NEW2 was refused:
    # P2 had neither pin. Base removed both old pins first and all three landed.
    monkeypatch.setattr(tel, "event", lambda *a, **k: None)
    monkeypatch.setattr(tel, "warn", lambda *a, **k: None)
    term, others = _terminal_with(db, [(OLD1, "Ali", "551"), (OLD2, "Bea", "552")], 3)
    new1, n, new2 = (_mrow(NEW1, P1, "Ali", "551"), _mrow(N, P3, "Newbie", "553"),
                     _mrow(NEW2, P2, "Bea", "552"))
    db.upsert_delta_users([_mrow(OLD1, P1, "Ali", "551"), _mrow(OLD2, P2, "Bea", "552"),
                           new1, n, new2] + others)
    db.delete_users_by_am_ids({OLD1, OLD2})
    on = _one_pass(monkeypatch, term, [new1, n, new2] + others)
    assert {str(NEW1), str(N), str(NEW2)} <= on


def test_with_room_for_every_new_pin_the_renewal_is_still_held(db, monkeypatch):
    # The renewal ordering itself is unchanged when the terminal has room: new pin first.
    events = []
    monkeypatch.setattr(tel, "event", lambda name, **f: events.append((name, f)))
    monkeypatch.setattr(tel, "warn", lambda *a, **k: None)
    term, others = _terminal_with(db, [(OLD1, "Ali", "551")], 1)       # 2 of 6 used
    new1, n = _mrow(NEW1, P1, "Ali", "551"), _mrow(N, P3, "Newbie", "553")
    db.upsert_delta_users([_mrow(OLD1, P1, "Ali", "551"), new1, n] + others)
    db.delete_users_by_am_ids({OLD1})
    on = _one_pass(monkeypatch, term, [new1, n] + others)
    assert {str(NEW1), str(N)} <= on and str(OLD1) not in on
    [hold] = [f for name, f in events if name == "RENEWAL_HOLD"]
    assert (hold["held"], hold["removed_after_push"]) == (1, 1)


# ================================================================== 3. a stale grant of a paying member
import random  # noqa: E402
import time  # noqa: E402

from app.core import access_verification as av  # noqa: E402
from tests.test_totp_index import _code_for, _settings  # noqa: E402

A, B, OTHER, ACCOUNT = 606, 909, 101, 5006


def _person_row(am, frm, until, main, uid):
    return {"activeMembershipId": am, "userId": uid, "membershipId": 3, "fullName": f"M{am}",
            "mainAccountId": main, "accessFrom": frm, "accessUntil": until, "offDays": []}


def _overlap_world(db, *, b_person):
    """A (ends 09-19) and B (09-16..10-16) in today's set, no mainAccountId; the QR credential's
    stored grants are stale: [A] only. B belongs to person ``b_person``; A to 7606."""
    rng = random.Random(7)
    cred = {"id": 6, "gymId": 1, "accountId": ACCOUNT, "enabled": True,
            "secretHex": "".join(rng.choice("0123456789abcdef") for _ in range(32)),
            "grantedActiveMembershipIds": [A], "updatedAt": "2026-09-01T10:00:00Z"}
    other = {"id": 1, "gymId": 1, "accountId": 5101, "enabled": True,
             "secretHex": "".join(rng.choice("0123456789abcdef") for _ in range(32)),
             "grantedActiveMembershipIds": [OTHER], "updatedAt": "2026-09-01T10:00:00Z"}
    eve = _v2([_person_row(A, "2026-08-20", "2026-09-19", None, 7606),
               _person_row(B, "2026-09-16", "2026-10-16", None, b_person),
               _person_row(OTHER, "2026-09-01", "2026-09-30", 5101, 7101)])
    eve["gymAccessCredentials"] = [cred, other]
    sections = {"members": True, "devices": False, "credentials": True, "settings": False}
    db.save_sync_cache_delta(eve, sections)
    _flip(db, "2026-09-19T20:00:05+01:00")
    r = _flip(db, "2026-09-20T07:30:00+01:00")                 # offline power-on: A held
    assert r["held"] == 1 and A in _ids("sync_users_held")
    return cred


def _scan(cred, mode):
    av._reset_access_days_cache_for_tests()
    creds, uam, _ = av.load_local_state()
    s = _settings(totp_roster_check_mode=mode)
    now = time.time()
    return av.verify_totp_resilient(scanned=_code_for(cred, s, now), settings=s,
                                    creds_payload=creds, users_by_am=uam, users_by_card={},
                                    scan_epoch=now, access_days=av.current_access_days())


def test_offline_trial_allows_a_paying_member_whose_stored_grant_is_an_expired_plan(db):
    # Review R4: the flip held A (its expired window stays stored); the credential's stored grants
    # are stale ([A]; the server would grant B); B's row has no mainAccountId, so the account
    # second chance misses. Trial refused DENY_NOT_ALLOWED_TODAY; base allowed (A still listed).
    cred = _overlap_world(db, b_person=7606)
    r = _scan(cred, "trial")
    assert r["allowed"] is True and r["dateCheck"] == "ok"


def test_an_expired_grant_of_a_person_not_listed_today_is_still_refused(db):
    cred = _overlap_world(db, b_person=7909)                   # B is somebody else
    r = _scan(cred, "trial")
    assert r["allowed"] is False and r["reason"] == "DENY_NOT_ALLOWED_TODAY"

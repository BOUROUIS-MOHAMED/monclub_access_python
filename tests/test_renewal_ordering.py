"""P3b-1 part E: renewal ordering on MEMBERSHIP-pin turnstiles (plan §7, guide §7 R3-21).

THE FAILURE THESE PIN
---------------------
Under pinScheme=MEMBERSHIP a person's device user is keyed by the MEMBERSHIP. The backend's
"renew" keeps the same activeMembershipId (same pin); a person who buys ANOTHER plan gets a new
activeMembershipId for the same userId, hence a NEW pin. P3b-1's date flip makes the headline
case: at 00:00:05 or at power-on the old plan's row is held out and the new plan's row promoted
in the SAME flip, so ONE full-sync pass sees the old pin leaving and the new pin to write.

Since P3a-2 removals run FIRST (guide §3.4b). So the old pin was deleted before the new one was
written, and when that write failed (a refused user row, a wedge, a crash) the person had
neither until a later pass -- locked out at the turnstile, with a valid plan.

Now an owned pin that left the roster is HELD when its person (member_person_link) still has a
desired pin that is not confirmed on the device at the start of the pass: it is removed only
after the push confirmed every desired pin of that person, and otherwise kept (state kept,
never pruned, never deleted by MIRROR) until a later pass confirms the new pin. The removal
ceiling still counts it; real leavers are still removed first; an explicit revocation is never
held; pinScheme=ACCOUNT is unaffected (a renewal keeps the account pin).

MB2000: the real driver + STA thread over the stateful fake terminal. PullSDK: a MagicMock SDK.
Both on a real temp SQLite database (``_DB_PATH``): nothing reaches the installed database.
"""
from __future__ import annotations

import logging
import queue
import re
import time
from datetime import datetime
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

import app.core.db as dbmod
import app.core.telemetry as tel
import app.core.ultra_engine as ue
from tests.fake_terminal import TerminalZkem
from tests.test_standalone_incremental_sync import _make_driver, _worker

PERSON = 900          # the member who bought another plan
OLD = 34439           # the plan that ended yesterday (held out by the date flip)
NEW = 30001           # the plan that starts today (promoted by the same flip)
LEAVER = 40001        # somebody else, really gone


# ═════════════════════════════ shared ═════════════════════════════

@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "renewal.db"), raising=False)
    dbmod._shutdown_db_writer_for_tests()
    dbmod.init_db()
    yield dbmod
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


@pytest.fixture
def events(monkeypatch):
    seen: List[tuple] = []
    real_event, real_warn = tel.event, tel.warn

    def _event(name, **f):
        seen.append((name, f))
        return real_event(name, **f)

    def _warn(name, **f):
        seen.append((name, f))
        return real_warn(name, **f)

    monkeypatch.setattr(tel, "event", _event)
    monkeypatch.setattr(tel, "warn", _warn)
    return seen


def _named(events, name) -> List[Dict[str, Any]]:
    return [f for n, f in events if n == name]


def _row(am: int, uid: int, name: str = "Ali", card: str = "555", **extra) -> dict:
    return {"activeMembershipId": am, "userId": uid, "membershipId": 3, "fullName": name,
            "firstCardId": card, "fingerprints": [], **extra}


def _flipped(db, gone_rows, kept_rows) -> None:
    """The state a date flip leaves: every plan was cached once (so member_person_link knows
    its person), and the rows that left today's roster are gone from sync_users."""
    db.upsert_delta_users(list(gone_rows) + list(kept_rows))
    db.delete_users_by_am_ids({int(r["activeMembershipId"]) for r in gone_rows})


# ═════════════════════════════ the two shared rules ═════════════════════════════

class TestRules:

    def test_a_hold_waits_for_every_desired_pin_of_its_person(self):
        from app.core.device_sync import renewal_released_holds

        persons = {"30001": PERSON, "30005": PERSON, "30002": 901}
        free = renewal_released_holds(
            {str(OLD): PERSON, "34440": 901}, person_by_pin=persons,
            unconfirmed={"30001", "30005", "30002"}, confirmed_now={"30001", "30002"},
        )
        assert free == {"34440"}, "30005 still waits: the person's old pin stays"
        assert renewal_released_holds(
            {str(OLD): PERSON}, person_by_pin=persons,
            unconfirmed={"30001"}, confirmed_now={"30001"},
        ) == {str(OLD)}, "30005 was confirmed before the pass: not waited for"

    def test_an_unreadable_person_link_holds_nothing(self, monkeypatch):
        import app.core.device_sync as ds

        def _broken(_ids):
            raise RuntimeError("database locked")
        monkeypatch.setattr(dbmod, "get_member_person_user_ids", _broken)
        assert ds.renewal_holds([str(OLD)], pending_persons={PERSON}) == {}, (
            "removed first, exactly as before")

    def test_exempt_and_unlinked_pins_are_never_held(self, db):
        from app.core.device_sync import renewal_holds

        _flipped(db, [_row(OLD, PERSON), _row(LEAVER, 901)], [_row(NEW, PERSON)])
        assert renewal_holds([str(OLD), str(LEAVER), "55555"], pending_persons={PERSON}) \
            == {str(OLD): PERSON}
        assert renewal_holds([str(OLD)], pending_persons={PERSON}, exempt={str(OLD)}) == {}


# ═════════════════════════════ MB2000 (ZK_STANDALONE) ═════════════════════════════

class RenewalTerminal(TerminalZkem):
    """The stateful fake MB2000, able to refuse one pin's user row or whole-user delete."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.refuse_user: set = set()
        self.refuse_delete: set = set()

    def SSR_SetUserInfo(self, machine, pin, name, pw, priv, enabled):
        if str(pin) in self.refuse_user:
            self._rec("SSR_SetUserInfo", machine, pin, name, pw, priv, enabled)
            return False
        return super().SSR_SetUserInfo(machine, pin, name, pw, priv, enabled)

    def SSR_DeleteEnrollData(self, machine, pin, backup):
        if str(pin) in self.refuse_delete:
            self._rec("SSR_DeleteEnrollData", machine, pin, backup)
            return False
        return super().SSR_DeleteEnrollData(machine, pin, backup)


def _owned_on_terminal(db, term, pin, name="Ali", card="555") -> None:
    term.add_user(str(pin), name, card)
    db.save_device_sync_state_batch(device_id=9, rows=[(str(pin), "h-old", True, None, "")])


def _setup(monkeypatch, term, users, **device):
    drv = _make_driver(term)
    term.sink = drv._on_att_event
    w, _cache = _worker(monkeypatch, driver=drv, users=users)
    w._device.update(device)
    w._cmd_queue = queue.Queue()
    return drv, w


def _pass(w, *, revoked=None, full_reconcile=False) -> None:
    w.request_full_sync(reason="timer", fingerprint_hash="h", revoked_ids=set(revoked or ()),
                        full_reconcile=full_reconcile)
    assert w._drain_full_sync_commands(limit=1) == 1


def _run(drv, w, **kw) -> None:
    try:
        _pass(w, **kw)
    finally:
        drv.disconnect()


def _idx(term, op, pin, *, after: int = -1):
    """Index in the terminal's call log of the first ``op`` on ``pin`` after ``after``."""
    for i, c in enumerate(term.calls):
        if i > after and c[0] == op and str(c[2]) == str(pin):
            return i
    return None


def _written(term, pin, **kw):
    return _idx(term, "SSR_SetUserInfo", pin, **kw)


def _deleted(term, pin, **kw):
    return _idx(term, "SSR_DeleteEnrollData", pin, **kw)


def _owned(db) -> set:
    return set(db.list_confirmed_device_sync_pins(device_id=9))


def _state(db) -> dict:
    return db.list_device_sync_hashes_and_status(device_id=9)


def _in_backoff(monkeypatch, pin, entry) -> None:
    """``pin``'s push keeps being refused with this exact content: the retry backoff holds
    it back (not pushed this pass, not failed this pass)."""
    h = ue._standalone_pin_hash(entry, [])
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    real = dbmod.list_device_sync_retry_state

    def _retry_state(*, device_id):
        out = dict(real(device_id=device_id) or {})
        out[str(pin)] = ("", False, 9, h, stamp)
        return out
    monkeypatch.setattr(dbmod, "list_device_sync_retry_state", _retry_state)


class TestStandaloneRenewal:

    def test_the_old_pin_is_removed_only_after_the_new_pin_is_written(self, db, monkeypatch,
                                                                     events):
        term = RenewalTerminal()
        _owned_on_terminal(db, term, OLD)
        _flipped(db, [_row(OLD, PERSON)], [_row(NEW, PERSON)])
        drv, w = _setup(monkeypatch, term, [_row(NEW, PERSON)])
        _run(drv, w)

        written, deleted = _written(term, NEW), _deleted(term, OLD)
        assert written is not None and deleted is not None
        assert written < deleted, (
            "removals-first deleted the old pin before the new one was written (R3-21)")
        assert str(OLD) not in term.users and str(NEW) in term.users
        assert str(OLD) not in _state(db), "a confirmed removal forgets its state"
        assert str(NEW) in _owned(db)
        [hold] = _named(events, "RENEWAL_HOLD")
        assert (hold["held"], hold["removed_after_push"], hold["kept"]) == (1, 1, 0)
        assert hold["worker"] == "ULTRA:9"
        assert w._removal_retry_at_mono is None

    def test_a_refused_new_pin_keeps_the_old_one_owned_and_the_next_pass_removes_it(
            self, db, monkeypatch, events):
        term = RenewalTerminal()
        term.refuse_user = {str(NEW)}
        _owned_on_terminal(db, term, OLD)
        _flipped(db, [_row(OLD, PERSON)], [_row(NEW, PERSON)])
        drv, w = _setup(monkeypatch, term, [_row(NEW, PERSON)])
        try:
            _pass(w)
            assert _deleted(term, OLD) is None, "the person would have had neither pin"
            assert str(OLD) in term.users
            assert str(OLD) in _owned(db), "still owned: a later pass can remove it"
            assert w._removal_retry_at_mono is None, "a kept hold is not a failed removal"
            [hold] = _named(events, "RENEWAL_HOLD")
            assert (hold["held"], hold["removed_after_push"], hold["kept"]) == (1, 0, 1)
            assert not _named(events, "REVOKE_ABORTED"), "a hold is not a ceiling refusal"

            term.refuse_user.clear()
            mark = len(term.calls)
            _pass(w)
        finally:
            drv.disconnect()
        written = _written(term, NEW, after=mark - 1)
        deleted = _deleted(term, OLD, after=mark - 1)
        assert written is not None and deleted is not None and written < deleted
        assert str(OLD) not in term.users and str(NEW) in term.users
        assert str(OLD) not in _state(db)

    def test_the_prune_keeps_a_kept_holds_state_row(self, db, monkeypatch):
        term = RenewalTerminal()
        term.refuse_user = {str(NEW)}
        _owned_on_terminal(db, term, OLD)
        _flipped(db, [_row(OLD, PERSON)], [_row(NEW, PERSON)])
        drv, w = _setup(monkeypatch, term, [_row(NEW, PERSON)])
        _run(drv, w)
        assert str(OLD) in _state(db), (
            "the prune dropped the row: the pin would stay on the terminal with no owner")
        assert str(OLD) in _owned(db)

    def test_a_pin_held_back_by_the_retry_backoff_keeps_the_old_pin(self, db, monkeypatch,
                                                                    events):
        term = RenewalTerminal()
        _owned_on_terminal(db, term, OLD)
        _flipped(db, [_row(OLD, PERSON)], [_row(NEW, PERSON)])
        _in_backoff(monkeypatch, NEW, {"pin": str(NEW), "name": "Ali", "card": "555"})
        drv, w = _setup(monkeypatch, term, [_row(NEW, PERSON)])
        _run(drv, w)
        assert _written(term, NEW) is None, "held back by the backoff"
        assert _deleted(term, OLD) is None and str(OLD) in _state(db)
        [hold] = _named(events, "RENEWAL_HOLD")
        assert (hold["held"], hold["removed_after_push"], hold["kept"]) == (1, 0, 1)
        assert w._removal_retry_at_mono is None

    def test_a_real_leaver_in_the_same_pass_is_still_removed_first(self, db, monkeypatch):
        term = RenewalTerminal()
        _owned_on_terminal(db, term, OLD)
        _owned_on_terminal(db, term, LEAVER, name="Bob", card="777")
        _flipped(db, [_row(OLD, PERSON), _row(LEAVER, 901, "Bob", "777")], [_row(NEW, PERSON)])
        drv, w = _setup(monkeypatch, term, [_row(NEW, PERSON)])
        _run(drv, w)
        leaver, written, old = _deleted(term, LEAVER), _written(term, NEW), _deleted(term, OLD)
        assert None not in (leaver, written, old)
        assert leaver < written < old
        assert not ({str(OLD), str(LEAVER)} & set(term.users))

    def test_an_explicit_revocation_of_the_old_pin_is_not_held(self, db, monkeypatch, events):
        term = RenewalTerminal()
        _owned_on_terminal(db, term, OLD)
        _flipped(db, [_row(OLD, PERSON)], [_row(NEW, PERSON)])
        drv, w = _setup(monkeypatch, term, [_row(NEW, PERSON)])
        _run(drv, w, revoked={OLD})
        deleted, written = _deleted(term, OLD), _written(term, NEW)
        assert deleted is not None and written is not None and deleted < written, (
            "an authoritative revocation is removed first, as before")
        assert not _named(events, "RENEWAL_HOLD")

    def test_a_person_whose_new_pin_is_already_confirmed_is_a_normal_leaver(
            self, db, monkeypatch, events):
        term = RenewalTerminal()
        _owned_on_terminal(db, term, OLD)
        new_entry = {"pin": str(NEW), "name": "Ali", "card": "555"}
        term.add_user(str(NEW), "Ali", "555")
        db.save_device_sync_state_batch(device_id=9, rows=[
            (str(NEW), ue._standalone_pin_hash(new_entry, []), True, None, "")])
        _flipped(db, [_row(OLD, PERSON)], [_row(NEW, PERSON), _row(30002, 901, "Bob", "777")])
        drv, w = _setup(monkeypatch, term, [_row(NEW, PERSON), _row(30002, 901, "Bob", "777")])
        _run(drv, w)
        assert _written(term, NEW) is None, "unchanged: not pushed"
        deleted, other = _deleted(term, OLD), _written(term, 30002)
        assert deleted is not None and other is not None and deleted < other
        assert not _named(events, "RENEWAL_HOLD")

    def test_no_person_link_means_no_hold(self, db, monkeypatch, events):
        """Unattributable (a pin never seen in sync_users on this database): removed first,
        exactly as before."""
        term = RenewalTerminal()
        _owned_on_terminal(db, term, OLD)
        drv, w = _setup(monkeypatch, term, [_row(NEW, PERSON)])
        _run(drv, w)
        deleted, written = _deleted(term, OLD), _written(term, NEW)
        assert deleted is not None and written is not None and deleted < written
        assert not _named(events, "RENEWAL_HOLD")

    def test_account_scheme_is_unaffected(self, db, monkeypatch, events):
        """Under ACCOUNT a renewal keeps the account pin: nothing is ever held. A departed
        account pin whose number happens to be a linked membership id is removed first."""
        term = RenewalTerminal()
        _owned_on_terminal(db, term, OLD)
        new_row = _row(NEW, PERSON, mainAccountId=5)
        _flipped(db, [_row(OLD, PERSON)], [new_row])
        drv, w = _setup(monkeypatch, term, [new_row], pinScheme="ACCOUNT")
        _run(drv, w)
        deleted, written = _deleted(term, OLD), _written(term, 5)
        assert deleted is not None and written is not None and deleted < written
        assert not _named(events, "RENEWAL_HOLD")


class TestStandaloneCeilingAndFailures:

    def _leavers(self, db, term, n):
        rows = []
        for i in range(n):
            pin = LEAVER + i
            _owned_on_terminal(db, term, pin, name=f"L{i}", card=str(7000 + i))
            rows.append(_row(pin, 7000 + i, f"L{i}", str(7000 + i)))
        return rows

    def test_the_ceiling_judges_the_leavers_and_a_release_beyond_it_waits(
            self, db, monkeypatch, events):
        # Review R1 (inverts the P3b-1 part-E rule "the ceiling counts holds"): the removals-
        # first step removes only the leavers, so its ceiling judges them; the released hold
        # would make 11 removals in the pass (> 10), so it waits for the next pass -- a pass
        # never removes more than the ceiling allows, as when the old pin went first.
        term = RenewalTerminal()
        _owned_on_terminal(db, term, OLD)
        leavers = self._leavers(db, term, 10)          # 10 leavers = ceiling 10: allowed
        _flipped(db, [_row(OLD, PERSON)] + leavers, [_row(NEW, PERSON)])
        drv, w = _setup(monkeypatch, term, [_row(NEW, PERSON)])
        try:
            _pass(w)
            written = _written(term, NEW)
            assert all(_deleted(term, r["activeMembershipId"]) < written for r in leavers)
            assert _deleted(term, OLD) is None and str(OLD) in term.users
            assert str(OLD) in _state(db), "kept: owned, removed by a later pass"
            [abort] = _named(events, "REVOKE_ABORTED")
            assert abort["path"] == "renewal_release" and abort["count"] == 11
            [hold] = _named(events, "RENEWAL_HOLD")
            assert (hold["held"], hold["removed_after_push"], hold["kept"]) == (1, 0, 1)

            mark = len(term.calls)
            _pass(w)                                   # nothing else to remove: it fits now
        finally:
            drv.disconnect()
        assert _deleted(term, OLD, after=mark - 1) is not None
        assert str(OLD) not in term.users and str(NEW) in term.users

    def test_a_kept_hold_does_not_push_the_next_days_leavers_over_the_ceiling(
            self, db, monkeypatch, events):
        # Review R1: day D the renewed member's new pin is refused, so the old one is kept;
        # day D+1 ten other plans end. Base had removed the old pin on day D and removed the
        # ten on D+1; counting the kept hold made 11 > 10 and left the ten on the turnstile.
        term = RenewalTerminal()
        term.refuse_user = {str(NEW)}
        _owned_on_terminal(db, term, OLD)
        leavers = self._leavers(db, term, 10)
        _flipped(db, [_row(OLD, PERSON)], [_row(NEW, PERSON)] + leavers)
        drv, w = _setup(monkeypatch, term, [_row(NEW, PERSON)] + leavers)
        try:
            _pass(w)                                   # day D: the old pin is kept
            assert str(OLD) in term.users
            _flipped(db, leavers, [_row(NEW, PERSON)])  # day D+1: the ten plans end
            ue.load_sync_cache().users[:] = [_row(NEW, PERSON)]
            events.clear()
            _pass(w)
        finally:
            drv.disconnect()
        assert not [a for a in _named(events, "REVOKE_ABORTED")
                    if a.get("path") == "standalone_revoke"]
        assert not any(str(r["activeMembershipId"]) in term.users for r in leavers)
        assert str(OLD) in term.users, "the renewed member still enters with the old pin"

    def test_under_the_ceiling_leavers_go_first_and_the_hold_after_the_push(
            self, db, monkeypatch, events):
        term = RenewalTerminal()
        _owned_on_terminal(db, term, OLD)
        leavers = self._leavers(db, term, 9)           # 9 + 1 hold = 10 = ceiling: allowed
        _flipped(db, [_row(OLD, PERSON)] + leavers, [_row(NEW, PERSON)])
        drv, w = _setup(monkeypatch, term, [_row(NEW, PERSON)])
        _run(drv, w)
        written = _written(term, NEW)
        assert all(_deleted(term, r["activeMembershipId"]) < written for r in leavers)
        assert _deleted(term, OLD) > written
        assert not _named(events, "REVOKE_ABORTED")
        assert str(OLD) not in term.users

    def test_a_failed_post_push_removal_is_a_normal_removal_failure_armed_once(
            self, db, monkeypatch, events):
        term = RenewalTerminal()
        _owned_on_terminal(db, term, OLD)
        _owned_on_terminal(db, term, LEAVER, name="Bob", card="777")
        # delete refused and the neutralise fallback's user write refused too
        term.refuse_delete = {str(OLD), str(LEAVER)}
        term.refuse_user = {str(OLD), str(LEAVER)}
        _flipped(db, [_row(OLD, PERSON), _row(LEAVER, 901, "Bob", "777")], [_row(NEW, PERSON)])
        drv, w = _setup(monkeypatch, term, [_row(NEW, PERSON)])
        _run(drv, w)
        written, old = _written(term, NEW), _deleted(term, OLD)
        assert old is not None and written < old, "the hold was only attempted after the push"
        assert str(OLD) in _state(db) and str(OLD) in _owned(db), "kept for the retry"
        assert w._removal_retry_at_mono is not None, "a refused removal is retried fast"
        assert w._removal_retry_streak == 1, "one pass arms the retry once"
        [sched] = _named(events, "REMOVAL_RETRY_SCHEDULED")
        assert sched["pins"] == 2, "the leaver's and the hold's failures, reported together"
        [hold] = _named(events, "RENEWAL_HOLD")
        assert (hold["held"], hold["removed_after_push"], hold["kept"]) == (1, 0, 0)

    def test_mirror_never_deletes_a_kept_hold(self, db, monkeypatch, events):
        term = RenewalTerminal()
        _owned_on_terminal(db, term, OLD)
        others = [_row(30002 + i, 901 + i, f"M{i}", str(800 + i)) for i in range(3)]
        _flipped(db, [_row(OLD, PERSON)], [_row(NEW, PERSON)] + others)
        _in_backoff(monkeypatch, NEW, {"pin": str(NEW), "name": "Ali", "card": "555"})
        db.arm_mirror_reconcile(device_id=9)
        drv, w = _setup(monkeypatch, term, [_row(NEW, PERSON)] + others,
                        rosterPushingPolicy="MIRROR")
        _run(drv, w, full_reconcile=True)
        assert w._on_full_sync_finished.call_args.kwargs["ok"] is True
        assert _named(events, "MIRROR_NOOP"), "MIRROR ran and found nothing to delete"
        assert str(OLD) in term.users and _deleted(term, OLD) is None

    def test_a_hold_revoked_mid_push_is_not_removed_twice(self, db, monkeypatch):
        """A targeted revoke served between two chunks removed the held pin itself: the
        post-push step must not delete it again -- the neutralise fallback would write a
        blank user back at that pin."""
        term = RenewalTerminal()
        _owned_on_terminal(db, term, OLD)
        others = [_row(30002 + i, 901 + i, f"M{i}", str(800 + i)) for i in range(12)]
        _flipped(db, [_row(OLD, PERSON)], [_row(NEW, PERSON)] + others)
        drv, w = _setup(monkeypatch, term, [_row(NEW, PERSON)] + others)
        orig = term.SSR_SetUserInfo
        fired = {"done": False}

        def _hook(machine, pin, name, pw, priv, enabled):
            ok = orig(machine, pin, name, pw, priv, enabled)
            if str(pin) == "30003" and not fired["done"]:
                fired["done"] = True
                w.request_member_revoke(OLD)
            return ok
        term.SSR_SetUserInfo = _hook
        _run(drv, w)
        assert fired["done"]
        assert [c for c in term.calls if c[0] == "SSR_DeleteEnrollData"
                and str(c[2]) == str(OLD)].__len__() == 1
        assert str(OLD) not in term.users, "no blank user written back at the pin"
        assert str(OLD) not in _state(db)

    def test_a_new_pin_left_to_the_continuation_keeps_the_old_one_until_it_is_written(
            self, db, monkeypatch, events):
        """The per-pass cap (§3.4e) leaves the new pin for the next pass: never sent, so
        never confirmed -- the old pin stays until the continuation writes the new one."""
        monkeypatch.setattr(ue, "_FULL_SYNC_MAX_PINS_PER_PASS", 2)
        term = RenewalTerminal()
        _owned_on_terminal(db, term, OLD)
        others = [_row(30002 + i, 901 + i, f"M{i}", str(800 + i)) for i in range(2)]
        _flipped(db, [_row(OLD, PERSON)], others + [_row(NEW, PERSON)])
        drv, w = _setup(monkeypatch, term, others + [_row(NEW, PERSON)])
        try:
            _pass(w)
            assert _written(term, NEW) is None, "capped out: left to the continuation"
            assert _deleted(term, OLD) is None and str(OLD) in _state(db)
            [hold] = _named(events, "RENEWAL_HOLD")
            assert (hold["held"], hold["removed_after_push"], hold["kept"]) == (1, 0, 1)
            assert w._pending_full_sync_request is not None, "the continuation is queued"
            mark = len(term.calls)
            assert w._drain_full_sync_commands(limit=1) == 1
        finally:
            drv.disconnect()
        written = _written(term, NEW, after=mark - 1)
        deleted = _deleted(term, OLD, after=mark - 1)
        assert written is not None and deleted is not None and written < deleted
        assert str(OLD) not in term.users and str(OLD) not in _state(db)

    def test_a_pass_that_stops_before_the_post_push_step_reports_its_removal_step_once(
            self, db, monkeypatch, events):
        """The removal step's report waits for the post-push removal of the holds; a pass
        that raises in between still reports it, once. Without that report the drain read
        the pass as one that never reported and re-armed the pending retry (errored)."""
        term = RenewalTerminal()
        _owned_on_terminal(db, term, OLD)
        _flipped(db, [_row(OLD, PERSON)], [_row(NEW, PERSON)])
        drv, w = _setup(monkeypatch, term, [_row(NEW, PERSON)])
        w._removal_retry_streak = 1                  # a retry from an earlier pass is pending
        w._removal_retry_at_mono = time.monotonic() + 30

        def _boom(**_kw):
            raise RuntimeError("boom")
        monkeypatch.setattr(w, "_backfill_pushed_fingers", _boom)
        _run(drv, w)
        assert w._on_full_sync_finished.call_args.kwargs["ok"] is False
        assert _deleted(term, OLD) is None and str(OLD) in _state(db)
        assert (w._removal_retry_at_mono, w._removal_retry_streak) == (None, 0), (
            "the step ran and nothing it attempted failed: one report, which clears it")
        [hold] = _named(events, "RENEWAL_HOLD")
        assert (hold["held"], hold["removed_after_push"], hold["kept"]) == (1, 0, 1)


# ═════════════════════════════ PullSDK (C3 panels) ═════════════════════════════

from tests.test_account_pin_device_sites import (  # noqa: E402,F401  (fixture)
    _engine, _member, _pullsdk_device, _sdk, sqlite_db,
)


def _gym58(**kw):
    d = _pullsdk_device(pinScheme="", pushingToDevicePolicy="1")
    d.update(kw)
    return d


def _m(am, uid, name="Ali", card=None):
    return _member(am, uid, None, name, card=card or str(100000 + am))


def _pull_sdk(device_pins):
    sdk = _sdk(device_pins)
    sdk.delete_device_data_batch.side_effect = lambda *, table, pins, chunk_size: (len(pins), [])
    return sdk


def _pull_pass(users, sdk, *, device=None, engine=None):
    eng = engine or _engine()
    with patch("app.core.device_sync.PullSDK", MagicMock(return_value=sdk)):
        eng._sync_one_device(device=device or _gym58(), users=users, local_fp_index={},
                             default_door_id=1)
    return eng


def _pin_re(pin) -> "re.Pattern[str]":
    return re.compile(rf"(^|\D)Pin={pin}(\D|$)")


def _pull_write_idx(sdk, pin):
    rx = _pin_re(pin)
    for i, (name, _args, kwargs) in enumerate(sdk.mock_calls):
        if name == "set_device_data" and kwargs.get("table") == "user" \
                and rx.search(str(kwargs.get("data") or "")):
            return i
        if name == "set_device_data_batch" and kwargs.get("table") == "user" \
                and any(rx.search(str(r)) for r in (kwargs.get("rows") or [])):
            return i
    return None


def _pull_delete_idx(sdk, pin):
    rx = _pin_re(pin)
    for i, (name, _args, kwargs) in enumerate(sdk.mock_calls):
        if "delete" not in name:
            continue
        if str(pin) in {str(p) for p in (kwargs.get("pins") or [])} \
                or rx.search(str(kwargs.get("data") or "")):
            return i
    return None


def _pull_state(db) -> set:
    return set(db.list_device_sync_pins(device_id=1))


def _tracked(db, *pins) -> None:
    for pin in pins:
        db.save_device_sync_state(device_id=1, pin=str(pin), desired_hash="h-old",
                                  ok=True, error=None)


def _refuse_user_batch(sdk, pin) -> None:
    """A batched user write reports ``pin``'s row failed (the others written)."""
    rx = _pin_re(pin)

    def _side(*_a, **kw):
        rows = list(kw.get("rows") or [])
        if kw.get("table") == "user":
            bad = [r for r in rows if rx.search(str(r))]
            return (len(rows) - len(bad), bad)
        return (len(rows), [])
    sdk.set_device_data_batch.side_effect = _side


def _refuse_user_write(sdk, pin) -> None:
    rx = _pin_re(pin)

    def _side(*, table, data, options):
        if table == "user" and rx.search(str(data)):
            raise RuntimeError("user row refused")
        return None
    sdk.set_device_data.side_effect = _side


class TestPullSdkRenewal:

    def test_the_old_pin_is_deleted_after_the_new_pin_is_written(self, sqlite_db, events):
        _flipped(sqlite_db, [_m(OLD, PERSON)], [_m(NEW, PERSON)])
        _tracked(sqlite_db, OLD)
        sdk = _pull_sdk([str(OLD)])
        eng = _pull_pass([_m(NEW, PERSON)], sdk)
        written, deleted = _pull_write_idx(sdk, NEW), _pull_delete_idx(sdk, OLD)
        assert written is not None and deleted is not None and written < deleted
        assert str(OLD) not in _pull_state(sqlite_db)
        assert eng._last_removal_report["failed"] == [] and eng._last_removal_report["complete"]
        [hold] = _named(events, "RENEWAL_HOLD")
        assert (hold["held"], hold["removed_after_push"], hold["kept"]) == (1, 1, 0)
        assert hold["device_id"] == 1

    def test_a_refused_new_pin_keeps_the_old_one_and_the_next_pass_removes_it(
            self, sqlite_db, events):
        _flipped(sqlite_db, [_m(OLD, PERSON)], [_m(NEW, PERSON)])
        _tracked(sqlite_db, OLD)
        sdk = _pull_sdk([str(OLD)])
        _refuse_user_write(sdk, NEW)
        eng = _pull_pass([_m(NEW, PERSON)], sdk)
        assert _pull_delete_idx(sdk, OLD) is None
        assert str(OLD) in _pull_state(sqlite_db)
        assert sqlite_db.get_device_sync_ownership_for_pin(device_id=1, pin=str(OLD)) is True
        assert eng._last_removal_report["failed"] == [], "a kept hold is not a failed removal"
        [hold] = _named(events, "RENEWAL_HOLD")
        assert (hold["held"], hold["removed_after_push"], hold["kept"]) == (1, 0, 1)

        sdk2 = _pull_sdk([str(OLD)])
        _pull_pass([_m(NEW, PERSON)], sdk2)
        written, deleted = _pull_write_idx(sdk2, NEW), _pull_delete_idx(sdk2, OLD)
        assert written is not None and deleted is not None and written < deleted
        assert str(OLD) not in _pull_state(sqlite_db)

    def test_a_pin_held_back_by_the_retry_backoff_keeps_the_old_pin(
            self, sqlite_db, monkeypatch, events):
        import app.core.device_sync as ds

        monkeypatch.setattr(ds.DeviceSyncEngine, "_compute_desired_hash",
                            lambda self, *, pin, **kw: f"H-{pin}")
        real = ds.list_device_sync_retry_state
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        def _retry_state(*, device_id):
            out = dict(real(device_id=device_id) or {})
            out[str(NEW)] = ("", False, 9, f"H-{NEW}", stamp)
            return out
        monkeypatch.setattr(ds, "list_device_sync_retry_state", _retry_state)
        _flipped(sqlite_db, [_m(OLD, PERSON)], [_m(NEW, PERSON)])
        _tracked(sqlite_db, OLD)
        sdk = _pull_sdk([str(OLD)])
        _pull_pass([_m(NEW, PERSON)], sdk)
        assert _pull_write_idx(sdk, NEW) is None, "held back by the backoff"
        assert _pull_delete_idx(sdk, OLD) is None and str(OLD) in _pull_state(sqlite_db)
        [hold] = _named(events, "RENEWAL_HOLD")
        assert (hold["held"], hold["removed_after_push"], hold["kept"]) == (1, 0, 1)

    def test_a_real_leaver_is_still_deleted_first(self, sqlite_db):
        _flipped(sqlite_db, [_m(OLD, PERSON), _m(LEAVER, 901, "Bob")], [_m(NEW, PERSON)])
        _tracked(sqlite_db, OLD, LEAVER)
        sdk = _pull_sdk([str(OLD), str(LEAVER)])
        _pull_pass([_m(NEW, PERSON)], sdk)
        leaver, written, old = (_pull_delete_idx(sdk, LEAVER), _pull_write_idx(sdk, NEW),
                                _pull_delete_idx(sdk, OLD))
        assert None not in (leaver, written, old)
        assert leaver < written < old

    def test_a_failed_post_push_delete_is_a_removal_failure(self, sqlite_db, events):
        _flipped(sqlite_db, [_m(OLD, PERSON)], [_m(NEW, PERSON)])
        _tracked(sqlite_db, OLD)
        sdk = _pull_sdk([str(OLD)])
        sdk.delete_device_data_batch.side_effect = lambda *, table, pins, chunk_size: (
            (0, [p for p in pins if str(p) == str(OLD)]) if table == "user"
            else (len(pins), []))
        eng = _pull_pass([_m(NEW, PERSON)], sdk)
        assert _pull_write_idx(sdk, NEW) < _pull_delete_idx(sdk, OLD)
        assert eng._last_removal_report["failed"] == [str(OLD)]
        assert eng._last_removal_report["complete"] is True
        assert str(OLD) in _pull_state(sqlite_db), "kept for the removal retry"
        [hold] = _named(events, "RENEWAL_HOLD")
        assert (hold["held"], hold["removed_after_push"], hold["kept"]) == (1, 0, 0)

    def test_the_ceiling_judges_the_leavers_and_a_release_beyond_it_waits(self, sqlite_db, events):
        # Review R1 (inverts "the ceiling counts holds"), as on the MB2000.
        leavers = [_m(LEAVER + i, 7000 + i, f"L{i}") for i in range(10)]
        _flipped(sqlite_db, [_m(OLD, PERSON)] + leavers, [_m(NEW, PERSON)])
        pins = [str(OLD)] + [str(LEAVER + i) for i in range(10)]
        _tracked(sqlite_db, *pins)
        sdk = _pull_sdk(pins)
        _pull_pass([_m(NEW, PERSON)], sdk)
        written = _pull_write_idx(sdk, NEW)
        assert all(_pull_delete_idx(sdk, LEAVER + i) < written for i in range(10))
        assert _pull_delete_idx(sdk, OLD) is None, "11 removals would exceed the ceiling"
        assert not [a for a in _named(events, "REVOKE_ABORTED") if a.get("path") == "stale"]
        [abort] = [a for a in _named(events, "REVOKE_ABORTED") if a.get("path") == "renewal_release"]
        assert abort["count"] == 11
        assert str(OLD) in _pull_state(sqlite_db)
        [hold] = _named(events, "RENEWAL_HOLD")
        assert (hold["held"], hold["removed_after_push"], hold["kept"]) == (1, 0, 1)

    def test_a_kept_hold_does_not_push_the_next_days_leavers_over_the_ceiling(
            self, sqlite_db, events):
        leavers = [_m(LEAVER + i, 7000 + i, f"L{i}") for i in range(10)]
        _flipped(sqlite_db, [_m(OLD, PERSON)], [_m(NEW, PERSON)] + leavers)
        pins = [str(OLD)] + [str(LEAVER + i) for i in range(10)]
        _tracked(sqlite_db, *pins)
        sdk = _pull_sdk(pins)
        _refuse_user_write(sdk, NEW)
        _refuse_user_batch(sdk, NEW)
        eng = _pull_pass([_m(NEW, PERSON)] + leavers, sdk)         # day D: old pin kept
        assert _pull_delete_idx(sdk, OLD) is None
        _flipped(sqlite_db, leavers, [_m(NEW, PERSON)])             # day D+1: ten plans end
        events.clear()
        sdk2 = _pull_sdk(pins)
        _refuse_user_write(sdk2, NEW)
        _refuse_user_batch(sdk2, NEW)
        _pull_pass([_m(NEW, PERSON)], sdk2, engine=eng)
        assert not [a for a in _named(events, "REVOKE_ABORTED") if a.get("path") == "stale"]
        assert all(_pull_delete_idx(sdk2, LEAVER + i) is not None for i in range(10))
        assert _pull_delete_idx(sdk2, OLD) is None, "the renewed member keeps the old pin"

    def test_under_the_ceiling_leavers_first_and_the_hold_after(self, sqlite_db, events):
        leavers = [_m(LEAVER + i, 7000 + i, f"L{i}") for i in range(9)]
        _flipped(sqlite_db, [_m(OLD, PERSON)] + leavers, [_m(NEW, PERSON)])
        pins = [str(OLD)] + [str(LEAVER + i) for i in range(9)]
        _tracked(sqlite_db, *pins)
        sdk = _pull_sdk(pins)
        _pull_pass([_m(NEW, PERSON)], sdk)
        written = _pull_write_idx(sdk, NEW)
        assert all(_pull_delete_idx(sdk, LEAVER + i) < written for i in range(9))
        assert _pull_delete_idx(sdk, OLD) > written
        assert not _named(events, "REVOKE_ABORTED")

    def test_a_person_whose_new_pin_is_already_confirmed_is_a_normal_leaver(
            self, sqlite_db, events):
        _flipped(sqlite_db, [_m(OLD, PERSON)], [_m(NEW, PERSON), _m(30002, 901, "Bob")])
        _tracked(sqlite_db, OLD)
        # First pass writes both new pins (the old one is held, then removed after).
        _pull_pass([_m(NEW, PERSON), _m(30002, 901, "Bob")], _pull_sdk([str(OLD)]))
        # The old pin is back on the panel (e.g. a restored backup) and tracked; NEW is
        # confirmed now, only 30003 needs a push.
        _tracked(sqlite_db, OLD)
        events.clear()
        sdk = _pull_sdk([str(OLD), str(NEW), "30002"])
        _pull_pass([_m(NEW, PERSON), _m(30002, 901, "Bob"), _m(30003, 902, "Cy")], sdk)
        assert _pull_write_idx(sdk, NEW) is None, "confirmed: not pushed"
        deleted, other = _pull_delete_idx(sdk, OLD), _pull_write_idx(sdk, 30003)
        assert deleted is not None and other is not None and deleted < other
        assert not _named(events, "RENEWAL_HOLD")

    def test_an_explicit_revocation_is_not_held(self, sqlite_db, events):
        _flipped(sqlite_db, [_m(OLD, PERSON)], [_m(NEW, PERSON)])
        _tracked(sqlite_db, OLD)
        sdk = _pull_sdk([str(OLD)])
        eng = _engine()
        # What the ULTRA worker's full sync hands the engine: the memberships this pass
        # revokes (its pre-pass may have failed to remove one; the stale step retries it).
        eng._full_sync_revoked_pins = {str(OLD)}
        _pull_pass([_m(NEW, PERSON)], sdk, engine=eng)
        deleted, written = _pull_delete_idx(sdk, OLD), _pull_write_idx(sdk, NEW)
        assert deleted is not None and written is not None and deleted < written
        assert not _named(events, "RENEWAL_HOLD")

    def test_the_ultra_full_sync_hands_its_revocations_to_the_engine(self, monkeypatch):
        import threading

        seen: Dict[str, Any] = {}

        class _Engine:
            def __init__(self, cfg, logger):
                self._last_single_device_error = ""
                self._last_removal_report = {"aborted": 0, "failed": [], "complete": True}

            def sync_member_on_connected_sdk(self, **kw):
                return True

            def run_one_device_on_connected_sdk(self, **kw):
                seen["pins"] = set(getattr(self, "_full_sync_revoked_pins", None) or ())
                return True

        w = ue.UltraDeviceWorker(
            device={"id": 5, "name": "Door", "ipAddress": "10.0.0.5", "portNumber": 4370},
            settings={}, popup_q=queue.Queue(), history_q=queue.Queue(),
            stop_event=threading.Event(),
        )
        w._connected = True
        w._sdk = SimpleNamespace(owns_event_source=False, _sdk="raw")
        w._on_full_sync_finished = MagicMock()
        monkeypatch.setattr(ue, "load_sync_cache",
                            lambda: SimpleNamespace(users=[{"activeMembershipId": 1}], devices=[]))
        monkeypatch.setattr("app.core.device_sync.DeviceSyncEngine", _Engine)
        w.request_full_sync(reason="timer", fingerprint_hash="h", revoked_ids={OLD})
        assert w._drain_full_sync_commands(limit=1) == 1
        assert seen["pins"] == {str(OLD)}

    def test_account_scheme_is_unaffected(self, sqlite_db, events):
        new_row = _member(NEW, PERSON, 5, "Ali", card="1900")
        _flipped(sqlite_db, [_m(OLD, PERSON)], [new_row])
        _tracked(sqlite_db, OLD)
        sdk = _pull_sdk([str(OLD)])
        _pull_pass([new_row], sdk, device=_gym58(pinScheme="ACCOUNT"))
        deleted, written = _pull_delete_idx(sdk, OLD), _pull_write_idx(sdk, 5)
        assert deleted is not None and written is not None and deleted < written
        assert not _named(events, "RENEWAL_HOLD")

    def test_the_batch_branch_deletes_the_old_pin_after_the_user_batch(self, sqlite_db, events):
        """More than 5 pins: Phase A writes the user rows in a batch; Phase D sets the outcome."""
        others = [_m(30002 + i, 901 + i, f"M{i}") for i in range(5)]
        _flipped(sqlite_db, [_m(OLD, PERSON)], [_m(NEW, PERSON)] + others)
        _tracked(sqlite_db, OLD)
        sdk = _pull_sdk([str(OLD)])
        _pull_pass([_m(NEW, PERSON)] + others, sdk)
        written, deleted = _pull_write_idx(sdk, NEW), _pull_delete_idx(sdk, OLD)
        assert written is not None and deleted is not None and written < deleted
        assert sdk.mock_calls[written][0] == "set_device_data_batch"
        assert str(OLD) not in _pull_state(sqlite_db)
        [hold] = _named(events, "RENEWAL_HOLD")
        assert (hold["held"], hold["removed_after_push"], hold["kept"]) == (1, 1, 0)

    def test_the_batch_branch_keeps_the_old_pin_when_the_new_user_row_is_refused(
            self, sqlite_db, events):
        others = [_m(30002 + i, 901 + i, f"M{i}") for i in range(5)]
        _flipped(sqlite_db, [_m(OLD, PERSON)], [_m(NEW, PERSON)] + others)
        _tracked(sqlite_db, OLD)
        sdk = _pull_sdk([str(OLD)])
        rx = _pin_re(NEW)

        def _batch(*, table, rows, chunk_size, progress_cb=None):
            bad = [r for r in rows if table == "user" and rx.search(str(r))]
            return (len(rows) - len(bad), bad)
        sdk.set_device_data_batch.side_effect = _batch
        _refuse_user_write(sdk, NEW)            # and the per-row fallback is refused too
        eng = _pull_pass([_m(NEW, PERSON)] + others, sdk)
        assert _pull_delete_idx(sdk, OLD) is None, "the person would have had neither pin"
        assert str(OLD) in _pull_state(sqlite_db)
        assert eng._last_removal_report["failed"] == []
        [hold] = _named(events, "RENEWAL_HOLD")
        assert (hold["held"], hold["removed_after_push"], hold["kept"]) == (1, 0, 1)

    def test_a_pass_that_raises_after_the_stale_step_keeps_the_hold(
            self, sqlite_db, monkeypatch, events):
        import app.core.device_sync as ds

        def _no_intent(**_kw):
            raise RuntimeError("intent not recorded")
        monkeypatch.setattr(ds, "record_push_intents", _no_intent)
        _flipped(sqlite_db, [_m(OLD, PERSON)], [_m(NEW, PERSON)])
        _tracked(sqlite_db, OLD)
        sdk = _pull_sdk([str(OLD)])
        eng = _engine()
        with pytest.raises(RuntimeError):
            _pull_pass([_m(NEW, PERSON)], sdk, engine=eng)
        assert _pull_write_idx(sdk, NEW) is None and _pull_delete_idx(sdk, OLD) is None
        assert str(OLD) in _pull_state(sqlite_db)
        assert eng._last_removal_report["complete"] is False, (
            "a pass that stopped early keeps a pending removal retry armed (R1-06)")
        [hold] = _named(events, "RENEWAL_HOLD")
        assert (hold["held"], hold["removed_after_push"], hold["kept"]) == (1, 0, 1)

    def test_a_pass_without_holds_is_unchanged(self, sqlite_db, events):
        """No person link: the stale step deletes before the push, exactly as before."""
        _tracked(sqlite_db, OLD)
        sdk = _pull_sdk([str(OLD)])
        _pull_pass([_m(NEW, PERSON)], sdk)
        assert _pull_delete_idx(sdk, OLD) < _pull_write_idx(sdk, NEW)
        assert not _named(events, "RENEWAL_HOLD")

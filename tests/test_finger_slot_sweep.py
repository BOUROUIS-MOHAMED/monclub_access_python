"""P3a-2 item 5: a deleted finger must not stay on the MB2000.

The vacated-slot removal (2026-09-05) needs to KNOW which slots a pin holds
(``device_sync_state.pushed_finger_ids``). An unknown set (NULL, or no row) yielded no
removal at all, and the recorded set of every pin pushed before that fix was written
as the desired set WITHOUT any clear (the backfill), so a finger deleted in those days
could still be resident under a "known" set.

Now: an owned pin that was never swept (``finger_slots_swept=0``) has its unused
slots 0-9 cleared with ``SSR_DelUserTmpExt`` -- at once on a targeted push, otherwise
by a bounded batch once a day after the morning sync. An empty slot answers False
(field-measured), so False is counted, never a failure; only an exception or a wedge
is. A first push (no row) or an unowned pin is never swept: on gym 45's shared
terminals that pin may be another system's user. ``pushed_finger_ids`` of an unknown
pin is recorded only after its sweep succeeded.

Real driver + real STA thread over a stateful fake terminal; real temp SQLite.
"""
from __future__ import annotations

import io
import queue
import re

import pytest

import app.core.db as dbmod
import app.core.ultra_engine as ue
from tests.fake_terminal import TerminalZkem
from tests.test_standalone_incremental_sync import _make_driver, _tpl, _user, _worker


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "sweep.db"), raising=False)
    dbmod.init_db()
    yield dbmod
    dbmod._shutdown_db_writer_for_tests()


def _own(db, pin, *, fingers=None, swept=False, ok=True):
    rows = [(str(pin), "h-old", ok, None, None if fingers is None else ",".join(map(str, sorted(fingers))))]
    db.save_device_sync_state_batch(device_id=9, rows=rows)
    if swept:
        db.mark_finger_slots_swept(device_id=9, pin=str(pin), finger_ids=None)


# ═════════════════════════ driver ═════════════════════════

class TestDriverSweep:

    def test_false_on_an_empty_slot_is_not_a_failure(self):
        term = TerminalZkem()
        term.add_user("117", "A", "1", fingers=(0, 3))
        drv = _make_driver(term)
        try:
            res = drv.sweep_finger_slots("117", [1, 2, 3], refresh=True)
        finally:
            drv.disconnect()
        assert res["ok"] is True
        assert (res["returned_true"], res["returned_false"], res["raised"]) == (1, 2, 0)
        assert term.fingers_of("117") == {0}, "slot 3 cleared, slot 0 (not swept) untouched"
        assert any(c[0] == "RefreshData" for c in term.calls)
        assert not any(c[0] == "SSR_DeleteEnrollData" for c in term.calls)

    def test_an_exception_is_a_failure(self):
        term = TerminalZkem()
        drv = _make_driver(term)
        real = term.SSR_DelUserTmpExt

        def _boom(machine, pin, finger):
            if int(finger) == 2:
                raise RuntimeError("COM fault")
            return real(machine, pin, finger)

        term.SSR_DelUserTmpExt = _boom
        try:
            res = drv.sweep_finger_slots("117", [1, 2, 3])
        finally:
            drv.disconnect()
        assert res["ok"] is False and res["raised"] == 1

    def test_out_of_range_slots_and_bad_pins_are_refused(self):
        term = TerminalZkem()
        drv = _make_driver(term)
        try:
            res = drv.sweep_finger_slots("117", [-1, 10, 12, "x", 4])
            bad = drv.sweep_finger_slots("abc", [1])
        finally:
            drv.disconnect()
        assert res["attempted"] == 1, "only 0-9 are finger slots"
        assert bad["ok"] is False

    def test_the_must_not_call_grep_still_counts_three(self):
        """zkemkeeper_guide.md §11: exactly two SSR_DelUserTmpExt call lines and ONE
        whole-user SSR_DeleteEnrollData(1, pin, 12); any finger-index DeleteEnrollData is
        the v1.4.25 hang."""
        src = io.open("app/sdk/zk_standalone.py", encoding="utf-8").read()
        assert len(re.findall(r"zk\.SSR_DelUserTmpExt\(", src)) == 2
        assert len(re.findall(r"zk\.SSR_DeleteEnrollData\(", src)) == 1
        assert "zk.SSR_DeleteEnrollData(1, pin, 12)" in src


# ═════════════════════════ targeted push ═════════════════════════

class TestTargetedPushSweeps:

    def _member_sync(self, monkeypatch, term, user):
        drv = _make_driver(term)
        w, _c = _worker(monkeypatch, driver=drv, users=[user])
        try:
            w._run_standalone_member_sync(int(user["activeMembershipId"]))
        finally:
            drv.disconnect()
        return w

    def test_an_owned_pin_with_an_unknown_set_loses_its_deleted_finger(self, db, monkeypatch):
        term = TerminalZkem()
        term.add_user("34439", "Ali", "1", fingers=(0, 3))        # finger 3 deleted long ago
        _own(db, "34439", fingers=None)                            # owned, set UNKNOWN
        self._member_sync(monkeypatch, term, _user(34439, "Ali", "1", fps=[_tpl(0, "AAAA")]))
        assert term.fingers_of("34439") == {0}
        owned, swept, fingers = db.get_finger_sweep_state(device_id=9, pin="34439")
        assert swept is True and fingers == {0}

    def test_a_laundered_known_set_is_swept_too(self, db, monkeypatch):
        """Recorded {0} by the 2026-09-05 backfill while slot 3 still held a deleted finger."""
        term = TerminalZkem()
        term.add_user("34439", "Ali", "1", fingers=(0, 3))
        _own(db, "34439", fingers={0})
        self._member_sync(monkeypatch, term, _user(34439, "Ali", "2", fps=[_tpl(0, "AAAA")]))
        assert term.fingers_of("34439") == {0}
        assert db.get_finger_sweep_state(device_id=9, pin="34439")[1] is True

    def test_a_swept_pin_is_not_swept_again(self, db, monkeypatch):
        term = TerminalZkem()
        term.add_user("34439", "Ali", "1", fingers=(0,))
        _own(db, "34439", fingers={0}, swept=True)
        self._member_sync(monkeypatch, term, _user(34439, "Ali", "2", fps=[_tpl(0, "AAAA")]))
        dels = [c for c in term.calls if c[0] == "SSR_DelUserTmpExt"]
        assert dels == [("SSR_DelUserTmpExt", 1, "34439", 0)], "only the delete-before-write"

    @pytest.mark.parametrize("seed", ["first_push", "unowned_row"])
    def test_never_on_a_pin_monclub_did_not_own_before_the_push(self, db, monkeypatch, seed):
        """A first push can collide with another system's user on a shared terminal:
        its fingerprints are not MonClub's to sweep."""
        term = TerminalZkem()
        term.add_user("34439", "OTHER", "9", fingers=(4,))
        if seed == "unowned_row":
            _own(db, "34439", fingers=None, ok=False)
        self._member_sync(monkeypatch, term, _user(34439, "Ali", "1", fps=[_tpl(0, "AAAA")]))
        assert 4 in term.fingers_of("34439")
        assert not any(c[0] == "SSR_DelUserTmpExt" and c[3] != 0 for c in term.calls)

    def test_a_failed_sweep_keeps_the_set_unknown(self, db, monkeypatch):
        term = TerminalZkem()
        term.add_user("34439", "Ali", "1", fingers=(0, 3))
        _own(db, "34439", fingers=None)
        real = term.SSR_DelUserTmpExt

        def _boom(machine, pin, finger):
            if int(finger) == 5:
                raise RuntimeError("COM fault")
            return real(machine, pin, finger)

        term.SSR_DelUserTmpExt = _boom
        self._member_sync(monkeypatch, term, _user(34439, "Ali", "1", fps=[_tpl(0, "AAAA")]))
        owned, swept, fingers = db.get_finger_sweep_state(device_id=9, pin="34439")
        assert swept is False and fingers is None, "recorded only after the clear succeeds"

    def test_no_sweep_when_fingerprints_are_disabled(self, db, monkeypatch):
        term = TerminalZkem()
        term.add_user("34439", "Ali", "1", fingers=(3,))
        _own(db, "34439", fingers=None)
        drv = _make_driver(term)
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(34439, "Ali", "1")])
        w._settings["fingerprint_enabled"] = False
        try:
            w._run_standalone_member_sync(34439)
        finally:
            drv.disconnect()
        assert 3 in term.fingers_of("34439")


# ═════════════════════════ daily bounded batch ═════════════════════════

class TestDailyBatch:

    def _setup(self, db, monkeypatch, n=3):
        term = TerminalZkem()
        users = []
        for i in range(n):
            pin = 30001 + i
            term.add_user(str(pin), f"M{i}", str(i), fingers=(0, 7))   # 7 = a stale finger
            users.append(_user(pin, f"M{i}", str(i), fps=[_tpl(0, "AAAA")]))
        drv = _make_driver(term)
        w, _c = _worker(monkeypatch, driver=drv, users=users)
        w._cmd_queue = queue.Queue()
        w._run_standalone_full_sync(reason="startup", fingerprint_hash="h")   # the morning pass
        # every pin is now owned and unswept (a full-roster push never sweeps)
        return term, drv, w

    def test_the_batch_sweeps_one_command_per_loop_iteration_after_the_morning_sync(
            self, db, monkeypatch):
        term, drv, w = self._setup(db, monkeypatch)
        try:
            assert all(7 in term.fingers_of(p) for p in ("30001", "30002", "30003"))
            iterations = 0
            while db.list_finger_sweep_candidates(device_id=9) and iterations < 50:
                before = len([c for c in term.calls if c[0] == "SSR_DelUserTmpExt"])
                w._drain_daily_maintenance()
                after = len([c for c in term.calls if c[0] == "SSR_DelUserTmpExt"])
                assert after - before <= ue._SWEEP_SLOTS_PER_COMMAND, "one short command per call"
                iterations += 1
        finally:
            drv.disconnect()
        assert db.list_finger_sweep_candidates(device_id=9) == {}
        assert all(term.fingers_of(p) == {0} for p in ("30001", "30002", "30003"))

    def test_not_before_the_days_first_full_sync_and_not_while_work_waits(self, db, monkeypatch):
        term, drv, w = self._setup(db, monkeypatch)
        try:
            w._maintenance_ready_day = "1999-01-01"
            w._drain_daily_maintenance()
            assert not any(c[0] == "SSR_DelUserTmpExt" and c[3] == 7 for c in term.calls)
            w._maintenance_ready_day = ue._local_day()
            w._cmd_queue.put(("door", 1))                       # an operator open is waiting
            w._drain_daily_maintenance()
            assert not any(c[0] == "SSR_DelUserTmpExt" and c[3] == 7 for c in term.calls)
        finally:
            drv.disconnect()

    def test_the_daily_cap_bounds_the_batch(self, db, monkeypatch):
        monkeypatch.setattr(ue, "_FINGER_SWEEP_DAILY_CAP", 2)
        term, drv, w = self._setup(db, monkeypatch, n=4)
        try:
            for _ in range(60):
                w._drain_daily_maintenance()
        finally:
            drv.disconnect()
        assert len(db.list_finger_sweep_candidates(device_id=9)) == 2

    def test_a_finger_recorded_since_the_snapshot_is_protected(self, db, monkeypatch):
        """A targeted push added finger 7 after the morning snapshot: the batch must not
        clear it (it clears only slots neither desired then nor recorded now)."""
        term, drv, w = self._setup(db, monkeypatch, n=1)
        db.save_device_sync_state_batch(device_id=9, rows=[("30001", "h-new", True, None, "0,7")])
        try:
            for _ in range(10):
                w._drain_daily_maintenance()
        finally:
            drv.disconnect()
        assert 7 in term.fingers_of("30001")


class TestDailyBatchReviewRoundOne:
    """R1-18/R1-19/R1-27: the batch planned a pin's slots once and resumed that plan
    across run-loop iterations -- after pushes in between, and after a later pass with an
    incomplete roster had rewritten the desired snapshot."""

    def _morning(self, db, monkeypatch, n):
        term = TerminalZkem()
        users = []
        for i in range(n):
            pin = 30001 + i
            term.add_user(str(pin), f"M{i}", str(i), fingers=(0, 7))     # 7 = a stale finger
            users.append(_user(pin, f"M{i}", str(i), fps=[_tpl(0, "AAAA")]))
        drv = _make_driver(term)
        w, cache = _worker(monkeypatch, driver=drv, users=users)
        w._cmd_queue = queue.Queue()
        w._run_standalone_full_sync(reason="startup", fingerprint_hash="h")
        return term, drv, w, cache

    def _until_sweeping(self, w, term, pin):
        """Drain until the BATCH has cleared this pin's first slice (the morning push's
        own delete-before-write of slot 0 does not count)."""
        mark = len(term.calls)
        for _ in range(10):
            w._drain_daily_maintenance()
            if any(c[0] == "SSR_DelUserTmpExt" and str(c[2]) == pin
                   for c in term.calls[mark:]):
                return
        raise AssertionError("the batch never started on " + pin)

    def test_a_targeted_push_between_two_sweep_commands_is_never_undone(self, db, monkeypatch):
        term, drv, w, _cache = self._morning(db, monkeypatch, 1)
        monkeypatch.setattr(w, "_member_row_in_db", lambda m: [
            _user(30001, "M0", "0", fps=[_tpl(0, "AAAA"), _tpl(5, "FFFF")])])
        try:
            self._until_sweeping(w, term, "30001")          # slots 1,2,3 cleared
            w._run_standalone_member_sync(30001)             # the member enrols finger 5
            assert 5 in term.fingers_of("30001")
            for _ in range(10):
                w._drain_daily_maintenance()
        finally:
            drv.disconnect()
        assert 5 in term.fingers_of("30001"), "the batch resumed its old plan and cleared it"

    def test_a_full_sync_between_two_sweep_commands_is_never_undone(self, db, monkeypatch):
        term, drv, w, cache = self._morning(db, monkeypatch, 1)
        try:
            self._until_sweeping(w, term, "30001")
            cache.users[:] = [_user(30001, "M0", "0", fps=[_tpl(0, "AAAA"), _tpl(5, "FFFF")])]
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h2")
            assert 5 in term.fingers_of("30001")
            for _ in range(10):
                w._drain_daily_maintenance()
        finally:
            drv.disconnect()
        assert 5 in term.fingers_of("30001")

    def test_a_later_incomplete_roster_never_empties_a_members_fingers(self, db, monkeypatch):
        term, drv, w, cache = self._morning(db, monkeypatch, 2)
        with dbmod.get_conn() as conn:                        # its targeted sweep had failed
            conn.execute("UPDATE device_sync_state SET pushed_finger_ids=NULL "
                         "WHERE device_id=9 AND pin='30002'")
            conn.commit()
        orig = w._build_standalone_roster

        def withheld(*a, **k):
            out = orig(*a, **k)
            w._last_standalone_roster_stats = {"withheld_missing_account": 1}
            return out
        try:
            self._until_sweeping(w, term, "30001")           # the day's queue holds 30002
            cache.users[:] = [u for u in cache.users if u["activeMembershipId"] == 30001]
            monkeypatch.setattr(w, "_build_standalone_roster", withheld)
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h2")
            for _ in range(20):
                w._drain_daily_maintenance()
        finally:
            drv.disconnect()
        assert 0 in term.fingers_of("30002"), "a paying member's finger was wiped"


class TestBackoffHeldPinsAreNotStampedSynced:

    def test_a_pin_in_retry_backoff_is_not_backfilled_as_ok(self, db, monkeypatch):
        """Found in the P3a-2 study: the backfill received every desired pin not pushed --
        including one held back by the retry backoff -- and wrote it ok=True, so a
        refused member silently became 'in sync' and was never retried."""
        term = TerminalZkem()
        drv = _make_driver(term)
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "A", "1")])
        h = ue._standalone_pin_hash({"pin": "30001", "name": "A", "card": "1"}, [])
        with dbmod.get_conn() as conn:
            conn.execute(
                "INSERT INTO device_sync_state (device_id, pin, desired_hash, last_ok, last_error, "
                "updated_at, pushed_finger_ids, ownership_confirmed, fail_streak, last_attempt_hash) "
                "VALUES (9, '30001', 'h-old', 0, 'refused', datetime('now','localtime'), NULL, 1, 9, ?)",
                (h,),
            )
            conn.commit()
        try:
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
        finally:
            drv.disconnect()
        assert db.list_device_sync_hashes_and_status(device_id=9)["30001"][1] is False

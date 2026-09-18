"""P3a-2 item 6: the door does not wait behind a long push, and one pass is capped.

Before: a full sync on a standalone terminal (MB2000) ran push_roster to its end on
the worker thread. Every chunk came back to that thread, but nothing ran between two
chunks: a QR/TOTP or staff-RFID rescue scan sat in the driver's event queue, a desk
"Open" sat in the command queue, and an enrolment's targeted push sat in the member
queue -- for the whole push (a documented 419 s for 928 members). And one pass pushed
every pin that needed it, however many.

Now, between two chunks, the worker decides the queued scans, opens the queued doors
and serves ONE pending member update or revoke. A pin that update wrote (or revoked)
is dropped from the chunks not yet sent, never recorded from the pass's older
snapshot, and never pruned. A pass pushes at most _FULL_SYNC_MAX_PINS_PER_PASS pins:
the rest stay pending (no state row), the roster hash is withheld, and the pass
queues its own continuation when it made progress.

Real driver + real STA thread over the stateful fake terminal; real temp SQLite.
"""
from __future__ import annotations

import queue
import threading
import time

import pytest

import app.core.db as dbmod
import app.core.telemetry as tel
import app.core.ultra_engine as ue
from tests.fake_terminal import TerminalZkem
from tests.test_standalone_incremental_sync import _make_driver, _tpl, _user, _worker


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "yield.db"), raising=False)
    dbmod.init_db()
    yield dbmod
    dbmod._shutdown_db_writer_for_tests()


class HookedTerminal(TerminalZkem):
    """Runs ``on_user[pin]()`` (once) right after SSR_SetUserInfo writes that pin.

    It runs on the STA thread, in the middle of a chunk -- i.e. exactly while the
    worker thread is blocked waiting for that chunk.
    """

    def __init__(self, **kw):
        super().__init__(**kw)
        self.on_user: dict = {}

    def SSR_SetUserInfo(self, machine, pin, name, pw, priv, enabled):
        ok = super().SSR_SetUserInfo(machine, pin, name, pw, priv, enabled)
        fn = self.on_user.pop(str(pin), None)
        if fn is not None:
            fn()
        return ok


def _members(n, first=30001):
    return [_user(first + i, f"M{i}", str(100 + i)) for i in range(n)]


def _punch(pin):
    return (str(pin), 0, 0, 1, 2026, 9, 18, 10, 0, 0, 0)


def _setup(monkeypatch, term, users):
    drv = _make_driver(term)
    term.sink = drv._on_att_event
    w, _cache = _worker(monkeypatch, driver=drv, users=users)
    w._cmd_queue = queue.Queue()
    return drv, w


def _writes(term, pin):
    return [c for c in term.calls if c[0] == "SSR_SetUserInfo" and str(c[2]) == str(pin)]


def _cap():
    return getattr(ue, "_FULL_SYNC_MAX_PINS_PER_PASS", 50)


# ═════════════════════════ reproductions: the door waited ═════════════════════════

class TestTheDoorDoesNotWait:

    def test_a_scan_during_a_push_is_decided_before_the_push_ends(self, db, monkeypatch):
        term = HookedTerminal()
        drv, w = _setup(monkeypatch, term, _members(40))
        decided = []
        w._process_event = lambda evt: decided.append((evt, len(term.users)))
        term.on_user["30012"] = lambda: term.pending_punches.append(_punch("777"))
        try:
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
        finally:
            drv.disconnect()
        assert len(term.users) == 40
        assert decided, "the scan was never decided during the push"
        assert decided[0][1] == 20, (
            "decided at the end of the chunk it arrived in (members 11-20), "
            "not after all 40 members were written")

    def test_a_desk_open_during_a_push_is_executed_before_the_push_ends(self, db, monkeypatch):
        term = HookedTerminal()
        drv, w = _setup(monkeypatch, term, _members(40))
        box = {"ok": False, "error": "timeout"}
        done = threading.Event()
        term.on_user["30012"] = lambda: w._cmd_queue.put_nowait(
            (1, 3000, done, box, time.monotonic() + 30.0))
        try:
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
        finally:
            drv.disconnect()
        # Call ORDER, not timestamps: the monotonic clock ticks every ~15.6 ms on Windows
        # and this fake takes no time, so every call may carry the same stamp.
        names = [n for n, _t, _a in term.call_times]
        unlock = [i for i, n in enumerate(names) if n == "ACUnlock"]
        last_write = max(i for i, n in enumerate(names) if n == "SSR_SetUserInfo")
        assert unlock and unlock[0] < last_write, "the door opened only after the push"
        assert names[:unlock[0]].count("SSR_SetUserInfo") == 20, (
            "opened at the end of the chunk it was queued in (members 11-20)")
        assert done.is_set() and box["ok"] is True

    def test_an_update_queued_mid_push_is_served_and_its_newer_data_wins(self, db, monkeypatch):
        term = HookedTerminal()
        drv, w = _setup(monkeypatch, term, _members(30))     # the pass's snapshot: "M24"
        monkeypatch.setattr(w, "_member_row_in_db",
                            lambda m: [_user(30025, "Renamed", "124")] if int(m) == 30025 else [])
        term.on_user["30005"] = lambda: w.request_member_sync(30025)
        try:
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
        finally:
            drv.disconnect()
        assert term.users["30025"]["name"] == "Renamed"
        assert len(_writes(term, "30025")) == 1, "the pass's older snapshot never re-pushed it"
        state = db.list_device_sync_hashes_and_status(device_id=9)
        assert state["30025"][0] == ue._standalone_pin_hash(
            {"pin": "30025", "name": "Renamed", "card": "124"}, [])
        assert not w._pending_member_syncs
        kw = w._on_full_sync_finished.call_args.kwargs
        assert kw["ok"] is True, "a superseded pin is not a failed pin"

    def test_a_revoke_queued_mid_push_is_served_and_the_pass_never_re_enrols(
            self, db, monkeypatch):
        term = HookedTerminal()
        term.add_user("30025", "M24", "124")
        db.save_device_sync_state_batch(device_id=9, rows=[("30025", "h-old", True, None, "")])
        drv, w = _setup(monkeypatch, term, _members(30))     # snapshot taken before the revoke
        term.on_user["30005"] = lambda: w.request_member_revoke(30025)
        try:
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
        finally:
            drv.disconnect()
        assert "30025" not in term.users
        assert _writes(term, "30025") == []
        assert "30025" not in db.list_device_sync_hashes_and_status(device_id=9)
        assert not w._pending_member_syncs and not w._active_member_revoke_ids

    def test_a_member_added_mid_push_keeps_its_ownership(self, db, monkeypatch):
        term = HookedTerminal()
        drv, w = _setup(monkeypatch, term, _members(30))     # 30099 not in the snapshot
        monkeypatch.setattr(w, "_member_row_in_db",
                            lambda m: [_user(30099, "New", "999")] if int(m) == 30099 else [])
        term.on_user["30005"] = lambda: w.request_member_sync(30099)
        try:
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
        finally:
            drv.disconnect()
        assert "30099" in term.users
        assert "30099" in db.list_confirmed_device_sync_pins(device_id=9), (
            "the pass's prune must not erase the proof that MonClub wrote it")

    def test_the_stall_clock_restarts_at_every_chunk(self, db, monkeypatch):
        term = HookedTerminal()
        drv, w = _setup(monkeypatch, term, _members(40))
        states = []
        monkeypatch.setattr(tel, "set_state", lambda wid, state, detail="": states.append(state))
        try:
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
        finally:
            drv.disconnect()
        # Entered once, then re-entered after each of the 3 between-chunk yields: the
        # WORKER_STALL clock measures one chunk, not the whole push.
        assert states.count("full_sync") == 4


# ═════════════════════════ the cap ═════════════════════════

class TestOnePassIsCapped:

    def test_a_pass_pushes_at_most_the_cap_and_the_rest_stays_pending(self, db, monkeypatch):
        term = HookedTerminal()
        drv, w = _setup(monkeypatch, term, _members(120))
        cap = _cap()
        try:
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
            assert len(term.users) == cap
            state = db.list_device_sync_hashes_and_status(device_id=9)
            assert len(state) == cap, "a pin left for later gets no row: never 'in sync'"
            kw = w._on_full_sync_finished.call_args.kwargs
            assert kw["ok"] is True and kw["fingerprint_hash"] is None
            assert w._pending_full_sync_request is not None, "it queued its continuation"
            passes = 1
            while w._pending_full_sync_request is not None and passes < 10:
                w._drain_full_sync_commands(limit=1)
                passes += 1
        finally:
            drv.disconnect()
        assert passes == 3 and len(term.users) == 120
        assert all(len(_writes(term, 30001 + i)) == 1 for i in range(120))
        assert w._on_full_sync_finished.call_args.kwargs["fingerprint_hash"] == "h"
        notes = [u.get("error_message") or "" for u in w._push_batch_updates]
        assert any("PUSH_CAPPED=70" in n for n in notes)

    def test_no_progress_queues_no_continuation(self, db, monkeypatch):
        term = HookedTerminal()
        term.setuserinfo_ok = False
        drv, w = _setup(monkeypatch, term, _members(120))
        try:
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
        finally:
            drv.disconnect()
        assert w._pending_full_sync_request is None

    def test_removals_first_then_new_then_failed_then_changed(self, db, monkeypatch):
        monkeypatch.setattr(ue, "_FULL_SYNC_MAX_PINS_PER_PASS", 3)
        term = HookedTerminal()
        term.add_user("30001", "Old", "100")
        term.add_user("30004", "M3", "103", fingers=(0, 1))
        db.save_device_sync_state_batch(device_id=9, rows=[
            ("30001", "h-old", True, None, ""),          # changed
            ("30002", "h-x", False, "refused", None),    # failed
            ("30004", "h-old", True, None, "0,1"),       # finger 1 deleted since
        ])
        users = [_user(30001, "M0", "100"), _user(30002, "M1", "101"),
                 _user(30003, "M2", "102"), _user(30004, "M3", "103", fps=[_tpl(0)])]
        drv, w = _setup(monkeypatch, term, users)
        try:
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
        finally:
            drv.disconnect()
        written = [str(c[2]) for c in term.calls if c[0] == "SSR_SetUserInfo"]
        assert written == ["30004", "30003", "30002"]
        assert ("SSR_DelUserTmpExt", 1, "30004", 1) in term.calls


# ═════════════════════════ driver contract ═════════════════════════

class TestDriverBetweenChunks:

    def _roster(self, n, first=30001):
        return [{"pin": str(first + i), "name": f"M{i}", "card": str(100 + i)} for i in range(n)]

    def test_called_between_chunks_only(self):
        term = TerminalZkem()
        drv = _make_driver(term)
        seen = []
        try:
            drv.push_roster(self._roster(25), {}, between_chunks=lambda: seen.append(len(term.users)))
        finally:
            drv.disconnect()
        assert seen == [10, 20], "never before the first chunk, never after the last"

    def test_never_in_bracket_mode(self):
        term = TerminalZkem()
        drv = _make_driver(term)
        seen = []
        try:
            drv.push_roster(self._roster(25), {}, bracket_enable_device=True,
                            between_chunks=lambda: seen.append(1))
        finally:
            drv.disconnect()
        assert seen == []

    def test_superseded_pins_are_dropped_from_the_chunks_not_yet_sent(self):
        term = TerminalZkem()
        drv = _make_driver(term)
        calls = iter([{"30015", "30003"}])
        try:
            res = drv.push_roster(self._roster(25), {}, between_chunks=lambda: next(calls, None))
        finally:
            drv.disconnect()
        assert "30015" not in term.users
        assert "30003" in term.users, "already written before the update: untouched"
        assert res["superseded_pins"] == ["30015"]
        assert "30015" not in res["failed_pins"] and res["ok"] is True
        assert res["pushed"] == 24

    def test_a_chunk_emptied_by_supersession_is_not_sent(self):
        term = TerminalZkem()
        drv = _make_driver(term)
        try:
            res = drv.push_roster(self._roster(11), {}, between_chunks=lambda: {"30011"})
        finally:
            drv.disconnect()
        assert [c for c in term.calls if c[0] == "RefreshData"] == [("RefreshData", 1)], (
            "one chunk command, not two")
        assert res["superseded_pins"] == ["30011"] and res["ok"] is True

    def test_events_of_a_chunk_are_queued_before_the_hook_runs(self):
        term = HookedTerminal()
        drv = _make_driver(term)
        term.sink = drv._on_att_event
        term.on_user["30005"] = lambda: term.pending_punches.append(_punch("777"))
        got = []
        try:
            drv.push_roster(self._roster(25), {},
                            between_chunks=lambda: got.append(drv.poll_rtlog_once()))
        finally:
            drv.disconnect()
        assert len(got[0]) == 1, "the punch of chunk 1 is there when chunk 1 returns"

    def test_a_failing_hook_never_stops_the_push(self):
        term = TerminalZkem()
        drv = _make_driver(term)

        def boom():
            raise RuntimeError("hook failed")
        try:
            res = drv.push_roster(self._roster(25), {}, between_chunks=boom)
        finally:
            drv.disconnect()
        assert res["ok"] is True and len(term.users) == 25

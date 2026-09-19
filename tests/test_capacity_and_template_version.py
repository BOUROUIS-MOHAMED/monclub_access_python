"""P3a-2 item 7: capacity and template-version checks (MB2000).

Before P3a-2 the driver read the terminal's occupancy and fingerprint algorithm
version at connect time only, as diagnostics: push_roster wrote every user and every
template unconditionally, and a version disagreement was only noticed AFTER the
terminal refused a template -- never when it accepted an unusable one.

Now: before a push that needs a NEW user or fingerprint slot, the status is re-read
(read_capacity) and only the writes the terminal has no room for are refused with
CAPACITY_FULL: a member certainly not on the terminal when no user slot is free (it
stays pending), and single fingers when no fingerprint slot is free (the member's
card and user row still land; the pin is recorded not in sync). Updates, replacements
and removals are never refused, and a vacated slot counts as free (review round 1). A
template whose algorithm version differs from the terminal's is not uploaded (its slot
is left as it was) and TEMPLATE_VERSION_MISMATCH is reported. An unreadable status or
version gates nothing. The zkemkeeper guide (§8) records that on the 2026-08-30 field
run neither was the cause of the refusals then seen: this is a new rail, not a
re-litigation.

Real driver + real STA thread over a stateful fake terminal; real temp SQLite.
"""
from __future__ import annotations

import pytest

import app.core.db as dbmod
import app.core.telemetry as tel
from tests.fake_terminal import TerminalZkem
from tests.test_standalone_incremental_sync import _make_driver, _tpl, _user, _worker


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "capacity.db"), raising=False)
    dbmod.init_db()
    yield dbmod
    dbmod._shutdown_db_writer_for_tests()


@pytest.fixture
def warns(monkeypatch):
    seen: list[tuple[str, dict]] = []
    monkeypatch.setattr(tel, "warn", lambda name, **f: seen.append((name, f)))
    return seen


def _named(warns, name):
    return [f for n, f in warns if n == name]


# ═════════════════════════ driver ═════════════════════════

class TestDriver:

    def test_read_capacity_reads_the_live_status(self):
        term = TerminalZkem()
        term.status = {11: 7, 10: 0}
        term.fp_version = "10"
        drv = _make_driver(term)
        try:
            cap = drv.read_capacity()
        finally:
            drv.disconnect()
        assert cap == {"ok": True, "users_free": 7, "fingerprints_free": 0, "fp_version": "10"}

    def test_an_unreadable_status_is_none_never_a_guess(self):
        term = TerminalZkem()
        drv = _make_driver(term)
        try:
            cap = drv.read_capacity()
        finally:
            drv.disconnect()
        assert cap["ok"] is True and cap["users_free"] is None and cap["fingerprints_free"] is None

    def test_a_template_of_another_version_is_not_uploaded(self, warns):
        term = TerminalZkem()
        term.fp_version = "10"
        term.add_user("117", "A", "1", fingers=(1,))
        drv = _make_driver(term)
        try:
            res = drv.push_roster([{"pin": "117", "name": "A", "card": "1"}],
                                  {"117": [_tpl(0, "AAAA", ver=10), _tpl(1, "BBBB", ver=9)]})
        finally:
            drv.disconnect()
        writes = [c for c in term.calls if c[0] == "SetUserTmpExStr"]
        assert [c[3] for c in writes] == [0], "the v9 template is never written"
        assert ("SSR_DelUserTmpExt", 1, "117", 1) not in term.calls, (
            "nor is its slot cleared: whatever was there stays")
        assert term.fingers_of("117") == {0, 1}
        assert res["ok"] is False and res["failed_pins"] == ["117"]
        [mm] = _named(warns, "TEMPLATE_VERSION_MISMATCH")
        assert mm["skipped"] == 1 and mm["device_fp_version"] == "10"

    @pytest.mark.parametrize("device_version", ["", "garbage"])
    def test_an_unreadable_device_version_gates_nothing(self, device_version, warns):
        term = TerminalZkem()
        term.fp_version = device_version
        drv = _make_driver(term)
        try:
            res = drv.push_roster([{"pin": "117", "name": "A", "card": "1"}],
                                  {"117": [_tpl(0, "AAAA", ver=9)]})
        finally:
            drv.disconnect()
        assert res["ok"] is True and term.fingers_of("117") == {0}
        assert _named(warns, "TEMPLATE_VERSION_MISMATCH") == []


# ═════════════════════════ engine admission ═════════════════════════

class TestCapacityAdmission:

    def _run(self, db, monkeypatch, term, users):
        drv = _make_driver(term)
        w, _c = _worker(monkeypatch, driver=drv, users=users)
        try:
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
        finally:
            drv.disconnect()
        return w

    def test_no_free_user_slot_refuses_new_pins_but_updates_an_owned_one(
            self, db, monkeypatch, warns):
        term = TerminalZkem()
        term.status = {11: 0, 10: 50}
        term.add_user("30001", "Old name", "1")
        db.save_device_sync_state_batch(device_id=9, rows=[("30001", "h-old", True, None, "")])
        users = [_user(30001, "New name", "1"), _user(30002, "B", "2"), _user(30003, "C", "3")]
        w = self._run(db, monkeypatch, term, users)
        assert term.users["30001"]["name"] == "New name", "an existing user needs no new slot"
        assert "30002" not in term.users and "30003" not in term.users
        [cf] = _named(warns, "CAPACITY_FULL")
        assert cf["users_free"] == 0 and cf["skipped"] == 2
        kw = w._on_full_sync_finished.call_args.kwargs
        assert kw["ok"] is True and kw["fingerprint_hash"] is None, (
            "not stamped in sync: the refused pins are retried by a later pass")
        state = db.list_device_sync_hashes_and_status(device_id=9)
        assert "30002" not in state and "30003" not in state, "still pending, nothing recorded"
        assert "CAPACITY_FULL=2" in (w._push_batch_updates[-1].get("error_message") or "")

    def test_the_free_count_is_a_budget(self, db, monkeypatch, warns):
        term = TerminalZkem()
        term.status = {11: 1, 10: 50}
        users = [_user(30001, "A", "1"), _user(30002, "B", "2")]
        self._run(db, monkeypatch, term, users)
        assert set(term.users) == {"30001"}

    def test_no_free_fingerprint_slot_refuses_a_new_finger_not_a_replacement(
            self, db, monkeypatch, warns):
        term = TerminalZkem()
        term.status = {11: 50, 10: 0}
        term.add_user("30001", "A", "1", fingers=(0,))
        db.save_device_sync_state_batch(device_id=9, rows=[("30001", "h-old", True, None, "0")])
        term.add_user("30002", "B", "2", fingers=(0,))
        db.save_device_sync_state_batch(device_id=9, rows=[("30002", "h-old", True, None, "0")])
        users = [_user(30001, "A", "1", fps=[_tpl(0, "NEWT")]),          # replaces finger 0
                 _user(30002, "B", "2", fps=[_tpl(0, "AAAA"), _tpl(1, "BBBB")]),  # adds finger 1
                 _user(30003, "C", "3")]                                   # new, no finger
        self._run(db, monkeypatch, term, users)
        written = {(c[2], c[3]) for c in term.calls if c[0] == "SetUserTmpExStr"}
        assert ("30001", 0) in written
        assert ("30002", 1) not in written, "a finger needing a new slot is refused"
        assert "30003" in term.users, "a user with no finger needs no fingerprint slot"

    def test_removals_still_run_when_the_terminal_is_full(self, db, monkeypatch, warns):
        term = TerminalZkem()
        term.status = {11: 0, 10: 0}
        term.add_user("34439", "Gone", "9")
        db.save_device_sync_state_batch(device_id=9, rows=[("34439", "h-old", True, None, "")])
        self._run(db, monkeypatch, term, [_user(30002, "B", "2")])
        assert "34439" not in term.users, "removals are what free space"

    def test_an_unreadable_status_gates_nothing(self, db, monkeypatch, warns):
        term = TerminalZkem()
        self._run(db, monkeypatch, term, [_user(30002, "B", "2")])
        assert "30002" in term.users and _named(warns, "CAPACITY_FULL") == []

    def test_a_targeted_push_into_a_full_terminal_is_deferred(self, db, monkeypatch, warns):
        term = TerminalZkem()
        term.status = {11: 0}
        drv = _make_driver(term)
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30002, "B", "2")])
        try:
            w._run_standalone_member_sync(30002)
        finally:
            drv.disconnect()
        assert "30002" not in term.users
        assert _named(warns, "CAPACITY_FULL")


# ═══════════════ review round 1: refuse the FINGER, never the member ═══════════════

class TestFingerLevelRefusal:
    """R1-10/11/17/29. The first version refused a whole pin when fingerprint slots
    were short, so a new member got no card either (they could not enter at all --
    base wrote the card and let the terminal refuse only the templates), and an owned
    member's vacated finger was never cleared. Only a write that needs a new slot is
    refused, and only that write."""

    def _run(self, db, monkeypatch, term, users):
        drv = _make_driver(term)
        w, _c = _worker(monkeypatch, driver=drv, users=users)
        try:
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
        finally:
            drv.disconnect()
        return w

    def test_a_new_member_gets_the_card_when_only_fingerprint_slots_are_short(
            self, db, monkeypatch, warns):
        term = TerminalZkem()
        term.status = {11: 500, 10: 0}
        w = self._run(db, monkeypatch, term,
                      [_user(30002, "B", "2", fps=[_tpl(0, "AAAA"), _tpl(1, "BBBB")])])
        assert term.users["30002"]["card"] == "2", "the card lands: the member can enter"
        assert term.fingers_of("30002") == set(), "no fingerprint slot free: none written"
        state = db.list_device_sync_hashes_and_status(device_id=9)
        assert state["30002"][1] is False, "not in sync: the fingers are retried later"
        [cf] = _named(warns, "CAPACITY_FULL")
        assert cf["withheld_fingers"] == 2 and cf["skipped"] == 0
        kw = w._on_full_sync_finished.call_args.kwargs
        assert kw["ok"] is True and kw["fingerprint_hash"] is None

    def test_a_vacated_slot_is_cleared_and_frees_room_for_the_new_finger(
            self, db, monkeypatch, warns):
        term = TerminalZkem()
        term.status = {11: 500, 10: 0}
        term.add_user("30002", "B", "2", fingers=(0, 3))
        db.save_device_sync_state_batch(device_id=9, rows=[("30002", "h-old", True, None, "0,3")])
        self._run(db, monkeypatch, term,
                  [_user(30002, "B", "2", fps=[_tpl(0, "AAAA"), _tpl(5, "FFFF")])])
        assert ("SSR_DelUserTmpExt", 1, "30002", 3) in term.calls, "the deleted finger is cleared"
        assert term.fingers_of("30002") == {0, 5}, "the cleared slot made room for finger 5"
        assert _named(warns, "CAPACITY_FULL") == []

    def test_a_card_change_lands_although_a_new_finger_does_not(self, db, monkeypatch, warns):
        term = TerminalZkem()
        term.status = {11: 500, 10: 0}
        term.add_user("30002", "B", "111", fingers=(0,))
        db.save_device_sync_state_batch(device_id=9, rows=[("30002", "h-old", True, None, "0")])
        self._run(db, monkeypatch, term,
                  [_user(30002, "B", "222", fps=[_tpl(0, "AAAA"), _tpl(1, "BBBB")])])
        assert term.users["30002"]["card"] == "222", "a lost card stops working"
        assert term.fingers_of("30002") == {0}

    def test_a_pin_already_written_but_unconfirmed_is_not_a_new_user(
            self, db, monkeypatch, warns):
        # A crash after the write: an intent, no state row. The terminal holds the user;
        # an update needs no new user slot, so a full user table does not block it.
        term = TerminalZkem()
        term.status = {11: 0, 10: 50}
        term.add_user("30002", "B", "111")
        db.record_push_intents(device_id=9, rows=[("30002", "B", "111", "h")],
                               protocol="ZK_STANDALONE")
        drv = _make_driver(term)
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30002, "B", "222")])
        monkeypatch.setattr(w, "_member_row_in_db", lambda m: [_user(30002, "B", "222")])
        try:
            w._run_standalone_member_sync(30002)
        finally:
            drv.disconnect()
        assert term.users["30002"]["card"] == "222"

    def test_a_refused_targeted_push_leaves_the_intent_as_it_was(self, db, monkeypatch, warns):
        term = TerminalZkem()
        term.status = {11: 0}
        drv = _make_driver(term)
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30002, "B", "2")])
        monkeypatch.setattr(w, "_member_row_in_db", lambda m: [_user(30002, "B", "2")])
        try:
            w._run_standalone_member_sync(30002)
        finally:
            drv.disconnect()
        assert "30002" not in term.users
        assert db.get_push_intent(device_id=9, pin="30002") is None, (
            "nothing was written, so nothing is claimed")

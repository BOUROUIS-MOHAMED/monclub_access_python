"""P3a-2 review round 1 (R1-14, R1-26): a member MonClub wrote is MonClub's, even if a
finger then failed.

Before: ``ownership_confirmed`` was set only by a push the engine recorded ok=1. On
the MB2000 the user row and card are written first (``SSR_SetUserInfo``) and the
fingerprints after, so a refused template -- or one TEMPLATE_VERSION_MISMATCH now
skips on every push -- left a member who could badge in with ownership 0. On
departure the revoke found the pin "not owned": SKIPPED_NOT_OWNED, final, nothing
deleted, and the member kept entering until the next day's intent read-back (or for
good, if that read-back did not match).

Now the driver names every pin whose user row the terminal ACCEPTED
(``user_written``), and the engine records those as owned even when the push is not
confirmed (last_ok stays 0, so the fingers are retried). A refused user row, a wedged
chunk or an unsent member confers nothing.

Real driver + real STA thread over the stateful fake terminal; real temp SQLite.
"""
from __future__ import annotations

import pytest

import app.core.db as dbmod
from tests.fake_terminal import TerminalZkem
from tests.test_standalone_incremental_sync import _make_driver, _tpl, _user, _worker


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "owner.db"), raising=False)
    dbmod.init_db()
    yield dbmod
    dbmod._shutdown_db_writer_for_tests()


def _roster(*pins):
    return [{"pin": str(p), "name": f"M{p}", "card": str(p)} for p in pins]


class TestDriver:

    def test_the_result_names_every_pin_whose_user_row_landed(self):
        term = TerminalZkem()
        term.settmp_ok = False
        drv = _make_driver(term)
        try:
            res = drv.push_roster(_roster(117, 118), {"117": [_tpl(0, "AAAA")]})
        finally:
            drv.disconnect()
        assert res["failed_pins"] == ["117"], "its finger was refused"
        assert res["user_written"] == ["117", "118"], "both user rows were accepted"

    def test_a_refused_user_row_is_not_named(self):
        term = TerminalZkem()
        term.setuserinfo_ok = False
        drv = _make_driver(term)
        try:
            res = drv.push_roster(_roster(117), {})
        finally:
            drv.disconnect()
        assert res["user_written"] == []


class TestOwnership:

    def _push_then_revoke(self, db, monkeypatch, term, user):
        drv = _make_driver(term)
        w, _c = _worker(monkeypatch, driver=drv, users=[user])
        try:
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
            owned = set(db.list_confirmed_device_sync_pins(device_id=9))
            state = db.list_device_sync_hashes_and_status(device_id=9)
            intent = db.get_push_intent(device_id=9, pin="30002")
            revoked = w._run_standalone_member_revoke(30002)
        finally:
            drv.disconnect()
        return owned, state, intent, revoked

    def test_a_member_whose_finger_was_refused_is_owned_and_removed_on_departure(
            self, db, monkeypatch):
        term = TerminalZkem()
        term.settmp_ok = False
        owned, state, intent, revoked = self._push_then_revoke(
            db, monkeypatch, term, _user(30002, "B", "2", fps=[_tpl(0, "AAAA")]))
        assert state["30002"][1] is False, "not in sync: the finger is retried"
        assert "30002" in owned, "the terminal accepted MonClub's user row"
        assert intent is None, "ownership settles the write-ahead intent"
        assert revoked is True and "30002" not in term.users, "the departure removes it"

    def test_a_template_of_another_version_does_not_cost_the_member_its_ownership(
            self, db, monkeypatch):
        term = TerminalZkem()
        term.fp_version = "10"
        owned, state, _intent, revoked = self._push_then_revoke(
            db, monkeypatch, term, _user(30002, "B", "2", fps=[_tpl(0, "AAAA", ver=9)]))
        assert state["30002"][1] is False
        assert "30002" in owned
        assert revoked is True and "30002" not in term.users

    def test_a_refused_user_row_confers_nothing(self, db, monkeypatch):
        term = TerminalZkem()
        term.setuserinfo_ok = False
        drv = _make_driver(term)
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30002, "B", "2")])
        try:
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
        finally:
            drv.disconnect()
        assert "30002" not in set(db.list_confirmed_device_sync_pins(device_id=9))
        assert db.get_push_intent(device_id=9, pin="30002") is not None, (
            "the intent stays: nothing proves what (if anything) landed")


class TestStateRow:

    def test_the_sixth_field_confers_ownership_without_confirming_the_push(self, db):
        db.record_push_intents(device_id=9, rows=[("41", "A", "1", "h")], protocol="ZK_STANDALONE")
        db.save_device_sync_state_batch(device_id=9, rows=[("41", "h", False, "refused", None, True)])
        assert db.list_device_sync_hashes_and_status(device_id=9)["41"][1] is False
        assert "41" in set(db.list_confirmed_device_sync_pins(device_id=9))
        assert db.get_push_intent(device_id=9, pin="41") is None

    def test_five_field_rows_are_unchanged(self, db):
        db.save_device_sync_state_batch(device_id=9, rows=[("41", "h", False, "refused", None)])
        assert "41" not in set(db.list_confirmed_device_sync_pins(device_id=9))

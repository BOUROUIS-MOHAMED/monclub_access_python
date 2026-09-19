"""P3a-2 item 3: write-ahead ownership. A crash mid-push must never leave a member on
the turnstile that MonClub cannot later prove it owns and remove.

Before P3a-2 ownership (``device_sync_state.ownership_confirmed``) was written once
per roster, after ``push_roster`` returned. A power cut after chunk 40 of 93 -- the
PC boots around opening and most gyms cut the power overnight -- left ~400 members on
the terminal with no row: the revoke pass only removes owned pins, so once any of them
left the roster they kept opening the door, forever.

Now: an intent row is committed durably (synchronous=FULL) BEFORE the first device
write of a push; results are recorded per chunk; a read-back that finds exactly the
name and card MonClub wrote at an intent pin turns it into ownership, and the revoke
pass removes it. A foreign user at that pin (different name/card) is never promoted.

Real driver + real STA thread over a stateful fake terminal; real temp SQLite; the
installed database is never opened.
"""
from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

import app.core.db as dbmod
import app.core.telemetry as tel
import app.core.ultra_engine as ue
from tests.fake_terminal import TerminalZkem
from tests.test_standalone_incremental_sync import _make_driver, _user, _worker


class PowerCut(BaseException):
    """The process dies: nothing after this point runs, no `except Exception` catches it."""


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "write-ahead.db"), raising=False)
    dbmod.init_db()
    yield dbmod
    dbmod._shutdown_db_writer_for_tests()


@pytest.fixture
def warns(monkeypatch):
    seen: list[tuple[str, dict]] = []
    monkeypatch.setattr(tel, "warn", lambda name, **f: seen.append((name, f)))
    return seen


def _members(n: int, start: int = 30001) -> List[dict]:
    return [_user(start + i, f"Member {i}", str(900000 + i)) for i in range(n)]


def _cut_after_chunk(drv, monkeypatch, n: int):
    """The terminal ACCEPTS chunk n, then the PC loses power before anything records it."""
    real_call = drv._call
    state = {"k": 0}

    def _call(op, args=None, timeout=None):
        res = real_call(op, args=args, timeout=timeout) if timeout else real_call(op, args=args)
        if op == "push_roster":
            state["k"] += 1
            if state["k"] == n:
                raise PowerCut()
        return res

    monkeypatch.setattr(drv, "_call", _call)


def _reboot(db):
    db._shutdown_db_writer_for_tests()
    db.init_db()                       # runs the every-start ownership migration


def _pins_of(users) -> set:
    return {str(u["activeMembershipId"]) for u in users}


class TestACrashMidPushLeavesNothingUnprovable:

    def test_every_member_on_the_terminal_is_owned_or_intended(self, db, monkeypatch):
        term = TerminalZkem()
        term.add_user("777", "OTHER SYS", "5555", fingers=(0,))     # another system's user
        drv = _make_driver(term)
        users = _members(45)                                         # chunks of 10
        w, _c = _worker(monkeypatch, driver=drv, users=users)
        _cut_after_chunk(drv, monkeypatch, 2)
        try:
            with pytest.raises(PowerCut):
                w._run_standalone_full_sync(reason="startup", fingerprint_hash="h")
        finally:
            drv.disconnect()
        _reboot(db)

        on_terminal = set(term.users) - {"777"}
        owned = db.list_confirmed_device_sync_pins(device_id=9)
        intents = set(db.list_push_intents(device_id=9))
        assert len(on_terminal) == 20, "chunks 1 and 2 reached the terminal"
        assert on_terminal <= owned | intents, (
            "a member on the terminal that MonClub can neither prove nor retract is the defect")
        chunk1 = {str(30001 + i) for i in range(10)}
        chunk2 = {str(30011 + i) for i in range(10)}
        assert chunk1 <= owned, "recorded per chunk: chunk 1 was confirmed before the cut"
        assert chunk2 <= intents and not chunk2 & owned, "chunk 2 landed but was never confirmed"
        assert "777" not in owned | intents, "a foreign user is never MonClub's"

    def test_the_intent_is_committed_before_the_first_device_write(self, db, monkeypatch):
        term = TerminalZkem()
        drv = _make_driver(term)
        w, _c = _worker(monkeypatch, driver=drv, users=_members(3))
        seen_at_first_write = {}
        real = term.SSR_SetUserInfo

        def _spy(machine, pin, *rest):
            if not seen_at_first_write:
                seen_at_first_write.update(db.list_push_intents(device_id=9))
            return real(machine, pin, *rest)

        term.SSR_SetUserInfo = _spy
        try:
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
        finally:
            drv.disconnect()
        assert set(seen_at_first_write) == {"30001", "30002", "30003"}
        assert seen_at_first_write["30001"]["name"] == "Member 0"
        assert seen_at_first_write["30001"]["card"] == "900000"
        assert db.list_push_intents(device_id=9) == {}, "all confirmed: every intent resolved"
        assert db.list_confirmed_device_sync_pins(device_id=9) == {"30001", "30002", "30003"}

    def test_no_intent_no_push(self, db, monkeypatch):
        term = TerminalZkem()
        drv = _make_driver(term)
        w, _c = _worker(monkeypatch, driver=drv, users=_members(3))
        monkeypatch.setattr(dbmod, "record_push_intents",
                            MagicMock(side_effect=RuntimeError("disk full")))
        try:
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
        finally:
            drv.disconnect()
        assert term.users == {}, "a write MonClub could not first record must not happen"
        assert w._on_full_sync_finished.call_args.kwargs["ok"] is False

    def test_a_refused_template_leaves_an_owned_member_not_an_orphan(self, db, monkeypatch):
        """No crash needed: the row lands, the finger is refused, the pin is 'failed' --
        before P3a-2 that member was on the terminal with no ownership at all.

        Review round 1 (R1-14/R1-26): it first left only an intent (settled by the next
        day's read-back, so a departure in between was SKIPPED_NOT_OWNED). The terminal
        accepted the user row, so the pin is now owned at once and the intent resolved."""
        term = TerminalZkem()
        term.settmp_ok = False
        drv = _make_driver(term)
        from tests.test_standalone_incremental_sync import _tpl
        users = [_user(30001, "Ali", "123", fps=[_tpl(0, "AAAA")])]
        w, _c = _worker(monkeypatch, driver=drv, users=users)
        try:
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h")
        finally:
            drv.disconnect()
        assert "30001" in term.users
        assert "30001" in set(db.list_confirmed_device_sync_pins(device_id=9))
        assert db.list_device_sync_hashes_and_status(device_id=9)["30001"][1] is False
        assert "30001" not in db.list_push_intents(device_id=9)


class TestReadBackPromotion:

    def _seed(self, db, rows):
        db.record_push_intents(device_id=9, rows=rows, protocol="ZK_STANDALONE")

    def test_match_promotes_absent_drops_foreign_is_kept(self, db, monkeypatch, warns):
        term = TerminalZkem()
        term.add_user("30011", "Member 10", "900010")               # ours, never confirmed
        term.add_user("777", "OTHER SYS", "5555")                   # foreign, same pin as intent
        drv = _make_driver(term)
        w, _c = _worker(monkeypatch, driver=drv, users=[])
        self._seed(db, [("30011", "Member 10", "900010", "h1"),
                        ("30099", "Gone", "1", "h2"),                # never reached the terminal
                        ("777", "Alice", "1", "h3")])                # our write never landed
        try:
            res = w._promote_intents_by_readback(desired_pins=set())
        finally:
            drv.disconnect()
        assert res == {"promoted": ["30011"], "dropped": ["30099"], "mismatched": ["777"]}
        assert db.list_confirmed_device_sync_pins(device_id=9) == {"30011"}
        left = db.list_push_intents(device_id=9)
        assert set(left) == {"777"} and left["777"]["readback_misses"] == 1

    def test_a_failed_listing_changes_nothing(self, db, monkeypatch):
        term = TerminalZkem()
        term.readall_ok = False
        drv = _make_driver(term)
        w, _c = _worker(monkeypatch, driver=drv, users=[])
        self._seed(db, [("30011", "Member 10", "900010", "h1")])
        try:
            res = w._promote_intents_by_readback(desired_pins=set())
        finally:
            drv.disconnect()
        assert res is None
        assert set(db.list_push_intents(device_id=9)) == {"30011"}
        assert db.list_confirmed_device_sync_pins(device_id=9) == set()

    def test_still_desired_intent_pins_are_not_read_back(self, db, monkeypatch):
        """They are confirmed by the next ordinary push; no enumeration is spent on them."""
        term = TerminalZkem()
        drv = _make_driver(term)
        w, _c = _worker(monkeypatch, driver=drv, users=[])
        self._seed(db, [("30011", "Member 10", "900010", "h1")])
        try:
            assert w._promote_intents_by_readback(desired_pins={"30011"}) is None
        finally:
            drv.disconnect()
        assert not any(c[0] == "ReadAllUserID" for c in term.calls)

    def test_end_to_end_the_crashed_member_who_left_is_removed(self, db, monkeypatch):
        term = TerminalZkem()
        term.add_user("777", "OTHER SYS", "5555")
        drv = _make_driver(term)
        users = _members(25)
        w, cache = _worker(monkeypatch, driver=drv, users=users)
        _cut_after_chunk(drv, monkeypatch, 2)
        with pytest.raises(PowerCut):
            w._run_standalone_full_sync(reason="startup", fingerprint_hash="h")
        _reboot(db)
        monkeypatch.setattr(drv, "_call", type(drv)._call.__get__(drv))  # power is back
        # Overnight member 30015 (chunk 2: on the terminal, never confirmed) expired.
        cache.users[:] = [u for u in users if u["activeMembershipId"] != 30015]
        try:
            w._run_standalone_full_sync(reason="startup", fingerprint_hash="h2")
            assert "30015" in term.users, "not owned yet: the ordinary revoke pass cannot touch it"
            res = w._promote_intents_by_readback(
                desired_pins={str(u["activeMembershipId"]) for u in cache.users})
            assert res and res["promoted"] == ["30015"]
            w._run_standalone_full_sync(reason="timer", fingerprint_hash="h3")
        finally:
            drv.disconnect()
        assert "30015" not in term.users, "proven ours, departed: removed"
        assert "777" in term.users, "the foreign user is untouched"


# ═════════════════════════ PullSDK (gym 58's C3-400s) ═════════════════════════

from tests.test_account_pin_device_sites import (  # noqa: E402,F401  (fixture)
    _deleted_pins, _engine, _member, _pullsdk_device, _removed_pins, _sdk, _written_pins,
    sqlite_db,
)


def _c3(**kw):
    d = _pullsdk_device(pinScheme="", pushingToDevicePolicy="1")
    d.update(kw)
    return d


def _panel_sdk(panel: Dict[str, str]):
    """A MagicMock PullSDK whose user-table reads answer from ``panel`` {pin: card}."""
    sdk = _sdk(list(panel))

    def _rows(*, table, fields="", filter_expr="", options="", initial_size=None):
        want = str(filter_expr or "").replace(" ", "")
        out = []
        for pin, card in panel.items():
            if want and want != f"Pin={pin}":
                continue
            row = {"Pin": pin}
            if "CardNo" in str(fields):
                row["CardNo"] = card
            out.append(row)
        return out

    sdk.get_device_data_rows.side_effect = _rows
    return sdk


def _c3_users(*ams):
    return [_member(am, 9000 + am, None, f"M{am}", card=str(100000 + am)) for am in ams]


class TestPullSdkWriteAhead:

    def test_intents_are_durable_before_phase_a(self, sqlite_db):
        users = _c3_users(*range(101, 111))
        sdk = _panel_sdk({})
        sdk.set_device_data_batch.side_effect = PowerCut()
        with patch("app.core.device_sync.PullSDK", MagicMock(return_value=sdk)):
            with pytest.raises(PowerCut):
                _engine()._sync_one_device(device=_c3(), users=users, local_fp_index={},
                                           default_door_id=1, changed_ids=None)
        _reboot(sqlite_db)
        intents = sqlite_db.list_push_intents(device_id=1)
        assert set(intents) == {str(a) for a in range(101, 111)}
        assert intents["101"]["card"] == "100101" and intents["101"]["protocol"] == "ZK_PULLSDK"
        assert sqlite_db.list_confirmed_device_sync_pins(device_id=1) == set()

    def test_a_confirmed_pass_leaves_no_intent(self, sqlite_db):
        sdk = _panel_sdk({})
        sdk.set_device_data_batch.side_effect = lambda *, table, rows, chunk_size, progress_cb=None: (len(rows), [])
        with patch("app.core.device_sync.PullSDK", MagicMock(return_value=sdk)):
            _engine()._sync_one_device(device=_c3(), users=_c3_users(*range(101, 111)),
                                       local_fp_index={}, default_door_id=1, changed_ids=None)
        assert sqlite_db.list_push_intents(device_id=1) == {}
        assert len(sqlite_db.list_confirmed_device_sync_pins(device_id=1)) == 10

    def test_the_full_sync_proves_and_removes_a_crashed_member_who_left(self, sqlite_db):
        sqlite_db.record_push_intents(
            device_id=1, protocol="ZK_PULLSDK",
            rows=[("150", "M150", "100150", "h"),      # written, never confirmed, member left
                  ("151", "M151", "100151", "h"),      # never reached the panel
                  ("152", "M152", "100152", "h")])     # a DIFFERENT user holds 152
        panel = {"101": "100101", "150": "100150", "152": "999"}
        sdk = _panel_sdk(panel)
        with patch("app.core.device_sync.PullSDK", MagicMock(return_value=sdk)):
            _engine()._sync_one_device(device=_c3(), users=_c3_users(101), local_fp_index={},
                                       default_door_id=1, changed_ids=None)
        assert "150" in _removed_pins(sdk), "proven MonClub's by its card, departed: removed"
        assert "152" not in _deleted_pins(sdk), "a foreign card at the pin: never touched"
        left = sqlite_db.list_push_intents(device_id=1)
        assert "151" not in left, "absent from the panel: the intent is moot"
        assert left["152"]["readback_misses"] == 1

    def test_a_targeted_revoke_of_an_intent_only_pin_proves_then_deletes(self, sqlite_db):
        from tests.test_account_pin_device_sites import _cache, _sonia, _ali_gym
        _cache(sqlite_db, [_ali_gym(), _sonia()])
        _cache(sqlite_db, [], valid_ids=[31000])                    # Sonia (pin 5) revoked
        sqlite_db.record_push_intents(device_id=1, protocol="ZK_PULLSDK",
                                      rows=[("5", "Sonia", "1901", "h")])
        sdk = _panel_sdk({"5": "1901"})
        eng = _engine()
        assert eng.sync_member_on_connected_sdk(
            sdk=sdk, device=_pullsdk_device(), member_id=5, revocation=True) is True
        assert _removed_pins(sdk) == {"5"}

    def test_a_targeted_revoke_never_promotes_a_different_card(self, sqlite_db):
        from tests.test_account_pin_device_sites import _cache, _sonia, _ali_gym
        _cache(sqlite_db, [_ali_gym(), _sonia()])
        _cache(sqlite_db, [], valid_ids=[31000])
        sqlite_db.record_push_intents(device_id=1, protocol="ZK_PULLSDK",
                                      rows=[("5", "Sonia", "1901", "h")])
        sdk = _panel_sdk({"5": "4242"})
        eng = _engine()
        assert eng.sync_member_on_connected_sdk(
            sdk=sdk, device=_pullsdk_device(), member_id=5, revocation=True) is False
        assert eng._last_member_sync_outcome == "SKIPPED_NOT_OWNED"
        assert _deleted_pins(sdk) == []


class TestPullSdkProofReviewRoundOne:
    """R1-12/R1-30: a read that FAILED, or answered nothing, is not proof of absence."""

    def _revoked_sonia(self, sqlite_db):
        from tests.test_account_pin_device_sites import _cache, _sonia, _ali_gym
        _cache(sqlite_db, [_ali_gym(), _sonia()])
        _cache(sqlite_db, [], valid_ids=[31000])                    # Sonia (pin 5) revoked
        sqlite_db.record_push_intents(device_id=1, protocol="ZK_PULLSDK",
                                      rows=[("5", "Sonia", "1901", "h")])

    def test_a_failed_panel_read_during_the_proof_is_retried_not_final(self, sqlite_db):
        self._revoked_sonia(sqlite_db)
        sdk = _panel_sdk({"5": "1901"})
        sdk.get_device_data_rows.side_effect = RuntimeError("GetDeviceData rc=-2")
        eng = _engine()
        assert eng.sync_member_on_connected_sdk(
            sdk=sdk, device=_pullsdk_device(), member_id=5, revocation=True) is False
        assert eng._last_member_sync_outcome == "OWNERSHIP_UNREADABLE", (
            "a SKIPPED_NOT_OWNED here is final: the member kept the card for good")
        assert "5" in sqlite_db.list_push_intents(device_id=1)

    def test_an_empty_answer_to_the_one_pin_read_keeps_the_intent(self, sqlite_db):
        self._revoked_sonia(sqlite_db)
        sdk = _panel_sdk({})
        eng = _engine()
        assert eng.sync_member_on_connected_sdk(
            sdk=sdk, device=_pullsdk_device(), member_id=5, revocation=True) is False
        assert _deleted_pins(sdk) == []
        assert "5" in sqlite_db.list_push_intents(device_id=1), (
            "the full sync's whole-table read settles it, not an empty one-pin answer")

    def test_an_empty_full_read_drops_no_intent(self, sqlite_db):
        sqlite_db.record_push_intents(device_id=1, protocol="ZK_PULLSDK",
                                      rows=[("150", "M150", "100150", "h")])
        sdk = _panel_sdk({})
        with patch("app.core.device_sync.PullSDK", MagicMock(return_value=sdk)):
            _engine()._sync_one_device(device=_c3(), users=_c3_users(101), local_fp_index={},
                                       default_door_id=1, changed_ids=None)
        assert "150" in sqlite_db.list_push_intents(device_id=1)

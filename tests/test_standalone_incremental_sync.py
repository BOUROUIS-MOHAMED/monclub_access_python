"""Incremental standalone (zkemkeeper / MB2000) sync — per-pin state in device_sync_state.

FIELD INCIDENTS THIS PINS
-------------------------
* v1.4.26 (2026-08-30): every full sync re-sent the whole roster — 928 members,
  419 s on the OXYGENE_FIT MB2000 — because ``push_roster`` has no diff and the
  engine gave it everything, every time.
* v1.4.28 (2026-08-31, operator report): "after a success enrolment the access
  pushes the full list". Mechanism: the post-enrolment targeted member sync is
  correct, but it never updated the scheduler's roster-hash baseline (``_last_hash``
  is only set when a FULL sync finishes), so the next hash evaluation concluded
  "roster changed" and queued that 7-minute push for one new fingerprint.

The PullSDK path already solves this with ``device_sync_state`` (one desired_hash
per (device, pin); skip when unchanged). These tests pin that the standalone path
now does the same — and, above all, the SAFETY DIRECTIONS:

* a state READ failure => push everything (never skip a pin because a lookup broke);
* a driver that cannot say which pins failed => every attempted pin is unconfirmed;
* MIRROR always receives the FULL desired roster, never the incremental subset
  (passing the subset would delete every unchanged member off a live turnstile);
* bracketed syncs (user-sync / daily-forced-sync / hard-reset) keep pushing every
  pin — their semantics are unchanged.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

import app.core.db as dbmod
import app.core.ultra_engine as ue


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #

class FakeDriver:
    """push_roster that records calls and can report per-pin failures."""
    owns_event_source = True

    def __init__(self, *, ok: bool = True, failed_pins: List[str] | None = None,
                 report_failed_pins: bool = True):
        self.ok = ok
        self.failed_pins = failed_pins
        self.report_failed_pins = report_failed_pins
        self.push_calls: List[tuple] = []

    def push_roster(self, users, templates_by_pin=None, *, bracket_enable_device=False, **kw):
        self.push_calls.append((list(users), dict(templates_by_pin or {}), bracket_enable_device))
        pins = [str(u["pin"]) for u in users]
        removals = sum(
            len(v) for v in (kw.get("remove_fingers_by_pin") or {}).values()
        )
        if self.failed_pins is not None:
            failed = [p for p in self.failed_pins if p in pins]
            res: Dict[str, Any] = {
                "ok": not failed, "pushed": len(users), "failed": len(failed),
                "templates_failed": 0, "skipped_pin": 0, "chunks_wedged": 0,
                "errors": ["refused"] if failed else [],
                "del_attempted": removals, "del_ok": removals,
            }
            if self.report_failed_pins:
                res["failed_pins"] = failed
            return res
        res = {
            "ok": self.ok, "pushed": len(users), "failed": 0 if self.ok else len(users),
            "templates_failed": 0, "skipped_pin": 0, "chunks_wedged": 0,
            "errors": [] if self.ok else ["boom"],
            "del_attempted": removals, "del_ok": removals,
        }
        if self.report_failed_pins:
            res["failed_pins"] = [] if self.ok else pins
        return res


class FakeState:
    """In-memory device_sync_state with the REAL upsert semantics: an ok=False row
    keeps its previous desired_hash (see save_device_sync_state_batch)."""

    def __init__(self, *, raise_on_read: bool = False):
        self.rows: Dict[str, tuple] = {}     # pin -> (hash, ok)
        self.raise_on_read = raise_on_read
        self.save_calls: List[list] = []
        self.prune_calls: List[list] = []
        self.delete_calls: List[str] = []

    def list(self, *, device_id):
        if self.raise_on_read:
            raise RuntimeError("db unavailable")
        return dict(self.rows)

    def list_owned(self, *, device_id):
        if self.raise_on_read:
            raise RuntimeError("db unavailable")
        return {pin for pin, (_hash, ok) in self.rows.items() if ok}

    def save_batch(self, *, device_id, rows):
        rows = list(rows)
        self.save_calls.append(rows)
        for row in rows:
            # Rows carry an optional 5th element (pushed_finger_ids) since the
            # finger-slot removal work; this fake only tracks (hash, ok), but it
            # must accept the wider tuple exactly as the real writer does.
            pin, h, ok = row[0], row[1], row[2]
            prev = self.rows.get(pin, ("", False))
            self.rows[pin] = ((h if ok else prev[0]), bool(ok))
        return len(rows)

    def prune(self, *, device_id, keep_pins):
        keep = {str(k) for k in keep_pins}
        self.prune_calls.append(sorted(keep))
        for p in [p for p in self.rows if p not in keep]:
            self.rows.pop(p)
        return 0

    def delete(self, *, device_id, pin):
        self.delete_calls.append(str(pin))
        self.rows.pop(str(pin), None)


def _tpl(fid: int = 0, data: str = "AAAA", ver: int = 10, size: int = 4) -> dict:
    return {"fingerId": fid, "templateVersion": ver, "templateData": data,
            "templateSize": size, "enabled": True}


def _user(am_id: int, name: str, card: str, fps: list | None = None) -> dict:
    return {"activeMembershipId": am_id, "userId": am_id * 10, "membershipId": 3,
            "fullName": name, "firstCardId": card, "fingerprints": list(fps or [])}


def _install_state(monkeypatch, st: FakeState) -> FakeState:
    monkeypatch.setattr(dbmod, "list_device_sync_hashes_and_status", st.list)
    monkeypatch.setattr(dbmod, "list_confirmed_device_sync_pins", st.list_owned)
    monkeypatch.setattr(dbmod, "save_device_sync_state_batch", st.save_batch)
    monkeypatch.setattr(dbmod, "prune_device_sync_state", st.prune)
    monkeypatch.setattr(dbmod, "delete_device_sync_state", st.delete)
    monkeypatch.setattr(dbmod, "clear_device_revocation_state", st.delete, raising=False)
    return st


@pytest.fixture
def state(monkeypatch) -> FakeState:
    return _install_state(monkeypatch, FakeState())


def _worker(monkeypatch, *, driver=None, users=None):
    """UltraDeviceWorker with only what the standalone sync drains touch."""
    w = ue.UltraDeviceWorker.__new__(ue.UltraDeviceWorker)
    w._device = {"id": 9, "name": "Entree 1"}
    w._device_id = 9
    w._device_name = "Entree 1"
    w._settings = {"fingerprint_enabled": True}
    w._cfg = None
    w._prefix = "[ULTRA:9]"
    w._tel_wid = "ULTRA:9"
    w._sdk = driver if driver is not None else FakeDriver()
    w._connected = True
    w._full_sync_lock = threading.Lock()
    w._pending_full_sync_request = None
    w._member_sync_lock = threading.Lock()
    w._pending_member_syncs = deque()
    w._pending_member_sync_ids = set()
    w._pending_member_revoke_ids = set()
    w._active_member_revoke_ids = set()
    w._confirmed_member_revoke_ids = set()
    w._full_sync_revocation_phase = {}
    w._wake_evt = threading.Event()
    w._active_sync_lock = threading.Lock()
    w._active_sync_engine = None
    w._on_full_sync_started = MagicMock()
    w._on_full_sync_finished = MagicMock()

    cache = SimpleNamespace(users=list(users or []))
    monkeypatch.setattr(ue, "load_sync_cache", lambda: cache)
    monkeypatch.setattr(ue, "insert_push_batch", MagicMock(return_value=1))
    w._push_batch_updates = []
    monkeypatch.setattr(ue, "update_push_batch", lambda **kw: w._push_batch_updates.append(kw))

    import app.core.device_sync as ds
    # local ZK9500 enrolment store is a real table; keep it out of these tests
    monkeypatch.setattr(ds.DeviceSyncEngine, "_build_local_fp_index_for_pins",
                        lambda self, *, pins, fingerprint_enabled: {}, raising=True)

    def _forbidden(*a, **k):
        raise AssertionError("ZK_STANDALONE device reached the PullSDK push path")
    monkeypatch.setattr(ds.DeviceSyncEngine, "run_one_device_on_connected_sdk", _forbidden, raising=True)
    monkeypatch.setattr(ds.DeviceSyncEngine, "sync_member_on_connected_sdk", _forbidden, raising=True)
    return w, cache


def _full_sync(w, *, reason="timer", fingerprint_hash="h1"):
    w.request_full_sync(reason=reason, fingerprint_hash=fingerprint_hash)
    assert w._drain_full_sync_commands(limit=1) == 1
    assert w._pending_full_sync_request is None, "full sync must always terminate"


def _pins(call) -> set:
    return {str(u["pin"]) for u in call[0]}


def _finished_kwargs(w) -> dict:
    return w._on_full_sync_finished.call_args.kwargs


# --------------------------------------------------------------------------- #
# The hash: exactly what the terminal is given, nothing it is not
# --------------------------------------------------------------------------- #

class TestPinHash:
    def test_name_is_cut_at_24_like_the_driver(self):
        base = {"pin": "1", "name": "A" * 24, "card": "1"}
        longer = {"pin": "1", "name": "A" * 24 + "TRAILING", "card": "1"}
        assert ue._standalone_pin_hash(base, []) == ue._standalone_pin_hash(longer, [])
        shorter = {"pin": "1", "name": "A" * 23 + "B", "card": "1"}
        assert ue._standalone_pin_hash(base, []) != ue._standalone_pin_hash(shorter, [])

    def test_card_is_digits_only_like_the_driver(self):
        a = {"pin": "1", "name": "n", "card": "12-34 56"}
        b = {"pin": "1", "name": "n", "card": "123456"}
        assert ue._standalone_pin_hash(a, []) == ue._standalone_pin_hash(b, [])
        c = {"pin": "1", "name": "n", "card": "123457"}
        assert ue._standalone_pin_hash(a, []) != ue._standalone_pin_hash(c, [])

    def test_template_order_does_not_matter(self):
        e = {"pin": "1", "name": "n", "card": "1"}
        t0, t1 = _tpl(0, "AAAA"), _tpl(1, "BBBB")
        assert ue._standalone_pin_hash(e, [t0, t1]) == ue._standalone_pin_hash(e, [t1, t0])

    def test_template_change_changes_the_hash(self):
        e = {"pin": "1", "name": "n", "card": "1"}
        assert ue._standalone_pin_hash(e, [_tpl(0, "AAAA")]) != ue._standalone_pin_hash(e, [_tpl(0, "AAAB")])
        assert ue._standalone_pin_hash(e, []) != ue._standalone_pin_hash(e, [_tpl(0, "AAAA")])

    def test_empty_template_data_is_ignored_like_the_driver(self):
        e = {"pin": "1", "name": "n", "card": "1"}
        assert ue._standalone_pin_hash(e, [_tpl(0, "")]) == ue._standalone_pin_hash(e, [])


# --------------------------------------------------------------------------- #
# Full sync becomes incremental
# --------------------------------------------------------------------------- #

class TestIncrementalFullSync:
    def test_explicit_revocation_is_never_readded_from_stale_cache(self, monkeypatch, state):
        w, _ = _worker(
            monkeypatch,
            users=[_user(117, "Bob", "1"), _user(118, "Revoked", "2")],
        )

        assert w.request_full_sync(
            reason="fast_patch_bundle",
            revoked_ids={118},
        ) is True
        assert w._drain_full_sync_commands(limit=1) == 1

        assert _pins(w._sdk.push_calls[0]) == {"117"}

    def test_first_sync_pushes_every_pin_and_records_state(self, monkeypatch, state):
        w, _ = _worker(monkeypatch, users=[_user(117, "Bob", "1"), _user(118, "Alice", "2")])
        _full_sync(w)
        assert _pins(w._sdk.push_calls[0]) == {"117", "118"}
        assert set(state.rows) == {"117", "118"}
        assert all(ok for _h, ok in state.rows.values())
        assert all(h for h, _ok in state.rows.values()), "a hash must be stored for every pushed pin"
        assert _finished_kwargs(w)["ok"] is True
        assert _finished_kwargs(w)["fingerprint_hash"] == "h1"

    def test_unchanged_roster_sends_nothing_but_still_completes(self, monkeypatch, state):
        w, _ = _worker(monkeypatch, users=[_user(117, "Bob", "1"), _user(118, "Alice", "2")])
        _full_sync(w, fingerprint_hash="h1")
        _full_sync(w, fingerprint_hash="h2")
        assert len(w._sdk.push_calls) == 1, "second sync must not touch the terminal"
        # ...yet it MUST finish as a success carrying the new hash, or the scheduler
        # would re-evaluate "roster changed" forever.
        assert _finished_kwargs(w)["ok"] is True
        assert _finished_kwargs(w)["fingerprint_hash"] == "h2"
        # and the history row says why nothing was sent
        last = w._push_batch_updates[-1]
        assert last["pins_attempted"] == 0 and last["status"] == "SUCCESS"
        assert "unchanged" in (last["error_message"] or "")

    def test_changed_card_pushes_only_that_pin(self, monkeypatch, state):
        users = [_user(117, "Bob", "1"), _user(118, "Alice", "2")]
        w, cache = _worker(monkeypatch, users=users)
        _full_sync(w)
        cache.users[1]["firstCardId"] = "999"
        _full_sync(w)
        assert _pins(w._sdk.push_calls[1]) == {"118"}

    def test_new_fingerprint_pushes_only_that_pin_with_its_template(self, monkeypatch, state):
        users = [_user(117, "Bob", "1"), _user(118, "Alice", "2")]
        w, cache = _worker(monkeypatch, users=users)
        _full_sync(w)
        cache.users[0]["fingerprints"] = [_tpl(0, "NEWTEMPLATE")]
        _full_sync(w)
        users_pushed, templates, _ = w._sdk.push_calls[1]
        assert {u["pin"] for u in users_pushed} == {"117"}
        assert "117" in templates and templates["117"][0]["templateData"] == "NEWTEMPLATE"
        assert "118" not in templates

    def test_pin_recorded_failed_is_retried_even_when_unchanged(self, monkeypatch, state):
        users = [_user(117, "Bob", "1"), _user(118, "Alice", "2")]
        w, _ = _worker(monkeypatch, users=users)
        _full_sync(w)
        h118 = state.rows["118"][0]
        state.rows["118"] = (h118, False)          # last attempt failed
        _full_sync(w)
        assert _pins(w._sdk.push_calls[1]) == {"118"}

    @pytest.mark.parametrize("reason", ["user-sync", "daily-forced-sync", "hard-reset"])
    def test_bracketed_reasons_push_everything_regardless_of_state(self, monkeypatch, state, reason):
        users = [_user(117, "Bob", "1"), _user(118, "Alice", "2")]
        w, _ = _worker(monkeypatch, users=users)
        _full_sync(w)                                   # everything now recorded synced
        _full_sync(w, reason=reason)
        users_pushed, _t, bracket = w._sdk.push_calls[1]
        assert {u["pin"] for u in users_pushed} == {"117", "118"}
        assert bracket is True

    def test_prune_forgets_pins_no_longer_desired(self, monkeypatch, state):
        users = [_user(117, "Bob", "1"), _user(118, "Alice", "2")]
        w, cache = _worker(monkeypatch, users=users)
        _full_sync(w)
        assert set(state.rows) == {"117", "118"}
        cache.users.pop(1)                              # Alice leaves the roster
        _full_sync(w)
        assert set(state.rows) == {"117"}
        # ...and if she comes back she is pushed again, not assumed present
        cache.users.append(_user(118, "Alice", "2"))
        _full_sync(w)
        assert _pins(w._sdk.push_calls[-1]) == {"118"}


# --------------------------------------------------------------------------- #
# Failure handling — the safety directions
# --------------------------------------------------------------------------- #

class TestFailureHandling:
    def test_ok_true_with_nonzero_failure_counter_confirms_no_pins(self, monkeypatch, state):
        class _ContradictorySuccess(FakeDriver):
            def push_roster(self, users, templates_by_pin=None, *, bracket_enable_device=False, **kw):
                self.push_calls.append((list(users), dict(templates_by_pin or {}), bracket_enable_device))
                return {
                    "ok": True,
                    "pushed": 1,
                    "failed": 1,
                    "templates_failed": 0,
                    "chunks_wedged": 0,
                    "skipped_pin": 0,
                    "failed_pins": [],
                }

        w, _ = _worker(
            monkeypatch,
            driver=_ContradictorySuccess(),
            users=[_user(117, "Bob", "1")],
        )
        _full_sync(w)

        assert state.rows["117"][1] is False
        assert _finished_kwargs(w)["ok"] is False
        assert _finished_kwargs(w)["fingerprint_hash"] is None
        last = w._push_batch_updates[-1]
        assert last["pins_success"] == 0 and last["pins_failed"] == 1
        assert last["status"] == "FAILED"

    def test_vacated_finger_clear_failure_is_failed_in_push_batch_history(self, monkeypatch, state):
        class _SlotRemovalFailure(FakeDriver):
            def push_roster(self, users, templates_by_pin=None, *, bracket_enable_device=False, **kw):
                self.push_calls.append((list(users), dict(templates_by_pin or {}), bracket_enable_device))
                return {
                    "ok": False,
                    "pushed": 1,
                    "failed": 0,
                    "templates_failed": 0,
                    "skipped_pin": 0,
                    "chunks_wedged": 0,
                    "errors": ["finger removal refused"],
                    "failed_pins": [" 117 "],
                    "del_attempted": 1,
                    "del_ok": 0,
                }

        w, _ = _worker(
            monkeypatch,
            driver=_SlotRemovalFailure(),
            users=[_user(117, "Bob", "1")],
        )
        _full_sync(w)

        last = w._push_batch_updates[-1]
        assert last["pins_attempted"] == 1
        assert last["pins_success"] == 0
        assert last["pins_failed"] == 1
        assert last["status"] == "FAILED"
        assert state.rows["117"][1] is False

    def test_partial_failure_marks_only_failed_pins_and_retries_just_them(self, monkeypatch, state):
        users = [_user(117, "Bob", "1"), _user(118, "Alice", "2"), _user(119, "Eve", "3")]
        drv = FakeDriver(failed_pins=["118"])
        w, _ = _worker(monkeypatch, driver=drv, users=users)
        _full_sync(w)
        assert state.rows["117"][1] is True and state.rows["119"][1] is True
        assert state.rows["118"][1] is False
        assert _finished_kwargs(w)["ok"] is False        # a refused pin is not a clean sync
        drv.failed_pins = []                              # terminal accepts it now
        _full_sync(w)
        assert _pins(w._sdk.push_calls[1]) == {"118"}, "only the failed pin is retried"
        assert state.rows["118"][1] is True

    def test_driver_without_failed_pins_and_failure_marks_all_attempted_unconfirmed(self, monkeypatch, state):
        users = [_user(117, "Bob", "1"), _user(118, "Alice", "2")]
        w, _ = _worker(monkeypatch, driver=FakeDriver(ok=False, report_failed_pins=False), users=users)
        _full_sync(w)
        assert all(ok is False for _h, ok in state.rows.values())
        assert _finished_kwargs(w)["fingerprint_hash"] is None

    def test_ok_false_with_empty_failed_pins_is_read_conservatively(self, monkeypatch, state):
        """A driver saying 'something failed' but naming nothing => nothing is confirmed."""
        class _Odd(FakeDriver):
            def push_roster(self, users, templates_by_pin=None, *, bracket_enable_device=False, **kw):
                self.push_calls.append((list(users), {}, bracket_enable_device))
                return {"ok": False, "pushed": len(users), "failed": 1, "errors": ["?"], "failed_pins": []}
        w, _ = _worker(monkeypatch, driver=_Odd(), users=[_user(117, "Bob", "1"), _user(118, "Alice", "2")])
        _full_sync(w)
        assert all(ok is False for _h, ok in state.rows.values())

    def test_state_read_error_falls_back_to_pushing_everything(self, monkeypatch):
        """The dangerous direction is SKIPPING a pin. A broken lookup must never do that."""
        st = _install_state(monkeypatch, FakeState())
        users = [_user(117, "Bob", "1"), _user(118, "Alice", "2")]
        w, _ = _worker(monkeypatch, users=users)
        _full_sync(w)
        assert len(w._sdk.push_calls) == 1
        st.raise_on_read = True
        _full_sync(w)
        assert _pins(w._sdk.push_calls[1]) == {"117", "118"}
        assert _finished_kwargs(w)["ok"] is True

    def test_state_write_error_never_flips_the_sync_result(self, monkeypatch, state):
        def _boom(**kw):
            raise RuntimeError("disk full")
        monkeypatch.setattr(dbmod, "save_device_sync_state_batch", _boom)
        w, _ = _worker(monkeypatch, users=[_user(117, "Bob", "1")])
        _full_sync(w)
        assert _finished_kwargs(w)["ok"] is True
        assert _finished_kwargs(w)["fingerprint_hash"] == "h1"


# --------------------------------------------------------------------------- #
# THE enrolment cascade
# --------------------------------------------------------------------------- #

class TestEnrolmentCascade:
    def test_member_sync_then_full_sync_is_a_noop(self, monkeypatch, state):
        """v1.4.28 field report: 'after a success enrolment the access pushes the
        full list'. The targeted member sync must record its pin as synced so the
        hash-triggered full sync that follows has nothing to push."""
        users = [_user(117, "Bob", "1"), _user(118, "Alice", "2")]
        w, cache = _worker(monkeypatch, users=users)
        _full_sync(w)                                          # steady state
        assert len(w._sdk.push_calls) == 1

        cache.users[0]["fingerprints"] = [_tpl(0, "ENROLLED")]  # enrolment lands in the cache
        w.request_member_sync(117)
        assert w._drain_member_sync_commands(limit=1) == 1
        assert _pins(w._sdk.push_calls[1]) == {"117"}
        assert w._sdk.push_calls[1][1]["117"][0]["templateData"] == "ENROLLED"
        assert state.rows["117"][1] is True

        _full_sync(w, fingerprint_hash="h-after-enrol")        # the cascade trigger
        assert len(w._sdk.push_calls) == 2, "the full sync must NOT re-push the roster"
        assert _finished_kwargs(w)["ok"] is True
        assert _finished_kwargs(w)["fingerprint_hash"] == "h-after-enrol"

    def test_failed_member_sync_is_recorded_so_the_full_sync_retries_it(self, monkeypatch, state):
        users = [_user(117, "Bob", "1"), _user(118, "Alice", "2")]
        drv = FakeDriver()
        w, cache = _worker(monkeypatch, driver=drv, users=users)
        _full_sync(w)
        cache.users[0]["fingerprints"] = [_tpl(0, "ENROLLED")]
        drv.failed_pins = ["117"]                              # terminal refuses the template
        w.request_member_sync(117)
        w._drain_member_sync_commands(limit=1)
        assert state.rows["117"][1] is False
        drv.failed_pins = []
        _full_sync(w)
        assert _pins(w._sdk.push_calls[-1]) == {"117"}, "the failed member is retried, nothing else"


# --------------------------------------------------------------------------- #
# MIRROR must never see the incremental subset
# --------------------------------------------------------------------------- #

class TestMirrorSafety:
    def test_mirror_receives_the_full_desired_roster_not_the_subset(self, monkeypatch, state):
        """If the subset were passed, every unchanged member would be deleted."""
        users = [_user(117, "Bob", "1"), _user(118, "Alice", "2"), _user(119, "Eve", "3")]
        w, cache = _worker(monkeypatch, users=users)
        _full_sync(w)
        seen: Dict[str, Any] = {}
        monkeypatch.setattr(w, "_maybe_mirror_reconcile",
                            lambda *, reason, roster_users: seen.update(roster=[u["pin"] for u in roster_users]))
        cache.users[2]["firstCardId"] = "333"                 # only Eve changes
        _full_sync(w)
        assert _pins(w._sdk.push_calls[1]) == {"119"}
        assert set(seen["roster"]) == {"117", "118", "119"}, "MIRROR must get the FULL roster"

    def test_mirror_delete_forgets_the_pins_state(self, monkeypatch, state):
        """A deleted-then-re-added member must be pushed again, not assumed present."""
        class _MirrorDriver(FakeDriver):
            def __init__(self):
                super().__init__()
                self.deleted = None
            def list_device_users(self, **_kw):
                return {"ok": True, "users": [{"pin": "117"}, {"pin": "40001"}]}
            def delete_users(self, pins, **_kw):
                self.deleted = list(pins)
                return {"ok": True, "deleted": len(pins), "failed": 0, "errors": []}

        monkeypatch.setattr(dbmod, "mirror_reconcile_is_armed", lambda **kw: True)
        monkeypatch.setattr(dbmod, "mirror_reconcile_record_plan", lambda **kw: None)
        monkeypatch.setattr(dbmod, "delete_device_mirror_pin", lambda **kw: None)
        drv = _MirrorDriver()
        # roster large enough that one delete stays under the 25 % abort fraction
        users = [_user(117, "Bob", "1")] + [_user(200 + i, f"M{i}", str(10 + i)) for i in range(5)]
        w, _ = _worker(monkeypatch, driver=drv, users=users)
        w._device["rosterPushingPolicy"] = "MIRROR"
        w._recent_member_push = {}
        state.rows["40001"] = ("stale-hash", True)            # a leftover 'synced' record
        _full_sync(w, reason="user-sync")
        assert drv.deleted == ["40001"]
        assert "40001" in state.delete_calls
        assert "40001" not in state.rows


# --------------------------------------------------------------------------- #
# Driver level: push_roster names WHICH pins were not confirmed
# --------------------------------------------------------------------------- #

class _FakeZkem:
    """Minimal zkemkeeper stand-in; per-pin failure injection for the push sequence."""

    def __init__(self):
        self.calls: List[tuple] = []
        self.fail_userinfo_for: set = set()
        self.fail_template_for: set = set()
        self.raise_card_for: set = set()

    def _rec(self, name, *args):
        self.calls.append((name, *args))

    def SetCommPassword(self, key): return True
    def Connect_Net(self, ip, port): self._rec("Connect_Net", ip, port); return True
    def RegEvent(self, machine, mask): return True
    def Disconnect(self): pass
    def ReadRTLog(self, machine): return False
    def GetRTLog(self, machine): return False
    def EnableDevice(self, machine, flag): self._rec("EnableDevice", flag); return True
    def RefreshData(self, machine): return True

    def SetStrCardNumber(self, card):
        self._rec("SetStrCardNumber", card)
        if card in self.raise_card_for:
            raise RuntimeError("simulated COM fault")
        return True

    def SSR_SetUserInfo(self, machine, pin, name, pw, priv, enabled):
        self._rec("SSR_SetUserInfo", pin)
        return str(pin) not in self.fail_userinfo_for

    def SSR_DelUserTmpExt(self, machine, pin, finger_id):
        self._rec("SSR_DelUserTmpExt", pin, finger_id); return True

    def SetUserTmpExStr(self, machine, pin, finger, flag, tmp):
        self._rec("SetUserTmpExStr", pin, finger)
        return str(pin) not in self.fail_template_for


def _make_driver(zk: _FakeZkem):
    from app.sdk.zk_standalone import ZKStandaloneDevice
    drv = ZKStandaloneDevice(
        {"id": 9, "name": "Entree 1", "ipAddress": "192.168.9.10", "portNumber": 4370},
        logger=MagicMock(),
    )
    drv._com_factory = lambda: zk
    drv._co_init = lambda: None
    drv._co_uninit = lambda: None
    drv._pump = lambda: None
    drv._refresh_pin_card_map = lambda: None  # type: ignore[method-assign]
    assert drv.connect() is True
    return drv


class TestDriverReportsFailedPins:
    def _roster(self):
        return [{"pin": "117", "name": "Bob", "card": "1"},
                {"pin": "118", "name": "Alice", "card": "2"},
                {"pin": "119", "name": "Eve", "card": "3"}]

    def test_refused_userinfo_names_exactly_that_pin(self):
        zk = _FakeZkem(); zk.fail_userinfo_for = {"118"}
        drv = _make_driver(zk)
        try:
            res = drv.push_roster(self._roster(), {})
        finally:
            drv.disconnect()
        assert res["ok"] is False
        assert res["failed_pins"] == ["118"]
        assert res["pushed"] == 2 and res["failed"] == 1

    def test_refused_template_names_the_pin_once_even_for_two_fingers(self):
        zk = _FakeZkem(); zk.fail_template_for = {"117"}
        drv = _make_driver(zk)
        try:
            res = drv.push_roster(self._roster(), {"117": [_tpl(0, "AAAA"), _tpl(1, "BBBB")]})
        finally:
            drv.disconnect()
        assert res["templates_failed"] == 2
        assert res["failed_pins"] == ["117"], "deduplicated: one member, one entry"
        assert res["ok"] is False

    def test_exception_mid_member_names_that_pin(self):
        zk = _FakeZkem(); zk.raise_card_for = {"2"}      # Alice's card
        drv = _make_driver(zk)
        try:
            res = drv.push_roster(self._roster(), {})
        finally:
            drv.disconnect()
        assert res["failed_pins"] == ["118"]
        assert res["pushed"] == 2

    def test_clean_push_reports_no_failed_pins(self):
        drv = _make_driver(_FakeZkem())
        try:
            res = drv.push_roster(self._roster(), {"119": [_tpl(0, "CCCC")]})
        finally:
            drv.disconnect()
        assert res["ok"] is True and res["failed_pins"] == []

    def test_wedged_chunk_names_every_pin_it_contained(self, monkeypatch):
        """A wedge returns no per-member result at all: nothing in that chunk is
        confirmed, so all of its pins must be retried by the next sync."""
        from app.sdk import zk_standalone as zs
        drv = _make_driver(_FakeZkem())
        real_call = drv._call
        state = {"n": 0}

        def _call(op, args=None, timeout=zs._DEFAULT_CMD_TIMEOUT_SEC):
            if op == "push_roster":
                state["n"] += 1
                if state["n"] == 2:                       # second chunk wedges
                    drv._abandon_sta_thread("simulated wedge")
                    raise TimeoutError("zkemkeeper command 'push_roster' timed out")
            return real_call(op, args=args, timeout=timeout)

        monkeypatch.setattr(drv, "_call", _call)
        users = [{"pin": str(i), "name": "x", "card": ""} for i in range(25)]  # 3 chunks of 10
        try:
            res = drv.push_roster(users, {})
        finally:
            drv.disconnect()
        assert res["chunks_wedged"] == 1
        assert res["ok"] is False
        assert set(res["failed_pins"]) == {str(i) for i in range(10, 20)}, (
            "exactly the wedged chunk's pins, and only those"
        )
        assert res["pushed"] == 15, "the other two chunks still landed"

    def test_reconnect_after_abandon_is_serviced_by_the_new_thread(self):
        """The superseded-thread race, found while writing the wedge test above.

        _sta_main checked the generation only at the TOP of its loop. A thread that
        was abandoned while merely slow (not stuck in COM -- plausible on the 4 GB
        client PC) was still sitting in _cmd_queue.get(), stole the successor's
        'connect', serviced it on its own COM object, then exited and cleared the
        SHARED connected flag. Observed: connect() -> True with is_connected False,
        and every later command answered "not connected".
        """
        zk = _FakeZkem()
        drv = _make_driver(zk)
        try:
            old = drv._sta_thread
            drv._abandon_sta_thread("simulated slow thread")
            assert drv._sta_thread is None
            assert drv.connect() is True
            assert drv.is_connected is True, "the successor's connection was reported down"
            # A real command must be executed on the new thread with a live COM object
            res = drv.push_roster([{"pin": "117", "name": "Bob", "card": "1"}], {})
            assert res["ok"] is True and res["pushed"] == 1
            assert res.get("error") != "not connected"
            deadline = time.monotonic() + 3.0
            while old.is_alive() and time.monotonic() < deadline:
                time.sleep(0.02)
            assert not old.is_alive(), "the superseded thread must exit"
            assert drv.is_connected is True, "its exit must not clear the successor's flag"
        finally:
            drv.disconnect()

    def test_failed_chunk_without_failed_pins_confirms_nothing(self, monkeypatch):
        """A chunk answering 'not connected' (no per-member results) must put every
        one of its pins into failed_pins -- otherwise the engine records them synced."""
        from app.sdk import zk_standalone as zs
        drv = _make_driver(_FakeZkem())
        real_call = drv._call
        state = {"n": 0}

        def _call(op, args=None, timeout=zs._DEFAULT_CMD_TIMEOUT_SEC):
            if op == "push_roster":
                state["n"] += 1
                if state["n"] == 2:
                    return {"ok": False, "pushed": 0, "failed": 0, "error": "not connected"}
            return real_call(op, args=args, timeout=timeout)

        monkeypatch.setattr(drv, "_call", _call)
        users = [{"pin": str(i), "name": "x", "card": ""} for i in range(25)]
        try:
            res = drv.push_roster(users, {})
        finally:
            drv.disconnect()
        assert res["ok"] is False
        assert set(res["failed_pins"]) == {str(i) for i in range(10, 20)}
        assert res["pushed"] == 15

"""Per-pin FINGER-SLOT state, and the removal set derived from it.

The driver can now clear a vacated slot (see test_zk_standalone_template_removal),
but it only clears what the engine tells it to. The engine has to know which
fingers it last pushed to THIS device -- ``desired_hash`` is a one-way sha1 whose
pre-image includes the template bytes, so the finger ids cannot be recovered from
it. Hence ``device_sync_state.pushed_finger_ids``.

THE INVARIANT THAT MAKES THE BACKFILL SAFE
------------------------------------------
``last_ok=1 AND desired_hash == <freshly computed hash>`` is the system's own
assertion that the terminal already holds exactly the desired state for that pin.
So for an unchanged pin we may record the desired finger ids as the pushed ones
WITHOUT touching the device. That is what stops the installed base from being
stuck at "unknown" forever -- a pin is only pushed when it changes, so without
the backfill a pre-upgrade member's first deletion would still have no baseline.

NULL MEANS UNKNOWN, NEVER EMPTY
-------------------------------
Reading a missing/NULL value as "no fingers were pushed" would make the removal
set empty for every legacy row and silently perpetuate the original bug. It must
also never be read as "sweep every slot": a blanket 0..9 clear over a ~900-pin
bracketed roster is ~9000 extra COM calls at ~100 ms each, which would blow the
600 s single-command deadline while holding EnableDevice(False) -- turnstile dead.
Unknown therefore means: clear nothing, and say so.
"""
from __future__ import annotations

import threading
from collections import deque
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

import app.core.db as dbmod
import app.core.ultra_engine as ue

from tests.test_standalone_incremental_sync import _tpl, _user, _worker, _full_sync


class RecordingDriver:
    """Captures remove_fingers_by_pin alongside the usual push arguments."""
    owns_event_source = True

    def __init__(self):
        self.push_calls: List[dict] = []

    def push_roster(self, users, templates_by_pin=None, *, remove_fingers_by_pin=None,
                    bracket_enable_device=False, **kw):
        self.push_calls.append({
            "users": list(users),
            "templates": dict(templates_by_pin or {}),
            "removals": {k: sorted(v) for k, v in (remove_fingers_by_pin or {}).items()},
            "bracket": bracket_enable_device,
        })
        pins = [str(u["pin"]) for u in users]
        return {"ok": True, "pushed": len(users), "failed": 0, "templates_failed": 0,
                "skipped_pin": 0, "chunks_wedged": 0, "errors": [], "failed_pins": [],
                "del_attempted": 0, "del_ok": 0}


class FingerState:
    """device_sync_state with the pushed_finger_ids column modelled.

    rows: pin -> (desired_hash, last_ok, pushed_finger_ids | None)
    """

    def __init__(self):
        self.rows: Dict[str, tuple] = {}
        self.save_calls: List[list] = []

    @staticmethod
    def _decode(raw):
        """Mirror db.list_device_pushed_fingers: NULL -> None, '' -> set()."""
        if raw is None:
            return None
        if isinstance(raw, (set, frozenset)):
            return set(raw)
        return {int(p) for p in str(raw).split(",") if p.strip()}

    # --- the two readers the engine uses -----------------------------------
    def list_hashes(self, *, device_id):
        return {p: (h, ok) for p, (h, ok, _f) in self.rows.items()}

    def list_fingers(self, *, device_id):
        return {p: (None if f is None else set(f)) for p, (_h, _ok, f) in self.rows.items()}

    # --- the writer ---------------------------------------------------------
    def save_batch(self, *, device_id, rows):
        rows = list(rows)
        self.save_calls.append(rows)
        for row in rows:
            pin, h, ok, _err = row[0], row[1], row[2], row[3]
            fingers = row[4] if len(row) > 4 else None
            prev = self.rows.get(pin, ("", False, None))
            self.rows[pin] = (
                (h if ok else prev[0]),
                bool(ok),
                # mirrors the real CASE WHEN excluded.last_ok = 1 guard: a failed
                # push must not destroy the record of what is actually resident.
                # Decoded on write so the stored value is what a read would return.
                (self._decode(fingers) if (ok and fingers is not None) else prev[2]),
            )
        return len(rows)

    def prune(self, *, device_id, keep_pins):
        keep = {str(k) for k in keep_pins}
        for p in [p for p in self.rows if p not in keep]:
            self.rows.pop(p)
        return 0

    def delete(self, *, device_id, pin):
        self.rows.pop(str(pin), None)


@pytest.fixture
def fstate(monkeypatch) -> FingerState:
    st = FingerState()
    monkeypatch.setattr(dbmod, "list_device_sync_hashes_and_status", st.list_hashes)
    monkeypatch.setattr(dbmod, "list_device_pushed_fingers", st.list_fingers, raising=False)
    monkeypatch.setattr(dbmod, "save_device_sync_state_batch", st.save_batch)
    monkeypatch.setattr(dbmod, "prune_device_sync_state", st.prune)
    monkeypatch.setattr(dbmod, "delete_device_sync_state", st.delete)
    # The targeted member read must be stubbed too, or _load_member_roster reaches
    # the REAL C:\ProgramData\MonClub Access\access\access.db and these tests start
    # asserting against a live gym's data. Empty here means "no sync_users row", so
    # the engine falls back to the sync cache these tests already control -- the
    # behaviour they were written against. Tests that specifically exercise the
    # targeted path override this (see test_standalone_member_sync_targeted_read).
    monkeypatch.setattr(
        dbmod, "list_sync_users_by_active_membership_ids",
        lambda active_membership_ids: [], raising=False,
    )
    return st


def _hash_for(user_entry: dict, templates: list) -> str:
    return ue._standalone_pin_hash(user_entry, templates)


class TestRemovalSetIsDerivedFromPushedFingers:

    def test_deleting_the_last_fingerprint_asks_the_driver_to_clear_the_slot(
            self, monkeypatch, fstate):
        """The Oxyfit field bug, end to end at the engine seam."""
        drv = RecordingDriver()
        # member is still in the roster, but has no fingerprints any more
        w, _cache = _worker(monkeypatch, driver=drv, users=[_user(34439, "malek Djait", "")])
        # ...and we know we previously pushed finger 0 to this device
        fstate.rows["34439"] = ("stale-hash", True, {0})

        _full_sync(w)

        assert len(drv.push_calls) == 1
        assert drv.push_calls[0]["removals"] == {"34439": [0]}

    def test_partial_deletion_removes_only_the_vacated_finger(self, monkeypatch, fstate):
        drv = RecordingDriver()
        w, _cache = _worker(
            monkeypatch, driver=drv,
            users=[_user(34439, "malek Djait", "", [_tpl(0, "AAAA")])],
        )
        fstate.rows["34439"] = ("stale-hash", True, {0, 2})

        _full_sync(w)

        assert drv.push_calls[0]["removals"] == {"34439": [2]}

    def test_unknown_previous_fingers_never_invents_a_removal_set(
            self, monkeypatch, fstate):
        """NULL is UNKNOWN. It must not become "nothing was pushed" (which would
        keep the bug) nor "sweep every slot" (which would blow the push budget)."""
        drv = RecordingDriver()
        w, _cache = _worker(monkeypatch, driver=drv, users=[_user(34439, "malek Djait", "")])
        fstate.rows["34439"] = ("stale-hash", True, None)   # legacy row

        _full_sync(w)

        assert drv.push_calls[0]["removals"] == {}

    def test_a_pin_that_gains_a_finger_has_no_removals(self, monkeypatch, fstate):
        drv = RecordingDriver()
        w, _cache = _worker(
            monkeypatch, driver=drv,
            users=[_user(34439, "m", "", [_tpl(0, "AAAA"), _tpl(2, "BBBB")])],
        )
        fstate.rows["34439"] = ("stale-hash", True, {0})

        _full_sync(w)

        assert drv.push_calls[0]["removals"] == {}


class TestPushedFingersArePersisted:

    def test_a_successful_push_records_the_new_finger_set(self, monkeypatch, fstate):
        drv = RecordingDriver()
        w, _cache = _worker(
            monkeypatch, driver=drv,
            users=[_user(34439, "m", "", [_tpl(0, "AAAA"), _tpl(2, "BBBB")])],
        )

        _full_sync(w)

        assert fstate.rows["34439"][2] == {0, 2}

    def test_removing_every_finger_records_an_empty_set_not_unknown(
            self, monkeypatch, fstate):
        """After the fix lands the pin must be KNOWN-empty, so a later re-enrol +
        delete cycle still computes a correct removal set."""
        drv = RecordingDriver()
        w, _cache = _worker(monkeypatch, driver=drv, users=[_user(34439, "m", "")])
        fstate.rows["34439"] = ("stale-hash", True, {0})

        _full_sync(w)

        assert fstate.rows["34439"][2] == set()


class TestTargetedMemberSync:
    """The path that actually fires seconds after a dashboard revocation.

    In the field the delete reached this path first (13:05:42) and the roster push
    only followed at 13:14 -- so if the removal set is missing here, the revoked
    finger stays live for the whole gap even once the full-sync path is fixed.
    """

    def test_member_sync_clears_the_vacated_slot(self, monkeypatch, fstate):
        drv = RecordingDriver()
        w, _cache = _worker(monkeypatch, driver=drv, users=[_user(34439, "malek Djait", "")])
        fstate.rows["34439"] = ("stale-hash", True, {0})

        w._run_standalone_member_sync(34439)

        assert len(drv.push_calls) == 1
        assert drv.push_calls[0]["removals"] == {"34439": [0]}

    def test_member_sync_records_the_new_finger_set(self, monkeypatch, fstate):
        drv = RecordingDriver()
        w, _cache = _worker(monkeypatch, driver=drv, users=[_user(34439, "m", "")])
        fstate.rows["34439"] = ("stale-hash", True, {0})

        w._run_standalone_member_sync(34439)

        assert fstate.rows["34439"][2] == set()


class TestBackfillFromTheUnchangedInvariant:

    def test_an_unchanged_pin_backfills_its_finger_ids_without_pushing(
            self, monkeypatch, fstate):
        """last_ok=1 and a matching hash IS the assertion that the device holds the
        desired state. Recording it costs no device I/O and is what gives legacy
        rows a baseline before their first deletion."""
        drv = RecordingDriver()
        tpl = _tpl(0, "AAAA")
        u = _user(34439, "m", "", [tpl])
        w, _cache = _worker(monkeypatch, driver=drv, users=[u])

        entry = {"pin": "34439", "name": "m", "card": ""}
        fstate.rows["34439"] = (_hash_for(entry, [tpl]), True, None)

        _full_sync(w)

        assert drv.push_calls == [], "an unchanged pin must not be pushed"
        assert fstate.rows["34439"][2] == {0}, "but its finger ids must be recorded"

    def test_backfill_does_not_overwrite_a_known_set(self, monkeypatch, fstate):
        drv = RecordingDriver()
        tpl = _tpl(0, "AAAA")
        u = _user(34439, "m", "", [tpl])
        w, _cache = _worker(monkeypatch, driver=drv, users=[u])

        entry = {"pin": "34439", "name": "m", "card": ""}
        fstate.rows["34439"] = (_hash_for(entry, [tpl]), True, {0})

        _full_sync(w)

        assert fstate.rows["34439"][2] == {0}

    def test_a_failed_pin_is_not_backfilled(self, monkeypatch, fstate):
        """last_ok=0 means the device state is unknown -- backfilling would assert
        something we do not know."""
        drv = RecordingDriver()
        tpl = _tpl(0, "AAAA")
        u = _user(34439, "m", "", [tpl])
        w, _cache = _worker(monkeypatch, driver=drv, users=[u])

        entry = {"pin": "34439", "name": "m", "card": ""}
        fstate.rows["34439"] = (_hash_for(entry, [tpl]), False, None)

        _full_sync(w)

        # it is re-pushed (last_ok=0), so it is not a backfill case at all
        assert drv.push_calls, "a failed pin must be retried"
        assert drv.push_calls[0]["removals"] == {}

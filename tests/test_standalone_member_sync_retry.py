"""Targeted member sync must never silently drop a change.

FIELD INCIDENT (Oxyfit dev rig, 2026-09-06 14:19-14:20)
-------------------------------------------------------
A fingerprint deleted in the dashboard kept opening the turnstile even with the
vacated-slot fix in place. The log shows why -- the change was thrown away
between the sync landing and the push:

    14:19:42  MEMBER_SYNC_DONE            -> pushed_finger_ids = '0,1,2'
    14:19:54  FP_ARRIVED templates=2 am_ids=34439      (finger 2 deleted)
    14:19:57  save_sync_cache_delta members_upserted=1
    14:20:00  routed targeted member sync to live workers
    14:20:01  [ULTRA:8] member 34439 not in device roster   <-- returned, did nothing
    14:20:02  [ULTRA:9] member 34439 not in device roster   <-- returned, did nothing
    14:20:07  rtlog ALLOW: card='ZKPIN:34439' - user NOT found in local cache
    14:20:13  ...member is present again

The member was transiently absent from the sync cache and ``_run_standalone_member_sync``
treated "not in the roster" as "nothing to do", returning as if it had succeeded.
The removal of finger 2 was lost; device_sync_state still read '0,1,2' while the
member actually had {0,1}. The member was NOT genuinely gone -- membership 275 is
in both devices' allowed list and validity was 2026-09-01..2027-09-01.

WHAT THIS PINS
--------------
1. an empty roster triggers ONE forced-fresh retry before anything is concluded;
2. if the member is genuinely absent after that, the pin is marked NOT-ok so the
   periodic full sync is guaranteed to re-evaluate it -- the change is deferred,
   never dropped;
3. the happy path does not pay for any of this.

Deliberately NOT done here: pushing a deletion for a member who has really left
the roster. That is a whole-user removal and routes through
SSR_DeleteEnrollData(1, pin, 12), whose hang status the guide grades [UNKNOWN].
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

import app.core.db as dbmod
import app.core.ultra_engine as ue

from tests.test_standalone_incremental_sync import _tpl, _user, _worker
from tests.test_standalone_finger_removal_state import FingerState, RecordingDriver, fstate  # noqa: F401


class _Cache:
    """Sequenced sync-cache stand-in: yields a different snapshot per load."""

    def __init__(self, snapshots: List[List[dict]]):
        self._snapshots = snapshots
        self.loads = 0
        self.invalidations: List[bool] = []

    def load(self):
        idx = min(self.loads, len(self._snapshots) - 1)
        self.loads += 1
        snap = self._snapshots[idx]
        return None if snap is None else SimpleNamespace(users=list(snap))

    def invalidate(self, *, clear_cached: bool = False):
        self.invalidations.append(bool(clear_cached))


@pytest.fixture
def seq(monkeypatch):
    def _install(snapshots):
        c = _Cache(snapshots)
        monkeypatch.setattr(ue, "load_sync_cache", c.load)
        monkeypatch.setattr(ue, "invalidate_sync_cache", c.invalidate, raising=False)
        return c
    return _install


MEMBER = _user(34439, "malek Djait", "", [_tpl(0, "AAAA")])


class TestTransientCacheMiss:

    def test_a_missing_member_triggers_one_forced_fresh_retry(
            self, monkeypatch, fstate, seq):
        """The field case: absent on the first read, present on the second."""
        drv = RecordingDriver()
        w, _c = _worker(monkeypatch, driver=drv)
        cache = seq([[], [MEMBER]])          # miss, then hit
        fstate.rows["34439"] = ("stale-hash", True, {0, 2})

        w._run_standalone_member_sync(34439)

        assert cache.loads == 2, "must re-read the cache instead of giving up"
        assert cache.invalidations == [True], "the retry must bypass the TTL, not reuse the stale snapshot"
        assert len(drv.push_calls) == 1, "the member must actually be pushed"
        # ...and the whole point: the vacated slot is still cleared
        assert drv.push_calls[0]["removals"] == {"34439": [2]}

    def test_the_happy_path_never_invalidates_the_cache(
            self, monkeypatch, fstate, seq):
        """A found member must not pay for the retry machinery."""
        drv = RecordingDriver()
        w, _c = _worker(monkeypatch, driver=drv)
        cache = seq([[MEMBER]])

        w._run_standalone_member_sync(34439)

        assert cache.loads == 1
        assert cache.invalidations == []
        assert len(drv.push_calls) == 1


class TestGenuinelyAbsentMemberIsDeferredNotDropped:

    def test_pin_is_marked_not_ok_so_the_full_sync_retries_it(
            self, monkeypatch, fstate, seq):
        """Still absent after the forced retry. We must not conclude 'synced'.

        Marking last_ok=0 is what makes _standalone_pins_needing_push stop
        skipping the pin -- it is the existing, proven retry channel. The
        desired_hash is preserved by the CASE WHEN guard in the upsert, so this
        does not destroy the record of what is resident on the terminal.
        """
        drv = RecordingDriver()
        w, _c = _worker(monkeypatch, driver=drv)
        cache = seq([[], []])                # absent both times
        fstate.rows["34439"] = ("stale-hash", True, {0, 2})

        w._run_standalone_member_sync(34439)

        assert cache.loads == 2
        assert drv.push_calls == [], "nothing can be pushed for a member we cannot see"
        stored_hash, ok, fingers = fstate.rows["34439"]
        assert ok is False, "the pin must be flagged for the full sync to retry"
        assert stored_hash == "stale-hash", "the hash must survive so we still know what is resident"
        assert fingers == {0, 2}, "the pushed-finger record must survive too"

    def test_an_unknown_pin_is_not_invented_into_the_state_table(
            self, monkeypatch, fstate, seq):
        """A member we have never pushed and cannot see must not gain a row --
        that would resurrect a pruned pin on every stray sync request."""
        drv = RecordingDriver()
        w, _c = _worker(monkeypatch, driver=drv)
        seq([[], []])

        w._run_standalone_member_sync(99999)

        assert "99999" not in fstate.rows
        assert drv.push_calls == []

    def test_no_sync_cache_at_all_is_still_deferred(self, monkeypatch, fstate, seq):
        """cache is None (DB unreadable) is the same class of failure."""
        drv = RecordingDriver()
        w, _c = _worker(monkeypatch, driver=drv)
        seq([None, None])
        fstate.rows["34439"] = ("stale-hash", True, {0})

        w._run_standalone_member_sync(34439)

        assert drv.push_calls == []
        assert fstate.rows["34439"][1] is False, "an unreadable cache must not read as synced"

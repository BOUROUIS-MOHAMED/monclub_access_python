"""A targeted member sync must read the member from the DB, not a shared snapshot.

FIELD INCIDENT — Oxyfit, 2026-09-06 16:29, on a freshly wiped terminal.

The backend normalised "delete this fingerprint" into "delete this membership"
(fixed in monclub_backend a933338d), so a fast-patch bundle removed the member's
`sync_users` row for ~39 s. The client logs an unfiltered row count on every
roster read, and it caught the hole exactly:

    16:28:56  rows=911
    16:29:17  POST /api/v2/sync/fast-patch-bundle
    16:29:46  rows=910      <- the row is gone
    16:30:08  rows=911      <- the next delta re-creates it

Three things went wrong inside that window. The backend fix removes the CAUSE,
but two of the three were client-side amplifiers that would bite again for any
other reason a snapshot goes stale, so they are pinned here:

1. **A revoked credential was RE-PUSHED.** At 16:29:20 a member sync ran off the
   snapshot held from *before* the deletion and wrote the deleted template back to
   the terminal (`templates_for=1 tpl_ok=1`) — then stamped `device_sync_state`
   with the hash of that pre-deletion roster, so no later sync saw a difference.
   That is why waiting did not heal it. A targeted, post-commit DB read cannot
   produce this: it never sees a pre-deletion state.

2. **The revocation was dropped.** At 16:30:04 the roster came back empty and the
   member sync returned as if it had succeeded.

3. There was **no way to tell from the log** whether the roster was empty because
   the row was gone or because a filter rejected it. `MEMBER_SYNC_DEFERRED` now
   carries `in_db`, which is exactly that discriminator.

The cache path is KEPT as a fallback, not replaced: a member created offline and
not yet reconciled has no `sync_users` row at all and is only visible through the
cache's projected-offline merge. Losing that would break offline creation.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

import app.core.db as dbmod
import app.core.ultra_engine as ue

from tests.test_standalone_incremental_sync import _tpl, _user, _worker
from tests.test_standalone_finger_removal_state import FingerState, RecordingDriver, fstate  # noqa: F401


@pytest.fixture
def targeted(monkeypatch):
    """Install a fake targeted DB read; returns the recorder."""
    state: Dict[str, Any] = {"rows": [], "calls": []}

    def _read(active_membership_ids):
        state["calls"].append(sorted(int(m) for m in active_membership_ids))
        wanted = {int(m) for m in active_membership_ids}
        return [u for u in state["rows"] if int(u.get("activeMembershipId") or 0) in wanted]

    monkeypatch.setattr(dbmod, "list_sync_users_by_active_membership_ids", _read, raising=False)
    return state


@pytest.fixture
def cache(monkeypatch):
    """Factory that installs a sync-cache stand-in and returns its recorder.

    MUST be called AFTER _worker(), which patches ue.load_sync_cache itself and
    would otherwise overwrite this one with its own empty snapshot.
    """
    def _install(users: List[dict] | None = None):
        state: Dict[str, Any] = {"users": list(users or []), "loads": 0}

        def _load():
            state["loads"] += 1
            return SimpleNamespace(users=list(state["users"]))

        monkeypatch.setattr(ue, "load_sync_cache", _load)
        monkeypatch.setattr(ue, "invalidate_sync_cache", lambda **kw: None, raising=False)
        return state

    return _install


class TestTheDbIsAuthoritative:

    def test_a_stale_snapshot_can_no_longer_re_push_a_revoked_finger(
            self, monkeypatch, fstate, targeted, cache):
        """Incident amplifier #1, pinned.

        The DB says the finger is gone. The shared snapshot still has it. The push
        must follow the DB: clear the slot, and write no template.
        """
        drv = RecordingDriver()
        w, _c = _worker(monkeypatch, driver=drv)

        targeted["rows"] = [_user(34439, "malek Djait", "")]                    # revoked
        cache([_user(34439, "malek Djait", "", [_tpl(0, "AAAA")])])             # stale
        fstate.rows["34439"] = ("stale-hash", True, {0})

        w._run_standalone_member_sync(34439)

        assert len(drv.push_calls) == 1
        call = drv.push_calls[0]
        assert call["templates"] == {}, "the revoked template must NOT be re-pushed"
        assert call["removals"] == {"34439": [0]}, "the vacated slot must be cleared"
        assert targeted["calls"] == [[34439]], "the DB must be read for this member"

    def test_the_shared_snapshot_is_not_loaded_when_the_db_answers(
            self, monkeypatch, fstate, targeted, cache):
        """The snapshot scan cost 7 s on the live worker in the field. A targeted
        read is ~1 ms and cannot be mid-transaction stale."""
        drv = RecordingDriver()
        w, _c = _worker(monkeypatch, driver=drv)
        cache_state = cache([])
        targeted["rows"] = [_user(34439, "m", "", [_tpl(0, "AAAA")])]

        w._run_standalone_member_sync(34439)

        assert len(drv.push_calls) == 1
        assert cache_state["loads"] == 0, "no full-snapshot load when the DB has the member"


class TestOfflineMembersStillWork:

    def test_a_member_with_no_sync_users_row_falls_back_to_the_cache(
            self, monkeypatch, fstate, targeted, cache):
        """A member created offline has no sync_users row and exists only via the
        cache's projected-offline merge. The targeted read must not lose them."""
        drv = RecordingDriver()
        w, _c = _worker(monkeypatch, driver=drv)

        targeted["rows"] = []                                                   # not reconciled yet
        cache_state = cache([_user(90001, "offline member", "", [_tpl(0, "AAAA")])])

        w._run_standalone_member_sync(90001)

        assert len(drv.push_calls) == 1, "an offline-projected member must still be pushed"
        assert [u["pin"] for u in drv.push_calls[0]["users"]] == ["90001"]
        assert cache_state["loads"] >= 1, "the cache fallback must have been consulted"


class TestDeferralSaysWhy:

    def test_deferred_telemetry_reports_the_row_is_absent(
            self, monkeypatch, fstate, targeted, cache):
        """in_db=False is the field signature of the backend's fingerprint-delete
        bug: the row itself was removed."""
        events: List[tuple] = []
        monkeypatch.setattr(ue._tel, "warn", lambda name, **kw: events.append((name, kw)))

        drv = RecordingDriver()
        w, _c = _worker(monkeypatch, driver=drv)
        targeted["rows"] = []
        cache([])
        fstate.rows["34439"] = ("stale-hash", True, {0})

        w._run_standalone_member_sync(34439)

        assert drv.push_calls == []
        deferred = [kw for name, kw in events if name == "MEMBER_SYNC_DEFERRED"]
        assert deferred, "a dropped member sync must emit MEMBER_SYNC_DEFERRED"
        assert deferred[0].get("in_db") is False
        assert fstate.rows["34439"][1] is False, "the pin must be flagged for retry"

    def test_deferred_telemetry_reports_the_row_is_present(
            self, monkeypatch, fstate, targeted, cache):
        """in_db=True means the row exists but something FILTERED it out — a
        different bug entirely, and one the field log previously could not name."""
        events: List[tuple] = []
        monkeypatch.setattr(ue._tel, "warn", lambda name, **kw: events.append((name, kw)))

        drv = RecordingDriver()
        w, _c = _worker(monkeypatch, driver=drv)
        # present in the DB, but the device filters it out (membership not allowed)
        targeted["rows"] = [dict(_user(34439, "m", ""), membershipId=999999)]
        cache([])
        w._device = dict(w._device, allowedMemberships=[3])
        fstate.rows["34439"] = ("stale-hash", True, {0})

        w._run_standalone_member_sync(34439)

        assert drv.push_calls == []
        deferred = [kw for name, kw in events if name == "MEMBER_SYNC_DEFERRED"]
        assert deferred, "a dropped member sync must emit MEMBER_SYNC_DEFERRED"
        assert deferred[0].get("in_db") is True

"""P3a-2 items 8 + 4: never delete a user MonClub cannot prove it pushed, and one
such user must not block everything else.

Item 8 (PullSDK, gym 58's C3-400s). ``DeviceSyncEngine.sync_member_on_connected_sdk``
deleted a non-deliverable pin from four tables with NO ownership check, under both
pin schemes, and erased the pin's state row even when the SDK delete failed. Under
ACCOUNT that deletes a stranger (110 account ids equal another person's membership
id). Now: owned -> delete (a failed delete keeps its row); not owned -> nothing is
deleted, the outcome is ``SKIPPED_NOT_OWNED`` (final); unreadable ownership -> nothing
is deleted and the revocation stays pending (retry).

Item 4 (ZK_STANDALONE, gym 45's shared MB2000s). An explicit revocation of a pin
MonClub cannot prove it owns made the whole full sync return before pushing
anything (an unconfirmed row) or abort the whole revoke pass after the push (no row)
-- and every later full sync of that device failed the same way, forever. Now that
pin is dropped from the pass as ``SKIPPED_NOT_OWNED``, the revocation is finished,
the other members are pushed and the other departed members are removed.

``SKIPPED_NOT_OWNED`` (final) is never the same thing as ``REVOKE_ABORTED`` (above
the ceiling, retryable): see ``test_an_above_ceiling_abort_still_leaves_the_revocation_pending``.
No real device, no installed database (temp ``_DB_PATH`` or in-memory fakes).
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import app.core.db as dbmod
import app.core.telemetry as tel
import app.core.ultra_engine as ue
from app.sdk.pullsdk import PullSDKError
from tests.test_account_pin_device_sites import (  # noqa: F401  (fixture)
    _ali_gym, _cache, _deleted_pins, _engine, _pullsdk_device, _removed_pins, _sdk,
    _sonia, _written_pins, sqlite_db,
)
from tests.test_standalone_finger_removal_state import FingerState, fstate  # noqa: F401
from tests.test_standalone_incremental_sync import _user, _worker
from tests.test_standalone_revoked_pin_removal import RevokeDriver, _authoritative_full_sync


@pytest.fixture
def warns(monkeypatch):
    seen: list[tuple[str, dict]] = []
    monkeypatch.setattr(tel, "warn", lambda name, **f: seen.append((name, f)))
    return seen


def _skips(warns):
    return [f for n, f in warns if n == "MEMBER_REVOKE_SKIPPED_NOT_OWNED"]


# ═════════════════════════ item 8: PullSDK targeted revoke ═════════════════════════

class TestPullSdkTargetedRevokeOwnership:

    def _revoke_sonia(self, sqlite_db, *, scheme="ACCOUNT", sdk=None):
        _cache(sqlite_db, [_ali_gym(), _sonia()])
        _cache(sqlite_db, [], valid_ids=[31000])            # Sonia's membership revoked
        sdk = sdk or _sdk()
        eng = _engine()
        r = eng.sync_member_on_connected_sdk(
            sdk=sdk, device=_pullsdk_device(pinScheme=scheme), member_id=5, revocation=True)
        return eng, sdk, r

    def test_an_unowned_account_pin_is_never_deleted(self, sqlite_db, warns):
        """No device_sync_state row for 777: MonClub never proved it wrote that user."""
        eng, sdk, r = self._revoke_sonia(sqlite_db)
        assert _deleted_pins(sdk) == [], "777 may be a stranger or another system's user"
        assert r is False
        assert eng._last_member_sync_outcome == "SKIPPED_NOT_OWNED"
        [skip] = _skips(warns)
        assert skip["pin"] == "777" and skip["member_id"] == 5

    def test_a_failed_first_push_row_is_not_ownership(self, sqlite_db, warns):
        sqlite_db.save_device_sync_state(device_id=1, pin="777", desired_hash="h",
                                         ok=False, error="authorize refused")
        eng, sdk, r = self._revoke_sonia(sqlite_db)
        assert _deleted_pins(sdk) == [] and r is False
        assert eng._last_member_sync_outcome == "SKIPPED_NOT_OWNED"
        assert "777" in sqlite_db.list_device_sync_pins(device_id=1), "the row is kept"

    def test_an_owned_pin_is_deleted_and_forgotten(self, sqlite_db, warns):
        sqlite_db.save_device_sync_state(device_id=1, pin="777", desired_hash="h",
                                         ok=True, error=None)
        eng, sdk, r = self._revoke_sonia(sqlite_db)
        assert _removed_pins(sdk) == {"777"} and r is True
        assert eng._last_member_sync_outcome == "DELETED"
        assert "777" not in sqlite_db.list_device_sync_pins(device_id=1)
        assert _skips(warns) == []

    def test_a_failed_delete_keeps_the_ownership_row_for_the_retry(self, sqlite_db):
        sqlite_db.save_device_sync_state(device_id=1, pin="777", desired_hash="h",
                                         ok=True, error=None)
        sdk = _sdk()

        def _delete(*, table, data, options=""):
            if table == "user":
                raise PullSDKError("DeleteDeviceData failed rc=-2")
            return 0

        sdk.delete_device_data.side_effect = _delete
        eng, _sdk_used, r = self._revoke_sonia(sqlite_db, sdk=sdk)
        assert r is False
        assert eng._last_member_sync_outcome == "DELETE_FAILED"
        assert sqlite_db.get_device_sync_ownership_for_pin(device_id=1, pin="777") is True, (
            "erasing the row on a failed delete made every retry read 'not owned'")

    def test_unreadable_ownership_deletes_nothing_and_is_not_a_skip(self, sqlite_db, monkeypatch):
        import app.core.device_sync as ds

        def _boom(**kw):
            raise RuntimeError("database is locked")

        monkeypatch.setattr(ds, "get_device_sync_ownership_for_pin", _boom)
        eng, sdk, r = self._revoke_sonia(sqlite_db)
        assert _deleted_pins(sdk) == [] and r is False
        assert eng._last_member_sync_outcome == "OWNERSHIP_UNREADABLE", (
            "cannot tell != proven not ours: the revocation stays pending")

    def test_the_gate_is_scheme_independent(self, sqlite_db, warns):
        """MEMBERSHIP too: 'never delete an unowned user' is not conditional on a setting."""
        eng, sdk, r = self._revoke_sonia(sqlite_db, scheme="MEMBERSHIP")
        assert _deleted_pins(sdk) == [] and r is False
        assert eng._last_member_sync_outcome == "SKIPPED_NOT_OWNED"
        sqlite_db.save_device_sync_state(device_id=1, pin="5", desired_hash="h", ok=True, error=None)
        eng2 = _engine()
        sdk2 = _sdk()
        assert eng2.sync_member_on_connected_sdk(
            sdk=sdk2, device=_pullsdk_device(), member_id=5, revocation=True) is True
        assert _removed_pins(sdk2) == {"5"}, "control: an owned MEMBERSHIP pin is still removed"


class TestPullSdkCallersTreatASkipAsFinished:
    """The ULTRA worker reads the bool as 'revocation done'. A skip returns False (never
    a false success) but must NOT re-queue forever."""

    class _Engine:
        outcome = "SKIPPED_NOT_OWNED"

        def __init__(self, cfg, logger):
            self._last_single_device_error = ""
            self._last_member_sync_outcome = None
            self.full_calls = 0

        def sync_member_on_connected_sdk(self, *, sdk, device, member_id, source, revocation=False):
            self._last_member_sync_outcome = type(self).outcome
            return False

        def run_one_device_on_connected_sdk(self, *, sdk, cache, device, source, changed_ids):
            self.full_calls += 1
            return True

    def _worker(self, monkeypatch):
        import queue
        import threading

        w = ue.UltraDeviceWorker(
            device={"id": 5, "name": "Door 1", "ipAddress": "10.0.0.5", "portNumber": 4370},
            settings={}, popup_q=queue.Queue(), history_q=queue.Queue(),
            stop_event=threading.Event(),
        )
        w._connected = True
        w._sdk = SimpleNamespace(owns_event_source=False, _sdk="raw-sdk")
        w._on_full_sync_finished = MagicMock()
        monkeypatch.setattr(ue, "load_sync_cache",
                            lambda: SimpleNamespace(users=[{"activeMembershipId": 99}], devices=[]))
        monkeypatch.setattr("app.core.device_sync.DeviceSyncEngine", self._Engine)
        return w

    def test_targeted_skip_releases_the_revocation(self, monkeypatch):
        w = self._worker(monkeypatch)
        w.request_full_sync = MagicMock()
        assert w.request_member_revoke(41) is True
        assert w._drain_member_sync_commands(limit=1) == 1
        assert list(w._pending_member_syncs) == []
        assert w._pending_member_revoke_ids == set()
        assert w._active_member_revoke_ids == set()
        w.request_full_sync.assert_not_called()

    def test_full_sync_skip_does_not_fail_the_pass(self, monkeypatch):
        w = self._worker(monkeypatch)
        w.request_full_sync(reason="fast_patch_bundle", fingerprint_hash="h", revoked_ids={41})
        assert w._drain_full_sync_commands(limit=1) == 1
        kw = w._on_full_sync_finished.call_args.kwargs
        assert kw["ok"] is True and kw["fingerprint_hash"] == "h"
        assert "revoked_ids" not in kw, "nothing left for the scheduler to re-queue"

    def test_an_unreadable_outcome_still_retries(self, monkeypatch):
        w = self._worker(monkeypatch)
        monkeypatch.setattr(self._Engine, "outcome", "OWNERSHIP_UNREADABLE")
        w.request_full_sync(reason="fast_patch_bundle", fingerprint_hash="h", revoked_ids={41})
        assert w._drain_full_sync_commands(limit=1) == 1
        kw = w._on_full_sync_finished.call_args.kwargs
        assert kw["ok"] is False and kw["revoked_ids"] == {41}


# ═════════════════════════ item 4: ZK_STANDALONE ═════════════════════════

class TestStandaloneUnownedRevocationNeverBlocksThePass:

    @pytest.mark.parametrize("seed", ["unconfirmed_row", "no_row"])
    def test_the_pass_pushes_removes_the_owned_and_skips_the_unowned(
            self, monkeypatch, fstate, warns, seed):
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "active", "")])
        fstate.rows["30002"] = ("old-hash", True, {0})       # an OWNED departed member
        if seed == "unconfirmed_row":
            fstate.rows["34439"] = ("attempted-hash", False, None)
        result = _authoritative_full_sync(w, 34439)

        assert "30001" in {u["pin"] for c in drv.push_calls for u in c["users"]}, (
            "the rest of the roster is pushed")
        assert drv.delete_calls == [["30002"]], "the owned departed member is removed"
        assert all("34439" not in c for c in drv.delete_calls), "never the unowned pin"
        assert not any(u["pin"] == "34439" for c in drv.push_calls for u in c["users"]), (
            "and it is not neutralised either")
        assert result["ok"] is True and result["fingerprint_hash"] == "revoked-hash"
        assert "revoked_ids" not in result
        assert w._full_sync_revocation_phase == {}
        [skip] = _skips(warns)
        assert skip["pin"] == "34439"
        assert "SKIPPED_NOT_OWNED" in (w._push_batch_updates[-1].get("error_message") or "")

    def test_a_skip_is_not_picked_up_again_by_the_next_sync(self, monkeypatch, fstate, warns):
        w, _c = _worker(monkeypatch, driver=RevokeDriver(), users=[_user(30001, "active", "")])
        _authoritative_full_sync(w, 34439)
        w.request_full_sync(reason="timer", fingerprint_hash="h2")
        assert w._pending_full_sync_request["revoked_ids"] == set()

    def test_unreadable_ownership_still_fails_closed(self, monkeypatch, fstate):
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "active", "")])
        monkeypatch.setattr(dbmod, "list_confirmed_device_sync_pins",
                            MagicMock(side_effect=RuntimeError("db unavailable")))
        result = _authoritative_full_sync(w, 34439)
        assert result["ok"] is False and result["revoked_ids"] == {34439}
        assert drv.delete_calls == []

    def test_an_above_ceiling_abort_still_leaves_the_revocation_pending(self, monkeypatch, fstate):
        """REVOKE_ABORTED is retryable, never final: the explicit revocation stays
        unconfirmed and the scheduler re-queues it."""
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "active", "")])
        for i in range(50):
            fstate.rows[str(40000 + i)] = ("old-hash", True, {0})
        result = _authoritative_full_sync(w, 40000)
        assert result["ok"] is False and result["revoked_ids"] == {40000}
        assert drv.delete_calls == []

    def test_targeted_revoke_of_an_unowned_pin_is_finished_not_escalated(
            self, monkeypatch, fstate, warns):
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[])
        full_sync = MagicMock(return_value=True)
        monkeypatch.setattr(w, "request_full_sync", full_sync)
        assert w._run_standalone_member_revoke(34439) is True
        assert drv.delete_calls == [] and drv.push_calls == []
        full_sync.assert_not_called()
        assert [s["pin"] for s in _skips(warns)] == ["34439"]

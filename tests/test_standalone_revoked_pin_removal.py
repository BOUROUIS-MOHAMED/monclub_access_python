"""A member who LEAVES the roster must lose access on the terminal.

FIELD REPORT, Oxyfit 2026-09-06. The operator set his membership to CANCELED,
then COMPLETED, INACTIVE, PENDING and EXPIRED in turn, and **kept opening the
turnstile every time**.

The backend is right: shouldExposeMembership (AccessPatchBundleService:449)
rejects any status that is not ACTIVE, plus unavailable / not-yet-started /
ended / frozen memberships, and emits entityDelete("ACTIVE_MEMBERSHIP", id). The
member correctly disappears from sync_users.

The client then did NOTHING to the device. The only device-side removal in the
standalone engine is _maybe_mirror_reconcile -> delete_users, which returns
immediately unless rosterPushingPolicy == "MIRROR" -- and PRESERVE is the default
that every gym runs. prune_device_sync_state then deleted the local record of the
departed pin, destroying the very information needed to clear it later.

On a ZK_STANDALONE terminal the device decides and opens; the PC only observes
(rtlog "reason=DEVICE_ALLOWED"). There is no PC-side veto. So leaving the
credential on the terminal IS granting access. A cancelled member kept entering
indefinitely.

DELETE, WITH NEUTRALISE AS THE FALLBACK
---------------------------------------
The departed pin is DELETED outright: delete_users -> SSR_DeleteEnrollData(1, pin, 12).
The vendor manual defines backupNumber 12 as "delete the user (including all
fingerprints, card numbers and passwords)", and the operator ran exactly that
against the live MB2000 through tools/mb2000_scripts/13_inspect_and_clear_tables.ps1
on 2026-09-06 and cleared the users and fingerprint tables successfully — which is
what finally retired the [UNKNOWN] on backup number 12.

A delete that FAILS for a pin still has to end in no access, so those pins fall
back to being neutralised (blank card, no fingers, enabled=False). The fallback is
targeted at the pins that actually failed: SSR_SetUserInfo auto-creates, so
neutralising a pin that WAS deleted would resurrect it as an empty row.

WHY THIS CANNOT TOUCH THE OTHER SYSTEM'S MEMBERS
------------------------------------------------
The revocation set is drawn from device_sync_state -- pins THIS app pushed. At
Oxyfit the terminal also holds ~930 users belonging to a second, non-MonClub
access system. They were never in device_sync_state, so they can never be
selected. That ownership rule is what makes this safe where MIRROR is not.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

import app.core.db as dbmod
import app.core.ultra_engine as ue

from tests.test_standalone_incremental_sync import _tpl, _user, _worker, _full_sync
from tests.test_standalone_finger_removal_state import FingerState, fstate  # noqa: F401


class RevokeDriver:
    """Records push_roster and delete_users. `fail_delete` names pins whose
    SSR_DeleteEnrollData is to be reported as failed."""
    owns_event_source = True

    def __init__(self, fail_delete: set[str] | None = None):
        self.push_calls: List[dict] = []
        self.delete_calls: List[List[str]] = []
        self._fail_delete = set(fail_delete or ())

    def delete_users(self, pins, *, timeout_sec: float = 300.0):
        pins = [str(p) for p in pins]
        self.delete_calls.append(list(pins))
        failed = [p for p in pins if p in self._fail_delete]
        return {"ok": not failed, "deleted": len(pins) - len(failed),
                "failed": len(failed), "failed_pins": failed, "errors": []}

    def push_roster(self, users, templates_by_pin=None, *, remove_fingers_by_pin=None,
                    bracket_enable_device=False, **kw):
        self.push_calls.append({
            "users": [dict(u) for u in users],
            "templates": dict(templates_by_pin or {}),
            "removals": {k: sorted(v) for k, v in (remove_fingers_by_pin or {}).items()},
        })
        removals = sum(len(v) for v in (remove_fingers_by_pin or {}).values())
        return {"ok": True, "pushed": len(users), "failed": 0, "templates_failed": 0,
                "skipped_pin": 0, "chunks_wedged": 0, "errors": [], "failed_pins": [],
                "del_attempted": removals, "del_ok": removals}


class FailingFallbackDriver(RevokeDriver):
    """Records the neutralise attempt but reports that it did not land."""

    def push_roster(self, users, templates_by_pin=None, *, remove_fingers_by_pin=None,
                    bracket_enable_device=False, **kw):
        success = super().push_roster(
            users,
            templates_by_pin,
            remove_fingers_by_pin=remove_fingers_by_pin,
            bracket_enable_device=bracket_enable_device,
            **kw,
        )
        if users and all(user.get("enabled") is False for user in users):
            return {"ok": False}
        return success


class ContractDriver(RevokeDriver):
    """Returns caller-supplied device contracts while retaining call evidence."""

    def __init__(self, *, delete_result=None, fallback_by_pin=None,
                 delete_raises=False, fallback_raises_for=None):
        super().__init__()
        self.delete_result = delete_result
        self.fallback_by_pin = dict(fallback_by_pin or {})
        self.delete_raises = delete_raises
        self.fallback_raises_for = set(fallback_raises_for or ())

    def delete_users(self, pins, *, timeout_sec: float = 300.0):
        pins = [str(p) for p in pins]
        self.delete_calls.append(pins)
        if self.delete_raises:
            raise RuntimeError("delete boom")
        return self.delete_result

    def push_roster(self, users, templates_by_pin=None, *, remove_fingers_by_pin=None,
                    bracket_enable_device=False, **kw):
        super().push_roster(
            users,
            templates_by_pin,
            remove_fingers_by_pin=remove_fingers_by_pin,
            bracket_enable_device=bracket_enable_device,
            **kw,
        )
        pin = str(users[0]["pin"])
        if pin in self.fallback_raises_for:
            raise RuntimeError("push boom")
        return self.fallback_by_pin.get(pin, {"ok": False})


def _revoked_push(drv: RevokeDriver) -> dict | None:
    """The push whose users are all disabled -- the neutralise pass."""
    for call in drv.push_calls:
        if call["users"] and all(u.get("enabled") is False for u in call["users"]):
            return call
    return None


def _fallback_success(*, slots: int) -> dict:
    return {
        "ok": True,
        "pushed": 1,
        "failed": 0,
        "templates_failed": 0,
        "skipped_pin": 0,
        "chunks_wedged": 0,
        "failed_pins": [],
        "del_attempted": slots,
        "del_ok": slots,
    }


def _authoritative_full_sync(w, member_id: int, *, fingerprint_hash: str = "revoked-hash") -> dict:
    assert w.request_full_sync(
        reason="fast_patch_bundle",
        fingerprint_hash=fingerprint_hash,
        revoked_ids={member_id},
    ) is True
    assert w._drain_full_sync_commands(limit=1) == 1
    assert w._pending_full_sync_request is None
    return w._on_full_sync_finished.call_args.kwargs


@pytest.fixture
def tracked_revocation_state(monkeypatch, fstate):
    mirrors = {"34439"}

    def clear_both(*, device_id, pin):
        fstate.delete(device_id=device_id, pin=pin)
        mirrors.discard(str(pin))

    # Keep the pre-fix two-call implementation isolated from the real local DB,
    # while making the new transactional seam observable too.
    monkeypatch.setattr(dbmod, "delete_device_mirror_pin",
                        lambda *, device_id, pin: mirrors.discard(str(pin)))
    monkeypatch.setattr(dbmod, "clear_device_revocation_state", clear_both, raising=False)
    return mirrors


class TestRemovalResultContract:

    @pytest.mark.parametrize("delete_result", [
        None,
        {},
        {"ok": True},
        {"ok": True, "deleted": 1, "failed": 0},
        {"ok": True, "deleted": 0, "failed": 1, "failed_pins": []},
        {"ok": True, "deleted": 1, "failed": 0, "failed_pins": ["34439"]},
        {"ok": False, "deleted": 1, "failed": 1, "failed_pins": ["34439"]},
        {"ok": False, "deleted": 0, "failed": 1, "failed_pins": ["foreign"]},
        {"ok": "yes", "deleted": 1, "failed": 0, "failed_pins": []},
        {"ok": False, "deleted": 0, "failed": "1", "failed_pins": ["34439"]},
        {"ok": False, "deleted": 0, "failed": 1, "failed_pins": "34439"},
    ])
    def test_ambiguous_delete_result_confirms_no_hard_deletion(self, monkeypatch,
                                                               delete_result):
        drv = ContractDriver(delete_result=delete_result)
        w, _c = _worker(monkeypatch, driver=drv, users=[])

        outcome = w._remove_standalone_pins(
            pins=["34439"], pushed_fingers={"34439": {0, 2}},
        )

        assert outcome.deleted == frozenset()
        assert outcome.neutralised == frozenset()
        assert outcome.failed == frozenset({"34439"})
        assert len(drv.push_calls) == 1, "ambiguous deletion must enter fallback"

    def test_consistent_partial_delete_is_attributed_per_pin(self, monkeypatch):
        drv = ContractDriver(
            delete_result={
                "ok": False,
                "deleted": 1,
                "failed": 1,
                "failed_pins": ["34440"],
            },
            fallback_by_pin={"34440": {"ok": False}},
        )
        w, _c = _worker(monkeypatch, driver=drv, users=[])

        outcome = w._remove_standalone_pins(
            pins=["34439", "34440"],
            pushed_fingers={"34439": {0}, "34440": {1}},
        )

        assert outcome.deleted == frozenset({"34439"})
        assert outcome.neutralised == frozenset()
        assert outcome.failed == frozenset({"34440"})

    def test_fallback_requires_every_expected_slot_clear_to_be_confirmed(self, monkeypatch):
        drv = ContractDriver(
            delete_result={
                "ok": False, "deleted": 0, "failed": 1,
                "failed_pins": ["34439"],
            },
            fallback_by_pin={"34439": {
                **_fallback_success(slots=2),
                "del_ok": 1,
            }},
        )
        w, _c = _worker(monkeypatch, driver=drv, users=[])

        outcome = w._remove_standalone_pins(
            pins=["34439"], pushed_fingers={"34439": {0, 2}},
        )

        assert outcome.neutralised == frozenset()
        assert outcome.failed == frozenset({"34439"})

    def test_partial_fallback_success_is_attributed_per_pin(self, monkeypatch):
        drv = ContractDriver(
            delete_result={
                "ok": False, "deleted": 0, "failed": 2,
                "failed_pins": ["34439", "34440"],
            },
            fallback_by_pin={
                "34439": _fallback_success(slots=2),
                "34440": {**_fallback_success(slots=1), "ok": False,
                            "failed_pins": ["34440"], "del_ok": 0},
            },
        )
        w, _c = _worker(monkeypatch, driver=drv, users=[])

        outcome = w._remove_standalone_pins(
            pins=["34439", "34440"],
            pushed_fingers={"34439": {0, 2}, "34440": {1}},
        )

        assert outcome.deleted == frozenset()
        assert outcome.neutralised == frozenset({"34439"})
        assert outcome.failed == frozenset({"34440"})

    def test_delete_exception_uses_confirmed_fallback(self, monkeypatch):
        drv = ContractDriver(
            delete_raises=True,
            fallback_by_pin={"34439": _fallback_success(slots=2)},
        )
        w, _c = _worker(monkeypatch, driver=drv, users=[])

        outcome = w._remove_standalone_pins(
            pins=["34439"], pushed_fingers={"34439": {0, 2}},
        )

        assert outcome.neutralised == frozenset({"34439"})
        assert outcome.failed == frozenset()

    def test_delete_and_push_exceptions_confirm_nothing(self, monkeypatch):
        drv = ContractDriver(delete_raises=True, fallback_raises_for={"34439"})
        w, _c = _worker(monkeypatch, driver=drv, users=[])

        outcome = w._remove_standalone_pins(
            pins=["34439"], pushed_fingers={"34439": {0, 2}},
        )

        assert outcome.deleted == frozenset()
        assert outcome.neutralised == frozenset()
        assert outcome.failed == frozenset({"34439"})


class TestImmediateAuthoritativeRevoke:

    def test_owned_pin_is_deleted_immediately_and_local_state_is_removed(
            self, monkeypatch, fstate, tracked_revocation_state):
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[])
        fstate.rows["34439"] = ("old-hash", True, {0, 2})
        telemetry = MagicMock()
        monkeypatch.setattr(ue._tel, "event", telemetry)

        assert w._run_standalone_member_revoke(34439) is True

        assert drv.delete_calls == [["34439"]]
        assert _revoked_push(drv) is None
        assert "34439" not in fstate.rows
        assert "34439" not in tracked_revocation_state
        done = next(
            call for call in telemetry.call_args_list
            if call.args and call.args[0] == "MEMBER_REVOKE_DONE"
        )
        assert done.kwargs["mode"] == "deleted"

    def test_failed_delete_neutralises_only_the_owned_pin_and_removes_local_state(
            self, monkeypatch, fstate, tracked_revocation_state):
        drv = RevokeDriver(fail_delete={"34439"})
        w, _c = _worker(monkeypatch, driver=drv, users=[])
        fstate.rows["34439"] = ("old-hash", True, {0, 2})
        telemetry = MagicMock()
        monkeypatch.setattr(ue._tel, "event", telemetry)

        assert w._run_standalone_member_revoke(34439) is True

        assert drv.delete_calls == [["34439"]]
        assert _revoked_push(drv) == {
            "users": [{"pin": "34439", "name": "", "card": "", "enabled": False}],
            "templates": {},
            "removals": {"34439": [0, 2]},
        }
        assert "34439" not in fstate.rows
        assert "34439" not in tracked_revocation_state
        done = next(
            call for call in telemetry.call_args_list
            if call.args and call.args[0] == "MEMBER_REVOKE_DONE"
        )
        assert done.kwargs["mode"] == "neutralised"

    def test_unowned_pin_is_not_touched_and_requests_full_reconciliation(
            self, monkeypatch, fstate):
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[])
        full_sync = MagicMock(return_value=True)
        monkeypatch.setattr(w, "request_full_sync", full_sync)
        telemetry = MagicMock()
        monkeypatch.setattr(ue._tel, "warn", telemetry)

        assert w._run_standalone_member_revoke(34439) is False

        assert drv.delete_calls == []
        assert drv.push_calls == []
        full_sync.assert_called_once_with(
            reason="revoke-ownership-missing",
            revoked_ids={34439},
        )
        assert any(
            call.args and call.args[0] == "MEMBER_REVOKE_OWNERSHIP_MISSING"
            for call in telemetry.call_args_list
        )

    def test_total_failure_keeps_local_state_and_requests_full_reconciliation(
            self, monkeypatch, fstate, tracked_revocation_state):
        drv = FailingFallbackDriver(fail_delete={"34439"})
        w, _c = _worker(monkeypatch, driver=drv, users=[])
        fstate.rows["34439"] = ("old-hash", True, {0, 2})
        full_sync = MagicMock(return_value=True)
        monkeypatch.setattr(w, "request_full_sync", full_sync)

        assert w._run_standalone_member_revoke(34439) is False

        assert drv.delete_calls == [["34439"]]
        assert _revoked_push(drv) is not None
        assert "34439" in fstate.rows
        assert "34439" in tracked_revocation_state
        full_sync.assert_called_once_with(
            reason="revoke-failed",
            revoked_ids={34439},
        )

    def test_atomic_local_cleanup_failure_retains_both_records_and_retries(
            self, monkeypatch, fstate, tracked_revocation_state):
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[])
        fstate.rows["34439"] = ("old-hash", True, {0, 2})
        monkeypatch.setattr(
            dbmod,
            "clear_device_revocation_state",
            MagicMock(side_effect=RuntimeError("db boom")),
            raising=False,
        )
        full_sync = MagicMock(return_value=True)
        monkeypatch.setattr(w, "request_full_sync", full_sync)
        telemetry = MagicMock()
        monkeypatch.setattr(ue._tel, "event", telemetry)
        warnings = MagicMock()
        monkeypatch.setattr(ue._tel, "warn", warnings)

        assert w._run_standalone_member_revoke(34439) is False

        assert "34439" in fstate.rows
        assert "34439" in tracked_revocation_state
        full_sync.assert_called_once_with(
            reason="revoke-failed",
            revoked_ids={34439},
        )
        assert not any(
            call.args and call.args[0] == "MEMBER_REVOKE_DONE"
            for call in telemetry.call_args_list
        )
        assert any(
            call.args and call.args[0] == "MEMBER_REVOKE_FAILED"
            for call in warnings.call_args_list
        )


class TestAuthoritativeFullSyncRetry:

    @staticmethod
    def _assert_unconfirmed(result: dict, member_id: int) -> None:
        assert result["ok"] is False
        assert result["fingerprint_hash"] is None
        assert result["revoked_ids"] == {member_id}

    def test_empty_roster_guard_requeues_explicit_revocation_without_advancing_hash(
            self, monkeypatch, fstate):
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(34439, "revoked", "")])
        fstate.rows["34439"] = ("old-hash", True, {0})

        result = _authoritative_full_sync(w, 34439)

        self._assert_unconfirmed(result, 34439)
        assert drv.delete_calls == []
        assert w._on_full_sync_finished.call_count == 1

    def test_unreadable_ownership_requeues_explicit_revocation_without_advancing_hash(
            self, monkeypatch, fstate):
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "active", "")])
        monkeypatch.setattr(
            dbmod,
            "list_device_sync_hashes_and_status",
            MagicMock(side_effect=RuntimeError("db unavailable")),
        )

        result = _authoritative_full_sync(w, 34439)

        self._assert_unconfirmed(result, 34439)
        assert drv.delete_calls == []
        assert w._on_full_sync_finished.call_count == 1

    def test_bulk_safety_refusal_requeues_explicit_revocation_without_advancing_hash(
            self, monkeypatch, fstate):
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "active", "")])
        for i in range(50):
            fstate.rows[str(40000 + i)] = ("old-hash", True, {0})

        result = _authoritative_full_sync(w, 40000)

        self._assert_unconfirmed(result, 40000)
        assert drv.delete_calls == []
        assert w._on_full_sync_finished.call_count == 1

    def test_removal_failure_requeues_explicit_revocation_without_advancing_hash(
            self, monkeypatch, fstate):
        drv = FailingFallbackDriver(fail_delete={"34439"})
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "active", "")])
        fstate.rows["34439"] = ("old-hash", True, {0})

        result = _authoritative_full_sync(w, 34439)

        self._assert_unconfirmed(result, 34439)
        assert "34439" in fstate.rows
        assert w._on_full_sync_finished.call_count == 1

    def test_local_cleanup_failure_requeues_explicit_revocation_without_advancing_hash(
            self, monkeypatch, fstate, tracked_revocation_state):
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "active", "")])
        fstate.rows["34439"] = ("old-hash", True, {0})
        monkeypatch.setattr(
            dbmod,
            "clear_device_revocation_state",
            MagicMock(side_effect=RuntimeError("db unavailable")),
            raising=False,
        )

        result = _authoritative_full_sync(w, 34439)

        self._assert_unconfirmed(result, 34439)
        assert "34439" in fstate.rows
        assert w._on_full_sync_finished.call_count == 1

    def test_missing_cache_requeues_explicit_revocation_without_advancing_hash(
            self, monkeypatch, fstate):
        w, _c = _worker(monkeypatch, driver=RevokeDriver(), users=[])
        monkeypatch.setattr(ue, "load_sync_cache", lambda: None)

        result = _authoritative_full_sync(w, 34439)

        self._assert_unconfirmed(result, 34439)
        assert w._on_full_sync_finished.call_count == 1

    def test_scheduler_retry_eventually_succeeds_after_ownership_becomes_available(
            self, monkeypatch, fstate, tracked_revocation_state):
        drv = RevokeDriver()
        w, _c = _worker(
            monkeypatch,
            driver=drv,
            users=[_user(30001, "active", ""), _user(34439, "revoked", "")],
        )
        scheduler = ue.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())
        w._on_full_sync_finished = scheduler._handle_worker_full_sync_finished

        assert w.request_full_sync(
            reason="fast_patch_bundle",
            fingerprint_hash="blocked-hash",
            revoked_ids={34439},
        ) is True
        assert w._drain_full_sync_commands(limit=1) == 1
        assert scheduler._drain_pending_sync_request() == (
            None,
            {34439},
            {9},
            "fast_patch_bundle",
        )

        fstate.rows["34439"] = ("old-hash", True, {0})
        assert w.request_member_revoke(34439) is True
        assert w.request_full_sync(
            reason="fast_patch_bundle",
            fingerprint_hash="retry-hash",
            revoked_ids={34439},
        ) is True
        assert w._drain_member_sync_commands(limit=1) == 0
        assert w._drain_full_sync_commands(limit=1) == 1

        assert drv.delete_calls == [["34439"]]
        assert scheduler._last_hash[9] == "retry-hash"
        assert scheduler._drain_pending_sync_request() is None

    def test_failed_full_sync_keeps_worker_protection_until_scheduler_redelivery(
            self, monkeypatch, fstate):
        drv = RevokeDriver()
        w, _c = _worker(
            monkeypatch,
            driver=drv,
            users=[_user(30001, "active", ""), _user(34439, "revoked", "")],
        )
        drv.push_roster = MagicMock(return_value={
            "ok": False,
            "pushed": 0,
            "failed": 1,
            "templates_failed": 0,
            "skipped_pin": 0,
            "chunks_wedged": 0,
            "errors": ["push failed"],
            "failed_pins": ["30001"],
        })
        scheduler = ue.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())
        w._on_full_sync_finished = scheduler._handle_worker_full_sync_finished
        w._confirmed_member_revoke_ids.add(34439)

        assert w.request_full_sync(
            reason="fast_patch_bundle",
            fingerprint_hash="failed-hash",
            revoked_ids={34439},
        ) is True
        assert w._drain_full_sync_commands(limit=1) == 1

        assert scheduler._pending_revoked_ids == {34439}
        assert w.request_member_sync(34439) is False
        assert w.has_pending_member_revoke(34439) is True
        assert w._confirmed_member_revoke_ids == {34439}
        assert list(w._pending_member_syncs) == []

    def test_scheduler_redelivery_during_failure_callback_adopts_retry_state(
            self, monkeypatch, fstate):
        drv = RevokeDriver()
        w, _c = _worker(
            monkeypatch,
            driver=drv,
            users=[_user(30001, "active", ""), _user(34439, "revoked", "")],
        )
        drv.push_roster = MagicMock(return_value={
            "ok": False,
            "pushed": 0,
            "failed": 1,
            "templates_failed": 0,
            "skipped_pin": 0,
            "chunks_wedged": 0,
            "errors": ["push failed"],
            "failed_pins": ["30001"],
        })
        scheduler = ue.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())
        redelivery: dict[str, bool] = {}

        def finish_and_redeliver(**kwargs):
            scheduler._handle_worker_full_sync_finished(**kwargs)
            changed_ids, revoked_ids, device_ids, reason = (
                scheduler._drain_pending_sync_request()
            )
            assert changed_ids is None
            assert device_ids == {9}
            redelivery["member"] = w.request_member_revoke(34439)
            redelivery["full"] = w.request_full_sync(
                reason=reason,
                fingerprint_hash="retry-hash",
                revoked_ids=revoked_ids,
            )

        w._on_full_sync_finished = finish_and_redeliver
        assert w.request_full_sync(
            reason="fast_patch_bundle",
            fingerprint_hash="failed-hash",
            revoked_ids={34439},
        ) is True

        assert w._drain_full_sync_commands(limit=1) == 1

        assert redelivery == {"member": True, "full": True}
        assert list(w._pending_member_syncs) == []
        assert w._pending_member_revoke_ids == set()
        assert w._pending_full_sync_request["revoked_ids"] == {34439}
        assert scheduler._drain_pending_sync_request() is None


class TestARevokedMemberLosesTheirCredentials:

    def test_a_member_who_leaves_the_roster_is_DELETED_from_the_device(
            self, monkeypatch, fstate):
        """The field case: membership set to CANCELED, so the member is gone."""
        drv = RevokeDriver()
        # roster no longer contains 34439 at all
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "someone else", "")])
        # ...but we pushed them before, with finger 0 and a card
        fstate.rows["34439"] = ("old-hash", True, {0})

        _full_sync(w)

        assert drv.delete_calls == [["34439"]], "the departed pin must be DELETED"
        assert _revoked_push(drv) is None, "a clean delete needs no neutralise fallback"

    def test_a_pin_the_delete_could_not_remove_falls_back_to_neutralise(
            self, monkeypatch, fstate):
        """A failed delete must still end in no access."""
        drv = RevokeDriver(fail_delete={"34439"})
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "a", "")])
        fstate.rows["34439"] = ("old-hash", True, {0})
        fstate.rows["34440"] = ("old-hash", True, {1})

        _full_sync(w)

        assert drv.delete_calls == [["34439", "34440"]]
        call = _revoked_push(drv)
        assert call is not None, "the pin that survived the delete must be neutralised"
        assert [u["pin"] for u in call["users"]] == ["34439"], (
            "only the FAILED pin -- SSR_SetUserInfo auto-creates, so neutralising a "
            "successfully deleted pin would resurrect it as an empty row"
        )
        assert call["removals"] == {"34439": [0]}
        assert call["users"][0]["card"] == ""
        assert call["users"][0]["enabled"] is False

    def test_pins_we_never_pushed_are_never_touched(self, monkeypatch, fstate):
        """Oxyfit: the terminal holds ~930 users from a SECOND access system. They
        are not in device_sync_state, so they must be invisible to this path."""
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "a", "")])
        fstate.rows["30001"] = ("h", True, set())     # the only pin we own

        _full_sync(w)

        assert drv.delete_calls == [], "nothing to revoke; the foreign pins are not ours"

    def test_a_member_still_in_the_roster_is_never_revoked(self, monkeypatch, fstate):
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv,
                        users=[_user(34439, "malek", "", [_tpl(0, "AAAA")])])
        fstate.rows["34439"] = ("old-hash", True, {0})

        _full_sync(w)

        assert drv.delete_calls == []

    def test_state_is_pruned_only_after_the_revoke_pass(
            self, monkeypatch, fstate, tracked_revocation_state):
        """prune_device_sync_state deletes the record of what we pushed. If it runs
        first, the finger ids are gone and a fallback could never clear the slot."""
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "a", "")])
        fstate.rows["34439"] = ("old-hash", True, {0})

        _full_sync(w)

        assert drv.delete_calls == [["34439"]]
        assert "34439" not in fstate.rows, "the departed pin's state must then be pruned"
        assert "34439" not in tracked_revocation_state


class TestSafetyRails:

    def test_an_empty_roster_never_revokes_anything(self, monkeypatch, fstate):
        """A failed or half-built sync must not be read as 'everyone left'."""
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[])
        for pin in ("30001", "30002", "30003"):
            fstate.rows[pin] = ("h", True, {0})

        _full_sync(w)

        assert drv.delete_calls == [] and _revoked_push(drv) is None

    def test_a_mass_departure_aborts_rather_than_revoking(self, monkeypatch, fstate):
        """Same percent floor MIRROR uses: refuse an implausible bulk revocation."""
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "a", "")])
        for i in range(50):                      # 50 departed vs a 1-member roster
            fstate.rows[str(40000 + i)] = ("h", True, {0})

        _full_sync(w)

        assert drv.delete_calls == [], "an implausible bulk revocation must abort"
        assert "40000" in fstate.rows, "and the state must NOT be pruned after an abort"

    def test_a_failed_push_does_not_trigger_revocation(self, monkeypatch, fstate):
        """Revocation runs only after a SUCCESSFUL push, like MIRROR."""
        class _Failing(RevokeDriver):
            def push_roster(self, users, templates_by_pin=None, **kw):
                super().push_roster(users, templates_by_pin, **kw)
                return {"ok": False, "pushed": 0, "failed": len(users),
                        "templates_failed": 0, "skipped_pin": 0, "chunks_wedged": 0,
                        "errors": ["boom"], "failed_pins": [str(u["pin"]) for u in users]}

        drv = _Failing()
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "a", "")])
        fstate.rows["34439"] = ("old-hash", True, {0})

        _full_sync(w)

        assert drv.delete_calls == []

    def test_revoke_telemetry_counts_only_confirmed_outcomes(
            self, monkeypatch, fstate, tracked_revocation_state):
        drv = FailingFallbackDriver(fail_delete={"34439"})
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "a", "")])
        fstate.rows["34439"] = ("old-hash", True, {0})
        telemetry = MagicMock()
        monkeypatch.setattr(ue._tel, "event", telemetry)

        _full_sync(w)

        done = next(
            call for call in telemetry.call_args_list
            if call.args and call.args[0] == "REVOKE_DONE"
        )
        assert done.kwargs["deleted"] == 0
        assert done.kwargs["neutralised"] == 0
        assert done.kwargs["slots"] == 0
        assert done.kwargs["ok"] is False
        assert "34439" in fstate.rows
        assert "34439" in tracked_revocation_state

"""P3b-2 step 5: add-only turnstiles, handovers and "Confirm removal" in the push engines.

A new driver (a lease just assigned, a forced handover) has no local proof that MonClub
wrote any pin on that turnstile. Before its ownership backup is restored, "not owned" proves
nothing: a departed member the previous driver pushed would be finalised SKIPPED_NOT_OWNED and
stay on the turnstile for good. So until the record is trusted every removal DEFERS (retryable,
state kept, prune skipped), pushes still run, and nothing is reported as REVOKE_ABORTED.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

import app.core.db as dbmod
import app.core.push_safety as ps
import app.core.telemetry as tel
from app.core.v2 import lease_gate as lg
from app.core.v2 import problems as pr
from tests.test_account_pin_device_sites import (  # noqa: F401  (fixture)
    _ali_gym, _cache, _deleted_pins, _engine, _pullsdk_device, _sdk, _sonia, sqlite_db,
)
from tests.test_standalone_finger_removal_state import FingerState, fstate  # noqa: F401
from tests.test_standalone_incremental_sync import _user, _worker
from tests.test_standalone_revoked_pin_removal import RevokeDriver, _authoritative_full_sync


@pytest.fixture(autouse=True)
def _clean():
    lg.reset_for_tests()
    pr.registry.reset_for_tests()
    yield
    lg.reset_for_tests()
    pr.registry.reset_for_tests()


@pytest.fixture
def warns(monkeypatch):
    seen = []
    monkeypatch.setattr(tel, "warn", lambda name, **f: seen.append((name, f)))
    return seen


def _lease(did, *, forced=False, restored=True, release=False):
    body = {"gymUsesAssignments": True, "role": "DRIVER", "readerOf": [], "drive": [], "release": []}
    if release:
        body["release"] = [{"gymDeviceId": did, "generation": 3, "newDriverPcId": 6}]
    else:
        body["drive"] = [{"gymDeviceId": did, "generation": 3, "state": "DRIVE", "handoverForced": forced}]
    lg.install(lg.snapshot_from_assignment(body, source="server", add_only=[] if restored else [did]))


def _names(warns):
    return [n for n, _f in warns]


# ------------------------------------------------------------------ the ceiling function

def test_an_add_only_turnstile_defers_every_removal_and_it_is_not_a_revoke_aborted(warns):
    _lease(8, restored=False)
    v = ps.check_bulk_removal(count=2, roster_count=100, path="standalone_revoke", device_id=8,
                              sample=["1", "2"])
    assert not v.allowed and v.reason == "add_only"
    assert "REMOVAL_DEFERRED" in _names(warns) and "REVOKE_ABORTED" not in _names(warns)
    assert pr.registry.snapshot(8) == [], "a deferral offers no Confirm-removal"


def test_a_turnstile_being_handed_over_defers_too():
    _lease(8, release=True)
    assert ps.check_bulk_removal(count=1, roster_count=100, path="stale", device_id=8,
                                 sample=["1"]).reason == "handover_release"


def test_without_assignments_the_ceiling_is_unchanged():
    assert ps.check_bulk_removal(count=2, roster_count=100, path="stale", device_id=8, sample=["1", "2"]).allowed
    v = ps.check_bulk_removal(count=30, roster_count=100, path="stale", device_id=8,
                              sample=[str(i) for i in range(30)])
    assert not v.allowed and v.reason == "above_ceiling"


def test_a_ceiling_refusal_is_recorded_with_every_pin_for_the_report():
    pins = [str(1000 + i) for i in range(30)]
    ps.check_bulk_removal(count=30, roster_count=100, path="standalone_revoke", device_id=8, sample=pins)
    [problem] = pr.registry.snapshot(8)
    assert problem["code"] == "REVOKE_ABORTED" and problem["count"] == 30 and problem["pins"] == sorted(pins)
    assert problem["reason"] == "above_ceiling" and problem["path"] == "standalone_revoke"
    assert problem["pinSetHash"] == pr.canonical_hash(pins)
    # The same step allowed later resolves it.
    ps.check_bulk_removal(count=1, roster_count=100, path="standalone_revoke", device_id=8, sample=["1"])
    assert pr.registry.snapshot(8) == []


def test_the_table_clear_and_the_renewal_release_are_never_confirmable():
    ps.check_bulk_removal(count=50, roster_count=10, path="table_clear", device_id=8)
    ps.check_bulk_removal(count=50, roster_count=10, path="renewal_release", device_id=8,
                          sample=[str(i) for i in range(50)])
    assert pr.registry.snapshot(8) == []


def test_a_confirm_removal_lets_exactly_that_list_through_once():
    pins = [str(1000 + i) for i in range(30)]
    pr.registry.approve_removal(8, pr.canonical_hash(pins), 30, expires_wall=__import__("time").time() + 60)
    other = pins[:-1] + ["9999"]
    assert not ps.check_bulk_removal(count=30, roster_count=100, path="stale", device_id=8, sample=other).allowed
    assert ps.check_bulk_removal(count=30, roster_count=100, path="stale", device_id=8, sample=pins).allowed
    assert not ps.check_bulk_removal(count=30, roster_count=100, path="stale", device_id=8, sample=pins).allowed, \
        "spent: one approval, one removal step"


def test_a_confirm_removal_never_empties_a_turnstile_on_an_empty_roster():
    pins = ["1", "2"]
    pr.registry.approve_removal(8, pr.canonical_hash(pins), 2, expires_wall=__import__("time").time() + 60)
    v = ps.check_bulk_removal(count=2, roster_count=0, path="stale", device_id=8, sample=pins)
    assert not v.allowed and v.reason == "empty_roster"


def test_an_expired_approval_is_not_used():
    pins = [str(i) for i in range(30)]
    pr.registry.approve_removal(8, pr.canonical_hash(pins), 30, expires_wall=__import__("time").time() - 1)
    assert not ps.check_bulk_removal(count=30, roster_count=100, path="stale", device_id=8, sample=pins).allowed


# ------------------------------------------------------------------ MB2000 full sync

def test_an_add_only_full_sync_pushes_but_removes_and_finalises_nothing(monkeypatch, fstate, warns):
    drv = RevokeDriver()
    w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "active", "")])
    _lease(w._device_id, restored=False)
    fstate.rows["30002"] = ("old-hash", True, {0})        # a departed member this PC owns
    result = _authoritative_full_sync(w, 34439)           # a revocation of a pin it cannot prove
    assert "30001" in {u["pin"] for c in drv.push_calls for u in c["users"]}, "adds still happen"
    assert drv.delete_calls == [], "no removal while the record is not trusted"
    assert "MEMBER_REVOKE_SKIPPED_NOT_OWNED" not in _names(warns), "never finalised as not owned"
    assert result["ok"] is False and result["revoked_ids"] == {34439}, "the revocation stays pending"
    assert "REVOKE_ABORTED" not in _names(warns)


def test_once_restored_the_same_pass_removes_the_owned_departed_member(monkeypatch, fstate, warns):
    drv = RevokeDriver()
    w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "active", "")])
    _lease(w._device_id, restored=True)
    fstate.rows["30002"] = ("old-hash", True, {0})
    _authoritative_full_sync(w, 34439)
    assert drv.delete_calls == [["30002"]]


def test_an_add_only_targeted_revoke_defers_and_never_finalises(monkeypatch, fstate, warns):
    drv = RevokeDriver()
    w, _c = _worker(monkeypatch, driver=drv, users=[])
    _lease(w._device_id, forced=True)
    full_sync = MagicMock(return_value=True)
    monkeypatch.setattr(w, "request_full_sync", full_sync)
    assert w._run_standalone_member_revoke(34439) is False
    assert drv.delete_calls == [] and drv.push_calls == []
    full_sync.assert_called_once()
    assert "MEMBER_REVOKE_SKIPPED_NOT_OWNED" not in _names(warns)


def test_a_turnstile_being_handed_over_takes_no_write(monkeypatch, fstate):
    drv = RevokeDriver()
    w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "active", "")])
    _lease(w._device_id, release=True)
    assert w.request_full_sync(reason="timer", fingerprint_hash="h") is True
    assert w._drain_full_sync_commands(limit=1) == 0
    assert w._pending_full_sync_request is not None, "kept queued, not dropped"
    assert drv.push_calls == []
    lg.reset_for_tests()                                  # the handover is cancelled
    assert w._drain_full_sync_commands(limit=1) == 1


def test_vacated_finger_slots_are_not_cleared_on_an_add_only_turnstile(monkeypatch, fstate):
    w, _c = _worker(monkeypatch, driver=RevokeDriver(), users=[])
    _lease(w._device_id, restored=False)
    assert w._standalone_removals(to_push=[{"pin": "1"}], templates_by_pin={}, pushed_fingers={"1": [0, 3]}) == {}


# ------------------------------------------------------------------ PullSDK targeted revoke

def test_a_pullsdk_add_only_revoke_is_deferred_not_skipped(sqlite_db, warns):
    _cache(sqlite_db, [_ali_gym(), _sonia()])
    _cache(sqlite_db, [], valid_ids=[31000])
    _lease(1, restored=False)
    sdk = _sdk()
    eng = _engine()
    r = eng.sync_member_on_connected_sdk(sdk=sdk, device=_pullsdk_device(pinScheme="ACCOUNT"), member_id=5,
                                         revocation=True)
    assert r is False and eng._last_member_sync_outcome == "DEFERRED"
    assert _deleted_pins(sdk) == []
    assert "MEMBER_REVOKE_SKIPPED_NOT_OWNED" not in _names(warns)

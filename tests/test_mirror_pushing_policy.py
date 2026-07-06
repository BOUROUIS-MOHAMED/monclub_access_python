"""MIRROR pushing-policy reconcile guards (UltraDeviceWorker._maybe_mirror_reconcile).

MIRROR deletes users off a LIVE turnstile, so these tests pin every guard. The
worker is built via object.__new__ (no COM / no threads) with only the attributes
the reconcile touches; the db ack/mirror helpers are monkeypatched.
"""
from __future__ import annotations

from typing import Any, Dict, List

import pytest

from app.core.ultra_engine import UltraDeviceWorker


class FakeDriver:
    """Minimal ZK_STANDALONE driver surface the reconcile calls."""

    def __init__(self, device_pins: List[str], list_ok: bool = True):
        self._device_pins = [str(p) for p in device_pins]
        self._list_ok = list_ok
        self.list_calls = 0
        self.deleted: List[str] | None = None

    def list_device_users(self, **_kw) -> Dict[str, Any]:
        self.list_calls += 1
        if not self._list_ok:
            return {"ok": False, "users": [], "error": "enumeration failed"}
        return {"ok": True, "users": [{"pin": p} for p in self._device_pins]}

    def delete_users(self, pins, **_kw) -> Dict[str, Any]:
        self.deleted = list(pins)
        return {"ok": True, "deleted": len(pins), "failed": 0, "errors": []}


class PullSDKishDriver:
    """A driver WITHOUT the enumerate/delete primitives (like PullSDKDevice)."""
    def __init__(self):
        self.deleted = None


def _make_worker(*, policy="MIRROR", device_pins=None, list_ok=True,
                 capabilities=None, recent=None, sdk=None):
    w = object.__new__(UltraDeviceWorker)
    w._device = {"id": 9, "rosterPushingPolicy": policy, "deviceCapabilities": capabilities}
    w._sdk = sdk if sdk is not None else FakeDriver(device_pins or [], list_ok=list_ok)
    w._tel_wid = "TEST:9"
    w._device_id = 9
    w._prefix = "[TEST:9]"
    w._recent_member_push = dict(recent or {})
    return w


def _roster(pins):
    return [{"pin": str(p)} for p in pins]


@pytest.fixture(autouse=True)
def _patch_db(monkeypatch):
    """Default: armed + no-op plan/record/mirror-delete. Individual tests override armed."""
    monkeypatch.setattr("app.core.db.mirror_reconcile_is_armed", lambda **kw: True)
    monkeypatch.setattr("app.core.db.mirror_reconcile_record_plan", lambda **kw: None)
    monkeypatch.setattr("app.core.db.delete_device_mirror_pin", lambda **kw: None)


# --------------------------------------------------------------------------- #
# The mandatory rail + the policy/reason/capability gates
# --------------------------------------------------------------------------- #

def test_empty_roster_never_deletes():
    """MANDATORY: an empty roster must never wipe the device."""
    w = _make_worker(device_pins=["40000", "40001"])
    w._maybe_mirror_reconcile(reason="user-sync", roster_users=_roster([]))
    assert w._sdk.deleted is None
    assert w._sdk.list_calls == 0  # bailed before even listing


def test_preserve_policy_is_noop():
    w = _make_worker(policy="PRESERVE", device_pins=["40000"])
    w._maybe_mirror_reconcile(reason="user-sync", roster_users=_roster(["117"]))
    assert w._sdk.deleted is None and w._sdk.list_calls == 0


def test_null_policy_is_noop():
    w = _make_worker(policy=None, device_pins=["40000"])
    w._maybe_mirror_reconcile(reason="user-sync", roster_users=_roster(["117"]))
    assert w._sdk.deleted is None


def test_reason_gate_blocks_non_full_reasons():
    w = _make_worker(device_pins=["40000"])
    w._maybe_mirror_reconcile(reason="timer-refresh", roster_users=_roster(["117"]))
    assert w._sdk.deleted is None and w._sdk.list_calls == 0


def test_pullsdk_driver_without_primitives_is_noop():
    w = _make_worker(sdk=PullSDKishDriver())
    w._maybe_mirror_reconcile(reason="user-sync", roster_users=_roster(["117"]))
    assert w._sdk.deleted is None


def test_list_failure_never_deletes():
    """A failed enumeration must NOT be read as an empty device."""
    w = _make_worker(device_pins=["40000", "40001"], list_ok=False)
    w._maybe_mirror_reconcile(reason="user-sync", roster_users=_roster(["117"]))
    assert w._sdk.deleted is None


# --------------------------------------------------------------------------- #
# Diff, protection, floor, dry-run, happy path
# --------------------------------------------------------------------------- #

def test_protected_floor_and_allowlist_excluded():
    # device: 117 (in roster), 40001 (extra), 95000 (>= floor -> protected),
    #         50000 (allowlisted). roster: 117 + filler so the %-floor allows 1 delete.
    w = _make_worker(
        device_pins=["117", "40001", "95000", "50000"],
        capabilities={"mirrorProtectedPins": ["50000"]},
    )
    w._maybe_mirror_reconcile(reason="user-sync",
                              roster_users=_roster(["117", "200", "201", "202", "203"]))
    assert w._sdk.deleted == ["40001"]  # only the true extra


def test_grace_window_protects_recent_enroll():
    import time as _t
    w = _make_worker(device_pins=["117", "88888"],
                     recent={"88888": _t.monotonic()})  # just pushed
    w._maybe_mirror_reconcile(reason="user-sync",
                              roster_users=_roster(["117", "200", "201", "202"]))
    assert w._sdk.deleted is None  # 88888 protected by grace -> no extras


def test_percent_floor_aborts_mass_delete(monkeypatch):
    # 3 extras vs a roster of 4 -> 75% > 25% cap -> abort.
    w = _make_worker(device_pins=["1", "2", "3", "117"])
    w._maybe_mirror_reconcile(reason="user-sync", roster_users=_roster(["117", "118", "119", "120"]))
    assert w._sdk.deleted is None


def test_dry_run_unarmed_logs_but_never_deletes(monkeypatch):
    recorded = {}
    monkeypatch.setattr("app.core.db.mirror_reconcile_is_armed", lambda **kw: False)
    monkeypatch.setattr("app.core.db.mirror_reconcile_record_plan",
                        lambda **kw: recorded.update(kw))
    w = _make_worker(device_pins=["117", "40001"])
    w._maybe_mirror_reconcile(reason="user-sync",
                              roster_users=_roster(["117", "200", "201", "202"]))
    assert w._sdk.deleted is None          # dry-run: nothing deleted
    assert recorded.get("count") == 1      # but the plan was recorded for review


def test_happy_path_deletes_extras_sorted():
    # roster of 9 so 2 extras (2/9 = 22%) stays under the 25% floor
    roster = ["117"] + [str(200 + i) for i in range(8)]
    w = _make_worker(device_pins=["117", "40002", "40001"])
    w._maybe_mirror_reconcile(reason="daily-forced-sync", roster_users=_roster(roster))
    assert w._sdk.deleted == ["40001", "40002"]  # both extras, sorted, deleted once

from unittest.mock import MagicMock

import pytest

from app.core import db, off_hours, push_safety
from tests.test_removal_ceiling_pullsdk import _run, _users, _gym58_device, _removed_pins, warns
from tests.test_account_pin_device_sites import sqlite_db
from tests.test_standalone_finger_removal_state import fstate
from tests.test_standalone_incremental_sync import _worker
from tests.test_standalone_revoked_pin_removal import RevokeDriver


@pytest.mark.parametrize("held_count,unplanned_count,desired_count,allowed", [
    (40, 0, 60, True), (0, 40, 60, False), (30, 12, 0, False), (40, 0, 0, True),
])
def test_pullsdk_exact_hold_bound(sqlite_db, monkeypatch, warns, held_count, unplanned_count,
                                 desired_count, allowed):
    planned = {str(40000 + i) for i in range(held_count)}
    old = planned | {str(50000 + i) for i in range(unplanned_count)}
    monkeypatch.setattr(off_hours, "held_pins_for_device", lambda d: planned)
    for pin in old:
        sqlite_db.save_device_sync_state(device_id=1, pin=pin, desired_hash="h", ok=True, error=None)
    sdk = _run(_users(*range(101, 101 + desired_count)), _gym58_device(), device_pins=sorted(old))
    assert _removed_pins(sdk) == (old if allowed else set())
    assert bool([1 for name, _ in warns if name == "REVOKE_ABORTED"]) is (not allowed)


@pytest.mark.parametrize("held_count,unplanned_count,desired_count,allowed", [
    (40, 0, 60, True), (0, 40, 60, False), (30, 12, 0, False), (40, 0, 0, True),
])
def test_standalone_exact_hold_bound(monkeypatch, fstate, held_count, unplanned_count,
                                    desired_count, allowed):
    drv = RevokeDriver()
    worker, _ = _worker(monkeypatch, driver=drv, users=[])
    planned = {str(40000 + i) for i in range(held_count)}
    old = planned | {str(50000 + i) for i in range(unplanned_count)}
    monkeypatch.setattr(off_hours, "held_pins_for_device", lambda d: planned)
    for pin in old:
        fstate.rows[pin] = ("old-hash", True, {0})
    result = worker._neutralise_revoked_pins(desired_pins={str(i) for i in range(desired_count)},
                                            roster_count=desired_count)
    assert result is allowed
    assert {p for call in drv.delete_calls for p in call} == (old if allowed else set())


def test_split_is_exact():
    assert off_hours.split_removals(["1", "2", "3"], {"2", "9"}) == (["1", "3"], ["2"])
    assert off_hours.split_removals([], {"1"}) == ([], [])


def test_account_open_membership_keeps_its_pin_and_errors_do_not_exempt(monkeypatch):
    rows = [{"activeMembershipId": 1, "mainAccountId": 7},
            {"activeMembershipId": 2, "mainAccountId": 8}]
    monkeypatch.setattr(db, "list_off_hours_held_rows", lambda: rows)
    monkeypatch.setattr(db, "list_sync_users", lambda: [{"activeMembershipId": 3, "mainAccountId": 7}])
    assert off_hours.held_pins_for_device({"pinScheme": "ACCOUNT"}) == {"8"}
    assert off_hours.held_pins_for_device({"pinScheme": "MEMBERSHIP"}) == {"1", "2"}
    monkeypatch.setattr(db, "list_off_hours_held_rows", MagicMock(side_effect=RuntimeError("read")))
    assert off_hours.held_pins_for_device({}) == set()
    assert not push_safety.check_bulk_removal(count=40, roster_count=60, path="stale").allowed


def test_planned_holds_still_obey_leases_and_confirm_only_unplanned(monkeypatch):
    monkeypatch.setattr(push_safety._lease_gate, "removals_blocked", lambda d: "add_only")
    assert not push_safety.check_bulk_removal(count=0, planned_count=40, roster_count=40,
                                             device_id=1, path="stale").allowed
    monkeypatch.setattr(push_safety._lease_gate, "removals_blocked", lambda d: None)
    approve = MagicMock(return_value=True)
    monkeypatch.setattr(push_safety._problems.registry, "consume_approval", approve)
    assert push_safety.check_bulk_removal(count=12, planned_count=30, roster_count=30,
        device_id=1, path="stale", sample=[str(i) for i in range(12)]).allowed
    approve.assert_called_once_with(1, [str(i) for i in range(12)])

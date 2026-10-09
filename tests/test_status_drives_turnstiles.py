"""/api/v2/status ultra.drivesTurnstiles: False only on a READER PC, so the dashboard does not
raise "Lecteur non connecté" on a PC that is never meant to connect to a turnstile."""
from __future__ import annotations

import pytest

from app.api.local_access_api_v2 import _pc_drives_ultra_turnstiles
from app.core.v2 import lease_gate
from app.core.v2.lease_gate import DriveEntry, LeaseSnapshot, ReleaseEntry


@pytest.fixture(autouse=True)
def _reset_lease():
    lease_gate.reset_for_tests()
    yield
    lease_gate.reset_for_tests()


def _leased(**kw) -> LeaseSnapshot:
    return LeaseSnapshot(mode=lease_gate.MODE_LEASED, role=kw.pop("role", "DRIVER"), source="server", **kw)


def test_unassigned_gym_drives_when_it_has_ultra_devices():
    assert _pc_drives_ultra_turnstiles({"ULTRA": 2}) is True
    assert _pc_drives_ultra_turnstiles({"ULTRA": 0}) is False
    assert _pc_drives_ultra_turnstiles(None) is False


def test_reader_pc_drives_nothing():
    lease_gate.install(_leased(role="READER"))
    assert _pc_drives_ultra_turnstiles({"ULTRA": 3}) is False


def test_driver_pc_with_a_drive_entry():
    lease_gate.install(_leased(drive={7: DriveEntry(device_id=7, generation=1, state="DRIVE")}))
    assert _pc_drives_ultra_turnstiles({"ULTRA": 3}) is True


def test_waiting_for_release_only_is_not_driving():
    lease_gate.install(_leased(drive={7: DriveEntry(device_id=7, generation=1, state="WAIT_FOR_RELEASE")}))
    assert _pc_drives_ultra_turnstiles({"ULTRA": 3}) is False


def test_pc_handing_over_still_drives():
    lease_gate.install(_leased(release={7: ReleaseEntry(device_id=7, generation=1)}))
    assert _pc_drives_ultra_turnstiles({"ULTRA": 3}) is True

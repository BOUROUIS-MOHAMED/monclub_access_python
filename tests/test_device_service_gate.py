"""In service / Keep entry history (ULTRA merge plan 2, Task 5; spec sections 3, 5)."""
from __future__ import annotations

from app.core.device_service_gate import (
    device_in_service,
    devices_in_service,
    in_service,
    keeps_history,
    out_of_service_reason,
)
from app.core.settings_reader import normalize_device_settings


def test_a_device_is_in_service_unless_active_or_access_device_is_off():
    assert device_in_service({"id": 1}) is True
    assert device_in_service({"id": 1, "active": True, "accessDevice": True}) is True
    assert out_of_service_reason({"active": False}) == "active=False"
    assert out_of_service_reason({"active": 0, "accessDevice": True}) == "active=False"
    assert out_of_service_reason({"accessDevice": "false"}) == "accessDevice=False"
    assert out_of_service_reason({"access_device": 0}) == "accessDevice=False"
    assert out_of_service_reason(None) is None


def test_devices_in_service_keeps_order_and_drops_the_others():
    devs = [{"id": 1}, {"id": 2, "active": False}, {"id": 3, "accessDevice": False}, {"id": 4}]
    assert [d["id"] for d in devices_in_service(devs)] == [1, 4]


def test_the_settings_flags_follow_normalize_device_settings():
    on = normalize_device_settings({"active": True, "accessDevice": True, "saveHistory": True})
    off = normalize_device_settings({"active": True, "accessDevice": False, "saveHistory": False})
    assert (in_service(on), keeps_history(on)) == (True, True)
    assert (in_service(off), keeps_history(off)) == (False, False)


def test_missing_keys_mean_on():
    assert in_service({}) is True and keeps_history({}) is True
    assert in_service(None) is True and keeps_history(None) is True

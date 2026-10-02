"""What the PC writes into a turnstile for one device (ULTRA merge plan 2, Tasks 14-15;
spec sections 3, 8.4)."""
from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.core import device_push_rules as rules
from app.core.device_sync import DeviceSyncEngine


def _engine():
    return DeviceSyncEngine(cfg=None, logger=logging.getLogger("test.push_rules"))


@pytest.mark.parametrize("stored, bitmask", [
    ([1], 1), ([2], 2), ([3], 4), ([4], 8), ([1, 2], 3), ([1, 2, 3, 4], 15), ([4, 1], 9)])
def test_door_numbers_become_the_bitmask(stored, bitmask):
    doors, mask = rules.door_numbers_and_bitmask({"id": 1, "doorIds": stored}, 15)
    assert (doors, mask) == (sorted(set(stored)), bitmask)


def test_no_door_keeps_todays_meaning_presets_then_all_doors():
    presets = [{"doorNumber": 1, "pulseSeconds": 3}, {"doorNumber": 3, "pulseSeconds": 2}]
    assert rules.door_numbers_and_bitmask({"id": 1, "doorIds": [], "doorPresets": presets}, 15) == ([1, 3], 5)
    assert rules.door_numbers_and_bitmask({"id": 1, "doorIds": []}, 15) == ([15], 15)


def test_values_outside_1_to_4_are_ignored_with_one_warning(monkeypatch):
    log = MagicMock()
    monkeypatch.setattr(rules, "logger", log)
    dev = {"id": 77, "doorIds": [8, 2]}
    assert rules.door_numbers_and_bitmask(dev, 15) == ([2], 2)
    assert rules.door_numbers_and_bitmask(dev, 15) == ([2], 2)
    assert log.warning.call_count == 1


def test_the_default_door_written_into_an_empty_list_is_not_warned(monkeypatch):
    log = MagicMock()
    monkeypatch.setattr(rules, "logger", log)
    assert rules.door_numbers_and_bitmask({"id": 78, "doorIds": [15]}, 15) == ([15], 15)
    log.warning.assert_not_called()


def test_the_push_context_uses_door_numbers():
    doors, mask, _tz, _fp = _engine()._resolve_push_context(device={"doorIds": [3]}, default_door_id=15)
    assert (doors, mask) == ([3], 4)


def test_panel_params_are_what_the_push_writes():
    dev = {"doorPresets": [{"doorNumber": 1, "pulseSeconds": 3}, {"doorNumber": 2, "pulseSeconds": 0}],
           "anti_fraude_card": True, "anti_fraude_duration": 400}
    assert rules.panel_param_items(dev) == (["Door1Drivertime=3"], "Door1Intertime=255,Door2Intertime=255")
    assert rules.panel_param_items(dict(dev, anti_fraude_card=False)) == (["Door1Drivertime=3"], "AntiPassback=0")
    assert rules.panel_param_items(dict(dev, anti_fraude_duration=0))[1] == "Door1Intertime=30,Door2Intertime=30"
    assert rules.panel_param_items({}) == ([], "AntiPassback=0")


def _fingerprint(device, users=()):
    return _engine().build_device_sync_fingerprint(device=device, users=list(users), local_fp_index={})[0]


def test_a_panel_block_change_moves_the_device_hash():
    base = {"id": 5, "name": "x", "doorIds": [1], "accessDataMode": "ULTRA",
            "doorPresets": [{"doorNumber": 1, "pulseSeconds": 3}],
            "antiFraudeCard": True, "antiFraudeDuration": 30}
    h = _fingerprint(base)
    assert _fingerprint(dict(base, antiFraudeDuration=60)) != h
    assert _fingerprint(dict(base, antiFraudeCard=False)) != h
    assert _fingerprint(dict(base, doorPresets=[{"doorNumber": 1, "pulseSeconds": 5}])) != h
    assert _fingerprint(dict(base)) == h


def test_an_out_of_service_device_is_never_pushed():
    eng = _engine()
    cache = SimpleNamespace(users=[], devices=[])
    for device in ({"id": 5, "active": False}, {"id": 5, "accessDevice": False}):
        assert eng._run_single_device_sync(cache=cache, device=device, source="t", changed_ids=None,
                                           sync_run_id=None, sdk=object()) is False

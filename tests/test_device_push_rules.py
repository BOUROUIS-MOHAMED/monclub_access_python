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


# ------------------------------------------------------------------ Task 15: roster by card choice
USERS = [{"activeMembershipId": 5, "userId": 105, "mainAccountId": 700, "membershipId": 7,
          "fullName": "Alice", "firstCardId": "1005", "fingerprints": []}]


def _dev(**extra):
    d = {"id": 9, "name": "e", "accessDataMode": "ULTRA", "deviceProtocol": "ZK_PULLSDK",
         "doorIds": [1], "allowedMemberships": []}
    d.update(extra)
    return d


def test_turnstile_cards_keep_the_roster_unchanged():
    desired = {"5": {"firstCardId": "1005", "fullName": "Alice"}}
    assert rules.roster_for_card_mode(desired, _dev()) is desired
    assert rules.roster_for_card_mode(desired, _dev(cardDecision="TURNSTILE")) is desired


@pytest.mark.parametrize("choice", ["PC", "OFF"])
def test_pc_or_off_without_fingerprints_writes_nothing(choice):
    desired = {"5": {"firstCardId": "1005"}}
    assert rules.roster_for_card_mode(desired, _dev(cardDecision=choice, fingerprintEnabled=False)) == {}


@pytest.mark.parametrize("choice", ["PC", "OFF"])
def test_pc_or_off_with_fingerprints_writes_members_without_cards(choice):
    user = {"firstCardId": "1005", "secondCardId": "2", "cards": ["3"], "fullName": "Alice",
            "fingerprints": [{"fingerId": 1}]}
    out = rules.roster_for_card_mode({"5": user}, _dev(cardDecision=choice, fingerprintEnabled=True))
    assert out == {"5": {"fullName": "Alice", "fingerprints": [{"fingerId": 1}]}}
    assert user["firstCardId"] == "1005"            # the cached member row is not touched


def test_pc_on_a_standalone_terminal_keeps_the_cards_d10():
    desired = {"5": {"firstCardId": "1005"}}
    assert rules.roster_for_card_mode(desired, _dev(cardDecision="PC", deviceProtocol="ZK_STANDALONE")) is desired


def test_normalize_device_keeps_the_card_decision():
    assert _engine()._normalize_device(_dev(cardDecision="PC"))["cardDecision"] == "PC"


def test_the_push_filter_applies_the_card_choice_only_when_asked():
    eng = _engine()
    pc = eng._normalize_device(_dev(cardDecision="PC", fingerprintEnabled=False))
    assert eng._filter_users_for_device(users=list(USERS), device=dict(pc), default_door_id=15,
                                        apply_card_mode=True) == {}
    assert set(eng._filter_users_for_device(users=list(USERS), device=dict(pc), default_door_id=15)) == {"5"}
    off_fp = eng._normalize_device(_dev(cardDecision="OFF", fingerprintEnabled=True))
    row = eng._filter_users_for_device(users=list(USERS), device=dict(off_fp), default_door_id=15,
                                       apply_card_mode=True)["5"]
    assert "firstCardId" not in row and row["fullName"] == "Alice"


def test_every_push_path_asks_for_the_card_choice():
    import inspect

    import app.core.ultra_engine as ue

    assert "apply_card_mode=True" in inspect.getsource(DeviceSyncEngine._sync_one_device)
    assert "apply_card_mode=True" in inspect.getsource(DeviceSyncEngine.sync_member_on_connected_sdk)
    assert "apply_card_mode=True" in inspect.getsource(DeviceSyncEngine.build_device_sync_fingerprint)
    assert "apply_card_mode=True" in inspect.getsource(ue.UltraDeviceWorker._build_standalone_roster)


def test_a_card_choice_change_moves_the_device_hash():
    hashes = {_fingerprint(_dev(), USERS),
              _fingerprint(_dev(cardDecision="OFF", fingerprintEnabled=True), USERS),
              _fingerprint(_dev(cardDecision="PC"), USERS)}
    assert len(hashes) == 3


def test_the_mb2000_roster_writes_no_card_when_cards_are_off():
    from tests.test_ultra_engine import _make_settings, _make_worker

    off = _make_worker(device=_dev(cardDecision="OFF", fingerprintEnabled=True),
                       settings=_make_settings(fingerprint_enabled=False))
    users, _tpl, _hashes = off._build_standalone_roster(SimpleNamespace(users=list(USERS)))
    assert users == [{"pin": "5", "name": "Alice", "card": ""}]
    turnstile = _make_worker(device=_dev(), settings=_make_settings(fingerprint_enabled=False))
    users, _tpl, _hashes = turnstile._build_standalone_roster(SimpleNamespace(users=list(USERS)))
    assert users == [{"pin": "5", "name": "Alice", "card": "1005"}]


def test_the_erase_wizard_still_counts_the_members_of_a_pc_device():
    from app.core.erase_wizard import refill_roster

    roster = refill_roster(_dev(cardDecision="PC", fingerprintEnabled=False), SimpleNamespace(users=list(USERS)))
    assert roster["members"] == 1


def test_the_worker_still_names_the_member_of_an_account_pin_on_a_pc_device():
    from tests.test_ultra_engine import _make_worker

    w = _make_worker(device=_dev(cardDecision="PC", fingerprintEnabled=False, pinScheme="ACCOUNT"))
    alice = dict(USERS[0])
    assert w._user_for_device_pin("700", {5: alice}) is alice

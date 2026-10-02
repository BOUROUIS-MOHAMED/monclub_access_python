"""ULTRA merge keys in normalize_device_settings (plan 2, Task 3; spec 2026-10-02 sections 3, 4, D6, D10)."""
from __future__ import annotations

import pytest

from app.core.settings_reader import (
    CARDS_OFF,
    CARDS_PC,
    CARDS_TURNSTILE,
    MEMBER_BLOCK_MAX_SECONDS,
    PC_DECIDED_MAX_IDLE_POLL_MS,
    effective_card_decision,
    member_block_seconds,
    normalize_device_settings,
)


@pytest.mark.parametrize("raw", [None, "", "garbage", 7])
def test_absent_null_or_unknown_card_choice_is_turnstile(raw):
    dev = {} if raw is None else {"cardDecision": raw}
    assert effective_card_decision(dev) == CARDS_TURNSTILE


def test_off_and_turnstile_are_read_as_sent_and_case_does_not_matter():
    assert effective_card_decision({"cardDecision": "OFF"}) == CARDS_OFF
    assert effective_card_decision({"cardDecision": "turnstile"}) == CARDS_TURNSTILE
    assert effective_card_decision({"card_decision": "off"}) == CARDS_OFF


def test_pc_on_a_pullsdk_panel_is_pc():
    assert effective_card_decision({"cardDecision": "PC"}) == CARDS_PC
    assert effective_card_decision({"cardDecision": "PC", "deviceProtocol": "ZK_PULLSDK"}) == CARDS_PC


@pytest.mark.parametrize("protocol", ["ZK_STANDALONE", "MB2000", "zkemkeeper"])
def test_pc_on_a_standalone_terminal_is_turnstile_d10(protocol):
    assert effective_card_decision({"cardDecision": "PC", "deviceProtocol": protocol}) == CARDS_TURNSTILE


def test_an_explicit_member_block_is_used_and_clamped():
    assert member_block_seconds({"memberBlockSeconds": 45}) == 45
    assert member_block_seconds({"memberBlockSeconds": 0, "antiFraudeQrCode": True}) == 0
    assert member_block_seconds({"memberBlockSeconds": -5}) == 0
    assert member_block_seconds({"memberBlockSeconds": 99999}) == MEMBER_BLOCK_MAX_SECONDS == 3600


def test_a_null_member_block_is_the_section_3_derivation():
    base = {"memberBlockSeconds": None, "antiFraudeDuration": 40}
    assert member_block_seconds(dict(base, antiFraudeQrCode=True, antiFraudeCard=False)) == 40
    assert member_block_seconds(dict(base, antiFraudeQrCode=False, antiFraudeCard=True,
                                     accessDataMode="ULTRA")) == 0
    assert member_block_seconds(dict(base, antiFraudeQrCode=False, antiFraudeCard=True,
                                     accessDataMode="AGENT")) == 40
    assert member_block_seconds(dict(base, antiFraudeQrCode=False, antiFraudeCard=False,
                                     accessDataMode="AGENT")) == 0
    assert member_block_seconds({}) == 30   # QR blocking on by default, duration 30 by default


def test_the_raw_duration_is_used_not_the_anti_fraud_clamp():
    assert member_block_seconds({"antiFraudeQrCode": True, "antiFraudeDuration": 0}) == 0
    assert member_block_seconds({"antiFraudeQrCode": True, "antiFraudeDuration": 500}) == 500


def test_normalized_settings_carry_the_new_keys():
    s = normalize_device_settings({"cardDecision": "OFF", "memberBlockSeconds": 20,
                                   "allowedMemberships": [3, "4", 0, -1, 3, "x"]})
    assert s["card_decision"] == CARDS_OFF
    assert s["member_block_seconds"] == 20
    assert s["allowed_memberships"] == [3, 4]


def test_a_pc_device_polls_with_a_ceiling_of_at_most_300_ms():
    assert PC_DECIDED_MAX_IDLE_POLL_MS == 300
    ultra = {"accessDataMode": "ULTRA"}
    pc = normalize_device_settings(dict(ultra, cardDecision="PC", emptyBackoffMaxMs=2000))
    assert pc["empty_backoff_max_ms"] == 300
    low = normalize_device_settings(dict(ultra, cardDecision="PC", emptyBackoffMaxMs=150))
    assert low["empty_backoff_max_ms"] == 150
    turnstile = normalize_device_settings(dict(ultra, cardDecision="TURNSTILE", emptyBackoffMaxMs=2000))
    assert turnstile["empty_backoff_max_ms"] == 2000
    standalone_pc = normalize_device_settings(dict(ultra, cardDecision="PC", deviceProtocol="ZK_STANDALONE",
                                                   emptyBackoffMaxMs=2000))
    assert standalone_pc["empty_backoff_max_ms"] == 2000   # PC refused on the driver (D10)


def test_pending_removal_request_ids_are_read():
    s = normalize_device_settings({"fingerprintEraseRequestId": " 0F0E0D0C-0B0A-4908-8706-050403020100 ",
                                   "cardRemovalRequestId": "1a2b3c4d-0000-4000-8000-000000000001"})
    assert s["fingerprint_erase_request_id"] == "0f0e0d0c-0b0a-4908-8706-050403020100"
    assert s["card_removal_request_id"] == "1a2b3c4d-0000-4000-8000-000000000001"
    none = normalize_device_settings({"cardRemovalRequestId": None, "fingerprint_erase_request_id": ""})
    assert (none["fingerprint_erase_request_id"], none["card_removal_request_id"]) == (None, None)
    assert normalize_device_settings({"card_removal_request_id": "AB"})["card_removal_request_id"] == "ab"


def test_an_unconverted_agent_device_keeps_its_ceiling():
    # The backend backfill gives an AGENT device with rfidEnabled cardDecision=PC before its
    # conversion; the AGENT engine reads empty_backoff_max_ms too (realtime_agent.py:878).
    agent = normalize_device_settings({"accessDataMode": "AGENT", "cardDecision": "PC", "emptyBackoffMaxMs": 2000})
    assert agent["empty_backoff_max_ms"] == 2000

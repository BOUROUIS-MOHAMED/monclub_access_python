"""PC-decided entries on the ULTRA worker (ULTRA merge plan 2, Tasks 8-10; spec section 4)."""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import app.core.ultra_engine as _ue
from app.core import card_decision as cd
from app.core.db import get_local_state_generation
from tests.test_ultra_engine import _make_settings, _make_worker

STAFF_PLAN, GYM_PLAN = 99, 10
STAFF = {"fullName": "Staff Person", "membershipId": STAFF_PLAN, "activeMembershipId": 500,
         "userId": 50, "mainAccountId": 800, "image": "img", "phone": "111"}
ANNA = {"fullName": "Anna", "membershipId": GYM_PLAN, "activeMembershipId": 501, "userId": 51,
        "mainAccountId": 700}
STAFF_CARD, ANNA_CARD = "13604719", "22222222"


def _worker(**settings):
    s = _make_settings(totp_digits=7, totp_prefix="9")
    s.update({"rfid_enabled": True, "ultra_rfid_staff_rescue_enabled": True, "totp_validation": True})
    s.update(settings)
    w = _make_worker(settings=s)
    w._cached_state = ([], {500: STAFF, 501: ANNA}, {STAFF_CARD: [STAFF], ANNA_CARD: [ANNA]})
    w._cached_state_gen = get_local_state_generation()
    w._cached_state_ts = time.monotonic()
    w._open_door_with_retry = MagicMock(return_value=True)
    w._enqueue_notification = MagicMock()
    w._enqueue_history = MagicMock()
    return w


def _staff_ids(*plans):
    return patch.object(_ue, "get_staff_membership_ids_cached", return_value=frozenset(plans))


# ------------------------------------------------------------------ Task 8: staff-card rescue
def test_the_worker_takes_its_pc_methods_from_the_mixin():
    from app.core.ultra_pc_entry import PcEntryMixin

    assert issubclass(_ue.UltraDeviceWorker, PcEntryMixin)
    assert _ue.UltraDeviceWorker._handle_rfid_rescue is PcEntryMixin._handle_rfid_rescue
    assert _ue._scan_mode_for_event({"scan_mode_hint": "fingerprint"}) == "FINGERPRINT"
    assert _ue._uid_for_alert({"userId": "7"}) == 7


def test_the_staff_rescue_is_refused_on_a_plan_list_without_the_staff_plan():
    w = _worker(allowed_memberships=[GYM_PLAN])
    w._handle_deny = MagicMock()
    with _staff_ids(STAFF_PLAN), patch("app.core.ultra_pc_entry._tel") as tel:
        w._handle_rfid_rescue(STAFF_CARD, "t", "e1", 1, "20", {})
    w._open_door_with_retry.assert_not_called()
    w._handle_deny.assert_called_once()
    decisions = [c for c in tel.event.call_args_list if c.args and c.args[0] == "PC_DECISION"]
    assert len(decisions) == 1 and decisions[0].kwargs["reason"] == cd.DENY_PLAN_NOT_ALLOWED


def test_cards_off_rescues_no_staff_card():
    w = _worker(card_decision="OFF")
    w._handle_deny = MagicMock()
    with _staff_ids(STAFF_PLAN):
        w._handle_rfid_rescue(STAFF_CARD, "t", "e2", 1, "20", {})
    w._open_door_with_retry.assert_not_called()
    w._handle_deny.assert_called_once()


def test_a_rescued_staff_member_is_never_blocked():
    w = _worker(member_block_seconds=30)
    with _staff_ids(STAFF_PLAN):
        w._handle_rfid_rescue(STAFF_CARD, "t", "e3", 1, "20", {})
    w._open_door_with_retry.assert_called_once()
    assert w._member_guard().size() == 0

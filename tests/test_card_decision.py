"""The PC verdict (ULTRA merge plan 2, Task 6; spec section 4, D6, owner decisions OD-3, OD-4)."""
from __future__ import annotations

from app.core import card_decision as cd
from app.core.repeat_guard import RepeatGuard

STAFF_PLAN, GYM_PLAN, SPA_PLAN = 99, 10, 20
ANNA = {"fullName": "Anna", "membershipId": GYM_PLAN, "activeMembershipId": 501, "userId": 1,
        "mainAccountId": 700, "firstCardId": "1234567"}
ANNA_SPA = {"fullName": "Anna", "membershipId": SPA_PLAN, "activeMembershipId": 502, "userId": 1,
            "mainAccountId": 700}
STAFF = {"fullName": "Sam", "membershipId": STAFF_PLAN, "activeMembershipId": 600, "userId": 2,
         "mainAccountId": 800, "firstCardId": "7654321"}
USERS_BY_AM = {501: ANNA, 502: ANNA_SPA, 600: STAFF}
USERS_BY_CARD = {"1234567": [ANNA], "7654321": [STAFF]}


def _settings(**over):
    s = {"enabled": True, "card_decision": "PC", "rfid_enabled": True, "rfid_min_digits": 1,
         "rfid_max_digits": 16, "allowed_memberships": [], "ultra_rfid_staff_rescue_enabled": True}
    s.update(over)
    return s


def _card(card, settings=None, guard=None, now=1000.0, staff=frozenset({STAFF_PLAN})):
    return cd.decide_pc_card(card_no=card, settings=settings or _settings(), users_by_card=USERS_BY_CARD,
                             users_by_am=USERS_BY_AM, staff_ids=staff, guard=guard, now=now)


def _qr(result, settings=None, guard=None, now=1000.0, staff=frozenset({STAFF_PLAN})):
    return cd.decide_qr(totp_result=result, settings=settings or _settings(card_decision="TURNSTILE"),
                        users_by_am=USERS_BY_AM, staff_ids=staff, guard=guard, now=now)


# ------------------------------------------------------------------ PC cards
def test_a_known_card_is_allowed_with_its_member_and_key():
    v = _card("1234567")
    assert (v.allowed, v.reason, v.user, v.member_key, v.staff) == (True, cd.ALLOW_PC_CARD, ANNA, "acc:700", False)


def test_out_of_service_decides_nothing():
    v = _card("1234567", _settings(enabled=False))
    assert (v.allowed, v.reason, v.user) == (False, cd.DENY_OUT_OF_SERVICE, None)


def test_a_device_whose_cards_the_pc_does_not_decide_refuses():
    assert _card("1234567", _settings(card_decision="TURNSTILE")).reason == cd.DENY_NOT_PC_DECIDED


def test_an_unknown_card_is_refused_with_the_verify_card_reason():
    v = _card("5555555")
    assert (v.allowed, v.reason, v.card_valid) == (False, "DENY_NO_CARD_MATCH", False)


def test_the_card_length_limits_apply():
    v = _card("1234567", _settings(rfid_min_digits=8))
    assert (v.allowed, v.reason) == (False, "INVALID_CARD_LENGTH")


def test_the_old_rfid_switch_does_not_apply_to_pc_cards():
    assert _card("1234567", _settings(rfid_enabled=False)).allowed is True


def test_refused_for_an_unallowed_plan_d6():
    v = _card("1234567", _settings(allowed_memberships=[STAFF_PLAN]))
    assert (v.allowed, v.reason, v.user) == (False, cd.DENY_PLAN_NOT_ALLOWED, ANNA)


def test_one_allowed_plan_of_the_person_is_enough():
    assert _card("1234567", _settings(allowed_memberships=[SPA_PLAN])).allowed is True


def test_an_empty_plan_list_is_every_member():
    assert _card("1234567", _settings(allowed_memberships=[])).allowed is True


def test_a_card_whose_member_has_no_plan_is_refused_on_a_plan_list():
    planless = {"fullName": "P", "activeMembershipId": 900, "userId": 9}
    v = cd.decide_pc_card(card_no="1111", settings=_settings(allowed_memberships=[GYM_PLAN]),
                          users_by_card={"1111": [planless]}, users_by_am={900: planless},
                          staff_ids=frozenset(), guard=None, now=0.0)
    assert (v.allowed, v.reason) == (False, cd.DENY_PLAN_NOT_ALLOWED)


def test_blocked_inside_the_window_and_free_after_it():
    g = RepeatGuard()
    g.arm("acc:700", 30, now=1000.0)
    assert _card("1234567", guard=g, now=1010.0).reason == cd.DENY_REPEAT_BLOCK
    assert _card("1234567", guard=g, now=1031.0).allowed is True


def test_staff_are_exempt_from_the_member_block():
    g = RepeatGuard()
    g.arm("acc:800", 30, now=1000.0)
    v = _card("7654321", guard=g, now=1001.0)
    assert (v.allowed, v.staff) == (True, True)


# ------------------------------------------------------------------ QR
def _match(user=ANNA, account=700, reason="ALLOW"):
    return {"allowed": True, "reason": reason, "user": user, "accountId": account}


def test_a_refused_qr_keeps_its_reason():
    v = _qr({"allowed": False, "reason": "DENY_EXPIRED", "user": None})
    assert (v.allowed, v.reason) == (False, "DENY_EXPIRED")


def test_a_matched_qr_is_allowed_with_its_reason():
    v = _qr(_match())
    assert (v.allowed, v.reason, v.member_key) == (True, "ALLOW", "acc:700")


def test_d6_applies_to_qr():
    v = _qr(_match(), _settings(card_decision="TURNSTILE", allowed_memberships=[STAFF_PLAN]))
    assert (v.allowed, v.reason) == (False, cd.DENY_PLAN_NOT_ALLOWED)


def test_an_unlisted_qr_follows_the_member_list_check_od3():
    plans = _settings(card_decision="TURNSTILE", allowed_memberships=[GYM_PLAN])
    unlisted = dict(_match(user=None, account=12345), rosterCheck="not_in_roster")
    assert _qr(unlisted, plans).allowed is True                                 # Trial: let in (counted)
    enforce = dict(plans, totp_roster_check_mode="enforce")
    assert _qr(unlisted, enforce).reason == cd.DENY_NOT_IN_LOCAL_ROSTER        # Enforce: refused
    for verdict in ("roster_behind", "roster_empty"):                          # the check's never-refuse cases
        assert _qr(dict(unlisted, rosterCheck=verdict), enforce).allowed is True


def test_a_qr_matched_by_account_finds_the_persons_plans():
    v = _qr(_match(user=None, account=700), _settings(card_decision="TURNSTILE", allowed_memberships=[SPA_PLAN]))
    assert v.allowed is True
    v = _qr(_match(user=None, account=700), _settings(card_decision="TURNSTILE", allowed_memberships=[STAFF_PLAN]))
    assert v.reason == cd.DENY_PLAN_NOT_ALLOWED


def test_qr_member_block_and_staff_exemption():
    g = RepeatGuard()
    g.arm("acc:700", 30, now=1000.0)
    assert _qr(_match(), guard=g, now=1005.0).reason == cd.DENY_REPEAT_BLOCK
    g.arm("acc:800", 30, now=1000.0)
    assert _qr(_match(user=STAFF, account=800), guard=g, now=1005.0).allowed is True


# ------------------------------------------------------------------ staff-card rescue
def _staff(card, settings=None, staff=frozenset({STAFF_PLAN})):
    return cd.decide_staff_card(card_no=card, settings=settings or _settings(card_decision="TURNSTILE"),
                                users_by_card=USERS_BY_CARD, users_by_am=USERS_BY_AM, staff_ids=staff)


def test_a_valid_staff_card_is_rescued():
    v = _staff("7654321")
    assert (v.allowed, v.reason, v.staff, v.card_valid) == (True, cd.ALLOW_STAFF_RFID, True, True)


def test_a_valid_non_staff_card_is_not_rescued():
    v = _staff("1234567")
    assert (v.allowed, v.reason, v.card_valid, v.staff) == (False, cd.DENY_NOT_STAFF, True, False)


def test_an_unknown_card_is_not_rescued():
    v = _staff("0000000")
    assert (v.allowed, v.card_valid) == (False, False)


def test_the_rescue_switch_and_the_rfid_switch_still_apply():
    assert _staff("7654321", _settings(card_decision="TURNSTILE", ultra_rfid_staff_rescue_enabled=False)).reason \
        == cd.DENY_STAFF_RESCUE_OFF
    assert _staff("7654321", _settings(card_decision="TURNSTILE", rfid_enabled=False)).allowed is False


def test_cards_off_rescues_no_card():
    assert _staff("7654321", _settings(card_decision="OFF")).reason == cd.DENY_CARDS_OFF


def test_d6_applies_to_the_staff_rescue_od4():
    v = _staff("7654321", _settings(card_decision="TURNSTILE", allowed_memberships=[GYM_PLAN]))
    assert (v.allowed, v.reason) == (False, cd.DENY_PLAN_NOT_ALLOWED)


# ------------------------------------------------------------------ one person, one card, two plans
def test_one_person_with_the_card_on_two_plan_rows_is_one_member():
    spa_with_card = dict(ANNA_SPA, firstCardId="1234567")
    by_card = {"1234567": [ANNA, spa_with_card]}
    v = cd.decide_pc_card(card_no="1234567", settings=_settings(allowed_memberships=[SPA_PLAN]),
                          users_by_card=by_card, users_by_am=USERS_BY_AM, staff_ids=frozenset(),
                          guard=None, now=0.0)
    assert (v.allowed, v.user["membershipId"]) == (True, SPA_PLAN)
    v = cd.decide_pc_card(card_no="1234567", settings=_settings(), users_by_card=by_card,
                          users_by_am=USERS_BY_AM, staff_ids=frozenset(), guard=None, now=0.0)
    assert (v.allowed, v.user["membershipId"]) == (True, GYM_PLAN)


def test_a_staff_person_with_two_rows_keeps_the_staff_row():
    staff_member_row = {"fullName": "Sam", "membershipId": GYM_PLAN, "activeMembershipId": 601, "userId": 2,
                        "mainAccountId": 800, "firstCardId": "7654321"}
    g = RepeatGuard()
    g.arm("acc:800", 30, now=1000.0)
    v = cd.decide_pc_card(card_no="7654321", settings=_settings(),
                          users_by_card={"7654321": [staff_member_row, STAFF]}, users_by_am=USERS_BY_AM,
                          staff_ids=frozenset({STAFF_PLAN}), guard=g, now=1001.0)
    assert (v.allowed, v.staff, v.user["membershipId"]) == (True, True, STAFF_PLAN)


def test_two_people_sharing_a_card_stay_a_collision():
    bob = {"fullName": "Bob", "membershipId": GYM_PLAN, "activeMembershipId": 777, "userId": 3,
           "mainAccountId": 900}
    v = cd.decide_pc_card(card_no="1234567", settings=_settings(), users_by_card={"1234567": [ANNA, bob]},
                          users_by_am=USERS_BY_AM, staff_ids=frozenset(), guard=None, now=0.0)
    assert (v.allowed, v.reason) == (False, "DENY_CARD_COLLISION")

"""The PC's verdict for every entry the PC decides on an ULTRA turnstile (spec 2026-10-02 section 4).

Three kinds reach it, all after the turnstile refused the credential and reported it:
- a QR code (the QR rescue): the code already matched in access_verification.verify_totp_resilient
  (format, TOTP window, roster check, allowed days); this adds the device's plans (D6) and the
  member block (repeat_guard.py);
- a card on a device whose cards the PC decides (cardDecision = PC, C3 panels only, D10);
- a STAFF card (the staff-card rescue, moved here from ultra_engine.py::_handle_rfid_rescue).

Pure: no database, no device, no clock. The caller hands in what it already holds -- normalized
settings, users_by_card / users_by_am (today's member list), the cached STAFF plan ids, the
worker's RepeatGuard and the monotonic time. Output: a Verdict, allow or refuse with a reason.

Checks for a PC card, in the order of spec section 4: In service; the card is known (on today's
list, which is the server's deliverable set of the day -- the push writes exactly that list,
device_sync._filter_users_for_device); one of the member's plans is allowed on this device (D6);
the card length; the member block. verify_card checks the length before the match, so an unknown
card of the wrong length is refused as INVALID_CARD_LENGTH: another reason, the same answer.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, Optional

from app.core.access_verification import (
    ROSTER_MODE_ENFORCE,
    ROSTER_NOT_IN,
    totp_roster_check_mode,
    verify_card,
)
from app.core.device_service_gate import in_service
from app.core.repeat_guard import RepeatGuard, member_key
from app.core.settings_reader import CARDS_OFF, CARDS_PC

ALLOW_PC_CARD = "ALLOW_PC_CARD"
ALLOW_STAFF_RFID = "ALLOW_STAFF_RFID"
DENY_OUT_OF_SERVICE = "DENY_OUT_OF_SERVICE"
DENY_CARDS_OFF = "DENY_CARDS_OFF"
DENY_NOT_PC_DECIDED = "DENY_NOT_PC_DECIDED"
DENY_NOT_STAFF = "DENY_NOT_STAFF"
DENY_STAFF_RESCUE_OFF = "DENY_STAFF_RESCUE_OFF"
DENY_PLAN_NOT_ALLOWED = "DENY_PLAN_NOT_ALLOWED"
DENY_REPEAT_BLOCK = "DENY_REPEAT_BLOCK"
DENY_NOT_IN_LOCAL_ROSTER = "DENY_NOT_IN_LOCAL_ROSTER"   # verify_totp's own reason, reused (OD-3)


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason: str
    user: Optional[Mapping[str, Any]] = None
    staff: bool = False
    member_key: Optional[str] = None
    card_valid: bool = False


def _positive_int(value: Any) -> Optional[int]:
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def plan_id(user: Any) -> Optional[int]:
    """The plan (membershipId) of a member row; None when absent."""
    return _positive_int(user.get("membershipId")) if isinstance(user, Mapping) else None


def is_staff(user: Any, staff_ids: Iterable[int]) -> bool:
    pid = plan_id(user)
    try:
        return pid is not None and pid in staff_ids
    except TypeError:
        return False


def allowed_plans(settings: Mapping[str, Any]) -> frozenset:
    """The device's plan list (settings ``allowed_memberships``). Empty = every member: the push
    writes everyone when it is empty (device_sync._filter_users_for_device, inventory 1a)."""
    return frozenset(p for p in (_positive_int(x) for x in (settings.get("allowed_memberships") or ()))
                     if p is not None)


def member_plan_ids(user: Any, users_by_am: Optional[Mapping[int, Any]], account_id: Any = None) -> frozenset:
    """Every plan of the person: the row's own, plus every row of today's list on the same main
    account (D6: "one of the member's plans is allowed")."""
    plans = set()
    pid = plan_id(user)
    if pid is not None:
        plans.add(pid)
    acc = _positive_int(account_id)
    if acc is None and isinstance(user, Mapping):
        acc = _positive_int(user.get("mainAccountId"))
    if acc is not None:
        for row in (users_by_am or {}).values():
            if isinstance(row, Mapping) and _positive_int(row.get("mainAccountId")) == acc:
                rp = plan_id(row)
                if rp is not None:
                    plans.add(rp)
    return frozenset(plans)


def plan_refusal(settings: Mapping[str, Any], user: Any, users_by_am: Optional[Mapping[int, Any]],
                 account_id: Any = None, *, unknown_refusal: Optional[str]) -> Optional[str]:
    """DENY_PLAN_NOT_ALLOWED, or None. No plan list: None at once, without reading the member list.
    A person with no known plan gets ``unknown_refusal``: for a card DENY_PLAN_NOT_ALLOWED (the push
    writes no row without a plan when a list exists), for a QR unlisted_qr_refusal's answer (OD-3)."""
    allowed = allowed_plans(settings)
    if not allowed:
        return None
    plans = member_plan_ids(user, users_by_am, account_id)
    if not plans:
        return unknown_refusal
    return None if plans & allowed else DENY_PLAN_NOT_ALLOWED


def unlisted_qr_refusal(totp_result: Mapping[str, Any], settings: Mapping[str, Any]) -> Optional[str]:
    """OD-3 (owner, 2026-10-02): a recognised QR whose member is not on today's member list follows
    the QR member-list check. Trial lets it in (record_totp_roster_check counted it as
    not_in_roster); Enforce refuses it with DENY_NOT_IN_LOCAL_ROSTER -- verify_totp already does so
    before this step, so this gives the same answer here. The check's own never-refuse verdicts stay
    allowed, as the check treats them: roster_behind (the list is older than the index that matched)
    and roster_empty (no list to check)."""
    if (totp_result.get("rosterCheck") == ROSTER_NOT_IN
            and totp_roster_check_mode(settings) == ROSTER_MODE_ENFORCE):
        return DENY_NOT_IN_LOCAL_ROSTER
    return None


def _one_row_per_person(hits: Any, settings: Mapping[str, Any], staff_ids: Iterable[int] = ()) -> List[Any]:
    """The rows of one card number, with the rows of ONE person reduced to one: among the rows of a
    plan allowed on this device (every row when the device has no plan list), a STAFF row first,
    else the first; no allowed row, the first. load_local_state indexes one entry per
    member row, so a person with two plans and one card would read as DENY_CARD_COLLISION and never
    reach D6's "one of the member's plans". Rows of two different people (or of an unknown person)
    are kept, so verify_card's collision refusal still stands for them."""
    rows = [h for h in (hits if isinstance(hits, list) else [hits]) if isinstance(h, Mapping)]
    if len(rows) < 2:
        return rows
    persons = {member_key(r) for r in rows}
    if len(persons) != 1 or None in persons:
        return rows
    allowed = allowed_plans(settings)
    candidates = [r for r in rows if not allowed or plan_id(r) in allowed]
    if not candidates:
        return [rows[0]]
    staff_rows = [r for r in candidates if is_staff(r, staff_ids)]
    return [staff_rows[0] if staff_rows else candidates[0]]


def _blocked(guard: Optional[RepeatGuard], key: Optional[str], now: float) -> bool:
    return guard is not None and key is not None and guard.remaining(key, now=now) > 0


def decide_qr(*, totp_result: Any, settings: Mapping[str, Any], users_by_am: Optional[Mapping[int, Any]],
              staff_ids: Iterable[int], guard: Optional[RepeatGuard], now: float) -> Verdict:
    """A QR the turnstile refused. A code verify_totp refused keeps its reason; a matched code
    passes In service, the device's plans (D6; a member not on today's list follows the member-list
    check, OD-3) and the member block (staff exempt). The allowed reason is verify_totp's own ("ALLOW")."""
    result = totp_result if isinstance(totp_result, Mapping) else {}
    user = result.get("user") if isinstance(result.get("user"), Mapping) else None
    if not result.get("allowed"):
        return Verdict(False, str(result.get("reason") or "DENY_TOTP_FAILED"), user)
    if not in_service(settings):
        return Verdict(False, DENY_OUT_OF_SERVICE, user)
    account_id = result.get("accountId")
    staff = is_staff(user, staff_ids)
    key = member_key(user, account_id)
    refusal = plan_refusal(settings, user, users_by_am, account_id,
                           unknown_refusal=unlisted_qr_refusal(result, settings))
    if refusal:
        return Verdict(False, refusal, user, staff, key)
    if not staff and _blocked(guard, key, now):
        return Verdict(False, DENY_REPEAT_BLOCK, user, staff, key)
    return Verdict(True, str(result.get("reason") or "ALLOW"), user, staff, key)


def decide_pc_card(*, card_no: str, settings: Mapping[str, Any], users_by_card: Optional[Mapping[str, Any]],
                   users_by_am: Optional[Mapping[int, Any]], staff_ids: Iterable[int],
                   guard: Optional[RepeatGuard], now: float) -> Verdict:
    """A card on a device whose cards the PC decides (spec section 4). ``rfid_enabled`` (the old
    switch) does not apply: the card choice replaced it (spec section 3)."""
    if not in_service(settings):
        return Verdict(False, DENY_OUT_OF_SERVICE)
    if settings.get("card_decision") != CARDS_PC:
        return Verdict(False, DENY_NOT_PC_DECIDED)
    code = (card_no or "").strip()
    hits = _one_row_per_person((users_by_card or {}).get(code) or [], settings, staff_ids)
    vr = verify_card(scanned=code, settings={**dict(settings), "rfid_enabled": True},
                     users_by_card={code: hits} if hits else {})
    if not vr.get("allowed"):
        return Verdict(False, str(vr.get("reason") or "DENY_NO_CARD_MATCH"))
    user = vr.get("user") if isinstance(vr.get("user"), Mapping) else None
    staff = is_staff(user, staff_ids)
    key = member_key(user)
    refusal = plan_refusal(settings, user, users_by_am, unknown_refusal=DENY_PLAN_NOT_ALLOWED)
    if refusal:
        return Verdict(False, refusal, user, staff, key, True)
    if not staff and _blocked(guard, key, now):
        return Verdict(False, DENY_REPEAT_BLOCK, user, staff, key, True)
    return Verdict(True, ALLOW_PC_CARD, user, staff, key, True)


def decide_staff_card(*, card_no: str, settings: Mapping[str, Any], users_by_card: Optional[Mapping[str, Any]],
                      users_by_am: Optional[Mapping[int, Any]], staff_ids: Iterable[int]) -> Verdict:
    """A card the turnstile refused, on a device that does not leave cards to the PC: reopened only
    for a valid STAFF member -- verify_card (rfid_enabled, format, length, exactly one member,
    unchanged from the old rescue), the STAFF plan, and the device's plans (D6, OD-4). Cards OFF
    rescue nothing."""
    if not in_service(settings):
        return Verdict(False, DENY_OUT_OF_SERVICE)
    if settings.get("card_decision") == CARDS_OFF:
        return Verdict(False, DENY_CARDS_OFF)
    if not bool(settings.get("ultra_rfid_staff_rescue_enabled", True)):
        return Verdict(False, DENY_STAFF_RESCUE_OFF)
    vr = verify_card(scanned=card_no, settings=dict(settings), users_by_card=dict(users_by_card or {}))
    if not vr.get("allowed"):
        return Verdict(False, str(vr.get("reason") or "DENY_NO_CARD_MATCH"))
    user = vr.get("user") if isinstance(vr.get("user"), Mapping) else None
    key = member_key(user)
    if not is_staff(user, staff_ids):
        return Verdict(False, DENY_NOT_STAFF, user, False, key, True)
    refusal = plan_refusal(settings, user, users_by_am, unknown_refusal=DENY_PLAN_NOT_ALLOWED)
    if refusal:
        return Verdict(False, refusal, user, True, key, True)
    return Verdict(True, ALLOW_STAFF_RFID, user, True, key, True)

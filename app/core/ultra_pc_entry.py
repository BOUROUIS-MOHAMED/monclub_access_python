"""PC-decided entries on an ULTRA worker (ULTRA merge, spec 2026-10-02 section 4).

UltraDeviceWorker mixes this in. The verdicts are card_decision.py (pure); this module acts on them:
- _handle_rfid_rescue: a card the turnstile refused, reopened only for a valid STAFF member (the
  staff-card rescue, moved here from ultra_engine.py; its decision is card_decision.decide_staff_card);
- _handle_pc_card: a card on a device whose cards the PC decides (cardDecision = PC, C3 only);
- the QR rescue stays in ultra_engine.py::_handle_totp_rescue and calls card_decision.decide_qr,
  then _arm_member_block / _note_pc_refusal from here.

Allowed: open the door with the relay pulse (_open_door_with_retry: the door preset's pulse, else
pulse_time_ms), popup, history, then arm the member block (repeat_guard.py; never for staff).
Refused: the turnstile's refusal stands, the reason goes to the popup and the history, and
_note_pc_refusal records it -- plan 3 (desk_alerts.py) plays the refusal sound from there.

The worker provides: _settings, _prefix, _tel_wid, _get_cached_local_state, _open_door_with_retry,
_enqueue_notification, _enqueue_history, _handle_deny and _staff_membership_ids.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

from app.core import card_decision as _cd
from app.core import telemetry as _tel
from app.core.repeat_guard import RepeatGuard

logger = logging.getLogger("zkapp")


def _scan_mode_for_event(raw_row: Any, default: str = "RFID_CARD") -> str:
    """Popup/history scan_mode for one device event.

    ZK_STANDALONE (zkemkeeper / MB2000) reports the verify modality per punch and
    the driver publishes it as rawRow["scan_mode_hint"] (app/sdk/zk_standalone.py).
    PullSDK/C3 rows carry no such key, so C2-400 behaviour is byte-identical.

    CONFIDENT OVERRIDE ONLY: only FINGERPRINT is honoured. PASSWORD/UNKNOWN have no
    branch in the popup's method mapper and would render as "Carte" anyway, so
    emitting them buys nothing while leaking unmapped values into the scan_mode
    space that /door-history also consumes.
    """
    try:
        if isinstance(raw_row, dict):
            if str(raw_row.get("scan_mode_hint") or "").strip().upper() == "FINGERPRINT":
                return "FINGERPRINT"
    except Exception:
        pass
    return default


def _uid_for_alert(user: Any) -> Optional[int]:
    """userId out of a cached member dict, for the frequent-pass VISUAL alert only.

    Returns None whenever the member could not be resolved, which switches the
    alert off for that scan. Never raises and never participates in the access
    decision.
    """
    try:
        if isinstance(user, dict) and user.get("userId") not in (None, ""):
            return int(str(user.get("userId")).strip())
    except (ValueError, TypeError):
        pass
    return None


def reported_card(card_no: str, raw_row: Any) -> str:
    """The card number of a refused event; "" when it is not a card. A PullSDK row whose own
    ``cardno`` is empty carries the PIN in ``cardNo`` (a finger or PIN record,
    pullsdk.PullSDKDevice.poll_rtlog, F-004), and a number made only of zeros is no card."""
    card = str(card_no or "").strip()
    if isinstance(raw_row, dict) and "cardno" in raw_row:
        card = str(raw_row.get("cardno") or "").strip()
    return card if card.isdigit() and card.strip("0") else ""


def _mask(card_no: str) -> str:
    return card_no[0] + "*" * (len(card_no) - 2) + card_no[-1] if len(card_no) > 2 else card_no


def member_popup_fields(user: Any) -> Dict[str, Any]:
    """The member fields of an entry popup, from a cached member row; empty when unknown."""
    if not isinstance(user, dict):
        return {
            "user_full_name": "", "user_image": "", "user_membership_id": None,
            "user_membership_plan_id": None, "user_phone": "", "user_valid_from": "",
            "user_valid_to": "", "user_birthday": "", "image_source": "", "user_image_status": "",
            "user_profile_image": "", "user_id": None,
        }
    membership_id: Optional[int] = None
    raw_am_id = user.get("activeMembershipId")
    if raw_am_id is not None:
        try:
            membership_id = int(str(raw_am_id).strip())
        except (ValueError, TypeError):
            membership_id = None
    return {
        "user_full_name": str(user.get("fullName", user.get("full_name", user.get("name", ""))) or ""),
        "user_image": str(user.get("image", "") or ""),
        "user_membership_id": membership_id,
        "user_membership_plan_id": user.get("membershipId"),
        "user_phone": str(user.get("phone", "") or ""),
        "user_valid_from": str(user.get("validFrom", user.get("valid_from", "")) or ""),
        "user_valid_to": str(user.get("validTo", user.get("valid_to", "")) or ""),
        "user_birthday": str(user.get("birthday") or ""),
        "image_source": str(user.get("imageSource", "") or ""),
        "user_image_status": str(user.get("userImageStatus", "") or ""),
        "user_profile_image": str(user.get("userProfileImage", "") or ""),
        # for the frequent-pass visual alert only
        "user_id": _uid_for_alert(user),
    }


class PcEntryMixin:
    """The PC-decision steps of UltraDeviceWorker. No __init__: the worker's state is lazy."""

    def _member_guard(self) -> RepeatGuard:
        """This worker's member block (created on first use, so a worker built without __init__
        -- every test harness -- gets one too)."""
        guard = getattr(self, "_repeat_guard", None)
        if guard is None:
            guard = RepeatGuard()
            self._repeat_guard = guard
        return guard

    def _arm_member_block(self, verdict: "_cd.Verdict") -> None:
        """Start the member block after a door the PC opened (spec section 3). Staff never."""
        if verdict.staff or not verdict.member_key:
            return
        seconds = int(self._settings.get("member_block_seconds") or 0)
        if seconds > 0:
            self._member_guard().arm(verdict.member_key, seconds, now=time.monotonic())

    def _note_pc_refusal(self, verdict: "_cd.Verdict", *, kind: str, door_id: Optional[int]) -> None:
        """Every refusal a card_decision check added -- a PC card, a QR refused on the device's
        plans or by the member block, a staff card refused on the plans: one log line and
        [T] PC_DECISION. Plan 3 (desk_alerts.py) adds the refusal sound here."""
        logger.info(f"{self._prefix} PC_REFUSED: kind={kind} reason={verdict.reason} door={door_id}")
        _tel.event("PC_DECISION", worker=self._tel_wid, kind=kind, allowed=False,
                   reason=verdict.reason, door=door_id)

    def _open_for_verdict(
        self, verdict: "_cd.Verdict", *, kind: str, card_no: str, event_time: str, event_id: str,
        door_id: Optional[int], event_type: str, raw_row: Dict[str, Any],
    ) -> bool:
        """An allowed card verdict: open the door, then popup and history, then the member block."""
        fields = member_popup_fields(verdict.user)
        plan = fields["user_membership_plan_id"]
        tag = "RFID_STAFF_RESCUE" if kind == "staff" else "PC_CARD"
        logger.info(
            f"{self._prefix} {tag} opening: card={_mask(card_no)} user={fields['user_full_name']!r} "
            f"plan={plan} door={door_id} event_id={event_id}"
        )
        t_cmd = time.monotonic()
        door_opened = self._open_door_with_retry(door_id=door_id)
        cmd_ms = (time.monotonic() - t_cmd) * 1000
        reason = verdict.reason if door_opened else "DOOR_CMD_FAILED"
        if kind == "staff":
            _tel.event("RFID_STAFF_RESCUE", worker=self._tel_wid, ok=door_opened,
                       plan=plan, cmd_ms=round(cmd_ms), event_id=event_id)
        else:
            _tel.event("PC_DECISION", worker=self._tel_wid, kind=kind, allowed=door_opened,
                       reason=reason, door=door_id)
        if door_opened:
            self._arm_member_block(verdict)
        self._enqueue_notification(
            event_id=event_id, allowed=door_opened, reason=reason,
            scan_mode=_scan_mode_for_event(raw_row), door_id=door_id, **fields,
        )
        self._enqueue_history(
            event_id=event_id, allowed=door_opened, reason=reason, event_type=event_type,
            card_no=card_no, event_time=event_time, door_id=door_id, raw=raw_row,
        )
        return door_opened

    def _handle_rfid_rescue(
        self, card_no: str, event_time: str, event_id: str,
        door_id: Optional[int], event_type: str, raw_row: Dict[str, Any],
    ):
        """PC-side STAFF rescue for a denied RFID card.

        The device denied this card (unknown, or -- the common case -- its punch-interval re-entry
        block fired). If the card is a VALID member whose plan is STAFF and one of the device's
        plans (D6), the PC re-opens the door so staff skip the re-entry delay. Every other denied
        card falls through to _handle_deny, so the device's decision stands.

        SECURITY: opens ONLY when card_decision.decide_staff_card allows: rfid enabled, format and
        length, exactly one active-member match (verify_card), a STAFF plan, the device's plans,
        cards not OFF. Runs on the worker thread; opens via the held SDK socket (no 2nd Connect).
        """
        if not bool(self._settings.get("ultra_rfid_staff_rescue_enabled", True)):
            self._handle_deny(card_no, event_time, event_id, door_id, event_type, raw_row)
            return
        t0 = time.monotonic()
        _creds, users_by_am, users_by_card = self._get_cached_local_state()
        staff_ids = self._staff_membership_ids()
        verdict = _cd.decide_staff_card(
            card_no=card_no, settings=self._settings, users_by_card=users_by_card,
            users_by_am=users_by_am, staff_ids=staff_ids,
        )
        # Observability for the staff blind spot (unchanged): valid = a recognised active member,
        # staff_n = size of the STAFF plan set (0 => backend membersType not deployed), staff =
        # matched, plan = the member's plan.
        _tel.event(
            "RFID_RESCUE_EVAL", worker=self._tel_wid, valid=verdict.card_valid,
            staff=verdict.staff, staff_n=len(staff_ids), plan=_cd.plan_id(verdict.user),
            event_id=event_id,
        )
        if not verdict.allowed:
            if verdict.reason == _cd.DENY_PLAN_NOT_ALLOWED:
                self._note_pc_refusal(verdict, kind="staff", door_id=door_id)
            self._handle_deny(card_no, event_time, event_id, door_id, event_type, raw_row)
            return
        self._open_for_verdict(
            verdict, kind="staff", card_no=card_no, event_time=event_time, event_id=event_id,
            door_id=door_id, event_type=event_type, raw_row=raw_row,
        )
        if (time.monotonic() - t0) * 1000 >= 250:
            _tel.warn("RFID_RESCUE_SLOW", worker=self._tel_wid,
                      dur_ms=round((time.monotonic() - t0) * 1000))

    def _handle_pc_card(
        self, card_no: str, event_time: str, event_id: str,
        door_id: Optional[int], event_type: str, raw_row: Dict[str, Any],
    ):
        """A card on a device whose cards the PC decides (spec section 4). The turnstile holds no
        card, refused this one and reported it. The PC checks In service, the card and its member,
        the device's plans (D6), the card length and the member block, then opens or lets the
        refusal stand -- with its reason on the popup and in the history."""
        card = reported_card(card_no, raw_row)
        if not card:
            # Not a card (a finger or PIN record carries the PIN; a door or alarm record carries
            # nothing or zeros): today's denied-event path, never a PC card decision.
            self._handle_deny(card_no, event_time, event_id, door_id, event_type, raw_row)
            return
        card_no = card
        _creds, users_by_am, users_by_card = self._get_cached_local_state()
        verdict = _cd.decide_pc_card(
            card_no=card_no, settings=self._settings, users_by_card=users_by_card,
            users_by_am=users_by_am, staff_ids=self._staff_membership_ids(),
            guard=self._member_guard(), now=time.monotonic(),
        )
        if verdict.allowed:
            self._open_for_verdict(
                verdict, kind="card", card_no=card_no, event_time=event_time, event_id=event_id,
                door_id=door_id, event_type=event_type, raw_row=raw_row,
            )
            return
        self._note_pc_refusal(verdict, kind="card", door_id=door_id)
        self._enqueue_notification(
            event_id=event_id, allowed=False, reason=verdict.reason,
            scan_mode=_scan_mode_for_event(raw_row), door_id=door_id,
            **member_popup_fields(verdict.user),
        )
        self._enqueue_history(
            event_id=event_id, allowed=False, reason=verdict.reason, event_type=event_type,
            card_no=card_no, event_time=event_time, door_id=door_id, raw=raw_row,
        )

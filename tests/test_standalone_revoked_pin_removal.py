"""A member who LEAVES the roster must lose access on the terminal.

FIELD REPORT, Oxyfit 2026-09-06. The operator set his membership to CANCELED,
then COMPLETED, INACTIVE, PENDING and EXPIRED in turn, and **kept opening the
turnstile every time**.

The backend is right: shouldExposeMembership (AccessPatchBundleService:449)
rejects any status that is not ACTIVE, plus unavailable / not-yet-started /
ended / frozen memberships, and emits entityDelete("ACTIVE_MEMBERSHIP", id). The
member correctly disappears from sync_users.

The client then did NOTHING to the device. The only device-side removal in the
standalone engine is _maybe_mirror_reconcile -> delete_users, which returns
immediately unless rosterPushingPolicy == "MIRROR" -- and PRESERVE is the default
that every gym runs. prune_device_sync_state then deleted the local record of the
departed pin, destroying the very information needed to clear it later.

On a ZK_STANDALONE terminal the device decides and opens; the PC only observes
(rtlog "reason=DEVICE_ALLOWED"). There is no PC-side veto. So leaving the
credential on the terminal IS granting access. A cancelled member kept entering
indefinitely.

DELETE, WITH NEUTRALISE AS THE FALLBACK
---------------------------------------
The departed pin is DELETED outright: delete_users -> SSR_DeleteEnrollData(1, pin, 12).
The vendor manual defines backupNumber 12 as "delete the user (including all
fingerprints, card numbers and passwords)", and the operator ran exactly that
against the live MB2000 through tools/mb2000_scripts/13_inspect_and_clear_tables.ps1
on 2026-09-06 and cleared the users and fingerprint tables successfully — which is
what finally retired the [UNKNOWN] on backup number 12.

A delete that FAILS for a pin still has to end in no access, so those pins fall
back to being neutralised (blank card, no fingers, enabled=False). The fallback is
targeted at the pins that actually failed: SSR_SetUserInfo auto-creates, so
neutralising a pin that WAS deleted would resurrect it as an empty row.

WHY THIS CANNOT TOUCH THE OTHER SYSTEM'S MEMBERS
------------------------------------------------
The revocation set is drawn from device_sync_state -- pins THIS app pushed. At
Oxyfit the terminal also holds ~930 users belonging to a second, non-MonClub
access system. They were never in device_sync_state, so they can never be
selected. That ownership rule is what makes this safe where MIRROR is not.
"""
from __future__ import annotations

from typing import Any, Dict, List

import pytest

import app.core.db as dbmod
import app.core.ultra_engine as ue

from tests.test_standalone_incremental_sync import _tpl, _user, _worker, _full_sync
from tests.test_standalone_finger_removal_state import FingerState, fstate  # noqa: F401


class RevokeDriver:
    """Records push_roster and delete_users. `fail_delete` names pins whose
    SSR_DeleteEnrollData is to be reported as failed."""
    owns_event_source = True

    def __init__(self, fail_delete: set[str] | None = None):
        self.push_calls: List[dict] = []
        self.delete_calls: List[List[str]] = []
        self._fail_delete = set(fail_delete or ())

    def delete_users(self, pins, *, timeout_sec: float = 300.0):
        pins = [str(p) for p in pins]
        self.delete_calls.append(list(pins))
        failed = [p for p in pins if p in self._fail_delete]
        return {"ok": not failed, "deleted": len(pins) - len(failed),
                "failed": len(failed), "failed_pins": failed, "errors": []}

    def push_roster(self, users, templates_by_pin=None, *, remove_fingers_by_pin=None,
                    bracket_enable_device=False, **kw):
        self.push_calls.append({
            "users": [dict(u) for u in users],
            "templates": dict(templates_by_pin or {}),
            "removals": {k: sorted(v) for k, v in (remove_fingers_by_pin or {}).items()},
        })
        return {"ok": True, "pushed": len(users), "failed": 0, "templates_failed": 0,
                "skipped_pin": 0, "chunks_wedged": 0, "errors": [], "failed_pins": [],
                "del_attempted": 0, "del_ok": 0}


def _revoked_push(drv: RevokeDriver) -> dict | None:
    """The push whose users are all disabled -- the neutralise pass."""
    for call in drv.push_calls:
        if call["users"] and all(u.get("enabled") is False for u in call["users"]):
            return call
    return None


class TestARevokedMemberLosesTheirCredentials:

    def test_a_member_who_leaves_the_roster_is_DELETED_from_the_device(
            self, monkeypatch, fstate):
        """The field case: membership set to CANCELED, so the member is gone."""
        drv = RevokeDriver()
        # roster no longer contains 34439 at all
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "someone else", "")])
        # ...but we pushed them before, with finger 0 and a card
        fstate.rows["34439"] = ("old-hash", True, {0})

        _full_sync(w)

        assert drv.delete_calls == [["34439"]], "the departed pin must be DELETED"
        assert _revoked_push(drv) is None, "a clean delete needs no neutralise fallback"

    def test_a_pin_the_delete_could_not_remove_falls_back_to_neutralise(
            self, monkeypatch, fstate):
        """A failed delete must still end in no access."""
        drv = RevokeDriver(fail_delete={"34439"})
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "a", "")])
        fstate.rows["34439"] = ("old-hash", True, {0})
        fstate.rows["34440"] = ("old-hash", True, {1})

        _full_sync(w)

        assert drv.delete_calls == [["34439", "34440"]]
        call = _revoked_push(drv)
        assert call is not None, "the pin that survived the delete must be neutralised"
        assert [u["pin"] for u in call["users"]] == ["34439"], (
            "only the FAILED pin -- SSR_SetUserInfo auto-creates, so neutralising a "
            "successfully deleted pin would resurrect it as an empty row"
        )
        assert call["removals"] == {"34439": [0]}
        assert call["users"][0]["card"] == ""
        assert call["users"][0]["enabled"] is False

    def test_pins_we_never_pushed_are_never_touched(self, monkeypatch, fstate):
        """Oxyfit: the terminal holds ~930 users from a SECOND access system. They
        are not in device_sync_state, so they must be invisible to this path."""
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "a", "")])
        fstate.rows["30001"] = ("h", True, set())     # the only pin we own

        _full_sync(w)

        assert drv.delete_calls == [], "nothing to revoke; the foreign pins are not ours"

    def test_a_member_still_in_the_roster_is_never_revoked(self, monkeypatch, fstate):
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv,
                        users=[_user(34439, "malek", "", [_tpl(0, "AAAA")])])
        fstate.rows["34439"] = ("old-hash", True, {0})

        _full_sync(w)

        assert drv.delete_calls == []

    def test_state_is_pruned_only_after_the_revoke_pass(self, monkeypatch, fstate):
        """prune_device_sync_state deletes the record of what we pushed. If it runs
        first, the finger ids are gone and a fallback could never clear the slot."""
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "a", "")])
        fstate.rows["34439"] = ("old-hash", True, {0})

        _full_sync(w)

        assert drv.delete_calls == [["34439"]]
        assert "34439" not in fstate.rows, "the departed pin's state must then be pruned"


class TestSafetyRails:

    def test_an_empty_roster_never_revokes_anything(self, monkeypatch, fstate):
        """A failed or half-built sync must not be read as 'everyone left'."""
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[])
        for pin in ("30001", "30002", "30003"):
            fstate.rows[pin] = ("h", True, {0})

        _full_sync(w)

        assert drv.delete_calls == [] and _revoked_push(drv) is None

    def test_a_mass_departure_aborts_rather_than_revoking(self, monkeypatch, fstate):
        """Same percent floor MIRROR uses: refuse an implausible bulk revocation."""
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "a", "")])
        for i in range(50):                      # 50 departed vs a 1-member roster
            fstate.rows[str(40000 + i)] = ("h", True, {0})

        _full_sync(w)

        assert drv.delete_calls == [], "an implausible bulk revocation must abort"
        assert "40000" in fstate.rows, "and the state must NOT be pruned after an abort"

    def test_a_failed_push_does_not_trigger_revocation(self, monkeypatch, fstate):
        """Revocation runs only after a SUCCESSFUL push, like MIRROR."""
        class _Failing(RevokeDriver):
            def push_roster(self, users, templates_by_pin=None, **kw):
                super().push_roster(users, templates_by_pin, **kw)
                return {"ok": False, "pushed": 0, "failed": len(users),
                        "templates_failed": 0, "skipped_pin": 0, "chunks_wedged": 0,
                        "errors": ["boom"], "failed_pins": [str(u["pin"]) for u in users]}

        drv = _Failing()
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "a", "")])
        fstate.rows["34439"] = ("old-hash", True, {0})

        _full_sync(w)

        assert drv.delete_calls == []

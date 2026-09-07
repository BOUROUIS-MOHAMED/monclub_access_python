"""ZK_STANDALONE (MB2000) finger-slot REMOVAL.

Field incident, Oxyfit gym, 2026-09-05: a fingerprint deleted from the dashboard
kept opening the turnstile. The delete reached the local DB (the push went from
``templates_for=1`` to ``templates_for=0``) but no COM call was ever issued for
the vacated slot, so the terminal kept the template and went on verifying it
(``ZKEM_VERIFY_OK`` / rtlog ALLOW, 29 minutes after the delete).

Cause: the only slot clear in the driver sits INSIDE the loop over the templates
the member STILL has, so an empty desired set means the loop body never runs. The
template mirror is write-only: it can add and overwrite, it can never remove.

These tests pin the two halves of the fix:
  1. the clear's return value is CAPTURED (it used to be a bare expression inside
     ``except Exception: pass``, so nothing downstream could tell "cleared" from
     "refused" from "threw" -- which made any removal fix unverifiable);
  2. slots that were pushed before and are no longer desired ARE cleared.

Everything runs against the fake COM object -- no hardware.
"""
from __future__ import annotations

from tests.test_zk_standalone_driver import FakeZkem, _make_driver


_TPL = {"fingerId": 0, "templateVersion": 10, "templateData": "QUJD", "templateSize": 3}


class TestClearOutcomeIsObservable:
    """The driver must report what the terminal actually did with each clear."""

    def test_clear_attempts_and_successes_are_reported(self):
        drv, zk = _make_driver()
        drv.connect()
        try:
            res = drv.push_roster(
                [{"pin": "117", "name": "Bob", "card": ""}],
                {"117": [dict(_TPL)]},
            )
        finally:
            drv.disconnect()

        # One template written => exactly one delete-before-write clear.
        assert res["del_attempted"] == 1
        assert res["del_ok"] == 1

    def test_a_refused_clear_is_not_counted_as_ok(self):
        """A firmware that refuses the clear must be distinguishable from success.

        Without this the driver reports the same numbers whether the slot was
        emptied or not, and the removal fix built on top would be unfalsifiable.
        """
        zk = FakeZkem()
        zk.delusertmp_ok = False
        drv, zk = _make_driver(fake=zk)
        drv.connect()
        try:
            res = drv.push_roster(
                [{"pin": "117", "name": "Bob", "card": ""}],
                {"117": [dict(_TPL)]},
            )
        finally:
            drv.disconnect()

        assert res["del_attempted"] == 1
        assert res["del_ok"] == 0


class TestVacatedSlotsAreCleared:
    """The reported bug: a finger removed from the desired set must leave the device."""

    def test_removing_the_only_finger_still_clears_its_slot(self):
        """The exact field scenario: templates_for drops 1 -> 0 for a member who
        stays in the roster. The slot must be cleared even though the template
        loop has nothing to iterate."""
        drv, zk = _make_driver()
        drv.connect()
        try:
            res = drv.push_roster(
                [{"pin": "117", "name": "Bob", "card": ""}],
                {},                                   # no templates left
                remove_fingers_by_pin={"117": [0]},   # ...but finger 0 was pushed before
            )
        finally:
            drv.disconnect()

        assert res["ok"] is True
        assert ("117", 0) in zk.deleted
        assert res["del_attempted"] == 1
        assert res["del_ok"] == 1

    def test_partial_removal_clears_only_the_vacated_slot(self):
        """Had fingers 0 and 2, finger 2 deleted: 0 is rewritten, 2 is cleared."""
        drv, zk = _make_driver()
        drv.connect()
        try:
            drv.push_roster(
                [{"pin": "117", "name": "Bob", "card": ""}],
                {"117": [dict(_TPL)]},                # finger 0 still desired
                remove_fingers_by_pin={"117": [2]},   # finger 2 gone
            )
        finally:
            drv.disconnect()

        assert ("117", 2) in zk.deleted
        # finger 0 is cleared too, but as part of its normal delete-before-write
        assert ("117", 0) in zk.deleted

    def test_refused_vacated_slot_clear_marks_the_pin_failed(self):
        zk = FakeZkem()
        zk.delusertmp_ok = False
        drv, zk = _make_driver(fake=zk)
        drv.connect()
        try:
            res = drv.push_roster(
                [{"pin": "117", "name": "", "card": "", "enabled": False}],
                {},
                remove_fingers_by_pin={"117": [0]},
            )
        finally:
            drv.disconnect()

        assert res["ok"] is False
        assert res["failed_pins"] == ["117"]
        assert res["del_attempted"] == 1
        assert res["del_ok"] == 0

    def test_raised_vacated_slot_clear_marks_the_pin_failed(self):
        class RaisingClearZkem(FakeZkem):
            def SSR_DelUserTmpExt(self, machine, pin, finger_id):
                self._rec("SSR_DelUserTmpExt", machine, pin, finger_id)
                raise RuntimeError("clear boom")

        drv, zk = _make_driver(fake=RaisingClearZkem())
        drv.connect()
        try:
            res = drv.push_roster(
                [{"pin": "117", "name": "", "card": "", "enabled": False}],
                {},
                remove_fingers_by_pin={"117": [0]},
            )
        finally:
            drv.disconnect()

        assert res["ok"] is False
        assert res["failed_pins"] == ["117"]
        assert res["del_attempted"] == 1
        assert res["del_ok"] == 0

    def test_a_slot_that_is_still_desired_is_never_in_the_removal_set(self):
        """Belt and braces: a caller that wrongly asks to remove a desired finger
        must not end up with the template deleted after it was written."""
        drv, zk = _make_driver()
        drv.connect()
        try:
            drv.push_roster(
                [{"pin": "117", "name": "Bob", "card": ""}],
                {"117": [dict(_TPL)]},
                remove_fingers_by_pin={"117": [0]},   # contradicts the desired set
            )
        finally:
            drv.disconnect()

        names = [c[0] for c in zk.calls]
        # The write must be the LAST thing that touches slot 0.
        assert names[-1] != "SSR_DelUserTmpExt" or names.index("SetUserTmpExStr") > 0
        writes = [c for c in zk.calls if c[0] == "SetUserTmpExStr"]
        assert writes, "the still-desired template must still be written"
        last_touch = max(
            i for i, c in enumerate(zk.calls)
            if c[0] in ("SSR_DelUserTmpExt", "SetUserTmpExStr") and c[3] == 0
        )
        assert zk.calls[last_touch][0] == "SetUserTmpExStr"

    def test_no_removal_set_means_no_extra_clears(self):
        """Steady state must cost exactly what it costs today."""
        drv, zk = _make_driver()
        drv.connect()
        try:
            drv.push_roster([{"pin": "117", "name": "Bob", "card": ""}], {})
        finally:
            drv.disconnect()

        assert zk.deleted == []

    def test_the_removal_uses_the_proven_api_never_delete_enroll_data(self):
        """SSR_DeleteEnrollData with a finger index never returns on this firmware."""
        drv, zk = _make_driver()
        drv.connect()
        try:
            drv.push_roster(
                [{"pin": "117", "name": "Bob", "card": ""}],
                {},
                remove_fingers_by_pin={"117": [0, 2]},
            )
        finally:
            drv.disconnect()

        names = [c[0] for c in zk.calls]
        assert "SSR_DeleteEnrollData" not in names
        assert names.count("SSR_DelUserTmpExt") == 2

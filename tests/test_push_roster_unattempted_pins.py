"""A push that STOPS early must never report the members it never sent as landed.

``ZKStandaloneDevice.push_roster`` has three ``break`` exits in its wedge handler:
three consecutive wedged chunks, a reconnect that returns False, and a reconnect
that raises. Before P3a-2 the chunks after a ``break`` were never attempted and
their pins never reached ``failed_pins``. The engine
(``_standalone_failed_pins_from_result`` -> ``_record_standalone_pin_state``) then
recorded every one of them ``ok=True``: ``ownership_confirmed=1`` plus a stored hash.
So a member who was never written was skipped as "unchanged" forever, and -- on the
shared gym-45 MB2000s -- became a revoke-pass delete candidate for a pin that may
hold another system's user.

Driver: every unattempted pin is named, reason ``not_attempted``.
Engine: a result whose confirmed pins outnumber what the driver says it pushed is
ambiguous and confirms nothing (defence for a driver without the fix).

No real COM, no database: the driver runs its real STA thread over a fake COM
object and ``_refresh_pin_card_map`` is stubbed (see ``_make_driver``).
"""
from __future__ import annotations

import pytest

import app.core.ultra_engine as ue
from tests.test_standalone_incremental_sync import _FakeZkem, _make_driver


def _users(n: int) -> list[dict]:
    return [{"pin": str(i), "name": "x", "card": ""} for i in range(n)]


def _wedge_on(drv, monkeypatch, chunk_numbers: set[int]):
    """Make the Nth push_roster STA command wedge (abandon + TimeoutError)."""
    from app.sdk import zk_standalone as zs

    real_call = drv._call
    state = {"n": 0}

    def _call(op, args=None, timeout=zs._DEFAULT_CMD_TIMEOUT_SEC):
        if op == "push_roster":
            state["n"] += 1
            if state["n"] in chunk_numbers:
                drv._abandon_sta_thread("simulated wedge")
                raise TimeoutError("zkemkeeper command 'push_roster' timed out")
        return real_call(op, args=args, timeout=timeout)

    monkeypatch.setattr(drv, "_call", _call)
    return state


class TestDriverNamesUnattemptedPins:
    def test_reconnect_false_after_a_wedge_names_every_remaining_pin(self, monkeypatch):
        drv = _make_driver(_FakeZkem())
        _wedge_on(drv, monkeypatch, {2})
        monkeypatch.setattr(drv, "connect", lambda: False)
        try:
            res = drv.push_roster(_users(35), {})   # chunks 0-9, 10-19, 20-29, 30-34
        finally:
            drv.disconnect()
        assert res["ok"] is False
        assert res["pushed"] == 10, "only chunk 1 landed"
        assert set(res["failed_pins"]) == {str(i) for i in range(10, 35)}, (
            "the wedged chunk AND every chunk after the break must be unconfirmed"
        )
        assert res["not_attempted"] == 15

    def test_reconnect_raising_after_a_wedge_names_every_remaining_pin(self, monkeypatch):
        drv = _make_driver(_FakeZkem())
        _wedge_on(drv, monkeypatch, {1})

        def _boom():
            raise RuntimeError("COM gone")

        monkeypatch.setattr(drv, "connect", _boom)
        try:
            res = drv.push_roster(_users(25), {})
        finally:
            drv.disconnect()
        assert res["pushed"] == 0
        assert set(res["failed_pins"]) == {str(i) for i in range(25)}
        assert res["not_attempted"] == 15

    def test_the_consecutive_wedge_cap_names_every_remaining_pin(self):
        from app.sdk.zk_standalone import ZKStandaloneDevice, _PUSH_MAX_CONSECUTIVE_WEDGES

        drv = ZKStandaloneDevice({"id": 9, "ipAddress": "10.0.0.9"}, logger=None)
        drv.connect = lambda: True  # type: ignore[method-assign]

        def always_wedge(op, args=None, timeout=None):
            raise TimeoutError("timed out")

        drv._call = always_wedge  # type: ignore[method-assign]
        drv._refresh_pin_card_map = lambda: None  # type: ignore[method-assign]
        res = drv.push_roster(_users(950), {})
        assert res["chunks_wedged"] == _PUSH_MAX_CONSECUTIVE_WEDGES
        assert len(res["failed_pins"]) == 950, "30 wedged + 920 never attempted"
        assert res["not_attempted"] == 950 - 10 * _PUSH_MAX_CONSECUTIVE_WEDGES

    def test_a_push_that_completes_reports_nothing_unattempted(self):
        drv = _make_driver(_FakeZkem())
        try:
            res = drv.push_roster(_users(25), {})
        finally:
            drv.disconnect()
        assert res["ok"] is True
        assert res["failed_pins"] == []
        assert res["not_attempted"] == 0


class TestEngineConfirmsNothingOnAnAmbiguousResult:
    """Defence in depth: a driver WITHOUT the fix (or any driver) whose result
    confirms more pins than it says it pushed must confirm none of them."""

    def test_pins_the_driver_did_not_push_are_not_confirmed(self):
        users = [{"pin": str(i)} for i in range(25)]
        # The pre-fix shape: chunk 2 wedged, the break skipped chunk 3, and only
        # the wedged chunk's pins were named.
        result = {"ok": False, "pushed": 10, "failed": 0, "templates_failed": 0,
                  "skipped_pin": 0, "chunks_wedged": 1, "errors": ["wedge"],
                  "failed_pins": [str(i) for i in range(10, 20)]}
        failed = ue.UltraDeviceWorker._standalone_failed_pins_from_result(
            users=users, result=result,
        )
        assert failed == {str(i) for i in range(25)}

    def test_a_consistent_partial_result_is_still_trusted(self):
        users = [{"pin": str(i)} for i in range(25)]
        result = {"ok": False, "pushed": 15, "failed": 0, "templates_failed": 0,
                  "skipped_pin": 0, "chunks_wedged": 1, "errors": ["wedge"],
                  "failed_pins": [str(i) for i in range(10, 20)]}
        failed = ue.UltraDeviceWorker._standalone_failed_pins_from_result(
            users=users, result=result,
        )
        assert failed == {str(i) for i in range(10, 20)}

    @pytest.mark.parametrize("pushed", [None, "15"])
    def test_a_missing_or_malformed_pushed_count_is_not_a_consistency_check(self, pushed):
        """Only an int ``pushed`` can prove an inconsistency; absent it, the
        existing contract (trust a well-formed failed_pins) is unchanged."""
        users = [{"pin": str(i)} for i in range(3)]
        result = {"ok": False, "errors": ["x"], "failed_pins": ["1"]}
        if pushed is not None:
            result["pushed"] = pushed
        failed = ue.UltraDeviceWorker._standalone_failed_pins_from_result(
            users=users, result=result,
        )
        assert failed == {"1"}

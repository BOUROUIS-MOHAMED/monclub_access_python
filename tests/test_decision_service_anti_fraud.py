"""
Integration tests: AntiFraudGuard wired into DecisionService.

Pattern mirrors test_launch_safety_regressions.py: run the service in a
background thread for a short burst, patch the DB/verify calls, then check
the guard state.
"""
from __future__ import annotations

import queue
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from app.core.anti_fraud import AntiFraudGuard
from app.core.realtime_agent import CommandResult, DecisionService, EMA, NotificationGate
from app.core.access_types import AccessEvent


DEVICE_ID = 42
CARD_NO = "9ABC1234"
CRED_ID = "cred-uuid-0001"


class _DummyLogger:
    def info(self, *a, **k): pass
    def warning(self, *a, **k): pass
    def error(self, *a, **k): pass
    def exception(self, *a, **k): pass
    def debug(self, *a, **k): pass


AF_SETTINGS = {
    "enabled": True,
    "totp_enabled": False,
    "rfid_enabled": True,
    "anti_fraude_card": True,
    "anti_fraude_qr_code": True,
    "anti_fraude_duration": 30,
    "save_history": False,   # skip DB writes in unit tests
    "show_notifications": False,
    "win_notify_enabled": False,
    "popup_enabled": False,
    "door_ids": [1],
    "door_entry_id": 1,
    "pulse_time_ms": 200,
    "cmd_timeout_ms": 5000,
    "timeout_ms": 5000,
    "door_presets": [],
}


def _make_ds(settings_override=None, guard=None):
    settings = {**AF_SETTINGS, **(settings_override or {})}
    cmd_bus = MagicMock()
    cmd_bus.open_door.return_value = CommandResult(ok=True, error="", cmd_ms=0.0)
    ds = DecisionService(
        logger=_DummyLogger(),
        event_queue=queue.Queue(),
        command_bus=cmd_bus,
        notify_q=queue.Queue(),
        popup_q=queue.Queue(),
        history_q=queue.Queue(),
        settings_provider=lambda _: settings,
        global_settings=lambda: {},
        notify_gate=NotificationGate(global_settings=lambda: {}),
        decision_ema=EMA(alpha=0.1),
        guard=guard or AntiFraudGuard(),
    )
    return ds, cmd_bus


def _run_one_event(ds: DecisionService, ev: AccessEvent, timeout: float = 0.5) -> None:
    """Start service, push one event, wait briefly, stop."""
    ds.event_queue.put(ev)
    ds.start()
    time.sleep(timeout)
    ds.stop()


def _make_event(**kwargs) -> AccessEvent:
    base = dict(
        event_id="evt-001",
        device_id=DEVICE_ID,
        door_id=1,
        event_type="RTLOG",
        card_no=CARD_NO,
        event_time="2026-04-08T12:00:00",
        raw={},
        poll_ms=10.0,
    )
    base.update(kwargs)
    return AccessEvent(**base)


# ---------------------------------------------------------------------------
# Card anti-fraud pre-check
# ---------------------------------------------------------------------------

class TestCardPreCheck:
    def test_verify_totp_skipped_when_card_blocked(self):
        guard = AntiFraudGuard()
        guard.record(DEVICE_ID, CARD_NO, "card", 30.0)

        ds, cmd_bus = _make_ds(guard=guard)
        ev = _make_event()

        with (
            patch("app.core.realtime_agent.access_history_exists", return_value=False),
            patch("app.core.realtime_agent.insert_access_history", return_value=0),
            patch.object(ds, "_verify_totp") as mock_verify,
        ):
            _run_one_event(ds, ev)
            mock_verify.assert_not_called()

        cmd_bus.open_door.assert_not_called()

    def test_verify_totp_called_when_card_not_blocked(self):
        guard = AntiFraudGuard()
        ds, cmd_bus = _make_ds(guard=guard)
        ev = _make_event()

        with (
            patch("app.core.realtime_agent.access_history_exists", return_value=False),
            patch("app.core.realtime_agent.insert_access_history", return_value=0),
            patch.object(
                ds, "_verify_totp",
                return_value={"allowed": False, "reason": "DENY_UNKNOWN_CARD", "scanMode": "RFID"},
            ) as mock_verify,
            patch.object(ds, "_load_local_state", return_value=([], {}, {})),
        ):
            _run_one_event(ds, ev)
            mock_verify.assert_called_once()

    def test_card_check_skipped_when_anti_fraude_card_disabled(self):
        guard = AntiFraudGuard()
        guard.record(DEVICE_ID, CARD_NO, "card", 30.0)  # would block

        ds, cmd_bus = _make_ds(
            settings_override={"anti_fraude_card": False},
            guard=guard,
        )
        ev = _make_event()

        with (
            patch("app.core.realtime_agent.access_history_exists", return_value=False),
            patch("app.core.realtime_agent.insert_access_history", return_value=0),
            patch.object(
                ds, "_verify_totp",
                return_value={"allowed": False, "reason": "DENY_UNKNOWN_CARD", "scanMode": "RFID"},
            ) as mock_verify,
            patch.object(ds, "_load_local_state", return_value=([], {}, {})),
        ):
            _run_one_event(ds, ev)
            # anti_fraude_card=False → guard is bypassed → verify_totp is called
            mock_verify.assert_called_once()


# ---------------------------------------------------------------------------
# guard.record() after successful grant
# ---------------------------------------------------------------------------

class TestGuardRecord:
    def test_record_called_after_allowed_grant(self):
        guard = AntiFraudGuard()
        # save_history=True so insert_access_history is called and _history_claimed > 0
        ds, cmd_bus = _make_ds(settings_override={"save_history": True}, guard=guard)
        ev = _make_event()

        with (
            patch("app.core.realtime_agent.access_history_exists", return_value=False),
            patch("app.core.realtime_agent.insert_access_history", return_value=1),
            patch.object(
                ds, "_verify_totp",
                return_value={"allowed": True, "reason": "GRANT", "scanMode": "RFID"},
            ),
            patch.object(ds, "_load_local_state", return_value=([], {}, {})),
        ):
            _run_one_event(ds, ev)

        blocked, _ = guard.check(DEVICE_ID, CARD_NO, "card")
        assert blocked is True

    def test_record_not_called_when_history_not_claimed(self):
        guard = AntiFraudGuard()
        ds, cmd_bus = _make_ds(guard=guard)
        ev = _make_event()

        with (
            patch("app.core.realtime_agent.access_history_exists", return_value=False),
            patch("app.core.realtime_agent.insert_access_history", return_value=0),
            patch.object(
                ds, "_verify_totp",
                return_value={"allowed": True, "reason": "GRANT", "scanMode": "RFID"},
            ),
            patch.object(ds, "_load_local_state", return_value=([], {}, {})),
        ):
            _run_one_event(ds, ev)

        blocked, _ = guard.check(DEVICE_ID, CARD_NO, "card")
        assert blocked is False  # not recorded because rowcount=0

    def test_record_not_called_when_denied(self):
        guard = AntiFraudGuard()
        ds, cmd_bus = _make_ds(guard=guard)
        ev = _make_event()

        with (
            patch("app.core.realtime_agent.access_history_exists", return_value=False),
            patch("app.core.realtime_agent.insert_access_history", return_value=1),
            patch.object(
                ds, "_verify_totp",
                return_value={"allowed": False, "reason": "DENY_UNKNOWN_CARD", "scanMode": "RFID"},
            ),
            patch.object(ds, "_load_local_state", return_value=([], {}, {})),
        ):
            _run_one_event(ds, ev)

        blocked, _ = guard.check(DEVICE_ID, CARD_NO, "card")
        assert blocked is False  # allowed=False → not recorded

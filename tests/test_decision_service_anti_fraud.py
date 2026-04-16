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


def _make_ds(settings_override=None, guard=None, feedback_callback=None):
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
        feedback_callback=feedback_callback,
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


# ---------------------------------------------------------------------------
# Audio feedback for duration block (Task 2.8) and daily-limit alert (Task 2.9)
# ---------------------------------------------------------------------------

class TestAntiFraudAudioFeedback:
    """Verify feedback_callback fires on anti-fraud events (sound/toast cues)."""

    def test_duration_card_block_emits_anti_fraud_duration(self):
        guard = AntiFraudGuard()
        guard.record(DEVICE_ID, CARD_NO, "card", 30.0)  # pre-block
        events = []
        ds, _ = _make_ds(
            guard=guard,
            feedback_callback=lambda kind, payload: events.append((kind, payload)),
        )
        ev = _make_event()

        with (
            patch("app.core.realtime_agent.access_history_exists", return_value=False),
            patch("app.core.realtime_agent.insert_access_history", return_value=0),
            patch.object(ds, "_load_local_state", return_value=([], {}, {})),
        ):
            _run_one_event(ds, ev)

        kinds = [k for k, _ in events]
        assert "anti_fraud_duration" in kinds
        payload = next(p for k, p in events if k == "anti_fraud_duration")
        assert payload["reason"] == "DENY_ANTI_FRAUD_CARD"
        assert payload["device_id"] == DEVICE_ID
        assert payload["remaining_seconds"] > 0

    def test_duration_without_feedback_callback_is_silent(self):
        """No callback = no emit = no error."""
        guard = AntiFraudGuard()
        guard.record(DEVICE_ID, CARD_NO, "card", 30.0)
        ds, _ = _make_ds(guard=guard, feedback_callback=None)
        ev = _make_event()

        with (
            patch("app.core.realtime_agent.access_history_exists", return_value=False),
            patch("app.core.realtime_agent.insert_access_history", return_value=0),
            patch.object(ds, "_load_local_state", return_value=([], {}, {})),
        ):
            _run_one_event(ds, ev)
        # No assertion beyond "didn't crash" — the test passes if _run_one_event returns

    def test_daily_limit_zero_never_queries_count(self):
        """limit=0 short-circuits the check — count_today_for_user_door not called."""
        events = []
        ds, _ = _make_ds(
            settings_override={
                "save_history": True,
                "anti_fraude_daily_pass_limit": 0,
            },
            feedback_callback=lambda kind, payload: events.append((kind, payload)),
        )
        ev = _make_event()

        with (
            patch("app.core.realtime_agent.access_history_exists", return_value=False),
            patch("app.core.realtime_agent.insert_access_history", return_value=1),
            patch("app.core.realtime_agent.count_today_for_user_door") as mock_count,
            patch.object(
                ds, "_verify_totp",
                return_value={
                    "allowed": True, "reason": "GRANT", "scanMode": "RFID",
                    "user": {"userId": 99, "fullName": "Test User"},
                },
            ),
            patch.object(ds, "_load_local_state", return_value=([], {}, {})),
        ):
            _run_one_event(ds, ev)
            mock_count.assert_not_called()
        daily_events = [p for k, p in events if k == "anti_fraud_daily_limit"]
        assert daily_events == []

    def test_daily_limit_below_limit_emits_nothing(self):
        events = []
        ds, _ = _make_ds(
            settings_override={
                "save_history": True,
                "anti_fraude_daily_pass_limit": 5,
            },
            feedback_callback=lambda kind, payload: events.append((kind, payload)),
        )
        ev = _make_event()

        with (
            patch("app.core.realtime_agent.access_history_exists", return_value=False),
            patch("app.core.realtime_agent.insert_access_history", return_value=1),
            patch("app.core.realtime_agent.count_today_for_user_door", return_value=3),
            patch.object(
                ds, "_verify_totp",
                return_value={
                    "allowed": True, "reason": "GRANT", "scanMode": "RFID",
                    "user": {"userId": 99, "fullName": "Test User"},
                },
            ),
            patch.object(ds, "_load_local_state", return_value=([], {}, {})),
        ):
            _run_one_event(ds, ev)

        daily_events = [p for k, p in events if k == "anti_fraud_daily_limit"]
        assert daily_events == []

    def test_daily_limit_at_limit_emits_nothing(self):
        """Count == limit is OK (Nth entry is the last allowed silent one)."""
        events = []
        ds, _ = _make_ds(
            settings_override={
                "save_history": True,
                "anti_fraude_daily_pass_limit": 5,
            },
            feedback_callback=lambda kind, payload: events.append((kind, payload)),
        )
        ev = _make_event()

        with (
            patch("app.core.realtime_agent.access_history_exists", return_value=False),
            patch("app.core.realtime_agent.insert_access_history", return_value=1),
            patch("app.core.realtime_agent.count_today_for_user_door", return_value=5),
            patch.object(
                ds, "_verify_totp",
                return_value={
                    "allowed": True, "reason": "GRANT", "scanMode": "RFID",
                    "user": {"userId": 99, "fullName": "Test User"},
                },
            ),
            patch.object(ds, "_load_local_state", return_value=([], {}, {})),
        ):
            _run_one_event(ds, ev)
        daily_events = [p for k, p in events if k == "anti_fraud_daily_limit"]
        assert daily_events == []

    def test_daily_limit_above_limit_emits_alert(self):
        events = []
        ds, _ = _make_ds(
            settings_override={
                "save_history": True,
                "anti_fraude_daily_pass_limit": 5,
            },
            feedback_callback=lambda kind, payload: events.append((kind, payload)),
        )
        ev = _make_event()

        with (
            patch("app.core.realtime_agent.access_history_exists", return_value=False),
            patch("app.core.realtime_agent.insert_access_history", return_value=1),
            patch("app.core.realtime_agent.count_today_for_user_door", return_value=6),
            patch.object(
                ds, "_verify_totp",
                return_value={
                    "allowed": True, "reason": "GRANT", "scanMode": "RFID",
                    "user": {"userId": 99, "fullName": "Karim Ahmed"},
                },
            ),
            patch.object(ds, "_load_local_state", return_value=([], {}, {})),
        ):
            _run_one_event(ds, ev)

        daily_events = [p for k, p in events if k == "anti_fraud_daily_limit"]
        assert len(daily_events) == 1
        p = daily_events[0]
        assert p["user_id"] == 99
        assert p["full_name"] == "Karim Ahmed"
        assert p["count_today"] == 6
        assert p["limit"] == 5
        assert p["device_id"] == DEVICE_ID

    def test_daily_limit_skipped_when_user_id_not_resolved(self):
        events = []
        ds, _ = _make_ds(
            settings_override={
                "save_history": True,
                "anti_fraude_daily_pass_limit": 5,
            },
            feedback_callback=lambda kind, payload: events.append((kind, payload)),
        )
        ev = _make_event()

        with (
            patch("app.core.realtime_agent.access_history_exists", return_value=False),
            patch("app.core.realtime_agent.insert_access_history", return_value=1),
            patch("app.core.realtime_agent.count_today_for_user_door", return_value=99),
            patch.object(
                ds, "_verify_totp",
                return_value={
                    "allowed": True, "reason": "GRANT", "scanMode": "RFID",
                    # No user dict → user_id unresolved
                },
            ),
            patch.object(ds, "_load_local_state", return_value=([], {}, {})),
        ):
            _run_one_event(ds, ev)

        daily_events = [p for k, p in events if k == "anti_fraud_daily_limit"]
        assert daily_events == []

    def test_daily_limit_skipped_when_history_not_claimed(self):
        events = []
        ds, _ = _make_ds(
            settings_override={
                "save_history": True,
                "anti_fraude_daily_pass_limit": 5,
            },
            feedback_callback=lambda kind, payload: events.append((kind, payload)),
        )
        ev = _make_event()

        with (
            patch("app.core.realtime_agent.access_history_exists", return_value=False),
            patch("app.core.realtime_agent.insert_access_history", return_value=0),  # dedup
            patch("app.core.realtime_agent.count_today_for_user_door", return_value=99),
            patch.object(
                ds, "_verify_totp",
                return_value={
                    "allowed": True, "reason": "GRANT", "scanMode": "RFID",
                    "user": {"userId": 99, "fullName": "X"},
                },
            ),
            patch.object(ds, "_load_local_state", return_value=([], {}, {})),
        ):
            _run_one_event(ds, ev)

        daily_events = [p for k, p in events if k == "anti_fraud_daily_limit"]
        assert daily_events == []

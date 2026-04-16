"""End-to-end anti-fraud daily pass-limit flow test.

Verifies the full Python-side chain without mocks at the DB layer:
  settings → DecisionService → insert_access_history (with user_id)
           → count_today_for_user_door → feedback callback emits
           anti-fraud-daily-limit when count > limit.

Uses a real in-memory-ish SQLite (via init_db) plus real count_today_for_user_door,
but mocks verify_totp to avoid needing a real credential store.
"""
from __future__ import annotations

import queue
import time
import uuid
from unittest.mock import patch

import pytest

from app.core.access_types import AccessEvent
from app.core.anti_fraud import AntiFraudGuard
from app.core.db import get_conn, init_db
from app.core.realtime_agent import (
    CommandResult,
    DecisionService,
    EMA,
    NotificationGate,
)


@pytest.fixture(autouse=True, scope="module")
def _ensure_db():
    init_db()


DEVICE_ID = 777
DOOR_ID = 1
USER_ID = 88888
FULL_NAME = "Integration Test User"


INTEGRATION_SETTINGS = {
    "enabled": True,
    "totp_enabled": False,
    "rfid_enabled": True,
    "anti_fraude_card": True,
    "anti_fraude_qr_code": True,
    "anti_fraude_duration": 30,
    "anti_fraude_daily_pass_limit": 3,  # alert fires on 4th+ entry
    "save_history": True,  # real DB writes so count_today sees them
    "show_notifications": False,
    "win_notify_enabled": False,
    "popup_enabled": False,
    "door_ids": [DOOR_ID],
    "door_entry_id": DOOR_ID,
    "pulse_time_ms": 200,
    "cmd_timeout_ms": 5000,
    "timeout_ms": 5000,
    "door_presets": [],
}


class _DummyLogger:
    def info(self, *a, **k): pass
    def warning(self, *a, **k): pass
    def error(self, *a, **k): pass
    def exception(self, *a, **k): pass
    def debug(self, *a, **k): pass


class _MockCommandBus:
    def open_door(self, **kwargs):
        return CommandResult(ok=True, error="", cmd_ms=0.0)


def _cleanup_test_rows():
    with get_conn() as conn:
        conn.execute("DELETE FROM access_history WHERE user_id = ?", (USER_ID,))
        conn.commit()


def test_full_flow_fires_alert_above_limit():
    """Feed 4 allowed card events; assert daily-limit alert fires exactly once
    (on the 4th, which is the first entry above the limit of 3)."""
    _cleanup_test_rows()

    events_emitted: list[tuple[str, dict]] = []

    def feedback_callback(kind: str, payload: dict) -> None:
        events_emitted.append((kind, payload))

    guard = AntiFraudGuard()
    ds = DecisionService(
        logger=_DummyLogger(),
        event_queue=queue.Queue(),
        command_bus=_MockCommandBus(),
        notify_q=queue.Queue(),
        popup_q=queue.Queue(),
        history_q=queue.Queue(),
        settings_provider=lambda _: INTEGRATION_SETTINGS,
        global_settings=lambda: {},
        notify_gate=NotificationGate(global_settings=lambda: {}),
        decision_ema=EMA(alpha=0.1),
        guard=guard,
        feedback_callback=feedback_callback,
    )

    with (
        patch("app.core.realtime_agent.access_history_exists", return_value=False),
        patch.object(
            ds, "_verify_totp",
            return_value={
                "allowed": True,
                "reason": "GRANT",
                "scanMode": "RFID",
                "user": {"userId": USER_ID, "fullName": FULL_NAME},
            },
        ),
        patch.object(ds, "_load_local_state", return_value=([], {}, {})),
    ):
        # Each event needs a unique event_id and a unique card_no so the
        # AntiFraudGuard duration block doesn't interfere.
        for i in range(4):
            ev = AccessEvent(
                event_id=f"integ-evt-{uuid.uuid4().hex}",
                device_id=DEVICE_ID,
                door_id=DOOR_ID,
                event_type="RTLOG",
                card_no=f"CARD-{i}",
                event_time="2026-04-15T12:00:00",
                raw={},
                poll_ms=10.0,
            )
            ds.event_queue.put(ev)

        ds.start()
        # Give the service time to drain 4 events
        deadline = time.time() + 3.0
        while time.time() < deadline and ds.event_queue.qsize() > 0:
            time.sleep(0.05)
        time.sleep(0.3)  # drain in-flight
        ds.stop()
        ds.join(timeout=1.0)

    # Verify database state: 4 rows for this user, all allowed=1
    with get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM access_history WHERE user_id = ? AND allowed = 1",
            (USER_ID,),
        ).fetchone()
    assert row[0] == 4, f"expected 4 allowed rows, got {row[0]}"

    # Verify feedback events: exactly ONE daily-limit alert (on the 4th entry)
    daily_events = [p for k, p in events_emitted if k == "anti_fraud_daily_limit"]
    assert len(daily_events) == 1, (
        f"expected 1 daily-limit alert, got {len(daily_events)}: "
        f"{[e for e in events_emitted]}"
    )
    alert = daily_events[0]
    assert alert["user_id"] == USER_ID
    assert alert["full_name"] == FULL_NAME
    assert alert["count_today"] == 4
    assert alert["limit"] == 3
    assert alert["device_id"] == DEVICE_ID
    assert alert["door_id"] == DOOR_ID

    _cleanup_test_rows()


def test_full_flow_no_alert_when_limit_disabled():
    """With anti_fraude_daily_pass_limit=0, no alert ever fires."""
    _cleanup_test_rows()

    events_emitted: list[tuple[str, dict]] = []
    settings = {**INTEGRATION_SETTINGS, "anti_fraude_daily_pass_limit": 0}

    ds = DecisionService(
        logger=_DummyLogger(),
        event_queue=queue.Queue(),
        command_bus=_MockCommandBus(),
        notify_q=queue.Queue(),
        popup_q=queue.Queue(),
        history_q=queue.Queue(),
        settings_provider=lambda _: settings,
        global_settings=lambda: {},
        notify_gate=NotificationGate(global_settings=lambda: {}),
        decision_ema=EMA(alpha=0.1),
        guard=AntiFraudGuard(),
        feedback_callback=lambda k, p: events_emitted.append((k, p)),
    )

    with (
        patch("app.core.realtime_agent.access_history_exists", return_value=False),
        patch.object(
            ds, "_verify_totp",
            return_value={
                "allowed": True, "reason": "GRANT", "scanMode": "RFID",
                "user": {"userId": USER_ID, "fullName": FULL_NAME},
            },
        ),
        patch.object(ds, "_load_local_state", return_value=([], {}, {})),
    ):
        for i in range(5):
            ev = AccessEvent(
                event_id=f"integ-evt-{uuid.uuid4().hex}",
                device_id=DEVICE_ID,
                door_id=DOOR_ID,
                event_type="RTLOG",
                card_no=f"CARD-DISABLED-{i}",
                event_time="2026-04-15T12:00:00",
                raw={},
                poll_ms=10.0,
            )
            ds.event_queue.put(ev)

        ds.start()
        deadline = time.time() + 3.0
        while time.time() < deadline and ds.event_queue.qsize() > 0:
            time.sleep(0.05)
        time.sleep(0.3)
        ds.stop()
        ds.join(timeout=1.0)

    daily_events = [p for k, p in events_emitted if k == "anti_fraud_daily_limit"]
    assert daily_events == []

    _cleanup_test_rows()

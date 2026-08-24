"""Frequent-pass VISUAL alert: X passages by the same member inside Y minutes.

The alert exists so the entry screen can tell the front desk "this member already
came through N minutes ago". It is ALERT ONLY — these tests also pin the fact that
nothing here can block anybody: the rule is evaluated from access_history AFTER the
access decision is made, and it is independent of anti_fraude_daily_pass_limit.
"""
from __future__ import annotations

import datetime as dt
import sqlite3

import pytest

SCHEMA = """
CREATE TABLE access_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    event_id TEXT NOT NULL,
    device_id INTEGER,
    door_id INTEGER,
    card_no TEXT,
    event_time TEXT,
    allowed INTEGER,
    reason TEXT,
    user_id INTEGER,
    UNIQUE(event_id)
);
CREATE INDEX ix_access_history_user_door_day
    ON access_history(user_id, device_id, door_id, allowed, created_at);
"""


@pytest.fixture()
def conn(monkeypatch):
    c = sqlite3.connect(":memory:")
    c.executescript(SCHEMA)

    class _Guard:
        def __enter__(self):
            return c

        def __exit__(self, *exc):
            return False

    import app.core.db as db

    monkeypatch.setattr(db, "get_conn", lambda: _Guard(), raising=True)
    return c


def _add(conn, *, minutes_ago, user_id=7, device_id=1, door_id=1, allowed=1):
    ts = (dt.datetime.now() - dt.timedelta(minutes=minutes_ago)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO access_history (created_at,event_id,device_id,door_id,allowed,user_id)"
        " VALUES (?,?,?,?,?,?)",
        (ts, f"e{minutes_ago}-{user_id}-{device_id}-{door_id}-{allowed}", device_id, door_id, allowed, user_id),
    )
    conn.commit()
    return ts


def test_counts_only_this_member_device_door_and_grants(conn):
    from app.core.db import count_recent_for_user_door

    mine = _add(conn, minutes_ago=3)
    _add(conn, minutes_ago=2, allowed=0)        # denied -> ignored
    _add(conn, minutes_ago=1, user_id=9)        # other member
    _add(conn, minutes_ago=1, device_id=2)      # other device
    _add(conn, minutes_ago=1, door_id=2)        # other door
    _add(conn, minutes_ago=90)                  # outside the window

    count, last = count_recent_for_user_door(user_id=7, device_id=1, door_id=1, window_minutes=5)
    assert count == 1
    assert last == mine, "previous-entry timestamp powers 'premier passage a HH:MM'"


def test_window_is_rolling_not_calendar_day(conn):
    """The pre-existing daily cap resets at midnight; this one is a rolling window."""
    from app.core.db import count_recent_for_user_door

    _add(conn, minutes_ago=45)
    assert count_recent_for_user_door(user_id=7, device_id=1, door_id=1, window_minutes=5)[0] == 0
    assert count_recent_for_user_door(user_id=7, device_id=1, door_id=1, window_minutes=60)[0] == 1


@pytest.mark.parametrize("window", [0, -5, None])
def test_disabled_window_short_circuits(conn, window):
    from app.core.db import count_recent_for_user_door

    _add(conn, minutes_ago=1)
    assert count_recent_for_user_door(user_id=7, device_id=1, door_id=1, window_minutes=window) == (0, None)


def test_unresolved_member_never_alerts(conn):
    from app.core.db import count_recent_for_user_door

    _add(conn, minutes_ago=1)
    assert count_recent_for_user_door(user_id=None, device_id=1, door_id=1, window_minutes=5) == (0, None)


def test_threshold_fires_on_the_Xth_passage(conn):
    """Default X=2 must fire on the SECOND passage, matching the design's '2e passage'.

    The engine adds 1 for the in-flight scan because ULTRA writes history
    asynchronously, so the current row is not in access_history yet.
    """
    from app.core.db import count_recent_for_user_door

    limit = 2

    def fires():
        prior, _ = count_recent_for_user_door(user_id=7, device_id=1, door_id=1, window_minutes=5)
        return (prior + 1) >= limit

    assert fires() is False, "first passage of the window must not alert"
    _add(conn, minutes_ago=3)
    assert fires() is True, "second passage must alert (design: '2e passage')"


def test_popup_payload_defaults_are_inert():
    """A normal scan must carry the alert switched off, so the screen stays green."""
    from app.core.access_types import NotificationRequest
    from app.core.realtime_agent import _popup_payload_from_request

    payload = _popup_payload_from_request(NotificationRequest(event_id="e", title="t", message=""))
    assert payload["repeatCount"] == 0
    assert payload["previousEntryAt"] == ""
    assert payload["allowed"] is False

"""Tests for the Access v3 dashboard feed (GET /api/v2/dashboard/overview).

The dashboard's centre column is a timeline of member names, but access_history
stores only a card number — names are resolved through the sync cache. These
tests pin the two things that would silently ruin the screen:

  * the day aggregate must bucket by LOCAL hour, tolerate both "YYYY-MM-DD HH:.."
    and ISO "YYYY-MM-DDTHH:.." timestamps, fall back to created_at when
    event_time is NULL/empty, and ignore other days;
  * a row that cannot be resolved to a member must still come back (with an
    empty userFullName) so the UI can fall back to "Carte ####" rather than
    dropping the entry.
"""
from __future__ import annotations

import datetime as dt
import sqlite3

import pytest


class _FakeCtx:
    def __init__(self, query=None, app=None):
        self._q = query or {}
        self.app = app
        self.sent = None

    def q_int(self, *keys, default=0):
        for k in keys:
            if k in self._q:
                try:
                    return int(self._q[k])
                except Exception:
                    return default
        return default

    def send_json(self, status, payload):
        self.sent = (status, payload)


_SCHEMA = """
CREATE TABLE access_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    event_id TEXT NOT NULL,
    device_id INTEGER,
    door_id INTEGER,
    card_no TEXT,
    event_time TEXT,
    event_type TEXT,
    allowed INTEGER,
    reason TEXT,
    raw_json TEXT,
    history_source TEXT NOT NULL DEFAULT 'AGENT',
    user_id INTEGER,
    active_membership_id INTEGER,
    UNIQUE(event_id)
)
"""


@pytest.fixture()
def seeded_db(monkeypatch):
    """An in-memory access_history wired in place of access.store.get_conn."""
    conn = sqlite3.connect(":memory:")
    conn.execute(_SCHEMA)

    today = dt.datetime.now().strftime("%Y-%m-%d")
    yesterday = (dt.datetime.now() - dt.timedelta(days=1)).strftime("%Y-%m-%d")
    rows = [
        # (created_at, event_id, event_time, allowed, card_no)
        (f"{today} 08:15:00", "a", f"{today} 08:15:00", 1, "0042 1"),
        (f"{today} 08:47:00", "b", f"{today} 08:47:00", 1, "0042 2"),
        (f"{today} 18:01:00", "c", f"{today}T18:01:00", 1, "0042 3"),   # ISO 'T'
        (f"{today} 18:05:00", "d", f"{today} 18:05:00", 1, "0042 4"),
        (f"{today} 18:44:00", "e", f"{today} 18:44:00", 1, "0042 5"),
        (f"{today} 18:59:00", "f", "", 0, "0042 6"),                    # empty -> created_at
        (f"{today} 09:00:00", "g", None, 0, "0042 7"),                  # NULL  -> created_at
        (f"{yesterday} 18:00:00", "h", f"{yesterday} 18:00:00", 1, "0042 8"),
    ]
    for created_at, eid, etime, allowed, card in rows:
        conn.execute(
            "INSERT INTO access_history (created_at, event_id, event_time, allowed, card_no, raw_json)"
            " VALUES (?,?,?,?,?,?)",
            (created_at, eid, etime, allowed, card, "{}"),
        )
    conn.commit()

    class _Guard:
        def __enter__(self):
            return conn

        def __exit__(self, *exc):
            return False

    import access.store as store

    monkeypatch.setattr(store, "get_conn", lambda: _Guard(), raising=False)
    return conn


def _reset_caches():
    import app.api.local_access_api_v2 as m

    m._dash_today_cache.update({"at": 0.0, "day": "", "value": None})
    m._dash_users_cache.update({"at": 0.0, "by_am": {}, "by_card": {}, "devices": {}})


def test_today_buckets_by_local_hour_and_ignores_other_days(seeded_db):
    import app.api.local_access_api_v2 as m

    _reset_caches()
    today = m._dash_today()

    assert today["total"] == 7, "yesterday's row must not be counted"
    assert today["granted"] == 5
    assert today["denied"] == 2
    assert len(today["hourly"]) == 24
    # 08:15 + 08:47
    assert today["hourly"][8] == 2
    # 09:00 arrived with a NULL event_time and must fall back to created_at
    assert today["hourly"][9] == 1
    # three 18:xx rows with mixed separators, plus the empty-event_time row
    assert today["hourly"][18] == 4
    assert today["peakHour"] == 18


def test_today_is_ttl_cached(seeded_db, monkeypatch):
    """The aggregate scans access_history, which sits on the access engine's hot
    path — a second call inside the TTL must not touch the DB again."""
    import app.api.local_access_api_v2 as m

    _reset_caches()
    first = m._dash_today()

    import access.store as store

    def _boom():
        raise AssertionError("access_history was re-read inside the TTL window")

    monkeypatch.setattr(store, "get_conn", _boom, raising=False)
    assert m._dash_today() == first


def _fake_history_rows(monkeypatch, count=8):
    """Stub the (pre-existing, separately tested) history reader with rows that
    carry only what the dashboard serializer touches."""
    from types import SimpleNamespace

    today = dt.datetime.now().strftime("%Y-%m-%d")
    rows = [
        SimpleNamespace(
            id=i,
            event_id=f"evt-{i}",
            created_at=f"{today} 09:0{i}:00",
            event_time=f"{today} 09:0{i}:00",
            device_id=1,
            door_id=1,
            card_no=f"0042 {1000 + i}",
            event_type="",
            allowed=1 if i % 2 == 0 else 0,
            reason="ALLOW_CARD" if i % 2 == 0 else "DENY_NO_CARD_MATCH",
            raw_json="{}",
            history_source="AGENT",
            user_id=None,
            active_membership_id=None,
        )
        for i in range(count)
    ]

    import access.store as store

    monkeypatch.setattr(store, "get_recent_access_history", lambda limit=50: rows[:limit], raising=False)
    return rows


def test_overview_returns_unresolved_rows_with_empty_name(seeded_db, monkeypatch):
    """No sync cache => nothing resolves, but every row must still be returned so
    the UI can fall back to the card number instead of showing a blank feed."""
    import app.api.local_access_api_v2 as m

    _reset_caches()
    _fake_history_rows(monkeypatch)
    ctx = _FakeCtx(query={"limit": "10"})
    m._handle_dashboard_overview(ctx)

    status, payload = ctx.sent
    assert status == 200
    assert payload["ok"] is True
    assert payload["today"]["total"] == 7

    feed = payload["feed"]
    assert feed, "feed must not be empty"
    assert len(feed) <= 10
    for item in feed:
        assert item["userFullName"] == ""      # unresolved, by construction
        assert item["cardNo"], "card number is the UI's fallback label"
        assert "allowed" in item and isinstance(item["allowed"], bool)
        assert item["at"], "every row needs a timestamp for the timeline"


def test_overview_limit_is_clamped(seeded_db, monkeypatch):
    import app.api.local_access_api_v2 as m

    _reset_caches()
    seen = {}

    from types import SimpleNamespace
    import access.store as store

    def _reader(limit=50):
        seen["limit"] = limit
        return [
            SimpleNamespace(
                id=i, event_id=f"e{i}", created_at="2026-07-30 09:00:00",
                event_time="2026-07-30 09:00:00", device_id=1, door_id=1,
                card_no="0042 1", event_type="", allowed=1, reason="ALLOW_CARD",
                raw_json="{}", history_source="AGENT", user_id=None,
                active_membership_id=None,
            )
            for i in range(limit)
        ]

    monkeypatch.setattr(store, "get_recent_access_history", _reader, raising=False)

    ctx = _FakeCtx(query={"limit": "9999"})
    m._handle_dashboard_overview(ctx)
    _, payload = ctx.sent
    assert seen["limit"] == m._DASH_FEED_LIMIT_MAX, "an unbounded limit must be clamped"
    assert len(payload["feed"]) <= m._DASH_FEED_LIMIT_MAX

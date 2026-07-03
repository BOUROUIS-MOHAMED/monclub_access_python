"""Tests for the popup polling fallback (GET /api/v2/popup/poll).

Stateless, sequence-cursor polling so the popup window can catch up even when the
SSE stream silently half-dies. First poll (cursor < 0) must pin the cursor at the
current HEAD with NO backlog (live-only, no "ancient user" re-show); subsequent
polls return only events newer than the given per-engine cursors.
"""
from __future__ import annotations


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


class _FakeApp:
    def __init__(self, agent=None, ultra=None):
        self._agent_engine = agent
        self._ultra_engine = ultra


class _FakeUltra:
    def __init__(self, latest, since_map):
        self.running = True
        self._latest = latest
        self._since_map = since_map  # {since_seq: [(seq, payload), ...]}

    def get_latest_popup_event_seq(self):
        return self._latest

    def get_popup_events_since(self, seq, limit=10):
        return list(self._since_map.get(seq, []))


def _poll(ctx):
    import app.api.local_access_api_v2 as m
    m._handle_popup_poll(ctx)
    return ctx.sent


def test_first_poll_pins_head_no_backlog():
    # cursor -1 (default, not supplied) => return HEAD, no events (live-only).
    ultra = _FakeUltra(latest=5, since_map={})
    ctx = _FakeCtx(query={}, app=_FakeApp(ultra=ultra))
    status, body = _poll(ctx)
    assert status == 200
    assert body["seqUltra"] == 5
    assert body["events"] == []  # NO backlog on first poll


def test_subsequent_poll_returns_new_events_and_advances_cursor():
    ultra = _FakeUltra(
        latest=7,
        since_map={5: [(6, {"eventId": "a"}), (7, {"eventId": "b"})]},
    )
    ctx = _FakeCtx(query={"since_ultra": "5"}, app=_FakeApp(ultra=ultra))
    status, body = _poll(ctx)
    assert status == 200
    assert body["seqUltra"] == 7  # advanced to the last delivered seq
    assert [e["eventId"] for e in body["events"]] == ["a", "b"]


def test_no_new_events_keeps_cursor():
    ultra = _FakeUltra(latest=7, since_map={7: []})
    ctx = _FakeCtx(query={"since_ultra": "7"}, app=_FakeApp(ultra=ultra))
    _, body = _poll(ctx)
    assert body["seqUltra"] == 7 and body["events"] == []


def test_no_engines_returns_empty():
    ctx = _FakeCtx(query={}, app=_FakeApp())  # neither engine present
    status, body = _poll(ctx)
    assert status == 200
    assert body["events"] == [] and body["seqAgent"] == 0 and body["seqUltra"] == 0


def test_engine_not_running_is_skipped():
    ultra = _FakeUltra(latest=9, since_map={})
    ultra.running = False  # engine present but stopped
    ctx = _FakeCtx(query={"since_ultra": "3"}, app=_FakeApp(ultra=ultra))
    _, body = _poll(ctx)
    # not running => no head read, cursor clamped to >=0, no events
    assert body["events"] == [] and body["seqUltra"] == 3

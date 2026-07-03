"""Tests for the popup-window freeze-telemetry endpoint (POST /api/v2/popup/telemetry).

The popup is a separate webview the backend can't introspect; this beacon makes a
popup FREEZE visible in the backend log (a gap in POPUP_HB = webview hang). The
handler must be tolerant (always 200) and emit a POPUP_HB telemetry event.
"""
from __future__ import annotations

from unittest.mock import MagicMock


class _FakeCtx:
    def __init__(self, body):
        self._b = body
        self.sent = None

    def body(self):
        if isinstance(self._b, Exception):
            raise self._b
        return self._b

    def send_json(self, status, payload):
        self.sent = (status, payload)


def test_popup_telemetry_emits_hb_and_returns_200(monkeypatch):
    import app.api.local_access_api_v2 as m
    fake_tel = MagicMock()
    monkeypatch.setattr(m, "_tel", fake_tel)

    ctx = _FakeCtx({
        "kind": "hb", "window": "popup", "lanes": 2, "sse": "open",
        "sseReconnects": 1, "lastSseAgeMs": 1200, "lastShownAgeMs": 3400, "uptimeMs": 99999,
    })
    m._handle_popup_telemetry(ctx)

    assert ctx.sent == (200, {"ok": True})
    fake_tel.event.assert_called_once()
    args, kwargs = fake_tel.event.call_args
    assert args[0] == "POPUP_HB"
    assert kwargs["win"] == "popup"
    assert kwargs["lanes"] == 2
    assert kwargs["sse"] == "open"
    assert kwargs["reconns"] == 1
    assert kwargs["sse_age_ms"] == 1200
    assert kwargs["shown_age_ms"] == 3400
    assert kwargs["uptime_ms"] == 99999


def test_popup_telemetry_defaults_missing_fields(monkeypatch):
    import app.api.local_access_api_v2 as m
    fake_tel = MagicMock()
    monkeypatch.setattr(m, "_tel", fake_tel)

    m._handle_popup_telemetry(_FakeCtx({}))  # empty body
    kwargs = fake_tel.event.call_args.kwargs
    assert kwargs["kind"] == "hb" and kwargs["win"] == "popup"
    assert kwargs["lanes"] == -1 and kwargs["sse_age_ms"] == -1  # sentinels for "unknown"


def test_popup_telemetry_never_raises(monkeypatch):
    import app.api.local_access_api_v2 as m
    monkeypatch.setattr(m, "_tel", MagicMock())
    ctx = _FakeCtx(ValueError("bad body"))  # body() raises
    m._handle_popup_telemetry(ctx)          # must swallow and still 200
    assert ctx.sent == (200, {"ok": True})

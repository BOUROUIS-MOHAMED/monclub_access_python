"""desk_alerts.py (ULTRA merge plan 3, Task 1): the feedback bus moved out of app.py, the repeat-block
sound, the daily pass alert, the frequent-pass count, the Windows toast. No device, no database:
the history counts are injected."""
from __future__ import annotations

import pytest

from app.core import desk_alerts as da


@pytest.fixture
def bus():
    b = da.FeedbackBus()
    previous = da.install_bus(b)
    yield b
    da.install_bus(previous)


def _settings(**kw):
    s = {"save_history": True, "anti_fraude_daily_pass_limit": 0, "win_notify_enabled": False,
         "frequent_pass_limit": 0, "frequent_pass_window_minutes": 0}
    s.update(kw)
    return s


# ------------------------------------------------------------------ the bus
def test_the_bus_numbers_events_and_returns_those_after_a_seq():
    b = da.FeedbackBus()
    first = b.publish("sync_completed_success", {"syncRunId": 4})
    b.publish("device_push_success", {"deviceId": 9})
    assert first["seq"] == 1 and first["type"] == "sync_completed_success" and first["syncRunId"] == 4
    assert first["at"].endswith("Z")
    assert [e["seq"] for e in b.since(0)] == [1, 2]
    assert [e["type"] for e in b.since(1)] == ["device_push_success"]


def test_the_bus_keeps_the_last_200_and_caps_a_read_at_100():
    b = da.FeedbackBus()
    for i in range(250):
        b.publish("x", {"i": i})
    assert len(b.since(0, limit=1000)) == 100
    assert b.since(0, limit=1)[0]["seq"] == 51          # 250 - 200 + 1


def test_emit_without_a_bus_does_nothing():
    previous = da.install_bus(None)
    try:
        assert da.emit("anti_fraud_duration", {}) is False
    finally:
        da.install_bus(previous)


# ------------------------------------------------------------------ the repeat-block sound
def test_a_repeat_block_refusal_rings_once(bus):
    assert da.refusal_sound(_settings(), allowed=False, reason="DENY_REPEAT_BLOCK", device_id=5,
                            device_name="Entree", door_id=1, user_id=7, user_full_name="Anna")
    [event] = bus.since(0)
    assert event["type"] == da.EVENT_REPEAT
    assert event["reason"] == "DENY_REPEAT_BLOCK" and event["device_id"] == 5 and event["user_id"] == 7


@pytest.mark.parametrize("allowed,reason", [
    (True, "ALLOW_PC_CARD"), (False, "DEVICE_DENIED"), (False, "DENY_PLAN_NOT_ALLOWED"),
    (False, "DENY_EXPIRED"), (False, "DOOR_CMD_FAILED"),
])
def test_no_other_scan_rings(bus, allowed, reason):
    assert not da.refusal_sound(_settings(), allowed=allowed, reason=reason, device_id=5,
                                device_name="E", door_id=1, user_id=7, user_full_name="")
    assert bus.since(0) == []


# ------------------------------------------------------------------ the daily pass alert
def _daily(bus, settings, prior, **kw):
    args = dict(allowed=True, device_id=5, device_name="Entree", door_id=1, user_id=7,
                user_full_name="Anna", count_today=lambda **_k: prior)
    args.update(kw)
    return da.daily_alert(settings, **args)


def test_the_daily_alert_fires_above_the_limit_counting_the_scan_in_flight(bus):
    s = _settings(anti_fraude_daily_pass_limit=3)
    assert _daily(bus, s, prior=2) is None             # 3rd entry: not above 3
    payload = _daily(bus, s, prior=3)                   # 4th entry
    assert payload == {"user_id": 7, "full_name": "Anna", "count_today": 4, "limit": 3,
                       "device_id": 5, "device_name": "Entree", "door_id": 1}
    [event] = bus.since(0)
    assert event["type"] == da.EVENT_DAILY and event["count_today"] == 4


def test_the_daily_alert_is_off_by_default_and_reads_nothing(bus):
    calls = []
    assert _daily(bus, _settings(), prior=99, count_today=lambda **k: calls.append(k) or 99) is None
    assert calls == [] and bus.since(0) == []


@pytest.mark.parametrize("kw", [{"allowed": False}, {"user_id": None}, {"door_id": None}])
def test_the_daily_alert_needs_an_allowed_known_member_and_a_door(bus, kw):
    assert _daily(bus, _settings(anti_fraude_daily_pass_limit=1), prior=5, **kw) is None


def test_no_daily_alert_when_the_device_keeps_no_history(bus):
    assert _daily(bus, _settings(anti_fraude_daily_pass_limit=1, save_history=False), prior=5) is None


def test_a_failed_daily_count_is_no_alert(bus):
    def boom(**_k):
        raise RuntimeError("db locked")
    assert _daily(bus, _settings(anti_fraude_daily_pass_limit=1), prior=0, count_today=boom) is None


# ------------------------------------------------------------------ the frequent-pass count (moved)
def test_the_frequent_pass_badge_counts_the_scan_in_flight():
    s = _settings(frequent_pass_limit=2, frequent_pass_window_minutes=5)
    seen = []

    def recent(**kw):
        seen.append(kw)
        return (1, "2026-10-02 10:00:00")

    rep = da.frequent_pass(s, allowed=True, user_id=7, device_id=5, door_id=1, count_recent=recent)
    assert rep == {"repeat_count": 2, "repeat_limit": 2, "repeat_window_min": 5,
                   "previous_entry_at": "2026-10-02 10:00:00"}
    assert seen == [{"user_id": 7, "device_id": 5, "door_id": 1, "window_minutes": 5}]


def test_the_frequent_pass_badge_is_inert_below_the_limit_or_when_off():
    inert = {"repeat_count": 0, "repeat_limit": 0, "repeat_window_min": 0, "previous_entry_at": ""}
    s = _settings(frequent_pass_limit=3, frequent_pass_window_minutes=5)
    assert da.frequent_pass(s, allowed=True, user_id=7, device_id=5, door_id=1,
                            count_recent=lambda **k: (1, "x")) == inert
    assert da.frequent_pass(_settings(), allowed=True, user_id=7, device_id=5, door_id=1,
                            count_recent=lambda **k: (9, "x")) == inert
    assert da.frequent_pass(s, allowed=False, user_id=7, device_id=5, door_id=1,
                            count_recent=lambda **k: (9, "x")) == inert


# ------------------------------------------------------------------ the Windows toast
def test_a_toast_is_queued_only_when_the_device_switch_is_on():
    shown = []
    svc = da.ToastService(show=lambda t, m, i: shown.append((t, m, i)), global_settings=lambda: {},
                          autostart=False)
    common = dict(reason="DEVICE_DENIED", device_name="Entree", door_id=2, user_full_name="Anna",
                  user_image="")
    assert not da.entry_toast(_settings(), allowed=False, service=svc, **common)
    svc_kw = dict(service=svc)
    assert da.entry_toast(_settings(win_notify_enabled=True), allowed=False, **common, **svc_kw)
    assert svc.drain_once() == 1
    assert shown == [("Access DENY", "Anna | Entree | door=2 | reason=DEVICE_DENIED", "")]


def test_the_global_switch_silences_every_toast():
    shown = []
    svc = da.ToastService(show=lambda *a: shown.append(a),
                          global_settings=lambda: {"notification_service_enabled": False},
                          autostart=False)
    assert svc.submit("Access OK", "Anna", "")
    assert svc.drain_once() == 0 and shown == []


def test_a_full_toast_queue_drops_instead_of_waiting():
    svc = da.ToastService(show=lambda *a: None, global_settings=lambda: {}, autostart=False)
    for _ in range(da.ToastService.QUEUE_MAX):
        assert svc.submit("t", "m")
    assert svc.submit("t", "m") is False


def test_a_failing_toast_is_swallowed():
    def boom(*_a):
        raise OSError("powershell missing")
    svc = da.ToastService(show=boom, global_settings=lambda: {}, autostart=False)
    svc.submit("t", "m")
    assert svc.drain_once() == 0


# ------------------------------------------------------------------ after_scan: one call, every alert
def test_after_scan_rings_and_toasts_a_repeat_block_once(bus, monkeypatch):
    svc = da.ToastService(show=lambda *a: None, global_settings=lambda: {}, autostart=False)
    monkeypatch.setattr(da, "_toasts", svc)
    da.after_scan(_settings(win_notify_enabled=True), device_id=5, device_name="E", allowed=False,
                  reason="DENY_REPEAT_BLOCK", user_id=7, user_full_name="Anna", user_image="",
                  door_id=1)
    assert [e["type"] for e in bus.since(0)] == [da.EVENT_REPEAT]
    assert svc.drain_once() == 1



# ------------------------------------------------------------------ Task 2: MainApp delegates
def test_main_app_publishes_and_reads_through_its_bus():
    from app.ui.app import MainApp

    app = MainApp.__new__(MainApp)            # no __init__: only the bus is needed
    app._feedback_bus = da.FeedbackBus()
    event = app.publish_feedback_event("sync_completed_success", {"syncRunId": 3})
    assert event["seq"] == 1 and event["syncRunId"] == 3
    assert app.get_feedback_events_since(0) == [event]
    assert app.get_feedback_events_since(1) == []


def test_main_app_installs_its_bus_for_the_ultra_workers():
    from pathlib import Path

    source = Path("app/ui/app.py").read_text(encoding="utf-8")
    assert "self._feedback_bus = _desk_alerts.FeedbackBus()" in source
    assert "_desk_alerts.install_bus(self._feedback_bus)" in source
    assert "_feedback_events_cond" not in source

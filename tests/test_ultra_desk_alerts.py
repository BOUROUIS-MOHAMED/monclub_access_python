"""The desk alerts on a real ULTRA worker (ULTRA merge plan 3, Task 3): one funnel
(UltraDeviceWorker._enqueue_notification) calls desk_alerts.after_scan once per decided scan,
before the popup switch; the history rows of a member the PC knows carry that member."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import app.core.db as dbmod
from app.core import card_decision as cd
from app.core import desk_alerts as da
from tests.test_ultra_pc_entry import ANNA_CARD, _evt, _staff_ids, _worker


@pytest.fixture
def bus():
    b = da.FeedbackBus()
    previous = da.install_bus(b)
    yield b
    da.install_bus(previous)


@pytest.fixture
def toasts(monkeypatch):
    svc = da.ToastService(show=lambda *a: None, global_settings=lambda: {}, autostart=False)
    monkeypatch.setattr(da, "_toasts", svc)
    return svc


def _types(bus):
    return [e["type"] for e in bus.since(0, limit=100)]


def test_a_repeat_block_refusal_rings_exactly_once(bus):
    w = _worker(card_decision="PC", member_block_seconds=30)
    del w._enqueue_notification                 # the real funnel
    w._burst_debounce_sec = lambda: 0.0
    with _staff_ids(), patch("app.core.ultra_engine.get_membership_brief_index_cached",
                             return_value={}):
        w._process_event(_evt(ANNA_CARD, "c1"))
        w._process_event(_evt(ANNA_CARD, "c2"))
    assert _types(bus) == [da.EVENT_REPEAT]
    reasons = [w._popup_q.get_nowait().reason for _ in range(w._popup_q.qsize())]
    assert reasons == [cd.ALLOW_PC_CARD, cd.DENY_REPEAT_BLOCK]


def test_a_device_with_the_popup_off_still_toasts_and_alerts(bus, toasts, monkeypatch):
    monkeypatch.setattr(dbmod, "count_today_for_user_door", lambda **k: 1)
    w = _worker(popup_enabled=False, win_notify_enabled=True, anti_fraude_daily_pass_limit=1,
                save_history=True)
    del w._enqueue_notification
    w._process_event(_evt(ANNA_CARD, "c3", etype=0))
    assert w._popup_q.qsize() == 0
    [event] = bus.since(0)
    assert event["type"] == da.EVENT_DAILY and event["user_id"] == 51 and event["count_today"] == 2
    assert toasts.drain_once() == 1


def test_the_frequent_pass_badge_still_reaches_the_popup(monkeypatch):
    monkeypatch.setattr(dbmod, "count_recent_for_user_door", lambda **k: (1, "2026-10-02 09:58:00"))
    w = _worker(frequent_pass_limit=2, frequent_pass_window_minutes=5)
    del w._enqueue_notification
    with patch("app.core.ultra_engine.get_membership_brief_index_cached", return_value={}):
        w._process_event(_evt(ANNA_CARD, "c4", etype=0))
    req = w._popup_q.get_nowait()
    assert (req.repeat_count, req.repeat_limit, req.repeat_window_min, req.previous_entry_at) == \
        (2, 2, 5, "2026-10-02 09:58:00")


def test_a_card_the_turnstile_allowed_writes_its_member_into_the_history():
    w = _worker()
    del w._enqueue_history
    with patch("app.core.ultra_engine.insert_access_history", return_value=1) as insert:
        w._process_event(_evt(ANNA_CARD, "c5", etype=0))
    assert insert.call_args.kwargs["user_id"] == 51


def test_a_card_the_pc_opened_writes_its_member_into_the_history():
    w = _worker(card_decision="PC")
    with _staff_ids():
        w._process_event(_evt(ANNA_CARD, "c6"))
    assert w._enqueue_history.call_args.kwargs["user_id"] == 51


def test_an_unknown_card_writes_no_member():
    w = _worker()
    del w._enqueue_history
    w._handle_rfid_rescue = MagicMock()
    with patch("app.core.ultra_engine.insert_access_history", return_value=1) as insert:
        w._process_event(_evt("55555555", "c7", etype=0))
    assert insert.call_args.kwargs["user_id"] is None

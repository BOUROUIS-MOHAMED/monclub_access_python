"""Member fees F3c: the cached fee lines reach the entry-screen event (guide §3.12).

Path: sync_users.fees_json -> _coerce_user_row_to_payload ``fees`` -> the engine's resolved
member -> UltraDeviceWorker._enqueue_notification(user_fees=) / the AGENT request ->
NotificationRequest.fees -> realtime_agent._popup_payload_from_request ``fees`` +
``feeDueSoonDays`` -> tauri-ui PopupWindow. Display only: nothing here changes a decision.
"""
from __future__ import annotations

import inspect
from unittest.mock import patch

from app.core import realtime_agent
from app.core.access_types import NotificationRequest
from tests.test_ultra_pc_entry import ANNA, ANNA_CARD, _evt, _staff_ids, _worker

FEES = [{"name": "Casier", "dueDate": "2026-10-12", "required": False, "paid": True}]
ANNA_WITH_FEES = dict(ANNA, fees=FEES)


def _worker_knowing_anna_with_fees(**settings):
    w = _worker(**settings)
    w._cached_state = ([], {501: ANNA_WITH_FEES}, {ANNA_CARD: [ANNA_WITH_FEES]})
    return w


# ── the payload ────────────────────────────────────────────────────────────────────────────

def test_a_request_without_fees_publishes_none_and_reads_no_setting():
    req = NotificationRequest(event_id="e", title="t", message="")
    assert req.fees == []
    with patch.object(realtime_agent, "_get_backend_global_settings") as read:
        payload = realtime_agent._popup_payload_from_request(req)
    read.assert_not_called()
    assert payload["fees"] == [] and payload["feeDueSoonDays"] == 7


def test_a_request_with_fees_publishes_them_with_the_gym_window():
    req = NotificationRequest(event_id="e", title="t", message="", fees=list(FEES))
    with patch.object(realtime_agent, "_get_backend_global_settings",
                      return_value={"fee_due_soon_days": 14}):
        payload = realtime_agent._popup_payload_from_request(req)
    assert payload["fees"] == FEES
    assert payload["feeDueSoonDays"] == 14


def test_an_unreadable_setting_falls_back_to_seven():
    req = NotificationRequest(event_id="e", title="t", message="", fees=list(FEES))
    with patch.object(realtime_agent, "_get_backend_global_settings", side_effect=RuntimeError("db")):
        assert realtime_agent._popup_payload_from_request(req)["feeDueSoonDays"] == 7


# ── ULTRA ──────────────────────────────────────────────────────────────────────────────────

def test_a_turnstile_decided_entry_forwards_the_fees():
    w = _worker_knowing_anna_with_fees()
    w._process_event(_evt(ANNA_CARD, "f1", etype=0))
    kw = w._enqueue_notification.call_args.kwargs
    assert (kw["allowed"], kw["reason"]) == (True, "DEVICE_ALLOWED")
    assert kw["user_fees"] == FEES


def test_a_pc_decided_card_forwards_the_fees():
    w = _worker_knowing_anna_with_fees(card_decision="PC")
    with _staff_ids():
        w._process_event(_evt(ANNA_CARD, "f2"))
    kw = w._enqueue_notification.call_args.kwargs
    assert kw["allowed"] is True and kw["user_fees"] == FEES


def test_the_real_funnel_puts_the_fees_on_the_popup_request():
    w = _worker_knowing_anna_with_fees()
    del w._enqueue_notification                 # the real UltraDeviceWorker._enqueue_notification
    with patch("app.core.ultra_engine.get_membership_brief_index_cached", return_value={}):
        w._process_event(_evt(ANNA_CARD, "f3", etype=0))
    req = w._popup_q.get_nowait()
    assert req.allowed is True and req.fees == FEES


def test_a_member_without_fees_and_an_unknown_card_carry_none():
    from app.core.ultra_pc_entry import member_popup_fields

    assert member_popup_fields(ANNA)["user_fees"] == []
    assert member_popup_fields(None)["user_fees"] == []
    assert member_popup_fields(ANNA_WITH_FEES)["user_fees"] == FEES


def test_both_resolved_member_call_sites_in_ultra_engine_pass_the_fees():
    """_handle_allow and the QR rescue (_handle_totp_rescue). A parameter nothing passes is the
    birthday bug of TestUltraPopulatesBirthday again (test_device_sync_protocol_guard.py)."""
    from app.core import ultra_engine

    src = inspect.getsource(ultra_engine)
    assert src.count('user_fees=(user.get("fees") if isinstance(user, dict) else None),') == 2


# ── AGENT ──────────────────────────────────────────────────────────────────────────────────

def test_the_agent_engine_passes_the_fees():
    src = inspect.getsource(realtime_agent)
    assert 'fees=list(user.get("fees") or []) if isinstance(user, dict) else [],' in src

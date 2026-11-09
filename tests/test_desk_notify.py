from __future__ import annotations

import importlib
import json

import pytest


@pytest.fixture
def desk(tmp_path, monkeypatch):
    from app.core import db
    monkeypatch.setattr(db, "_DB_PATH", str(tmp_path / "desk.db"))
    db.init_db()
    from app.core import desk_notify
    module = importlib.reload(desk_notify)
    yield module
    importlib.reload(module)
    db._shutdown_db_writer_for_tests()


def test_defaults_and_unknown_fields(desk):
    assert desk.settings() == desk.DEFAULTS
    assert desk.normalize({"enabled": "true", "mode": "bad", "position": "bad", "screen": -1,
                           "durationSec": 3, "maxVisible": 4, "sound": 1, "testNonce": -1}) == desk.DEFAULTS
    assert desk.normalize(None) == desk.DEFAULTS


@pytest.mark.parametrize("key,values", [
    ("mode", ["ALL", "REFUSALS_AND_ALERTS", "REFUSALS_ONLY"]),
    ("position", ["TOP_LEFT", "TOP_CENTER", "TOP_RIGHT", "BOTTOM_LEFT", "BOTTOM_CENTER", "BOTTOM_RIGHT"]),
    ("durationSec", [0, 5, 8, 15]), ("maxVisible", [1, 2, 3, 5]), ("screen", [0, 1, 2]),
])
def test_contract_sets(desk, key, values):
    for value in values:
        assert desk.normalize({key: value})[key] == value


def test_heartbeat_persists_and_old_backend_keeps_value(desk):
    desk.on_heartbeat_response({"deskNotify": {"enabled": True, "mode": "ALL", "durationSec": 0}})
    from app.core import db
    with db.get_conn() as conn:
        stored = json.loads(conn.execute("SELECT value_json FROM v2_kv WHERE key=?", ("desk_notify_settings",)).fetchone()[0])
    assert stored == desk.settings()
    assert stored["enabled"] and stored["durationSec"] == 0
    desk = importlib.reload(desk)
    desk.on_heartbeat_response({"refusedInfoEnabled": False})
    assert desk.settings() == stored


def test_nonce_growth_queues_one_desk_only_test_and_survives_restart(desk):
    desk.on_heartbeat_response({"deskNotify": {"enabled": True, "testNonce": 123}})
    [(seq, event)] = desk.events_since(0)
    assert event["deskTest"] and event["deskOnly"] and event["allowed"]
    assert event["userFullName"] == "Test MonClub"
    desk.on_heartbeat_response({"deskNotify": {"enabled": True, "testNonce": 123}})
    desk.on_heartbeat_response({"deskNotify": {"enabled": True, "testNonce": 122}})
    assert desk.events_since(seq) == []
    desk = importlib.reload(desk)
    desk.on_heartbeat_response({"deskNotify": {"enabled": True, "testNonce": 122}})
    assert desk.events_since(0) == []


def test_local_test_requires_enabled_settings(desk):
    assert desk.queue_test() is False
    desk.on_heartbeat_response({"deskNotify": {"enabled": True}})
    assert desk.queue_test() is True
    assert len(desk.events_since(0)) == 1


def test_ultra_hidden_refusal_is_delivered_when_tv_popup_is_off(desk, monkeypatch):
    from tests.test_ultra_pc_entry import _worker
    from app.core import desk_alerts
    from app.core.realtime_agent import _popup_payload_from_request
    monkeypatch.setattr(desk_alerts, "after_scan", lambda *a, **k: None)
    monkeypatch.setattr(desk_alerts, "frequent_pass", lambda *a, **k: {})
    desk.on_heartbeat_response({"deskNotify": {"enabled": True}})
    worker = _worker(popup_enabled=False)
    del worker._enqueue_notification
    worker._enqueue_notification(event_id="hidden", allowed=False, reason="MEMBERSHIP_EXPIRED", scan_mode="RFID_CARD",
                                 user_full_name="Private Name", user_image="", user_membership_id=42,
                                 user_phone="", user_valid_from="", user_valid_to="")
    payload = _popup_payload_from_request(worker._popup_q.get_nowait())
    assert payload["deskOnly"] is True
    assert payload["refusedDisplay"] is False
    assert payload["popupEnabled"] is False
    assert payload["userMembershipId"] == 42


def test_local_handlers(desk):
    from types import SimpleNamespace
    from app.api import local_access_api_v2 as api
    from access.local_api_routes import ACCESS_LOCAL_ROUTE_SPECS
    assert ("GET", "/api/v2/desk-notify/settings", "_handle_desk_notify_settings") in ACCESS_LOCAL_ROUTE_SPECS
    replies = []
    ctx = SimpleNamespace(send_json=lambda *args: replies.append(args))
    api._handle_desk_notify_settings(ctx)
    assert replies.pop() == (200, desk.DEFAULTS)
    api._handle_desk_notify_test(ctx)
    assert replies.pop()[0] == 409
    desk.on_heartbeat_response({"deskNotify": {"enabled": True}})
    api._handle_desk_notify_test(ctx)
    assert replies.pop() == (200, {"ok": True})


def test_sse_delivers_a_desk_test_without_any_device_engine(desk, monkeypatch):
    from types import SimpleNamespace
    from app.api import local_access_api_v2 as api
    desk.on_heartbeat_response({"deskNotify": {"enabled": True}})
    assert desk.queue_test()
    messages = []
    def send(event, payload):
        messages.append((event, payload))
        return event != "popup"  # Disconnect immediately after receiving the test.
    ctx = SimpleNamespace(app=SimpleNamespace(), handler=SimpleNamespace(client_address=("127.0.0.1", 1)),
                          q=lambda *a, **k: k.get("default", ""), q_int=lambda *a, **k: k.get("default", 0),
                          send_sse_start=lambda: None, send_sse_event=send)
    monkeypatch.setattr(api.time, "sleep", lambda *a: None)
    api._handle_agent_events_sse(ctx)
    tests = [payload for event, payload in messages if event == "popup"]
    assert len(tests) == 1
    assert tests[0]["deskTest"] and tests[0]["deskOnly"]


def test_corrupt_stored_settings_fall_back_to_defaults(desk):
    from app.core.v2.store import kv_put
    kv_put("desk_notify_settings", "not a settings object")
    assert importlib.reload(desk).settings() == desk.DEFAULTS

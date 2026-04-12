from __future__ import annotations

import base64
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

from access.config import serialize_access_config
from access.local_api_routes import ACCESS_LOCAL_ROUTE_SPECS
from app.api import local_access_api_v2
from app.core.config import AppConfig


class _FeedbackCtx:
    def __init__(self, app, body: dict | None = None) -> None:
        self.app = app
        self._body = body or {}
        self.responses: list[tuple[int, object]] = []
        self.binary: tuple[int, bytes, str] | None = None
        self.events: list[tuple[str, object]] = []
        self._feedback_sent = 0

    def body(self) -> dict:
        return dict(self._body)

    def send_json(self, status: int, payload: object) -> None:
        self.responses.append((status, payload))

    def send_bytes(self, status: int, payload: bytes, content_type: str) -> None:
        self.binary = (status, payload, content_type)

    def send_sse_start(self) -> None:
        return None

    def send_sse_event(self, event: str, data: object) -> bool:
        self.events.append((event, data))
        if event in {"device_push_success", "sync_completed_success"}:
            self._feedback_sent += 1
            return self._feedback_sent < 2
        return True


class _FeedbackApp:
    def __init__(self) -> None:
        self.cfg = AppConfig()
        self.logger = MagicMock()
        self.persist_config = MagicMock()
        self._events: list[dict] = []
        self._events_lock = threading.Lock()
        self._events_cond = threading.Condition(self._events_lock)
        self._event_seq = 0

    def publish_feedback_event(self, event_type: str, payload: dict) -> dict:
        with self._events_cond:
            self._event_seq += 1
            event = {
                "seq": self._event_seq,
                "type": event_type,
                **payload,
            }
            self._events.append(event)
            self._events_cond.notify_all()
            return event

    def get_feedback_events_since(self, seq: int, *, limit: int = 20) -> list[dict]:
        with self._events_lock:
            return [dict(event) for event in self._events if int(event.get("seq") or 0) > seq][:limit]


def test_feedback_config_serialization_includes_defaults() -> None:
    serialized = serialize_access_config(AppConfig.from_dict({}))

    assert serialized["push_success_sound_enabled"] is True
    assert serialized["sync_success_sound_enabled"] is True
    assert serialized["push_success_animation_enabled"] is True
    assert serialized["sync_success_animation_enabled"] is True
    assert serialized["push_success_repeat_mode"] == "per_device"
    assert serialized["push_success_sound_source"] == "default"
    assert serialized["sync_success_sound_source"] == "default"
    assert serialized["push_success_custom_sound_path"] == ""
    assert serialized["sync_success_custom_sound_path"] == ""


def test_feedback_config_normalizes_invalid_values() -> None:
    cfg = AppConfig.from_dict(
        {
            "push_success_repeat_mode": "sometimes",
            "push_success_sound_source": "weird",
            "sync_success_sound_source": "other",
            "push_success_custom_sound_path": None,
            "sync_success_custom_sound_path": None,
        }
    )

    assert cfg.push_success_repeat_mode == "per_device"
    assert cfg.push_success_sound_source == "default"
    assert cfg.sync_success_sound_source == "default"
    assert cfg.push_success_custom_sound_path == ""
    assert cfg.sync_success_custom_sound_path == ""


def test_access_routes_expose_feedback_endpoints() -> None:
    expected = {
        ("GET", "/api/v2/feedback/events", "_handle_feedback_events_sse"),
        ("GET", "/api/v2/feedback/sounds/device-push", "_handle_feedback_sound_device_push_get"),
        ("POST", "/api/v2/feedback/sounds/device-push", "_handle_feedback_sound_device_push_post"),
        ("DELETE", "/api/v2/feedback/sounds/device-push", "_handle_feedback_sound_device_push_delete"),
        ("GET", "/api/v2/feedback/sounds/sync-complete", "_handle_feedback_sound_sync_complete_get"),
        ("POST", "/api/v2/feedback/sounds/sync-complete", "_handle_feedback_sound_sync_complete_post"),
        ("DELETE", "/api/v2/feedback/sounds/sync-complete", "_handle_feedback_sound_sync_complete_delete"),
    }

    assert expected.issubset(set(ACCESS_LOCAL_ROUTE_SPECS))


def test_feedback_events_sse_emits_queued_events() -> None:
    app = _FeedbackApp()
    ctx = _FeedbackCtx(app)

    worker = threading.Thread(target=local_access_api_v2._handle_feedback_events_sse, args=(ctx,), daemon=True)
    worker.start()

    deadline = time.time() + 1.0
    while not ctx.events and time.time() < deadline:
        time.sleep(0.01)

    app.publish_feedback_event(
        "device_push_success",
        {"syncRunId": 9, "batchId": 4, "deviceId": 3, "deviceName": "Front Door"},
    )

    deadline = time.time() + 2.0
    while ctx._feedback_sent < 1 and time.time() < deadline:
        time.sleep(0.01)

    worker.join(timeout=0.5)

    feedback_events = [data for event, data in ctx.events if event == "device_push_success"]
    assert len(feedback_events) == 1
    assert feedback_events[0]["syncRunId"] == 9
    assert feedback_events[0]["deviceId"] == 3
    assert feedback_events[0]["deviceName"] == "Front Door"


def test_feedback_sound_upload_get_and_reset_round_trip(tmp_path, monkeypatch) -> None:
    app = _FeedbackApp()
    layout = SimpleNamespace(access_data_dir=tmp_path)
    monkeypatch.setattr(local_access_api_v2, "get_desktop_path_layout", lambda: layout)

    sound_bytes = b"ID3-test-audio"
    upload_ctx = _FeedbackCtx(
        app,
        body={
            "fileName": "celebration.mp3",
            "contentBase64": base64.b64encode(sound_bytes).decode("ascii"),
        },
    )

    local_access_api_v2._handle_feedback_sound_device_push_post(upload_ctx)

    assert upload_ctx.responses[0][0] == 200
    assert app.cfg.push_success_sound_source == "custom"
    assert app.cfg.push_success_custom_sound_path

    stored_path = tmp_path / "feedback"
    assert stored_path.exists()
    assert stored_path.joinpath("device-push-success.mp3").read_bytes() == sound_bytes

    get_ctx = _FeedbackCtx(app)
    local_access_api_v2._handle_feedback_sound_device_push_get(get_ctx)

    assert get_ctx.binary is not None
    assert get_ctx.binary[0] == 200
    assert get_ctx.binary[1] == sound_bytes
    assert get_ctx.binary[2] == "audio/mpeg"

    delete_ctx = _FeedbackCtx(app)
    local_access_api_v2._handle_feedback_sound_device_push_delete(delete_ctx)

    assert delete_ctx.responses[0][0] == 200
    assert app.cfg.push_success_sound_source == "default"
    assert app.cfg.push_success_custom_sound_path == ""
    assert not stored_path.joinpath("device-push-success.mp3").exists()


def test_main_app_helper_only_emits_sync_complete_feedback_for_success() -> None:
    from app.ui.app import MainApp

    events: list[tuple[str, dict]] = []
    app = SimpleNamespace(
        publish_feedback_event=lambda event_type, payload: events.append((event_type, payload)),
    )
    trigger_context = SimpleNamespace(run_type="TRIGGERED", trigger_source="SYNC_NOW_API")

    MainApp._maybe_emit_sync_success_feedback(
        app,
        sync_run_id=12,
        final_status="SUCCESS",
        trigger_context=trigger_context,
    )
    MainApp._maybe_emit_sync_success_feedback(
        app,
        sync_run_id=13,
        final_status="PARTIAL",
        trigger_context=trigger_context,
    )

    assert events == [
        (
            "sync_completed_success",
            {
                "syncRunId": 12,
                "runType": "TRIGGERED",
                "triggerSource": "SYNC_NOW_API",
            },
        )
    ]

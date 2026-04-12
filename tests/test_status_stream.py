from __future__ import annotations

import threading
import time
from contextlib import ExitStack, contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from access.local_api_routes import ACCESS_LOCAL_ROUTE_SPECS
from app.api import local_access_api_v2
from app.core.device_sync import DeviceSyncEngine


class _StatusStreamApp:
    def __init__(self, engine: DeviceSyncEngine) -> None:
        self._device_sync_engine = engine
        self._sync_work_running = False
        self._last_sync_at = None
        self._last_sync_ok = True
        self._last_sync_error = None
        self._last_device_sync_at = None
        self._last_device_sync_ok = True
        self._last_device_sync_error = None
        self._agent_engine = None
        self._ultra_engine = None

    def _restriction_reasons(self) -> list[str]:
        return []

    def _compute_expiry_warnings(self) -> dict[str, object]:
        return {}

    def get_access_mode_summary(self) -> dict[str, int]:
        return {"DEVICE": 1, "AGENT": 0, "ULTRA": 0, "UNKNOWN": 0}


class _UltraProgressEngine:
    def __init__(self, progress: dict[str, object]) -> None:
        self._progress = progress
        self.running = True

    def get_sync_progress_snapshot(self) -> tuple[dict[str, object], int]:
        return self._progress, 1

    def get_status(self) -> dict[str, object]:
        return {"running": True, "devices": {}}


class _FakeStatusStreamCtx:
    def __init__(self, app: _StatusStreamApp) -> None:
        self.app = app
        self.events: list[tuple[str, object]] = []
        self._status_sent = 0

    def send_sse_start(self) -> None:
        return None

    def send_sse_event(self, event: str, data: object) -> bool:
        self.events.append((event, data))
        if event == "status":
            self._status_sent += 1
            return self._status_sent < 2
        return True


def _make_cache() -> SimpleNamespace:
    return SimpleNamespace(
        updated_at="2026-04-06T12:00:00Z",
        contract_status=True,
        contract_end_date="2026-06-30",
        devices=[{"id": 7, "name": "Front Door", "accessDataMode": "DEVICE"}],
    )


def _make_auth() -> SimpleNamespace:
    return SimpleNamespace(
        token="local-api-token",
        email="person@example.com",
        last_login_at="2026-04-06T11:30:00Z",
    )


@contextmanager
def _patched_status_dependencies():
    cache = _make_cache()
    with ExitStack() as stack:
        stack.enter_context(
            patch.multiple(
                local_access_api_v2,
                _build_update_status_payload=MagicMock(return_value={
                    "updateAvailable": False,
                    "downloaded": False,
                    "downloading": False,
                    "progress": None,
                    "progressPercent": None,
                    "currentReleaseId": None,
                    "lastCheckAt": None,
                    "lastError": None,
                }),
            )
        )
        stack.enter_context(
            patch(
                "app.core.db.load_sync_contract_meta",
                return_value={
                    "contractStatus": cache.contract_status,
                    "contractEndDate": cache.contract_end_date,
                    "updatedAt": cache.updated_at,
                },
            )
        )
        stack.enter_context(
            patch("app.core.db.list_sync_devices_payload", return_value=list(cache.devices))
        )
        yield


def test_build_status_payload_includes_live_device_sync_progress() -> None:
    engine = DeviceSyncEngine(cfg=SimpleNamespace(), logger=MagicMock())
    engine._set_progress(
        running=True,
        deviceName="Front Door",
        deviceId=7,
        current=2,
        total=5,
    )
    app = _StatusStreamApp(engine)

    with (
        patch("access.store.load_auth_token", return_value=_make_auth()),
        patch("access.store.load_sync_cache", return_value=_make_cache()),
        _patched_status_dependencies(),
    ):
        payload = local_access_api_v2._build_status_payload(app)

    assert payload["deviceSync"]["progress"] == {
        "running": True,
        "deviceName": "Front Door",
        "deviceId": 7,
        "current": 2,
        "total": 5,
    }


def test_build_status_payload_uses_ultra_sync_progress_when_main_engine_is_idle() -> None:
    engine = DeviceSyncEngine(cfg=SimpleNamespace(), logger=MagicMock())
    app = _StatusStreamApp(engine)
    app._ultra_engine = _UltraProgressEngine({
        "running": True,
        "deviceName": "door 1",
        "deviceId": 5,
        "current": 12,
        "total": 1100,
    })

    with (
        patch("access.store.load_auth_token", return_value=_make_auth()),
        patch("access.store.load_sync_cache", return_value=_make_cache()),
        _patched_status_dependencies(),
    ):
        payload = local_access_api_v2._build_status_payload(app)

    assert payload["deviceSync"]["progress"] == {
        "running": True,
        "deviceName": "door 1",
        "deviceId": 5,
        "current": 12,
        "total": 1100,
    }


def test_build_status_payload_hides_stale_progress_when_no_sync_is_running() -> None:
    engine = DeviceSyncEngine(cfg=SimpleNamespace(), logger=MagicMock())
    engine._set_progress(
        running=False,
        deviceName="Front Door",
        deviceId=7,
        current=0,
        total=1276,
    )
    app = _StatusStreamApp(engine)
    app._ultra_engine = _UltraProgressEngine({
        "running": False,
        "deviceName": "door 1",
        "deviceId": 5,
        "current": 0,
        "total": 1276,
    })
    app._ultra_engine.running = False

    with (
        patch("access.store.load_auth_token", return_value=_make_auth()),
        patch("access.store.load_sync_cache", return_value=_make_cache()),
        _patched_status_dependencies(),
    ):
        payload = local_access_api_v2._build_status_payload(app)

    assert payload["deviceSync"]["progress"] is None


def test_status_stream_emits_updated_status_when_device_sync_changes() -> None:
    engine = DeviceSyncEngine(cfg=SimpleNamespace(), logger=MagicMock())
    app = _StatusStreamApp(engine)
    ctx = _FakeStatusStreamCtx(app)

    with (
        patch("access.store.load_auth_token", return_value=_make_auth()),
        patch("access.store.load_sync_cache", return_value=_make_cache()),
        _patched_status_dependencies(),
    ):
        worker = threading.Thread(target=local_access_api_v2._handle_status_stream_sse, args=(ctx,), daemon=True)
        worker.start()

        deadline = time.time() + 1.0
        while ctx._status_sent < 1 and time.time() < deadline:
            time.sleep(0.01)

        engine._set_progress(
            running=True,
            deviceName="Front Door",
            deviceId=7,
            current=1,
            total=3,
        )

        deadline = time.time() + 2.0
        while ctx._status_sent < 2 and time.time() < deadline:
            time.sleep(0.01)

        worker.join(timeout=0.5)

    status_events = [data for event, data in ctx.events if event == "status"]
    assert len(status_events) == 2
    assert status_events[0]["deviceSync"]["progress"] is None
    assert status_events[1]["deviceSync"]["progress"]["running"] is True
    assert status_events[1]["deviceSync"]["progress"]["current"] == 1


def test_access_routes_expose_status_stream_endpoint() -> None:
    assert ("GET", "/api/v2/status/stream", "_handle_status_stream_sse") in ACCESS_LOCAL_ROUTE_SPECS

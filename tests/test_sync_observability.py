import importlib
import json
import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


def _reload_db_module(tmp_path, monkeypatch):
    import app.core.db as db_module

    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    importlib.reload(db_module)
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()
    return db_module


def _make_engine(tmp_path, monkeypatch):
    db_module = _reload_db_module(tmp_path, monkeypatch)
    from app.core.device_sync import DeviceSyncEngine

    engine = DeviceSyncEngine(cfg=SimpleNamespace(plcomm_dll_path="", timeout_ms=5000), logger=logging.getLogger("test"))
    return engine, db_module


def _make_device(dev_id=1):
    return {
        "id": dev_id,
        "name": "TestDevice",
        "ipAddress": "10.0.0.1",
        "portNumber": 4370,
        "password": "",
        "active": True,
        "accessDevice": True,
        "accessDataMode": "DEVICE",
        "fingerprintEnabled": False,
        "authorizeTimezoneId": 1,
        "doorIds": [15],
        "doorPresets": [],
        "pushingToDevicePolicy": "ALL",
    }


def _make_user(am_id):
    return {
        "activeMembershipId": am_id,
        "userId": am_id + 1000,
        "membershipId": am_id,
        "fullName": f"User {am_id}",
        "phone": "0600000000",
        "email": f"u{am_id}@example.com",
        "validFrom": "2026-01-01",
        "validTo": "2026-12-31",
        "firstCardId": str(am_id * 100),
        "secondCardId": None,
        "image": None,
        "fingerprints": [],
        "faceId": None,
        "accountUsernameId": None,
        "qrCodePayload": None,
        "birthday": None,
        "imageSource": None,
        "userImageStatus": None,
    }


def _patch_sdk(device_pins=None):
    sdk_cls = MagicMock()
    sdk_inst = MagicMock()
    sdk_cls.return_value = sdk_inst
    sdk_inst.get_device_data_rows.return_value = [{"Pin": p} for p in (device_pins or [])]
    sdk_inst.set_device_data.return_value = 0
    sdk_inst.set_device_data_batch.return_value = (50, [])
    sdk_inst.clear_device_table.return_value = 0
    sdk_inst.delete_device_data.return_value = 0
    sdk_inst.set_device_param.return_value = 0
    sdk_inst.disconnect.return_value = None
    sdk_inst.__enter__ = lambda s: s
    sdk_inst.__exit__ = MagicMock(return_value=False)
    return sdk_cls, sdk_inst


def test_sync_observability_tables_exist(tmp_path, monkeypatch):
    db = _reload_db_module(tmp_path, monkeypatch)

    with db.get_conn() as conn:
        sync_cols = {row["name"] for row in conn.execute("PRAGMA table_info(sync_run_history)").fetchall()}
        batch_cols = {row["name"] for row in conn.execute("PRAGMA table_info(push_batch_history)").fetchall()}
        pin_cols = {row["name"] for row in conn.execute("PRAGMA table_info(push_pin_history)").fetchall()}
        fk_on = conn.execute("PRAGMA foreign_keys").fetchone()[0]

    assert fk_on == 1
    assert {"id", "run_type", "trigger_source", "status", "raw_response", "created_at"} <= sync_cols
    assert {"id", "sync_run_id", "device_id", "device_name", "policy", "status", "created_at"} <= batch_cols
    assert {"id", "batch_id", "pin", "operation", "status"} <= pin_cols


def test_push_pin_history_cascades_on_batch_delete(tmp_path, monkeypatch):
    db = _reload_db_module(tmp_path, monkeypatch)

    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO push_batch_history (
                sync_run_id, device_id, device_name, policy, status, created_at
            ) VALUES (NULL, 1, 'Door A', 'INCREMENTAL', 'SUCCESS', '2026-04-11T10:00:00')
            """
        )
        batch_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            """
            INSERT INTO push_pin_history (batch_id, pin, full_name, operation, status, error_message, duration_ms)
            VALUES (?, '101', 'Alice', 'UPSERT', 'SUCCESS', NULL, 12)
            """,
            (batch_id,),
        )
        conn.commit()
        conn.execute("DELETE FROM push_batch_history WHERE id = ?", (batch_id,))
        conn.commit()
        remaining = conn.execute("SELECT COUNT(*) FROM push_pin_history WHERE batch_id = ?", (batch_id,)).fetchone()[0]

    assert remaining == 0


def test_sync_run_helper_round_trip_and_list_filter(tmp_path, monkeypatch):
    db = _reload_db_module(tmp_path, monkeypatch)

    first_id = db.insert_sync_run(
        run_type="TRIGGERED",
        trigger_source="SYNC_NOW_API",
        trigger_hint=json.dumps({"manual": True}),
        status="IN_PROGRESS",
        created_at="2026-04-11T10:00:00",
    )
    second_id = db.insert_sync_run(
        run_type="PERIODIC",
        trigger_source="TIMER",
        status="IN_PROGRESS",
        created_at="2026-04-11T10:05:00",
    )

    db.update_sync_run(
        id=first_id,
        status="PARTIAL",
        members_total=250,
        members_changed=3,
        devices_synced=2,
        duration_ms=4200,
        error_message="device dispatch delayed",
        raw_response=json.dumps({"refresh": {"members": True}, "usersCount": 3}),
    )
    db.update_sync_run(
        id=second_id,
        status="SUCCESS",
        members_total=250,
        members_changed=0,
        devices_synced=2,
        duration_ms=1800,
        raw_response=json.dumps({"refresh": {"members": False}, "usersCount": 0}),
    )

    detail = db.get_sync_run(first_id)
    failed_only = db.list_sync_runs(page=0, size=10, status="PARTIAL")
    page = db.list_sync_runs(page=0, size=1)

    assert detail["trigger_source"] == "SYNC_NOW_API"
    assert detail["members_changed"] == 3
    assert json.loads(detail["raw_response"])["usersCount"] == 3
    assert failed_only["total"] == 1
    assert failed_only["items"][0]["id"] == first_id
    assert "raw_response" not in failed_only["items"][0]
    assert page["total"] == 2
    assert len(page["items"]) == 1


def test_push_history_helper_round_trip(tmp_path, monkeypatch):
    db = _reload_db_module(tmp_path, monkeypatch)

    run_id = db.insert_sync_run(
        run_type="PERIODIC",
        trigger_source="TIMER",
        status="IN_PROGRESS",
        created_at="2026-04-11T10:00:00",
    )
    batch_id = db.insert_push_batch(
        sync_run_id=run_id,
        device_id=7,
        device_name="Main Gate",
        policy="INCREMENTAL",
        status="IN_PROGRESS",
        created_at="2026-04-11T10:01:00",
    )
    db.insert_push_pin(
        batch_id=batch_id,
        pin="101",
        full_name="Alice",
        operation="UPSERT",
        status="SUCCESS",
        duration_ms=21,
    )
    db.insert_push_pin(
        batch_id=batch_id,
        pin="102",
        full_name="Bob",
        operation="UPSERT",
        status="FAILED",
        error_message="timeout",
        duration_ms=34,
    )
    db.update_push_batch(
        id=batch_id,
        pins_attempted=2,
        pins_success=1,
        pins_failed=1,
        status="PARTIAL",
        duration_ms=1550,
        error_message="1 pin failed",
    )

    listing = db.list_push_batches(page=0, size=10, device_id=7)
    pins = db.get_push_batch_pins(batch_id)

    assert listing["total"] == 1
    assert listing["items"][0]["device_name"] == "Main Gate"
    assert listing["items"][0]["status"] == "PARTIAL"
    assert len(pins) == 2
    assert pins[0]["pin"] == "101"
    assert pins[1]["error_message"] == "timeout"


def test_resolve_sync_context_prefers_pending_request():
    from app.core.sync_observability import SyncTriggerContext, resolve_sync_context

    context, startup_pending = resolve_sync_context(
        pending=SyncTriggerContext(
            run_type="HARD_RESET",
            trigger_source="SYNC_NOW_API",
            trigger_hint={"hardReset": True},
        ),
        startup_pending=True,
    )

    assert context.run_type == "HARD_RESET"
    assert context.trigger_source == "SYNC_NOW_API"
    assert context.trigger_hint == {"hardReset": True}
    assert startup_pending is False


def test_resolve_sync_context_uses_startup_once_then_timer():
    from app.core.sync_observability import resolve_sync_context

    startup_context, startup_pending = resolve_sync_context(pending=None, startup_pending=True)
    timer_context, timer_pending = resolve_sync_context(pending=None, startup_pending=startup_pending)

    assert startup_context.run_type == "PERIODIC"
    assert startup_context.trigger_source == "STARTUP"
    assert startup_pending is False
    assert timer_context.run_type == "PERIODIC"
    assert timer_context.trigger_source == "TIMER"
    assert timer_pending is False


def test_request_sync_now_stores_pending_context_and_schedules():
    from app.ui.app import MainApp

    scheduled = []
    app = SimpleNamespace(
        _pending_sync_context=None,
        after=lambda delay, callback: scheduled.append((delay, callback)),
        _sync_tick=lambda: None,
    )

    MainApp.request_sync_now(
        app,
        trigger_source="SYNC_NOW_API",
        run_type="HARD_RESET",
        trigger_hint={"hardReset": True},
    )

    assert len(scheduled) == 1
    assert scheduled[0][0] == 50
    assert app._pending_sync_context.run_type == "HARD_RESET"
    assert app._pending_sync_context.trigger_source == "SYNC_NOW_API"
    assert app._pending_sync_context.trigger_hint == {"hardReset": True}


def test_main_app_initializes_scheduler_before_first_after(monkeypatch):
    import app.ui.app as app_module

    class StopInit(Exception):
        pass

    cfg = SimpleNamespace(
        plcomm_dll_path="C:/sdk/plcommpro.dll",
        zkfp_dll_path="C:/sdk/libzkfp.dll",
        log_level="INFO",
    )
    logger = MagicMock()

    monkeypatch.setattr(app_module, "add_windows_dll_search_paths", lambda: None)
    monkeypatch.setattr(app_module, "ensure_dirs", lambda: None)
    monkeypatch.setattr(app_module, "init_db", lambda: None)
    monkeypatch.setattr(app_module, "load_access_app_config", lambda: cfg)
    monkeypatch.setattr(app_module.MainApp, "_resolve_sdk_dll", lambda self, path: path)
    monkeypatch.setattr(app_module, "require_32bit_python_for_32bit_dll", lambda path: None)
    monkeypatch.setattr(app_module, "setup_logging", lambda *args, **kwargs: logger)
    monkeypatch.setattr(app_module, "get_access_config_status", lambda: {})
    monkeypatch.setattr(app_module, "get_access_storage_status", lambda: {})
    monkeypatch.setattr(app_module, "check_zkemkeeper_registration", lambda: {"ok": True})
    monkeypatch.setattr(app_module, "UpdateManager", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(app_module, "DeviceSyncEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(app_module, "DeviceAttendanceMaintenanceEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(app_module, "AgentRealtimeEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(app_module, "UltraEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(app_module.MainApp, "_sync_startup_registration", lambda self: None)

    def assert_scheduler_initialized(self, delay_ms, callback):
        assert self._scheduled == []
        assert hasattr(self, "_sched_lock")
        assert self._sched_id_counter == 0
        raise StopInit

    monkeypatch.setattr(app_module.MainApp, "after", assert_scheduler_initialized)

    with pytest.raises(StopInit):
        app_module.MainApp()


def test_sync_handlers_schedule_expected_trigger_metadata():
    from app.api import local_access_api_v2 as api_module

    scheduled = []
    requests = []
    responses = []

    def after(delay, callback):
        scheduled.append((delay, callback))

    def send_json(status, payload):
        responses.append((status, payload))

    app = SimpleNamespace(
        after=after,
        request_sync_now=lambda **kwargs: requests.append(kwargs),
        _ultra_engine=None,
    )
    ctx = SimpleNamespace(app=app, send_json=send_json, body=lambda: {})

    api_module._handle_sync_now(ctx)
    assert responses[-1][0] == 200
    assert responses[-1][1]["ok"] is True
    scheduled.pop(0)[1]()
    assert requests.pop(0) == {
        "trigger_source": "SYNC_NOW_API",
        "run_type": "TRIGGERED",
        "trigger_hint": None,
    }

    with patch("app.core.db.clear_all_device_sync_hashes", return_value=7):
        api_module._handle_sync_hard_reset(ctx)
    assert responses[-1][0] == 200
    assert responses[-1][1]["cleared"] == 7
    scheduled.pop(0)[1]()
    assert requests.pop(0) == {
        "trigger_source": "SYNC_NOW_API",
        "run_type": "HARD_RESET",
        "trigger_hint": {"hardReset": True},
    }


def test_sync_now_handler_preserves_dashboard_trigger_hint():
    from app.api import local_access_api_v2 as api_module

    scheduled = []
    requests = []
    responses = []

    def after(delay, callback):
        scheduled.append((delay, callback))

    def send_json(status, payload):
        responses.append((status, payload))

    app = SimpleNamespace(
        after=after,
        request_sync_now=lambda **kwargs: requests.append(kwargs),
        _ultra_engine=None,
    )
    hint = {
        "entityType": "ACTIVE_MEMBERSHIP",
        "entityId": 77,
        "operation": "UPDATE",
        "priority": "HIGH",
    }
    ctx = SimpleNamespace(app=app, send_json=send_json, body=lambda: dict(hint))

    api_module._handle_sync_now(ctx)

    assert responses[-1][0] == 200
    scheduled.pop(0)[1]()
    assert requests.pop(0) == {
        "trigger_source": "SYNC_NOW_API",
        "run_type": "TRIGGERED",
        "trigger_hint": hint,
    }


def test_local_api_server_suppresses_connection_abort_tracebacks(monkeypatch):
    from app.api import local_access_api_v2 as api_module

    delegated = []
    monkeypatch.setattr(
        api_module.ThreadingHTTPServer,
        "handle_error",
        lambda self, request, client_address: delegated.append((request, client_address)),
    )
    monkeypatch.setattr(
        api_module,
        "sys",
        SimpleNamespace(exc_info=lambda: (ConnectionAbortedError, ConnectionAbortedError("closed"), None)),
    )

    server = object.__new__(api_module._AppHTTPServerV2)
    server.app = SimpleNamespace(logger=MagicMock())
    request = object()

    api_module._AppHTTPServerV2.handle_error(server, request, ("127.0.0.1", 25298))

    assert delegated == []
    server.app.logger.info.assert_called_once()


def test_local_api_server_delegates_unexpected_errors(monkeypatch):
    from app.api import local_access_api_v2 as api_module

    delegated = []
    monkeypatch.setattr(
        api_module.ThreadingHTTPServer,
        "handle_error",
        lambda self, request, client_address: delegated.append((request, client_address)),
    )
    monkeypatch.setattr(
        api_module,
        "sys",
        SimpleNamespace(exc_info=lambda: (ValueError, ValueError("boom"), None)),
    )

    server = object.__new__(api_module._AppHTTPServerV2)
    server.app = SimpleNamespace(logger=MagicMock())
    request = object()

    api_module._AppHTTPServerV2.handle_error(server, request, ("127.0.0.1", 25298))

    assert delegated == [(request, ("127.0.0.1", 25298))]


def test_build_sync_response_summary_is_compact():
    from app.core.sync_observability import build_sync_response_summary, serialize_trigger_hint

    summary = build_sync_response_summary(
        data={
            "membersDeltaMode": True,
            "users": [{"activeMembershipId": 1}, {"activeMembershipId": 2}],
            "devices": [{"id": 9}],
            "validMemberIds": [1, 2, 3],
            "refreshMembers": True,
            "refreshDevices": False,
            "refreshCredentials": True,
            "refreshSettings": False,
        },
        refresh={
            "members": True,
            "devices": False,
            "credentials": True,
            "settings": False,
        },
        new_tokens={"membersVersion": "mv-1", "devicesVersion": "dv-1"},
    )

    assert summary == {
        "refresh": {
            "members": True,
            "devices": False,
            "credentials": True,
            "settings": False,
        },
        "membersDeltaMode": True,
        "usersCount": 2,
        "devicesCount": 1,
        "validMemberIdsCount": 3,
        "newTokens": {"membersVersion": "mv-1", "devicesVersion": "dv-1"},
    }
    assert serialize_trigger_hint({"source": "manual"}) == '{"source":"manual"}'
    assert serialize_trigger_hint(None) is None


def test_device_sync_records_push_batch_and_pin_rows(tmp_path, monkeypatch):
    engine, db = _make_engine(tmp_path, monkeypatch)
    users = [_make_user(1), _make_user(2), _make_user(3)]
    device = _make_device()
    run_id = db.insert_sync_run(
        run_type="PERIODIC",
        trigger_source="TIMER",
        status="IN_PROGRESS",
        created_at="2026-04-11T10:00:00",
    )

    sdk_cls, _sdk_inst = _patch_sdk(device_pins=[])
    with patch("app.core.device_sync.PullSDK", sdk_cls):
        engine._sync_one_device(
            device=device,
            users=users,
            local_fp_index={},
            default_door_id=15,
            sync_run_id=run_id,
        )

    batches = db.list_push_batches(page=0, size=10)
    assert batches["total"] == 1
    batch = batches["items"][0]
    assert batch["sync_run_id"] == run_id
    assert batch["device_id"] == 1
    assert batch["pins_attempted"] == 3
    assert batch["pins_success"] == 3
    assert batch["pins_failed"] == 0

    pins = db.get_push_batch_pins(batch["id"])
    assert len(pins) == 3
    assert all(pin["operation"] == "UPSERT" for pin in pins)
    assert all(pin["status"] == "SUCCESS" for pin in pins)


def test_device_sync_emits_feedback_event_on_successful_batch(tmp_path, monkeypatch):
    db = _reload_db_module(tmp_path, monkeypatch)
    from app.core.device_sync import DeviceSyncEngine

    events: list[tuple[str, dict]] = []
    engine = DeviceSyncEngine(
        cfg=SimpleNamespace(plcomm_dll_path="", timeout_ms=5000),
        logger=logging.getLogger("test"),
        feedback_callback=lambda event_type, payload: events.append((event_type, payload)),
    )
    users = [_make_user(1), _make_user(2)]
    device = _make_device(dev_id=7)
    run_id = db.insert_sync_run(
        run_type="PERIODIC",
        trigger_source="TIMER",
        status="IN_PROGRESS",
        created_at="2026-04-11T10:00:00",
    )

    sdk_cls, _sdk_inst = _patch_sdk(device_pins=[])
    with patch("app.core.device_sync.PullSDK", sdk_cls):
        engine._sync_one_device(
            device=device,
            users=users,
            local_fp_index={},
            default_door_id=15,
            sync_run_id=run_id,
        )

    assert events == [
        (
            "device_push_success",
            {
                "syncRunId": run_id,
                "batchId": 1,
                "deviceId": 7,
                "deviceName": "TestDevice",
            },
        )
    ]


def test_cleanup_stale_in_progress_sync_runs(tmp_path, monkeypatch):
    """Stale IN_PROGRESS rows from a previous session are marked INTERRUPTED."""
    db = _reload_db_module(tmp_path, monkeypatch)

    # Insert one IN_PROGRESS and one SUCCESS run
    stale_id = db.insert_sync_run(
        run_type="PERIODIC",
        trigger_source="TIMER",
        status="IN_PROGRESS",
        created_at="2026-04-11T09:00:00",
    )
    done_id = db.insert_sync_run(
        run_type="PERIODIC",
        trigger_source="TIMER",
        status="SUCCESS",
        created_at="2026-04-11T09:05:00",
    )
    db.update_sync_run(id=done_id, status="SUCCESS", duration_ms=1000)

    cleaned = db.cleanup_stale_in_progress_sync_runs()

    assert cleaned == 1
    stale_row = db.get_sync_run(stale_id)
    done_row = db.get_sync_run(done_id)
    assert stale_row["status"] == "INTERRUPTED"
    assert "restarted" in stale_row["error_message"]
    assert done_row["status"] == "SUCCESS"  # untouched

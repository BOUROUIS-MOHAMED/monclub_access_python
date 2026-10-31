from types import SimpleNamespace
from unittest.mock import Mock

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    from app.core import db
    monkeypatch.setattr(db, "_DB_PATH", str(tmp_path / "force-open.db"))
    db.init_db()
    yield db
    db._shutdown_db_writer_for_tests()


def test_force_open_row_inserted_and_marked_synced(db, monkeypatch):
    from app.api import local_access_api_v2 as routes
    from access import pc_identity
    monkeypatch.setattr(pc_identity, "get_pc_identity_service", lambda app: SimpleNamespace(
        status=lambda: {"pcUuid": "this-pc"}))
    routes._door_open_last.clear()
    worker = SimpleNamespace(request_door_open=lambda **kw: {"ok": True})
    api = SimpleNamespace(upload_force_opens=Mock(return_value={"saved": 1, "duplicates": 0}))
    app = SimpleNamespace(_ultra_engine=SimpleNamespace(running=True, _workers={7: worker}),
                          _api=lambda: api)
    ctx = SimpleNamespace(app=app, param_int=lambda k: 7, body=lambda: {"doorNumber": 2}, send_json=Mock())
    routes._handle_device_door_open(ctx)
    assert ctx.send_json.call_args.args[0] == 200
    rows = db.list_pending_force_open_events()
    assert len(rows) == 1
    assert rows[0]["device_id"] == 7
    assert rows[0]["door_id"] == 2
    assert rows[0]["agent_id"] is None
    routes.staff_upload_force_opens(app, "gym-token")
    assert db.list_pending_force_open_events() == []
    event = api.upload_force_opens.call_args.kwargs["events"][0]
    assert event["pcUuid"] == "this-pc"
    assert event["localId"] == rows[0]["local_id"]


def test_force_open_upload_failure_retries_same_local_id(db, monkeypatch):
    from app.api import local_access_api_v2 as routes
    from access import pc_identity
    monkeypatch.setattr(pc_identity, "get_pc_identity_service", lambda app: SimpleNamespace(status=lambda: {"pcUuid": "pc"}))
    local_id = db.insert_force_open_event(device_id=7, door_id=1, agent_id=3)
    upload = Mock(side_effect=[ConnectionError("timeout"), {"saved": 0, "duplicates": 1}])
    app = SimpleNamespace(_api=lambda: SimpleNamespace(upload_force_opens=upload))
    routes.staff_upload_force_opens(app, "gym")
    assert db.list_pending_force_open_events()[0]["attempts"] == 1
    routes.staff_upload_force_opens(app, "gym")
    assert db.list_pending_force_open_events() == []
    assert [call.kwargs["events"][0]["localId"] for call in upload.call_args_list] == [local_id, local_id]


def test_forwarded_request_is_not_recorded_as_a_successful_open(db):
    from app.api import local_access_api_v2 as routes
    from access import v2_routes
    app = SimpleNamespace(_v2_runtime=SimpleNamespace(availability="ON", api=SimpleNamespace(
        request_command=lambda body: {"command": {"id": "cmd"}, "created": True})))
    ctx = SimpleNamespace(app=app, param_int=lambda k: 7, body=lambda: {"doorNumber": 2}, send_json=Mock())
    v2_routes._handle_v2_request_door(ctx)
    assert ctx.send_json.call_args.args[0] == 202
    assert db.list_pending_force_open_events() == []

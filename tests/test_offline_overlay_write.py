from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.core import db, offline_actions
from app.core.v2 import lease_gate
from tests.test_offline_actions import ctx
from tests.test_account_pin_device_sites import _cache, _ali_gym, _pullsdk_device, _engine, _sdk


@pytest.fixture
def desk(ctx):
    ctx.app._request_running_ultra_sync = Mock(return_value=True)
    with db.get_conn() as conn:
        db._insert_device_row(conn.cursor(), _pullsdk_device())
        conn.commit()
    return ctx.app


def create(desk, request_id=None):
    return offline_actions.record_if_offline(desk, "CREATE", {"creationKind": "account_plus_membership", "body": {
        "clientRequestId": request_id, "firstname": "Ali", "lastname": "B", "membershipId": 3, "cardId": "1234"}})


def test_create_offline_writes_temp_member_entry(desk):
    result = create(desk)
    row, = db.list_offline_overlay()
    assert row["local_id"] == result["localId"] and row["kind"] == "TEMP_MEMBER"
    assert row["card"] == "1234" and row["full_name"] == "Ali B"
    assert row["temp_pin"] == "900000001" and row["device_ids"] == [1]
    desk._request_running_ultra_sync.assert_called_once()
    assert desk._request_running_ultra_sync.call_args.kwargs["changed_ids"] is None


def test_temp_pin_skips_pins_already_on_device(desk):
    db.save_device_sync_state(device_id=1, pin="900000001", desired_hash="h", ok=True, error=None)
    create(desk)
    assert db.list_offline_overlay()[0]["temp_pin"] == "900000002"


def test_temp_pin_never_reused(desk):
    first = create(desk)
    pin = db.list_offline_overlay()[0]["temp_pin"]
    db.drop_offline_overlay(first["localId"], "EXPIRED")
    create(desk)
    assert db.list_offline_overlay()[1]["temp_pin"] != pin


def test_reader_pc_writes_no_overlay(desk, monkeypatch):
    monkeypatch.setattr(lease_gate, "_current", lease_gate.LeaseSnapshot(role="READER"))
    assert create(desk)["code"] == "READER_OFFLINE"
    assert not db.list_offline_overlay()


@pytest.mark.parametrize("driver", ["pullsdk", "standalone"])
def test_overlay_finger_survives_targeted_member_sync(desk, monkeypatch, driver):
    user = _ali_gym()
    user["fingerprints"] = []
    _cache(db, [user])
    result = offline_actions.record_if_offline(desk, "FINGERPRINT", {"activeMembershipId": 31000,
        "fingerId": 1, "templateVersion": 10, "templateEncoding": "BASE64", "templateData": "AQIDBA==",
        "label": "Index", "enabled": True}, target_id=31000)
    assert result["ok"]
    if driver == "standalone":
        from tests.test_standalone_incremental_sync import _worker
        from tests.test_standalone_finger_removal_state import RecordingDriver
        drv = RecordingDriver()
        worker, _ = _worker(monkeypatch, driver=drv, users=[user])
        worker._device["id"] = worker._device_id = 1
        worker._run_standalone_member_sync(31000)
        assert drv.push_calls[0]["templates"]["31000"][0]["templateData"] == "AQIDBA=="
    else:
        sdk = _sdk()
        engine = _engine()
        captured = []
        monkeypatch.setattr(engine, "_push_templates", lambda sdk, **kw: (captured.extend(kw["templates"]) or len(kw["templates"]), []))
        engine.sync_member_on_connected_sdk(sdk=sdk, device=_pullsdk_device(fingerprintEnabled=True), member_id=31000)
        assert captured[0]["templateData"] == "AQIDBA=="


def test_disable_here_is_offline_only_and_checks_permission(desk):
    from app.api.local_access_api_v2 import _handle_member_fingerprint_disable_here
    context = SimpleNamespace(app=desk, param_int=lambda k: 31000 if k == "activeMembershipId" else 77, send_json=Mock())
    desk.staff_session.offline_detector.set_manual(False)
    _handle_member_fingerprint_disable_here(context)
    assert context.send_json.call_args.args[1]["code"] == "ONLINE_USE_DASHBOARD"
    desk.staff_session.offline_detector.set_manual(True)
    _cache(db, [{**_ali_gym(), "fingerprints": [{"id": 77, "fingerId": 1}]}])
    _handle_member_fingerprint_disable_here(context)
    assert db.list_offline_overlay()[0]["kind"] == "FINGER_DISABLE"


def test_offline_action_and_overlay_roll_back_together(desk, monkeypatch):
    def fail(conn, row):
        raise RuntimeError("overlay failed")
    monkeypatch.setattr(db, "_insert_offline_overlay", fail)
    with pytest.raises(RuntimeError):
        create(desk)
    assert not db.list_offline_pending_actions() and not db.list_offline_overlay()
    with db.get_conn() as conn:
        assert not conn.execute("SELECT * FROM used_temp_pins").fetchall()


def test_membership_only_existing_account_pin_has_no_duplicate_temp(desk):
    user = _ali_gym()
    user["accountUsernameId"] = "ali"
    _cache(db, [user])
    with db.get_conn() as conn:
        conn.execute("UPDATE sync_devices SET pin_scheme = 'ACCOUNT' WHERE id = 1")
        conn.commit()
    db.save_device_sync_state(device_id=1, pin="5", desired_hash="h", ok=True, error=None)
    result = offline_actions.record_if_offline(desk, "CREATE", {"creationKind": "membership_only",
        "body": {"accountUsernameId": "ali", "membershipId": 3, "cardId": "1234"}})
    assert result["ok"] and not db.list_offline_overlay()


def test_upload_rejection_drops_overlay_but_transport_failure_does_not(desk):
    result = create(desk)
    desk._api.return_value.upload_offline_actions.side_effect = ConnectionError("offline")
    offline_actions.upload_pending(desk, "gym", pc_uuid="pc-test")
    assert db.list_offline_overlay()[0]["state"] == "ACTIVE"
    desk._api.return_value.upload_offline_actions.side_effect = None
    desk._api.return_value.upload_offline_actions.return_value = {"stored": 0, "duplicates": 0,
        "rejected": [{"localId": result["localId"], "reason": "UNKNOWN_AGENT"}]}
    offline_actions.upload_pending(desk, "gym", pc_uuid="pc-test")
    assert db.list_offline_overlay()[0]["dropped_reason"] == "REJECTED"


def test_create_targets_only_devices_delivering_the_plan(desk):
    with db.get_conn() as conn:
        db._insert_device_row(conn.cursor(), _pullsdk_device(id=2, allowedMemberships=[99]))
        conn.commit()
    create(desk)
    assert db.list_offline_overlay()[0]["device_ids"] == [1]


def test_create_with_suspect_clock_never_requests_device_write(desk, monkeypatch):
    monkeypatch.setattr(db, "gym_date_status", lambda **kw: {"suspect": True, "gym_date": None})
    assert create(desk)["ok"]
    assert db.list_offline_overlay()[0]["state"] == "DROPPED"
    desk._request_running_ultra_sync.assert_not_called()


def test_temp_pin_uses_server_pc_id_modulo_and_persists_it(desk):
    import base64
    import json
    encoded = base64.urlsafe_b64encode(json.dumps({"gymAccessPcId": 1234}).encode()).decode().rstrip("=")
    desk._pc_identity_service = SimpleNamespace(_pc_token=f"header.{encoded}.signature")
    create(desk)
    desk._pc_identity_service = None
    create(desk)
    assert [r["temp_pin"] for r in db.list_offline_overlay()] == ["923400001", "923400002"]


def test_staff_login_off_preserves_legacy_queue(desk):
    from app.api import local_access_api_v2 as routes
    desk.staff_session._snapshot["enabled"] = False
    context = SimpleNamespace(app=desk, body=lambda: {"opKind": "edit", "targetId": 17,
        "payload": {"id": 17, "cardId": "1234"}}, send_json=Mock())
    routes._handle_member_mutation(context)
    desk.submit_offline_mutation.assert_called_once()
    assert not db.list_offline_overlay() and not db.list_offline_pending_actions()


def test_member_display_does_not_promise_a_pass_after_expiry_or_upload(desk):
    result = create(desk)
    assert offline_actions.pending_members()[0]["offlinePassState"] == "ACTIVE"
    desk._api.return_value.upload_offline_actions.return_value = {"stored": 1, "duplicates": 0, "rejected": []}
    offline_actions.upload_pending(desk, "gym", pc_uuid="pc-test")
    db.drop_offline_overlay(result["localId"], "EXPIRED")
    assert offline_actions.pending_members()[0]["offlinePassState"] == "DROPPED"

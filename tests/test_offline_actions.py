import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.api import local_access_api_v2 as routes


@pytest.fixture
def ctx(monkeypatch, tmp_path):
    from app.core import db, staff_session, offline_actions
    from app.core.v2 import lease_gate
    monkeypatch.setattr(db, "_DB_PATH", str(tmp_path / "actions.db"))
    db.init_db()
    monkeypatch.setattr(staff_session, "kv_get", lambda k: None)
    staff = staff_session.StaffSession()
    staff._snapshot.update(enabled=True, allowedAgents=[{"id": 1, "name": "Amira", "adminAgent": True}])
    staff._offline_config = {"doorLimit": 20, "moneyLimit": 10}
    staff.offline_detector.set_manual(True)
    staff.offline_session._unlocked = True
    staff.offline_session.act_as(1)
    lease = lease_gate.LeaseSnapshot(role="ALL_TURNSTILES")
    monkeypatch.setattr(lease_gate, "_current", lease)
    monkeypatch.setattr(offline_actions, "upload_soon", lambda app: None)
    app = SimpleNamespace(staff_session=staff, _api=Mock(), submit_offline_mutation=Mock(return_value={"queued": True}))
    return SimpleNamespace(app=app, body=lambda: {"opKind": "edit", "targetId": 17,
        "payload": {"id": 17, "cardId": "0017", "secondCardId": "", "note": "Hors ligne"}}, send_json=Mock())


def test_offline_edit_goes_to_pending_not_backend(ctx):
    from app.core.db import list_offline_pending_actions
    routes._handle_member_mutation(ctx)
    assert ctx.send_json.call_args.args[0] == 200
    rows = list_offline_pending_actions()
    assert len(rows) == 1 and rows[0]["kind"] == "EDIT"
    assert rows[0]["payload"] == {"id": 17, "cardId": "0017", "secondCardId": "", "note": "Hors ligne"}
    ctx.app._api.assert_not_called()
    ctx.app.submit_offline_mutation.assert_not_called()


def test_reader_offline_refused(ctx, monkeypatch):
    from app.core.v2 import lease_gate
    monkeypatch.setattr(lease_gate, "_current", lease_gate.LeaseSnapshot(role="READER"))
    routes._handle_member_mutation(ctx)
    assert ctx.send_json.call_args.args[1]["code"] == "READER_OFFLINE"
    ctx.app.submit_offline_mutation.assert_not_called()


def test_limit_reached_refused(ctx):
    ctx.app.staff_session._offline_config["moneyLimit"] = 1
    routes._handle_member_mutation(ctx)
    routes._handle_member_mutation(ctx)
    assert ctx.send_json.call_args.args == (409, {"ok": False, "code": "LIMIT_REACHED", "category": "MONEY", "used": 1, "max": 1})


def test_upload_marks_uploaded_and_keeps_rejected(ctx):
    from app.core import db, offline_actions
    routes._handle_member_mutation(ctx)
    routes._handle_member_mutation(ctx)
    rows = db.list_offline_pending_actions()
    ctx.app._api.return_value.upload_offline_actions.return_value = {
        "stored": 1, "duplicates": 0, "rejected": [{"localId": rows[1]["local_id"], "reason": "UNKNOWN_AGENT"}]}
    offline_actions.upload_pending(ctx.app, "gym", pc_uuid="pc-test")
    remaining = db.list_offline_pending_actions()
    assert len(remaining) == 1 and remaining[0]["last_error"] == "UNKNOWN_AGENT"
    assert remaining[0]["attempts"] == 1
    assert ctx.app.staff_session.offline_session.limits()["money"]["used"] == 2
    sent = ctx.app._api.return_value.upload_offline_actions.call_args.kwargs["events"]
    assert sent[0]["pcUuid"] == "pc-test" and sent[0]["actAsAgentId"] == 1
    assert sent[0]["payload"]["id"] == 17


def test_switch_off_keeps_old_queue(ctx):
    ctx.app.staff_session._snapshot["enabled"] = False
    routes._handle_member_mutation(ctx)
    assert ctx.send_json.call_args.args == (200, {"queued": True})
    ctx.app.submit_offline_mutation.assert_called_once()


def test_locked_never_feeds_old_queue(ctx):
    ctx.app.staff_session.offline_session.relock()
    routes._handle_member_mutation(ctx)
    assert ctx.send_json.call_args.args[1]["code"] == "OFFLINE_LOCKED"
    ctx.app.submit_offline_mutation.assert_not_called()


def test_payload_is_encrypted_and_removed_after_upload(ctx):
    from app.core import db, offline_actions
    routes._handle_member_mutation(ctx)
    with db.get_conn() as conn:
        stored = conn.execute("SELECT payload_json FROM offline_pending_actions").fetchone()[0]
    assert stored.startswith("dpapi:") and "Hors ligne" not in stored
    ctx.app._api.return_value.upload_offline_actions.return_value = {"stored": 0, "duplicates": 1, "rejected": []}
    offline_actions.upload_pending(ctx.app, "gym", pc_uuid="pc-test")
    assert not db.list_offline_pending_actions()


def test_create_dependency_and_payload_contract(ctx):
    from app.core import db, offline_actions
    created = offline_actions.record_if_offline(ctx.app, "CREATE", {"creationKind": "membership_only", "body": {
        "firstName": "Ali", "lastName": "B", "price": 60, "payedPrice": 60, "membership_id": 3}})
    local_id = created["localId"]
    row = db.list_offline_pending_actions()[0]
    assert row["payload"]["body"]["clientRequestId"] == local_id
    projection = offline_actions.pending_members()[0]
    edit = offline_actions.record_if_offline(ctx.app, "EDIT", {"id": projection["activeMembershipId"],
        "cardId": "0012", "secondCardId": ""}, target_id=projection["activeMembershipId"])
    dependent = next(r for r in db.list_offline_pending_actions() if r["local_id"] == edit["localId"])
    assert dependent["depends_on_local_id"] == local_id
    assert dependent["target_active_membership_id"] is None


def test_upload_timeout_keeps_same_id_for_retry(ctx):
    from app.core import db, offline_actions
    routes._handle_member_mutation(ctx)
    original = db.list_offline_pending_actions()[0]["local_id"]
    ctx.app._api.return_value.upload_offline_actions.side_effect = ConnectionError("timeout")
    offline_actions.upload_pending(ctx.app, "gym", pc_uuid="pc-test")
    row = db.list_offline_pending_actions()[0]
    assert row["local_id"] == original and row["attempts"] == 1 and row["last_error"]


@pytest.mark.parametrize("kind", ["CREATE", "RENEW", "PAY_REST", "EDIT", "FREEZE", "FREEZE_CANCEL", "DELETE", "FINGERPRINT"])
def test_contract_fixture_recorded_without_payload_changes(ctx, kind):
    from pathlib import Path
    from app.core import db, offline_actions
    payload = json.loads((Path("tests/fixtures/offline_actions") / (kind.lower() + ".json")).read_text())
    result = offline_actions.record_if_offline(ctx.app, kind, payload, target_id=None if kind == "CREATE" else 10)
    assert result["ok"]
    row = db.list_offline_pending_actions()[0]
    assert row["payload"] == payload
    if kind == "CREATE":
        assert row["local_id"] == "offline-create-fixture"


def test_card_only_edit_uses_door_limit(ctx):
    from app.core import db, offline_actions
    result = offline_actions.record_if_offline(ctx.app, "EDIT", {"id": 17, "cardId": "1234", "secondCardId": ""}, target_id=17)
    assert result["ok"]
    assert db.list_offline_pending_actions()[0]["category"] == "DOOR"


def test_uploaded_create_keeps_dependency_reference_without_secrets(ctx):
    from pathlib import Path
    from app.core import db, offline_actions
    payload = json.loads(Path("tests/fixtures/offline_actions/create.json").read_text())
    created = offline_actions.record_if_offline(ctx.app, "CREATE", payload)
    ctx.app._api.return_value.upload_offline_actions.return_value = {"stored": 1, "duplicates": 0, "rejected": []}
    offline_actions.upload_pending(ctx.app, "gym", pc_uuid="pc-test")
    assert not db.list_offline_pending_actions()
    projection = offline_actions.pending_members()[0]
    dependent = offline_actions.record_if_offline(ctx.app, "FINGERPRINT", {"fingerId": 0, "templateData": "AQIDBA=="},
                                                  target_id=projection["activeMembershipId"])
    assert dependent["ok"]
    assert db.list_offline_pending_actions()[0]["depends_on_local_id"] == created["localId"]
    with db.get_conn() as conn:
        receipts = conn.execute("SELECT value_json FROM v2_kv WHERE key = 'offline_action_receipts'").fetchone()[0]
    assert "password" not in receipts and "templateData" not in receipts


def test_server_decision_retires_uploaded_marker(ctx):
    from app.core import offline_actions
    routes._handle_member_mutation(ctx)
    ctx.app._api.return_value.upload_offline_actions.return_value = {"stored": 1, "duplicates": 0, "rejected": []}
    offline_actions.upload_pending(ctx.app, "gym", pc_uuid="pc-test")
    receipt = offline_actions.uploaded_receipts()[0]
    ctx.app.staff_session._snapshot["agent"] = {"id": 1, "name": "Amira"}
    ctx.app._api.return_value.list_offline_actions.return_value = {"items": [
        {"localId": receipt["local_id"], "status": "APPLIED"}], "hasNext": False}
    offline_actions.reconcile_uploaded(ctx.app, "gym")
    assert not offline_actions.uploaded_receipts()


def test_replayed_uploaded_action_does_not_consume_limit_twice(ctx):
    from app.core import db, offline_actions
    payload = {"activeMembershipId": 17, "membership_id": 1, "price": 60, "payedPrice": 60,
               "paymentMethod": "CASH", "clientRequestId": "same-request"}
    offline_actions.record_if_offline(ctx.app, "RENEW", payload, target_id=17)
    ctx.app._api.return_value.upload_offline_actions.return_value = {"stored": 1, "duplicates": 0, "rejected": []}
    offline_actions.upload_pending(ctx.app, "gym", pc_uuid="pc-test")
    replay = offline_actions.record_if_offline(ctx.app, "RENEW", payload, target_id=17)
    assert replay["ok"]
    assert not db.list_offline_pending_actions()
    assert ctx.app.staff_session.offline_session.limits()["money"]["used"] == 1


@pytest.mark.parametrize("enabled", [True, False])
def test_transport_failure_before_detector_never_feeds_legacy_for_staff_gym(ctx, enabled):
    import ast
    from pathlib import Path
    from app.core import db
    source = ast.parse(Path("app/ui/app.py").read_text(encoding="utf-8"))
    main = next(n for n in source.body if isinstance(n, ast.ClassDef) and n.name == "MainApp")
    method = next(n for n in main.body if isinstance(n, ast.FunctionDef) and n.name == "submit_offline_mutation")
    scope = {"Dict": dict, "Any": object, "_MONEY_OP_KINDS": set(),
             "insert_offline_mutation": db.insert_offline_mutation,
             "mark_offline_mutation_failure": db.mark_offline_mutation_failure,
             "classify_failure": lambda **kw: {"recommendation": "save_later", "failure_type": "network", "failure_code": "NETWORK"}}
    exec(compile(ast.Module(body=[method], type_ignores=[]), "app/ui/app.py", "exec"), scope)
    ctx.app.staff_session._snapshot["enabled"] = enabled
    ctx.app.staff_session.offline_detector.set_manual(False)
    ctx.app.attempt_offline_mutation = lambda **kw: {"ok": False, "lastHttpStatus": None, "error": "network"}
    ctx.app._offline_money_mutations_enabled = False
    result = scope["submit_offline_mutation"](ctx.app, op_kind="edit", target_kind="active_membership", target_id=17, payload={"id": 17})
    if enabled:
        assert result["code"] == "OFFLINE_LOCKED"
        assert not db.list_offline_mutations()
    else:
        assert result["queued"]
        assert len(db.list_offline_mutations()) == 1


def test_immediate_upload_failure_does_not_undo_saved_action(ctx, monkeypatch):
    from app.core import db, offline_actions
    def no_thread(app):
        raise RuntimeError("cannot start thread")
    monkeypatch.setattr(offline_actions, "upload_soon", no_thread)
    routes._handle_member_mutation(ctx)
    assert ctx.send_json.call_args.args[0] == 200
    assert len(db.list_offline_pending_actions()) == 1

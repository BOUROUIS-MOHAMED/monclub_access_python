from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.api import local_access_api_v2 as routes
from app.core.staff_session import StaffSession
from app.api.monclub_api import MonClubApiError, MonClubApiConflictError


@pytest.fixture
def ctx(monkeypatch):
    from app.core import staff_session
    monkeypatch.setattr(staff_session, "kv_get", lambda k: None)
    monkeypatch.setattr(staff_session, "kv_put", lambda *a, **k: None)
    session = StaffSession()
    app = SimpleNamespace(staff_session=session, submit_offline_mutation=Mock(return_value={"ok": True}),
                          _api=Mock(), after=Mock())
    return SimpleNamespace(app=app, body=lambda: {"opKind": "edit", "targetId": 1, "payload": {}},
                           send_json=Mock())


def enable(ctx, staff=None):
    api = SimpleNamespace(get_staff_current=lambda **kw: {
        "staffLoginEnabled": True, "agent": staff, "token": "staff" if staff else None,
    }, set_staff_cookie=lambda t: None)
    ctx.app.staff_session.poll_once(api, "gym")


def test_mutation_blocked_without_agent_when_switch_on(ctx):
    enable(ctx)
    routes._handle_member_mutation(ctx)
    assert ctx.send_json.call_args.args == (403, {"ok": False, "code": "NO_AGENT", "permission": "ACTIVE_MEMBERSHIP_UPDATE"})
    ctx.app.submit_offline_mutation.assert_not_called()


def test_mutation_allowed_when_switch_off(ctx):
    routes._handle_member_mutation(ctx)
    assert ctx.send_json.call_args.args == (200, {"ok": True})
    ctx.app.submit_offline_mutation.assert_called_once()


def test_renew_offline_returns_503(ctx, monkeypatch):
    enable(ctx, {"id": 1, "name": "Sami", "adminAgent": True})
    import access.store
    monkeypatch.setattr(access.store, "load_auth_token", lambda: SimpleNamespace(token="gym"))
    ctx.app._api.return_value.renew.side_effect = MonClubApiError("unreachable")
    routes._handle_staff_renew(ctx)
    assert ctx.send_json.call_args.args[0] == 503
    assert ctx.send_json.call_args.args[1]["code"] == "OFFLINE"


def test_renew_conflict_body_passes_through(ctx, monkeypatch):
    enable(ctx, {"id": 1, "name": "Sami", "adminAgent": True})
    import access.store
    monkeypatch.setattr(access.store, "load_auth_token", lambda: SimpleNamespace(token="gym"))
    ctx.app._api.return_value.renew.side_effect = MonClubApiConflictError(
        "debt changed", body='{"code":"RENEWAL_DEBT_CHANGED","details":{"amount":40}}')
    routes._handle_staff_renew(ctx)
    assert ctx.send_json.call_args.args == (409, {"code": "RENEWAL_DEBT_CHANGED", "details": {"amount": 40}})
    ctx.app.after.assert_not_called()


@pytest.mark.parametrize("handler", [routes._handle_staff_renew, routes._handle_staff_pay_rest, routes._handle_staff_payment_details])
def test_new_online_routes_require_switch_on(ctx, handler):
    handler(ctx)
    assert ctx.send_json.call_args.args[0] == 403
    ctx.app._api.assert_not_called()


@pytest.mark.parametrize("allowed", [False, True])
def test_pending_fingerprint_rechecks_permission_after_capture(ctx, monkeypatch, allowed):
    """Run the real worker with a fake scanner; never import the native UI/SDKs."""
    import ast
    import base64
    import threading
    import time
    from pathlib import Path
    source = Path("app/ui/app.py").read_text(encoding="utf-8")
    main = next(n for n in ast.parse(source).body if isinstance(n, ast.ClassDef) and n.name == "MainApp")
    method = next(n for n in main.body if isinstance(n, ast.FunctionDef) and n.name == "_remote_enroll_worker")
    persist = Mock()
    scanner = Mock()
    scanner.enroll_3_samples.return_value = b"fingerprint-test"
    scope = {"Optional": __import__("typing").Optional, "time": time, "_tel": Mock(),
             "load_auth_token": lambda: SimpleNamespace(token="gym"), "ZKFinger": lambda *a, **kw: scanner,
             "_encoding_to_backend": lambda v: "BASE64", "to_b64": lambda b: base64.b64encode(b).decode(),
             "insert_offline_subresource": persist}
    exec(compile(ast.Module(body=[method], type_ignores=[]), "app/ui/app.py", "exec"), scope)
    activity = Mock()
    monkeypatch.setattr(routes, "_staff_activity", activity)
    ctx.app.staff_session = SimpleNamespace(has_permission=lambda *p: allowed)
    app = SimpleNamespace(staff_session=ctx.app.staff_session, logger=Mock(), _restriction_reasons=lambda: [],
        _find_user_membership=lambda uid: (-1, {"offlinePendingLocalId": "pending"}),
        cfg=SimpleNamespace(zkfp_dll_path="", template_version=10, template_encoding="base64"),
        _enroll_cancel_event=threading.Event(), _enroll_state_lock=threading.Lock())
    scope["_remote_enroll_worker"](app, 1, 0, "Member", "zk9500", active_membership_id_override=-1)
    if allowed:
        persist.assert_called_once()
        activity.assert_called_once_with(app)
        assert app._last_enroll_outcome["outcome"] == "ok_deferred_offline"
    else:
        persist.assert_not_called()
        activity.assert_not_called()
        assert app._last_enroll_outcome["outcome"] != "ok_deferred_offline"

from copy import deepcopy

import pytest


class StaffApi:
    def __init__(self, data):
        self.data = data
        self.cookie = None

    def get_staff_current(self, token):
        return deepcopy(self.data)

    def set_staff_cookie(self, token):
        self.cookie = token


def current(staff_id=1, permissions=()):
    return {"staffLoginEnabled": True, "agent": {
        "id": staff_id, "name": f"Staff {staff_id}", "adminAgent": False,
        "permissions": list(permissions), "since": "2026-10-31T08:02:00",
    }, "token": "access-token", "allowedAgents": [], "version": staff_id}


@pytest.fixture
def session(monkeypatch):
    from app.core import staff_session
    memory = {}
    monkeypatch.setattr(staff_session, "kv_get", memory.get)
    monkeypatch.setattr(staff_session, "kv_put", lambda k, v, **kw: memory.__setitem__(k, v))
    monkeypatch.setattr(staff_session, "kv_delete", lambda k: memory.pop(k, None))
    monkeypatch.setattr(staff_session, "protect_auth_token", lambda t: "protected:" + t)
    return staff_session.StaffSession()


def test_no_cookie_when_switch_off(session):
    import logging
    import requests
    from app.api.monclub_api import ApiEndpoints, MonClubApi
    api = MonClubApi(ApiEndpoints("https://api.example.test/api/v1/login", "", "", ""), logging.getLogger(__name__))
    api.data = current()
    api.get_staff_current = lambda **kw: deepcopy(api.data)
    session.poll_once(api, "gym")
    request = requests.Request("POST", "https://api.example.test/api/v1/gym/activeMembership/renew")
    assert api._session.prepare_request(request).headers["Cookie"] == "currentAgentId=access-token"
    api.data = {"staffLoginEnabled": False, "agent": None, "token": None, "allowedAgents": []}
    session.poll_once(api, "gym")
    assert "Cookie" not in api._session.prepare_request(request).headers
    assert session.require("ANY") == (True, None)
    assert session.snapshot()["enabled"] is False


def test_require_no_agent(session):
    data = current()
    data.update(agent=None, token=None)
    session.poll_once(StaffApi(data), "gym")
    assert session.require("ACTIVE_MEMBERSHIP_MANAGEMENT") == (False, "NO_AGENT")


def test_require_missing_permission(session):
    session.poll_once(StaffApi(current(permissions=["ACTIVE_MEMBERSHIP_RENEWAL"])), "gym")
    assert session.require("ACTIVE_MEMBERSHIP_MANAGEMENT", "ACTIVE_MEMBERSHIP_RENEWAL") == (False, "MISSING_PERMISSION")
    assert session.has_permission("ACTIVE_MEMBERSHIP_RENEWAL")


def test_agent_change_sets_changed_at(session):
    api = StaffApi(current())
    session.poll_once(api, "gym")
    api.data = current(2)
    session.poll_once(api, "gym")
    snapshot = session.snapshot()
    assert snapshot["changedAt"]
    assert snapshot["previousAgentName"] == "Staff 1"
    session.poll_once(api, "gym")
    assert session.snapshot()["changedAt"] == snapshot["changedAt"]


def test_network_failure_keeps_snapshot_and_cookie(session):
    api = StaffApi(current())
    session.poll_once(api, "gym")
    before = session.snapshot()
    def fail(**kw):
        raise ConnectionError("offline")
    api.get_staff_current = fail
    session.poll_once(api, "gym")
    assert session.snapshot() == before
    assert api.cookie == "access-token"


def test_logout_during_poll_does_not_restore_session(session):
    api = StaffApi(current())
    session.poll_once(api, "gym")
    def logout(**kw):
        session.clear(api)
        return current()
    api.get_staff_current = logout
    session.poll_once(api, "gym")
    assert session.snapshot()["agent"] is None
    assert api.cookie is None


def test_token_persisted_protected_and_not_in_public_snapshot(session):
    from app.core import staff_session
    session.poll_once(StaffApi(current()), "gym")
    assert staff_session.kv_get("staff_session")["token"] == "protected:access-token"
    assert "token" not in session.snapshot()


def test_poll_cannot_install_a_session_for_a_replaced_gym_login(session):
    api = StaffApi(current())
    session._is_token_current = lambda token: False
    session.poll_once(api, "previous-gym-login")
    assert session.snapshot()["agent"] is None
    assert api.cookie is None

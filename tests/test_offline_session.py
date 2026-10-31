from copy import deepcopy
from types import SimpleNamespace

import pytest


CODE = {"salt": "AAECAwQFBgcICQoLDA0ODw==", "hash": "cwVZgBnjhRJbt6z5DHQfL+rcp/HlWAk8G2vvHVhn0Rc=", "iterations": 210000}


@pytest.fixture
def offline(monkeypatch):
    from app.core import offline_session
    memory = {}
    monkeypatch.setattr(offline_session, "kv_get", memory.get)
    monkeypatch.setattr(offline_session, "kv_put", lambda k, v, **kw: memory.__setitem__(k, deepcopy(v)))
    staff = SimpleNamespace(snapshot=lambda: {"enabled": True, "allowedAgents": [
        {"id": 1, "name": "Amira", "permissions": ["EDIT"]},
        {"id": 2, "name": "Sami", "permissions": ["RENEW"]}]},
        offline_config=lambda: {"doorLimit": 20, "moneyLimit": 10, "code": CODE})
    return offline_session.OfflineSession(staff)


def test_offline_code_known_vector(offline):
    assert offline.unlock("482913")["ok"]
    assert offline.unlock("482914")["code"] == "WRONG"


def test_five_wrong_codes_lock_five_minutes(offline, monkeypatch):
    from app.core import offline_session
    now = [1000.0]
    monkeypatch.setattr(offline_session.time, "time", lambda: now[0])
    for remaining in (4, 3, 2, 1):
        assert offline.unlock("111111")["remaining"] == remaining
    assert offline.unlock("111111") == {"ok": False, "code": "LOCKED", "seconds": 300}
    restarted = offline_session.OfflineSession(offline._staff)
    assert restarted.unlock("482913")["code"] == "LOCKED"
    now[0] += 300
    assert restarted.unlock("482913")["ok"]


def test_act_as_uses_that_agent_permissions(offline):
    assert offline.require("EDIT") == (False, "OFFLINE_LOCKED")
    offline.unlock("482913")
    assert offline.act_as(1)["ok"]
    assert offline.require("EDIT") == (True, None)
    assert offline.require("RENEW") == (False, "MISSING_PERMISSION")
    offline.act_as(2)
    assert offline.require("EDIT") == (False, "MISSING_PERMISSION")
    offline.relock()
    assert offline.require("RENEW") == (False, "OFFLINE_LOCKED")


def test_limit_counts_per_day(offline, monkeypatch, tmp_path):
    from app.core import db, offline_session
    monkeypatch.setattr(db, "_DB_PATH", str(tmp_path / "usage.db"))
    with db.get_conn() as conn:
        conn.execute("CREATE TABLE offline_pending_actions (category TEXT, local_day TEXT)")
        conn.executemany("INSERT INTO offline_pending_actions VALUES (?, ?)", [
            ("DOOR", "2026-10-30"), ("MONEY", "2026-10-31"), ("DOOR", "2026-10-31")])
        conn.commit()
    monkeypatch.setattr(offline_session, "local_day", lambda: "2026-10-31")
    assert offline.limits() == {"door": {"used": 1, "max": 20}, "money": {"used": 1, "max": 10}}


def test_verifier_cached_protected_and_not_in_status(monkeypatch):
    from app.core import staff_session
    memory = {}
    monkeypatch.setattr(staff_session, "kv_get", memory.get)
    monkeypatch.setattr(staff_session, "kv_put", lambda k, v, **kw: memory.__setitem__(k, v))
    monkeypatch.setattr(staff_session, "protect_auth_token", lambda v: "sealed:" + v)
    monkeypatch.setattr(staff_session, "unprotect_auth_token", lambda v: v.removeprefix("sealed:"))
    api = SimpleNamespace(get_staff_current=lambda **kw: {"staffLoginEnabled": True, "agent": None,
        "allowedAgents": [], "offline": {"code": CODE, "doorLimit": 20, "moneyLimit": 10}},
        set_staff_cookie=lambda v: None)
    session = staff_session.StaffSession()
    session.poll_once(api, "gym")
    assert "code" not in str(memory["staff_session"]["snapshot"])
    assert memory["staff_session"]["offline"].startswith("sealed:")
    assert staff_session.StaffSession().offline_config()["code"] == CODE

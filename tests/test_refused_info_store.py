from __future__ import annotations

import importlib
import threading

import pytest


@pytest.fixture
def store(tmp_path, monkeypatch):
    from app.core import db
    monkeypatch.setattr(db, "_DB_PATH", str(tmp_path / "refused.db"))
    db.init_db()
    from app.core import refused_info
    module = importlib.reload(refused_info)
    yield module
    db._shutdown_db_writer_for_tests()


def row(user=7, account=42, cards=None, name="A"):
    return dict(userId=user, accountId=account, activeMembershipId=900 + user,
                fullName=name, image=None, cardIds=cards or ["111"], planTitle="Annuel",
                reasonCode="MEMBERSHIP_EXPIRED", reasonDate="2026-10-15")


def payload(*rows):
    return dict(generatedAt="2026-10-31T12:00:00", since="2025-10-31", rows=list(rows))


def table_rows():
    from app.core import db
    with db.get_conn() as conn:
        return [tuple(r) for r in conn.execute("SELECT * FROM refused_directory")]


def test_heartbeat_true_turns_on_and_persists(store):
    store.on_heartbeat_response({"refusedInfoEnabled": True})
    assert store.is_enabled() is True
    from app.core import db
    with db.get_conn() as conn:
        assert conn.execute("SELECT enabled FROM refused_info_state WHERE id=1").fetchone()[0] == 1
    assert importlib.reload(store).is_enabled() is True


@pytest.mark.parametrize("response", [{}, {"refusedInfoEnabled": False}, {"refusedInfoEnabled": None}, {"refusedInfoEnabled": 1}])
def test_heartbeat_missing_or_false_turns_off(store, response):
    store.set_enabled(True)
    store.on_heartbeat_response(response)
    assert store.is_enabled() is False


def test_refresh_builds_index_by_card_and_account(store, monkeypatch):
    store.set_enabled(True)
    monkeypatch.setattr(store, "_fetch_directory", lambda: payload(row(), row(8, 43, ["222"], "B")))
    assert store.refresh_directory()
    assert store.current_index().by_card["111"].full_name == "A"
    assert store.current_index().by_account[42].user_id == 7
    assert len(table_rows()) == 2
    assert importlib.reload(store).is_enabled()
    assert store.current_index().by_card["111"].full_name == "A"


def test_card_shared_by_two_users_is_marked_collision(store, monkeypatch):
    store.set_enabled(True)
    monkeypatch.setattr(store, "_fetch_directory", lambda: payload(row(cards=["999"]), row(8, 43, ["999"])))
    assert store.refresh_directory()
    assert store.current_index().by_card["999"] is None


@pytest.mark.parametrize("failure", ["network", "500", "json", "shape"])
def test_refresh_failure_keeps_previous_table_and_index(store, monkeypatch, failure):
    store.set_enabled(True)
    monkeypatch.setattr(store, "_fetch_directory", lambda: payload(row()))
    assert store.refresh_directory()
    before, rows = store.current_index(), table_rows()
    def fail():
        if failure == "shape":
            return {"rows": [{}]}
        raise ValueError(failure)
    monkeypatch.setattr(store, "_fetch_directory", fail)
    assert store.refresh_directory() is False
    assert store.current_index() is before
    assert table_rows() == rows


def test_switch_off_clears_table_and_index(store, monkeypatch):
    store.set_enabled(True)
    monkeypatch.setattr(store, "_fetch_directory", lambda: payload(row()))
    assert store.refresh_directory()
    store.set_enabled(False)
    assert store.current_index() is None
    assert table_rows() == []


def test_switch_off_during_refresh_never_swaps_in(store, monkeypatch):
    store.set_enabled(True)
    fetching, release = threading.Event(), threading.Event()
    def fetch():
        fetching.set()
        assert release.wait(5)
        return payload(row())
    monkeypatch.setattr(store, "_fetch_directory", fetch)
    thread = threading.Thread(target=store.refresh_directory)
    thread.start()
    assert fetching.wait(5)
    store.set_enabled(False)
    release.set()
    thread.join(5)
    assert not thread.is_alive()
    assert store.current_index() is None
    assert table_rows() == []


def test_refresh_waits_for_running_writer_outcome(store, monkeypatch):
    from app.core import db
    store.set_enabled(True)
    monkeypatch.setattr(store, "_fetch_directory", lambda: payload(row()))
    original = db._run_db_write_sync
    running, release = threading.Event(), threading.Event()
    def delayed(label, operation, **kwargs):
        def write(conn, profile):
            running.set()
            assert release.wait(5)
            return operation(conn, profile)
        return original(label, write, **kwargs)
    monkeypatch.setattr(db, "_DB_WRITE_WAIT_TIMEOUT_SEC", 0.02)
    monkeypatch.setattr(db, "_run_db_write_sync", delayed)
    results = []
    thread = threading.Thread(target=lambda: results.append(store.refresh_directory()))
    thread.start()
    try:
        assert running.wait(5)
        thread.join(0.1)
        assert thread.is_alive(), "refresh reported an outcome before the running transaction finished"
    finally:
        release.set()
        thread.join(5)
    assert results == [True]
    assert len(table_rows()) == 1
    assert store.current_index().by_card["111"].full_name == "A"


def test_disabled_never_fetches(store, monkeypatch):
    def unexpected():
        raise AssertionError("disabled fetch")
    monkeypatch.setattr(store, "_fetch_directory", unexpected)
    assert store.refresh_directory() is False


def test_unreadable_switch_defaults_off(store, monkeypatch):
    from app.core import db
    monkeypatch.setattr(store, "_enabled", None)
    def unreadable():
        raise RuntimeError("unreadable database")
    monkeypatch.setattr(db, "get_conn", unreadable)
    assert store.is_enabled() is False
    assert store.current_index() is None


def test_http_helper_uses_gym_token_and_timeout(store, monkeypatch):
    from app.api.monclub_api import MonClubApi
    from app.core import db
    from types import SimpleNamespace
    from app.core.app_const import API_REFUSED_DIRECTORY_URL
    calls = []
    monkeypatch.setattr(db, "load_auth_token", lambda: SimpleNamespace(token="gym-token"))
    def get(self, **kwargs):
        calls.append(kwargs)
        return payload(row())
    monkeypatch.setattr(MonClubApi, "_get_json_dict", get)
    store.set_enabled(True)
    assert store.refresh_directory()
    assert calls[0]["url"] == API_REFUSED_DIRECTORY_URL
    assert calls[0]["token"] == "gym-token"
    assert calls[0]["timeout"] == 30


@pytest.mark.parametrize("failure", ["network", "500", "json"])
def test_http_failure_keeps_previous_table_and_index(store, monkeypatch, failure):
    from app.api.monclub_api import MonClubApi
    from app.core import db
    from types import SimpleNamespace
    store.set_enabled(True)
    with monkeypatch.context() as m:
        m.setattr(store, "_fetch_directory", lambda: payload(row()))
        assert store.refresh_directory()
    before, saved = store.current_index(), table_rows()
    monkeypatch.setattr(db, "load_auth_token", lambda: SimpleNamespace(token="gym-token"))
    def get(*args, **kwargs):
        if failure == "network":
            raise OSError("offline")
        def bad_json():
            raise ValueError("bad JSON")
        return SimpleNamespace(status_code=500 if failure == "500" else 200,
                               text="invalid", json=bad_json)
    monkeypatch.setattr("requests.Session.get", get)
    assert not store.refresh_directory()
    assert store.current_index() is before
    assert table_rows() == saved


@pytest.mark.parametrize("raises", [False, True])
def test_pc_identity_heartbeat_handler_is_isolated(store, raises):
    from access.pc_identity import PcIdentityService, PcCredentials
    from tests.test_pc_identity import _MemoryStore, _ServiceApi
    from unittest.mock import Mock
    api = _ServiceApi()
    api.send_heartbeat = Mock(return_value={"refusedInfoEnabled": True})
    handler = Mock(side_effect=RuntimeError("handler") if raises else store.on_heartbeat_response)
    service = PcIdentityService(credential_store=_MemoryStore(PcCredentials("u", "s")),
                               api_client=api, gym_token_provider=lambda: "gym-token",
                               heartbeat_response_handler=handler)
    assert service.heartbeat_once()
    handler.assert_called_once_with({"refusedInfoEnabled": True})
    assert service.status()["state"] == "active"

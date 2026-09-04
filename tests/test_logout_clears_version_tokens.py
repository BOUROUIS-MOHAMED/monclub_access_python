"""POST /api/v2/auth/logout must clear the sync version tokens together with the cache.

WHY THIS FILE EXISTS
--------------------
``_handle_auth_logout`` (app/api/local_access_api_v2.py) wipes the cached sync tables
through ``save_sync_cache(None)`` -- sync_users, sync_devices,
sync_gym_access_credentials (the TOTP secrets) and five more -- but until 2026-09-04 it
never called ``clear_version_tokens()``. The login that follows schedules a sync with
hint ``{"reason": "AUTH_LOGIN"}``, which ``apply_trigger_hint_to_version_tokens`` leaves
untouched, so the next request re-sent the OLD credentialsVersion / devicesVersion and
the backend answered refreshCredentials=false / refreshDevices=false: the emptied tables
never refilled. Members were rescued only by SYNC-HEAL, which needs the stored
membersVersion to claim >= 50 members -- a smaller gym stayed at an empty roster.

Every test patches ``app.core.db._DB_PATH`` to a temp file. Nothing here may touch the
real ``C:\\ProgramData\\MonClub Access\\access\\access.db``.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "test.db"), raising=False)
    db_module.init_db()
    yield db_module
    if hasattr(db_module, "_shutdown_db_writer_for_tests"):
        db_module._shutdown_db_writer_for_tests()


@pytest.fixture(autouse=True)
def _no_tv_side_effects(monkeypatch):
    """The handler mirrors the logout into the TV store; keep that off the real disk."""
    import tv.auth_bridge as bridge

    cleared = MagicMock()
    monkeypatch.setattr(bridge, "clear_tv_auth_bridge_state", cleared)
    return cleared


# The membersVersion encodes "<memberCount>:<maxUpdated>:<fpCount>:<maxFpUpdated>"
# (sync_scope.member_count_from_token). 12 members is below the SYNC-HEAL floor of 50,
# i.e. exactly the gym size the heal cannot rescue.
_TOKENS = {
    "membersVersion": "12:2026-09-01T10:00:00:3:2026-08-30T09:00:00",
    "devicesVersion": "2:2026-08-01T00:00:00",
    "credentialsVersion": "12:2026-08-15T00:00:00",
    "settingsVersion": "2026-07-01T00:00:00",
    "membersUpdatedAfter": "2026-09-01T10:00:00",
}


def _user(am_id: int, user_id: int) -> dict:
    return {
        "activeMembershipId": am_id,
        "userId": user_id,
        "membershipId": 50,
        "fullName": f"Member {user_id}",
        "phone": "0600000000",
        "email": f"m{user_id}@example.com",
        "validFrom": "2026-01-01",
        "validTo": "2026-12-31",
        "firstCardId": str(1000 + user_id),
        "secondCardId": None,
        "image": None,
        "fingerprints": [],
    }


def _credential(*, cred_id: int, account_id: int) -> dict:
    return {
        "id": cred_id,
        "gymId": 58,
        "accountId": account_id,
        "secretHex": "abc123",
        "enabled": True,
        "rotatedAt": "2026-04-01T00:00:00",
        "createdAt": "2026-04-01T00:00:00",
        "updatedAt": "2026-04-01T00:00:00",
        "grantedActiveMembershipIds": [account_id],
    }


def _seed_logged_in_state(db) -> None:
    db.save_version_tokens(_TOKENS)
    data = {
        "users": [_user(1, 100), _user(2, 200)],
        "membersDeltaMode": False,
        "validMemberIds": None,
        "devices": [
            {"id": 7, "name": "Entree", "ipAddress": "192.168.1.201", "accessDataMode": "ULTRA"},
        ],
        "gymAccessCredentials": [_credential(cred_id=1, account_id=100)],
        "infrastructures": [],
        "membership": [],
        "contractStatus": True,
        "contractEndDate": "2026-12-31",
        "accessSoftwareSettings": {},
    }
    db.save_sync_cache_delta(
        data, {"members": True, "devices": True, "credentials": True, "settings": False}
    )


def _counts(db) -> dict:
    with db.get_conn() as conn:
        return {
            table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in ("sync_users", "sync_gym_access_credentials", "sync_devices")
        }


def _fake_ctx():
    sent: list = []
    app = SimpleNamespace(
        after=MagicMock(),
        stop_realtime_agent=MagicMock(),
        logger=MagicMock(),
        _update_manager=SimpleNamespace(stop=MagicMock()),
        evaluate_access_and_redirect=MagicMock(),
    )
    ctx = SimpleNamespace(app=app, send_json=lambda status, payload: sent.append((status, payload)))
    return ctx, sent


def test_seed_is_meaningful(db):
    """Guard for the tests below: the seeded state must have something to lose."""
    _seed_logged_in_state(db)
    assert db.load_version_tokens() == _TOKENS
    assert _counts(db) == {"sync_users": 2, "sync_gym_access_credentials": 1, "sync_devices": 1}


def test_logout_clears_tokens_and_the_three_tables(db, _no_tv_side_effects):
    import app.api.local_access_api_v2 as v2

    _seed_logged_in_state(db)
    ctx, sent = _fake_ctx()

    v2._handle_auth_logout(ctx)

    assert db.load_version_tokens() == {}
    assert _counts(db) == {"sync_users": 0, "sync_gym_access_credentials": 0, "sync_devices": 0}
    assert sent == [(200, {"ok": True})]
    _no_tv_side_effects.assert_called_once_with()
    ctx.app.stop_realtime_agent.assert_called_once_with()


def test_logout_keeps_member_shadow(db):
    """member_shadow holds content hashes; it must survive so the shadow diff after
    re-login only flags members that really changed."""
    import app.api.local_access_api_v2 as v2

    _seed_logged_in_state(db)
    db.upsert_member_shadow(users=[_user(1, 100)])
    ctx, _sent = _fake_ctx()

    v2._handle_auth_logout(ctx)

    with db.get_conn() as conn:
        assert int(conn.execute("SELECT COUNT(*) FROM member_shadow").fetchone()[0]) == 1


def test_pre_fix_hole_a_cache_wipe_alone_leaves_tokens_that_would_be_sent(db):
    """Documents the defect: `save_sync_cache(None)` (all the old handler did) empties the
    tables but keeps the tokens; the AUTH_LOGIN hint strips nothing; SYNC-HEAL cannot fire
    for a 12-member gym; and the request builder would put the stale
    credentialsVersion/devicesVersion on the wire, so the backend would answer
    "no refresh" for tables that are empty."""
    from app.api.monclub_api import MonClubApi, MonClubApiError
    from app.core.sync_scope import apply_trigger_hint_to_version_tokens, member_cache_is_stale

    _seed_logged_in_state(db)

    db.save_sync_cache(None)  # the pre-fix logout

    assert _counts(db) == {"sync_users": 0, "sync_gym_access_credentials": 0, "sync_devices": 0}
    stale_tokens = db.load_version_tokens()
    assert stale_tokens == _TOKENS

    hinted = apply_trigger_hint_to_version_tokens(stale_tokens, {"reason": "AUTH_LOGIN"})
    assert hinted is not None
    assert hinted["credentialsVersion"] == _TOKENS["credentialsVersion"]
    assert hinted["devicesVersion"] == _TOKENS["devicesVersion"]
    # The member self-heal needs >= 50 members in the token: it does not rescue this gym.
    assert member_cache_is_stale(0, hinted["membersVersion"]) is False

    captured = _capture_sync_request_params(MonClubApi, MonClubApiError, hinted)
    assert captured["credentialsVersion"] == _TOKENS["credentialsVersion"]
    assert captured["devicesVersion"] == _TOKENS["devicesVersion"]
    assert captured["membersVersion"] == _TOKENS["membersVersion"]


def test_after_the_fix_the_post_login_sync_carries_no_version_tokens(db):
    """The only thing that stops the stale tokens from being sent is the handler
    clearing them: after logout the request has no version keys at all, so the
    backend performs a full refresh of every section."""
    import app.api.local_access_api_v2 as v2
    from app.api.monclub_api import MonClubApi, MonClubApiError
    from app.core.sync_scope import apply_trigger_hint_to_version_tokens

    _seed_logged_in_state(db)
    ctx, _sent = _fake_ctx()
    v2._handle_auth_logout(ctx)

    hinted = apply_trigger_hint_to_version_tokens(db.load_version_tokens(), {"reason": "AUTH_LOGIN"})
    assert hinted is None

    captured = _capture_sync_request_params(MonClubApi, MonClubApiError, hinted)
    assert set(captured) == {"lastCheckTimeStamp"}


def test_logout_is_loud_but_still_completes_when_token_clear_fails(db, monkeypatch):
    """A failure to clear the tokens must not break logout, and must not be silent."""
    import app.api.local_access_api_v2 as v2

    _seed_logged_in_state(db)

    def _boom():
        raise RuntimeError("disk on fire")

    monkeypatch.setattr("app.core.db.clear_version_tokens", _boom)
    ctx, sent = _fake_ctx()

    v2._handle_auth_logout(ctx)

    assert sent == [(200, {"ok": True})]
    assert _counts(db) == {"sync_users": 0, "sync_gym_access_credentials": 0, "sync_devices": 0}
    assert ctx.app.logger.warning.called
    assert any(
        "ersion" in str(call.args[0]) for call in ctx.app.logger.warning.call_args_list
    ), "the token-clear failure must be named in the warning"


def test_dead_duplicate_logout_paths_are_gone():
    """force_login / clear_auth were the intended fix (they did clear the tokens) but had
    zero callers; the API handler is now the single logout path."""
    import app.ui.app as app_module

    assert not hasattr(app_module.MainApp, "force_login")
    assert not hasattr(app_module.MainApp, "clear_auth")


# --------------------------------------------------------------------------- helpers

def _capture_sync_request_params(MonClubApi, MonClubApiError, version_tokens):
    """Drive the real request builder (`MonClubApi.get_sync_data`) against a session
    that records the query params and refuses to go on the network."""

    class _Refused(Exception):
        pass

    captured: dict = {}

    class _Session:
        def get(self, url, params=None, headers=None, timeout=None):
            captured.update(dict(params or {}))
            raise _Refused("no network in tests")

    api = MonClubApi.__new__(MonClubApi)
    api.endpoints = SimpleNamespace(
        sync_url="https://backend.example/manager/gym/access/v1/getSyncData"
    )
    api.logger = MagicMock()
    api._session = _Session()

    with pytest.raises(MonClubApiError):
        api.get_sync_data(token="jwt", version_tokens=version_tokens)
    return captured

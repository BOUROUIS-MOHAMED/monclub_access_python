"""Access v5 Card P (Profil): the session window and role read from the stored JWT, and the
gym name from GET /manager/access/v1/gym/me cached in auth_state, all exposed on /status."""
from __future__ import annotations

import base64
import json
import logging
from contextlib import ExitStack, contextmanager
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import app.core.db as dbmod
from app.api import local_access_api_v2
from app.core import gym_info
from shared.auth_state import jwt_account_role, jwt_session_window, read_jwt_claims


def _b64url(obj) -> str:
    raw = obj if isinstance(obj, bytes) else json.dumps(obj).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwt(claims: dict) -> str:
    return f"{_b64url({'alg': 'HS256'})}.{_b64url(claims)}.c2lnbmF0dXJl"


# 2026-10-01T00:00:00Z and 2026-10-31T00:00:00Z (a 30-day token, the backend default).
IAT = 1790812800
EXP = 1793404800
GYM_TOKEN = _jwt({"roles": ["ROLE_GYM"], "esv": 1, "sub": "gym@club.tn", "iat": IAT, "exp": EXP})


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "profile.db"), raising=False)
    dbmod._shutdown_db_writer_for_tests()
    dbmod.init_db()
    yield dbmod
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


# ================================================================ JWT claims (display only)
def test_claims_are_read_from_an_unpadded_base64url_payload() -> None:
    claims = read_jwt_claims(GYM_TOKEN)
    assert claims["roles"] == ["ROLE_GYM"] and claims["iat"] == IAT and claims["exp"] == EXP


@pytest.mark.parametrize("token", [
    "", "abc", "a.b", "a.b.c.d", "x.!!!.y",
    f"h.{_b64url(b'not json')}.s",
    f"h.{_b64url([1, 2])}.s",
])
def test_a_token_that_is_not_a_jwt_object_reads_as_none(token) -> None:
    assert read_jwt_claims(token) is None
    assert jwt_session_window(token) == (None, None)
    assert jwt_account_role(token) is None


def test_the_window_is_iat_and_exp_in_utc_with_an_offset() -> None:
    assert jwt_session_window(GYM_TOKEN) == ("2026-10-01T00:00:00+00:00", "2026-10-31T00:00:00+00:00")


@pytest.mark.parametrize("bad", [None, "1793404800", True, [1]])
def test_a_missing_or_non_numeric_claim_is_none_not_guessed(bad) -> None:
    issued, expires = jwt_session_window(_jwt({"iat": IAT, "exp": bad}))
    assert issued == "2026-10-01T00:00:00+00:00" and expires is None


@pytest.mark.parametrize("roles, want", [
    (["ROLE_GYM"], "GYM"),
    (["ROLE_ADMIN"], "ADMIN"),
    (["GYM"], "GYM"),
    ([], None),
    (["ROLE_GYM", "ROLE_ADMIN"], None),
    ("ROLE_GYM", None),
    ([7], None),
])
def test_the_role_needs_exactly_one_role_claim(roles, want) -> None:
    assert jwt_account_role(_jwt({"roles": roles})) == want


# ================================================================ gym name cache (auth_state)
def test_init_db_twice_keeps_the_gym_name_columns(db) -> None:
    db.init_db()
    with db.get_conn() as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(auth_state)").fetchall()}
    assert {"gym_name", "gym_name_email"} <= cols


def test_the_gym_name_is_returned_only_for_the_email_it_was_fetched_for(db) -> None:
    db.save_auth_token(email="gym@club.tn", token=GYM_TOKEN)
    db.save_gym_name(email="gym@club.tn", gym_name="Oxyfit Lac")
    assert db.load_gym_name("gym@club.tn") == "Oxyfit Lac"
    assert db.load_gym_name("GYM@Club.tn") == "Oxyfit Lac"
    assert db.load_gym_name("other@club.tn") is None
    assert db.load_gym_name("") is None


def test_a_token_refresh_keeps_the_cached_name(db) -> None:
    db.save_auth_token(email="gym@club.tn", token=GYM_TOKEN)
    db.save_gym_name(email="gym@club.tn", gym_name="Oxyfit Lac")
    db.save_auth_token(email="gym@club.tn", token=_jwt({"iat": IAT + 10}))
    assert db.load_gym_name("gym@club.tn") == "Oxyfit Lac"


def test_logout_drops_the_name_and_a_late_fetch_does_not_recreate_the_row(db) -> None:
    db.save_auth_token(email="gym@club.tn", token=GYM_TOKEN)
    db.save_gym_name(email="gym@club.tn", gym_name="Oxyfit Lac")
    db.clear_auth_token()
    db.save_gym_name(email="gym@club.tn", gym_name="Oxyfit Lac")
    with db.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) FROM auth_state").fetchone()[0] == 0
    assert db.load_gym_name("gym@club.tn") is None


def test_an_empty_name_reads_as_none(db) -> None:
    db.save_auth_token(email="gym@club.tn", token=GYM_TOKEN)
    db.save_gym_name(email="gym@club.tn", gym_name="Oxyfit Lac")
    db.save_gym_name(email="gym@club.tn", gym_name="")
    assert db.load_gym_name("gym@club.tn") is None


@pytest.mark.parametrize("body, want", [
    ({"name": "Oxyfit Lac", "enabled": True}, "Oxyfit Lac"),
    ({"name": "  Oxyfit Lac  "}, "Oxyfit Lac"),
    ({"name": "N/A", "enabled": False, "contract_end_date": None}, ""),
    ({"name": ""}, ""),
    ({"name": None}, ""),
    ({}, ""),
    (["Oxyfit"], ""),
])
def test_the_name_of_a_gym_me_answer(body, want) -> None:
    assert gym_info.gym_name_from_answer(body) == want


@pytest.mark.parametrize("body, want", [
    ({"name": "Oxyfit Lac", "account_name": " Sami Ben Ali "}, "Sami Ben Ali"),
    ({"name": "Oxyfit Lac", "account_name": None}, ""),
    ({"name": "Oxyfit Lac"}, ""),  # a backend before Card P2
    ({"account_name": 12}, ""),
    (["x"], ""),
])
def test_the_account_name_of_a_gym_me_answer(body, want) -> None:
    assert gym_info.account_name_from_answer(body) == want


def test_the_account_name_is_cached_with_the_gym_name_for_the_same_email(db) -> None:
    db.save_auth_token(email="gym@club.tn", token=GYM_TOKEN)
    db.save_gym_name(email="gym@club.tn", gym_name="Oxyfit Lac", account_name="Sami Ben Ali")
    assert db.load_account_name("gym@club.tn") == "Sami Ben Ali"
    assert db.load_account_name("other@club.tn") is None
    db.save_gym_name(email="gym@club.tn", gym_name="Oxyfit Lac")  # no account_name: cleared
    assert db.load_account_name("gym@club.tn") is None
    assert db.load_gym_name("gym@club.tn") == "Oxyfit Lac"


def test_init_db_adds_the_account_name_column(db) -> None:
    with db.get_conn() as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(auth_state)").fetchall()}
    assert "account_name" in cols


# ================================================================ the refresher
class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _Api:
    def __init__(self, answer) -> None:
        self.answer = answer
        self.calls = []

    def get_gym_me(self, *, token, timeout):
        self.calls.append((token, timeout))
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def _refresher(api, clock):
    return gym_info.GymNameRefresher(api_factory=lambda: api, logger=logging.getLogger("t"),
                                     clock=clock, start_thread=lambda fn: fn())


def test_nothing_is_fetched_when_logged_out(db) -> None:
    api = _Api({"name": "Oxyfit Lac"})
    assert _refresher(api, _Clock()).maybe_refresh() is False
    assert api.calls == []


def test_the_first_online_sync_fetches_and_caches_the_name(db) -> None:
    db.save_auth_token(email="gym@club.tn", token=GYM_TOKEN)
    api = _Api({"name": "Oxyfit Lac", "enabled": True})
    assert _refresher(api, _Clock()).maybe_refresh() is True
    assert api.calls == [(GYM_TOKEN, gym_info.REQUEST_TIMEOUT_SEC)]
    assert db.load_gym_name("gym@club.tn") == "Oxyfit Lac"


def test_the_refresher_stores_the_account_name_and_an_old_backend_leaves_none(db) -> None:
    db.save_auth_token(email="gym@club.tn", token=GYM_TOKEN)
    api, clock = _Api({"name": "Oxyfit Lac", "account_name": "Sami Ben Ali"}), _Clock()
    r = _refresher(api, clock)
    r.maybe_refresh()
    assert db.load_account_name("gym@club.tn") == "Sami Ben Ali"
    api.answer = {"name": "Oxyfit Lac", "enabled": True, "contract_end_date": None}
    r.reset()
    r.maybe_refresh()
    assert db.load_account_name("gym@club.tn") is None
    assert db.load_gym_name("gym@club.tn") == "Oxyfit Lac"


def test_after_an_answer_the_next_fetch_waits_an_hour(db) -> None:
    db.save_auth_token(email="gym@club.tn", token=GYM_TOKEN)
    api, clock = _Api({"name": "Oxyfit Lac"}), _Clock()
    r = _refresher(api, clock)
    assert r.maybe_refresh() is True
    clock.now += gym_info.SUCCESS_INTERVAL_SEC - 1
    assert r.maybe_refresh() is False
    clock.now += 1
    assert r.maybe_refresh() is True
    assert len(api.calls) == 2


def test_a_transport_failure_retries_after_five_minutes_and_keeps_the_old_name(db) -> None:
    from app.api.monclub_api import MonClubApiError

    db.save_auth_token(email="gym@club.tn", token=GYM_TOKEN)
    db.save_gym_name(email="gym@club.tn", gym_name="Oxyfit Lac")
    api, clock = _Api(MonClubApiError("offline")), _Clock()
    r = _refresher(api, clock)
    assert r.maybe_refresh() is True
    assert db.load_gym_name("gym@club.tn") == "Oxyfit Lac"
    clock.now += gym_info.RETRY_INTERVAL_SEC - 1
    assert r.maybe_refresh() is False
    clock.now += 1
    assert r.maybe_refresh() is True


def test_an_http_refusal_waits_the_full_hour_and_touches_nothing_else(db) -> None:
    from app.api.monclub_api import MonClubApiHttpError

    db.save_auth_token(email="gym@club.tn", token=GYM_TOKEN)
    api, clock = _Api(MonClubApiHttpError("gym/me: HTTP 401", status_code=401)), _Clock()
    r = _refresher(api, clock)
    assert r.maybe_refresh() is True
    assert db.load_auth_token() is not None  # no logout, no token change
    clock.now += gym_info.RETRY_INTERVAL_SEC
    assert r.maybe_refresh() is False
    clock.now += gym_info.SUCCESS_INTERVAL_SEC
    assert r.maybe_refresh() is True


def test_an_account_without_a_gym_clears_the_cached_name(db) -> None:
    db.save_auth_token(email="admin@monclub.tn", token=_jwt({"roles": ["ROLE_ADMIN"]}))
    db.save_gym_name(email="admin@monclub.tn", gym_name="Old Gym")
    _refresher(_Api({"name": "N/A", "enabled": False, "contract_end_date": None}), _Clock()).maybe_refresh()
    assert db.load_gym_name("admin@monclub.tn") is None


def test_a_new_login_fetches_at_once_despite_the_throttle(db) -> None:
    db.save_auth_token(email="gym@club.tn", token=GYM_TOKEN)
    api, clock = _Api({"name": "Oxyfit Lac"}), _Clock()
    r = _refresher(api, clock)
    assert r.maybe_refresh() is True
    db.save_auth_token(email="other@club.tn", token=GYM_TOKEN)
    api.answer = {"name": "Oxyfit Marsa"}
    assert r.maybe_refresh() is True
    assert db.load_gym_name("other@club.tn") == "Oxyfit Marsa"
    assert db.load_gym_name("gym@club.tn") is None


def test_one_fetch_at_a_time(db) -> None:
    db.save_auth_token(email="gym@club.tn", token=GYM_TOKEN)
    started = []
    r = gym_info.GymNameRefresher(api_factory=lambda: _Api({"name": "x"}), logger=logging.getLogger("t"),
                                  clock=_Clock(), start_thread=started.append)
    assert r.maybe_refresh() is True
    db.save_auth_token(email="other@club.tn", token=GYM_TOKEN)
    assert r.maybe_refresh() is False  # still in flight, even for a new login
    started[0]()
    assert r.maybe_refresh() is True


def test_logging_back_in_with_the_same_email_fetches_at_the_next_online_sync(db) -> None:
    db.save_auth_token(email="gym@club.tn", token=GYM_TOKEN)
    api, clock = _Api({"name": "Oxyfit Lac"}), _Clock()
    r = _refresher(api, clock)
    assert r.maybe_refresh() is True
    db.clear_auth_token()  # logout drops the cached name with the row
    r.reset()
    db.save_auth_token(email="gym@club.tn", token=GYM_TOKEN)
    r.reset()
    assert db.load_gym_name("gym@club.tn") is None
    assert r.maybe_refresh() is True  # not throttled for an hour
    assert db.load_gym_name("gym@club.tn") == "Oxyfit Lac"


def test_a_fetch_in_flight_at_reset_does_not_rearm_the_throttle(db) -> None:
    db.save_auth_token(email="gym@club.tn", token=GYM_TOKEN)
    started = []
    r = gym_info.GymNameRefresher(api_factory=lambda: _Api({"name": "Oxyfit Lac"}), logger=logging.getLogger("t"),
                                  clock=_Clock(), start_thread=started.append)
    assert r.maybe_refresh() is True
    r.reset()
    started[0]()  # the old fetch finishes after the reset
    assert r.maybe_refresh() is True


def test_the_login_and_logout_handlers_reset_the_refresh_and_never_fail_on_it() -> None:
    import inspect

    calls = []
    local_access_api_v2._reset_gym_name_refresh(SimpleNamespace(_gym_name_refresher=SimpleNamespace(
        reset=lambda: calls.append(1))))
    local_access_api_v2._reset_gym_name_refresh(SimpleNamespace())  # no refresher: no error
    assert calls == [1]
    for handler in (local_access_api_v2._handle_auth_login, local_access_api_v2._handle_auth_logout):
        src = inspect.getsource(handler)
        assert "_reset_gym_name_refresh(ctx.app)" in src, handler.__name__


# ================================================================ MonClubApi.get_gym_me
class _Resp:
    def __init__(self, status, body=None, text=""):
        self.status_code = status
        self._body = body
        self.text = text

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class _Session:
    def __init__(self, answer):
        self.answer = answer
        self.calls = []

    def get(self, url, headers=None, timeout=None):
        self.calls.append((url, dict(headers or {}), timeout))
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def _real_api(answer):
    from app.api.monclub_api import ApiEndpoints, MonClubApi

    api = MonClubApi(ApiEndpoints(login_url="https://api.example.test/api/v1/public/access/v1/gym/login",
                                  sync_url="", create_user_fingerprint_url="", latest_release_url=""),
                     logging.getLogger("t"))
    api._session = _Session(answer)
    return api


def test_get_gym_me_calls_the_manager_route_with_the_gym_token() -> None:
    api = _real_api(_Resp(200, {"name": "Oxyfit Lac", "enabled": True, "contract_end_date": "2026-12-31"}))
    assert api.get_gym_me(token="jwt", timeout=7)["name"] == "Oxyfit Lac"
    url, headers, timeout = api._session.calls[0]
    assert url == "https://api.example.test/api/v1/manager/access/v1/gym/me"
    assert headers["Authorization"] == "Bearer jwt" and timeout == 7


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_get_gym_me_raises_with_the_status_on_a_non_200(status) -> None:
    from app.api.monclub_api import MonClubApiHttpError

    with pytest.raises(MonClubApiHttpError) as err:
        _real_api(_Resp(status, text="nope")).get_gym_me(token="jwt")
    assert err.value.status_code == status


@pytest.mark.parametrize("answer", [_Resp(200, ValueError("bad")), _Resp(200, ["x"]), OSError("down")])
def test_get_gym_me_raises_on_a_bad_body_or_a_transport_failure(answer) -> None:
    from app.api.monclub_api import MonClubApiError, MonClubApiHttpError

    with pytest.raises(MonClubApiError) as err:
        _real_api(answer).get_gym_me(token="jwt")
    assert not isinstance(err.value, MonClubApiHttpError)


# ================================================================ /status session block
class _StatusApp:
    def __init__(self) -> None:
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

    def _compute_expiry_warnings(self) -> dict:
        return {}

    def get_access_mode_summary(self) -> dict:
        return {"DEVICE": 0, "AGENT": 0, "ULTRA": 0, "UNKNOWN": 0}


@contextmanager
def _status_deps(auth):
    with ExitStack() as stack:
        stack.enter_context(patch("access.store.load_auth_token", return_value=auth))
        stack.enter_context(patch("app.core.db.load_sync_contract_meta", return_value={}))
        stack.enter_context(patch("app.core.db.list_sync_devices_payload", return_value=[]))
        stack.enter_context(patch.object(
            local_access_api_v2, "_build_update_status_payload",
            return_value={
                "updateAvailable": False, "downloaded": False, "downloading": False,
                "progress": None, "progressPercent": None, "currentReleaseId": None,
                "lastCheckAt": None, "lastError": None,
            },
        ))
        yield


def test_status_exposes_the_token_window_role_and_cached_gym_name(db) -> None:
    db.save_auth_token(email="gym@club.tn", token=GYM_TOKEN)
    db.save_gym_name(email="gym@club.tn", gym_name="Oxyfit Lac")
    auth = SimpleNamespace(email="gym@club.tn", token=GYM_TOKEN, last_login_at="2026-10-01T01:00:00")
    with _status_deps(auth):
        payload = local_access_api_v2._build_status_payload_uncached(_StatusApp())
    s = payload["session"]
    assert s["sessionIssuedAt"] == "2026-10-01T00:00:00+00:00"
    assert s["sessionExpiresAt"] == "2026-10-31T00:00:00+00:00"
    assert s["accountRole"] == "GYM"
    assert s["gymName"] == "Oxyfit Lac"
    assert s["accountName"] is None  # nobody set it: Profil falls back to the e-mail prefix
    assert s["email"] == "gym@club.tn"
    # The token (or any part of it) is never on the wire.
    wire = json.dumps(payload, default=str)
    assert GYM_TOKEN not in wire and GYM_TOKEN.split(".")[1] not in wire


def test_status_fields_are_null_when_logged_out_or_unreadable(db) -> None:
    with _status_deps(None):
        s = local_access_api_v2._build_status_payload_uncached(_StatusApp())["session"]
    assert (s["sessionIssuedAt"], s["sessionExpiresAt"], s["accountRole"], s["gymName"]) == (None, None, None, None)

    auth = SimpleNamespace(email="gym@club.tn", token="opaque-not-a-jwt", last_login_at="")
    with _status_deps(auth):
        s = local_access_api_v2._build_status_payload_uncached(_StatusApp())["session"]
    assert (s["sessionIssuedAt"], s["sessionExpiresAt"], s["accountRole"], s["gymName"]) == (None, None, None, None)


def test_status_exposes_the_cached_account_name(db) -> None:
    db.save_auth_token(email="gym@club.tn", token=GYM_TOKEN)
    db.save_gym_name(email="gym@club.tn", gym_name="Oxyfit Lac", account_name="Sami Ben Ali")
    auth = SimpleNamespace(email="gym@club.tn", token=GYM_TOKEN, last_login_at="")
    with _status_deps(auth):
        s = local_access_api_v2._build_status_payload_uncached(_StatusApp())["session"]
    assert s["accountName"] == "Sami Ben Ali"
    with _status_deps(None):
        s = local_access_api_v2._build_status_payload_uncached(_StatusApp())["session"]
    assert s["accountName"] is None

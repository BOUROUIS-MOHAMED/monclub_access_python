"""Access v5 Card P (Profil): the session window read from the stored JWT, exposed on /status."""
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
from shared.auth_state import jwt_session_window, read_jwt_claims


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


def test_the_window_is_iat_and_exp_in_utc_with_an_offset() -> None:
    assert jwt_session_window(GYM_TOKEN) == ("2026-10-01T00:00:00+00:00", "2026-10-31T00:00:00+00:00")


@pytest.mark.parametrize("bad", [None, "1793404800", True, [1]])
def test_a_missing_or_non_numeric_claim_is_none_not_guessed(bad) -> None:
    issued, expires = jwt_session_window(_jwt({"iat": IAT, "exp": bad}))
    assert issued == "2026-10-01T00:00:00+00:00" and expires is None


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


def test_status_exposes_the_token_window(db) -> None:
    db.save_auth_token(email="gym@club.tn", token=GYM_TOKEN)
    auth = SimpleNamespace(email="gym@club.tn", token=GYM_TOKEN, last_login_at="2026-10-01T01:00:00")
    with _status_deps(auth):
        payload = local_access_api_v2._build_status_payload_uncached(_StatusApp())
    s = payload["session"]
    assert s["sessionIssuedAt"] == "2026-10-01T00:00:00+00:00"
    assert s["sessionExpiresAt"] == "2026-10-31T00:00:00+00:00"
    assert s["email"] == "gym@club.tn"
    # The token (or any part of it) is never on the wire.
    wire = json.dumps(payload, default=str)
    assert GYM_TOKEN not in wire and GYM_TOKEN.split(".")[1] not in wire


def test_status_fields_are_null_when_logged_out_or_unreadable(db) -> None:
    with _status_deps(None):
        s = local_access_api_v2._build_status_payload_uncached(_StatusApp())["session"]
    assert (s["sessionIssuedAt"], s["sessionExpiresAt"]) == (None, None)

    auth = SimpleNamespace(email="gym@club.tn", token="opaque-not-a-jwt", last_login_at="")
    with _status_deps(auth):
        s = local_access_api_v2._build_status_payload_uncached(_StatusApp())["session"]
    assert (s["sessionIssuedAt"], s["sessionExpiresAt"]) == (None, None)

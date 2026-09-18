"""The optional-content scheduler must send the bearer token string, not the stored object.

``load_auth_token()`` returns an ``AuthTokenState`` dataclass. The scheduler used to hand the
whole object to ``MonClubApi.get_optional_content_sync(token=...)``, which formats
``f"Bearer {token}"`` — so the header carried the dataclass repr (email, access token and
refresh token in clear) and the backend could never authenticate it.

These tests drive the real ``MonClubApi`` with a fake HTTP session and assert on the header
and body that would actually go on the wire. The header tests patch every database call; the
version-marker tests use the documented ``_DB_PATH`` temp-database override. Neither touches
the installed database.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

from app.api.monclub_api import ApiEndpoints, MonClubApi
from app.core import optional_content_sync as ocs
from shared.auth_state import AuthTokenState

_AUTH = AuthTokenState(
    email="owner@example.test",
    token="access-token-123",
    last_login_at="2026-09-18 08:00:00",
    refresh_token="refresh-secret-456",
    next_refresh_at="2026-09-18T09:00:00Z",
)


class _FakeResponse:
    status_code = 200
    text = "{}"

    @staticmethod
    def json() -> Dict[str, Any]:
        return {"refreshEvents": False, "refreshProducts": False, "refreshDeals": False}


class _RecordingSession:
    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []

    def post(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append({"url": url, **kwargs})
        return _FakeResponse()


def _run_one_cycle(auth: Any) -> _RecordingSession:
    session = _RecordingSession()
    api = MonClubApi(
        endpoints=ApiEndpoints(
            login_url="https://example.test/api/v1/login",
            sync_url="https://example.test/api/v1/sync",
            create_user_fingerprint_url="",
            latest_release_url="",
            optional_content_sync_url="https://example.test/content/sync",
        ),
        logger=MagicMock(),
    )
    api._session = session
    with (
        patch("app.core.db.load_auth_token", return_value=auth),
        patch("access.config.build_access_api_endpoints", return_value=SimpleNamespace()),
        patch("app.api.monclub_api.MonClubApi", return_value=api),
        patch("app.core.db.delete_passed_optional_events"),
        patch("app.core.db.get_optional_sync_state", return_value={}),
        patch("app.core.db.replace_optional_events"),
        patch("app.core.db.replace_optional_products"),
        patch("app.core.db.replace_optional_deals"),
        patch("app.core.db.save_optional_sync_state"),
    ):
        ocs.OptionalContentSyncScheduler()._sync_once()
    return session


def test_authorization_header_is_the_bearer_token_string() -> None:
    session = _run_one_cycle(_AUTH)

    assert len(session.calls) == 1
    assert session.calls[0]["headers"]["Authorization"] == "Bearer access-token-123"


def test_authorization_header_never_carries_the_refresh_token_or_the_object_repr() -> None:
    header = _run_one_cycle(_AUTH).calls[0]["headers"]["Authorization"]

    assert "refresh-secret-456" not in header
    assert "AuthTokenState" not in header
    assert "owner@example.test" not in header


def test_no_stored_token_makes_no_request() -> None:
    assert _run_one_cycle(None).calls == []


# ── Version markers round-trip through the real database ────────────────────────────
#
# Uses the documented ``_DB_PATH`` temp-database override. The scheduler used to read the
# state row with keys the row does not have (``events_last_version_at``) and to call
# ``save_optional_sync_state`` with keyword names it does not accept, so the markers were
# never read, never saved (a swallowed TypeError), and every cycle re-downloaded every section.


class _ScriptedSession:
    def __init__(self, replies: List[Dict[str, Any]]) -> None:
        self.replies = list(replies)
        self.bodies: List[Dict[str, Any]] = []

    def post(self, url: str, **kwargs: Any) -> Any:
        self.bodies.append(dict(kwargs["json"]))
        reply = self.replies.pop(0)
        return SimpleNamespace(status_code=200, text="{}", json=lambda: reply)


def _real_db_cycle(session: _ScriptedSession) -> None:
    api = MonClubApi(
        endpoints=ApiEndpoints(
            login_url="https://example.test/api/v1/login",
            sync_url="https://example.test/api/v1/sync",
            create_user_fingerprint_url="",
            latest_release_url="",
            optional_content_sync_url="https://example.test/content/sync",
        ),
        logger=MagicMock(),
    )
    api._session = session
    with (
        patch("app.core.db.load_auth_token", return_value=_AUTH),
        patch("access.config.build_access_api_endpoints", return_value=SimpleNamespace()),
        patch("app.api.monclub_api.MonClubApi", return_value=api),
    ):
        ocs.OptionalContentSyncScheduler()._sync_once()


def test_version_markers_are_saved_and_sent_back_on_the_next_cycle(tmp_path, monkeypatch) -> None:
    import app.core.db as db_module

    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "optional.db"), raising=False)
    db_module.init_db()

    session = _ScriptedSession([
        {
            "refreshEvents": True, "refreshProducts": True, "refreshDeals": True,
            "eventsVersionAt": "2026-09-18#e1", "productsVersionAt": "p1", "dealsVersionAt": "d1",
            "events": [], "products": [], "deals": [],
        },
        {
            "refreshEvents": True, "refreshProducts": False, "refreshDeals": False,
            "eventsVersionAt": "2026-09-18#e2", "events": [],
        },
        {"refreshEvents": False, "refreshProducts": False, "refreshDeals": False},
    ])

    _real_db_cycle(session)
    state = db_module.get_optional_sync_state()
    assert (state["events_version_at"], state["products_version_at"], state["deals_version_at"]) == (
        "2026-09-18#e1", "p1", "d1",
    )
    assert state["last_sync_at"]

    _real_db_cycle(session)
    _real_db_cycle(session)

    assert session.bodies[0] == {}
    assert session.bodies[1] == {
        "eventsLastVersionAt": "2026-09-18#e1",
        "productsLastVersionAt": "p1",
        "dealsLastVersionAt": "d1",
    }
    # Only the events marker moved; the unchanged sections kept theirs.
    assert session.bodies[2] == {
        "eventsLastVersionAt": "2026-09-18#e2",
        "productsLastVersionAt": "p1",
        "dealsLastVersionAt": "d1",
    }


def test_a_section_that_failed_to_store_keeps_its_old_marker(tmp_path, monkeypatch) -> None:
    import app.core.db as db_module

    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "optional.db"), raising=False)
    db_module.init_db()
    session = _ScriptedSession([
        {
            "refreshEvents": True, "refreshProducts": True, "refreshDeals": False,
            "eventsVersionAt": "e1", "productsVersionAt": "p1", "events": [], "products": [],
        },
        {"refreshEvents": False, "refreshProducts": False, "refreshDeals": False},
    ])

    with patch("app.core.db.replace_optional_products", side_effect=RuntimeError("disk full")):
        _real_db_cycle(session)
    _real_db_cycle(session)

    # events stored -> marker advanced; products failed -> asked for again next cycle.
    assert session.bodies[1] == {"eventsLastVersionAt": "e1"}

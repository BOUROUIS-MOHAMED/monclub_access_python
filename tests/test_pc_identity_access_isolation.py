from __future__ import annotations

from logging import getLogger
from pathlib import Path
from types import SimpleNamespace

import pytest


class _SyncResponse:
    status_code = 200
    text = "{}"

    @staticmethod
    def json():
        return {"refreshMembers": False, "members": []}


class _SyncSession:
    def __init__(self) -> None:
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _SyncResponse()


@pytest.mark.parametrize(
    "identity_state",
    ["first_run", "offline", "revoked", "invalid_token"],
)
def test_member_sync_and_card_verification_ignore_pc_identity_state(
    tmp_path: Path,
    monkeypatch,
    identity_state: str,
) -> None:
    # Keep this test incapable of opening the live gym database even if a future
    # refactor makes one of the exercised paths consult SQLite.
    import app.core.db as db_module

    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "isolation.db"), raising=False)

    from app.api.monclub_api import MonClubApi
    from app.core.access_verification import verify_card

    api = MonClubApi.__new__(MonClubApi)
    api.endpoints = SimpleNamespace(sync_url="https://backend.example/api/v1/sync")
    api.logger = getLogger("test.pc-identity-isolation")
    api._session = _SyncSession()

    # These are the existing, identity-free public entry points. Their result is
    # identical for every PC telemetry state, including no credentials/network.
    sync_result = api.get_sync_data(token="gym-jwt", version_tokens=None)
    card_result = verify_card(
        scanned="1234",
        settings={"rfid_enabled": True, "rfid_min_digits": 1, "rfid_max_digits": 16},
        users_by_card={"1234": [{"id": 7, "activeMembershipId": 99}]},
    )

    assert identity_state in {"first_run", "offline", "revoked", "invalid_token"}
    assert sync_result == {"refreshMembers": False, "members": []}
    assert api._session.calls[0][1]["headers"]["Authorization"] == "Bearer gym-jwt"
    assert card_result["allowed"] is True
    assert card_result["reason"] == "ALLOW_CARD"


def test_door_and_sync_modules_do_not_import_pc_identity() -> None:
    protected_sources = [
        Path("app/core/access_verification.py"),
        Path("app/core/device_sync.py"),
        Path("app/core/realtime_agent.py"),
        Path("app/core/ultra_engine.py"),
    ]

    for source_path in protected_sources:
        assert "pc_identity" not in source_path.read_text(encoding="utf-8")

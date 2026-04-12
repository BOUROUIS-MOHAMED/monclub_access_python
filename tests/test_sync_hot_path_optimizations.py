from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import threading


def _fail_full_cache(*args, **kwargs):
    raise AssertionError("full sync cache load should not be used on this hot path")


def test_get_access_mode_summary_uses_direct_device_payload(monkeypatch):
    import app.ui.app as app_module

    app = SimpleNamespace()

    monkeypatch.setattr(app_module, "load_sync_cache", _fail_full_cache)
    monkeypatch.setattr(
        "app.core.db.list_sync_devices_payload",
        lambda: [
            {"id": 1, "accessDataMode": "DEVICE"},
            {"id": 2, "access_data_mode": "ULTRA"},
            {"id": 3, "accessDataMode": "AGENT"},
            {"id": 4, "accessDataMode": "mystery"},
        ],
    )

    summary = app_module.MainApp.get_access_mode_summary(app)

    assert summary == {"DEVICE": 1, "AGENT": 1, "ULTRA": 1, "UNKNOWN": 1}


def test_restriction_reasons_uses_contract_meta_snapshot(monkeypatch):
    import app.ui.app as app_module

    app = SimpleNamespace(
        cfg=SimpleNamespace(max_login_age_minutes=43200),
        logger=MagicMock(),
    )

    monkeypatch.setattr(
        app_module,
        "load_auth_token",
        lambda: SimpleNamespace(token="jwt", last_login_at="2026-04-10T09:00:00Z"),
    )
    monkeypatch.setattr(app_module, "load_sync_cache", _fail_full_cache)
    monkeypatch.setattr(
        "app.core.db.load_sync_contract_meta",
        lambda: {
            "contractStatus": False,
            "contractEndDate": "2026-04-01",
            "updatedAt": "2026-04-10T09:00:00Z",
        },
    )

    reasons = app_module.MainApp._restriction_reasons(app)

    assert "Contract inactive (status=false from backend)." in reasons
    assert any("Contract expired" in reason for reason in reasons)


def test_sync_cache_user_handlers_use_direct_queries(monkeypatch):
    from app.api import local_access_api_v2 as api_module

    sent: list[tuple[int, dict]] = []
    ctx = SimpleNamespace(
        q_int=lambda *args, default=0: default,
        send_json=lambda status, payload: sent.append((status, payload)),
    )

    monkeypatch.setattr("access.store.load_sync_cache", _fail_full_cache)
    monkeypatch.setattr("app.core.db.list_sync_users", lambda: [{"activeMembershipId": 11}])
    monkeypatch.setattr("app.core.db.list_sync_memberships", lambda: [{"id": 7, "title": "Gold"}])

    api_module._handle_sync_cache_users(ctx)
    api_module._handle_sync_cache_memberships(ctx)

    assert sent == [
        (200, {"users": [{"activeMembershipId": 11}], "total": 1}),
        (200, {"memberships": [{"id": 7, "title": "Gold"}]}),
    ]


def test_status_payload_uses_direct_contract_and_device_snapshots(monkeypatch):
    from app.api import local_access_api_v2 as api_module

    class _App:
        _sync_work_running = False
        _last_sync_at = None
        _last_sync_ok = True
        _last_sync_error = None
        _last_device_sync_at = None
        _last_device_sync_ok = True
        _last_device_sync_error = None
        _agent_engine = None
        _ultra_engine = None

        def _restriction_reasons(self) -> list[str]:
            return []

        def _compute_expiry_warnings(self) -> dict[str, object]:
            return {}

        def get_access_mode_summary(self) -> dict[str, int]:
            return {"DEVICE": 0, "AGENT": 0, "ULTRA": 2, "UNKNOWN": 0}

    monkeypatch.setattr("access.store.load_auth_token", lambda: SimpleNamespace(
        token="jwt",
        email="person@example.com",
        last_login_at="2026-04-10T09:00:00Z",
    ))
    monkeypatch.setattr("access.store.load_sync_cache", _fail_full_cache)
    monkeypatch.setattr(
        "app.core.db.load_sync_contract_meta",
        lambda: {
            "contractStatus": True,
            "contractEndDate": "2026-06-30",
            "updatedAt": "2026-04-12T00:56:28Z",
        },
    )
    monkeypatch.setattr(
        "app.core.db.list_sync_devices_payload",
        lambda: [
            {"id": 5, "name": "Door 1", "accessDataMode": "ULTRA"},
            {"id": 6, "name": "Door 2", "accessDataMode": "ULTRA"},
        ],
    )
    monkeypatch.setattr(
        api_module,
        "_build_update_status_payload",
        lambda app: {
            "updateAvailable": False,
            "downloaded": False,
            "downloading": False,
            "progress": None,
            "progressPercent": None,
            "currentReleaseId": None,
            "lastCheckAt": None,
            "lastError": None,
        },
    )

    payload = api_module._build_status_payload(_App())

    assert payload["session"]["contractStatus"] is True
    assert payload["session"]["contractEndDate"] == "2026-06-30"
    assert payload["sync"]["lastSyncAt"] == "2026-04-12T00:56:28Z"
    assert payload["mode"] == {"DEVICE": 0, "AGENT": 0, "ULTRA": 2, "UNKNOWN": 0}


def test_member_shadow_delta_path_skips_full_diff(monkeypatch):
    import app.ui.app as app_module

    upserted = []
    deleted = []
    app = SimpleNamespace(logger=MagicMock())

    monkeypatch.setattr(
        "app.core.db.diff_member_shadow",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("full shadow diff should be skipped in delta mode")),
    )
    monkeypatch.setattr("app.core.db.list_member_shadow_deleted_ids", lambda *, valid_member_ids: [77])
    monkeypatch.setattr("app.core.db.upsert_member_shadow", lambda *, users: upserted.extend(users))
    monkeypatch.setattr(
        "app.core.db.delete_member_shadow",
        lambda *, active_membership_ids: deleted.extend(active_membership_ids),
    )

    changed_ids = app_module.MainApp._apply_member_shadow_sync(
        app,
        data={
            "membersDeltaMode": True,
            "users": [{"activeMembershipId": 5, "fullName": "Updated User"}],
            "validMemberIds": [5],
        },
        refresh={"members": True},
        delta_changed_ids={5},
    )

    assert changed_ids == {5}
    assert upserted == [{"activeMembershipId": 5, "fullName": "Updated User"}]
    assert deleted == [77]


def test_request_running_ultra_sync_delegates_delta_ids():
    import app.ui.app as app_module

    request_sync_now = MagicMock()
    app = SimpleNamespace(
        _ultra_lock=threading.Lock(),
        _ultra_engine=SimpleNamespace(running=True, request_sync_now=request_sync_now),
        logger=MagicMock(),
    )

    started = app_module.MainApp._request_running_ultra_sync(
        app,
        refresh={"members": True, "devices": False},
        changed_ids={42},
        reason="SYNC_NOW_API",
    )

    assert started is True
    request_sync_now.assert_called_once_with(changed_ids={42}, reason="sync_now_api")


def test_request_running_ultra_sync_preserves_deletion_only_delta():
    import app.ui.app as app_module

    request_sync_now = MagicMock()
    app = SimpleNamespace(
        _ultra_lock=threading.Lock(),
        _ultra_engine=SimpleNamespace(running=True, request_sync_now=request_sync_now),
        logger=MagicMock(),
    )

    started = app_module.MainApp._request_running_ultra_sync(
        app,
        refresh={"members": True, "devices": False},
        changed_ids=set(),
        reason="CHANGE_DETECTOR",
    )

    assert started is True
    request_sync_now.assert_called_once_with(changed_ids=set(), reason="change_detector")

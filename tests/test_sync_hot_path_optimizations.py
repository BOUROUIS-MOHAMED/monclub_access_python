from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import threading
import time


def _fail_full_cache(*args, **kwargs):
    raise AssertionError("full sync cache load should not be used on this hot path")


def test_get_access_mode_summary_uses_direct_device_payload(monkeypatch):
    import app.ui.app as app_module

    app = SimpleNamespace()

    monkeypatch.setattr("app.core.db.peek_sync_cache", lambda: None)
    monkeypatch.setattr(app_module, "load_sync_cache", _fail_full_cache)
    monkeypatch.setattr(
        "app.core.db.load_sync_device_mode_summary",
        lambda: {"DEVICE": 1, "AGENT": 1, "ULTRA": 1, "UNKNOWN": 1},
    )

    summary = app_module.MainApp.get_access_mode_summary(app)

    assert summary == {"DEVICE": 1, "AGENT": 1, "ULTRA": 1, "UNKNOWN": 1}


def test_get_access_mode_summary_prefers_cached_sync_snapshot(monkeypatch):
    import app.ui.app as app_module

    app = SimpleNamespace()
    cache = SimpleNamespace(
        devices=[
            {"id": 5, "accessDataMode": "ULTRA"},
            {"id": 6, "access_data_mode": "DEVICE"},
            {"id": 7, "accessDataMode": "AGENT"},
            {"id": 8, "accessDataMode": "mystery"},
        ]
    )

    monkeypatch.setattr("app.core.db.peek_sync_cache", lambda: cache)
    monkeypatch.setattr(
        "app.core.db.load_sync_device_mode_summary",
        lambda: (_ for _ in ()).throw(AssertionError("db mode summary should not be used when cache exists")),
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
    monkeypatch.setattr("app.core.db.peek_sync_cache", lambda: None)
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


def test_restriction_reasons_prefers_cached_sync_snapshot(monkeypatch):
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
    monkeypatch.setattr(
        "app.core.db.peek_sync_cache",
        lambda: SimpleNamespace(
            contract_status=False,
            contract_end_date="2026-04-01",
        ),
    )
    monkeypatch.setattr(
        "app.core.db.load_sync_contract_meta",
        lambda: (_ for _ in ()).throw(AssertionError("contract snapshot DB lookup should not be used when cache exists")),
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
    monkeypatch.setattr(
        "app.core.db.list_sync_users_page",
        lambda *, limit=0, offset=0: ([{"activeMembershipId": 11}], 1),
    )
    monkeypatch.setattr("app.core.db.list_sync_memberships", lambda: [{"id": 7, "title": "Gold"}])

    api_module._handle_sync_cache_users(ctx)
    api_module._handle_sync_cache_memberships(ctx)

    assert sent == [
        (200, {"users": [{"activeMembershipId": 11}], "total": 1}),
        (200, {"memberships": [{"id": 7, "title": "Gold"}]}),
    ]


def test_sync_cache_meta_uses_direct_counts(monkeypatch):
    from app.api import local_access_api_v2 as api_module

    sent: list[tuple[int, dict]] = []
    ctx = SimpleNamespace(
        send_json=lambda status, payload: sent.append((status, payload)),
    )

    monkeypatch.setattr("access.store.load_sync_cache", _fail_full_cache)
    monkeypatch.setattr(
        "app.core.db.load_sync_contract_meta",
        lambda: {
            "contractStatus": True,
            "contractEndDate": "2026-12-31",
            "updatedAt": "2026-04-12T00:56:28Z",
        },
    )
    monkeypatch.setattr("app.core.db.list_sync_users", _fail_full_cache)
    monkeypatch.setattr("app.core.db.list_sync_devices_payload", _fail_full_cache)
    monkeypatch.setattr("app.core.db.list_sync_memberships", _fail_full_cache)
    monkeypatch.setattr("app.core.db.list_sync_infrastructures", _fail_full_cache)
    monkeypatch.setattr("app.core.db.list_sync_gym_access_credentials", _fail_full_cache)
    monkeypatch.setattr("app.core.db.count_sync_users", lambda: 1277)
    monkeypatch.setattr("app.core.db.count_sync_devices", lambda: 2)
    monkeypatch.setattr("app.core.db.count_sync_memberships", lambda: 9)
    monkeypatch.setattr("app.core.db.count_sync_infrastructures", lambda: 1)
    monkeypatch.setattr("app.core.db.count_sync_gym_access_credentials", lambda: 1277)

    api_module._handle_sync_cache_meta(ctx)

    assert sent == [(
        200,
        {
            "hasSyncData": True,
            "contractStatus": True,
            "contractEndDate": "2026-12-31",
            "lastSyncAt": "2026-04-12T00:56:28Z",
            "userCount": 1277,
            "deviceCount": 2,
            "membershipCount": 9,
            "infrastructureCount": 1,
            "credentialCount": 1277,
        },
    )]


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
    monkeypatch.setattr("app.core.db.list_sync_devices_payload", _fail_full_cache)
    monkeypatch.setattr(
        "app.core.db.load_sync_device_mode_summary",
        lambda: {"DEVICE": 0, "AGENT": 0, "ULTRA": 2, "UNKNOWN": 0},
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


def test_log_sync_cache_write_profile_logs_profile_when_slow(monkeypatch):
    import app.ui.app as app_module

    logger = MagicMock()
    monkeypatch.setattr(
        "app.core.db.get_last_db_write_profile",
        lambda _label=None: {"queue_wait_ms": 512.0, "commit_ms": 7.0},
    )

    app_module._log_sync_cache_write_profile(logger, 7198)

    logger.info.assert_any_call("[SYNC-DEBUG] local cache write took %dms", 7198)
    logger.info.assert_any_call(
        "[SYNC-DEBUG] local cache write profile=%s",
        {"queue_wait_ms": 512.0, "commit_ms": 7.0},
    )


def test_defer_ultra_reconnects_for_change_detector():
    import app.ui.app as app_module

    defer_reconnects = MagicMock(return_value=2)
    app = SimpleNamespace(
        _ultra_lock=threading.Lock(),
        _ultra_engine=SimpleNamespace(running=True, defer_reconnects=defer_reconnects),
        logger=MagicMock(),
    )

    changed = app_module.MainApp._defer_ultra_reconnects(
        app,
        trigger_source="CHANGE_DETECTOR",
        duration_sec=20.0,
    )

    assert changed == 2
    defer_reconnects.assert_called_once_with(duration_sec=20.0, reason="change_detector")


def test_defer_ultra_reconnects_skips_startup():
    import app.ui.app as app_module

    defer_reconnects = MagicMock()
    app = SimpleNamespace(
        _ultra_lock=threading.Lock(),
        _ultra_engine=SimpleNamespace(running=True, defer_reconnects=defer_reconnects),
        logger=MagicMock(),
    )

    changed = app_module.MainApp._defer_ultra_reconnects(
        app,
        trigger_source="STARTUP",
        duration_sec=20.0,
    )

    assert changed == 0
    defer_reconnects.assert_not_called()


def test_member_shadow_delta_path_skips_full_diff(monkeypatch):
    import app.ui.app as app_module

    app = SimpleNamespace(logger=MagicMock())

    monkeypatch.setattr(
        "app.core.db.diff_member_shadow",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("full shadow diff should be skipped in delta mode")),
    )
    monkeypatch.setattr(
        "app.core.db.apply_member_shadow_delta",
        lambda *, users, valid_member_ids: [77],
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

    assert changed_ids == {5, 77}
    app.logger.info.assert_called_once_with(
        "[ShadowDiff] delta fast-path: changed=%d deleted=%d",
        1,
        1,
    )


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
    request_sync_now.assert_called_once_with(changed_ids={42}, device_ids=None, reason="sync_now_api")


def test_request_running_ultra_sync_skips_empty_member_delta():
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

    assert started is False
    request_sync_now.assert_not_called()


def test_load_sync_cache_returns_stale_snapshot_while_async_refresh_runs(monkeypatch):
    import app.core.db as db_module

    stale = db_module.SyncCacheState(
        contract_status=True,
        contract_end_date="2026-12-31",
        access_software_settings=None,
        users=[],
        membership=[],
        devices=[],
        infrastructures=[],
        gym_access_credentials=[],
        updated_at="stale",
    )
    fresh = db_module.SyncCacheState(
        contract_status=True,
        contract_end_date="2027-01-31",
        access_software_settings=None,
        users=[{"activeMembershipId": 1}],
        membership=[],
        devices=[],
        infrastructures=[],
        gym_access_credentials=[],
        updated_at="fresh",
    )
    started = threading.Event()
    release = threading.Event()

    def _fake_load():
        started.set()
        assert release.wait(timeout=1.0)
        return fresh

    monkeypatch.setattr(db_module, "_load_sync_cache_db", _fake_load)

    with db_module._sync_cache_lock:
        original_entry = db_module._sync_cache_entry
        original_loading = db_module._sync_cache_loading
        db_module._sync_cache_entry = (time.monotonic() + 30.0, stale)
        db_module._sync_cache_loading = None

    try:
        db_module.invalidate_sync_cache()
        result = db_module.load_sync_cache()
        assert result is stale
        assert started.wait(timeout=0.5) is True

        release.set()
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            with db_module._sync_cache_lock:
                _, cached = db_module._sync_cache_entry
                loading = db_module._sync_cache_loading
            if cached is fresh and loading is None:
                break
            time.sleep(0.01)

        with db_module._sync_cache_lock:
            _, cached = db_module._sync_cache_entry
            loading = db_module._sync_cache_loading

        assert cached is fresh
        assert loading is None
    finally:
        with db_module._sync_cache_lock:
            db_module._sync_cache_entry = original_entry
            db_module._sync_cache_loading = original_loading

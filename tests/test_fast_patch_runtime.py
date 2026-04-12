from __future__ import annotations

import threading
from types import SimpleNamespace
from unittest.mock import MagicMock


def test_apply_fast_patch_bundle_invalidates_caches_and_requests_member_ultra_sync(monkeypatch):
    import app.ui.app as app_module

    invalidate = MagicMock()
    monkeypatch.setattr("app.core.db.apply_fast_patch_bundle", lambda bundle: {"applied": 1, "skipped": 0, "ignored": None})
    monkeypatch.setattr("app.core.db.invalidate_sync_cache", invalidate)

    app = SimpleNamespace(
        logger=MagicMock(),
        reset_runtime_fast_patch_caches=MagicMock(),
        _request_running_ultra_sync=MagicMock(return_value=True),
        request_sync_now=MagicMock(),
    )
    bundle = {
        "bundleId": "bundle-1",
        "generatedAt": "2026-04-12T12:00:00Z",
        "requiresReconcile": True,
        "items": [
            {
                "kind": "ENTITY_UPSERT",
                "entityType": "ACTIVE_MEMBERSHIP",
                "entityId": 9,
                "revision": "2026-04-12T12:00:00Z",
                "impact": {"affectedMemberIds": [9], "affectedDeviceIds": [7]},
            }
        ],
    }

    result = app_module.MainApp.apply_fast_patch_bundle(app, bundle)

    assert result == {"ok": True, "applied": 1, "skipped": 0, "ignored": None}
    invalidate.assert_called_once()
    app.reset_runtime_fast_patch_caches.assert_called_once()
    app._request_running_ultra_sync.assert_called_once_with(
        refresh={"members": True, "devices": False},
        changed_ids={9},
        reason="FAST_PATCH_BUNDLE",
    )
    app.request_sync_now.assert_called_once_with(
        trigger_source="FAST_PATCH_BUNDLE",
        run_type="TRIGGERED",
        trigger_hint={"reason": "fast_patch_bundle"},
    )


def test_apply_fast_patch_bundle_requests_device_rescope_sync(monkeypatch):
    import app.ui.app as app_module

    invalidate = MagicMock()
    monkeypatch.setattr("app.core.db.apply_fast_patch_bundle", lambda bundle: {"applied": 1, "skipped": 0, "ignored": None})
    monkeypatch.setattr("app.core.db.invalidate_sync_cache", invalidate)

    app = SimpleNamespace(
        logger=MagicMock(),
        reset_runtime_fast_patch_caches=MagicMock(),
        _request_running_ultra_sync=MagicMock(return_value=True),
        request_sync_now=MagicMock(),
    )
    bundle = {
        "bundleId": "bundle-device",
        "generatedAt": "2026-04-12T12:01:00Z",
        "requiresReconcile": True,
        "items": [
            {
                "kind": "ENTITY_UPSERT",
                "entityType": "GYM_DEVICE",
                "entityId": 7,
                "revision": "2026-04-12T12:01:00Z",
                "impact": {"affectedMemberIds": [], "affectedDeviceIds": [7], "requiresDeviceRescope": True},
            }
        ],
    }

    result = app_module.MainApp.apply_fast_patch_bundle(app, bundle)

    assert result == {"ok": True, "applied": 1, "skipped": 0, "ignored": None}
    invalidate.assert_called_once()
    app._request_running_ultra_sync.assert_called_once_with(
        refresh={"members": False, "devices": True},
        changed_ids=None,
        reason="FAST_PATCH_BUNDLE",
    )


def test_apply_fast_patch_bundle_duplicate_short_circuits_runtime_actions(monkeypatch):
    import app.ui.app as app_module

    invalidate = MagicMock()
    monkeypatch.setattr("app.core.db.apply_fast_patch_bundle", lambda bundle: {"applied": 0, "skipped": 0, "ignored": "duplicate_bundle"})
    monkeypatch.setattr("app.core.db.invalidate_sync_cache", invalidate)

    app = SimpleNamespace(
        logger=MagicMock(),
        reset_runtime_fast_patch_caches=MagicMock(),
        _request_running_ultra_sync=MagicMock(return_value=True),
        request_sync_now=MagicMock(),
    )

    result = app_module.MainApp.apply_fast_patch_bundle(app, {"bundleId": "bundle-dup", "items": []})

    assert result == {"ok": True, "duplicate": True, "applied": 0, "skipped": 0, "ignored": "duplicate_bundle"}
    invalidate.assert_not_called()
    app.reset_runtime_fast_patch_caches.assert_not_called()
    app._request_running_ultra_sync.assert_not_called()
    app.request_sync_now.assert_not_called()


def test_reset_runtime_fast_patch_caches_calls_engine_hooks():
    import app.ui.app as app_module

    agent = SimpleNamespace(reset_fast_patch_caches=MagicMock())
    ultra = SimpleNamespace(reset_fast_patch_caches=MagicMock())
    app = SimpleNamespace(
        _agent_engine=agent,
        _ultra_engine=ultra,
        logger=MagicMock(),
    )

    app_module.MainApp.reset_runtime_fast_patch_caches(app)

    agent.reset_fast_patch_caches.assert_called_once()
    ultra.reset_fast_patch_caches.assert_called_once()


def test_decision_service_reset_fast_patch_caches_clears_hot_state():
    import app.core.realtime_agent as rt_module

    svc = SimpleNamespace(
        _cache_lock=threading.Lock(),
        _creds_cache_at=10.0,
        _creds_cache=[{"accountId": 3}],
        _users_cache_at=12.0,
        _users_by_active_membership_id={9: {"activeMembershipId": 9}},
        _users_by_card={"123": [{"activeMembershipId": 9}]},
    )

    rt_module.DecisionService.reset_fast_patch_caches(svc)

    assert svc._creds_cache == []
    assert svc._creds_cache_at == 0.0
    assert svc._users_by_active_membership_id == {}
    assert svc._users_by_card == {}
    assert svc._users_cache_at == 0.0


def test_agent_realtime_engine_reset_fast_patch_caches_clears_shared_caches():
    import app.core.realtime_agent as rt_module

    decider = SimpleNamespace(reset_fast_patch_caches=MagicMock())
    engine = SimpleNamespace(
        _lock=threading.Lock(),
        _devices_cache_at=5.0,
        _devices_cache=[{"id": 7}],
        _global_cache_at=6.0,
        _global_cache={"access_server_port": 8788},
        _deciders=[decider],
    )

    rt_module.AgentRealtimeEngine.reset_fast_patch_caches(engine)

    assert engine._devices_cache == []
    assert engine._devices_cache_at == 0.0
    assert engine._global_cache == {}
    assert engine._global_cache_at == 0.0
    decider.reset_fast_patch_caches.assert_called_once()


def test_ultra_reset_fast_patch_caches_clears_worker_cache_and_fanout():
    import app.core.ultra_engine as ultra_module

    worker = SimpleNamespace(_cached_state=("creds", "users", "cards"), _cached_state_ts=15.0)
    ultra_module.UltraDeviceWorker.reset_fast_patch_caches(worker)
    assert worker._cached_state is None
    assert worker._cached_state_ts == 0.0

    worker_a = SimpleNamespace(reset_fast_patch_caches=MagicMock())
    worker_b = SimpleNamespace(reset_fast_patch_caches=MagicMock())
    engine = SimpleNamespace(_workers={1: worker_a, 2: worker_b})

    ultra_module.UltraEngine.reset_fast_patch_caches(engine)

    worker_a.reset_fast_patch_caches.assert_called_once()
    worker_b.reset_fast_patch_caches.assert_called_once()

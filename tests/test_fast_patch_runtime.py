from __future__ import annotations

import importlib
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def runtime_db(tmp_path, monkeypatch):
    import app.core.db as db_module

    importlib.reload(db_module)
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "fast_patch_runtime.db"), raising=False)
    db_module.init_db()
    db_module.invalidate_sync_cache()
    monkeypatch.setattr(db_module, "refresh_sync_cache_async", MagicMock())
    return db_module


def _runtime_app():
    return SimpleNamespace(
        logger=MagicMock(),
        reset_runtime_fast_patch_caches=MagicMock(),
        _request_running_ultra_sync=MagicMock(return_value=True),
        _defer_ultra_reconnects=MagicMock(),
        request_sync_now=MagicMock(),
    )


def _runtime_member(member_id: int, name: str) -> dict:
    return {
        "userId": 1000 + member_id,
        "activeMembershipId": member_id,
        "membershipId": 7,
        "fullName": name,
        "fingerprints": [],
    }


def test_apply_fast_patch_bundle_invalidates_caches_and_requests_targeted_member_ultra_sync_without_immediate_reconcile(monkeypatch):
    import app.ui.app as app_module

    invalidate = MagicMock()
    monkeypatch.setattr("app.core.db.apply_fast_patch_bundle", lambda bundle: {"applied": 2, "skipped": 0, "ignored": None})
    monkeypatch.setattr("app.core.db.invalidate_sync_cache", invalidate)

    app = SimpleNamespace(
        logger=MagicMock(),
        reset_runtime_fast_patch_caches=MagicMock(),
        _request_running_ultra_sync=MagicMock(return_value=True),
        _defer_ultra_reconnects=MagicMock(),
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
            },
            {
                "kind": "SECTION_REPLACE",
                "entityType": "CREDENTIALS",
                "revision": "2026-04-12T12:00:00Z",
                "payload": {
                    "mergeMode": "UPSERT_ONLY",
                    "gymAccessCredentials": [
                        {
                            "accountId": 501,
                            "gymId": 42,
                            "secretHex": "abc123",
                            "enabled": True,
                            "grantedActiveMembershipIds": [9],
                        }
                    ],
                },
                "impact": {"affectedMemberIds": [9], "affectedDeviceIds": []},
            }
        ],
    }

    result = app_module.MainApp.apply_fast_patch_bundle(app, bundle)

    assert result == {"ok": True, "applied": 2, "skipped": 0, "ignored": None}
    invalidate.assert_called_once()
    app.reset_runtime_fast_patch_caches.assert_called_once()
    app._request_running_ultra_sync.assert_called_once_with(
        refresh={"members": True, "devices": False},
        changed_ids={9},
        revoked_ids=set(),
        device_ids={7},
        reason="FAST_PATCH_BUNDLE",
    )
    app.request_sync_now.assert_not_called()


def test_apply_fast_patch_bundle_requests_device_rescope_sync(monkeypatch):
    import app.ui.app as app_module

    invalidate = MagicMock()
    monkeypatch.setattr("app.core.db.apply_fast_patch_bundle", lambda bundle: {"applied": 1, "skipped": 0, "ignored": None})
    monkeypatch.setattr("app.core.db.invalidate_sync_cache", invalidate)

    app = SimpleNamespace(
        logger=MagicMock(),
        reset_runtime_fast_patch_caches=MagicMock(),
        _request_running_ultra_sync=MagicMock(return_value=True),
        _defer_ultra_reconnects=MagicMock(),
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
        revoked_ids=set(),
        device_ids={7},
        reason="FAST_PATCH_BUNDLE",
    )


def test_apply_fast_patch_bundle_routes_membership_delete_as_authoritative_revoke(monkeypatch):
    import app.ui.app as app_module

    monkeypatch.setattr(
        "app.core.db.apply_fast_patch_bundle",
        lambda bundle: {"applied": 2, "skipped": 0, "ignored": None},
    )
    app = SimpleNamespace(
        logger=MagicMock(),
        reset_runtime_fast_patch_caches=MagicMock(),
        _request_running_ultra_sync=MagicMock(return_value=True),
        _defer_ultra_reconnects=MagicMock(),
        request_sync_now=MagicMock(),
    )
    bundle = {
        "bundleId": "bundle-delete",
        "requiresReconcile": False,
        "items": [
            {
                "kind": "ENTITY_DELETE",
                "entityType": "ACTIVE_MEMBERSHIP",
                "entityId": 9,
                "impact": {"affectedMemberIds": [9], "affectedDeviceIds": [7]},
            },
            {
                "kind": "ENTITY_UPSERT",
                "entityType": "ACTIVE_MEMBERSHIP",
                "entityId": 9,
                "impact": {"affectedMemberIds": [9], "affectedDeviceIds": []},
            },
        ],
    }

    app_module.MainApp.apply_fast_patch_bundle(app, bundle)

    app._request_running_ultra_sync.assert_called_once_with(
        refresh={"members": True, "devices": False},
        changed_ids=set(),
        revoked_ids={9},
        device_ids={7},
        reason="FAST_PATCH_BUNDLE",
    )


def test_apply_fast_patch_bundle_normalizes_delete_classifier(monkeypatch):
    import app.ui.app as app_module

    monkeypatch.setattr(
        "app.core.db.apply_fast_patch_bundle",
        lambda bundle: {"applied": 1, "skipped": 0, "ignored": None},
    )
    app = SimpleNamespace(
        logger=MagicMock(),
        reset_runtime_fast_patch_caches=MagicMock(),
        _request_running_ultra_sync=MagicMock(return_value=True),
        _defer_ultra_reconnects=MagicMock(),
        request_sync_now=MagicMock(),
    )
    bundle = {
        "requiresReconcile": False,
        "items": [{
            "kind": "  entity_delete ",
            "entityType": " active_membership  ",
            "entityId": "13",
            "impact": {"affectedMemberIds": [13], "affectedDeviceIds": []},
        }],
    }

    app_module.MainApp.apply_fast_patch_bundle(app, bundle)

    app._request_running_ultra_sync.assert_called_once_with(
        refresh={"members": True, "devices": False},
        changed_ids=set(),
        revoked_ids={13},
        device_ids=None,
        reason="FAST_PATCH_BUNDLE",
    )


def test_apply_fast_patch_bundle_ignores_malformed_delete_entity_ids(monkeypatch):
    import app.ui.app as app_module

    monkeypatch.setattr(
        "app.core.db.apply_fast_patch_bundle",
        lambda bundle: {"applied": 4, "skipped": 0, "ignored": None},
    )
    app = SimpleNamespace(
        logger=MagicMock(),
        reset_runtime_fast_patch_caches=MagicMock(),
        _request_running_ultra_sync=MagicMock(return_value=True),
        _defer_ultra_reconnects=MagicMock(),
        request_sync_now=MagicMock(),
    )
    bundle = {
        "requiresReconcile": False,
        "items": [
            {
                "kind": "ENTITY_DELETE",
                "entityType": "ACTIVE_MEMBERSHIP",
                "entityId": None,
                "impact": {"affectedMemberIds": [9]},
            },
            {
                "kind": "ENTITY_DELETE",
                "entityType": "ACTIVE_MEMBERSHIP",
                "impact": {"affectedMemberIds": [10]},
            },
            {
                "kind": "ENTITY_DELETE",
                "entityType": "ACTIVE_MEMBERSHIP",
                "entityId": "not-an-id",
                "impact": {"affectedMemberIds": [11]},
            },
            {
                "kind": "ENTITY_DELETE",
                "entityType": "ACTIVE_MEMBERSHIP",
                "entityId": 9.5,
                "impact": {"affectedMemberIds": [12]},
            },
        ],
    }

    app_module.MainApp.apply_fast_patch_bundle(app, bundle)

    app._request_running_ultra_sync.assert_called_once_with(
        refresh={"members": True, "devices": False},
        changed_ids={9, 10, 11, 12},
        revoked_ids=set(),
        device_ids=None,
        reason="FAST_PATCH_BUNDLE",
    )


def test_apply_fast_patch_bundle_keeps_unrelated_delete_as_ordinary_change(monkeypatch):
    import app.ui.app as app_module

    monkeypatch.setattr(
        "app.core.db.apply_fast_patch_bundle",
        lambda bundle: {"applied": 1, "skipped": 0, "ignored": None},
    )
    app = SimpleNamespace(
        logger=MagicMock(),
        reset_runtime_fast_patch_caches=MagicMock(),
        _request_running_ultra_sync=MagicMock(return_value=True),
        _defer_ultra_reconnects=MagicMock(),
        request_sync_now=MagicMock(),
    )
    bundle = {
        "requiresReconcile": False,
        "items": [{
            "kind": "ENTITY_DELETE",
            "entityType": "CREDENTIALS",
            "entityId": 21,
            "impact": {"affectedMemberIds": [9], "affectedDeviceIds": [7]},
        }],
    }

    app_module.MainApp.apply_fast_patch_bundle(app, bundle)

    app._request_running_ultra_sync.assert_called_once_with(
        refresh={"members": True, "devices": False},
        changed_ids={9},
        revoked_ids=set(),
        device_ids={7},
        reason="FAST_PATCH_BUNDLE",
    )


def test_request_running_ultra_sync_gives_revocation_precedence():
    import app.ui.app as app_module

    request_sync_now = MagicMock(return_value=True)
    app = SimpleNamespace(
        _ultra_lock=threading.Lock(),
        _ultra_engine=SimpleNamespace(running=True, request_sync_now=request_sync_now),
        logger=MagicMock(),
    )

    started = app_module.MainApp._request_running_ultra_sync(
        app,
        refresh={"members": True, "devices": False},
        changed_ids={9, 10},
        revoked_ids={"9"},
        device_ids={"7"},
        reason="FAST_PATCH_BUNDLE",
    )

    assert started is True
    request_sync_now.assert_called_once_with(
        changed_ids={10},
        revoked_ids={9},
        device_ids={7},
        reason="fast_patch_bundle",
    )


def test_request_running_ultra_sync_does_not_skip_revoke_only_request():
    import app.ui.app as app_module

    request_sync_now = MagicMock(return_value=True)
    app = SimpleNamespace(
        _ultra_lock=threading.Lock(),
        _ultra_engine=SimpleNamespace(running=True, request_sync_now=request_sync_now),
        logger=MagicMock(),
    )

    started = app_module.MainApp._request_running_ultra_sync(
        app,
        refresh={"members": True, "devices": False},
        changed_ids=set(),
        revoked_ids={9},
        reason="FAST_PATCH_BUNDLE",
    )

    assert started is True
    request_sync_now.assert_called_once_with(
        changed_ids=set(),
        revoked_ids={9},
        device_ids=None,
        reason="fast_patch_bundle",
    )


def test_request_running_ultra_sync_rejects_noncanonical_member_ids():
    import app.ui.app as app_module

    request_sync_now = MagicMock(return_value=True)
    app = SimpleNamespace(
        _ultra_lock=threading.Lock(),
        _ultra_engine=SimpleNamespace(running=True, request_sync_now=request_sync_now),
        logger=MagicMock(),
    )

    started = app_module.MainApp._request_running_ultra_sync(
        app,
        refresh={"members": True, "devices": False},
        changed_ids={True, 9.5, 10.0, "9.5", "bad", " 11 ", "012", 0, -2, 42, "43"},
        revoked_ids={False, 19.5, 20.0, "19.5", "nope", " 21 ", "022", 0, -3, 44, "45"},
        reason="FAST_PATCH_BUNDLE",
    )

    assert started is True
    request_sync_now.assert_called_once_with(
        changed_ids={42, 43},
        revoked_ids={44, 45},
        device_ids=None,
        reason="fast_patch_bundle",
    )


def test_runtime_stale_membership_delete_does_not_revoke_newer_local_member(runtime_db):
    import app.ui.app as app_module

    runtime_db.apply_fast_patch_bundle({
        "bundleId": "seed-newer-member",
        "generatedAt": "2026-04-12T12:10:00Z",
        "items": [{
            "kind": "ENTITY_UPSERT",
            "entityType": "ACTIVE_MEMBERSHIP",
            "entityId": 9,
            "revision": "2026-04-12T12:10:00Z",
            "payload": {"member": _runtime_member(9, "Still Active")},
        }],
    })
    app = _runtime_app()
    result = app_module.MainApp.apply_fast_patch_bundle(app, {
        "bundleId": "stale-delete",
        "generatedAt": "2026-04-12T12:09:00Z",
        "requiresReconcile": False,
        "items": [{
            "kind": "ENTITY_DELETE",
            "entityType": "ACTIVE_MEMBERSHIP",
            "entityId": 9,
            "revision": "2026-04-12T12:09:00Z",
            "impact": {"affectedMemberIds": [9], "affectedDeviceIds": [7]},
        }],
    })

    assert result["appliedItemIndexes"] == []
    assert runtime_db.list_sync_users()[0]["fullName"] == "Still Active"
    app._request_running_ultra_sync.assert_not_called()


def test_runtime_applied_membership_delete_routes_revocation(runtime_db):
    import app.ui.app as app_module

    runtime_db.apply_fast_patch_bundle({
        "bundleId": "seed-delete-member",
        "generatedAt": "2026-04-12T12:00:00Z",
        "items": [{
            "kind": "ENTITY_UPSERT",
            "entityType": "ACTIVE_MEMBERSHIP",
            "entityId": 9,
            "revision": "2026-04-12T12:00:00Z",
            "payload": {"member": _runtime_member(9, "Delete Me")},
        }],
    })
    app = _runtime_app()
    result = app_module.MainApp.apply_fast_patch_bundle(app, {
        "bundleId": "accepted-delete",
        "generatedAt": "2026-04-12T12:01:00Z",
        "requiresReconcile": False,
        "items": [{
            "kind": "ENTITY_DELETE",
            "entityType": "ACTIVE_MEMBERSHIP",
            "entityId": 9,
            "revision": "2026-04-12T12:01:00Z",
            "impact": {"affectedMemberIds": [9], "affectedDeviceIds": [7]},
        }],
    })

    assert result["appliedItemIndexes"] == [0]
    assert runtime_db.list_sync_users() == []
    app._request_running_ultra_sync.assert_called_once_with(
        refresh={"members": True, "devices": False},
        changed_ids=set(),
        revoked_ids={9},
        device_ids={7},
        reason="FAST_PATCH_BUNDLE",
    )


def test_runtime_mixed_bundle_routes_only_transactionally_applied_item(runtime_db):
    import app.ui.app as app_module

    runtime_db.apply_fast_patch_bundle({
        "bundleId": "seed-mixed-member",
        "generatedAt": "2026-04-12T12:10:00Z",
        "items": [{
            "kind": "ENTITY_UPSERT",
            "entityType": "ACTIVE_MEMBERSHIP",
            "entityId": 9,
            "revision": "2026-04-12T12:10:00Z",
            "payload": {"member": _runtime_member(9, "Keep Me")},
        }],
    })
    app = _runtime_app()
    result = app_module.MainApp.apply_fast_patch_bundle(app, {
        "bundleId": "mixed-runtime",
        "generatedAt": "2026-04-12T12:11:00Z",
        "requiresReconcile": False,
        "items": [
            {
                "kind": "ENTITY_DELETE",
                "entityType": "ACTIVE_MEMBERSHIP",
                "entityId": 9,
                "revision": "2026-04-12T12:09:00Z",
                "impact": {"affectedMemberIds": [9], "affectedDeviceIds": [7]},
            },
            {
                "kind": "ENTITY_UPSERT",
                "entityType": "ACTIVE_MEMBERSHIP",
                "entityId": 10,
                "revision": "2026-04-12T12:11:00Z",
                "payload": {"member": _runtime_member(10, "Apply Me")},
                "impact": {"affectedMemberIds": [10], "affectedDeviceIds": [8]},
            },
        ],
    })

    assert result["appliedItemIndexes"] == [1]
    assert [row["activeMembershipId"] for row in runtime_db.list_sync_users()] == [9, 10]
    app._request_running_ultra_sync.assert_called_once_with(
        refresh={"members": True, "devices": False},
        changed_ids={10},
        revoked_ids=set(),
        device_ids={8},
        reason="FAST_PATCH_BUNDLE",
    )


def test_malformed_accepted_delete_impact_revokes_globally_and_schedules_fallback(monkeypatch):
    import app.ui.app as app_module

    results = [
        {"applied": 1, "skipped": 0, "ignored": None, "appliedItemIndexes": [0]},
        {"applied": 0, "skipped": 0, "ignored": "duplicate_bundle", "appliedItemIndexes": []},
    ]
    monkeypatch.setattr("app.core.db.apply_fast_patch_bundle", MagicMock(side_effect=results))
    app = _runtime_app()
    bundle = {
        "bundleId": "malformed-delete-impact",
        "requiresReconcile": False,
        "items": [{
            "kind": "ENTITY_DELETE",
            "entityType": "ACTIVE_MEMBERSHIP",
            "entityId": 9,
            "impact": "not-an-object",
        }],
    }

    first = app_module.MainApp.apply_fast_patch_bundle(app, bundle)
    second = app_module.MainApp.apply_fast_patch_bundle(app, bundle)

    assert first["ok"] is True
    assert second["duplicate"] is True
    app._request_running_ultra_sync.assert_called_once_with(
        refresh={"members": True, "devices": False},
        changed_ids=set(),
        revoked_ids={9},
        device_ids=None,
        reason="FAST_PATCH_BUNDLE",
    )
    app.request_sync_now.assert_called_once_with(
        trigger_source="FAST_PATCH_BUNDLE",
        run_type="TRIGGERED",
        trigger_hint={"reason": "fast_patch_bundle"},
    )
    assert any("malformed" in str(call).lower() for call in app.logger.warning.call_args_list)


def test_malformed_accepted_impact_ids_use_full_reconcile_without_partial_sync(monkeypatch):
    import app.ui.app as app_module

    monkeypatch.setattr(
        "app.core.db.apply_fast_patch_bundle",
        lambda bundle: {"applied": 1, "skipped": 0, "ignored": None, "appliedItemIndexes": [0]},
    )
    app = _runtime_app()
    app_module.MainApp.apply_fast_patch_bundle(app, {
        "requiresReconcile": False,
        "items": [{
            "kind": "ENTITY_UPSERT",
            "entityType": "ACTIVE_MEMBERSHIP",
            "entityId": 9,
            "impact": {
                "affectedMemberIds": [9.5, True, "bad"],
                "affectedDeviceIds": "not-a-list",
            },
        }],
    })

    app._request_running_ultra_sync.assert_not_called()
    app.request_sync_now.assert_called_once()
    assert any("rejected" in str(call).lower() for call in app.logger.warning.call_args_list)


def test_legacy_mixed_result_without_item_identity_uses_full_reconcile(monkeypatch):
    import app.ui.app as app_module

    monkeypatch.setattr(
        "app.core.db.apply_fast_patch_bundle",
        lambda bundle: {"applied": 1, "skipped": 1, "ignored": None},
    )
    app = _runtime_app()
    app_module.MainApp.apply_fast_patch_bundle(app, {
        "requiresReconcile": False,
        "items": [
            {
                "kind": "ENTITY_DELETE",
                "entityType": "ACTIVE_MEMBERSHIP",
                "entityId": 9,
                "impact": {"affectedMemberIds": [9]},
            },
            {
                "kind": "ENTITY_UPSERT",
                "entityType": "ACTIVE_MEMBERSHIP",
                "entityId": 10,
                "impact": {"affectedMemberIds": [10]},
            },
        ],
    })

    app._request_running_ultra_sync.assert_not_called()
    app.request_sync_now.assert_called_once()
    assert any("ambiguous" in str(call).lower() for call in app.logger.warning.call_args_list)


def test_apply_fast_patch_bundle_duplicate_short_circuits_runtime_actions(monkeypatch):
    import app.ui.app as app_module

    invalidate = MagicMock()
    monkeypatch.setattr("app.core.db.apply_fast_patch_bundle", lambda bundle: {"applied": 0, "skipped": 0, "ignored": "duplicate_bundle"})
    monkeypatch.setattr("app.core.db.invalidate_sync_cache", invalidate)

    app = SimpleNamespace(
        logger=MagicMock(),
        reset_runtime_fast_patch_caches=MagicMock(),
        _request_running_ultra_sync=MagicMock(return_value=True),
        _defer_ultra_reconnects=MagicMock(),
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

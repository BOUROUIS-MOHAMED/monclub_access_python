from __future__ import annotations

import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    db_path = str(tmp_path / "authoritative-revocations.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()
    yield db_module
    if hasattr(db_module, "_shutdown_db_writer_for_tests"):
        db_module._shutdown_db_writer_for_tests()


def _make_user(active_membership_id: int) -> dict:
    return {
        "activeMembershipId": active_membership_id,
        "userId": active_membership_id + 100,
        "membershipId": 50,
        "firstName": f"Member{active_membership_id}",
        "lastName": "Example",
        "fullName": f"Member{active_membership_id} Example",
        "phone": "0600000000",
        "email": f"member{active_membership_id}@example.com",
        "firstCardId": f"CARD-{active_membership_id}",
        "secondCardId": None,
        "validFrom": "2026-01-01",
        "validTo": "2026-12-31",
        "status": "ACTIVE",
        "contractStatus": "ACTIVE",
        "fingerprints": [],
        "faceId": None,
        "accountUsernameId": None,
        "qrCodePayload": None,
        "birthday": None,
        "image": None,
        "imageSource": None,
        "userImageStatus": None,
    }


def _app():
    return SimpleNamespace(logger=MagicMock())


def _shadow_ids(db) -> set[int]:
    with db.get_conn() as conn:
        return {
            int(row["active_membership_id"])
            for row in conn.execute(
                "SELECT active_membership_id FROM member_shadow"
            ).fetchall()
        }


def test_delta_authoritative_deletion_is_returned_only_as_revocation(db):
    from app.ui.app import MainApp

    db.upsert_member_shadow(users=[_make_user(1), _make_user(2)])

    changed, revoked = MainApp._apply_member_shadow_sync(
        _app(),
        data={
            "membersDeltaMode": True,
            "users": [_make_user(1)],
            "validMemberIds": [1],
        },
        refresh={"members": True},
        delta_changed_ids={1},
    )

    assert changed == {1}
    assert revoked == {2}
    assert _shadow_ids(db) == {1}


def test_full_authoritative_deletion_is_returned_only_as_revocation(db):
    from app.ui.app import MainApp

    db.upsert_member_shadow(users=[_make_user(1), _make_user(2)])

    changed, revoked = MainApp._apply_member_shadow_sync(
        _app(),
        data={
            "membersDeltaMode": False,
            "users": [_make_user(1)],
            "validMemberIds": [1],
        },
        refresh={"members": True},
        delta_changed_ids=None,
    )

    assert changed is None
    assert revoked == {2}
    assert _shadow_ids(db) == {1}


def test_full_without_valid_ids_derives_authority_from_incoming_roster(db):
    from app.ui.app import MainApp

    users = [_make_user(1), _make_user(2)]
    refresh = {"members": True, "devices": False, "credentials": False, "settings": False}
    db.save_sync_cache_delta(
        {"users": users, "membersDeltaMode": False, "contractStatus": True}, refresh
    )
    db.upsert_member_shadow(users=users)
    response = {"users": [_make_user(1)], "membersDeltaMode": False, "contractStatus": True}

    outcome = db.save_sync_cache_delta(response, refresh)
    changed, revoked = MainApp._apply_member_shadow_sync(
        _app(),
        data=response,
        refresh=refresh,
        delta_changed_ids=None,
        cache_members_delete_refused=outcome["members_delete_refused"],
        authoritative_member_ids=outcome["authoritative_member_ids"],
        authoritative_member_ids_valid=outcome["authoritative_member_ids_valid"],
    )

    assert changed is None
    assert revoked == {2}
    assert set(db.get_all_cached_user_am_ids()) == {1}
    assert _shadow_ids(db) == {1}


@pytest.mark.parametrize(
    ("raw_valid_ids", "refused", "remaining"),
    [
        (["1"], False, {1}),
        ([True], True, {1, 2}),
        ([1.5], True, {1, 2}),
        (["1.5"], True, {1, 2}),
    ],
)
def test_cache_and_shadow_share_one_authoritative_id_contract(
    db, raw_valid_ids, refused, remaining
):
    from app.ui.app import MainApp

    users = [_make_user(1), _make_user(2)]
    refresh = {"members": True, "devices": False, "credentials": False, "settings": False}
    db.save_sync_cache_delta(
        {"users": users, "membersDeltaMode": False, "contractStatus": True}, refresh
    )
    db.upsert_member_shadow(users=users)
    response = {
        "users": [],
        "membersDeltaMode": True,
        "validMemberIds": raw_valid_ids,
        "contractStatus": True,
    }

    outcome = db.save_sync_cache_delta(response, refresh)
    changed, revoked = MainApp._apply_member_shadow_sync(
        _app(),
        data=response,
        refresh=refresh,
        delta_changed_ids=set(),
        cache_members_delete_refused=outcome["members_delete_refused"],
        authoritative_member_ids=outcome["authoritative_member_ids"],
        authoritative_member_ids_valid=outcome["authoritative_member_ids_valid"],
    )

    assert outcome["members_delete_refused"] is refused
    assert set(db.get_all_cached_user_am_ids()) == remaining
    assert _shadow_ids(db) == remaining
    assert revoked == (set() if refused else {2})
    assert changed == set()


@pytest.mark.parametrize("invalid_id", [True, 1.5])
def test_full_invalid_user_id_cannot_overwrite_existing_member(db, invalid_id):
    from app.ui.app import MainApp

    refresh = {"members": True, "devices": False, "credentials": False, "settings": False}
    original = _make_user(1)
    original["firstCardId"] = "CARD-A"
    db.save_sync_cache_delta({"users": [original], "membersDeltaMode": False}, refresh)
    db.upsert_member_shadow(users=[original])
    invalid = _make_user(1)
    invalid["activeMembershipId"] = invalid_id
    invalid["firstCardId"] = "CARD-B"
    response = {"users": [invalid], "membersDeltaMode": False}

    outcome = db.save_sync_cache_delta(response, refresh)
    changed, revoked = MainApp._apply_member_shadow_sync(
        _app(), data=response, refresh=refresh, delta_changed_ids=None,
        cache_members_delete_refused=outcome["members_delete_refused"],
        authoritative_member_ids=outcome["authoritative_member_ids"],
        authoritative_member_ids_valid=outcome["authoritative_member_ids_valid"],
        accepted_member_user_indexes=outcome["accepted_member_user_indexes"],
    )

    assert outcome["members_delete_refused"] is True
    assert db.list_sync_users()[0]["firstCardId"] == "CARD-A"
    assert db.get_member_shadow_cards() == {1: "CARD-A"}
    assert changed is None
    assert revoked == set()


def test_mixed_valid_and_invalid_users_only_apply_safe_rows(db):
    from app.ui.app import MainApp

    refresh = {"members": True, "devices": False, "credentials": False, "settings": False}
    original = _make_user(1)
    original["firstCardId"] = "CARD-A"
    db.save_sync_cache_delta({"users": [original], "membersDeltaMode": False}, refresh)
    db.upsert_member_shadow(users=[original])
    valid = _make_user(2)
    invalid_bool = _make_user(1)
    invalid_bool["activeMembershipId"] = True
    invalid_bool["firstCardId"] = "BAD-BOOL"
    invalid_float = _make_user(1)
    invalid_float["activeMembershipId"] = 1.5
    invalid_float["firstCardId"] = "BAD-FLOAT"
    response = {
        "users": [valid, invalid_bool, invalid_float],
        "membersDeltaMode": True,
        "validMemberIds": [1, 2],
    }

    outcome = db.save_sync_cache_delta(response, refresh)
    changed, revoked = MainApp._apply_member_shadow_sync(
        _app(), data=response, refresh=refresh, delta_changed_ids={2},
        cache_members_delete_refused=outcome["members_delete_refused"],
        authoritative_member_ids=outcome["authoritative_member_ids"],
        authoritative_member_ids_valid=outcome["authoritative_member_ids_valid"],
        accepted_member_user_indexes=outcome["accepted_member_user_indexes"],
    )

    assert outcome["accepted_member_user_indexes"] == [0]
    assert outcome["members_delete_refused"] is True
    assert {row["activeMembershipId"]: row["firstCardId"] for row in db.list_sync_users()} == {
        1: "CARD-A", 2: "CARD-2",
    }
    assert db.get_member_shadow_cards() == {1: "CARD-A", 2: "CARD-2"}
    assert changed == {2}
    assert revoked == set()


def test_canonical_string_user_id_upserts_in_cache_and_shadow(db):
    from app.ui.app import MainApp

    refresh = {"members": True, "devices": False, "credentials": False, "settings": False}
    user = _make_user(2)
    user["activeMembershipId"] = "2"
    response = {"users": [user], "membersDeltaMode": False}

    outcome = db.save_sync_cache_delta(response, refresh)
    _changed, revoked = MainApp._apply_member_shadow_sync(
        _app(), data=response, refresh=refresh, delta_changed_ids=None,
        cache_members_delete_refused=outcome["members_delete_refused"],
        authoritative_member_ids=outcome["authoritative_member_ids"],
        authoritative_member_ids_valid=outcome["authoritative_member_ids_valid"],
        accepted_member_user_indexes=outcome["accepted_member_user_indexes"],
    )

    assert outcome["accepted_member_user_indexes"] == [0]
    assert [row["activeMembershipId"] for row in db.list_sync_users()] == [2]
    assert _shadow_ids(db) == {2}
    assert revoked == set()


def test_full_h006_cache_refusal_preserves_shadow_and_emits_no_revocations(db):
    from app.ui.app import MainApp

    users = [_make_user(member_id) for member_id in range(1, 12)]
    refresh = {
        "members": True,
        "devices": False,
        "credentials": False,
        "settings": False,
    }
    seed = {
        "users": users,
        "membersDeltaMode": False,
        "validMemberIds": list(range(1, 12)),
        "contractStatus": True,
        "contractEndDate": "2026-12-31",
        "currentMembersVersion": "new-members",
        "currentMembersRefreshedAt": "new-watermark",
        "currentDevicesVersion": "new-devices",
    }
    db.save_sync_cache_delta(seed, refresh)
    db.upsert_member_shadow(users=users)

    refused = {
        "users": [],
        "membersDeltaMode": False,
        "validMemberIds": [],
        "contractStatus": True,
        "contractEndDate": "2026-12-31",
    }
    cache_write_outcome = db.save_sync_cache_delta(refused, refresh)
    cache_profile = db.get_last_db_write_profile("save_sync_cache_delta")

    changed, revoked = MainApp._apply_member_shadow_sync(
        _app(),
        data=refused,
        refresh=refresh,
        delta_changed_ids=None,
        cache_members_delete_refused=cache_write_outcome["members_delete_refused"],
    )

    assert cache_profile["members_full_refresh_refused"] is True
    assert set(db.get_all_cached_user_am_ids()) == set(range(1, 12))
    assert _shadow_ids(db) == set(range(1, 12))
    assert changed is None
    assert revoked == set()


def test_h006_refusal_emits_no_revocations_and_preserves_shadow(db):
    from app.ui.app import MainApp

    db.upsert_member_shadow(users=[_make_user(member_id) for member_id in range(1, 12)])

    changed, revoked = MainApp._apply_member_shadow_sync(
        _app(),
        data={
            "membersDeltaMode": True,
            "users": [],
            "validMemberIds": [],
        },
        refresh={"members": True},
        delta_changed_ids=set(),
    )

    assert changed == set()
    assert revoked == set()
    assert _shadow_ids(db) == set(range(1, 12))


def test_delta_cache_refusal_suppresses_shadow_deletes_but_keeps_upserts(db):
    from app.ui.app import MainApp

    cache_users = [_make_user(member_id) for member_id in range(1, 12)]
    shadow_users = [_make_user(member_id) for member_id in range(1, 11)]
    refresh = {
        "members": True,
        "devices": False,
        "credentials": False,
        "settings": False,
    }
    db.save_sync_cache_delta(
        {
            "users": cache_users,
            "membersDeltaMode": False,
            "validMemberIds": list(range(1, 12)),
            "contractStatus": True,
            "contractEndDate": "2026-12-31",
        },
        refresh,
    )
    db.upsert_member_shadow(users=shadow_users)

    updated = _make_user(3)
    updated["fullName"] = "Safely Updated"
    added = _make_user(12)
    refused_delta = {
        "users": [updated, added],
        "membersDeltaMode": True,
        "validMemberIds": [],
        "contractStatus": True,
        "contractEndDate": "2026-12-31",
    }
    cache_write_outcome = db.save_sync_cache_delta(refused_delta, refresh)

    changed, revoked = MainApp._apply_member_shadow_sync(
        _app(),
        data=refused_delta,
        refresh=refresh,
        delta_changed_ids={3, 12},
        cache_members_delete_refused=cache_write_outcome["members_delete_refused"],
    )

    assert cache_write_outcome["members_delete_refused"] is True
    assert set(db.get_all_cached_user_am_ids()) == set(range(1, 13))
    assert _shadow_ids(db) == set(range(1, 11)) | {12}
    with db.get_conn() as conn:
        name = conn.execute(
            "SELECT full_name FROM member_shadow WHERE active_membership_id=3"
        ).fetchone()["full_name"]
    assert name == "Safely Updated"
    assert changed == {3, 12}
    assert revoked == set()


def test_shadow_error_emits_no_revocations_and_preserves_changed_ids(db, monkeypatch):
    from app.ui.app import MainApp

    db.upsert_member_shadow(users=[_make_user(1), _make_user(2)])
    monkeypatch.setattr(
        db,
        "diff_member_shadow",
        MagicMock(side_effect=RuntimeError("shadow unavailable")),
    )

    changed, revoked = MainApp._apply_member_shadow_sync(
        _app(),
        data={
            "membersDeltaMode": False,
            "users": [_make_user(1)],
            "validMemberIds": [1],
        },
        refresh={"members": True},
        delta_changed_ids={1},
    )

    assert changed == {1}
    assert revoked == set()
    assert _shadow_ids(db) == {1, 2}


def test_late_shadow_delete_error_restores_original_changed_ids(db, monkeypatch):
    from app.ui.app import MainApp

    original_changed = {99}
    db.upsert_member_shadow(users=[_make_user(1), _make_user(2)])
    modified_user = _make_user(1)
    modified_user["firstCardId"] = "UPDATED-CARD"
    monkeypatch.setattr(
        db,
        "delete_member_shadow",
        MagicMock(side_effect=RuntimeError("delete unavailable")),
    )

    changed, revoked = MainApp._apply_member_shadow_sync(
        _app(),
        data={
            "membersDeltaMode": False,
            "users": [modified_user],
            "validMemberIds": [1],
        },
        refresh={"members": True},
        delta_changed_ids=original_changed,
    )

    assert changed == {99}
    assert changed is not original_changed
    assert revoked == set()
    assert _shadow_ids(db) == {1, 2}


def test_revocation_takes_precedence_over_incoming_changed_id(db):
    from app.ui.app import MainApp

    db.upsert_member_shadow(users=[_make_user(1), _make_user(2)])

    changed, revoked = MainApp._apply_member_shadow_sync(
        _app(),
        data={
            "membersDeltaMode": True,
            "users": [_make_user(1)],
            "validMemberIds": [1],
        },
        refresh={"members": True},
        delta_changed_ids={1, 2},
    )

    assert changed == {1}
    assert revoked == {2}


def test_main_sync_routing_keeps_ultra_sets_separate_and_unions_device_ids():
    from app.ui.app import MainApp

    ultra_changed, ultra_revoked, device_changed = MainApp._member_sync_dispatch_ids(
        changed_ids={1},
        revoked_ids={2},
    )

    assert ultra_changed == {1}
    assert ultra_revoked == {2}
    assert device_changed == {1, 2}


def test_main_sync_routing_preserves_device_full_semantics():
    from app.ui.app import MainApp

    ultra_changed, ultra_revoked, device_changed = MainApp._member_sync_dispatch_ids(
        changed_ids=None,
        revoked_ids={2},
    )

    assert ultra_changed is None
    assert ultra_revoked == {2}
    assert device_changed is None


class _InlineThread:
    def __init__(self, *, target, daemon):
        self._target = target

    def start(self):
        self._target()


def _run_main_sync_dispatch(
    monkeypatch,
    *,
    changed_ids,
    revoked_ids,
    cache_members_delete_refused=False,
    use_real_tokens=False,
):
    import app.ui.app as app_module

    response = {
        "refreshMembers": True,
        "refreshDevices": False,
        "refreshCredentials": False,
        "refreshSettings": False,
        "membersDeltaMode": changed_ids is not None,
        "users": [_make_user(member_id) for member_id in sorted(changed_ids or ())],
        "validMemberIds": sorted((changed_ids or set()) | revoked_ids),
        "contractStatus": True,
        "contractEndDate": "2026-12-31",
        "currentMembersVersion": "new-members",
        "currentMembersRefreshedAt": "new-watermark",
        "currentDevicesVersion": "new-devices",
    }
    api = SimpleNamespace(
        do_proactive_refresh=MagicMock(return_value=False),
        get_sync_data=MagicMock(return_value=response),
    )
    ultra_request = MagicMock(return_value=True)
    device_run = MagicMock(return_value=True)
    shadow_sync = MagicMock(return_value=(changed_ids, revoked_ids))
    token_save = MagicMock()
    token_delete = MagicMock()
    ultra_device = {"id": 2, "accessDataMode": "ULTRA"}
    cache = SimpleNamespace(devices=[ultra_device], users=[])
    ultra_engine = SimpleNamespace(
        running=True,
        _workers={2: object()},
        request_sync_now=ultra_request,
        refresh_devices=MagicMock(),
        stop=MagicMock(),
    )
    app = SimpleNamespace(
        logger=MagicMock(),
        cfg=SimpleNamespace(device_sync_enabled=True),
        _sync_work_running=False,
        _pending_sync_context=None,
        _startup_sync_pending=False,
        _sync_fail_count=0,
        _last_sync_at=None,
        _last_sync_ok=None,
        _last_sync_error=None,
        _last_device_sync_at=None,
        _last_device_sync_ok=None,
        _last_device_sync_error=None,
        _ultra_lock=threading.Lock(),
        _ultra_engine=ultra_engine,
        _ultra_history_consumer=None,
        _agent_engine=SimpleNamespace(is_running=MagicMock(return_value=False)),
        _device_sync_engine=SimpleNamespace(
            run_blocking=device_run,
            get_progress_snapshot=MagicMock(return_value=({"total": 1}, None)),
        ),
        _device_attendance_engine=SimpleNamespace(run_blocking=MagicMock()),
        after=MagicMock(),
        evaluate_access_and_redirect=MagicMock(),
        reschedule_sync_timer=MagicMock(),
        _api=lambda: api,
        _defer_ultra_reconnects=MagicMock(return_value=0),
        _apply_member_shadow_sync=shadow_sync,
        _member_sync_dispatch_ids=app_module.MainApp._member_sync_dispatch_ids,
        _request_running_ultra_sync=lambda **kwargs: app_module.MainApp._request_running_ultra_sync(
            app, **kwargs
        ),
        _restriction_reasons=MagicMock(return_value=[]),
        get_access_mode_summary=MagicMock(
            return_value={"DEVICE": 1, "AGENT": 0, "ULTRA": 1, "UNKNOWN": 0}
        ),
        maybe_run_offline_retry=MagicMock(),
        _maybe_emit_sync_success_feedback=MagicMock(),
    )

    monkeypatch.setattr(app_module.threading, "Thread", _InlineThread)
    monkeypatch.setattr(
        app_module,
        "load_auth_token",
        lambda: SimpleNamespace(token="jwt", email="member@example.com"),
    )
    monkeypatch.setattr(app_module, "load_version_tokens", lambda: {"membersVersion": "1"})
    monkeypatch.setattr(app_module, "load_sync_cache", lambda: cache)
    monkeypatch.setattr(
        app_module,
        "save_sync_cache_delta",
        MagicMock(
            return_value={
                "members_delete_refused": cache_members_delete_refused,
            }
        ),
    )
    if not use_real_tokens:
        monkeypatch.setattr(app_module, "save_version_tokens", token_save)
        monkeypatch.setattr("app.core.db.delete_version_tokens", token_delete)
    monkeypatch.setattr(app_module, "member_cache_is_stale", lambda *_args: False)
    monkeypatch.setattr("app.core.db.insert_sync_run", lambda **_kwargs: None)
    monkeypatch.setattr("app.core.db.invalidate_sync_cache", lambda: None)
    monkeypatch.setattr("app.core.db.refresh_sync_cache_async", lambda: None)
    monkeypatch.setattr("app.core.db.list_sync_devices_payload", lambda: [ultra_device])
    monkeypatch.setattr("app.core.db.count_sync_users", lambda: 100)
    monkeypatch.setattr(
        "app.core.settings_reader.get_backend_global_settings", lambda: {}
    )

    app_module.MainApp._sync_tick(app)
    return ultra_request, device_run, shadow_sync, token_save, token_delete


@pytest.mark.parametrize(
    ("changed_ids", "revoked_ids", "expected_device_ids"),
    [
        ({1}, {2}, {1, 2}),
        (None, {2}, None),
    ],
)
def test_main_sync_dispatches_separate_ultra_ids_and_legacy_device_union(
    monkeypatch, changed_ids, revoked_ids, expected_device_ids
):
    ultra_request, device_run, _shadow_sync, _token_save, _token_delete = _run_main_sync_dispatch(
        monkeypatch,
        changed_ids=changed_ids,
        revoked_ids=revoked_ids,
    )

    ultra_request.assert_called_once_with(
        changed_ids=changed_ids,
        revoked_ids=revoked_ids,
        device_ids=None,
        reason="timer",
    )
    assert device_run.call_args.kwargs["changed_ids"] == expected_device_ids


def test_main_sync_h006_refusal_dispatches_no_revocations_and_clears_member_tokens(
    db, monkeypatch
):
    db.save_version_tokens(
        {
            "membersVersion": "old-members",
            "membersUpdatedAfter": "old-watermark",
            "devicesVersion": "old-devices",
            "credentialsVersion": "old-credentials",
        }
    )
    ultra_request, device_run, shadow_sync, token_save, token_delete = _run_main_sync_dispatch(
        monkeypatch,
        changed_ids=None,
        revoked_ids=set(),
        cache_members_delete_refused=True,
        use_real_tokens=True,
    )

    assert shadow_sync.call_args.kwargs["cache_members_delete_refused"] is True
    ultra_request.assert_called_once_with(
        changed_ids=None,
        revoked_ids=set(),
        device_ids=None,
        reason="timer",
    )
    assert device_run.call_args.kwargs["changed_ids"] is None
    assert db.load_version_tokens() == {
        "devicesVersion": "new-devices",
        "credentialsVersion": "old-credentials",
    }


@pytest.mark.parametrize(
    "invalid_id",
    [True, 2.5, "2.5", "02", 0, -1],
)
def test_shadow_sync_never_truncates_or_accepts_noncanonical_valid_ids(
    db, invalid_id
):
    from app.ui.app import MainApp

    db.upsert_member_shadow(users=[_make_user(2)])

    changed, revoked = MainApp._apply_member_shadow_sync(
        _app(),
        data={
            "membersDeltaMode": True,
            "users": [],
            "validMemberIds": [invalid_id],
        },
        refresh={"members": True},
        delta_changed_ids=set(),
    )

    assert changed == set()
    assert revoked == set()
    assert _shadow_ids(db) == {2}

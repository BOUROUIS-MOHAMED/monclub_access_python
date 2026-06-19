from app.core.sync_scope import (
    apply_trigger_hint_to_version_tokens,
    build_device_membership_scope,
    device_membership_scope_changed,
    member_cache_is_stale,
    member_count_from_token,
    strip_all_member_version_tokens,
    strip_member_version_tokens,
)


def test_build_device_membership_scope_normalizes_order_and_types() -> None:
    scope = build_device_membership_scope(
        [
            {
                "id": "5",
                "accessDataMode": "ultra",
                "allowedMemberships": ["3", 1, 3, "2"],
            }
        ]
    )

    assert scope == {5: ("ULTRA", (1, 2, 3))}


def test_device_membership_scope_changed_detects_allowed_membership_change() -> None:
    previous = [{"id": 5, "accessDataMode": "ULTRA", "allowedMemberships": [1]}]
    current = [{"id": 5, "accessDataMode": "ULTRA", "allowedMemberships": [1, 2]}]

    assert device_membership_scope_changed(previous, current) is True


def test_device_membership_scope_changed_detects_access_mode_change() -> None:
    previous = [{"id": 5, "accessDataMode": "DEVICE", "allowedMemberships": [1, 2]}]
    current = [{"id": 5, "accessDataMode": "ULTRA", "allowedMemberships": [1, 2]}]

    assert device_membership_scope_changed(previous, current) is True


def test_strip_member_version_tokens_keeps_non_member_tokens() -> None:
    tokens = {
        "membersVersion": "members-token",
        "membersUpdatedAfter": "2026-04-09T17:43:28",
        "devicesVersion": "devices-token",
        "credentialsVersion": "creds-token",
        "settingsVersion": "settings-token",
    }

    assert strip_member_version_tokens(tokens) == {
        "membersUpdatedAfter": "2026-04-09T17:43:28",
        "devicesVersion": "devices-token",
        "credentialsVersion": "creds-token",
        "settingsVersion": "settings-token",
    }


def test_apply_trigger_hint_to_version_tokens_forces_member_refresh_for_membership_updates() -> None:
    tokens = {
        "membersVersion": "members-token",
        "membersUpdatedAfter": "2026-04-09T17:43:28",
        "devicesVersion": "devices-token",
        "credentialsVersion": "creds-token",
        "settingsVersion": "settings-token",
    }

    assert apply_trigger_hint_to_version_tokens(
        tokens,
        {"entityType": "ACTIVE_MEMBERSHIP", "operation": "UPDATE"},
    ) == {
        "membersUpdatedAfter": "2026-04-09T17:43:28",
        "devicesVersion": "devices-token",
        "credentialsVersion": "creds-token",
        "settingsVersion": "settings-token",
    }


def test_apply_trigger_hint_to_version_tokens_keeps_member_tokens_for_other_entities() -> None:
    tokens = {
        "membersVersion": "members-token",
        "membersUpdatedAfter": "2026-04-09T17:43:28",
        "devicesVersion": "devices-token",
    }

    assert apply_trigger_hint_to_version_tokens(
        tokens,
        {"entityType": "GYM_DEVICE", "operation": "UPDATE"},
    ) == {
        "membersVersion": "members-token",
        "membersUpdatedAfter": "2026-04-09T17:43:28",
        "devicesVersion": "devices-token",
    }


def test_strip_all_member_version_tokens_drops_both_member_tokens() -> None:
    # Unlike strip_member_version_tokens, this must also drop membersUpdatedAfter
    # so the backend returns the FULL member list instead of a delta.
    tokens = {
        "membersVersion": "1706:2026-06-10T15:01:39:0:0",
        "membersUpdatedAfter": "2026-06-10T15:02:06",
        "devicesVersion": "devices-token",
        "credentialsVersion": "creds-token",
        "settingsVersion": "settings-token",
    }

    assert strip_all_member_version_tokens(tokens) == {
        "devicesVersion": "devices-token",
        "credentialsVersion": "creds-token",
        "settingsVersion": "settings-token",
    }


def test_member_count_from_token_parses_leading_count() -> None:
    assert member_count_from_token("1706:2026-06-10T15:01:39.328283:0:0") == 1706


def test_member_count_from_token_handles_missing_or_garbage() -> None:
    assert member_count_from_token(None) is None
    assert member_count_from_token("") is None
    assert member_count_from_token("not-a-number:x") is None


def test_member_cache_is_stale_flags_wiped_cache() -> None:
    # 30 local rows but the token says the backend has 1706 valid members.
    assert member_cache_is_stale(30, "1706:2026-06-10T15:01:39:0:0") is True


def test_member_cache_is_stale_ignores_healthy_cache() -> None:
    # A handful of members legitimately filtered client-side is not "stale".
    assert member_cache_is_stale(1447, "1452:2026-04-17T16:31:34:0:0") is False
    assert member_cache_is_stale(1706, "1706:2026-06-10T15:01:39:0:0") is False
    # Conservative floor: even a moderately-populated cache is not flagged, so the
    # heal never forces a heavy full sync every cycle on unusual-but-healthy data.
    assert member_cache_is_stale(1400, "1706:2026-06-10T15:01:39:0:0") is False


def test_member_cache_is_stale_ignores_small_gyms_and_missing_token() -> None:
    assert member_cache_is_stale(0, "40:2026-01-01T00:00:00:0:0") is False  # below min_expected
    assert member_cache_is_stale(0, None) is False
    assert member_cache_is_stale(5, "") is False

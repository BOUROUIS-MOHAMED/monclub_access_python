from app.core.sync_scope import (
    apply_trigger_hint_to_version_tokens,
    build_device_membership_scope,
    device_membership_scope_changed,
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

from __future__ import annotations

from typing import Any, Iterable, Mapping


def _normalized_membership_ids(values: Any) -> tuple[int, ...]:
    if not isinstance(values, (list, tuple, set)):
        return ()
    out: set[int] = set()
    for value in values:
        try:
            out.add(int(value))
        except (TypeError, ValueError):
            continue
    return tuple(sorted(out))


def build_device_membership_scope(
    devices: Iterable[dict[str, Any]] | None,
) -> dict[int, tuple[str, tuple[int, ...]]]:
    scope: dict[int, tuple[str, tuple[int, ...]]] = {}
    for device in devices or ():
        if not isinstance(device, dict):
            continue
        try:
            device_id = int(device.get("id"))
        except (TypeError, ValueError):
            continue

        access_mode = str(
            device.get("accessDataMode") or device.get("access_data_mode") or ""
        ).strip().upper()
        allowed_memberships = _normalized_membership_ids(
            device.get("allowedMemberships") or device.get("allowed_memberships") or []
        )
        scope[device_id] = (access_mode, allowed_memberships)
    return scope


def device_membership_scope_changed(
    previous_devices: Iterable[dict[str, Any]] | None,
    new_devices: Iterable[dict[str, Any]] | None,
) -> bool:
    return build_device_membership_scope(previous_devices) != build_device_membership_scope(new_devices)


def strip_member_version_tokens(tokens: dict[str, Any] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in (tokens or {}).items():
        if key in {"membersVersion", "membersUpdatedAfter"} or value is None:
            continue
        out[str(key)] = str(value)
    return out


def apply_trigger_hint_to_version_tokens(
    tokens: Mapping[str, Any] | None,
    trigger_hint: Mapping[str, Any] | None,
) -> dict[str, str] | None:
    normalized = {
        str(key): str(value)
        for key, value in (tokens or {}).items()
        if value is not None
    }
    if not normalized:
        return None

    entity_type = ""
    if isinstance(trigger_hint, Mapping):
        entity_type = str(
            trigger_hint.get("entityType") or trigger_hint.get("entity_type") or ""
        ).strip().upper()

    if entity_type == "ACTIVE_MEMBERSHIP":
        return strip_member_version_tokens(normalized)
    return normalized

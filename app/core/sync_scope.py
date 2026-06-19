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
        if key == "membersVersion" or value is None:
            continue
        out[str(key)] = str(value)
    return out


def strip_all_member_version_tokens(tokens: dict[str, Any] | None) -> dict[str, str]:
    """Drop BOTH member tokens: ``membersVersion`` and ``membersUpdatedAfter``.

    Unlike :func:`strip_member_version_tokens` (which keeps ``membersUpdatedAfter``
    and therefore leaves the backend in *delta* mode), this removes the delta
    watermark too, so ``getSyncData`` returns the FULL member list. Used to
    rebuild a local member cache that was emptied without clearing its version
    tokens (hard reset, schema migration, manual wipe)."""
    out: dict[str, str] = {}
    for key, value in (tokens or {}).items():
        if key in ("membersVersion", "membersUpdatedAfter") or value is None:
            continue
        out[str(key)] = str(value)
    return out


def strip_device_version_tokens(tokens: dict[str, Any] | None) -> dict[str, str]:
    """Drop the devicesVersion token so the backend must return full device
    state on the next getSyncData call. Used by the UI's manual "refresh
    favorites" action to work around the backend not bumping devicesVersion
    when a preset's favoriteEnabled flips."""
    out: dict[str, str] = {}
    for key, value in (tokens or {}).items():
        if key == "devicesVersion" or value is None:
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
    force_device_refresh = False
    if isinstance(trigger_hint, Mapping):
        entity_type = str(
            trigger_hint.get("entityType") or trigger_hint.get("entity_type") or ""
        ).strip().upper()
        force_device_refresh = bool(
            trigger_hint.get("forceDeviceRefresh")
            or trigger_hint.get("force_device_refresh")
        )

    if entity_type == "ACTIVE_MEMBERSHIP":
        stripped = strip_member_version_tokens(normalized)
        import logging as _log
        _log.getLogger(__name__).info(
            "[SYNC-DEBUG] trigger_hint=%s → stripped membersVersion (had=%s now=%s)",
            dict(trigger_hint) if trigger_hint else None,
            "membersVersion" in normalized,
            "membersVersion" in stripped,
        )
        return stripped
    if force_device_refresh or entity_type in ("DEVICE", "DOOR_PRESET", "FAVORITE"):
        stripped = strip_device_version_tokens(normalized)
        import logging as _log
        _log.getLogger(__name__).info(
            "[SYNC-DEBUG] trigger_hint=%s → stripped devicesVersion (had=%s now=%s) "
            "force=%s entity=%s",
            dict(trigger_hint) if trigger_hint else None,
            "devicesVersion" in normalized,
            "devicesVersion" in stripped,
            force_device_refresh,
            entity_type,
        )
        return stripped
    return normalized


# ── Member-cache integrity self-heal ─────────────────────────────────────────
# Guards against a local ``sync_users`` table that was emptied (hard reset,
# schema migration, manual wipe) while its ``sync_version_tokens`` survived.
# When that happens the stored ``membersVersion`` still matches the backend, so
# every sync returns ``refreshMembers=false`` / a tiny delta and the cache never
# refills — leaving the operator stuck at a handful of users. We detect the gap
# by comparing the local row count to the member count the backend encoded in
# the ``membersVersion`` token, and force a full refresh when too many are
# missing.
# A genuinely stuck cache is always a tiny fraction of the real member count
# (it wiped to ~0 and only re-accrues churn), so a conservative 50% floor catches
# every real case while never tripping on a healthy cache — where the only gap is
# the handful of members filtered client-side (null user/membership) — and so
# never forces a heavy full sync every cycle.
MEMBER_CACHE_HEAL_MIN_EXPECTED = 50
MEMBER_CACHE_HEAL_RATIO = 0.5


def member_count_from_token(members_version: Any) -> int | None:
    """Return the member count the backend encoded in a ``membersVersion`` token.

    The backend builds it as ``"<memberCount>:<maxUpdated>:<fpCount>:<maxFpUpdated>"``
    (``GymAccessController.computeMembersVersion``). Returns the leading count, or
    ``None`` when the token is absent or unparseable."""
    if members_version in (None, ""):
        return None
    try:
        return int(str(members_version).split(":", 1)[0])
    except (TypeError, ValueError):
        return None


def member_cache_is_stale(
    local_count: int,
    members_version: Any,
    *,
    min_expected: int = MEMBER_CACHE_HEAL_MIN_EXPECTED,
    ratio: float = MEMBER_CACHE_HEAL_RATIO,
) -> bool:
    """True when the local member cache is far smaller than the token claims.

    Returns ``False`` when the token is missing/unparseable or the backend member
    count is below ``min_expected`` (small gyms / first sync), so a healthy cache
    (``local`` ≈ ``expected``) never trips it. A handful of members legitimately
    filtered client-side stays well above ``ratio`` and is not treated as stale."""
    expected = member_count_from_token(members_version)
    if expected is None or expected < min_expected:
        return False
    return local_count < expected * ratio

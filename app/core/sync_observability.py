from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Mapping


@dataclass(frozen=True)
class SyncTriggerContext:
    run_type: str
    trigger_source: str
    trigger_hint: Dict[str, Any] | None = None


def resolve_sync_context(
    *,
    pending: SyncTriggerContext | None,
    startup_pending: bool,
) -> tuple[SyncTriggerContext, bool]:
    if pending is not None:
        return pending, False
    if startup_pending:
        return SyncTriggerContext(run_type="PERIODIC", trigger_source="STARTUP"), False
    return SyncTriggerContext(run_type="PERIODIC", trigger_source="TIMER"), False


def serialize_trigger_hint(trigger_hint: Mapping[str, Any] | None) -> str | None:
    if not trigger_hint:
        return None
    return json.dumps(dict(trigger_hint), ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def build_sync_response_summary(
    *,
    data: Mapping[str, Any],
    refresh: Mapping[str, Any],
    new_tokens: Mapping[str, Any] | None,
) -> Dict[str, Any]:
    users = data.get("users")
    devices = data.get("devices")
    valid_member_ids = data.get("validMemberIds")
    return {
        "refresh": {
            "members": bool(refresh.get("members")),
            "devices": bool(refresh.get("devices")),
            "credentials": bool(refresh.get("credentials")),
            "settings": bool(refresh.get("settings")),
        },
        "membersDeltaMode": bool(data.get("membersDeltaMode")),
        "usersCount": len(users) if isinstance(users, list) else 0,
        "devicesCount": len(devices) if isinstance(devices, list) else 0,
        "validMemberIdsCount": len(valid_member_ids) if isinstance(valid_member_ids, list) else 0,
        "newTokens": dict(new_tokens or {}),
    }

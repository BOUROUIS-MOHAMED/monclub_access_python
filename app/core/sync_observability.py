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


def is_explicit_user_sync(context: SyncTriggerContext | None) -> bool:
    """True when a sync was explicitly forced by a person, as opposed to an automatic trigger.

    Explicit (push allowed even in manual sync mode):
      • the dashboard "Sync data" button   → SYNC_NOW_API + trigger_hint {"reason": "user-sync"}
      • the scheduled daily 22:00 auto-sync → SYNC_NOW_API + trigger_hint {"reason": "daily-auto-sync"}
      • a HARD_RESET maintenance action     → SYNC_NOW_API + run_type HARD_RESET / hint hardReset

    Automatic (suppressed in manual sync mode):
      • TIMER / STARTUP (periodic), CHANGE_DETECTOR, AUTH_LOGIN, FAST_PATCH_BUNDLE, and the
        dashboard's per-edit auto-dispatch (SYNC_NOW_API carrying an entity hint, no marker).
    """
    if context is None:
        return False
    source = str(getattr(context, "trigger_source", "") or "").strip().upper()
    if source != "SYNC_NOW_API":
        return False
    run_type = str(getattr(context, "run_type", "") or "").strip().upper()
    hint = context.trigger_hint if isinstance(getattr(context, "trigger_hint", None), dict) else {}
    reason = str(hint.get("reason") or "").strip().lower()
    return (
        reason in ("user-sync", "daily-auto-sync")
        or run_type == "HARD_RESET"
        or bool(hint.get("hardReset"))
    )


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

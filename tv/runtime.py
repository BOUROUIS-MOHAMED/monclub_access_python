"""TV runtime boundary for standalone and transitional combined mode."""

from __future__ import annotations

import threading
from typing import Any, Dict

from app.core.tv_local_cache import (
    ensure_tv_local_schema,
    run_tv_deployment_preflight,
    run_tv_startup_reconciliation,
)


_TV_RUNTIME_STATE_ATTR = "_tv_runtime_state"


def attach_tv_runtime(app: Any) -> Dict[str, Any]:
    """Ensure the app has TV-owned runtime bootstrap state."""

    state = getattr(app, _TV_RUNTIME_STATE_ATTR, None)
    if isinstance(state, dict):
        return state

    state = {
        "lock": threading.Lock(),
        "startup_started": False,
        "lastTriggerSource": None,
        "lastPreflight": None,
        "lastStartupResult": None,
        "lastError": None,
    }
    setattr(app, _TV_RUNTIME_STATE_ATTR, state)
    return state


def get_tv_runtime_state(app: Any) -> Dict[str, Any]:
    return attach_tv_runtime(app)


def start_tv_runtime(app: Any, *, trigger_source: str = "TV_PROCESS_START") -> bool:
    """Kick off TV startup hardening from a TV-owned boundary module."""

    state = attach_tv_runtime(app)
    lock = state["lock"]
    with lock:
        if state["startup_started"]:
            return False
        state["startup_started"] = True
        state["lastTriggerSource"] = trigger_source
        state["lastError"] = None

    def _run() -> None:
        try:
            ensure_tv_local_schema()
            preflight = run_tv_deployment_preflight(include_query_checks=False)
            state["lastPreflight"] = preflight
            try:
                app.logger.info(
                    "TV preflight at startup: status=%s blockers=%s warnings=%s",
                    preflight.get("status"),
                    len(preflight.get("blockers") or []),
                    len(preflight.get("warnings") or []),
                )
            except Exception:
                pass

            if not bool(preflight.get("ok")):
                try:
                    app.logger.error(
                        "TV startup reconciliation skipped due to preflight blockers: %s",
                        preflight.get("blockers"),
                    )
                except Exception:
                    pass
                return

            result = run_tv_startup_reconciliation(trigger_source=trigger_source)
            state["lastStartupResult"] = result
            try:
                if bool(result.get("ok")):
                    app.logger.info(
                        "TV startup reconciliation completed: status=%s failedPhases=%s",
                        result.get("status"),
                        result.get("failedPhaseCount"),
                    )
                else:
                    app.logger.warning("TV startup reconciliation blocked/failed: %s", result)
            except Exception:
                pass
        except Exception as exc:
            state["lastError"] = str(exc)
            try:
                app.logger.exception("TV startup reconciliation error: %s", exc)
            except Exception:
                pass

    threading.Thread(target=_run, daemon=True, name="tv-startup-reconciliation").start()
    return True


def schedule_tv_shell_startup(app: Any) -> None:
    """Schedule standalone TV shell startup work."""

    app.after(200, app.start_local_api_server)
    app.after(450, lambda: app._ensure_update_manager_started(check_now=True))
    app.after(900, app._launch_tauri_ui)


def attach_combined_tv_runtime(app: Any) -> Dict[str, Any]:
    return attach_tv_runtime(app)


def get_combined_tv_runtime_state(app: Any) -> Dict[str, Any]:
    return get_tv_runtime_state(app)


def start_combined_tv_runtime(app: Any, *, trigger_source: str = "ACCESS_LOCAL_API_START") -> bool:
    return start_tv_runtime(app, trigger_source=trigger_source)


__all__ = [
    "attach_tv_runtime",
    "attach_combined_tv_runtime",
    "get_tv_runtime_state",
    "get_combined_tv_runtime_state",
    "schedule_tv_shell_startup",
    "start_tv_runtime",
    "start_combined_tv_runtime",
]

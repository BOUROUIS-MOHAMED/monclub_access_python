"""Access runtime boundary for the current combined implementation."""

from __future__ import annotations

from typing import Any

from app.core.device_sync import DeviceSyncEngine
from app.core.realtime_agent import AgentRealtimeEngine
from app.core.settings_reader import get_backend_global_settings
from access.update_runtime import UpdateManager, UpdateStatus


def schedule_access_shell_startup(app: Any) -> None:
    """Schedule Access-owned startup work for the current combined shell."""

    app.after(200, app._poll_logs)
    app.after(400, app.start_local_api_server)
    app.after(500, app.reschedule_sync_timer)
    app.after(650, lambda: app._ensure_update_manager_started(check_now=True))
    app.after(700, app.evaluate_access_and_redirect)
    app.after(1500, app._launch_tauri_ui)
    app.after(5000, app.start_expiry_warning_scheduler)

__all__ = [
    "AgentRealtimeEngine",
    "DeviceSyncEngine",
    "UpdateManager",
    "UpdateStatus",
    "get_backend_global_settings",
    "schedule_access_shell_startup",
]

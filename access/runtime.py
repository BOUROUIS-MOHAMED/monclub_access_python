"""Access runtime boundary for the current combined implementation."""

from __future__ import annotations

from typing import Any

from app.core.device_attendance import DeviceAttendanceMaintenanceEngine
from app.core.device_sync import DeviceSyncEngine
from app.core.realtime_agent import AgentRealtimeEngine
from app.core.settings_reader import get_backend_global_settings
from access.update_runtime import UpdateManager, UpdateStatus


def _start_optional_content_sync_scheduler(_app: Any) -> None:
    try:
        from app.core.optional_content_sync import get_optional_content_sync_scheduler
        get_optional_content_sync_scheduler().start()
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning(
            "[runtime] Failed to start optional content sync scheduler: %s", exc
        )


def schedule_access_shell_startup(app: Any) -> None:
    """Schedule Access-owned startup work for the current combined shell."""

    app.after(200, app._poll_logs)
    app.after(400, app.start_local_api_server)
    app.after(500, app.reschedule_sync_timer)
    app.after(650, lambda: app._ensure_update_manager_started(check_now=True))
    app.after(700, app.evaluate_access_and_redirect)
    app.after(1500, app._launch_tauri_ui)
    app.after(5000, app.start_expiry_warning_scheduler)
    app.after(10000, lambda: _start_optional_content_sync_scheduler(app))

__all__ = [
    "AgentRealtimeEngine",
    "DeviceAttendanceMaintenanceEngine",
    "DeviceSyncEngine",
    "UpdateManager",
    "UpdateStatus",
    "get_backend_global_settings",
    "schedule_access_shell_startup",
]

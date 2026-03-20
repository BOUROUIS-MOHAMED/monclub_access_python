"""TV bootstrap boundary for standalone and transitional combined mode."""

from __future__ import annotations

from shared.contracts import DesktopComponentDescriptor
from tv.storage import get_tv_storage_paths
from tv.runtime import (
    attach_combined_tv_runtime,
    attach_tv_runtime,
    get_combined_tv_runtime_state,
    get_tv_runtime_state,
    schedule_tv_shell_startup,
    start_combined_tv_runtime,
    start_tv_runtime,
)


def describe_tv_component() -> DesktopComponentDescriptor:
    paths = get_tv_storage_paths()
    return DesktopComponentDescriptor(
        component_id="tv",
        display_name="MonClub TV",
        entry_module="tv.main",
        current_runtime_db_path=paths.current_runtime_db_path,
        future_runtime_db_path=paths.future_db_path,
        owned_capabilities=(
            "monitor-inventory",
            "screen-bindings",
            "snapshot-cache",
            "player-runtime",
            "tv-support-observability",
            "tv-ui-shell",
            "tv-local-api",
        ),
        notes=(
            "Phase 3 adds a real standalone TV process entry through tv.main.",
            "Phase 4 activates tv.db as the live TV runtime database.",
            "Phase 6 activates tv/config.json and a TV-owned update runtime wrapper.",
        ),
    )


def configure_combined_tv_runtime(app) -> None:
    """Attach TV-owned combined-mode state without starting a new process."""

    attach_combined_tv_runtime(app)


def create_tv_app():
    from tv.app import TvApp

    return TvApp()


def run_tv_app() -> None:
    app = create_tv_app()
    app.mainloop()


__all__ = [
    "attach_tv_runtime",
    "attach_combined_tv_runtime",
    "configure_combined_tv_runtime",
    "create_tv_app",
    "describe_tv_component",
    "get_combined_tv_runtime_state",
    "get_tv_runtime_state",
    "run_tv_app",
    "schedule_tv_shell_startup",
    "start_combined_tv_runtime",
    "start_tv_runtime",
]

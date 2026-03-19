"""Phase 1 Access bootstrap facade."""

from __future__ import annotations

from shared.contracts import DesktopComponentDescriptor
from access.storage import get_access_storage_paths


def describe_access_component() -> DesktopComponentDescriptor:
    paths = get_access_storage_paths()
    return DesktopComponentDescriptor(
        component_id="access",
        display_name="MonClub Access",
        entry_module="access.main",
        current_runtime_db_path=paths.current_runtime_db_path,
        future_runtime_db_path=paths.future_db_path,
        owned_capabilities=(
            "device-sync",
            "realtime-agent",
            "offline-creations",
            "access-history",
            "access-ui-shell",
            "local-api-shell",
        ),
        notes=(
            "Phase 1 keeps the current combined runtime behavior.",
            "The standalone Access process continues to host the existing local API and Tauri launcher.",
        ),
    )


def create_access_app():
    from app.ui.app import MainApp

    return MainApp()


def run_access_app() -> None:
    app = create_access_app()
    app.mainloop()


__all__ = ["create_access_app", "describe_access_component", "run_access_app"]


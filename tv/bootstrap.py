"""Phase 1 TV bootstrap scaffold."""

from __future__ import annotations

from shared.contracts import DesktopComponentDescriptor
from tv.storage import get_tv_storage_paths


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
        ),
        notes=(
            "Phase 1 only scaffolds the standalone TV entry.",
            "The live TV runtime is still hosted inside the current Access process until later phases.",
        ),
    )


def run_tv_app() -> None:
    descriptor = describe_tv_component()
    print(
        f"{descriptor.display_name} bootstrap is scaffolded in Phase 1. "
        "The standalone TV runtime is intentionally deferred to a later migration phase."
    )


__all__ = ["describe_tv_component", "run_tv_app"]


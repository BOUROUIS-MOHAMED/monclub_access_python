"""Access storage metadata for the live split-runtime layout."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from shared.desktop_paths import get_desktop_path_layout


@dataclass(frozen=True)
class AccessStoragePaths:
    current_runtime_db_path: Path
    future_db_path: Path
    current_config_path: Path
    future_config_path: Path
    data_dir: Path


def get_access_storage_paths() -> AccessStoragePaths:
    layout = get_desktop_path_layout()
    return AccessStoragePaths(
        current_runtime_db_path=layout.access_db_path,
        future_db_path=layout.access_db_path,
        current_config_path=layout.access_config_path,
        future_config_path=layout.access_config_path,
        data_dir=layout.access_data_dir,
    )


def current_access_runtime_db_path() -> Path:
    return get_access_storage_paths().current_runtime_db_path


__all__ = ["AccessStoragePaths", "current_access_runtime_db_path", "get_access_storage_paths"]

"""Split-ready TV storage metadata."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from shared.desktop_paths import get_desktop_path_layout


@dataclass(frozen=True)
class TvStoragePaths:
    current_runtime_db_path: Path
    future_db_path: Path
    current_config_path: Path
    future_config_path: Path
    data_dir: Path


def get_tv_storage_paths() -> TvStoragePaths:
    layout = get_desktop_path_layout()
    return TvStoragePaths(
        current_runtime_db_path=layout.legacy_combined_db_path,
        future_db_path=layout.tv_db_path,
        current_config_path=layout.legacy_config_path,
        future_config_path=layout.tv_config_path,
        data_dir=layout.tv_data_dir,
    )


__all__ = ["TvStoragePaths", "get_tv_storage_paths"]


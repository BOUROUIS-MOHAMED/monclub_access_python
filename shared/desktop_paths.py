"""Split-ready desktop path metadata for Access/TV separation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.core.utils import (
    ACCESS_CONFIG_PATH,
    ACCESS_DATA_DIR,
    ACCESS_DB_PATH,
    APP_NAME,
    BACKUP_DIR,
    CACHE_DIR,
    CONFIG_PATH,
    DATA_DIR,
    DATA_ROOT,
    DB_PATH,
    IMAGES_CACHE_DIR,
    LEGACY_APP_DIR,
    LEGACY_DATA_DIR,
    LOG_DIR,
    SHARED_DATA_DIR,
    SHARED_INSTALL_CONFIG_PATH,
    TV_CONFIG_PATH,
    TV_DATA_DIR,
    TV_DB_PATH,
    VERSIONS_DIR,
    runtime_base_dir,
    runtime_internal_dir,
)


@dataclass(frozen=True)
class DesktopPathLayout:
    app_name: str
    repo_root: Path
    repo_legacy_data_dir: Path
    runtime_root: Path
    runtime_internal_root: Path
    data_root: Path
    legacy_data_dir: Path
    legacy_logs_dir: Path
    legacy_cache_dir: Path
    legacy_images_cache_dir: Path
    legacy_backup_dir: Path
    legacy_versions_dir: Path
    legacy_config_path: Path
    legacy_combined_db_path: Path
    access_data_dir: Path
    access_config_path: Path
    access_db_path: Path
    tv_data_dir: Path
    tv_config_path: Path
    tv_db_path: Path
    shared_data_dir: Path
    shared_install_config_path: Path


def get_desktop_path_layout() -> DesktopPathLayout:
    return DesktopPathLayout(
        app_name=APP_NAME,
        repo_root=LEGACY_APP_DIR,
        repo_legacy_data_dir=LEGACY_DATA_DIR,
        runtime_root=runtime_base_dir(),
        runtime_internal_root=runtime_internal_dir(),
        data_root=DATA_ROOT,
        legacy_data_dir=DATA_DIR,
        legacy_logs_dir=LOG_DIR,
        legacy_cache_dir=CACHE_DIR,
        legacy_images_cache_dir=IMAGES_CACHE_DIR,
        legacy_backup_dir=BACKUP_DIR,
        legacy_versions_dir=VERSIONS_DIR,
        legacy_config_path=CONFIG_PATH,
        legacy_combined_db_path=DB_PATH,
        access_data_dir=ACCESS_DATA_DIR,
        access_config_path=ACCESS_CONFIG_PATH,
        access_db_path=ACCESS_DB_PATH,
        tv_data_dir=TV_DATA_DIR,
        tv_config_path=TV_CONFIG_PATH,
        tv_db_path=TV_DB_PATH,
        shared_data_dir=SHARED_DATA_DIR,
        shared_install_config_path=SHARED_INSTALL_CONFIG_PATH,
    )


__all__ = ["DesktopPathLayout", "get_desktop_path_layout"]


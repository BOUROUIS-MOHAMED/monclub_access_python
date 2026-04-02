"""TV-owned persisted config facade."""

from __future__ import annotations

from shared.api.monclub_api import ApiEndpoints
from shared.config import (
    TV_CONFIG_FIELDS,
    AppConfig,
    ConfigEnvelope,
    TvConfigSection,
    apply_component_config_patch,
    get_component_config_status,
    load_component_app_config,
    serialize_component_config,
    split_config,
    save_component_app_config,
)


def load_tv_app_config() -> AppConfig:
    return load_component_app_config("tv")


def save_tv_app_config(cfg: AppConfig) -> None:
    save_component_app_config("tv", cfg)


def load_tv_config(cfg: AppConfig | ConfigEnvelope | None = None) -> TvConfigSection:
    return split_config(cfg).tv


def load_tv_config_envelope(cfg: AppConfig | ConfigEnvelope | None = None) -> ConfigEnvelope:
    return split_config(cfg)


def serialize_tv_config(cfg: AppConfig | ConfigEnvelope | None = None):
    return serialize_component_config("tv", cfg)


def apply_tv_config_patch(cfg: AppConfig, patch):
    return apply_component_config_patch("tv", cfg, patch)


def get_tv_config_status():
    return get_component_config_status("tv")


def build_tv_api_endpoints(cfg: AppConfig | ConfigEnvelope | None = None) -> ApiEndpoints:
    """Build TV-specific API endpoints from centralized constants (app/core/app_const.py)."""
    from app.core.app_const import (
        API_LOGIN_URL,
        API_LATEST_RELEASE_URL,
        API_TV_SCREENS_URL,
        API_TV_SCREEN_BY_ID_URL,
        API_TV_SCREEN_CONTENT_PLAN_URL,
        API_TV_SCREEN_SNAPSHOTS_URL,
        API_TV_SNAPSHOT_LATEST_URL,
        API_TV_SNAPSHOT_BY_ID_URL,
        API_TV_SNAPSHOT_MANIFEST_URL,
        API_TV_AD_TASKS_FETCH_URL,
        API_TV_AD_TASK_CONFIRM_READY_URL,
        API_TV_AD_TASK_SUBMIT_PROOF_URL,
    )
    return ApiEndpoints(
        login_url=API_LOGIN_URL,
        sync_url="",
        create_user_fingerprint_url="",
        latest_release_url=API_LATEST_RELEASE_URL,
        access_create_membership_url="",
        access_create_account_membership_url="",
        tv_screens_url=API_TV_SCREENS_URL,
        tv_screen_by_id_url=API_TV_SCREEN_BY_ID_URL,
        tv_screen_content_plan_url=API_TV_SCREEN_CONTENT_PLAN_URL,
        tv_screen_snapshots_url=API_TV_SCREEN_SNAPSHOTS_URL,
        tv_snapshot_latest_url=API_TV_SNAPSHOT_LATEST_URL,
        tv_snapshot_by_id_url=API_TV_SNAPSHOT_BY_ID_URL,
        tv_snapshot_manifest_url=API_TV_SNAPSHOT_MANIFEST_URL,
        tv_ad_tasks_fetch_url=API_TV_AD_TASKS_FETCH_URL,
        tv_ad_task_confirm_ready_url=API_TV_AD_TASK_CONFIRM_READY_URL,
        tv_ad_task_submit_proof_url=API_TV_AD_TASK_SUBMIT_PROOF_URL,
    )


__all__ = [
    "AppConfig",
    "ConfigEnvelope",
    "TV_CONFIG_FIELDS",
    "TvConfigSection",
    "apply_tv_config_patch",
    "build_tv_api_endpoints",
    "get_tv_config_status",
    "load_tv_app_config",
    "load_tv_config",
    "load_tv_config_envelope",
    "save_tv_app_config",
    "serialize_tv_config",
]

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
    section = load_tv_config(cfg)
    return ApiEndpoints(
        login_url="",
        sync_url="",
        create_user_fingerprint_url="",
        latest_release_url=section.api_latest_release_url,
        access_create_membership_url="",
        access_create_account_membership_url="",
        tv_snapshot_latest_url=section.api_tv_snapshot_latest_url,
        tv_snapshot_manifest_url=section.api_tv_snapshot_manifest_url,
        tv_ad_tasks_fetch_url=section.api_tv_ad_tasks_fetch_url,
        tv_ad_task_confirm_ready_url=section.api_tv_ad_task_confirm_ready_url,
        tv_ad_task_submit_proof_url=section.api_tv_ad_task_submit_proof_url,
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

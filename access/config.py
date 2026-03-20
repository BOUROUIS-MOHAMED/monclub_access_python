"""Access-owned persisted config facade."""

from __future__ import annotations

from shared.api.monclub_api import ApiEndpoints
from shared.config import (
    ACCESS_CONFIG_FIELDS,
    AppConfig,
    ConfigEnvelope,
    AccessConfigSection,
    apply_component_config_patch,
    get_component_config_status,
    load_component_app_config,
    serialize_component_config,
    split_config,
    save_component_app_config,
)


def load_access_app_config() -> AppConfig:
    return load_component_app_config("access")


def save_access_app_config(cfg: AppConfig) -> None:
    save_component_app_config("access", cfg)


def load_access_config(cfg: AppConfig | ConfigEnvelope | None = None) -> AccessConfigSection:
    return split_config(cfg).access


def load_access_config_envelope(cfg: AppConfig | ConfigEnvelope | None = None) -> ConfigEnvelope:
    return split_config(cfg)


def serialize_access_config(cfg: AppConfig | ConfigEnvelope | None = None):
    return serialize_component_config("access", cfg)


def apply_access_config_patch(cfg: AppConfig, patch):
    return apply_component_config_patch("access", cfg, patch)


def get_access_config_status():
    return get_component_config_status("access")


def build_access_api_endpoints(cfg: AppConfig | ConfigEnvelope | None = None) -> ApiEndpoints:
    section = load_access_config(cfg)
    return ApiEndpoints(
        login_url=section.api_login_url,
        sync_url=section.api_sync_url,
        create_user_fingerprint_url=section.api_create_user_fingerprint_url,
        latest_release_url=section.api_latest_release_url,
        access_create_membership_url=section.api_access_create_membership_url,
        access_create_account_membership_url=section.api_access_create_account_membership_url,
        tv_snapshot_latest_url="",
        tv_snapshot_manifest_url="",
        tv_ad_tasks_fetch_url="",
        tv_ad_task_confirm_ready_url="",
        tv_ad_task_submit_proof_url="",
    )


__all__ = [
    "ACCESS_CONFIG_FIELDS",
    "AppConfig",
    "AccessConfigSection",
    "ConfigEnvelope",
    "apply_access_config_patch",
    "build_access_api_endpoints",
    "get_access_config_status",
    "load_access_app_config",
    "load_access_config",
    "load_access_config_envelope",
    "save_access_app_config",
    "serialize_access_config",
]

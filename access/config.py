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
    """Build Access-specific API endpoints from centralized constants (app/core/app_const.py)."""
    from app.core.app_const import (
        API_LOGIN_URL,
        API_SYNC_URL,
        API_CREATE_USER_FINGERPRINT_URL,
        API_LATEST_RELEASE_URL,
        API_ACCESS_CREATE_MEMBERSHIP_URL,
        API_ACCESS_CREATE_ACCOUNT_MEMBERSHIP_URL,
        API_OPTIONAL_CONTENT_SYNC_URL,
    )
    return ApiEndpoints(
        login_url=API_LOGIN_URL,
        sync_url=API_SYNC_URL,
        create_user_fingerprint_url=API_CREATE_USER_FINGERPRINT_URL,
        latest_release_url=API_LATEST_RELEASE_URL,
        access_create_membership_url=API_ACCESS_CREATE_MEMBERSHIP_URL,
        access_create_account_membership_url=API_ACCESS_CREATE_ACCOUNT_MEMBERSHIP_URL,
        tv_snapshot_latest_url="",
        tv_snapshot_manifest_url="",
        tv_ad_tasks_fetch_url="",
        tv_ad_task_confirm_ready_url="",
        tv_ad_task_submit_proof_url="",
        optional_content_sync_url=API_OPTIONAL_CONTENT_SYNC_URL,
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

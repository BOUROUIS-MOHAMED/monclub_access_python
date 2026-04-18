"""Shared config helpers for split Access/TV persisted configuration."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional

from app.core.config import AppConfig as LegacyAppConfig
from app.core.utils import load_json, save_json
from shared.api.monclub_api import ApiEndpoints
from shared.component_identity import get_component_identity
from shared.desktop_paths import get_desktop_path_layout
from shared.runtime_support import ensure_dirs

AppConfig = LegacyAppConfig
ConfigComponent = Literal["access", "tv"]

SHARED_CONFIG_FIELDS: tuple[str, ...] = ()
SHARED_INSTALL_FIELDS = (
    "schema_version",
    "config_mode",
    "migrated_from_legacy_config_at",
    "legacy_config_source_path",
    "installed_components",
    "updater_runtime_mode",
    "ipc_mode",
)

ACCESS_CONFIG_FIELDS = (
    "selected_device_id",
    "data_mode",
    "device_timeout_ms",
    "local_api_enabled",
    "local_api_host",
    "local_api_port",
    "update_enabled",
    "update_platform",
    "update_channel",
    "update_check_interval_sec",
    "update_auto_download_zip",
    "template_version",
    "template_encoding",
    "plcomm_dll_path",
    "zkfp_dll_path",
    "sync_interval_sec",
    "max_login_age_minutes",
    "device_sync_enabled",
    "agent_realtime_enabled",
    "agent_global",
    "agent_devices",
    "tray_enabled",
    "minimize_to_tray_on_close",
    "start_minimized_to_tray",
    "start_on_system_startup",
    "login_email",
    "log_level",
    "push_success_sound_enabled",
    "sync_success_sound_enabled",
    "push_success_animation_enabled",
    "sync_success_animation_enabled",
    "push_success_repeat_mode",
    "push_success_sound_source",
    "sync_success_sound_source",
    "push_success_custom_sound_path",
    "sync_success_custom_sound_path",
    # Card scanner (SCR100 / USB HID)
    "scanner_mode",
    "scanner_network_ip",
    "scanner_network_port",
    "scanner_network_timeout_ms",
    "scanner_usb_device_path",
    "scan_shortcut",
    # Favorites overlay
    "favorites_overlay_anchor",
    "favorites_overlay_show_all_presets",
)

TV_CONFIG_FIELDS = (
    "local_api_enabled",
    "local_api_host",
    "local_api_port",
    "update_enabled",
    "update_platform",
    "update_channel",
    "update_check_interval_sec",
    "update_auto_download_zip",
    "minimize_to_tray_on_close",
    "start_on_system_startup",
    "autostart_bindings_enabled",
    "log_level",
)

# TV_COMPAT_OVERLAY_FIELDS: URL fields were removed — no overlay needed anymore.
TV_COMPAT_OVERLAY_FIELDS: tuple[str, ...] = ()


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _default_installed_components() -> Dict[str, bool]:
    return {"access": True, "tv": True}


@dataclass(frozen=True)
class SharedConfigSection:
    schema_version: int = 1
    config_mode: str = "SPLIT"
    migrated_from_legacy_config_at: str = ""
    legacy_config_source_path: str = ""
    installed_components: Dict[str, bool] = field(default_factory=_default_installed_components)
    updater_runtime_mode: str = "SHARED_ENGINE_SEPARATE_STATE"
    ipc_mode: str = "NONE"


@dataclass(frozen=True)
class AccessConfigSection:
    selected_device_id: Optional[int]
    data_mode: str
    device_timeout_ms: int
    local_api_enabled: bool
    local_api_host: str
    local_api_port: int
    update_enabled: bool
    update_platform: str
    update_channel: str
    update_check_interval_sec: int
    update_auto_download_zip: bool
    template_version: int
    template_encoding: str
    plcomm_dll_path: str
    zkfp_dll_path: str
    sync_interval_sec: int
    max_login_age_minutes: int
    device_sync_enabled: bool
    agent_realtime_enabled: bool
    agent_global: Dict[str, Any] = field(default_factory=dict)
    agent_devices: Dict[str, Any] = field(default_factory=dict)
    tray_enabled: bool = True
    minimize_to_tray_on_close: bool = True
    start_minimized_to_tray: bool = False
    start_on_system_startup: bool = False
    login_email: str = ""
    log_level: str = "DEBUG"
    push_success_sound_enabled: bool = True
    sync_success_sound_enabled: bool = True
    push_success_animation_enabled: bool = True
    sync_success_animation_enabled: bool = True
    push_success_repeat_mode: str = "per_device"
    push_success_sound_source: str = "default"
    sync_success_sound_source: str = "default"
    push_success_custom_sound_path: str = ""
    sync_success_custom_sound_path: str = ""
    scanner_mode: str = "zkemkeeper"
    scanner_network_ip: str = ""
    scanner_network_port: int = 4370
    scanner_network_timeout_ms: int = 20000
    scanner_usb_device_path: str = ""
    scan_shortcut: str = "CTRL_CAPSLOCK"   # Global shortcut to trigger SCR100 card scan
    favorites_overlay_anchor: str = "right-center"
    favorites_overlay_show_all_presets: bool = False


@dataclass(frozen=True)
class TvConfigSection:
    local_api_enabled: bool
    local_api_host: str
    local_api_port: int
    update_enabled: bool
    update_platform: str
    update_channel: str
    update_check_interval_sec: int
    update_auto_download_zip: bool
    minimize_to_tray_on_close: bool = True
    start_on_system_startup: bool = False
    autostart_bindings_enabled: bool = False
    log_level: str = "DEBUG"


@dataclass(frozen=True)
class ConfigEnvelope:
    raw: AppConfig
    shared: SharedConfigSection
    access: AccessConfigSection
    tv: TvConfigSection


def _component_config_path(component: ConfigComponent):
    layout = get_desktop_path_layout()
    return layout.access_config_path if component == "access" else layout.tv_config_path


def _component_fields(component: ConfigComponent) -> tuple[str, ...]:
    return ACCESS_CONFIG_FIELDS if component == "access" else TV_CONFIG_FIELDS


def _component_default_config(component: ConfigComponent) -> AppConfig:
    cfg = AppConfig()
    identity = get_component_identity(component)
    cfg.local_api_host = identity.default_local_api_host
    cfg.local_api_port = identity.default_local_api_port
    return cfg


def _legacy_component_overrides(component: ConfigComponent, legacy_raw: Dict[str, Any]) -> Dict[str, Any]:
    payload = _subset_from_mapping(legacy_raw, _component_fields(component))
    # The legacy config was Access-oriented, so copying its local API port into TV
    # would recreate a port collision after the split.
    if component == "tv":
        payload.pop("local_api_port", None)
    return payload


def _load_legacy_raw() -> Dict[str, Any]:
    layout = get_desktop_path_layout()
    raw = load_json(layout.legacy_config_path, default={})
    return raw if isinstance(raw, dict) else {}


def _subset_from_mapping(source: Dict[str, Any], fields: tuple[str, ...]) -> Dict[str, Any]:
    return {name: source[name] for name in fields if name in source}


def _subset_from_cfg(cfg: AppConfig, fields: tuple[str, ...]) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    for name in fields:
        try:
            payload[name] = getattr(cfg, name)
        except Exception:
            pass
    return payload


def _normalize_shared_install(raw: Dict[str, Any] | None = None) -> SharedConfigSection:
    data = raw or {}
    installed = data.get("installed_components")
    if not isinstance(installed, dict):
        installed = _default_installed_components()
    return SharedConfigSection(
        schema_version=int(data.get("schema_version") or 1),
        config_mode=str(data.get("config_mode") or "SPLIT"),
        migrated_from_legacy_config_at=str(data.get("migrated_from_legacy_config_at") or ""),
        legacy_config_source_path=str(data.get("legacy_config_source_path") or ""),
        installed_components={
            "access": bool(installed.get("access", True)),
            "tv": bool(installed.get("tv", True)),
        },
        updater_runtime_mode=str(data.get("updater_runtime_mode") or "SHARED_ENGINE_SEPARATE_STATE"),
        ipc_mode=str(data.get("ipc_mode") or "NONE"),
    )


def _write_component_defaults_if_missing(component: ConfigComponent, *, legacy_raw: Dict[str, Any]) -> bool:
    path = _component_config_path(component)
    if path.exists():
        return False
    defaults = _component_default_config(component)
    payload = _subset_from_cfg(defaults, _component_fields(component))
    payload.update(_legacy_component_overrides(component, legacy_raw))
    normalized = AppConfig.from_dict(payload)
    save_json(path, _subset_from_cfg(normalized, _component_fields(component)))
    return True


# One-shot guard: migration only has meaningful work to do on the first call
# per process. Subsequent calls would just re-read and re-validate files that
# haven't changed. Re-running it on every /config GET and PATCH adds ~1 s of
# file I/O on Windows (AV-scanned reads of 4 config files each call).
_MIGRATION_DONE: bool = False


def migrate_split_config_if_needed() -> None:
    global _MIGRATION_DONE
    if _MIGRATION_DONE:
        return

    ensure_dirs()
    layout = get_desktop_path_layout()
    legacy_raw = _load_legacy_raw()

    created_access = _write_component_defaults_if_missing("access", legacy_raw=legacy_raw)
    created_tv = _write_component_defaults_if_missing("tv", legacy_raw=legacy_raw)

    shared_path = layout.shared_install_config_path
    shared_raw = load_json(shared_path, default={})
    shared_exists = isinstance(shared_raw, dict) and bool(shared_raw)
    shared_cfg = _normalize_shared_install(shared_raw if isinstance(shared_raw, dict) else {})

    if (not shared_path.exists()) or (not shared_exists):
        shared_cfg = SharedConfigSection(
            migrated_from_legacy_config_at=_now_utc_iso() if legacy_raw and (created_access or created_tv) else "",
            legacy_config_source_path=str(layout.legacy_config_path) if legacy_raw else "",
        )
        save_json(shared_path, asdict(shared_cfg))
        _MIGRATION_DONE = True
        return

    changed = False
    shared_payload = asdict(shared_cfg)
    if legacy_raw and not shared_cfg.migrated_from_legacy_config_at and (created_access or created_tv):
        shared_payload["migrated_from_legacy_config_at"] = _now_utc_iso()
        shared_payload["legacy_config_source_path"] = str(layout.legacy_config_path)
        changed = True
    if changed:
        save_json(shared_path, shared_payload)

    _MIGRATION_DONE = True


def load_shared_install_config() -> SharedConfigSection:
    migrate_split_config_if_needed()
    raw = load_json(get_desktop_path_layout().shared_install_config_path, default={})
    return _normalize_shared_install(raw if isinstance(raw, dict) else {})


def save_shared_install_config(cfg: SharedConfigSection) -> None:
    migrate_split_config_if_needed()
    save_json(get_desktop_path_layout().shared_install_config_path, asdict(cfg))


def load_component_app_config(component: ConfigComponent) -> AppConfig:
    migrate_split_config_if_needed()
    raw = load_json(_component_config_path(component), default={})
    if not isinstance(raw, dict):
        raw = {}
    payload = _subset_from_cfg(_component_default_config(component), _component_fields(component))
    payload.update(_subset_from_mapping(raw, _component_fields(component)))
    return AppConfig.from_dict(payload)


def save_component_app_config(component: ConfigComponent, cfg: AppConfig) -> None:
    migrate_split_config_if_needed()
    payload = _subset_from_cfg(_component_default_config(component), _component_fields(component))
    payload.update(_subset_from_cfg(cfg, _component_fields(component)))
    normalized = AppConfig.from_dict(payload)
    save_json(
        _component_config_path(component),
        _subset_from_cfg(normalized, _component_fields(component)),
    )


def load_config() -> AppConfig:
    """Compatibility loader that merges split config back into one view."""

    access_cfg = load_component_app_config("access")
    tv_cfg = load_component_app_config("tv")
    merged = access_cfg.to_dict()
    for field_name in TV_COMPAT_OVERLAY_FIELDS:
        merged[field_name] = getattr(tv_cfg, field_name, merged.get(field_name))
    return AppConfig.from_dict(merged)


def save_config(cfg: AppConfig) -> None:
    save_component_app_config("access", cfg)
    save_component_app_config("tv", cfg)


def get_component_config_status(component: ConfigComponent) -> Dict[str, Any]:
    migrate_split_config_if_needed()
    layout = get_desktop_path_layout()
    shared_cfg = load_shared_install_config()
    live_path = _component_config_path(component)
    return {
        "component": component,
        "liveConfigPath": str(live_path),
        "liveConfigExists": live_path.exists(),
        "legacyConfigPath": str(layout.legacy_config_path),
        "legacyConfigExists": layout.legacy_config_path.exists(),
        "sharedInstallConfigPath": str(layout.shared_install_config_path),
        "sharedInstallConfigExists": layout.shared_install_config_path.exists(),
        "configMode": shared_cfg.config_mode,
        "ipcMode": shared_cfg.ipc_mode,
        "updaterRuntimeMode": shared_cfg.updater_runtime_mode,
        "migratedFromLegacyAt": shared_cfg.migrated_from_legacy_config_at,
    }


def _build_access_section_from_cfg(cfg: AppConfig) -> AccessConfigSection:
    return AccessConfigSection(
        selected_device_id=getattr(cfg, "selected_device_id", None),
        data_mode=str(getattr(cfg, "data_mode", "DEVICE") or "DEVICE"),
        device_timeout_ms=int(getattr(cfg, "device_timeout_ms", 5000) or 5000),
        local_api_enabled=bool(getattr(cfg, "local_api_enabled", True)),
        local_api_host=str(getattr(cfg, "local_api_host", "127.0.0.1") or "127.0.0.1"),
        local_api_port=int(getattr(cfg, "local_api_port", 8788) or 8788),
        update_enabled=bool(getattr(cfg, "update_enabled", True)),
        update_platform=str(getattr(cfg, "update_platform", "WINDOWS") or "WINDOWS"),
        update_channel=str(getattr(cfg, "update_channel", "stable") or "stable"),
        update_check_interval_sec=int(getattr(cfg, "update_check_interval_sec", 30) or 30),
        update_auto_download_zip=bool(getattr(cfg, "update_auto_download_zip", True)),
        template_version=int(getattr(cfg, "template_version", 10) or 10),
        template_encoding=str(getattr(cfg, "template_encoding", "base64") or "base64"),
        plcomm_dll_path=str(getattr(cfg, "plcomm_dll_path", "") or ""),
        zkfp_dll_path=str(getattr(cfg, "zkfp_dll_path", "") or ""),
        sync_interval_sec=int(getattr(cfg, "sync_interval_sec", 60) or 60),
        max_login_age_minutes=int(getattr(cfg, "max_login_age_minutes", 43200) or 43200),
        device_sync_enabled=bool(getattr(cfg, "device_sync_enabled", True)),
        agent_realtime_enabled=bool(getattr(cfg, "agent_realtime_enabled", True)),
        agent_global=dict(getattr(cfg, "agent_global", {}) or {}),
        agent_devices=dict(getattr(cfg, "agent_devices", {}) or {}),
        tray_enabled=bool(getattr(cfg, "tray_enabled", True)),
        minimize_to_tray_on_close=bool(getattr(cfg, "minimize_to_tray_on_close", True)),
        start_minimized_to_tray=bool(getattr(cfg, "start_minimized_to_tray", False)),
        start_on_system_startup=bool(getattr(cfg, "start_on_system_startup", False)),
        login_email=str(getattr(cfg, "login_email", "") or ""),
        log_level=str(getattr(cfg, "log_level", "DEBUG") or "DEBUG"),
        push_success_sound_enabled=bool(getattr(cfg, "push_success_sound_enabled", True)),
        sync_success_sound_enabled=bool(getattr(cfg, "sync_success_sound_enabled", True)),
        push_success_animation_enabled=bool(getattr(cfg, "push_success_animation_enabled", True)),
        sync_success_animation_enabled=bool(getattr(cfg, "sync_success_animation_enabled", True)),
        push_success_repeat_mode=str(getattr(cfg, "push_success_repeat_mode", "per_device") or "per_device"),
        push_success_sound_source=str(getattr(cfg, "push_success_sound_source", "default") or "default"),
        sync_success_sound_source=str(getattr(cfg, "sync_success_sound_source", "default") or "default"),
        push_success_custom_sound_path=str(getattr(cfg, "push_success_custom_sound_path", "") or ""),
        sync_success_custom_sound_path=str(getattr(cfg, "sync_success_custom_sound_path", "") or ""),
        scanner_mode=str(getattr(cfg, "scanner_mode", "zkemkeeper") or "zkemkeeper"),
        scanner_network_ip=str(getattr(cfg, "scanner_network_ip", "") or ""),
        scanner_network_port=int(getattr(cfg, "scanner_network_port", 4370) or 4370),
        scanner_network_timeout_ms=int(getattr(cfg, "scanner_network_timeout_ms", 20000) or 20000),
        scanner_usb_device_path=str(getattr(cfg, "scanner_usb_device_path", "") or ""),
        scan_shortcut=str(getattr(cfg, "scan_shortcut", "CTRL_CAPSLOCK") or "CTRL_CAPSLOCK"),
        favorites_overlay_anchor=str(getattr(cfg, "favorites_overlay_anchor", "right-center") or "right-center"),
        favorites_overlay_show_all_presets=bool(getattr(cfg, "favorites_overlay_show_all_presets", False)),
    )


def _build_tv_section_from_cfg(cfg: AppConfig) -> TvConfigSection:
    return TvConfigSection(
        local_api_enabled=bool(getattr(cfg, "local_api_enabled", True)),
        local_api_host=str(getattr(cfg, "local_api_host", "127.0.0.1") or "127.0.0.1"),
        local_api_port=int(getattr(cfg, "local_api_port", 8789) or 8789),
        update_enabled=bool(getattr(cfg, "update_enabled", True)),
        update_platform=str(getattr(cfg, "update_platform", "WINDOWS") or "WINDOWS"),
        update_channel=str(getattr(cfg, "update_channel", "stable") or "stable"),
        update_check_interval_sec=int(getattr(cfg, "update_check_interval_sec", 30) or 30),
        update_auto_download_zip=bool(getattr(cfg, "update_auto_download_zip", True)),
        minimize_to_tray_on_close=bool(getattr(cfg, "minimize_to_tray_on_close", True)),
        start_on_system_startup=bool(getattr(cfg, "start_on_system_startup", False)),
        log_level=str(getattr(cfg, "log_level", "DEBUG") or "DEBUG"),
    )


def _coerce_app_config(cfg: AppConfig | ConfigEnvelope | None = None) -> AppConfig:
    if cfg is None:
        return load_config()
    if isinstance(cfg, ConfigEnvelope):
        return cfg.raw
    return cfg


def split_config(cfg: AppConfig | ConfigEnvelope | None = None) -> ConfigEnvelope:
    if cfg is None:
        access_cfg = load_component_app_config("access")
        tv_cfg = load_component_app_config("tv")
        merged = access_cfg.to_dict()
        for field_name in TV_COMPAT_OVERLAY_FIELDS:
            merged[field_name] = getattr(tv_cfg, field_name, merged.get(field_name))
        raw = AppConfig.from_dict(merged)
        access_section = _build_access_section_from_cfg(access_cfg)
        tv_section = _build_tv_section_from_cfg(tv_cfg)
    else:
        raw = _coerce_app_config(cfg)
        access_section = _build_access_section_from_cfg(raw)
        tv_section = _build_tv_section_from_cfg(raw)

    return ConfigEnvelope(
        raw=raw,
        shared=load_shared_install_config(),
        access=access_section,
        tv=tv_section,
    )


def load_config_envelope() -> ConfigEnvelope:
    return split_config()


def serialize_component_config(component: ConfigComponent, cfg: AppConfig | ConfigEnvelope | None = None) -> Dict[str, Any]:
    envelope = split_config(cfg)
    if component == "access":
        return asdict(envelope.access)
    return asdict(envelope.tv)


def apply_component_config_patch(component: ConfigComponent, cfg: AppConfig, patch: Dict[str, Any]) -> Dict[str, Any]:
    changed: Dict[str, Any] = {}
    for key, value in (patch or {}).items():
        if key not in _component_fields(component):
            continue
        try:
            setattr(cfg, key, value)
            changed[key] = value
        except Exception:
            pass
    return changed


def build_api_endpoints(cfg: AppConfig | ConfigEnvelope | None = None) -> ApiEndpoints:
    """Build all API endpoints from centralized constants (app/core/app_const.py).

    The cfg parameter is accepted for backward compatibility but is no longer
    used — backend URLs are not stored in or read from runtime config.
    """
    from app.core.app_const import (
        API_LOGIN_URL,
        API_SYNC_URL,
        API_CREATE_USER_FINGERPRINT_URL,
        API_LATEST_RELEASE_URL,
        API_ACCESS_CREATE_MEMBERSHIP_URL,
        API_ACCESS_CREATE_ACCOUNT_MEMBERSHIP_URL,
        API_TV_SNAPSHOT_LATEST_URL,
        API_TV_SNAPSHOT_MANIFEST_URL,
        API_TV_AD_TASKS_FETCH_URL,
        API_TV_AD_TASK_CONFIRM_READY_URL,
        API_TV_AD_TASK_SUBMIT_PROOF_URL,
    )
    return ApiEndpoints(
        login_url=API_LOGIN_URL,
        sync_url=API_SYNC_URL,
        create_user_fingerprint_url=API_CREATE_USER_FINGERPRINT_URL,
        latest_release_url=API_LATEST_RELEASE_URL,
        access_create_membership_url=API_ACCESS_CREATE_MEMBERSHIP_URL,
        access_create_account_membership_url=API_ACCESS_CREATE_ACCOUNT_MEMBERSHIP_URL,
        tv_snapshot_latest_url=API_TV_SNAPSHOT_LATEST_URL,
        tv_snapshot_manifest_url=API_TV_SNAPSHOT_MANIFEST_URL,
        tv_ad_tasks_fetch_url=API_TV_AD_TASKS_FETCH_URL,
        tv_ad_task_confirm_ready_url=API_TV_AD_TASK_CONFIRM_READY_URL,
        tv_ad_task_submit_proof_url=API_TV_AD_TASK_SUBMIT_PROOF_URL,
    )


__all__ = [
    "ACCESS_CONFIG_FIELDS",
    "AppConfig",
    "AccessConfigSection",
    "ConfigComponent",
    "ConfigEnvelope",
    "SHARED_CONFIG_FIELDS",
    "SHARED_INSTALL_FIELDS",
    "SharedConfigSection",
    "TV_CONFIG_FIELDS",
    "TvConfigSection",
    "apply_component_config_patch",
    "build_api_endpoints",
    "get_component_config_status",
    "load_component_app_config",
    "load_config",
    "load_config_envelope",
    "load_shared_install_config",
    "migrate_split_config_if_needed",
    "save_component_app_config",
    "save_config",
    "save_shared_install_config",
    "serialize_component_config",
    "split_config",
]

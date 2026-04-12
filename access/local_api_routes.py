"""Access-owned local API route registration.

The HTTP server shell stays in the legacy module for Phase 2, but route ownership
is separated here so access and TV registration logic no longer mix in one place.
"""

from __future__ import annotations

from typing import Tuple

RouteSpec = Tuple[str, str, str]

ACCESS_LOCAL_ROUTE_SPECS: tuple[RouteSpec, ...] = (
    ("GET", "/api/v2/health", "_handle_health"),
    ("GET", "/api/v2/platform", "_handle_platform"),
    ("GET", "/api/v2/status", "_handle_status"),
    ("GET", "/api/v2/status/stream", "_handle_status_stream_sse"),
    ("POST", "/api/v2/auth/login", "_handle_auth_login"),
    ("GET", "/api/v2/auth/status", "_handle_auth_status"),
    ("POST", "/api/v2/auth/logout", "_handle_auth_logout"),
    ("POST", "/api/v2/auth/verify-admin-password", "_handle_auth_verify_admin_password"),
    ("GET", "/api/v2/config", "_handle_config_get"),
    ("PATCH", "/api/v2/config", "_handle_config_patch"),
    ("POST", "/api/v2/config/restart-local-api", "_handle_config_restart_api"),
    ("GET", "/api/v2/feedback/events", "_handle_feedback_events_sse"),
    ("GET", "/api/v2/feedback/sounds/device-push", "_handle_feedback_sound_device_push_get"),
    ("POST", "/api/v2/feedback/sounds/device-push", "_handle_feedback_sound_device_push_post"),
    ("DELETE", "/api/v2/feedback/sounds/device-push", "_handle_feedback_sound_device_push_delete"),
    ("GET", "/api/v2/feedback/sounds/sync-complete", "_handle_feedback_sound_sync_complete_get"),
    ("POST", "/api/v2/feedback/sounds/sync-complete", "_handle_feedback_sound_sync_complete_post"),
    ("DELETE", "/api/v2/feedback/sounds/sync-complete", "_handle_feedback_sound_sync_complete_delete"),
    ("POST", "/api/v2/sync/now", "_handle_sync_now"),
    ("POST", "/api/v2/sync/hard-reset", "_handle_sync_hard_reset"),
    ("GET", "/api/v2/sync-history", "_handle_sync_history_list"),
    ("GET", "/api/v2/sync-history/{id}", "_handle_sync_history_detail"),
    ("GET", "/api/v2/push-history", "_handle_push_history_list"),
    ("GET", "/api/v2/push-history/{batchId}/pins", "_handle_push_history_pins"),
    ("GET", "/api/v2/sync/cache/meta", "_handle_sync_cache_meta"),
    ("GET", "/api/v2/sync/cache/users", "_handle_sync_cache_users"),
    ("GET", "/api/v2/sync/cache/memberships", "_handle_sync_cache_memberships"),
    ("GET", "/api/v2/sync/cache/devices", "_handle_sync_cache_devices"),
    ("GET", "/api/v2/sync/cache/infrastructures", "_handle_sync_cache_infrastructures"),
    ("GET", "/api/v2/sync/cache/credentials", "_handle_sync_cache_credentials"),
    ("GET", "/api/v2/offline-creations/active", "_handle_offline_creations_active"),
    ("GET", "/api/v2/offline-creations/history", "_handle_offline_creations_history"),
    ("GET", "/api/v2/offline-creations/{localId}", "_handle_offline_creation_get"),
    ("POST", "/api/v2/offline-creations/attempt", "_handle_offline_creation_attempt"),
    ("POST", "/api/v2/offline-creations/queue", "_handle_offline_creation_queue"),
    ("PATCH", "/api/v2/offline-creations/{localId}", "_handle_offline_creation_patch"),
    ("POST", "/api/v2/offline-creations/{localId}/toggle", "_handle_offline_creation_toggle"),
    ("POST", "/api/v2/offline-creations/{localId}/retry", "_handle_offline_creation_retry"),
    ("POST", "/api/v2/offline-creations/{localId}/cancel", "_handle_offline_creation_cancel"),
    ("POST", "/api/v2/offline-creations/{localId}/duplicate", "_handle_offline_creation_duplicate"),
    ("POST", "/api/v2/offline-creations/{localId}/archive", "_handle_offline_creation_archive"),
    ("POST", "/api/v2/offline-creations/process-due", "_handle_offline_creations_process_due"),
    ("POST", "/api/v2/devices/{deviceId}/connect", "_handle_device_connect"),
    ("POST", "/api/v2/devices/{deviceId}/disconnect", "_handle_device_disconnect"),
    ("GET", "/api/v2/devices/{deviceId}/info", "_handle_device_info"),
    ("GET", "/api/v2/devices/{deviceId}/table/{tableName}", "_handle_device_table"),
    ("POST", "/api/v2/devices/{deviceId}/door/open", "_handle_device_door_open"),
    ("POST", "/api/v2/devices/{deviceId}/users/push", "_handle_device_users_push"),
    ("GET", "/api/v2/devices/{deviceId}/users", "_handle_device_users_list"),
    ("POST", "/api/v2/devices/{deviceId}/users/delete", "_handle_device_users_delete"),
    ("POST", "/api/v2/devices/{deviceId}/force-resync", "_handle_device_force_resync"),
    ("GET", "/api/v2/devices/{deviceId}/door-presets", "_handle_device_door_presets_list"),
    ("POST", "/api/v2/devices/{deviceId}/door-presets", "_handle_device_door_presets_create"),
    ("DELETE", "/api/v2/devices/{deviceId}/door-presets/{presetId}", "_handle_device_door_presets_delete"),
    ("GET", "/api/v2/ultra/status", "_handle_ultra_status"),
    ("GET", "/api/v2/agent/status", "_handle_agent_status"),
    ("POST", "/api/v2/agent/start", "_handle_agent_start"),
    ("POST", "/api/v2/agent/stop", "_handle_agent_stop"),
    ("POST", "/api/v2/agent/refresh-devices", "_handle_agent_refresh_devices"),
    ("GET", "/api/v2/agent/devices", "_handle_agent_devices"),
    ("POST", "/api/v2/agent/devices/{deviceId}/enable", "_handle_agent_device_enable"),
    ("POST", "/api/v2/agent/devices/{deviceId}/disable", "_handle_agent_device_disable"),
    ("GET", "/api/v2/agent/events", "_handle_agent_events_sse"),
    ("GET", "/api/v2/agent/settings/global", "_handle_agent_settings_global"),
    ("GET", "/api/v2/agent/settings/device/{deviceId}", "_handle_agent_settings_device"),
    ("POST", "/api/v2/enroll/start", "_handle_enroll_start"),
    ("POST", "/api/v2/enroll/cancel", "_handle_enroll_cancel"),
    ("GET", "/api/v2/enroll/status", "_handle_enroll_status"),
    ("GET", "/api/v2/enroll/events", "_handle_enroll_events_sse"),
    ("POST", "/api/v2/enroll/retry-push", "_handle_enroll_retry_push"),
    ("GET", "/api/v2/fingerprints", "_handle_fingerprints_list"),
    ("DELETE", "/api/v2/fingerprints/{id}", "_handle_fingerprints_delete"),
    ("POST", "/api/v2/scanner/start", "_handle_scanner_start"),
    ("POST", "/api/v2/scanner/stop", "_handle_scanner_stop"),
    ("GET", "/api/v2/scanner/status", "_handle_scanner_status"),
    ("POST", "/api/v2/scanner/discover", "_handle_scanner_discover"),
    ("GET", "/api/v2/scanner/discover/status", "_handle_scanner_discover_status"),
    ("GET", "/api/v2/logs/recent", "_handle_logs_recent"),
    ("GET", "/api/v2/logs/stream", "_handle_logs_stream_sse"),
    ("POST", "/api/v2/logs/open-dir", "_handle_logs_open_dir"),
    ("GET", "/api/v2/update/status", "_handle_update_status"),
    ("POST", "/api/v2/update/check", "_handle_update_check"),
    ("POST", "/api/v2/update/download", "_handle_update_download"),
    ("POST", "/api/v2/update/install", "_handle_update_install"),
    ("POST", "/api/v2/update/cancel", "_handle_update_cancel"),
    ("GET", "/api/v2/update/version", "_handle_update_version_info"),
    ("GET", "/api/v2/storage/status", "_handle_access_storage_status"),
    ("GET", "/api/v2/db/tables", "_handle_db_tables"),
    ("GET", "/api/v2/db/table/{tableName}", "_handle_db_table_query"),
    ("GET", "/api/v2/db/access-history", "_handle_db_access_history"),
    ("POST", "/api/v2/db/export", "_handle_db_export"),
    ("GET", "/api/v2/db/stats", "_handle_db_stats"),
    ("POST", "/api/v2/app/show", "_handle_app_show"),
    ("POST", "/api/v2/app/hide", "_handle_app_hide"),
    ("POST", "/api/v2/app/quit", "_handle_app_quit"),
    ("GET", "/api/v1/access/health", "_handle_v1_health"),
    ("GET", "/api/v1/access/enroll", "_handle_v1_enroll"),
)


def register_access_local_api_routes(router) -> None:
    from app.api import local_access_api_v2 as legacy

    for method, pattern, handler_name in ACCESS_LOCAL_ROUTE_SPECS:
        router.add(method, pattern, getattr(legacy, handler_name))


def get_access_local_api_route_specs() -> tuple[RouteSpec, ...]:
    return ACCESS_LOCAL_ROUTE_SPECS


__all__ = [
    "ACCESS_LOCAL_ROUTE_SPECS",
    "get_access_local_api_route_specs",
    "register_access_local_api_routes",
]

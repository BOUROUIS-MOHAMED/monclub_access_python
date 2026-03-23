"""TV-owned local API route registration for the combined runtime shell."""

from __future__ import annotations

from typing import Tuple

RouteSpec = Tuple[str, str, str]

TV_LOCAL_ROUTE_SPECS: tuple[RouteSpec, ...] = (
    ("POST", "/api/v2/tv/auth/login", "_handle_tv_auth_login"),
    ("POST", "/api/v2/tv/auth/logout", "_handle_tv_auth_logout"),
    ("GET", "/api/v2/tv/auth/status", "_handle_tv_auth_status"),
    ("POST", "/api/v2/tv/app/quit", "_handle_tv_app_quit"),
    ("GET", "/api/v2/tv/logs/recent", "_handle_tv_logs_recent"),
    ("GET", "/api/v2/tv/logs/stream", "_handle_tv_logs_stream_sse"),
    ("GET", "/api/v2/tv/config", "_handle_tv_config_get"),
    ("PATCH", "/api/v2/tv/config", "_handle_tv_config_patch"),
    ("POST", "/api/v2/tv/config/restart-local-api", "_handle_tv_config_restart_api"),
    ("GET", "/api/v2/tv/update/status", "_handle_tv_update_status"),
    ("POST", "/api/v2/tv/update/check", "_handle_tv_update_check"),
    ("POST", "/api/v2/tv/update/download", "_handle_tv_update_download"),
    ("POST", "/api/v2/tv/update/install", "_handle_tv_update_install"),
    ("POST", "/api/v2/tv/update/cancel", "_handle_tv_update_cancel"),
    ("GET", "/api/v2/tv/update/version", "_handle_tv_update_version_info"),
    ("GET", "/api/v2/tv/host/monitors", "_handle_tv_host_monitors_get"),
    ("POST", "/api/v2/tv/host/monitors/refresh", "_handle_tv_host_monitors_refresh"),
    ("GET", "/api/v2/tv/host/bindings", "_handle_tv_host_bindings_get"),
    ("POST", "/api/v2/tv/host/bindings", "_handle_tv_host_bindings_post"),
    ("PATCH", "/api/v2/tv/host/bindings/{bindingId}", "_handle_tv_host_binding_patch"),
    ("DELETE", "/api/v2/tv/host/bindings/{bindingId}", "_handle_tv_host_binding_delete"),
    ("POST", "/api/v2/tv/host/bindings/{bindingId}/start", "_handle_tv_host_binding_start"),
    ("POST", "/api/v2/tv/host/bindings/{bindingId}/stop", "_handle_tv_host_binding_stop"),
    ("POST", "/api/v2/tv/host/bindings/{bindingId}/restart", "_handle_tv_host_binding_restart"),
    ("GET", "/api/v2/tv/host/bindings/{bindingId}/status", "_handle_tv_host_binding_status"),
    ("GET", "/api/v2/tv/host/bindings/{bindingId}/events", "_handle_tv_host_binding_events"),
    ("POST", "/api/v2/tv/host/bindings/{bindingId}/runtime-event", "_handle_tv_host_binding_runtime_event"),
    ("GET", "/api/v2/tv/host/bindings/{bindingId}/support-summary", "_handle_tv_host_binding_support_summary"),
    ("POST", "/api/v2/tv/host/bindings/{bindingId}/support-actions/run", "_handle_tv_host_binding_support_action_run"),
    ("GET", "/api/v2/tv/host/bindings/{bindingId}/support-actions/history", "_handle_tv_host_binding_support_action_history"),
    ("GET", "/api/v2/tv/observability/overview", "_handle_tv_observability_overview"),
    ("GET", "/api/v2/tv/observability/bindings", "_handle_tv_observability_bindings"),
    ("GET", "/api/v2/tv/observability/bindings/{bindingId}", "_handle_tv_observability_binding_detail"),
    ("GET", "/api/v2/tv/observability/gyms", "_handle_tv_observability_gyms"),
    ("GET", "/api/v2/tv/observability/gyms/{gymId}", "_handle_tv_observability_gym_detail"),
    ("GET", "/api/v2/tv/observability/proofs", "_handle_tv_observability_proofs_v2"),
    ("GET", "/api/v2/tv/observability/retention", "_handle_tv_observability_retention"),
    ("POST", "/api/v2/tv/observability/retention/run", "_handle_tv_observability_retention_run"),
    ("GET", "/api/v2/tv/observability/events", "_handle_tv_observability_events_v2"),
    ("GET", "/api/v2/tv/startup/latest", "_handle_tv_hardening_startup_latest"),
    ("GET", "/api/v2/tv/startup/runs", "_handle_tv_hardening_startup_runs"),
    ("POST", "/api/v2/tv/startup/run", "_handle_tv_hardening_startup_run"),
    ("GET", "/api/v2/tv/startup/preflight", "_handle_tv_hardening_preflight"),
    ("GET", "/api/v2/tv/storage/status", "_handle_tv_storage_status"),
    ("GET", "/api/v2/tv/snapshots", "_handle_tv_snapshots_list"),
    ("GET", "/api/v2/tv/snapshots/latest", "_handle_tv_snapshots_latest"),
    ("GET", "/api/v2/tv/snapshots/{snapshotId}/assets", "_handle_tv_snapshot_assets"),
    ("POST", "/api/v2/tv/snapshots/sync", "_handle_tv_snapshots_sync"),
    ("GET", "/api/v2/tv/sync-runs", "_handle_tv_sync_runs"),
    ("GET", "/api/v2/tv/assets", "_handle_tv_assets_list"),
    ("POST", "/api/v2/tv/assets/download", "_handle_tv_assets_download"),
    ("GET", "/api/v2/tv/assets/{mediaAssetId}", "_handle_tv_asset_detail"),
    ("GET", "/api/v2/tv/readiness", "_handle_tv_readiness_list"),
    ("GET", "/api/v2/tv/readiness/latest", "_handle_tv_readiness_latest"),
    ("POST", "/api/v2/tv/readiness/recompute", "_handle_tv_readiness_recompute"),
    ("GET", "/api/v2/tv/activation", "_handle_tv_activation_list"),
    ("GET", "/api/v2/tv/activation/latest", "_handle_tv_activation_latest"),
    ("POST", "/api/v2/tv/activation/evaluate", "_handle_tv_activation_evaluate"),
    ("POST", "/api/v2/tv/activation/activate-latest-ready", "_handle_tv_activation_activate_latest_ready"),
    ("GET", "/api/v2/tv/activation/attempts", "_handle_tv_activation_attempts"),
    ("GET", "/api/v2/tv/player/{bindingId}/status", "_handle_tv_player_status"),
    ("GET", "/api/v2/tv/player/{bindingId}/render-context", "_handle_tv_player_render_context"),
    ("POST", "/api/v2/tv/player/{bindingId}/reevaluate", "_handle_tv_player_reevaluate"),
    ("POST", "/api/v2/tv/player/{bindingId}/reload", "_handle_tv_player_reload"),
    ("POST", "/api/v2/tv/player/{bindingId}/state", "_handle_tv_player_state_report"),
    ("GET", "/api/v2/tv/player/{bindingId}/events", "_handle_tv_player_events"),
    ("GET", "/api/v2/tv/ad-runtime/tasks", "_handle_tv_ad_tasks_list"),
    ("GET", "/api/v2/tv/ad-runtime/tasks/{taskId}", "_handle_tv_ad_tasks_runtime_one"),
    ("GET", "/api/v2/tv/ad-runtime/gyms/{gymId}", "_handle_tv_gym_ad_runtime_one"),
    ("POST", "/api/v2/tv/ad-runtime/evaluate", "_handle_tv_ad_evaluate"),
    ("POST", "/api/v2/tv/ad-runtime/tasks/{taskId}/inject-now", "_handle_tv_ad_tasks_inject_now"),
    ("POST", "/api/v2/tv/ad-runtime/tasks/{taskId}/abort", "_handle_tv_ad_tasks_abort"),
    ("GET", "/api/v2/tv/ad-runtime/runtime/list", "_handle_tv_ad_tasks_runtime_list"),
    ("GET", "/api/v2/tv/ad-runtime/runtime/{taskId}", "_handle_tv_ad_tasks_runtime_one"),
    ("POST", "/api/v2/tv/ad-runtime/startup-recover", "_handle_tv_ad_startup_recover"),
    ("GET", "/api/v2/tv/ad-proofs", "_handle_tv_ad_proofs_list"),
    ("GET", "/api/v2/tv/ad-proofs/{proofId}", "_handle_tv_ad_proofs_one"),
    ("POST", "/api/v2/tv/ad-proofs/process-outbox", "_handle_tv_ad_proofs_process_outbox"),
    ("POST", "/api/v2/tv/ad-proofs/{proofId}/retry", "_handle_tv_ad_proofs_retry"),
    ("POST", "/api/v2/tv/ad-proofs/startup-recover", "_handle_tv_ad_proofs_startup_recover"),
    ("POST", "/api/v2/tv/screen-messages", "_handle_tv_screen_messages_post"),
    ("GET", "/api/v2/tv/screen-messages", "_handle_tv_screen_messages_get"),
)


def register_tv_local_api_routes(router) -> None:
    from app.api import local_access_api_v2 as legacy

    for method, pattern, handler_name in TV_LOCAL_ROUTE_SPECS:
        router.add(method, pattern, getattr(legacy, handler_name))


def get_tv_local_api_route_specs() -> tuple[RouteSpec, ...]:
    return TV_LOCAL_ROUTE_SPECS


__all__ = [
    "TV_LOCAL_ROUTE_SPECS",
    "get_tv_local_api_route_specs",
    "register_tv_local_api_routes",
]

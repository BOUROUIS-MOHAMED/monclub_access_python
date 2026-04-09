# app/api/local_access_api_v2.py
"""
Local HTTP API v2 for Tauri+React UI.

Binds to 127.0.0.1.  All endpoints under /api/v2/*.
Backward-compatible v1 endpoints are kept with Deprecation headers.

SSE endpoints:
  - GET /api/v2/status/stream
  - GET /api/v2/logs/stream
  - GET /api/v2/agent/events
  - GET /api/v2/enroll/events
"""
from __future__ import annotations

import json
import logging
import os
import queue
import re
import threading
import time
import traceback
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

_logger = logging.getLogger(__name__)

_SQLITE_TABLE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

from app.api.monclub_api import MonClubApiHttpError

# TV boundary — imported through the phase 1 TV facade so new code does not
# depend on the legacy implementation module directly.
from tv.api import (  # noqa: E402
    ensure_tv_local_schema,
    # Screen bindings
    load_tv_screen_binding, load_tv_screen_binding_by_id, save_tv_screen_binding,
    create_tv_screen_binding, delete_tv_screen_binding,
    start_tv_screen_binding, stop_tv_screen_binding, restart_tv_screen_binding,
    update_tv_screen_binding, get_tv_screen_binding, list_tv_screen_bindings,
    # Host monitors
    list_tv_host_monitors, replace_tv_host_monitors,
    # Binding runtime / events
    upsert_tv_screen_binding_runtime, load_tv_screen_binding_runtime,
    record_tv_screen_binding_event, list_tv_screen_binding_events,
    record_tv_screen_binding_runtime_event,
    # Snapshot cache
    load_tv_latest_snapshot, load_tv_snapshot_by_id, list_tv_snapshot_cache,
    load_tv_snapshot_manifest, load_tv_latest_ready_snapshot, load_tv_previous_ready_snapshot,
    # Asset state
    load_tv_local_asset_state, list_tv_cache_assets,
    # Readiness
    load_tv_latest_readiness,
    # Activation
    evaluate_tv_activation, activate_tv_latest_ready_snapshot,
    load_tv_activation_status, list_tv_activation_attempts,
    # Downloads
    load_tv_latest_download_batch, list_tv_download_jobs,
    # Player
    load_tv_player_status, get_tv_player_render_context,
    reevaluate_tv_player, reload_tv_player,
    report_tv_player_state, list_tv_player_events,
    # Player state persistence
    load_tv_player_state,
    # Support / observability
    load_tv_binding_support_summary, run_tv_binding_support_action, list_tv_support_action_logs,
    get_tv_retention_policy, run_tv_retention_maintenance,
    get_tv_observability_overview, list_tv_observability_bindings, get_tv_observability_binding,
    list_tv_observability_gyms, get_tv_observability_gym,
    list_tv_observability_proofs, get_tv_observability_retention, list_tv_observability_events,
    run_tv_startup_reconciliation, run_tv_deployment_preflight,
    load_tv_startup_reconciliation_latest, list_tv_startup_reconciliation_runs,
    # Ad runtime (A7)
    list_tv_ad_task_cache, upsert_tv_ad_task_cache, load_tv_ad_task_cache_one,
    list_tv_ad_task_runtime, load_tv_ad_task_runtime, upsert_tv_ad_task_runtime,
    load_tv_gym_ad_runtime, upsert_tv_gym_ad_runtime,
    inject_tv_ad_task_now, abort_tv_ad_task_now,
    complete_tv_ad_display, abort_tv_ad_display,
    reconcile_all_active_gyms, startup_recover_ad_runtime,
    # A8: Ad proof outbox
    create_tv_ad_proof,
    list_tv_ad_proof_outbox, load_tv_ad_proof, process_tv_ad_proof_outbox,
    retry_tv_ad_proof, startup_recover_proof_outbox,
    # Screen messages
    create_tv_screen_message, list_tv_screen_messages,
)




# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(str(v).strip())
    except Exception:
        return default


def _safe_str(v: Any, default: str = "") -> str:
    if v is None:
        return default
    try:
        return str(v)
    except Exception:
        return default



def _safe_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    s = _safe_str(v, "").strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return True
    if s in {"0", "false", "no", "off"}:
        return False
    return default



def _split_csv_upper(raw: str) -> List[str]:
    out: List[str] = []
    for part in _safe_str(raw, "").replace(";", ",").split(","):
        s = _safe_str(part, "").strip().upper()
        if s and s not in out:
            out.append(s)
    return out
def _qs_first(qs: Dict[str, List[str]], *names: str, default: str = "") -> str:
    for n in names:
        v = qs.get(n)
        if v and len(v) > 0:
            return (v[0] or "").strip()
    return default


def _read_json_body(handler: BaseHTTPRequestHandler) -> Dict[str, Any]:
    length = int(handler.headers.get("Content-Length") or "0")
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def _load_tv_dashboard_runtime_token() -> str:
    try:
        from tv.auth_bridge import load_tv_auth_for_runtime

        auth = load_tv_auth_for_runtime()
        token = _safe_str(getattr(auth, "token", None), "").strip()
        if token:
            return token
    except Exception:
        pass

    try:
        from access.store import load_auth_token

        auth = load_auth_token()
        token = _safe_str(getattr(auth, "token", None), "").strip()
        if token:
            return token
    except Exception:
        pass

    return ""


def _send_tv_dashboard_auth_required(ctx: "_Ctx") -> None:
    ctx.send_json(401, {"ok": False, "error": "Login required to load dashboard TV data."})


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

_ALLOWED_ORIGIN = "tauri://localhost"

def _cors_headers(handler: BaseHTTPRequestHandler) -> None:
    # This API binds to 127.0.0.1 only, so it is safe to reflect the requesting
    # origin back to desktop UI callers instead of maintaining a brittle allowlist.
    # Packaged Tauri/WebView runtimes may use different localhost-like origins
    # across platforms/releases (for example http://tauri.localhost or
    # https://tauri.localhost), and reflecting the origin keeps the local shell
    # resilient without exposing the API outside loopback.
    origin = handler.headers.get("Origin", "")
    requested_headers = handler.headers.get("Access-Control-Request-Headers", "")
    requested_private_network = handler.headers.get("Access-Control-Request-Private-Network", "")
    if origin:
        handler.send_header("Access-Control-Allow-Origin", origin)
    else:
        # Fallback for non-browser callers (curl, Tauri sidecar, etc.)
        handler.send_header("Access-Control-Allow-Origin", "http://localhost")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
    if requested_headers.strip():
        handler.send_header("Access-Control-Allow-Headers", requested_headers)
    else:
        handler.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Local-Token")
    if requested_private_network.strip().lower() == "true":
        handler.send_header("Access-Control-Allow-Private-Network", "true")
    handler.send_header(
        "Vary",
        "Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network",
    )
    handler.send_header("Access-Control-Max-Age", "86400")


# ---------------------------------------------------------------------------
# HTTP Server wrapper
# ---------------------------------------------------------------------------

class _AppHTTPServerV2(ThreadingHTTPServer):
    def __init__(self, server_address, handler_class, *, app, router: "_Router"):
        super().__init__(server_address, handler_class)
        self.app = app
        self.router = router


class _Router:
    """Simple path-based router with path param extraction."""

    def __init__(self) -> None:
        self._routes: List[Tuple[str, str, Callable]] = []  # (method, pattern, handler)

    def add(self, method: str, pattern: str, handler: Callable) -> None:
        self._routes.append((method.upper(), pattern, handler))

    def match(self, method: str, path: str) -> Tuple[Optional[Callable], Dict[str, str]]:
        for route_method, pattern, handler in self._routes:
            if route_method != method.upper():
                continue
            params = self._match_pattern(pattern, path)
            if params is not None:
                return handler, params
        return None, {}

    @staticmethod
    def _match_pattern(pattern: str, path: str) -> Optional[Dict[str, str]]:
        p_parts = [p for p in pattern.split("/") if p]
        u_parts = [p for p in path.split("/") if p]
        if len(p_parts) != len(u_parts):
            return None
        params: Dict[str, str] = {}
        for pp, up in zip(p_parts, u_parts):
            if pp.startswith("{") and pp.endswith("}"):
                params[pp[1:-1]] = up
            elif pp != up:
                return None
        return params


# ---------------------------------------------------------------------------
# Request context
# ---------------------------------------------------------------------------

class _Ctx:
    """Convenience wrapper around a request."""

    def __init__(self, handler: BaseHTTPRequestHandler, params: Dict[str, str], qs: Dict[str, List[str]], app):
        self.handler = handler
        self.params = params
        self.qs = qs
        self.app = app
        self._body: Optional[Dict[str, Any]] = None

    def body(self) -> Dict[str, Any]:
        if self._body is None:
            try:
                self._body = _read_json_body(self.handler)
            except Exception:
                self._body = {}
        return self._body

    def q(self, *names: str, default: str = "") -> str:
        return _qs_first(self.qs, *names, default=default)

    def q_int(self, *names: str, default: int = 0) -> int:
        return _safe_int(self.q(*names, default=str(default)), default)

    def param(self, name: str) -> str:
        return self.params.get(name, "")

    def param_int(self, name: str, default: int = 0) -> int:
        return _safe_int(self.params.get(name, ""), default)

    def send_json(self, status: int, payload: Any) -> None:
        body = _json_bytes(payload)
        self.handler.send_response(status)
        _cors_headers(self.handler)
        self.handler.send_header("Content-Type", "application/json; charset=utf-8")
        self.handler.send_header("Content-Length", str(len(body)))
        self.handler.end_headers()
        self.handler.wfile.write(body)

    def send_sse_start(self) -> None:
        self.handler.send_response(200)
        _cors_headers(self.handler)
        self.handler.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.handler.send_header("Cache-Control", "no-cache")
        self.handler.send_header("Connection", "keep-alive")
        self.handler.end_headers()

    def send_sse_event(self, event: str, data: Any) -> bool:
        """Returns False if the connection is broken."""
        try:
            payload = json.dumps(data, ensure_ascii=False, default=str)
            msg = f"event: {event}\ndata: {payload}\n\n"
            self.handler.wfile.write(msg.encode("utf-8"))
            self.handler.wfile.flush()
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

# ==================== 1) HEALTH / STATUS ====================

def _handle_health(ctx: _Ctx) -> None:
    info = ctx.app.get_local_api_health()
    # augment with version info
    try:
        um = getattr(ctx.app, "_update_manager", None)
        if um:
            info["currentReleaseId"] = um.get_current_release_id()
    except Exception:
        pass
    ctx.send_json(200, info)


def _handle_platform(ctx: _Ctx) -> None:
    from shared.platform import platform_summary
    from app.core.utils import is_frozen, DATA_ROOT
    import sys
    ctx.send_json(200, {
        "platform": platform_summary(),
        "pythonBits": 8 * (8 if sys.maxsize > 2**32 else 4),
        "frozen": is_frozen(),
        "dataRoot": str(DATA_ROOT),
    })


# ==================== 1.5) UNIFIED STATUS ====================

def _handle_status(ctx: _Ctx) -> None:
    ctx.send_json(200, _build_status_payload(ctx.app))
    return
    """Unified status snapshot for Tauri dashboard â€” single call."""
    from access.store import load_auth_token, load_sync_cache

    auth = load_auth_token()
    reasons = []
    try:
        reasons = ctx.app._restriction_reasons() if auth else []
    except Exception:
        pass
    cache = load_sync_cache()

    session = {
        "loggedIn": bool(auth and auth.token),
        "restricted": bool(reasons),
        "reasons": reasons,
        "email": (auth.email if auth else None),
        "lastLoginAt": (auth.last_login_at if auth else None),
        "contractStatus": bool(cache and cache.contract_status),
        "contractEndDate": (cache.contract_end_date if cache else None),
    }

    # Add expiry warnings
    try:
        expiry = ctx.app._compute_expiry_warnings()
        session["loginDaysRemaining"] = expiry.get("loginDaysRemaining")
        session["loginWarning"] = expiry.get("loginWarning", False)
        session["contractDaysRemaining"] = expiry.get("contractDaysRemaining")
        session["contractWarning"] = expiry.get("contractWarning", False)
    except Exception:
        session["loginDaysRemaining"] = None
        session["loginWarning"] = False
        session["contractDaysRemaining"] = None
        session["contractWarning"] = False

    devices = list(cache.devices) if cache else []
    dev_count = 0
    agent_count = 0
    ultra_count = 0
    for d in devices:
        if isinstance(d, dict):
            adm = str(d.get("accessDataMode") or d.get("access_data_mode") or "").upper()
            if adm == "DEVICE":
                dev_count += 1
            elif adm == "AGENT":
                agent_count += 1
            elif adm == "ULTRA":
                ultra_count += 1
    unknown_count = len(devices) - dev_count - agent_count - ultra_count

    try:
        mode = ctx.app.get_access_mode_summary()
    except Exception:
        mode = {"DEVICE": dev_count, "AGENT": agent_count, "ULTRA": ultra_count, "UNKNOWN": unknown_count}

    # H-005: Real sync telemetry from MainApp instead of placeholders
    sync = {
        "running": bool(getattr(ctx.app, "_sync_work_running", False)),
        "lastSyncAt": getattr(ctx.app, "_last_sync_at", None) or (cache.updated_at if cache else None),
        "lastOk": getattr(ctx.app, "_last_sync_ok", bool(cache)),
        "lastError": getattr(ctx.app, "_last_sync_error", None),
    }

    pullsdk: Dict[str, Any] = {"connected": False, "deviceId": None, "ip": None, "since": None, "lastError": None}
    with _device_sdk_lock:
        if _device_sdk_pool:
            first_id = next(iter(_device_sdk_pool))
            pullsdk["connected"] = True
            pullsdk["deviceId"] = first_id

    eng = getattr(ctx.app, "_agent_engine", None)
    agent_running = bool(eng and eng.is_running())
    agent = {
        "running": agent_running,
        "eventQueueDepth": eng.get_queue_depth() if agent_running else 0,
        "avgDecisionMs": round(eng.get_avg_decision_ms(), 2) if agent_running else 0.0,
    }

    ultra_eng = getattr(ctx.app, "_ultra_engine", None)
    ultra_running = bool(ultra_eng and ultra_eng.running)
    ultra: Dict[str, Any] = {"running": ultra_running, "devices": {}}
    if ultra_running:
        try:
            ultra = ultra_eng.get_status()
        except Exception:
            pass

    updates = _build_update_status_payload(ctx.app)
    updates["progress"] = updates.get("progressPercent")

    # H-005: Device sync telemetry from MainApp instead of placeholders
    _ds_engine = getattr(ctx.app, "_device_sync_engine", None)
    _ds_prog = getattr(_ds_engine, "_sync_progress", None) if _ds_engine else None
    device_sync = {
        "lastRunAt": getattr(ctx.app, "_last_device_sync_at", None),
        "lastOk": getattr(ctx.app, "_last_device_sync_ok", True),
        "lastError": getattr(ctx.app, "_last_device_sync_error", None),
        "progress": {
            "running": _ds_prog.get("running", False),
            "deviceName": _ds_prog.get("deviceName", ""),
            "deviceId": _ds_prog.get("deviceId"),
            "current": _ds_prog.get("current", 0),
            "total": _ds_prog.get("total", 0),
        } if _ds_prog else None,
    }

    ctx.send_json(200, {
        "ok": True,
        "session": session,
        "mode": mode,
        "sync": sync,
        "deviceSync": device_sync,
        "pullsdk": pullsdk,
        "agent": agent,
        "ultra": ultra,
        "updates": updates,
    })

def _get_engine_progress_snapshot(engine: Any) -> Optional[Dict[str, Any]]:
    if not engine:
        return None
    try:
        progress, _ = engine.get_progress_snapshot()
        return progress
    except Exception:
        return getattr(engine, "_sync_progress", None)


def _get_live_device_sync_progress(app: Any) -> Optional[Dict[str, Any]]:
    main_progress = _get_engine_progress_snapshot(getattr(app, "_device_sync_engine", None))
    if main_progress and main_progress.get("running"):
        return main_progress

    ultra_eng = getattr(app, "_ultra_engine", None)
    ultra_progress = None
    if ultra_eng and hasattr(ultra_eng, "get_sync_progress_snapshot"):
        try:
            ultra_progress, _ = ultra_eng.get_sync_progress_snapshot()
        except Exception:
            ultra_progress = None
    if ultra_progress and ultra_progress.get("running"):
        return ultra_progress

    return None


_status_payload_lock = threading.Lock()
_status_payload_cache: tuple = (0.0, 0, None)  # (expires_at, app_id, payload)
_STATUS_PAYLOAD_TTL = 1.0  # seconds


def _build_status_payload(app: Any) -> Dict[str, Any]:
    global _status_payload_cache
    now = time.monotonic()
    app_id = id(app)
    with _status_payload_lock:
        expires, cached_app_id, cached = _status_payload_cache
        if now < expires and cached is not None and cached_app_id == app_id:
            return cached
    result = _build_status_payload_uncached(app)
    with _status_payload_lock:
        _status_payload_cache = (time.monotonic() + _STATUS_PAYLOAD_TTL, app_id, result)
    return result


def _build_status_payload_uncached(app: Any) -> Dict[str, Any]:
    from access.store import load_auth_token, load_sync_cache

    auth = load_auth_token()
    reasons = []
    try:
        reasons = app._restriction_reasons() if auth else []
    except Exception:
        pass
    cache = load_sync_cache()

    session = {
        "loggedIn": bool(auth and auth.token),
        "restricted": bool(reasons),
        "reasons": reasons,
        "email": (auth.email if auth else None),
        "lastLoginAt": (auth.last_login_at if auth else None),
        "contractStatus": bool(cache and cache.contract_status),
        "contractEndDate": (cache.contract_end_date if cache else None),
    }

    try:
        expiry = app._compute_expiry_warnings()
        session["loginDaysRemaining"] = expiry.get("loginDaysRemaining")
        session["loginWarning"] = expiry.get("loginWarning", False)
        session["contractDaysRemaining"] = expiry.get("contractDaysRemaining")
        session["contractWarning"] = expiry.get("contractWarning", False)
    except Exception:
        session["loginDaysRemaining"] = None
        session["loginWarning"] = False
        session["contractDaysRemaining"] = None
        session["contractWarning"] = False

    devices = list(cache.devices) if cache else []
    dev_count = 0
    agent_count = 0
    ultra_count = 0
    for d in devices:
        if isinstance(d, dict):
            adm = str(d.get("accessDataMode") or d.get("access_data_mode") or "").upper()
            if adm == "DEVICE":
                dev_count += 1
            elif adm == "AGENT":
                agent_count += 1
            elif adm == "ULTRA":
                ultra_count += 1
    unknown_count = len(devices) - dev_count - agent_count - ultra_count

    try:
        mode = app.get_access_mode_summary()
    except Exception:
        mode = {"DEVICE": dev_count, "AGENT": agent_count, "ULTRA": ultra_count, "UNKNOWN": unknown_count}

    sync = {
        "running": bool(getattr(app, "_sync_work_running", False)),
        "lastSyncAt": getattr(app, "_last_sync_at", None) or (cache.updated_at if cache else None),
        "lastOk": getattr(app, "_last_sync_ok", bool(cache)),
        "lastError": getattr(app, "_last_sync_error", None),
    }

    pullsdk: Dict[str, Any] = {"connected": False, "deviceId": None, "ip": None, "since": None, "lastError": None}
    with _device_sdk_lock:
        if _device_sdk_pool:
            first_id = next(iter(_device_sdk_pool))
            pullsdk["connected"] = True
            pullsdk["deviceId"] = first_id

    eng = getattr(app, "_agent_engine", None)
    agent_running = bool(eng and eng.is_running())
    agent = {
        "running": agent_running,
        "eventQueueDepth": eng.get_queue_depth() if agent_running else 0,
        "avgDecisionMs": round(eng.get_avg_decision_ms(), 2) if agent_running else 0.0,
    }

    ultra_eng = getattr(app, "_ultra_engine", None)
    ultra_running = bool(ultra_eng and ultra_eng.running)
    ultra: Dict[str, Any] = {"running": ultra_running, "devices": {}}
    if ultra_running:
        try:
            ultra = ultra_eng.get_status()
        except Exception:
            pass

    updates = _build_update_status_payload(app)
    updates["progress"] = updates.get("progressPercent")

    ds_progress = _get_live_device_sync_progress(app)
    device_sync = {
        "lastRunAt": getattr(app, "_last_device_sync_at", None),
        "lastOk": getattr(app, "_last_device_sync_ok", True),
        "lastError": getattr(app, "_last_device_sync_error", None),
        "progress": {
            "running": ds_progress.get("running", False),
            "deviceName": ds_progress.get("deviceName", ""),
            "deviceId": ds_progress.get("deviceId"),
            "current": ds_progress.get("current", 0),
            "total": ds_progress.get("total", 0),
        } if ds_progress else None,
    }

    return {
        "ok": True,
        "session": session,
        "mode": mode,
        "sync": sync,
        "deviceSync": device_sync,
        "pullsdk": pullsdk,
        "agent": agent,
        "ultra": ultra,
        "updates": updates,
    }


def _status_payload_signature(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _handle_status_stream_sse(ctx: _Ctx) -> None:
    ctx.send_sse_start()

    payload = _build_status_payload(ctx.app)
    last_signature = _status_payload_signature(payload)
    if not ctx.send_sse_event("status", payload):
        return

    idle_ticks = 0
    while True:
        time.sleep(1.0)

        payload = _build_status_payload(ctx.app)
        signature = _status_payload_signature(payload)
        if signature != last_signature:
            last_signature = signature
            idle_ticks = 0
            if not ctx.send_sse_event("status", payload):
                return
            continue

        idle_ticks += 1
        if idle_ticks >= 15:
            idle_ticks = 0
            if not ctx.send_sse_event("ping", {"t": int(time.time())}):
                return


# ==================== 2) AUTH ====================

def _handle_auth_login(ctx: _Ctx) -> None:
    body = ctx.body()
    email = _safe_str(body.get("email"), "").strip()
    password = _safe_str(body.get("password"), "")
    if not email or not password:
        ctx.send_json(400, {"ok": False, "error": "email and password are required"})
        return

    try:
        api = ctx.app._api()
        token = api.login(email=email, password=password)

        from access.store import save_auth_token
        save_auth_token(email=email, token=token)
        try:
            from tv.auth_bridge import mirror_access_auth_to_tv

            mirror_access_auth_to_tv(email=email, token=token)
        except Exception:
            ctx.app.logger.warning("TV auth mirror failed during login.", exc_info=True)

        ctx.app.cfg.login_email = email
        ctx.app.persist_config()
        ctx.app.logger.info("Login OK via API v2.")

        # trigger sync + redirect evaluation on main thread
        try:
            ctx.app.after(0, ctx.app.request_sync_now)
            ctx.app.after(100, ctx.app.evaluate_access_and_redirect)
        except Exception:
            pass

        ctx.send_json(200, {"ok": True, "token": token[:8] + "..." if len(token) > 8 else "***"})
    except MonClubApiHttpError as e:
        ctx.app.logger.warning("Login failed via API v2: HTTP %s", e.status_code)
        ctx.send_json(e.status_code, {"ok": False, "error": str(e)})
    except Exception as e:
        ctx.app.logger.exception("Login failed via API v2")
        ctx.send_json(500, {"ok": False, "error": str(e)})


def _handle_auth_status(ctx: _Ctx) -> None:
    from access.store import load_auth_token
    auth = load_auth_token()
    reasons = ctx.app._restriction_reasons() if auth else []
    ctx.send_json(200, {
        "loggedIn": bool(auth and auth.token),
        "restricted": bool(reasons),
        "reasons": reasons,
        "lastLoginAt": (auth.last_login_at if auth else None),
        "email": (auth.email if auth else None),
    })


def _handle_tv_auth_login(ctx: _Ctx) -> None:
    body = ctx.body()
    email = _safe_str(body.get("email"), "").strip()
    password = _safe_str(body.get("password"), "")
    if not email or not password:
        ctx.send_json(400, {"ok": False, "error": "email and password are required"})
        return
    try:
        import datetime
        api = ctx.app._api()
        token = api.login(email=email, password=password)
        from tv.auth_bridge import mirror_access_auth_to_tv
        mirror_access_auth_to_tv(email=email, token=token, last_login_at=datetime.datetime.utcnow().isoformat())
        # Mirror to Access on best-effort basis (SSO: if Access is co-installed)
        try:
            from access.store import save_auth_token
            save_auth_token(email=email, token=token)
        except Exception:
            ctx.app.logger.warning("Access auth mirror failed during TV login.", exc_info=True)
        ctx.app.cfg.login_email = email
        ctx.app.persist_config()
        ctx.app.logger.info("TV Login OK via API v2.")
        try:
            ctx.app.after(0, lambda: ctx.app._ensure_update_manager_started(check_now=True))
        except Exception:
            pass
        ctx.send_json(200, {"ok": True, "token": token[:8] + "..." if len(token) > 8 else "***"})
    except MonClubApiHttpError as e:
        ctx.app.logger.warning("TV Login failed via API v2: HTTP %s", e.status_code)
        ctx.send_json(e.status_code, {"ok": False, "error": str(e)})
    except Exception as e:
        ctx.app.logger.exception("TV Login failed via API v2")
        ctx.send_json(500, {"ok": False, "error": str(e)})


def _handle_tv_auth_status(ctx: _Ctx) -> None:
    from tv.auth_bridge import load_tv_auth_for_runtime
    auth = load_tv_auth_for_runtime()
    ctx.send_json(200, {
        "ok": True,
        "session": {
            "loggedIn": bool(auth and auth.token),
            "restricted": False,
            "reasons": [],
            "email": (auth.email if auth else None),
            "lastLoginAt": (auth.last_login_at if auth else None),
            "contractStatus": True,
            "contractEndDate": None,
            "loginDaysRemaining": None,
            "loginWarning": False,
            "contractDaysRemaining": None,
            "contractWarning": False,
        },
        "mode": {"DEVICE": 0, "AGENT": 0, "ULTRA": 0, "UNKNOWN": 0},
        "sync": {"running": False, "lastSyncAt": None, "lastOk": True, "lastError": None},
        "deviceSync": {"lastRunAt": None, "lastOk": True, "lastError": None},
        "pullsdk": {"connected": False, "deviceId": None, "ip": None, "since": None, "lastError": None},
        "agent": {"running": False, "eventQueueDepth": 0, "avgDecisionMs": 0},
        "updates": {"updateAvailable": False, "downloaded": False, "downloading": False,
                    "progress": None, "currentReleaseId": None, "lastCheckAt": None, "lastError": None},
    })


def _handle_tv_dashboard_screens_list(ctx: _Ctx) -> None:
    token = _load_tv_dashboard_runtime_token()
    if not token:
        _send_tv_dashboard_auth_required(ctx)
        return

    enabled_raw = ctx.q("enabled", default="")
    has_layout_raw = ctx.q("hasLayout", "has_layout", default="")
    include_archived_raw = ctx.q("includeArchived", "include_archived", default="")

    try:
        data = ctx.app._api().get_tv_screens(
            token=token,
            q=ctx.q("q", default="") or None,
            gym_id=ctx.q_int("gymId", "gym_id", default=0) or None,
            enabled=_safe_bool(enabled_raw) if enabled_raw != "" else None,
            orientation=ctx.q("orientation", default="") or None,
            has_layout=_safe_bool(has_layout_raw) if has_layout_raw != "" else None,
            include_archived=_safe_bool(include_archived_raw) if include_archived_raw != "" else None,
            page=max(0, ctx.q_int("page", default=0)),
            size=max(1, min(ctx.q_int("size", default=50), 200)),
            sort_by=ctx.q("sortBy", "sort_by", default="name") or "name",
            sort_dir=ctx.q("sortDir", "sort_dir", default="asc") or "asc",
        )
        ctx.send_json(200, {"ok": True, **data})
    except MonClubApiHttpError as e:
        ctx.send_json(e.status_code, {"ok": False, "error": str(e)})
    except Exception as e:
        ctx.app.logger.exception("TV dashboard screens list failed")
        ctx.send_json(500, {"ok": False, "error": str(e)})


def _handle_tv_dashboard_screen_detail(ctx: _Ctx) -> None:
    token = _load_tv_dashboard_runtime_token()
    if not token:
        _send_tv_dashboard_auth_required(ctx)
        return

    screen_id = ctx.param_int("screenId", 0)
    if screen_id <= 0:
        ctx.send_json(400, {"ok": False, "error": "screenId must be a positive integer."})
        return

    try:
        data = ctx.app._api().get_tv_screen_by_id(token=token, screen_id=screen_id)
        ctx.send_json(200, {"ok": True, **data})
    except MonClubApiHttpError as e:
        ctx.send_json(e.status_code, {"ok": False, "error": str(e)})
    except Exception as e:
        ctx.app.logger.exception("TV dashboard screen detail failed")
        ctx.send_json(500, {"ok": False, "error": str(e)})


def _handle_tv_dashboard_screen_content_plan(ctx: _Ctx) -> None:
    token = _load_tv_dashboard_runtime_token()
    if not token:
        _send_tv_dashboard_auth_required(ctx)
        return

    screen_id = ctx.param_int("screenId", 0)
    if screen_id <= 0:
        ctx.send_json(400, {"ok": False, "error": "screenId must be a positive integer."})
        return

    try:
        data = ctx.app._api().get_tv_screen_content_plan(token=token, screen_id=screen_id)
        ctx.send_json(200, {"ok": True, **data})
    except MonClubApiHttpError as e:
        ctx.send_json(e.status_code, {"ok": False, "error": str(e)})
    except Exception as e:
        ctx.app.logger.exception("TV dashboard screen content plan failed")
        ctx.send_json(500, {"ok": False, "error": str(e)})


def _handle_tv_dashboard_screen_snapshots(ctx: _Ctx) -> None:
    token = _load_tv_dashboard_runtime_token()
    if not token:
        _send_tv_dashboard_auth_required(ctx)
        return

    screen_id = ctx.param_int("screenId", 0)
    if screen_id <= 0:
        ctx.send_json(400, {"ok": False, "error": "screenId must be a positive integer."})
        return

    try:
        data = ctx.app._api().get_tv_screen_snapshots(
            token=token,
            screen_id=screen_id,
            page=max(0, ctx.q_int("page", default=0)),
            size=max(1, min(ctx.q_int("size", default=20), 100)),
            sort_by=ctx.q("sortBy", "sort_by", default="version") or "version",
            sort_dir=ctx.q("sortDir", "sort_dir", default="desc") or "desc",
        )
        ctx.send_json(200, {"ok": True, **data})
    except MonClubApiHttpError as e:
        ctx.send_json(e.status_code, {"ok": False, "error": str(e)})
    except Exception as e:
        ctx.app.logger.exception("TV dashboard screen snapshots failed")
        ctx.send_json(500, {"ok": False, "error": str(e)})


def _handle_tv_dashboard_screen_latest_snapshot(ctx: _Ctx) -> None:
    token = _load_tv_dashboard_runtime_token()
    if not token:
        _send_tv_dashboard_auth_required(ctx)
        return

    screen_id = ctx.param_int("screenId", 0)
    if screen_id <= 0:
        ctx.send_json(400, {"ok": False, "error": "screenId must be a positive integer."})
        return

    try:
        data = ctx.app._api().get_tv_latest_snapshot(
            token=token,
            screen_id=screen_id,
            resolve_at=ctx.q("resolveAt", "resolve_at", default="") or None,
        )
        ctx.send_json(200, {"ok": True, **data})
    except MonClubApiHttpError as e:
        ctx.send_json(e.status_code, {"ok": False, "error": str(e)})
    except Exception as e:
        ctx.app.logger.exception("TV dashboard latest snapshot failed")
        ctx.send_json(500, {"ok": False, "error": str(e)})


def _handle_tv_dashboard_snapshot_detail(ctx: _Ctx) -> None:
    token = _load_tv_dashboard_runtime_token()
    if not token:
        _send_tv_dashboard_auth_required(ctx)
        return

    snapshot_id = _safe_str(ctx.param("snapshotId"), "").strip()
    if not snapshot_id:
        ctx.send_json(400, {"ok": False, "error": "snapshotId is required."})
        return

    try:
        data = ctx.app._api().get_tv_snapshot_by_id(token=token, snapshot_id=snapshot_id)
        ctx.send_json(200, {"ok": True, **data})
    except MonClubApiHttpError as e:
        ctx.send_json(e.status_code, {"ok": False, "error": str(e)})
    except Exception as e:
        ctx.app.logger.exception("TV dashboard snapshot detail failed")
        ctx.send_json(500, {"ok": False, "error": str(e)})


def _handle_tv_dashboard_snapshot_manifest(ctx: _Ctx) -> None:
    token = _load_tv_dashboard_runtime_token()
    if not token:
        _send_tv_dashboard_auth_required(ctx)
        return

    snapshot_id = _safe_str(ctx.param("snapshotId"), "").strip()
    if not snapshot_id:
        ctx.send_json(400, {"ok": False, "error": "snapshotId is required."})
        return

    try:
        data = ctx.app._api().get_tv_snapshot_manifest(token=token, snapshot_id=snapshot_id)
        ctx.send_json(200, {"ok": True, **data})
    except MonClubApiHttpError as e:
        ctx.send_json(e.status_code, {"ok": False, "error": str(e)})
    except Exception as e:
        ctx.app.logger.exception("TV dashboard snapshot manifest failed")
        ctx.send_json(500, {"ok": False, "error": str(e)})


def _handle_tv_auth_logout(ctx: _Ctx) -> None:
    from tv.store import clear_tv_backend_auth_state
    clear_tv_backend_auth_state()
    # Mirror to Access on best-effort basis
    try:
        from access.store import clear_auth_token
        clear_auth_token()
    except Exception:
        ctx.app.logger.warning("Access auth mirror clear failed during TV logout.", exc_info=True)
    try:
        ctx.app._update_manager.stop()
    except Exception:
        pass
    ctx.app.logger.info("TV Logout via API v2.")
    ctx.send_json(200, {"ok": True})


def _handle_auth_logout(ctx: _Ctx) -> None:
    try:
        ctx.app.after(0, ctx.app._on_click_logout.__wrapped__ if hasattr(ctx.app._on_click_logout, '__wrapped__') else lambda: None)
    except Exception:
        pass
    # Direct logout (don't wait for Tk confirmation)
    try:
        ctx.app.stop_realtime_agent()
    except Exception:
        pass
    from access.store import clear_auth_token
    clear_auth_token()
    try:
        from tv.auth_bridge import clear_tv_auth_bridge_state

        clear_tv_auth_bridge_state()
    except Exception:
        ctx.app.logger.warning("TV auth mirror clear failed during logout.", exc_info=True)
    try:
        ctx.app._update_manager.stop()
    except Exception:
        pass
    try:
        from access.store import save_sync_cache
        save_sync_cache(None)
    except Exception:
        pass
    ctx.app.logger.info("Logout via API v2.")
    try:
        ctx.app.after(0, ctx.app.evaluate_access_and_redirect)
    except Exception:
        pass
    ctx.send_json(200, {"ok": True})


def _handle_auth_verify_admin_password(ctx: _Ctx) -> None:
    """Validate the gym admin-agent / statistics password.

    Body: { "password": "<plain-text>" }
    Returns 200 { ok: true } on success, 401 { ok: false, error: "..." } on wrong password.
    """
    body = ctx.body()
    password = _safe_str(body.get("password"), "")
    if not password:
        ctx.send_json(400, {"ok": False, "error": "password is required"})
        return

    from access.store import load_auth_token
    auth = load_auth_token()
    if not auth or not auth.token:
        ctx.send_json(401, {"ok": False, "error": "Not authenticated"})
        return

    try:
        api = ctx.app._api()
        valid = api.validate_statistics_password(token=auth.token, password=password)
        if valid:
            ctx.send_json(200, {"ok": True})
        else:
            ctx.send_json(401, {"ok": False, "error": "Mot de passe incorrect"})
    except MonClubApiHttpError as e:
        ctx.app.logger.warning("verify_admin_password: HTTP %s", e.status_code)
        ctx.send_json(e.status_code, {"ok": False, "error": str(e)})
    except Exception as e:
        ctx.app.logger.exception("verify_admin_password failed")
        ctx.send_json(500, {"ok": False, "error": str(e)})


# ==================== 3) CONFIG ====================

_CONFIG_SENSITIVE = {"password", "commPassword", "comm_password"}
_UPDATE_RUNTIME_FIELDS = {
    "update_enabled",
    "update_platform",
    "update_channel",
    "update_check_interval_sec",
    "update_auto_download_zip",
}


def _serialize_component_config(component: str, cfg) -> Dict[str, Any]:
    if component == "tv":
        from tv.config import serialize_tv_config

        return serialize_tv_config(cfg)
    from access.config import serialize_access_config

    return serialize_access_config(cfg)


def _apply_component_config_patch(component: str, cfg, patch: Dict[str, Any]) -> Dict[str, Any]:
    if component == "tv":
        from tv.config import apply_tv_config_patch

        return apply_tv_config_patch(cfg, patch)
    from access.config import apply_access_config_patch

    return apply_access_config_patch(cfg, patch)


def _maybe_refresh_update_manager(ctx: _Ctx, changed: Dict[str, Any]) -> None:
    if not changed or not any(key in _UPDATE_RUNTIME_FIELDS for key in changed):
        return
    try:
        ctx.app.after(0, lambda: ctx.app._ensure_update_manager_started(check_now=False))
    except Exception:
        pass


def _handle_component_config_get(ctx: _Ctx, component: str) -> None:
    ctx.send_json(200, _serialize_component_config(component, ctx.app.cfg))


def _handle_component_config_patch(ctx: _Ctx, component: str) -> None:
    body = ctx.body()
    if not body:
        ctx.send_json(400, {"ok": False, "error": "empty body"})
        return
    changed = _apply_component_config_patch(component, ctx.app.cfg, body)
    if changed:
        ctx.app.persist_config()
        _maybe_refresh_update_manager(ctx, changed)
        ctx.app.logger.info("%s config patched via API v2: %s", component.upper(), list(changed.keys()))
    ctx.send_json(
        200,
        {"ok": True, "changed": changed, "config": _serialize_component_config(component, ctx.app.cfg)},
    )


def _handle_config_get(ctx: _Ctx) -> None:
    _handle_component_config_get(ctx, "access")


def _handle_config_patch(ctx: _Ctx) -> None:
    _handle_component_config_patch(ctx, "access")


def _handle_config_restart_api(ctx: _Ctx) -> None:
    try:
        ctx.app.after(0, ctx.app.restart_local_api_server)
    except Exception:
        pass
    ctx.send_json(200, {"ok": True, "message": "Local API restart scheduled"})


def _handle_tv_config_get(ctx: _Ctx) -> None:
    _handle_component_config_get(ctx, "tv")


def _handle_tv_config_patch(ctx: _Ctx) -> None:
    _handle_component_config_patch(ctx, "tv")


def _handle_tv_config_restart_api(ctx: _Ctx) -> None:
    _handle_config_restart_api(ctx)


# ==================== 4) SYNC + CACHE ====================

def _handle_sync_now(ctx: _Ctx) -> None:
    _logger.info("[LocalAPI] sync_now: manual sync triggered")
    try:
        ctx.app.after(0, ctx.app.request_sync_now)
    except Exception:
        pass
    ctx.send_json(200, {"ok": True, "message": "sync triggered"})


def _handle_sync_hard_reset(ctx: _Ctx) -> None:
    """Clear all device sync hashes so the next sync re-pushes every user, then trigger sync."""
    try:
        from app.core.db import clear_all_device_sync_hashes
        cleared = clear_all_device_sync_hashes()

        # Also clear ULTRA scheduler in-memory hashes for all devices
        ultra_eng = getattr(ctx.app, "_ultra_engine", None)
        if ultra_eng:
            sched = getattr(ultra_eng, "_sync_scheduler", None)
            if sched:
                for device_id in list(getattr(sched, "_last_hash", {}).keys()):
                    sched.force_resync(device_id)

        ctx.app.after(0, ctx.app.request_sync_now)
        ctx.send_json(200, {"ok": True, "cleared": cleared, "message": "Hard reset: all sync hashes cleared, full push triggered"})
    except Exception as e:
        _logger.exception("[LocalAPI] hard-reset failed")
        ctx.send_json(500, {"ok": False, "error": str(e)})


def _handle_sync_cache_meta(ctx: _Ctx) -> None:
    from access.store import load_sync_cache
    cache = load_sync_cache()
    if not cache:
        ctx.send_json(200, {"hasSyncData": False})
        return
    ctx.send_json(200, {
        "hasSyncData": True,
        "contractStatus": cache.contract_status,
        "contractEndDate": cache.contract_end_date,
        "lastSyncAt": getattr(cache, "updated_at", None),
        "userCount": len(cache.users),
        "deviceCount": len(cache.devices),
        "membershipCount": len(cache.membership),
        "infrastructureCount": len(cache.infrastructures),
        "credentialCount": len(cache.gym_access_credentials),
    })


def _handle_sync_cache_users(ctx: _Ctx) -> None:
    from access.store import load_sync_cache
    cache = load_sync_cache()
    users = list(cache.users) if cache else []
    limit = ctx.q_int("limit", default=0)
    offset = ctx.q_int("offset", default=0)
    total = len(users)
    if offset > 0:
        users = users[offset:]
    if limit > 0:
        users = users[:limit]
    ctx.send_json(200, {"users": users, "total": total})


def _handle_sync_cache_memberships(ctx: _Ctx) -> None:
    from access.store import load_sync_cache
    cache = load_sync_cache()
    ctx.send_json(200, {"memberships": list(cache.membership) if cache else []})


def _handle_sync_cache_devices(ctx: _Ctx) -> None:
    from app.core.db import list_sync_devices_payload
    try:
        devices = list_sync_devices_payload()
    except Exception:
        from access.store import load_sync_cache
        cache = load_sync_cache()
        devices = list(cache.devices) if cache else []
    ctx.send_json(200, {"devices": devices})


def _handle_sync_cache_infrastructures(ctx: _Ctx) -> None:
    from access.store import load_sync_cache
    cache = load_sync_cache()
    ctx.send_json(200, {"infrastructures": list(cache.infrastructures) if cache else []})


def _handle_sync_cache_credentials(ctx: _Ctx) -> None:
    from access.store import list_sync_gym_access_credentials
    creds = list_sync_gym_access_credentials()
    # mask secret hex for safety
    for c in creds:
        if isinstance(c, dict) and "secretHex" in c:
            sh = c["secretHex"]
            if sh and len(sh) > 8:
                c["secretHex"] = sh[:4] + "..." + sh[-4:]
    ctx.send_json(200, {"credentials": creds})



# ==================== 4.4) TV SYNC / CACHE / READINESS ====================

def _tv_snapshot_view(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    out = dict(row)
    out["is_latest"] = bool(int(out.get("is_latest") or 0))
    out["is_previous_ready"] = bool(int(out.get("is_previous_ready") or 0))
    out["is_fully_ready"] = bool(int(out.get("is_fully_ready") or 0)) if "is_fully_ready" in out else None
    for key in ("payload_json", "manifest_json"):
        if key in out:
            try:
                out[key.replace("_json", "")] = json.loads(out.get(key) or "{}")
            except Exception:
                out[key.replace("_json", "")] = {}
    return out


def _tv_resolve_binding_id(ctx: _Ctx, body: Optional[Dict[str, Any]] = None) -> int:
    bid = ctx.q_int("bindingId", "binding_id", default=0)
    if bid <= 0 and isinstance(body, dict):
        bid = _safe_int(body.get("bindingId") or body.get("binding_id"), 0)
    if bid <= 0:
        b = load_tv_screen_binding()
        bid = _safe_int(b.get("bindingId"), 0)
    return bid


def _tv_resolve_screen_id(ctx: _Ctx, body: Optional[Dict[str, Any]] = None) -> int:
    sid = ctx.q_int("screenId", "screen_id", default=0)
    if sid <= 0 and isinstance(body, dict):
        sid = _safe_int(body.get("screenId") or body.get("screen_id"), 0)
    if sid > 0:
        return sid
    bid = _tv_resolve_binding_id(ctx, body)
    if bid > 0:
        b = load_tv_screen_binding_by_id(binding_id=bid)
        sid = _safe_int((b or {}).get("screen_id"), 0)
    if sid <= 0:
        b = load_tv_screen_binding()
        sid = _safe_int(b.get("screenId"), 0)
    return sid


def _handle_tv_binding_get(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    binding = load_tv_screen_binding()
    ctx.send_json(200, {"ok": True, "binding": binding})


def _handle_tv_app_quit(ctx: _Ctx) -> None:
    def _shutdown() -> None:
        try:
            ctx.app.after(0, ctx.app.quit_app)
        except Exception:
            try:
                ctx.app.quit_app()
            except Exception:
                pass

    threading.Timer(0.2, _shutdown).start()
    ctx.send_json(200, {"ok": True, "message": "TV app shutdown scheduled."})


def _handle_tv_binding_patch(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    body = ctx.body()
    sid = _safe_int(body.get("screenId") or body.get("screen_id"), 0)
    name = _safe_str(body.get("screenName") or body.get("screen_name"), "").strip()
    if sid <= 0:
        ctx.send_json(400, {"ok": False, "error": "screenId is required and must be > 0"})
        return
    updated = save_tv_screen_binding(screen_id=sid, screen_name=name or None)
    ctx.send_json(200, {"ok": True, "binding": updated})



def _handle_tv_host_monitors_get(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    rows = list_tv_host_monitors()
    ctx.send_json(200, {"ok": True, "rows": rows, "total": len(rows)})


def _handle_tv_host_monitors_refresh(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    body = ctx.body()
    monitors = []
    if isinstance(body, list):
        monitors = body
    elif isinstance(body, dict):
        monitors = body.get("monitors") if isinstance(body.get("monitors"), list) else []
    rows = replace_tv_host_monitors(monitors=monitors)
    ctx.send_json(200, {"ok": True, "rows": rows, "total": len(rows)})


def _handle_tv_host_bindings_get(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    rows = []
    for row in list_tv_screen_bindings():
        binding = dict(row)
        bid = _safe_int(binding.get("id"), 0)
        binding["runtime"] = load_tv_screen_binding_runtime(binding_id=bid) if bid > 0 else None
        rows.append(binding)
    ctx.send_json(200, {"ok": True, "rows": rows, "total": len(rows)})


def _handle_tv_host_bindings_post(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    body = ctx.body()
    sid = _safe_int(body.get("screenId") or body.get("screen_id"), 0)
    if sid <= 0:
        ctx.send_json(400, {"ok": False, "error": "screenId is required and must be > 0"})
        return
    try:
        row = create_tv_screen_binding(
            screen_id=sid,
            screen_name=_safe_str(body.get("screenName") or body.get("screen_name"), "") or None,
            monitor_id=_safe_str(body.get("monitorId") or body.get("monitor_id"), "") or None,
            monitor_label=_safe_str(body.get("monitorLabel") or body.get("monitor_label"), "") or None,
            monitor_index=_safe_int(body.get("monitorIndex") or body.get("monitor_index"), 0) if (body.get("monitorIndex") is not None or body.get("monitor_index") is not None) else None,
            enabled=_safe_bool(body.get("enabled"), default=True),
            autostart=_safe_bool(body.get("autostart"), default=False),
            fullscreen=_safe_bool(body.get("fullscreen"), default=True),
            target_display_id=_safe_str(body.get("targetDisplayId") or body.get("target_display_id"), "") or None,
            target_display_path=_safe_str(body.get("targetDisplayPath") or body.get("target_display_path"), "") or None,
            last_known_friendly_name=_safe_str(body.get("lastKnownFriendlyName") or body.get("last_known_friendly_name"), "") or None,
            last_known_bounds_x=_safe_int(body.get("lastKnownBoundsX") or body.get("last_known_bounds_x"), 0) if (body.get("lastKnownBoundsX") is not None or body.get("last_known_bounds_x") is not None) else None,
            last_known_bounds_y=_safe_int(body.get("lastKnownBoundsY") or body.get("last_known_bounds_y"), 0) if (body.get("lastKnownBoundsY") is not None or body.get("last_known_bounds_y") is not None) else None,
            last_known_width=_safe_int(body.get("lastKnownWidth") or body.get("last_known_width"), 0) if (body.get("lastKnownWidth") is not None or body.get("last_known_width") is not None) else None,
            last_known_height=_safe_int(body.get("lastKnownHeight") or body.get("last_known_height"), 0) if (body.get("lastKnownHeight") is not None or body.get("last_known_height") is not None) else None,
            last_known_display_order_index=_safe_int(body.get("lastKnownDisplayOrderIndex") or body.get("last_known_display_order_index"), 0) if (body.get("lastKnownDisplayOrderIndex") is not None or body.get("last_known_display_order_index") is not None) else None,
            display_attach_confidence=_safe_str(body.get("displayAttachConfidence") or body.get("display_attach_confidence"), "") or None,
        )
        ctx.send_json(200, {"ok": True, "binding": row})
    except ValueError as e:
        ctx.send_json(400, {"ok": False, "error": str(e)})


def _handle_tv_host_binding_patch(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    bid = _safe_int(ctx.param("bindingId"), 0)
    if bid <= 0:
        ctx.send_json(400, {"ok": False, "error": "bindingId is required"})
        return
    body = ctx.body()
    try:
        row = update_tv_screen_binding(
            binding_id=bid,
            screen_name=_safe_str(body.get("screenName") or body.get("screen_name"), "") if ("screenName" in body or "screen_name" in body) else None,
            monitor_id=_safe_str(body.get("monitorId") or body.get("monitor_id"), "") if ("monitorId" in body or "monitor_id" in body) else None,
            monitor_label=_safe_str(body.get("monitorLabel") or body.get("monitor_label"), "") if ("monitorLabel" in body or "monitor_label" in body) else None,
            monitor_index=_safe_int(body.get("monitorIndex") or body.get("monitor_index"), 0) if ("monitorIndex" in body or "monitor_index" in body) else None,
            enabled=_safe_bool(body.get("enabled"), default=False) if "enabled" in body else None,
            autostart=_safe_bool(body.get("autostart"), default=False) if "autostart" in body else None,
            fullscreen=_safe_bool(body.get("fullscreen"), default=True) if "fullscreen" in body else None,
            target_display_id=_safe_str(body.get("targetDisplayId") or body.get("target_display_id"), "") if ("targetDisplayId" in body or "target_display_id" in body) else None,
            target_display_path=_safe_str(body.get("targetDisplayPath") or body.get("target_display_path"), "") if ("targetDisplayPath" in body or "target_display_path" in body) else None,
            last_known_friendly_name=_safe_str(body.get("lastKnownFriendlyName") or body.get("last_known_friendly_name"), "") if ("lastKnownFriendlyName" in body or "last_known_friendly_name" in body) else None,
            last_known_bounds_x=_safe_int(body.get("lastKnownBoundsX") or body.get("last_known_bounds_x"), 0) if ("lastKnownBoundsX" in body or "last_known_bounds_x" in body) else None,
            last_known_bounds_y=_safe_int(body.get("lastKnownBoundsY") or body.get("last_known_bounds_y"), 0) if ("lastKnownBoundsY" in body or "last_known_bounds_y" in body) else None,
            last_known_width=_safe_int(body.get("lastKnownWidth") or body.get("last_known_width"), 0) if ("lastKnownWidth" in body or "last_known_width" in body) else None,
            last_known_height=_safe_int(body.get("lastKnownHeight") or body.get("last_known_height"), 0) if ("lastKnownHeight" in body or "last_known_height" in body) else None,
            last_known_display_order_index=_safe_int(body.get("lastKnownDisplayOrderIndex") or body.get("last_known_display_order_index"), 0) if ("lastKnownDisplayOrderIndex" in body or "last_known_display_order_index" in body) else None,
            display_attach_confidence=_safe_str(body.get("displayAttachConfidence") or body.get("display_attach_confidence"), "") if ("displayAttachConfidence" in body or "display_attach_confidence" in body) else None,
        )
        ctx.send_json(200, {"ok": True, "binding": row})
    except ValueError as e:
        ctx.send_json(400, {"ok": False, "error": str(e)})


def _handle_tv_host_binding_delete(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    bid = _safe_int(ctx.param("bindingId"), 0)
    if bid <= 0:
        ctx.send_json(400, {"ok": False, "error": "bindingId is required"})
        return
    try:
        ok = delete_tv_screen_binding(binding_id=bid)
        if not ok:
            ctx.send_json(404, {"ok": False, "error": "Binding not found"})
            return
        ctx.send_json(200, {"ok": True})
    except ValueError as e:
        ctx.send_json(400, {"ok": False, "error": str(e)})


def _handle_tv_host_binding_start(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    bid = _safe_int(ctx.param("bindingId"), 0)
    if bid <= 0:
        ctx.send_json(400, {"ok": False, "error": "bindingId is required"})
        return
    try:
        row = start_tv_screen_binding(binding_id=bid)
        ctx.send_json(200, {"ok": True, "binding": row})
    except ValueError as e:
        ctx.send_json(400, {"ok": False, "error": str(e)})


def _handle_tv_host_binding_stop(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    bid = _safe_int(ctx.param("bindingId"), 0)
    if bid <= 0:
        ctx.send_json(400, {"ok": False, "error": "bindingId is required"})
        return
    try:
        row = stop_tv_screen_binding(binding_id=bid)
        ctx.send_json(200, {"ok": True, "binding": row})
    except ValueError as e:
        ctx.send_json(400, {"ok": False, "error": str(e)})


def _handle_tv_host_binding_restart(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    bid = _safe_int(ctx.param("bindingId"), 0)
    if bid <= 0:
        ctx.send_json(400, {"ok": False, "error": "bindingId is required"})
        return
    try:
        row = restart_tv_screen_binding(binding_id=bid)
        ctx.send_json(200, {"ok": True, "binding": row})
    except ValueError as e:
        ctx.send_json(400, {"ok": False, "error": str(e)})


def _handle_tv_host_binding_status(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    bid = _safe_int(ctx.param("bindingId"), 0)
    if bid <= 0:
        ctx.send_json(400, {"ok": False, "error": "bindingId is required"})
        return
    row = get_tv_screen_binding(binding_id=bid)
    if not row:
        ctx.send_json(404, {"ok": False, "error": "Binding not found"})
        return
    ctx.send_json(200, {"ok": True, "binding": row})


def _handle_tv_host_binding_events(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    bid = _safe_int(ctx.param("bindingId"), 0)
    if bid <= 0:
        ctx.send_json(400, {"ok": False, "error": "bindingId is required"})
        return
    limit = max(1, min(ctx.q_int("limit", default=100), 500))
    offset = max(0, ctx.q_int("offset", default=0))
    rows = list_tv_screen_binding_events(binding_id=bid, limit=limit, offset=offset)
    ctx.send_json(200, {"ok": True, "rows": rows.get("rows") or [], "total": int(rows.get("total") or 0)})



def _handle_tv_host_binding_support_summary(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    bid = _safe_int(ctx.param("bindingId"), 0)
    if bid <= 0:
        ctx.send_json(400, {"ok": False, "error": "bindingId is required"})
        return
    summary = load_tv_binding_support_summary(binding_id=bid)
    if not bool(summary.get("ok")):
        ctx.send_json(404, {"ok": False, "error": summary.get("error") or "BINDING_NOT_FOUND"})
        return
    ctx.send_json(200, summary)


def _handle_tv_host_binding_support_action_run(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    bid = _safe_int(ctx.param("bindingId"), 0)
    if bid <= 0:
        ctx.send_json(400, {"ok": False, "error": "bindingId is required"})
        return
    body = ctx.body()
    action_type = _safe_str(body.get("actionType") or body.get("action_type"), "").strip()
    if not action_type:
        ctx.send_json(400, {"ok": False, "error": "actionType is required"})
        return
    options = body.get("options") if isinstance(body.get("options"), dict) else {}
    confirm = _safe_bool(body.get("confirm"), default=False)
    triggered_by = _safe_str(body.get("triggeredBy") or body.get("triggered_by"), "").strip() or "LOCAL_OPERATOR"

    result = run_tv_binding_support_action(
        app=ctx.app,
        binding_id=bid,
        action_type=action_type,
        options=options,
        confirm=confirm,
        triggered_by=triggered_by,
    )
    code = 200
    if not bool(result.get("ok")) and _safe_str(result.get("error"), "") == "BINDING_NOT_FOUND":
        code = 404
    ctx.send_json(code, result)


def _handle_tv_host_binding_support_action_history(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    bid = _safe_int(ctx.param("bindingId"), 0)
    if bid <= 0:
        ctx.send_json(400, {"ok": False, "error": "bindingId is required"})
        return
    limit = max(1, min(ctx.q_int("limit", default=100), 500))
    offset = max(0, ctx.q_int("offset", default=0))
    rows = list_tv_support_action_logs(binding_id=bid, limit=limit, offset=offset)
    ctx.send_json(200, {"ok": True, "rows": rows.get("rows") or [], "total": int(rows.get("total") or 0)})
def _handle_tv_host_binding_runtime_event(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    bid = _safe_int(ctx.param("bindingId"), 0)
    if bid <= 0:
        ctx.send_json(400, {"ok": False, "error": "bindingId is required"})
        return
    body = ctx.body()
    evt = _safe_str(body.get("eventType") or body.get("event_type"), "").strip()
    if not evt:
        ctx.send_json(400, {"ok": False, "error": "eventType is required"})
        return
    try:
        row = record_tv_screen_binding_runtime_event(
            binding_id=bid,
            event_type=evt,
            window_id=_safe_str(body.get("windowId") or body.get("window_id"), "") or None,
            error_code=_safe_str(body.get("errorCode") or body.get("error_code"), "") or None,
            error_message=_safe_str(body.get("errorMessage") or body.get("error_message"), "") or None,
            correlation_id=_safe_str(body.get("correlationId") or body.get("correlation_id"), "") or None,
        )
        ctx.send_json(200, {"ok": True, "binding": row})
    except ValueError as e:
        ctx.send_json(400, {"ok": False, "error": str(e)})


def _handle_tv_observability_bindings(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    limit = max(1, min(ctx.q_int("limit", default=200), 2000))
    offset = max(0, ctx.q_int("offset", default=0))
    gym_id = ctx.q_int("gymId", "gym_id", default=0)
    health = _safe_str(ctx.q("health", default=""), "").strip() or None
    runtime_state = _safe_str(ctx.q("runtimeState", "runtime_state", default=""), "").strip() or None
    q = _safe_str(ctx.q("q", "query", default=""), "").strip() or None
    problem_only = _safe_bool(ctx.q("problemOnly", "problem_only", default="0"), default=False)
    data = list_tv_observability_bindings(
        health=health,
        gym_id=(gym_id if gym_id > 0 else None),
        runtime_state=runtime_state,
        q=q,
        problem_only=problem_only,
        limit=limit,
        offset=offset,
    )
    ctx.send_json(200, data)


def _handle_tv_observability_binding_detail(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    bid = _safe_int(ctx.param("bindingId"), 0)
    if bid <= 0:
        ctx.send_json(400, {"ok": False, "error": "bindingId is required"})
        return
    event_limit = max(1, min(ctx.q_int("eventLimit", "event_limit", default=40), 500))
    history_limit = max(1, min(ctx.q_int("historyLimit", "history_limit", default=20), 200))
    data = get_tv_observability_binding(binding_id=bid, event_limit=event_limit, history_limit=history_limit)
    if not bool(data.get("ok")):
        ctx.send_json(404, {"ok": False, "error": data.get("error") or "BINDING_NOT_FOUND"})
        return
    ctx.send_json(200, data)


def _handle_tv_observability_gyms(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    limit = max(1, min(ctx.q_int("limit", default=100), 1000))
    offset = max(0, ctx.q_int("offset", default=0))
    data = list_tv_observability_gyms(limit=limit, offset=offset)
    ctx.send_json(200, data)


def _handle_tv_observability_gym_detail(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    gym_id = _safe_int(ctx.param("gymId"), 0)
    if gym_id <= 0:
        ctx.send_json(400, {"ok": False, "error": "gymId is required"})
        return
    data = get_tv_observability_gym(gym_id=gym_id)
    if not bool(data.get("ok")):
        ctx.send_json(404, {"ok": False, "error": data.get("error") or "GYM_NOT_FOUND"})
        return
    ctx.send_json(200, data)


def _handle_tv_observability_proofs_v2(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    limit = max(1, min(ctx.q_int("limit", default=200), 1000))
    offset = max(0, ctx.q_int("offset", default=0))
    gym_id = ctx.q_int("gymId", "gym_id", default=0)
    binding_id = ctx.q_int("bindingId", "binding_id", default=0)
    outbox_states = _split_csv_upper(ctx.q("outboxStates", "outbox_states", default=""))
    result_status = _safe_str(ctx.q("resultStatus", "result_status", default=""), "").strip() or None
    countable_raw = _safe_str(ctx.q("countable", default=""), "").strip().lower()
    countable = None
    if countable_raw in {"1", "true", "yes"}:
        countable = True
    elif countable_raw in {"0", "false", "no"}:
        countable = False
    data = list_tv_observability_proofs(
        gym_id=(gym_id if gym_id > 0 else None),
        binding_id=(binding_id if binding_id > 0 else None),
        outbox_states=(outbox_states or None),
        result_status=result_status,
        countable=countable,
        limit=limit,
        offset=offset,
    )
    ctx.send_json(200, data)


def _handle_tv_observability_retention(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    ctx.send_json(200, get_tv_observability_retention())


def _handle_tv_observability_retention_run(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    body = ctx.body()
    dry_run = _safe_bool(body.get("dryRun"), default=False)
    include_checks = _safe_bool(body.get("includeQueryChecks"), default=False)
    data = run_tv_retention_maintenance(dry_run=dry_run, include_query_checks=include_checks)
    ctx.send_json(200, data)


def _handle_tv_observability_events_v2(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    limit = max(1, min(ctx.q_int("limit", default=100), 1000))
    offset = max(0, ctx.q_int("offset", default=0))
    binding_id = ctx.q_int("bindingId", "binding_id", default=0)
    gym_id = ctx.q_int("gymId", "gym_id", default=0)
    sources = _split_csv_upper(ctx.q("sources", "source", default=""))
    data = list_tv_observability_events(
        binding_id=(binding_id if binding_id > 0 else None),
        gym_id=(gym_id if gym_id > 0 else None),
        limit=limit,
        offset=offset,
        sources=(sources or None),
    )
    ctx.send_json(200, {"ok": True, **data})


def _handle_tv_player_status(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    bid = _safe_int(ctx.param("bindingId"), 0)
    if bid <= 0:
        ctx.send_json(400, {"ok": False, "error": "bindingId is required"})
        return
    status = load_tv_player_status(binding_id=bid)
    if not bool(status.get("ok")):
        ctx.send_json(404, {"ok": False, "error": status.get("error") or "BINDING_NOT_FOUND"})
        return
    ctx.send_json(200, status)


def _handle_tv_player_render_context(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    bid = _safe_int(ctx.param("bindingId"), 0)
    if bid <= 0:
        ctx.send_json(400, {"ok": False, "error": "bindingId is required"})
        return
    persist = _safe_bool(ctx.q("persist", default="0"), default=False)
    context = get_tv_player_render_context(binding_id=bid, persist=persist)
    code = 200 if bool(context.get("ok")) else 404
    ctx.send_json(code, context)


def _handle_tv_player_reevaluate(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    bid = _safe_int(ctx.param("bindingId"), 0)
    if bid <= 0:
        ctx.send_json(400, {"ok": False, "error": "bindingId is required"})
        return
    body = ctx.body()
    persist = _safe_bool(body.get("persist"), default=True)
    result = reevaluate_tv_player(binding_id=bid, persist=persist)
    code = 200 if bool(result.get("ok")) else 404
    ctx.send_json(code, result)


def _handle_tv_player_reload(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    bid = _safe_int(ctx.param("bindingId"), 0)
    if bid <= 0:
        ctx.send_json(400, {"ok": False, "error": "bindingId is required"})
        return
    body = ctx.body()
    persist = _safe_bool(body.get("persist"), default=True)
    try:
        result = reload_tv_player(binding_id=bid, persist=persist)
        code = 200 if bool(result.get("ok")) else 404
        ctx.send_json(code, result)
    except ValueError as e:
        ctx.send_json(400, {"ok": False, "error": str(e)})


def _handle_tv_player_state_report(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    bid = _safe_int(ctx.param("bindingId"), 0)
    if bid <= 0:
        ctx.send_json(400, {"ok": False, "error": "bindingId is required"})
        return
    body = ctx.body()
    payload = body.get("state") if isinstance(body.get("state"), dict) else body
    event_type = _safe_str(body.get("eventType") or body.get("event_type"), "").strip() or "PLAYER_STATE_CHANGED"
    force = _safe_bool(body.get("force"), default=False)
    freshness = _safe_int(body.get("freshnessSeconds"), 20)
    try:
        out = report_tv_player_state(
            binding_id=bid,
            payload=payload if isinstance(payload, dict) else {},
            event_type=event_type,
            force=force,
            freshness_seconds=max(0, freshness),
        )
        ctx.send_json(200, {"ok": True, **out})
    except ValueError as e:
        ctx.send_json(400, {"ok": False, "error": str(e)})


def _handle_tv_player_events(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    bid = _safe_int(ctx.param("bindingId"), 0)
    if bid <= 0:
        ctx.send_json(400, {"ok": False, "error": "bindingId is required"})
        return
    limit = max(1, min(ctx.q_int("limit", default=100), 500))
    offset = max(0, ctx.q_int("offset", default=0))
    data = list_tv_player_events(binding_id=bid, limit=limit, offset=offset)
    ctx.send_json(200, {"ok": True, "rows": data.get("rows") or [], "total": int(data.get("total") or 0)})
def _handle_tv_sync_run(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    body = ctx.body()
    sid = _tv_resolve_screen_id(ctx, body)
    if sid <= 0:
        ctx.send_json(400, {"ok": False, "error": "No bound screen. Set /api/v2/tv/binding first."})
        return
    resolve_at = _safe_str(body.get("resolveAt") or body.get("resolve_at") or ctx.q("resolveAt", "resolve_at", default=""), "").strip()
    result = sync_latest_snapshot_for_screen(app=ctx.app, screen_id=sid, resolve_at=(resolve_at or None))
    code = 200 if bool(result.get("ok")) else 502
    ctx.send_json(code, result)


def _handle_tv_sync_status(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    sid = _tv_resolve_screen_id(ctx)
    if sid <= 0:
        ctx.send_json(200, {"ok": True, "screenId": None, "binding": load_tv_screen_binding(), "lastRun": None, "latestSnapshot": None, "latestReadySnapshot": None, "previousReadySnapshot": None, "latestReadiness": None, "latestDownloadBatch": None, "activation": None})
        return
    ctx.send_json(200, {
        "ok": True,
        "screenId": sid,
        "binding": load_tv_screen_binding(),
        "lastRun": load_latest_tv_sync_run(screen_id=sid),
        "latestSnapshot": _tv_snapshot_view(load_tv_latest_snapshot(screen_id=sid)),
        "latestReadySnapshot": _tv_snapshot_view(load_tv_latest_ready_snapshot(screen_id=sid)),
        "previousReadySnapshot": _tv_snapshot_view(load_tv_previous_ready_snapshot(screen_id=sid)),
        "latestReadiness": load_tv_latest_readiness(screen_id=sid),
        "latestDownloadBatch": load_tv_latest_download_batch(screen_id=sid),
        "activation": load_tv_activation_status(screen_id=sid),
    })


def _handle_tv_snapshot_latest(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    sid = _tv_resolve_screen_id(ctx)
    if sid <= 0:
        ctx.send_json(400, {"ok": False, "error": "No bound screen. Set /api/v2/tv/binding first."})
        return
    ctx.send_json(200, {
        "ok": True,
        "screenId": sid,
        "latest": _tv_snapshot_view(load_tv_latest_snapshot(screen_id=sid)),
        "latestReady": _tv_snapshot_view(load_tv_latest_ready_snapshot(screen_id=sid)),
        "previousReady": _tv_snapshot_view(load_tv_previous_ready_snapshot(screen_id=sid)),
    })


def _handle_tv_snapshot_by_id(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    snapshot_id = _safe_str(ctx.param("snapshotId"), "").strip()
    if not snapshot_id:
        ctx.send_json(400, {"ok": False, "error": "snapshotId is required"})
        return
    row = load_tv_snapshot_by_id(snapshot_id)
    if not row:
        ctx.send_json(404, {"ok": False, "error": "Snapshot not found"})
        return
    ctx.send_json(200, {"ok": True, "snapshot": _tv_snapshot_view(row)})


def _handle_tv_snapshot_manifest_by_id(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    snapshot_id = _safe_str(ctx.param("snapshotId"), "").strip()
    if not snapshot_id:
        ctx.send_json(400, {"ok": False, "error": "snapshotId is required"})
        return
    row = load_tv_snapshot_by_id(snapshot_id)
    if not row:
        ctx.send_json(404, {"ok": False, "error": "Snapshot not found"})
        return
    ctx.send_json(200, {"ok": True, "snapshotId": snapshot_id, "manifest": load_tv_snapshot_manifest(snapshot_id)})


def _handle_tv_readiness_latest(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    sid = _tv_resolve_screen_id(ctx)
    if sid <= 0:
        ctx.send_json(400, {"ok": False, "error": "No bound screen. Set /api/v2/tv/binding first."})
        return
    readiness = load_tv_latest_readiness(screen_id=sid)
    ctx.send_json(200, {
        "ok": True,
        "screenId": sid,
        "readiness": readiness,
        "latestSnapshot": _tv_snapshot_view(load_tv_latest_snapshot(screen_id=sid)),
        "previousReadySnapshot": _tv_snapshot_view(load_tv_previous_ready_snapshot(screen_id=sid)),
    })


def _handle_tv_cache_assets(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    sid = _tv_resolve_screen_id(ctx)
    if sid <= 0:
        ctx.send_json(400, {"ok": False, "error": "No bound screen. Set /api/v2/tv/binding first."})
        return

    version_raw = ctx.q("snapshotVersion", "snapshot_version", default="").strip()
    snapshot_version = _safe_int(version_raw, 0) if version_raw else None
    if snapshot_version is not None and snapshot_version <= 0:
        snapshot_version = None

    states_raw = ctx.q("states", "assetStates", default="")
    states: List[str] = []
    for part in states_raw.replace(";", ",").split(","):
        s = _safe_str(part, "").strip().upper()
        if s and s not in states:
            states.append(s)

    limit = max(1, min(ctx.q_int("limit", default=5000), 20000))
    offset = max(0, ctx.q_int("offset", default=0))

    assets = list_tv_cache_assets(
        screen_id=sid,
        snapshot_version=snapshot_version,
        states=states,
        limit=limit,
        offset=offset,
    )

    ctx.send_json(200, {
        "ok": True,
        "screenId": sid,
        "snapshotVersion": assets.get("snapshotVersion"),
        "rows": assets.get("rows") or [],
        "total": int(assets.get("total") or 0),
        "latestReadiness": load_tv_latest_readiness(screen_id=sid),
        "latestSnapshot": _tv_snapshot_view(load_tv_latest_snapshot(screen_id=sid)),
    })

def _handle_tv_downloads_run(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    body = ctx.body()
    sid = _tv_resolve_screen_id(ctx, body)
    if sid <= 0:
        ctx.send_json(400, {"ok": False, "error": "No bound screen. Set /api/v2/tv/binding first."})
        return

    snapshot_version = _safe_int(body.get("snapshotVersion") or body.get("snapshot_version"), 0)
    if snapshot_version <= 0:
        snapshot_version = 0
    run_bg = _safe_bool(body.get("runInBackground") if "runInBackground" in body else body.get("background"), default=False)
    retry_failed_only = _safe_bool(body.get("retryFailedOnly"), default=False)
    force = _safe_bool(body.get("force"), default=False)
    media_asset_id = _safe_str(body.get("mediaAssetId") or body.get("media_asset_id"), "").strip() or None
    max_attempts = max(1, min(_safe_int(body.get("maxAttempts"), 3), 5))
    max_concurrency = max(1, min(_safe_int(body.get("maxConcurrency"), 1), 4))

    result = run_tv_download_batch(
        screen_id=sid,
        snapshot_version=(snapshot_version if snapshot_version > 0 else None),
        trigger_source="MANUAL",
        retry_failed_only=retry_failed_only,
        media_asset_id=media_asset_id,
        force=force,
        max_attempts=max_attempts,
        run_in_background=run_bg,
        max_concurrency=max_concurrency,
    )
    code = 200 if bool(result.get("ok")) else 400
    ctx.send_json(code, result)


def _handle_tv_downloads_latest_batch(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    sid = _tv_resolve_screen_id(ctx)
    if sid <= 0:
        ctx.send_json(200, {"ok": True, "screenId": None, "batch": None})
        return
    batch = load_tv_latest_download_batch(screen_id=sid)
    ctx.send_json(200, {"ok": True, "screenId": sid, "batch": batch})


def _handle_tv_downloads_jobs(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    sid = _tv_resolve_screen_id(ctx)
    if sid <= 0:
        ctx.send_json(400, {"ok": False, "error": "No bound screen. Set /api/v2/tv/binding first."})
        return

    version_raw = ctx.q("snapshotVersion", "snapshot_version", default="").strip()
    snapshot_version = _safe_int(version_raw, 0) if version_raw else None
    if snapshot_version is not None and snapshot_version <= 0:
        snapshot_version = None

    batch_id = _safe_str(ctx.q("batchId", "batch_id", default=""), "").strip() or None
    states_raw = ctx.q("states", "state", default="")
    states: List[str] = []
    for part in states_raw.replace(";", ",").split(","):
        s = _safe_str(part, "").strip().upper()
        if s and s not in states:
            states.append(s)

    limit = max(1, min(ctx.q_int("limit", default=500), 5000))
    offset = max(0, ctx.q_int("offset", default=0))

    jobs = list_tv_download_jobs(
        screen_id=sid,
        snapshot_version=snapshot_version,
        batch_id=batch_id,
        states=states,
        limit=limit,
        offset=offset,
    )
    ctx.send_json(200, {
        "ok": True,
        "screenId": sid,
        "rows": jobs.get("rows") or [],
        "total": int(jobs.get("total") or 0),
        "latestBatch": load_tv_latest_download_batch(screen_id=sid),
        "latestReadiness": load_tv_latest_readiness(screen_id=sid),
    })



def _handle_tv_ad_tasks_list(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    gym_id = _safe_int(ctx.q("gymId", "gym_id", default=""), 0)
    remote_statuses = _split_csv_upper(ctx.q("remoteStatuses", "remoteStatus", "status", default=""))
    local_states = _split_csv_upper(ctx.q("localStates", "localState", "localPreparationStates", default=""))
    q = _safe_str(ctx.q("q", "query", default=""), "").strip() or None
    limit = max(1, min(ctx.q_int("limit", default=300), 5000))
    offset = max(0, ctx.q_int("offset", default=0))

    data = list_tv_ad_task_cache(
        gym_id=(gym_id if gym_id > 0 else None),
        remote_statuses=remote_statuses,
        local_states=local_states,
        q=q,
        limit=limit,
        offset=offset,
    )
    ctx.send_json(
        200,
        {
            "ok": True,
            "rows": data.get("rows") or [],
            "total": int(data.get("total") or 0),
            "limit": int(data.get("limit") or limit),
            "offset": int(data.get("offset") or offset),
        },
    )


def _handle_tv_ad_tasks_fetch(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    body = ctx.body()
    force = _safe_bool(body.get("force") if isinstance(body, dict) else False, default=False)
    limit = max(1, min(_safe_int((body.get("limit") if isinstance(body, dict) else 1000), 1000), 2000))
    correlation_id = _safe_str((body.get("correlationId") if isinstance(body, dict) else ""), "").strip() or None

    result = fetch_tv_ad_tasks_for_host(
        app=ctx.app,
        force=force,
        limit=limit,
        correlation_id=correlation_id,
    )
    code = 200 if bool(result.get("ok")) else 502
    ctx.send_json(code, result)


def _handle_tv_ad_tasks_prepare(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    body = ctx.body()
    campaign_task_id = _safe_int((body.get("campaignTaskId") if isinstance(body, dict) else 0), 0)
    force = _safe_bool(body.get("force") if isinstance(body, dict) else False, default=False)
    limit = max(1, min(_safe_int((body.get("limit") if isinstance(body, dict) else 300), 300), 2000))
    process_confirm = _safe_bool(body.get("processConfirm") if isinstance(body, dict) else True, default=True)
    correlation_id = _safe_str((body.get("correlationId") if isinstance(body, dict) else ""), "").strip() or None

    prepare = prepare_tv_ad_tasks(
        app=ctx.app,
        campaign_task_id=(campaign_task_id if campaign_task_id > 0 else None),
        force=force,
        limit=limit,
        correlation_id=correlation_id,
    )
    confirm: Dict[str, Any] = {"ok": True, "skipped": "NOT_REQUESTED"}
    if process_confirm:
        confirm = process_tv_ad_ready_confirm_outbox(app=ctx.app, force=False, limit=200, correlation_id=correlation_id)

    ok = bool(prepare.get("ok")) and bool(confirm.get("ok"))
    code = 200 if ok else 502
    ctx.send_json(code, {"ok": ok, "prepare": prepare, "confirm": confirm})


def _handle_tv_ad_tasks_cycle(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    body = ctx.body()
    force_fetch = _safe_bool(body.get("forceFetch") if isinstance(body, dict) else False, default=False)
    force_prepare = _safe_bool(body.get("forcePrepare") if isinstance(body, dict) else False, default=False)
    force_confirm = _safe_bool(body.get("forceConfirm") if isinstance(body, dict) else False, default=False)
    correlation_id = _safe_str((body.get("correlationId") if isinstance(body, dict) else ""), "").strip() or None
    result = run_tv_ad_task_cycle(
        app=ctx.app,
        force_fetch=force_fetch,
        force_prepare=force_prepare,
        force_confirm=force_confirm,
        correlation_id=correlation_id,
    )
    code = 200 if bool(result.get("ok")) else 502
    ctx.send_json(code, result)


def _handle_tv_ad_tasks_retry_prepare(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    task_id = _safe_int(ctx.param("taskId"), 0)
    if task_id <= 0:
        ctx.send_json(400, {"ok": False, "error": "taskId is required"})
        return
    body = ctx.body()
    correlation_id = _safe_str((body.get("correlationId") if isinstance(body, dict) else ""), "").strip() or None
    result = retry_tv_ad_task_prepare(app=ctx.app, campaign_task_id=task_id, correlation_id=correlation_id)
    code = 200 if bool(result.get("ok")) else 400
    ctx.send_json(code, result)


def _handle_tv_ad_tasks_retry_confirm(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    task_id = _safe_int(ctx.param("taskId"), 0)
    if task_id <= 0:
        ctx.send_json(400, {"ok": False, "error": "taskId is required"})
        return
    body = ctx.body()
    correlation_id = _safe_str((body.get("correlationId") if isinstance(body, dict) else ""), "").strip() or None
    result = retry_tv_ad_task_ready_confirm(app=ctx.app, campaign_task_id=task_id, correlation_id=correlation_id)
    code = 200 if bool(result.get("ok")) else 400
    ctx.send_json(code, result)
def _handle_tv_ad_tasks_runtime_list(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    gym_id = _safe_int(ctx.q("gymId", "gym_id", default=""), 0)
    task_id = _safe_int(ctx.q("taskId", "campaignTaskId", "campaign_task_id", default=""), 0)
    limit = max(1, min(ctx.q_int("limit", default=300), 5000))
    offset = max(0, ctx.q_int("offset", default=0))
    data = list_tv_ad_task_runtime(
        gym_id=(gym_id if gym_id > 0 else None),
        campaign_task_id=(task_id if task_id > 0 else None),
        limit=limit,
        offset=offset,
    )
    ctx.send_json(200, {"ok": True, "rows": data.get("rows") or [], "total": int(data.get("total") or 0), "limit": int(data.get("limit") or limit), "offset": int(data.get("offset") or offset)})


def _handle_tv_ad_tasks_runtime_one(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    task_id = _safe_int(ctx.param("taskId"), 0)
    if task_id <= 0:
        ctx.send_json(400, {"ok": False, "error": "taskId is required"})
        return
    row = load_tv_ad_task_runtime(campaign_task_id=task_id)
    if not row:
        ctx.send_json(404, {"ok": False, "error": "Task runtime not found"})
        return
    ctx.send_json(200, {"ok": True, "runtime": row})


def _handle_tv_gym_ad_runtime_one(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    gym_id = _safe_int(ctx.param("gymId"), 0)
    if gym_id <= 0:
        ctx.send_json(400, {"ok": False, "error": "gymId is required"})
        return
    row = load_tv_gym_ad_runtime(gym_id=gym_id)
    if not row:
        ctx.send_json(404, {"ok": False, "error": "Gym ad runtime not found"})
        return
    ctx.send_json(200, {"ok": True, "runtime": row})


def _handle_tv_ad_tasks_inject_now(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    task_id = _safe_int(ctx.param("taskId"), 0)
    if task_id <= 0:
        ctx.send_json(400, {"ok": False, "error": "taskId is required"})
        return
    body = ctx.body()
    support_confirm = _safe_bool(body.get("support") if isinstance(body, dict) else False, default=False) or _safe_bool(body.get("confirm") if isinstance(body, dict) else False, default=False)
    if not support_confirm:
        ctx.send_json(403, {"ok": False, "error": "SUPPORT_CONFIRM_REQUIRED"})
        return
    correlation_id = _safe_str((body.get("correlationId") if isinstance(body, dict) else ""), "").strip() or None
    result = inject_tv_ad_task_now(campaign_task_id=task_id, correlation_id=correlation_id)
    code = 200 if bool(result.get("ok")) else 400
    ctx.send_json(code, result)


def _handle_tv_ad_tasks_abort(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    task_id = _safe_int(ctx.param("taskId"), 0)
    if task_id <= 0:
        ctx.send_json(400, {"ok": False, "error": "taskId is required"})
        return
    body = ctx.body()
    support_confirm = _safe_bool(body.get("support") if isinstance(body, dict) else False, default=False) or _safe_bool(body.get("confirm") if isinstance(body, dict) else False, default=False)
    if not support_confirm:
        ctx.send_json(403, {"ok": False, "error": "SUPPORT_CONFIRM_REQUIRED"})
        return
    reason = _safe_str((body.get("reason") if isinstance(body, dict) else ""), "").strip() or "MANUAL_ABORT"
    correlation_id = _safe_str((body.get("correlationId") if isinstance(body, dict) else ""), "").strip() or None
    result = abort_tv_ad_task_now(campaign_task_id=task_id, reason=reason, correlation_id=correlation_id)
    code = 200 if bool(result.get("ok")) else 400
    ctx.send_json(code, result)


def _handle_tv_ad_reconcile_all(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    result = reconcile_all_active_gyms()
    ctx.send_json(200, result)


def _handle_tv_ad_evaluate(ctx: _Ctx) -> None:
    """POST /api/v2/tv/ad-runtime/evaluate — trigger due-task evaluation and injection cycle."""
    ensure_tv_local_schema()
    result = reconcile_all_active_gyms()
    ctx.send_json(200, result)



def _handle_tv_ad_startup_recover(ctx: _Ctx) -> None:
    """F27: Startup recovery — reset transient ad runtime states after crash."""
    result = startup_recover_ad_runtime()
    code = 200 if bool(result.get("ok")) else 500
    ctx.send_json(code, result)


def _handle_tv_ad_proofs_list(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    gym_id = _safe_int(ctx.q("gymId", "gym_id", default=""), 0)
    task_id = _safe_int(ctx.q("taskId", "campaignTaskId", "campaign_task_id", default=""), 0)
    states_raw = _safe_str(ctx.q("outboxStates", "outbox_states", default=""), "").strip()
    states = [s.strip().upper() for s in states_raw.split(",") if s.strip()] if states_raw else None
    limit = max(1, min(ctx.q_int("limit", default=300), 5000))
    offset = max(0, ctx.q_int("offset", default=0))
    data = list_tv_ad_proof_outbox(
        gym_id=(gym_id if gym_id > 0 else None),
        campaign_task_id=(task_id if task_id > 0 else None),
        outbox_states=states,
        limit=limit,
        offset=offset,
    )
    ctx.send_json(200, {"ok": True, "rows": data.get("rows") or [], "total": int(data.get("total") or 0), "limit": int(data.get("limit") or limit), "offset": int(data.get("offset") or offset)})


def _handle_tv_ad_proofs_one(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    proof_id = _safe_int(ctx.param("proofId"), 0)
    if proof_id <= 0:
        ctx.send_json(400, {"ok": False, "error": "proofId is required"})
        return
    row = load_tv_ad_proof(local_proof_id=proof_id)
    if not row:
        ctx.send_json(404, {"ok": False, "error": "Proof not found"})
        return
    ctx.send_json(200, {"ok": True, "proof": row})


def _handle_tv_ad_proofs_process_outbox(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    body = ctx.body()
    limit = max(1, min(_safe_int((body.get("limit") if isinstance(body, dict) else 50), 50), 200))
    correlation_id = _safe_str((body.get("correlationId") if isinstance(body, dict) else ""), "").strip() or None
    result = process_tv_ad_proof_outbox(app=ctx.app, limit=limit, correlation_id=correlation_id)
    ctx.send_json(200, result)


def _handle_tv_ad_proofs_retry(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    proof_id = _safe_int(ctx.param("proofId"), 0)
    if proof_id <= 0:
        ctx.send_json(400, {"ok": False, "error": "proofId is required"})
        return
    result = retry_tv_ad_proof(app=ctx.app, local_proof_id=proof_id)
    code = 200 if bool(result.get("ok")) else 400
    ctx.send_json(code, result)


def _handle_tv_ad_proofs_startup_recover(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    result = startup_recover_proof_outbox()
    ctx.send_json(200, result)


def _handle_tv_screen_messages_post(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    body = ctx.body()
    binding_id = _safe_int(body.get("bindingId") or body.get("binding_id"), 0)
    if binding_id <= 0:
        ctx.send_json(400, {"ok": False, "error": "bindingId is required and must be > 0"})
        return
    title = _safe_str(body.get("title"), "").strip()
    description = _safe_str(body.get("description"), "").strip()
    image_base64 = _safe_str(body.get("imageBase64") or body.get("image_base64"), "") or None
    display_duration_sec = max(3, min(10, _safe_int(body.get("displayDurationSec") or body.get("display_duration_sec"), 5)))
    row = create_tv_screen_message(
        binding_id=binding_id,
        title=title,
        description=description,
        image_base64=image_base64,
        display_duration_sec=display_duration_sec,
    )
    ctx.send_json(200, {"ok": True, "message": row})


def _handle_tv_screen_messages_get(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    binding_id = ctx.q_int("bindingId", "binding_id") or None
    limit = max(1, min(200, ctx.q_int("limit", default=50)))
    offset = max(0, ctx.q_int("offset", default=0))
    rows = list_tv_screen_messages(binding_id=binding_id, limit=limit, offset=offset)
    ctx.send_json(200, {"ok": True, "rows": rows, "total": len(rows)})


def _handle_tv_activation_status(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    sid = _tv_resolve_screen_id(ctx)
    if sid <= 0:
        ctx.send_json(400, {"ok": False, "error": "No bound screen. Set /api/v2/tv/binding first."})
        return
    status = load_tv_activation_status(screen_id=sid)
    ctx.send_json(200, {"ok": True, "screenId": sid, "activation": status})


def _handle_tv_activation_evaluate(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    body = ctx.body()
    sid = _tv_resolve_screen_id(ctx, body)
    if sid <= 0:
        ctx.send_json(400, {"ok": False, "error": "No bound screen. Set /api/v2/tv/binding first."})
        return
    auto_activate = _safe_bool(body.get("autoActivate") if isinstance(body, dict) else True, default=True)
    recheck = _safe_bool(body.get("recheckReadiness") if isinstance(body, dict) else True, default=True)
    result = evaluate_tv_activation(
        screen_id=sid,
        trigger_source="MANUAL_EVALUATE",
        auto_activate=auto_activate,
        manual=False,
        recheck_readiness=recheck,
    )
    code = 200 if bool(result.get("ok", True)) else 500
    ctx.send_json(code, result)


def _handle_tv_activation_activate_latest_ready(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    body = ctx.body()
    sid = _tv_resolve_screen_id(ctx, body)
    if sid <= 0:
        ctx.send_json(400, {"ok": False, "error": "No bound screen. Set /api/v2/tv/binding first."})
        return
    result = activate_tv_latest_ready_snapshot(screen_id=sid)
    code = 200 if bool(result.get("ok", True)) else 500
    ctx.send_json(code, result)


def _handle_tv_activation_history(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    sid = _tv_resolve_screen_id(ctx)
    if sid <= 0:
        ctx.send_json(400, {"ok": False, "error": "No bound screen. Set /api/v2/tv/binding first."})
        return
    limit = max(1, min(ctx.q_int("limit", default=50), 500))
    offset = max(0, ctx.q_int("offset", default=0))
    hist = list_tv_activation_attempts(screen_id=sid, limit=limit, offset=offset)
    ctx.send_json(200, {"ok": True, "screenId": sid, "rows": hist.get("rows") or [], "total": int(hist.get("total") or 0)})


# ==================== 4.45) TV OBSERVABILITY ====================

def _handle_tv_observability_overview(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    gym_id = ctx.q_int("gymId", "gym_id", default=0)
    data = get_tv_observability_overview(gym_id=(gym_id if gym_id > 0 else None))
    ctx.send_json(200, {"ok": True, **data})


def _handle_tv_observability_fleet_health(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    gym_id = ctx.q_int("gymId", "gym_id", default=0)
    health = ctx.q("health", default="")
    runtime_state = ctx.q("runtimeState", "runtime_state", default="")
    q = ctx.q("q", "query", default="")
    limit = max(1, min(ctx.q_int("limit", default=200), 2000))
    offset = max(0, ctx.q_int("offset", default=0))
    data = list_tv_observability_fleet_health(
        health=health or None,
        runtime_state=runtime_state or None,
        q=q or None,
        limit=limit,
        offset=offset,
        gym_id=(gym_id if gym_id > 0 else None),
    )
    ctx.send_json(200, {"ok": True, "rows": data.get("rows") or [], "total": int(data.get("total") or 0)})


def _handle_tv_observability_screen_details(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    sid = _safe_int(ctx.param("screenId"), 0)
    if sid <= 0:
        ctx.send_json(400, {"ok": False, "error": "screenId is required"})
        return
    data = get_tv_observability_screen_details(screen_id=sid)
    if not bool(data.get("ok")):
        ctx.send_json(404, {"ok": False, "error": data.get("error") or "SCREEN_NOT_FOUND"})
        return
    ctx.send_json(200, data)


def _handle_tv_observability_screen_timeline(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    sid = _safe_int(ctx.param("screenId"), 0)
    if sid <= 0:
        ctx.send_json(400, {"ok": False, "error": "screenId is required"})
        return
    limit = max(1, min(ctx.q_int("limit", default=200), 2000))
    offset = max(0, ctx.q_int("offset", default=0))
    data = get_tv_observability_screen_timeline(screen_id=sid, limit=limit, offset=offset)
    ctx.send_json(200, {"ok": True, "rows": data.get("rows") or [], "total": int(data.get("total") or 0)})


def _handle_tv_observability_heartbeats(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    gym_id = ctx.q_int("gymId", "gym_id", default=0)
    screen_id = ctx.q_int("screenId", "screen_id", default=0)
    binding_id = ctx.q_int("bindingId", "binding_id", default=0)
    from_utc = _safe_str(ctx.q("fromUtc", "from_utc", default=""), "").strip() or None
    to_utc = _safe_str(ctx.q("toUtc", "to_utc", default=""), "").strip() or None
    limit = max(1, min(ctx.q_int("limit", default=200), 2000))
    offset = max(0, ctx.q_int("offset", default=0))
    data = list_tv_observability_heartbeats(
        screen_id=(screen_id if screen_id > 0 else None),
        binding_id=(binding_id if binding_id > 0 else None),
        from_utc=from_utc,
        to_utc=to_utc,
        limit=limit,
        offset=offset,
        gym_id=(gym_id if gym_id > 0 else None),
    )
    ctx.send_json(200, {"ok": True, "rows": data.get("rows") or [], "total": int(data.get("total") or 0)})


def _handle_tv_observability_runtime_events(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    gym_id = ctx.q_int("gymId", "gym_id", default=0)
    screen_id = ctx.q_int("screenId", "screen_id", default=0)
    binding_id = ctx.q_int("bindingId", "binding_id", default=0)
    severities = _safe_str(ctx.q("severities", "severity", default=""), "").strip() or None
    event_types = _safe_str(ctx.q("eventTypes", "event_types", "types", default=""), "").strip() or None
    from_utc = _safe_str(ctx.q("fromUtc", "from_utc", default=""), "").strip() or None
    to_utc = _safe_str(ctx.q("toUtc", "to_utc", default=""), "").strip() or None
    limit = max(1, min(ctx.q_int("limit", default=200), 2000))
    offset = max(0, ctx.q_int("offset", default=0))
    data = list_tv_observability_runtime_events(
        screen_id=(screen_id if screen_id > 0 else None),
        binding_id=(binding_id if binding_id > 0 else None),
        severities=severities,
        event_types=event_types,
        from_utc=from_utc,
        to_utc=to_utc,
        limit=limit,
        offset=offset,
        gym_id=(gym_id if gym_id > 0 else None),
    )
    ctx.send_json(200, {"ok": True, "rows": data.get("rows") or [], "total": int(data.get("total") or 0)})


def _handle_tv_observability_proof_events(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    gym_id = ctx.q_int("gymId", "gym_id", default=0)
    screen_id = ctx.q_int("screenId", "screen_id", default=0)
    binding_id = ctx.q_int("bindingId", "binding_id", default=0)
    snapshot_version = ctx.q_int("snapshotVersion", "snapshot_version", default=0)
    timeline_types = _safe_str(ctx.q("timelineTypes", "timeline_types", default=""), "").strip() or None
    statuses = _safe_str(ctx.q("statuses", "status", default=""), "").strip() or None
    from_utc = _safe_str(ctx.q("fromUtc", "from_utc", default=""), "").strip() or None
    to_utc = _safe_str(ctx.q("toUtc", "to_utc", default=""), "").strip() or None
    limit = max(1, min(ctx.q_int("limit", default=200), 2000))
    offset = max(0, ctx.q_int("offset", default=0))
    data = list_tv_observability_proof_events(
        screen_id=(screen_id if screen_id > 0 else None),
        binding_id=(binding_id if binding_id > 0 else None),
        snapshot_version=(snapshot_version if snapshot_version > 0 else None),
        timeline_types=timeline_types,
        statuses=statuses,
        from_utc=from_utc,
        to_utc=to_utc,
        limit=limit,
        offset=offset,
        gym_id=(gym_id if gym_id > 0 else None),
    )
    ctx.send_json(200, {"ok": True, "rows": data.get("rows") or [], "total": int(data.get("total") or 0)})


def _handle_tv_observability_proof_stats(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    gym_id = ctx.q_int("gymId", "gym_id", default=0)
    screen_id = ctx.q_int("screenId", "screen_id", default=0)
    from_utc = _safe_str(ctx.q("fromUtc", "from_utc", default=""), "").strip() or None
    to_utc = _safe_str(ctx.q("toUtc", "to_utc", default=""), "").strip() or None
    bucket = _safe_str(ctx.q("bucket", default="HOUR"), "HOUR").strip().upper()
    if bucket not in {"HOUR", "DAY"}:
        bucket = "HOUR"
    data = get_tv_observability_proof_stats(
        screen_id=(screen_id if screen_id > 0 else None),
        from_utc=from_utc,
        to_utc=to_utc,
        gym_id=(gym_id if gym_id > 0 else None),
        bucket=bucket,
    )
    ctx.send_json(200, {"ok": True, **data})


def _handle_tv_observability_runtime_stats(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    gym_id = ctx.q_int("gymId", "gym_id", default=0)
    screen_id = ctx.q_int("screenId", "screen_id", default=0)
    from_utc = _safe_str(ctx.q("fromUtc", "from_utc", default=""), "").strip() or None
    to_utc = _safe_str(ctx.q("toUtc", "to_utc", default=""), "").strip() or None
    data = get_tv_observability_runtime_stats(
        screen_id=(screen_id if screen_id > 0 else None),
        from_utc=from_utc,
        to_utc=to_utc,
        gym_id=(gym_id if gym_id > 0 else None),
    )
    ctx.send_json(200, {"ok": True, **data})

# ==================== 4.46) TV HARDENING / RECOVERY ====================

def _handle_tv_hardening_startup_latest(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    data = load_tv_startup_reconciliation_latest()
    code = 200 if bool(data.get("ok")) else 404
    ctx.send_json(code, data)


def _handle_tv_hardening_startup_runs(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    limit = ctx.q_int("limit", default=20)
    offset = ctx.q_int("offset", default=0)
    data = list_tv_startup_reconciliation_runs(limit=limit, offset=offset)
    ctx.send_json(200, {"ok": True, **data})


def _handle_tv_hardening_startup_run(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    body = ctx.body()
    trigger_source = _safe_str(body.get("triggerSource") or body.get("trigger_source"), "API_MANUAL").strip() or "API_MANUAL"
    corr = _safe_str(body.get("correlationId") or body.get("correlation_id"), "").strip() or None
    include_checks = _safe_bool(body.get("includeQueryChecks") or body.get("include_query_checks"), default=False)
    monitors = body.get("monitors")
    if not isinstance(monitors, list):
        monitors = None
    data = run_tv_startup_reconciliation(
        trigger_source=trigger_source,
        monitors=monitors,
        correlation_id=corr,
        include_query_checks=include_checks,
    )
    if not bool(data.get("ok")) and _safe_str(data.get("result"), "").upper() == "BLOCKED":
        ctx.send_json(409, data)
        return
    ctx.send_json(200, data)


def _handle_tv_hardening_retention_policy(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    ctx.send_json(200, {"ok": True, "retentionDays": get_tv_retention_policy()})


def _handle_tv_hardening_retention_run(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    body = ctx.body()
    dry_run = _safe_bool(body.get("dryRun"), default=False)
    include_checks = _safe_bool(body.get("includeQueryChecks"), default=True)
    data = run_tv_retention_maintenance(dry_run=dry_run, include_query_checks=include_checks)
    ctx.send_json(200, data)


def _handle_tv_hardening_query_checks(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    limit = ctx.q_int("limit", default=200)
    data = run_tv_query_responsiveness_checks(limit=limit)
    ctx.send_json(200, {"ok": True, **data})



def _handle_tv_hardening_preflight(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    include_checks = _safe_bool(ctx.q("includeQueryChecks", "include_query_checks", default="0"), default=False)
    data = run_tv_deployment_preflight(include_query_checks=include_checks)
    ctx.send_json(200, data)

def _handle_tv_hardening_correlation_audit(ctx: _Ctx) -> None:
    ensure_tv_local_schema()
    correlation_id = _safe_str(ctx.q("correlationId", "correlation_id", default=""), "").strip()
    if not correlation_id:
        ctx.send_json(400, {"ok": False, "error": "correlationId is required"})
        return
    data = audit_tv_correlation_propagation(correlation_id=correlation_id)
    ctx.send_json(200, data)

# ==================== 4.5) OFFLINE CREATION QUEUE ====================

_OFFLINE_ACTIVE_STATES = ("pending", "processing", "failed_retryable", "blocked_auth")
_OFFLINE_HISTORY_STATES = ("succeeded", "reconciled", "cancelled", "failed_terminal", "archived")


def _split_state_filter(raw: str) -> List[str]:
    allowed = set(_OFFLINE_ACTIVE_STATES + _OFFLINE_HISTORY_STATES)
    out: List[str] = []
    for part in (raw or "").replace(";", ",").split(","):
        s = (part or "").strip().lower()
        if s and s in allowed and s not in out:
            out.append(s)
    return out


def _queue_payload_from_body(body: Dict[str, Any]) -> Dict[str, Any]:
    payload = body.get("payload")
    if isinstance(payload, dict):
        return dict(payload)
    # fallback: allow flat payload body from callers
    out = dict(body or {})
    for k in ("creationKind", "creation_kind", "failure", "failureType", "failureCode", "lastHttpStatus", "error"):
        out.pop(k, None)
    return out


def _handle_offline_creations_active(ctx: _Ctx) -> None:
    from access.store import list_offline_creations, count_offline_creations

    raw_state = ctx.q("state", "states", default="")
    states = _split_state_filter(raw_state) or list(_OFFLINE_ACTIVE_STATES)
    states = [s for s in states if s in _OFFLINE_ACTIVE_STATES]
    if not states:
        states = list(_OFFLINE_ACTIVE_STATES)

    limit = ctx.q_int("limit", default=200)
    offset = ctx.q_int("offset", default=0)
    rows = list_offline_creations(states=states, include_archived=False, limit=limit, offset=offset)
    total = count_offline_creations(states=states, include_archived=False)
    ctx.send_json(200, {"ok": True, "rows": rows, "total": total, "states": states})


def _handle_offline_creations_history(ctx: _Ctx) -> None:
    from access.store import list_offline_creations, count_offline_creations

    raw_state = ctx.q("state", "states", default="")
    states = _split_state_filter(raw_state) or list(_OFFLINE_HISTORY_STATES)
    states = [s for s in states if s in _OFFLINE_HISTORY_STATES]
    if not states:
        states = list(_OFFLINE_HISTORY_STATES)

    limit = ctx.q_int("limit", default=200)
    offset = ctx.q_int("offset", default=0)
    rows = list_offline_creations(states=states, include_archived=True, limit=limit, offset=offset)
    total = count_offline_creations(states=states, include_archived=True)
    ctx.send_json(200, {"ok": True, "rows": rows, "total": total, "states": states})


def _handle_offline_creation_get(ctx: _Ctx) -> None:
    from access.store import get_offline_creation

    local_id = ctx.param("localId")
    row = get_offline_creation(local_id)
    if not row:
        ctx.send_json(404, {"ok": False, "error": "offline row not found"})
        return
    ctx.send_json(200, {"ok": True, "row": row})


def _handle_offline_creation_attempt(ctx: _Ctx) -> None:
    body = ctx.body()
    creation_kind = _safe_str(body.get("creationKind") or body.get("creation_kind"), "membership_only")
    payload = _queue_payload_from_body(body)
    client_request_id = _safe_str(body.get("clientRequestId") or body.get("client_request_id"), "")

    result = ctx.app.attempt_offline_creation(
        creation_kind=creation_kind,
        payload=payload,
        client_request_id=client_request_id or None,
    )
    # Keep 200 with ok=false so UI can decide modify vs save-later without transport errors.
    ctx.send_json(200, result)


def _handle_offline_creation_queue(ctx: _Ctx) -> None:
    body = ctx.body()
    creation_kind = _safe_str(body.get("creationKind") or body.get("creation_kind"), "membership_only")
    payload = _queue_payload_from_body(body)
    failure = body.get("failure")
    if not isinstance(failure, dict):
        failure = {
            "failureType": body.get("failureType"),
            "failureCode": body.get("failureCode"),
            "lastHttpStatus": body.get("lastHttpStatus"),
            "error": body.get("error"),
        }

    try:
        row = ctx.app.queue_offline_creation(creation_kind=creation_kind, payload=payload, failure=failure)
        ctx.send_json(201, {"ok": True, "row": row})
    except Exception as e:
        ctx.send_json(400, {"ok": False, "error": str(e)})


def _handle_offline_creation_patch(ctx: _Ctx) -> None:
    from access.store import get_offline_creation, update_offline_creation_payload

    local_id = ctx.param("localId")
    body = ctx.body()
    payload = body.get("payload")
    if not isinstance(payload, dict):
        payload = _queue_payload_from_body(body)

    try_to_create_val = body.get("tryToCreate")
    if try_to_create_val is None:
        try_to_create_val = body.get("try_to_create")
    try_to_create: Optional[bool] = None
    if try_to_create_val is not None:
        try_to_create = _safe_bool(try_to_create_val, default=True)

    existing = get_offline_creation(local_id)
    if not existing:
        ctx.send_json(404, {"ok": False, "error": "offline row not found"})
        return

    row = update_offline_creation_payload(local_id, payload=payload, try_to_create=try_to_create)
    if not row:
        ctx.send_json(409, {"ok": False, "error": "row is read-only or final"})
        return
    ctx.send_json(200, {"ok": True, "row": row})


def _handle_offline_creation_toggle(ctx: _Ctx) -> None:
    from access.store import set_offline_creation_try_to_create

    local_id = ctx.param("localId")
    body = ctx.body()
    enabled = _safe_bool(body.get("enabled", True), default=True)
    row = set_offline_creation_try_to_create(local_id, enabled=enabled)
    if not row:
        ctx.send_json(404, {"ok": False, "error": "offline row not found or not mutable"})
        return
    ctx.send_json(200, {"ok": True, "row": row})


def _handle_offline_creation_retry(ctx: _Ctx) -> None:
    local_id = ctx.param("localId")
    res = ctx.app.process_offline_creation_row(local_id, source="manual_retry", force=True)
    if not bool(res.get("ok")):
        ctx.send_json(409, {"ok": False, "error": res.get("error") or "retry failed", "result": res})
        return
    ctx.send_json(200, {"ok": True, "result": res})


def _handle_offline_creation_cancel(ctx: _Ctx) -> None:
    from access.store import cancel_offline_creation

    local_id = ctx.param("localId")
    body = ctx.body()
    reason = _safe_str(body.get("reason"), "")
    row = cancel_offline_creation(local_id, reason=reason or None)
    if not row:
        ctx.send_json(404, {"ok": False, "error": "offline row not found or not cancellable"})
        return
    ctx.send_json(200, {"ok": True, "row": row})


def _handle_offline_creation_duplicate(ctx: _Ctx) -> None:
    from access.store import duplicate_offline_creation

    local_id = ctx.param("localId")
    row = duplicate_offline_creation(local_id)
    if not row:
        ctx.send_json(404, {"ok": False, "error": "offline row not found"})
        return
    ctx.send_json(201, {"ok": True, "row": row})


def _handle_offline_creation_archive(ctx: _Ctx) -> None:
    from access.store import archive_offline_creation

    local_id = ctx.param("localId")
    row = archive_offline_creation(local_id)
    if not row:
        ctx.send_json(404, {"ok": False, "error": "offline row not found"})
        return
    ctx.send_json(200, {"ok": True, "row": row})


def _handle_offline_creations_process_due(ctx: _Ctx) -> None:
    limit = ctx.q_int("limit", default=100)
    summary = ctx.app.process_due_offline_creations(source="manual", limit=limit)
    if not bool(summary.get("ok")):
        ctx.send_json(409, {"ok": False, "error": summary.get("error") or "process failed", "summary": summary})
        return
    ctx.send_json(200, {"ok": True, "summary": summary})


# ==================== 5) DEVICES (PullSDK) ====================

# Keep a small pool of per-device SDK connections for session-like use.
_device_sdk_pool: Dict[int, Any] = {}
_device_sdk_lock = threading.Lock()


def _get_device_conn_params(ctx: _Ctx, device_id: int) -> Tuple[str, int, int, str]:
    """Resolve connection params from sync cache + optional overrides."""
    from access.store import get_sync_device
    d = get_sync_device(device_id) or {}

    def pick(d, *keys, default=None):
        for k in keys:
            if isinstance(d, dict) and k in d and d[k] not in (None, ""):
                return d[k]
        return default

    ip = _safe_str(pick(d, "ipAddress", "ip_address", "ip", "host"), "").strip()
    port = _safe_int(pick(d, "portNumber", "port_number", "port"), 4370)
    timeout_ms = _safe_int(pick(d, "timeout_ms", "timeoutMs"), 5000)
    password = _safe_str(pick(d, "password", "commPassword", "comm_password"), "")

    # Allow body overrides
    try:
        body = ctx.body()
        if body.get("ip"):
            ip = str(body["ip"]).strip()
        if body.get("port"):
            port = _safe_int(body["port"], port)
        if body.get("password") is not None:
            password = str(body["password"])
        if body.get("timeoutMs"):
            timeout_ms = _safe_int(body["timeoutMs"], timeout_ms)
    except Exception:
        pass

    return ip, port, timeout_ms, password


def _connect_device(ctx: _Ctx, device_id: int) -> Tuple[Any, Optional[str]]:
    """Connect to a device, returns (sdk, error_or_none)."""
    from app.sdk.pullsdk import PullSDK
    ip, port, timeout_ms, password = _get_device_conn_params(ctx, device_id)
    if not ip:
        return None, "Device has no IP address"

    try:
        sdk = PullSDK(ctx.app.cfg.plcomm_dll_path, logger=ctx.app.logger)
        sdk.connect(ip=ip, port=port, timeout_ms=timeout_ms, password=password)
        return sdk, None
    except Exception as e:
        return None, str(e)


def _handle_device_connect(ctx: _Ctx) -> None:
    did = ctx.param_int("deviceId")
    _logger.info("[LocalAPI] device_connect: deviceId=%s", did)
    if did <= 0:
        ctx.send_json(400, {"ok": False, "error": "invalid deviceId"})
        return
    sdk, err = _connect_device(ctx, did)
    if err:
        _logger.warning("[LocalAPI] device_connect FAILED: deviceId=%s err=%s", did, err)
        ctx.send_json(500, {"ok": False, "error": err})
        return
    with _device_sdk_lock:
        old = _device_sdk_pool.pop(did, None)
        if old:
            try: old.disconnect()
            except Exception: pass
        _device_sdk_pool[did] = sdk
    _logger.info("[LocalAPI] device_connect OK: deviceId=%s", did)
    ctx.send_json(200, {"ok": True})


def _handle_device_disconnect(ctx: _Ctx) -> None:
    did = ctx.param_int("deviceId")
    _logger.info("[LocalAPI] device_disconnect: deviceId=%s", did)
    with _device_sdk_lock:
        sdk = _device_sdk_pool.pop(did, None)
    if sdk:
        try: sdk.disconnect()
        except Exception: pass
    ctx.send_json(200, {"ok": True})


def _handle_device_info(ctx: _Ctx) -> None:
    did = ctx.param_int("deviceId")
    sdk, err = _connect_device(ctx, did)
    if err:
        ctx.send_json(500, {"ok": False, "error": err})
        return
    try:
        params = {}
        raw = ""
        items = ctx.q("items", default=(
            "~DeviceName,~SerialNumber,FirmVer,MachineType,"
            "LockCount,ReaderCount,AuxInCount,AuxOutCount,"
            "IPAddress,NetMask,GATEIPAddress,MAC,"
            "~MaxUserCount,~MaxAttLogCount,~MaxUserFingerCount,"
            "AntiPassback,InterLock,DeviceID,"
            "Door1Drivertime,Door2Drivertime,Door3Drivertime,Door4Drivertime,"
            "Door1SensorType,Door2SensorType,Door3SensorType,Door4SensorType,"
            "Door1VerifyType,Door2VerifyType,Door3VerifyType,Door4VerifyType"
        ))
        if sdk.supports_get_device_param():
            raw = sdk.get_device_param(items=items, initial_size=65536)
            for part in raw.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
                for seg in part.split(","):
                    seg = seg.strip()
                    if "=" in seg:
                        k, v = seg.split("=", 1)
                        params[k.strip()] = v.strip()
        counts = {}
        for t in ["user", "userauthorize", "transaction", "templatev10", "timezone", "holiday"]:
            try:
                c = sdk.get_device_data_count(table=t)
                if c >= 0:
                    counts[t] = c
            except Exception:
                pass
        ctx.send_json(200, {"ok": True, "params": params, "counts": counts, "raw": raw})
    except Exception as e:
        ctx.send_json(500, {"ok": False, "error": str(e)})
    finally:
        try: sdk.disconnect()
        except Exception: pass


def _handle_device_table(ctx: _Ctx) -> None:
    did = ctx.param_int("deviceId")
    table_name = ctx.param("tableName")
    fields = ctx.q("fields", default="*")
    flt = ctx.q("filter", default="")
    max_rows = ctx.q_int("maxRows", default=10000)

    sdk, err = _connect_device(ctx, did)
    if err:
        ctx.send_json(500, {"ok": False, "error": err})
        return
    try:
        rows = sdk.get_device_data_rows(table=table_name, fields=fields, filter_expr=flt, options="")
        count = len(rows)
        if max_rows > 0:
            rows = rows[:max_rows]
        ctx.send_json(200, {"ok": True, "table": table_name, "rows": rows, "count": count})
    except Exception as e:
        ctx.send_json(500, {"ok": False, "error": str(e)})
    finally:
        try: sdk.disconnect()
        except Exception: pass


_door_open_last: Dict[int, float] = {}  # M-003: per-device rate limit for door open
_DOOR_OPEN_COOLDOWN_SEC = 1.0

def _handle_device_door_open(ctx: _Ctx) -> None:
    did = ctx.param_int("deviceId")

    # M-003: Rate limit — 1 second cooldown per device
    import time as _time
    _now = _time.monotonic()
    _last = _door_open_last.get(did, 0.0)
    if (_now - _last) < _DOOR_OPEN_COOLDOWN_SEC:
        ctx.send_json(429, {"ok": False, "error": "Door open rate limited (1s cooldown)"})
        return
    _door_open_last[did] = _now

    body = ctx.body()
    door = _safe_int(body.get("doorNumber"), 1)
    pulse_sec = _safe_int(body.get("pulseSeconds"), 3)
    if door < 1: door = 1
    if pulse_sec < 1: pulse_sec = 1
    if pulse_sec > 60: pulse_sec = 60

    # Try agent engine first (for AGENT-mode devices)
    eng = getattr(ctx.app, "_agent_engine", None)
    if eng and eng.is_running():
        try:
            res = eng._cmd_bus.open_door(
                device_id=did, door_id=door,
                pulse_time_ms=pulse_sec * 1000,
                timeout_ms=4000,
            )
            if res.ok:
                ctx.send_json(200, {"ok": True, "rc": 0, "source": "agent"})
                return
        except Exception:
            pass

    # Try ULTRA engine: use the worker's command queue to open the door
    # via its already-connected SDK.  No TCP disconnect/reconnect needed.
    ultra_eng = getattr(ctx.app, "_ultra_engine", None)
    if ultra_eng and ultra_eng.running:
        worker = ultra_eng._workers.get(did)
        if worker:
            _logger.info(
                "[LocalAPI] ULTRA door open via command queue: device_id=%s door=%s pulse_sec=%s",
                did, door, pulse_sec,
            )
            result = worker.request_door_open(door_id=door, pulse_ms=pulse_sec * 1000, timeout=2.0)
            ok = bool(result.get("ok", False))
            err = result.get("error", "")
            if ok:
                _logger.info("[LocalAPI] ULTRA door open OK: device_id=%s door=%s", did, door)
                ctx.send_json(200, {"ok": True, "rc": 0, "source": "ultra"})
            else:
                _logger.warning("[LocalAPI] ULTRA door open FAILED: device_id=%s door=%s error=%s", did, door, err)
                ctx.send_json(500, {"ok": False, "error": err or "door open failed"})
            return

    # Fallback: direct PullSDK connect (DEVICE-mode or unmanaged devices)
    sdk, err = _connect_device(ctx, did)
    if err:
        ctx.send_json(500, {"ok": False, "error": err})
        return
    try:
        rc = sdk.door_pulse_open(door=door, seconds=pulse_sec)
        ctx.send_json(200, {"ok": True, "rc": rc})
    except Exception as e:
        ctx.send_json(500, {"ok": False, "error": str(e)})
    finally:
        try: sdk.disconnect()
        except Exception: pass


def _handle_device_force_resync(ctx: _Ctx) -> None:
    """F-015: Clear sync hashes for a device to force full re-push of all users on next sync cycle."""
    did = ctx.param_int("deviceId")
    try:
        from app.core.db import clear_device_sync_hashes
        cleared = clear_device_sync_hashes(device_id=did)

        # Also clear the UltraSyncScheduler in-memory hash so it doesn't skip the device
        ultra_eng = getattr(ctx.app, "_ultra_engine", None)
        if ultra_eng:
            sched = getattr(ultra_eng, "_sync_scheduler", None)
            if sched:
                sched.force_resync(did)

        _logger.info("[LocalAPI] force-resync: device_id=%s cleared=%s sync hashes", did, cleared)
        ctx.send_json(200, {"ok": True, "cleared": cleared, "message": f"Cleared {cleared} sync hashes. Next sync cycle will re-push all users."})
    except Exception as e:
        _logger.error("[LocalAPI] force-resync: device_id=%s error=%s", did, e)
        ctx.send_json(500, {"ok": False, "error": str(e)})


def _handle_device_users_push(ctx: _Ctx) -> None:
    did = ctx.param_int("deviceId")
    body = ctx.body()
    pin = _safe_str(body.get("pin"), "").strip()
    name = _safe_str(body.get("name"), "").strip()
    card_no = _safe_str(body.get("cardNo"), "").strip()
    door_ids = body.get("doorIds") or [15]
    templates = body.get("templates") or []

    if not pin:
        ctx.send_json(400, {"ok": False, "error": "pin is required"})
        return

    sdk, err = _connect_device(ctx, did)
    if err:
        ctx.send_json(500, {"ok": False, "error": err})
        return

    try:
        # Push user
        pairs = [f"Pin={pin}"]
        if name: pairs.append(f"Name={name}")
        if card_no: pairs.append(f"CardNo={card_no}")
        user_data = "\t".join(pairs) + "\r\n"
        sdk.set_device_data(table="user", data=user_data, options="")

        # Push authorize — AuthorizeDoorId is a BITMASK (door1=1, door2=2, door3=4, door4=8).
        # Push ONE record with the combined bitmask for all doors.
        auth_result = "OK"
        bitmask = 0
        for door in door_ids:
            bitmask |= 1 << (int(door) - 1)
        try:
            auth_data = f"Pin={pin}\tAuthorizeTimezoneId=1\tAuthorizeDoorId={bitmask}\r\n"
            sdk.set_device_data(table="userauthorize", data=auth_data, options="")
        except Exception as ex:
            auth_result = str(ex)

        # Push templates
        tpl_ok = 0
        tpl_errors: List[str] = []
        for t in templates:
            fid = _safe_int(t.get("fingerId"), 0)
            ver = _safe_int(t.get("templateVersion"), 10)
            size = _safe_int(t.get("templateSize"), 0)
            tpl_data = _safe_str(t.get("templateData"), "").strip()
            if not tpl_data:
                continue
            table = "templatev10" if ver >= 10 else "template"
            tpl_line = f"Pin={pin}\tFingerID={fid}\tValid=1\tSize={size}\tTemplate={tpl_data}\r\n"
            try:
                sdk.set_device_data(table=table, data=tpl_line, options="")
                tpl_ok += 1
            except Exception as ex:
                tpl_errors.append(f"FingerID={fid}: {ex}")

        ctx.send_json(200, {
            "ok": True,
            "authResult": auth_result,
            "templateResult": f"{tpl_ok}/{len(templates)} pushed",
            "errors": tpl_errors,
        })
    except Exception as e:
        ctx.send_json(500, {"ok": False, "error": str(e)})
    finally:
        try: sdk.disconnect()
        except Exception: pass


def _handle_device_users_list(ctx: _Ctx) -> None:
    did = ctx.param_int("deviceId")
    sdk, err = _connect_device(ctx, did)
    if err:
        ctx.send_json(500, {"ok": False, "error": err})
        return
    try:
        rows = sdk.get_device_data_rows(table="user", fields="Pin;Name;CardNo", filter_expr="", options="")
        users = []
        for r in rows:
            users.append({
                "pin": _safe_str(r.get("Pin") or r.get("pin"), ""),
                "name": _safe_str(r.get("Name") or r.get("name"), ""),
                "cardNo": _safe_str(r.get("CardNo") or r.get("cardno"), ""),
            })
        ctx.send_json(200, {"ok": True, "users": users})
    except Exception as e:
        ctx.send_json(500, {"ok": False, "error": str(e)})
    finally:
        try: sdk.disconnect()
        except Exception: pass


def _handle_device_users_delete(ctx: _Ctx) -> None:
    did = ctx.param_int("deviceId")
    body = ctx.body()
    pin = _safe_str(body.get("pin"), "").strip()
    if not pin:
        ctx.send_json(400, {"ok": False, "error": "pin is required"})
        return

    sdk, err = _connect_device(ctx, did)
    if err:
        ctx.send_json(500, {"ok": False, "error": err})
        return
    try:
        cond = f"Pin={pin}"
        for table in ["templatev10", "template", "userauthorize", "user"]:
            try:
                if sdk.supports_delete_device_data():
                    sdk.delete_device_data(table=table, data=cond, options="")
            except Exception:
                pass
        ctx.send_json(200, {"ok": True})
    except Exception as e:
        ctx.send_json(500, {"ok": False, "error": str(e)})
    finally:
        try: sdk.disconnect()
        except Exception: pass


def _handle_device_door_presets_list(ctx: _Ctx) -> None:
    did = ctx.param_int("deviceId")
    from access.store import get_sync_device_payload, list_device_door_presets

    device_payload = get_sync_device_payload(did) or {}
    synced_presets = device_payload.get("doorPresets")

    if isinstance(synced_presets, list) and synced_presets:
        ctx.send_json(200, {"presets": [
            {
                "id": _safe_int((p or {}).get("id"), 0),
                "deviceId": _safe_int((p or {}).get("deviceId"), did),
                "doorNumber": _safe_int((p or {}).get("doorNumber"), 1),
                "pulseSeconds": _safe_int((p or {}).get("pulseSeconds"), 3),
                "doorName": _safe_str((p or {}).get("doorName"), ""),
            }
            for p in synced_presets
            if isinstance(p, dict)
        ]})
        return

    presets = list_device_door_presets(did)
    ctx.send_json(200, {"presets": [
        {"id": p.id, "deviceId": p.device_id, "doorNumber": p.door_number,
         "pulseSeconds": p.pulse_seconds, "doorName": p.door_name}
        for p in presets
    ]})


def _handle_device_door_presets_create(ctx: _Ctx) -> None:
    did = ctx.param_int("deviceId")
    body = ctx.body()
    from access.store import create_device_door_preset
    try:
        pid = create_device_door_preset(
            device_id=did,
            door_number=_safe_int(body.get("doorNumber"), 1),
            pulse_seconds=_safe_int(body.get("pulseSeconds"), 3),
            door_name=_safe_str(body.get("doorName"), "").strip(),
        )
        ctx.send_json(201, {"ok": True, "id": pid})
    except Exception as e:
        ctx.send_json(400, {"ok": False, "error": str(e)})


def _handle_device_door_presets_delete(ctx: _Ctx) -> None:
    preset_id = ctx.param_int("presetId")
    from access.store import delete_device_door_preset
    try:
        delete_device_door_preset(preset_id)
        ctx.send_json(200, {"ok": True})
    except Exception as e:
        ctx.send_json(400, {"ok": False, "error": str(e)})


# ==================== 6) AGENT REALTIME ====================

def _handle_agent_status(ctx: _Ctx) -> None:
    eng = getattr(ctx.app, "_agent_engine", None)
    running = bool(eng and eng.is_running())
    data: Dict[str, Any] = {"running": running, "eventQueueDepth": 0, "avgDecisionMs": 0.0}
    if eng and running:
        data["eventQueueDepth"] = eng.get_queue_depth()
        data["avgDecisionMs"] = round(eng.get_avg_decision_ms(), 2)

        # service status
        notif = getattr(eng, "_notif", None)
        hist = getattr(eng, "_hist", None)
        deciders = getattr(eng, "_deciders", [])
        data["notificationServiceAlive"] = bool(notif and notif.is_alive())
        data["historyServiceAlive"] = bool(hist and hist.is_alive())
        data["decisionWorkersActive"] = sum(1 for d in deciders if d.is_alive())
        data["decisionWorkersTotal"] = len(deciders)
    ctx.send_json(200, data)


def _handle_agent_start(ctx: _Ctx) -> None:
    try:
        ctx.app.after(0, ctx.app.start_realtime_agent)
    except Exception:
        pass
    ctx.send_json(200, {"ok": True})


def _handle_agent_stop(ctx: _Ctx) -> None:
    try:
        ctx.app.after(0, ctx.app.stop_realtime_agent)
    except Exception:
        pass
    ctx.send_json(200, {"ok": True})


def _handle_agent_refresh_devices(ctx: _Ctx) -> None:
    eng = getattr(ctx.app, "_agent_engine", None)
    if eng and eng.is_running():
        try:
            eng.refresh_devices()
        except Exception:
            pass
    ctx.send_json(200, {"ok": True})


def _handle_agent_devices(ctx: _Ctx) -> None:
    eng = getattr(ctx.app, "_agent_engine", None)
    snap = {}
    if eng and eng.is_running():
        try:
            snap = eng.get_status_snapshot()
        except Exception:
            pass
    ctx.send_json(200, {"devices": snap})


def _handle_agent_device_enable(ctx: _Ctx) -> None:
    did = ctx.param_int("deviceId")
    eng = getattr(ctx.app, "_agent_engine", None)
    if eng:
        try:
            eng.set_device_enabled(did, True)
        except Exception:
            pass
    ctx.send_json(200, {"ok": True})


def _handle_agent_device_disable(ctx: _Ctx) -> None:
    did = ctx.param_int("deviceId")
    eng = getattr(ctx.app, "_agent_engine", None)
    if eng:
        try:
            eng.set_device_enabled(did, False)
        except Exception:
            pass
    ctx.send_json(200, {"ok": True})


def _handle_agent_events_sse(ctx: _Ctx) -> None:
    """SSE stream: agent events (access decisions, device status, popups)."""
    client_addr = getattr(ctx.handler, "client_address", ("?", "?"))
    _logger.info(
        "[SSE/agent_events] client connected: %s:%s", client_addr[0], client_addr[1]
    )
    eng = getattr(ctx.app, "_agent_engine", None)
    _logger.debug(
        "[SSE/agent_events] agent_engine=%s running=%s",
        type(eng).__name__ if eng else None,
        bool(eng and eng.is_running()),
    )
    ctx.send_sse_start()

    # send initial status
    ctx.send_sse_event("status", {"running": bool(eng and eng.is_running())})

    # ?replayLast=N — send the last N popup events immediately on connect.
    # The popup display screen uses replayLast=1 so it shows the last entry
    # even if it happened before the window was opened.
    replay_last = max(0, min(ctx.q_int("replayLast", "replay_last", default=0), 20))

    last_popup_seq = 0
    if eng:
        try:
            latest = eng.get_latest_popup_event_seq()
            last_popup_seq = max(0, latest - replay_last)
        except Exception:
            last_popup_seq = 0

    last_snap: Dict[int, Dict[str, Any]] = {}
    while True:
        try:
            time.sleep(0.25)

            if not eng or not eng.is_running():
                eng = getattr(ctx.app, "_agent_engine", None)
                alive = ctx.send_sse_event("status", {"running": bool(eng and eng.is_running())})
                if not alive:
                    return
                time.sleep(1.0)
                continue

            # device status changes
            try:
                snap = eng.get_status_snapshot()
                if snap != last_snap:
                    alive = ctx.send_sse_event("device_status", snap)
                    if not alive:
                        return
                    last_snap = snap
            except Exception:
                pass

            # Fan out popup events to every SSE subscriber instead of letting
            # subscribers race on the same queue item.
            try:
                popup_events = eng.get_popup_events_since(last_popup_seq, limit=10)
            except Exception:
                popup_events = []
            for popup_seq, payload in popup_events:
                _logger.debug(
                    "[SSE/agent_events] sending AGENT popup seq=%s allowed=%s user=%r client=%s:%s",
                    popup_seq,
                    payload.get("allowed"),
                    payload.get("userFullName"),
                    client_addr[0], client_addr[1],
                )
                alive = ctx.send_sse_event("popup", payload)
                if not alive:
                    _logger.info(
                        "[SSE/agent_events] client disconnected (broken pipe) at popup seq=%s: %s:%s",
                        popup_seq, client_addr[0], client_addr[1],
                    )
                    return
                last_popup_seq = popup_seq

            # ULTRA engine popup events — drain non-blocking from popup_q
            ultra_eng = getattr(ctx.app, "_ultra_engine", None)
            if ultra_eng and ultra_eng.running:
                try:
                    from app.core.realtime_agent import _popup_payload_from_request
                    for _ in range(10):
                        try:
                            req = ultra_eng.popup_q.get_nowait()
                        except queue.Empty:
                            break
                        payload = _popup_payload_from_request(req)
                        _logger.debug(
                            "[SSE/agent_events] sending ULTRA popup allowed=%s user=%r client=%s:%s",
                            payload.get("allowed"),
                            payload.get("userFullName"),
                            client_addr[0], client_addr[1],
                        )
                        alive = ctx.send_sse_event("popup", payload)
                        if not alive:
                            _logger.info(
                                "[SSE/agent_events] client disconnected (ULTRA popup): %s:%s",
                                client_addr[0], client_addr[1],
                            )
                            return
                except Exception as _sse_exc:
                    _logger.warning("[SSE/agent_events] ULTRA popup dispatch error: %s", _sse_exc)

        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError) as _pipe_exc:
            _logger.info(
                "[SSE/agent_events] client disconnected (connection lost): %s:%s — %s",
                client_addr[0], client_addr[1], type(_pipe_exc).__name__,
            )
            return
        except Exception as _sse_loop_exc:
            _logger.warning(
                "[SSE/agent_events] unexpected error, closing stream: %s:%s — %s",
                client_addr[0], client_addr[1], _sse_loop_exc,
            )
            return


def _handle_agent_settings_global(ctx: _Ctx) -> None:
    settings = ctx.app.cfg.get_agent_global()
    ctx.send_json(200, settings)


def _handle_agent_settings_device(ctx: _Ctx) -> None:
    did = ctx.param_int("deviceId")
    settings = ctx.app.cfg.get_agent_device_settings(did)
    ctx.send_json(200, settings)


# ==================== 6b) ULTRA ====================

def _handle_ultra_status(ctx: _Ctx) -> None:
    """GET /api/v2/ultra/status — ULTRA engine status."""
    eng = getattr(ctx.app, "_ultra_engine", None)
    if eng is None or not eng.running:
        ctx.send_json(200, {"running": False, "devices": {}})
        return
    try:
        ctx.send_json(200, eng.get_status())
    except Exception:
        ctx.send_json(200, {"running": True, "devices": {}})


# ==================== 7) ENROLLMENT ====================

# Global enroll state (shared with main app's _enroll_state_lock)
_enroll_logs: List[str] = []
_enroll_step: str = ""
_enroll_result: Optional[str] = None  # "success" | "failed" | "cancelled" | None
_enroll_start_meta: Optional[Dict[str, Any]] = None  # set when enroll starts
_enroll_phase: Optional[Dict[str, Any]] = None  # structured phase for overlay UI
_enroll_phase_seq: int = 0  # monotonic counter for SSE delta detection
_enroll_last_tpl: Optional[Dict[str, Any]] = None  # stored after merge for retry-push
_enroll_last_tpl_lock = threading.Lock()
_enroll_lock = threading.Lock()
_enroll_event = threading.Event()  # signaled on each update


def _enroll_reset() -> None:
    global _enroll_logs, _enroll_step, _enroll_result, _enroll_start_meta, _enroll_phase, _enroll_phase_seq
    with _enroll_lock:
        _enroll_logs = []
        _enroll_step = ""
        _enroll_result = None
        _enroll_start_meta = None
        _enroll_phase = None
        _enroll_phase_seq = 0
        _enroll_event.clear()


def _enroll_partial_reset_for_retry() -> None:
    """Partial reset for retry-push: clears logs/step/result but NOT phase_seq.

    A full _enroll_reset() sets phase_seq=0.  Connected SSE clients track
    last_phase_seq locally; after a reset they would see phase_seq=1 which
    fails the ``phase_seq > last_phase_seq`` guard (e.g. 1 > 7 is False) and
    silently drop every subsequent phase event for that connection.
    """
    global _enroll_logs, _enroll_step, _enroll_result
    with _enroll_lock:
        _enroll_logs = []
        _enroll_step = ""
        _enroll_result = None
        _enroll_event.set()


def _enroll_set_start_meta(meta: Dict[str, Any]) -> None:
    global _enroll_start_meta
    with _enroll_lock:
        _enroll_start_meta = meta
        _enroll_event.set()


def _enroll_set_step(s: str) -> None:
    global _enroll_step
    with _enroll_lock:
        _enroll_step = s
        _enroll_event.set()


def _enroll_add_log(line: str) -> None:
    global _enroll_logs
    with _enroll_lock:
        _enroll_logs.append(line)
        _enroll_event.set()


def _enroll_set_result(r: str) -> None:
    global _enroll_result
    with _enroll_lock:
        _enroll_result = r
        _enroll_event.set()


def _enroll_set_phase(data: Dict[str, Any]) -> None:
    """Set structured phase data for the overlay UI (sent via SSE 'phase' event)."""
    global _enroll_phase, _enroll_phase_seq
    with _enroll_lock:
        _enroll_phase_seq += 1
        _enroll_phase = {**data, "_seq": _enroll_phase_seq}
        _enroll_event.set()


def _handle_enroll_start(ctx: _Ctx) -> None:
    body = ctx.body()

    # accept either "type" or "target" from frontend
    enroll_type = _safe_str(body.get("type"), "").strip().upper()
    target = _safe_str(body.get("target"), "").strip().lower()
    if not target:
        target = "backend" if enroll_type in ("BACKEND", "") else "local"

    user_id = _safe_str(body.get("userId"), "").strip()
    finger_id = _safe_str(body.get("fingerId"), "").strip()
    full_name = _safe_str(body.get("fullName"), "").strip()
    device = _safe_str(body.get("device"), "zk9500").strip()

    # Your current implementation only supports backend enroll
    if target != "backend":
        ctx.send_json(400, {"ok": False, "error": "LOCAL enroll not implemented. Use type=BACKEND."})
        return

    # begin_remote_enroll checks _enroll_running under its own lock.
    # We must NOT touch shared enroll globals before this point -- a 409
    # means another enrollment is still running and owns that state.
    result = ctx.app.begin_remote_enroll(
        user_id=user_id,
        finger_id=finger_id,
        full_name=full_name,
        device=device or "zk9500",
    )

    if result.get("ok"):
        # Worker will call _enroll_reset() as its first action; set start_meta
        # now so SSE clients get member info immediately after the 202.
        _enroll_set_start_meta({"userId": user_id, "fingerId": finger_id, "fullName": full_name})
        _enroll_add_log("Enroll requested…")
        ctx.send_json(202, result)
    else:
        # Do NOT write to shared state -- a running enrollment may own it.
        ctx.send_json(int(result.get("status") or 400), result)


def _handle_enroll_cancel(ctx: _Ctx) -> None:
    # Set SSE result + app cancel event to actually stop the scanner
    _enroll_set_result("cancelled")
    try:
        ctx.app.cancel_enroll()
    except Exception:
        pass
    ctx.send_json(200, {"ok": True})


def _handle_enroll_status(ctx: _Ctx) -> None:
    with _enroll_lock:
        running = getattr(ctx.app, "_enroll_running", False)
        ctx.send_json(200, {
            "running": running,
            "step": _enroll_step,
            "logs": list(_enroll_logs),
            "result": _enroll_result,
        })


_ENROLL_TPL_TTL_S = 600  # 10 minutes


def _enroll_store_tpl(data: Dict[str, Any]) -> None:
    global _enroll_last_tpl
    with _enroll_last_tpl_lock:
        _enroll_last_tpl = {**data, "timestamp": time.time()}


def _enroll_clear_tpl() -> None:
    global _enroll_last_tpl
    with _enroll_last_tpl_lock:
        _enroll_last_tpl = None


def _handle_enroll_retry_push(ctx: _Ctx) -> None:
    """Retry saving the last enrolled template to the backend (no re-scan needed)."""
    with _enroll_last_tpl_lock:
        tpl = _enroll_last_tpl

    if not tpl:
        ctx.send_json(404, {"ok": False, "error": "No template available for retry."})
        return

    age = time.time() - tpl.get("timestamp", 0)
    if age > _ENROLL_TPL_TTL_S:
        _enroll_clear_tpl()
        ctx.send_json(410, {"ok": False, "error": f"Template expired ({int(age)}s > {_ENROLL_TPL_TTL_S}s). Enroll again."})
        return

    from app.core.config import load_auth_token
    auth = load_auth_token()
    if not auth or not auth.token:
        ctx.send_json(401, {"ok": False, "error": "Not logged in."})
        return

    # Partial reset: clears logs/step/result but NOT phase_seq.
    # A full _enroll_reset() sets phase_seq=0; connected SSE clients whose
    # last_phase_seq > 0 would then never see the new push phase event
    # (condition: phase_seq > last_phase_seq would be e.g. 1 > 7 = False).
    _enroll_partial_reset_for_retry()
    _enroll_set_phase({"phase": "push"})
    _enroll_add_log("Retrying push to backend...")

    # Dispatch to a daemon thread so the HTTP server thread is not blocked.
    # The outbound API call has no timeout and could stall indefinitely on a
    # slow or unreachable backend, which would starve the SSE connection.
    _tpl_snapshot = dict(tpl)
    _token_snapshot = auth.token
    _app_ref = ctx.app

    def _do_retry_push() -> None:
        try:
            payload = {
                "activeMembershipId": int(_tpl_snapshot["active_membership_id"]),
                "fingerId": int(_tpl_snapshot["finger_id"]),
                "templateData": _tpl_snapshot["tpl_text"],
                "templateVersion": int(_tpl_snapshot["tpl_ver"]),
                "templateEncoding": _tpl_snapshot["enc_backend"],
                "label": "dashboard",
                "enabled": True,
            }
            api = _app_ref._api()
            resp = api.create_user_fingerprint(token=_token_snapshot, payload=payload)
            _enroll_add_log(f"Push OK: {resp}")
            _enroll_set_result("success")
            _enroll_clear_tpl()
        except Exception as e:
            _enroll_add_log(f"ERROR: Retry push failed: {e}")
            _enroll_set_result("failed")

    threading.Thread(target=_do_retry_push, daemon=True).start()
    ctx.send_json(202, {"ok": True, "message": "Retry push started"})


def _handle_enroll_events_sse(ctx: _Ctx) -> None:
    """SSE stream: enrollment progress. Sends initial snapshot immediately."""
    ctx.send_sse_start()

    last_log_idx = 0
    last_step = ""
    sent_result = False
    sent_start_meta: Optional[Dict[str, Any]] = None
    last_phase_seq = 0
    last_ping = time.time()

    def send_snapshot() -> bool:
        nonlocal last_log_idx, last_step, sent_result, sent_start_meta, last_phase_seq
        with _enroll_lock:
            step = _enroll_step
            logs = list(_enroll_logs)
            result = _enroll_result
            start_meta = _enroll_start_meta
            phase = _enroll_phase
            phase_seq = _enroll_phase_seq

        # send enroll_started if available
        if start_meta and start_meta != sent_start_meta:
            if not ctx.send_sse_event("enroll_started", start_meta):
                return False
            sent_start_meta = start_meta

        # send all existing logs
        for i in range(0, len(logs)):
            if not ctx.send_sse_event("log", {"line": logs[i]}):
                return False
        last_log_idx = len(logs)

        # send current step
        if step:
            if not ctx.send_sse_event("step", {"step": step}):
                return False
            last_step = step

        # send current phase if available
        if phase and phase_seq > last_phase_seq:
            phase_data = {k: v for k, v in phase.items() if k != "_seq"}
            if not ctx.send_sse_event("phase", phase_data):
                return False
            last_phase_seq = phase_seq

        # send current result once (but keep stream open)
        if result:
            if not ctx.send_sse_event(result, {"result": result}):
                return False
            sent_result = True

        return True

    if not send_snapshot():
        return

    while True:
        try:
            _enroll_event.wait(timeout=0.5)
            _enroll_event.clear()

            with _enroll_lock:
                step = _enroll_step
                logs = list(_enroll_logs)
                result = _enroll_result
                start_meta = _enroll_start_meta
                phase = _enroll_phase
                phase_seq = _enroll_phase_seq

            # detect reset (new enroll)
            if len(logs) < last_log_idx:
                last_log_idx = 0
            if result is None:
                sent_result = False
            if start_meta is None:
                sent_start_meta = None
            if phase is None:
                last_phase_seq = 0

            if start_meta and start_meta != sent_start_meta:
                if not ctx.send_sse_event("enroll_started", start_meta):
                    return
                sent_start_meta = start_meta

            for i in range(last_log_idx, len(logs)):
                if not ctx.send_sse_event("log", {"line": logs[i]}):
                    return
            last_log_idx = len(logs)

            if step and step != last_step:
                if not ctx.send_sse_event("step", {"step": step}):
                    return
                last_step = step

            if phase and phase_seq > last_phase_seq:
                phase_data = {k: v for k, v in phase.items() if k != "_seq"}
                if not ctx.send_sse_event("phase", phase_data):
                    return
                last_phase_seq = phase_seq

            if result and not sent_result:
                if not ctx.send_sse_event(result, {"result": result}):
                    return
                sent_result = True

            if time.time() - last_ping > 15:
                if not ctx.send_sse_event("ping", {"t": int(time.time())}):
                    return
                last_ping = time.time()

        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            return
        except Exception:
            return


def _handle_fingerprints_list(ctx: _Ctx) -> None:
    from access.store import list_fingerprints
    fps = list_fingerprints()
    ctx.send_json(200, {"fingerprints": [
        {"id": f.id, "createdAt": f.created_at, "pin": f.pin, "cardNo": f.card_no,
         "fingerId": f.finger_id, "templateVersion": f.template_version,
         "templateEncoding": f.template_encoding, "templateSize": f.template_size,
         "label": f.label}
        for f in fps
    ]})


def _handle_fingerprints_delete(ctx: _Ctx) -> None:
    fp_id = ctx.param_int("id")
    from access.store import delete_fingerprint
    try:
        delete_fingerprint(fp_id)
        ctx.send_json(200, {"ok": True})
    except Exception as e:
        ctx.send_json(400, {"ok": False, "error": str(e)})


# ==================== 8) SCANNER ====================

# Module-level discovery state (protected by _discovery_lock)
_discovery_lock = threading.Lock()
_discovery_running = False
_discovery_devices: list = []
_discovery_cancel = threading.Event()


def _handle_scanner_start(ctx: _Ctx) -> None:
    from app.core.card_scanner import get_scanner
    from app.core.config import load_config
    body = ctx.body()
    cfg = load_config()
    mode = _safe_str(body.get("mode"), cfg.scanner_mode) or "network"
    ip = _safe_str(body.get("ip"), cfg.scanner_network_ip) or ""
    port = _safe_int(body.get("port"), cfg.scanner_network_port) or 4370
    timeout_ms = _safe_int(body.get("timeout_ms"), cfg.scanner_network_timeout_ms) or 5000
    usb_device_path = _safe_str(body.get("usb_device_path"), cfg.scanner_usb_device_path) or ""

    scanner = get_scanner()
    started = scanner.start_scan(
        mode=mode,
        ip=ip,
        port=port,
        timeout_ms=timeout_ms,
        usb_device_path=usb_device_path,
    )
    if started:
        ctx.send_json(200, {"ok": True})
    else:
        ctx.send_json(409, {"ok": False, "error": "Scanner already active"})


def _handle_scanner_stop(ctx: _Ctx) -> None:
    from app.core.card_scanner import get_scanner
    get_scanner().stop_scan()
    ctx.send_json(200, {"ok": True})


def _handle_scanner_status(ctx: _Ctx) -> None:
    from app.core.card_scanner import get_scanner
    ctx.send_json(200, {"ok": True, "scanner": get_scanner().get_status()})


def _handle_scanner_discover(ctx: _Ctx) -> None:
    global _discovery_running, _discovery_devices, _discovery_cancel
    with _discovery_lock:
        if _discovery_running:
            ctx.send_json(409, {"ok": False, "error": "Discovery already running"})
            return
        _discovery_running = True
        _discovery_devices = []
        _discovery_cancel.clear()

    body = ctx.body()
    subnet = _safe_str(body.get("subnet"), "") or None

    # Check if scanner is active — skip handshake to avoid conflicting with live_capture
    from app.core.card_scanner import get_scanner
    from app.core.card_scanner import ScannerState
    scanner_active = get_scanner().state in (ScannerState.SCANNING, ScannerState.CONNECTING)

    def _run_discovery() -> None:
        global _discovery_running, _discovery_devices
        try:
            from app.core.network_discovery import scan_subnet
            results = scan_subnet(
                subnet=subnet,
                do_handshake=(not scanner_active),
                cancel_event=_discovery_cancel,
            )
            with _discovery_lock:
                _discovery_devices = results
        except Exception as e:
            logger.error(f"Discovery error: {e}")
        finally:
            with _discovery_lock:
                _discovery_running = False

    threading.Thread(target=_run_discovery, daemon=True, name="scanner-discover").start()
    ctx.send_json(200, {"ok": True})


def _handle_scanner_discover_status(ctx: _Ctx) -> None:
    with _discovery_lock:
        running = _discovery_running
        devices = list(_discovery_devices)
    ctx.send_json(200, {
        "ok": True,
        "running": running,
        "devices": [
            {
                "ip": d.ip,
                "port": d.port,
                "serialNumber": d.serial_number,
                "model": d.model,
            }
            for d in devices
        ],
    })


# ==================== 9) LOGS ====================

def _serialize_log_entry(entry: Any) -> Dict[str, Any]:
    repeat_count = max(1, _safe_int(getattr(entry, "repeat_count", 1), 1))
    raw_text = _safe_str(getattr(entry, "raw_text", getattr(entry, "text", "")), "")
    text = _safe_str(getattr(entry, "text", raw_text), raw_text)
    if repeat_count > 1 and text == raw_text:
        text = f"{raw_text} (x{repeat_count})"

    tokens: Dict[str, str] = {}
    raw_tokens = getattr(entry, "tokens", None)
    if isinstance(raw_tokens, dict):
        for key, value in raw_tokens.items():
            k = _safe_str(key, "").strip()
            v = _safe_str(value, "").strip()
            if k and v:
                tokens[k] = v

    ts = _safe_str(getattr(entry, "first_seen_at", getattr(entry, "ts", "")), "").strip()
    last_seen_at = _safe_str(getattr(entry, "last_seen_at", ts), ts).strip()
    if not ts:
        ts = last_seen_at or time.strftime("%Y-%m-%dT%H:%M:%S")

    return {
        "id": getattr(entry, "id", None),
        "revision": _safe_int(getattr(entry, "revision", repeat_count), repeat_count),
        "level": _safe_str(getattr(entry, "level", "INFO"), "INFO").upper(),
        "text": text,
        "rawText": raw_text or text,
        "repeatCount": repeat_count,
        "collapsed": repeat_count > 1,
        "ts": ts,
        "firstSeenAt": ts,
        "lastSeenAt": last_seen_at or ts,
        "tokens": tokens,
    }


def _read_log_filters(ctx: _Ctx) -> Dict[str, Any]:
    return {
        "level": ctx.q("level", default="ALL").upper(),
        "query": _safe_str(ctx.q("q", "query", "filter", "search", default=""), "").strip().lower(),
        "door": _safe_str(ctx.q("door", "doorId", "doorNumber", default=""), "").strip().lower(),
        "card": _safe_str(ctx.q("card", "cardId", "cardNo", "code", default=""), "").strip().lower(),
        "device": _safe_str(ctx.q("device", "deviceId", default=""), "").strip().lower(),
        "category": _safe_str(ctx.q("category", default="ALL"), "ALL").strip().upper(),
        "repeated_only": _safe_bool(ctx.q("repeatedOnly", "duplicatesOnly", "collapsedOnly", default="0"), False),
    }


def _payload_matches_log_filters(payload: Dict[str, Any], filters: Dict[str, Any]) -> bool:
    level = _safe_str(payload.get("level"), "INFO").upper()
    if filters["level"] not in ("", "ALL") and level != filters["level"]:
        return False

    repeat_count = max(1, _safe_int(payload.get("repeatCount"), 1))
    if filters["repeated_only"] and repeat_count <= 1:
        return False

    tokens = payload.get("tokens") if isinstance(payload.get("tokens"), dict) else {}
    category = _safe_str(tokens.get("category"), "SYSTEM").upper()
    if filters["category"] not in ("", "ALL") and category != filters["category"]:
        return False

    searchable_parts = [
        _safe_str(payload.get("rawText"), ""),
        _safe_str(payload.get("text"), ""),
        level,
        _safe_str(payload.get("ts"), ""),
        _safe_str(tokens.get("door"), ""),
        _safe_str(tokens.get("cardId"), ""),
        _safe_str(tokens.get("deviceId"), ""),
        _safe_str(tokens.get("userId"), ""),
        _safe_str(tokens.get("mode"), ""),
        category,
    ]
    searchable = " ".join(part for part in searchable_parts if part).lower()

    if filters["query"] and filters["query"] not in searchable:
        return False
    if filters["door"] and filters["door"] not in (_safe_str(tokens.get("door"), "").lower() or searchable):
        return False
    if filters["card"] and filters["card"] not in (_safe_str(tokens.get("cardId"), "").lower() or searchable):
        return False
    if filters["device"] and filters["device"] not in (_safe_str(tokens.get("deviceId"), "").lower() or searchable):
        return False
    return True


def _load_log_payloads(page: Any, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not page or not hasattr(page, "snapshot"):
        return []
    try:
        entries = page.snapshot()
    except Exception:
        return []
    payloads = [_serialize_log_entry(entry) for entry in entries]
    return [payload for payload in payloads if _payload_matches_log_filters(payload, filters)]


def _handle_logs_recent_common(ctx: _Ctx, *, include_ok: bool = False) -> None:
    page = getattr(ctx.app, "page_logs", None)
    filters = _read_log_filters(ctx)
    limit = ctx.q_int("limit", default=500)
    lines = _load_log_payloads(page, filters)
    total = len(lines)
    if limit > 0:
        lines = lines[-limit:]
    payload: Dict[str, Any] = {"lines": lines, "total": total}
    if include_ok:
        payload["ok"] = True
    ctx.send_json(200, payload)


def _stream_logs_common(ctx: _Ctx) -> None:
    ctx.send_sse_start()
    filters = _read_log_filters(ctx)
    page = getattr(ctx.app, "page_logs", None)
    last_revision = page.get_revision() if page and hasattr(page, "get_revision") else 0

    while True:
        try:
            time.sleep(0.2)
            if not page:
                page = getattr(ctx.app, "page_logs", None)
                last_revision = page.get_revision() if page and hasattr(page, "get_revision") else 0
                continue

            if not hasattr(page, "changes_since"):
                return

            last_revision, changed_entries = page.changes_since(last_revision)
            for entry in changed_entries:
                payload = _serialize_log_entry(entry)
                if _payload_matches_log_filters(payload, filters):
                    if not ctx.send_sse_event("log", payload):
                        return
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            return
        except Exception:
            return


def _handle_logs_recent(ctx: _Ctx) -> None:
    _handle_logs_recent_common(ctx)


def _handle_logs_stream_sse(ctx: _Ctx) -> None:
    """SSE stream: real-time log tail."""
    _stream_logs_common(ctx)


def _handle_tv_logs_recent(ctx: _Ctx) -> None:
    _handle_logs_recent_common(ctx, include_ok=True)


def _handle_tv_logs_stream_sse(ctx: _Ctx) -> None:
    _stream_logs_common(ctx)


def _handle_logs_open_dir(ctx: _Ctx) -> None:
    from app.core.utils import LOG_DIR
    path = str(LOG_DIR)
    try:
        os.startfile(path)
    except Exception:
        pass
    ctx.send_json(200, {"ok": True, "path": path})


# ==================== 9) UPDATES ====================

def _build_update_status_payload(app) -> Dict[str, Any]:
    um = getattr(app, "_update_manager", None)
    # Status lives on the manager itself (new design) or as a separate attribute (legacy)
    st = getattr(um, "status", None) or getattr(app, "_update_status", None)
    data: Dict[str, Any] = {"updateAvailable": False}
    if um:
        # Current version info (new semver fields)
        data["currentVersion"] = getattr(um, "get_current_version", lambda: "0.0.0")()
        data["currentCodename"] = getattr(um, "get_current_codename", lambda: "")()
        # Legacy field for backward compat
        data["currentReleaseId"] = getattr(um, "get_current_release_id", lambda: "dev")()
        component = getattr(um, "component", None)
        install_root = Path(getattr(um, "install_root", "")) if getattr(um, "install_root", None) else None
        updater_name = getattr(component, "updater_exe_name", None)
        updater_path = install_root / "updater" / updater_name if install_root and updater_name else None
        data["componentId"] = getattr(component, "component_id", None)
        data["componentDisplayName"] = getattr(component, "display_name", None)
        data["artifactName"] = getattr(component, "artifact_name", None)
        data["mainExecutable"] = getattr(component, "main_exe_name", None)
        data["updaterExecutable"] = updater_name
        data["updaterInstalled"] = bool(updater_path and updater_path.exists())
        data["installRoot"] = str(install_root) if install_root else None
        data["updateEnabled"] = bool(getattr(getattr(app, "cfg", None), "update_enabled", True))
        data["channel"] = getattr(getattr(app, "cfg", None), "update_channel", None)
        data["platform"] = getattr(getattr(app, "cfg", None), "update_platform", None)
    if st:
        data["updateAvailable"] = bool(getattr(st, "update_available", False))
        data["downloaded"] = bool(getattr(st, "downloaded", False))
        data["downloading"] = bool(getattr(st, "downloading", False))
        data["progressPercent"] = getattr(st, "progress_percent", None)
        data["lastCheckAt"] = getattr(st, "last_check_at", 0)
        data["lastError"] = getattr(st, "last_error", None)
        # New semver fields
        data["latestVersion"] = getattr(st, "latest_version", None)
        data["latestCodename"] = getattr(st, "latest_codename", None)
        data["releaseDate"] = getattr(st, "release_date", None)
        data["availableUntil"] = getattr(st, "available_until", None)
        data["sizeBytes"] = getattr(st, "size_bytes", None)
        data["releaseNotes"] = getattr(st, "release_notes", None)
        data["downloadUrl"] = getattr(st, "download_url", None)
        data["minCompatibleVersion"] = getattr(st, "min_compatible_version", None)
        # Legacy latestRelease block for backward compat
        lr = getattr(st, "latest_release", None)
        if isinstance(lr, dict):
            data["latestRelease"] = {
                "releaseId": lr.get("releaseId"),
                "publishDate": lr.get("publishedAt") or lr.get("publishDate") or lr.get("publish_date"),
                "channel": lr.get("channel"),
                "platform": lr.get("platform"),
                "version": lr.get("version"),
                "codename": lr.get("codename"),
                "notes": lr.get("releaseNotes") or lr.get("notes"),
                "availableUntil": lr.get("availableUntil"),
                "minCompatibleVersion": lr.get("minCompatibleVersion"),
            }
    return data


def _handle_component_update_status(ctx: _Ctx) -> None:
    ctx.send_json(200, _build_update_status_payload(ctx.app))


def _handle_component_update_check(ctx: _Ctx) -> None:
    um = getattr(ctx.app, "_update_manager", None)
    if um:
        try:
            um.request_check_now()
        except Exception:
            pass
    ctx.send_json(200, {"ok": True})


def _handle_component_update_download(ctx: _Ctx) -> None:
    um = getattr(ctx.app, "_update_manager", None)
    if um:
        try:
            um.request_download()
        except Exception:
            pass
    ctx.send_json(200, {"ok": True})


def _handle_component_update_install(ctx: _Ctx) -> None:
    um = getattr(ctx.app, "_update_manager", None)
    if not um:
        ctx.send_json(400, {"ok": False, "error": "update manager not available"})
        return
    can, reason = um.can_install_now()
    if not can:
        ctx.send_json(400, {"ok": False, "error": reason})
        return
    ctx.send_json(200, {"ok": True, "message": "launching installer and exiting"})
    # Schedule quit after response is sent
    def _do_install():
        try:
            um.launch_updater_and_exit()
        except Exception:
            pass
        try:
            ctx.app.after(0, ctx.app.quit_app)
        except Exception:
            pass
    threading.Timer(0.5, _do_install).start()


def _handle_update_status(ctx: _Ctx) -> None:
    _handle_component_update_status(ctx)


def _handle_update_check(ctx: _Ctx) -> None:
    _handle_component_update_check(ctx)


def _handle_update_download(ctx: _Ctx) -> None:
    _handle_component_update_download(ctx)


def _handle_update_install(ctx: _Ctx) -> None:
    _handle_component_update_install(ctx)


def _handle_tv_update_status(ctx: _Ctx) -> None:
    _handle_component_update_status(ctx)


def _handle_tv_update_check(ctx: _Ctx) -> None:
    _handle_component_update_check(ctx)


def _handle_tv_update_download(ctx: _Ctx) -> None:
    _handle_component_update_download(ctx)


def _handle_tv_update_install(ctx: _Ctx) -> None:
    _handle_component_update_install(ctx)


def _handle_component_update_cancel(ctx: _Ctx) -> None:
    um = getattr(ctx.app, "_update_manager", None)
    if um:
        try:
            um.cancel_download()
        except Exception:
            pass
    ctx.send_json(200, {"ok": True})


def _handle_update_cancel(ctx: _Ctx) -> None:
    _handle_component_update_cancel(ctx)


def _handle_tv_update_cancel(ctx: _Ctx) -> None:
    _handle_component_update_cancel(ctx)


def _handle_component_update_version_info(ctx: _Ctx) -> None:
    """Always-available endpoint: returns current version info regardless of update state."""
    um = getattr(ctx.app, "_update_manager", None)
    if um:
        ctx.send_json(200, {
            "ok": True,
            "currentVersion": getattr(um, "get_current_version", lambda: "0.0.0")(),
            "currentCodename": getattr(um, "get_current_codename", lambda: "")(),
            "currentReleaseId": getattr(um, "get_current_release_id", lambda: "dev")(),
            "componentId": getattr(getattr(um, "component", None), "component_id", None),
            "componentDisplayName": getattr(getattr(um, "component", None), "display_name", None),
        })
    else:
        ctx.send_json(200, {"ok": True, "currentVersion": "0.0.0", "currentCodename": "", "currentReleaseId": "dev"})


def _handle_update_version_info(ctx: _Ctx) -> None:
    _handle_component_update_version_info(ctx)


def _handle_tv_update_version_info(ctx: _Ctx) -> None:
    _handle_component_update_version_info(ctx)


# ==================== 10) LOCAL DB TOOLS ====================

def _handle_access_storage_status(ctx: _Ctx) -> None:
    from access.store import get_access_storage_status

    ctx.send_json(200, get_access_storage_status())


def _handle_tv_storage_status(ctx: _Ctx) -> None:
    from tv.store import get_tv_storage_status

    ctx.send_json(200, get_tv_storage_status())


def _normalize_sqlite_table_name(table_name: str) -> str:
    name = (table_name or "").strip()
    if not _SQLITE_TABLE_NAME_RE.fullmatch(name):
        raise ValueError("invalid table name")
    return name


def _handle_tv_db_tables(ctx: _Ctx) -> None:
    from shared.storage_migration import STORAGE_STATUS_TABLE, TV_OWNED_TABLES
    from tv.storage import current_tv_runtime_db_path
    from tv.store import get_conn

    owned_tables = set(TV_OWNED_TABLES)
    owned_tables.update({STORAGE_STATUS_TABLE, "tv_backend_auth_state"})
    tables = []
    db_path = current_tv_runtime_db_path()

    try:
        with get_conn() as conn:
            rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
            for row in rows:
                name = str(row[0])
                count = conn.execute(f"SELECT COUNT(*) FROM [{name}]").fetchone()[0]
                tables.append({
                    "name": name,
                    "rowCount": int(count or 0),
                    "owned": name in owned_tables,
                })
    except Exception as exc:
        ctx.send_json(500, {"ok": False, "error": str(exc)})
        return

    db_size = 0
    try:
        db_size = os.path.getsize(str(db_path))
    except Exception:
        pass

    ctx.send_json(200, {
        "ok": True,
        "dbPath": str(db_path),
        "dbSizeBytes": db_size,
        "tables": tables,
    })


def _handle_tv_db_table_query(ctx: _Ctx) -> None:
    from tv.store import get_conn

    try:
        table_name = _normalize_sqlite_table_name(ctx.param("tableName"))
    except ValueError as exc:
        ctx.send_json(400, {"ok": False, "error": str(exc)})
        return

    limit = ctx.q_int("limit", default=500)
    offset = max(0, ctx.q_int("offset", default=0))
    if limit <= 0:
        limit = 500
    if limit > 10000:
        limit = 10000

    try:
        with get_conn() as conn:
            table_exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table_name,),
            ).fetchone()
            if not table_exists:
                ctx.send_json(404, {"ok": False, "error": f"unknown table: {table_name}"})
                return

            total = conn.execute(f"SELECT COUNT(*) FROM [{table_name}]").fetchone()[0]
            cursor = conn.execute(f"SELECT * FROM [{table_name}] LIMIT ? OFFSET ?", (limit, offset))
            columns = [d[0] for d in (cursor.description or [])]
            rows = [dict(row) for row in cursor.fetchall()]
    except Exception as exc:
        ctx.send_json(400, {"ok": False, "error": str(exc)})
        return

    ctx.send_json(200, {
        "ok": True,
        "tableName": table_name,
        "columns": columns,
        "rows": rows,
        "total": total,
        "limit": limit,
        "offset": offset,
    })


def _handle_db_tables(ctx: _Ctx) -> None:
    from access.store import get_conn
    from access.storage import current_access_runtime_db_path
    tables = []
    try:
        with get_conn() as conn:
            rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
            for r in rows:
                name = r[0]
                count = conn.execute(f"SELECT COUNT(*) FROM [{name}]").fetchone()[0]
                tables.append({"name": name, "rowCount": count})
    except Exception:
        pass

    db_size = 0
    try:
        db_size = os.path.getsize(str(current_access_runtime_db_path()))
    except Exception:
        pass

    ctx.send_json(200, {"tables": tables, "dbSizeBytes": db_size})


def _handle_db_table_query(ctx: _Ctx) -> None:
    table_name = ctx.param("tableName")
    limit = ctx.q_int("limit", default=500)
    offset = ctx.q_int("offset", default=0)
    if limit > 10000:
        limit = 10000

    from access.store import get_conn
    try:
        with get_conn() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM [{table_name}]").fetchone()[0]
            cursor = conn.execute(f"SELECT * FROM [{table_name}] LIMIT ? OFFSET ?", (limit, offset))
            columns = [d[0] for d in cursor.description]
            rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
        ctx.send_json(200, {"rows": rows, "columns": columns, "total": total})
    except Exception as e:
        ctx.send_json(400, {"ok": False, "error": str(e)})


def _handle_db_access_history(ctx: _Ctx) -> None:
    from access.store import get_recent_access_history
    limit = ctx.q_int("limit", default=50)
    records = get_recent_access_history(limit=limit)
    ctx.send_json(200, {"records": [
        {
            "eventId": r.event_id,
            "deviceId": r.device_id,
            "doorId": r.door_id,
            "cardNo": r.card_no,
            "eventTime": r.event_time,
            "eventType": r.event_type,
            "allowed": r.allowed,
            "reason": r.reason,
            "pollMs": r.poll_ms,
            "decisionMs": r.decision_ms,
            "cmdMs": r.cmd_ms,
            "cmdOk": r.cmd_ok,
            "cmdError": r.cmd_error,
            "createdAt": r.created_at,
            "historySource": r.history_source,
            "backendSyncState": r.backend_sync_state,
            "backendAttemptCount": r.backend_attempt_count,
            "backendFailureCount": r.backend_failure_count,
            "backendLastAttemptAt": r.backend_last_attempt_at,
            "backendNextRetryAt": r.backend_next_retry_at,
            "backendSyncedAt": r.backend_synced_at,
            "backendLastError": r.backend_last_error,
        }
        for r in records
    ]})


def _handle_db_export(ctx: _Ctx) -> None:
    from access.store import get_conn
    from app.core.utils import now_iso
    export: Dict[str, Any] = {}
    tables_to_export = [
        "sync_users", "sync_memberships", "sync_devices", "sync_infrastructures",
        "sync_gym_access_credentials", "fingerprints", "device_door_presets",
        "agent_rtlog_state", "access_history", "device_sync_state", "device_attendance_state", "auth_state",
    ]
    try:
        with get_conn() as conn:
            for t in tables_to_export:
                try:
                    cursor = conn.execute(f"SELECT * FROM [{t}] LIMIT 10000")
                    cols = [d[0] for d in cursor.description]
                    export[t] = [dict(zip(cols, row)) for row in cursor.fetchall()]
                except Exception:
                    export[t] = []
    except Exception:
        pass

    export["_metadata"] = {
        "exportDate": now_iso(),
        "totalRecords": sum(len(export.get(t, [])) for t in tables_to_export),
    }
    ctx.send_json(200, export)


def _handle_db_stats(ctx: _Ctx) -> None:
    from access.store import get_conn
    from access.storage import current_access_runtime_db_path
    info: Dict[str, Any] = {}
    try:
        with get_conn() as conn:
            tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            info["tableCount"] = len(tables)
            sizes = {}
            for t in tables:
                name = t[0]
                c = conn.execute(f"SELECT COUNT(*) FROM [{name}]").fetchone()[0]
                sizes[name] = c
            info["tableSizes"] = sizes
        info["dbSizeBytes"] = os.path.getsize(str(current_access_runtime_db_path()))
    except Exception as e:
        info["error"] = str(e)
    ctx.send_json(200, info)


# ==================== 11) APP / TRAY COMMANDS ====================

def _handle_app_show(ctx: _Ctx) -> None:
    try:
        ctx.app.after(0, ctx.app.show_from_tray)
    except Exception:
        pass
    ctx.send_json(200, {"ok": True})


def _handle_app_hide(ctx: _Ctx) -> None:
    try:
        ctx.app.after(0, ctx.app.hide_to_tray)
    except Exception:
        pass
    ctx.send_json(200, {"ok": True})


def _handle_app_quit(ctx: _Ctx) -> None:
    ctx.send_json(200, {"ok": True})
    threading.Timer(0.3, lambda: ctx.app.after(0, ctx.app.quit_app)).start()


# ==================== DEPRECATED V1 ENDPOINTS ====================

def _handle_v1_health(ctx: _Ctx) -> None:
    """Deprecated: use GET /api/v2/health"""
    ctx.handler.send_header("Deprecation", "true")
    ctx.handler.send_header("Sunset", "2026-06-01")
    ctx.handler.send_header("Link", "</api/v2/health>; rel=\"successor-version\"")
    _handle_health(ctx)


def _handle_v1_enroll(ctx: _Ctx) -> None:
    """Deprecated: use POST /api/v2/enroll/start"""
    user_id = ctx.q("id", "userId", "user_id")
    finger_id = ctx.q("fingerId", "finger_id")
    full_name = ctx.q("fullName", "fullname", "name")
    device = ctx.q("device", "scanner")

    if not device and full_name and "?device=" in full_name:
        left, right = full_name.split("?device=", 1)
        full_name = left
        device = right.strip()

    result = ctx.app.begin_remote_enroll(
        user_id=user_id,
        finger_id=finger_id,
        full_name=full_name,
        device=device or "zk9500",
    )

    ctx.handler.send_header("Deprecation", "true")
    ctx.handler.send_header("Sunset", "2026-06-01")
    ctx.handler.send_header("Link", "</api/v2/enroll/start>; rel=\"successor-version\"")

    if result.get("ok"):
        ctx.send_json(202, result)
    else:
        code = int(result.get("status") or 400)
        ctx.send_json(code, result)



# ---------------------------------------------------------------------------
# TV Snapshot Sync handlers (A2)
# ---------------------------------------------------------------------------

def _handle_tv_snapshots_list(ctx: _Ctx) -> None:
    from tv.api import ensure_tv_local_schema, list_tv_snapshot_cache
    ensure_tv_local_schema()
    screen_id = ctx.q_int("screenId", default=0)
    limit = max(1, min(ctx.q_int("limit", default=50), 500))
    offset = max(0, ctx.q_int("offset", default=0))
    data = list_tv_snapshot_cache(screen_id=screen_id, limit=limit, offset=offset)
    ctx.send_json(200, {"ok": True, **data})


def _handle_tv_snapshots_latest(ctx: _Ctx) -> None:
    from tv.api import (ensure_tv_local_schema,
        load_tv_latest_snapshot, list_tv_screen_bindings)
    ensure_tv_local_schema()
    screen_id = ctx.q_int("screenId", default=0)
    if screen_id <= 0:
        # return latest for all screens
        bindings = list_tv_screen_bindings()
        results = []
        for b in bindings:
            sid = int(b.get("screen_id") or 0)
            if sid > 0:
                snap = load_tv_latest_snapshot(screen_id=sid)
                if snap:
                    results.append(snap)
        ctx.send_json(200, {"ok": True, "snapshots": results})
        return
    snap = load_tv_latest_snapshot(screen_id=screen_id)
    ctx.send_json(200, {"ok": True, "snapshot": snap})


def _handle_tv_snapshot_assets(ctx: _Ctx) -> None:
    from tv.api import (ensure_tv_local_schema,
        list_tv_snapshot_required_assets)
    ensure_tv_local_schema()
    snapshot_id = str(ctx.param("snapshotId") or "").strip()
    if not snapshot_id:
        ctx.send_json(400, {"ok": False, "error": "snapshotId is required"})
        return
    assets = list_tv_snapshot_required_assets(snapshot_id=snapshot_id)
    ctx.send_json(200, {"ok": True, "assets": assets, "total": len(assets)})


def _handle_tv_snapshots_sync(ctx: _Ctx) -> None:
    from tv.api import ensure_tv_local_schema, run_tv_snapshot_sync
    ensure_tv_local_schema()
    import threading as _thr

    def _run():
        try:
            result = run_tv_snapshot_sync(app=ctx.app)
            ctx.app.logger.info("[TvSync] Manual sync result: ok=%s synced=%s",
                                result.get("ok"), result.get("synced"))
        except Exception as e:
            ctx.app.logger.exception("[TvSync] Manual sync failed: %s", e)

    _thr.Thread(target=_run, daemon=True).start()
    ctx.send_json(202, {"ok": True, "message": "Snapshot sync started in background"})


def _handle_tv_sync_runs(ctx: _Ctx) -> None:
    from tv.api import ensure_tv_local_schema, list_tv_sync_run_logs
    ensure_tv_local_schema()
    screen_id = ctx.q_int("screenId", default=0) or None
    limit = max(1, min(ctx.q_int("limit", default=50), 500))
    offset = max(0, ctx.q_int("offset", default=0))
    data = list_tv_sync_run_logs(screen_id=screen_id, limit=limit, offset=offset)
    ctx.send_json(200, {"ok": True, **data})


# ---------------------------------------------------------------------------
# TV Asset Download handlers (A3)
# ---------------------------------------------------------------------------

def _handle_tv_assets_list(ctx: _Ctx) -> None:
    from tv.api import (ensure_tv_local_schema,
        list_tv_cache_assets)
    ensure_tv_local_schema()
    screen_id = ctx.q_int("screenId", default=0)
    snapshot_id = str(ctx.param("snapshotId") or "").strip()
    asset_state = str(ctx.param("state") or "").strip()
    media_asset_id = str(ctx.param("mediaAssetId") or "").strip()
    limit = max(1, min(ctx.q_int("limit", default=50), 500))
    offset = max(0, ctx.q_int("offset", default=0))
    data = list_tv_cache_assets(
        screen_id=screen_id, snapshot_id=snapshot_id,
        asset_state=asset_state, media_asset_id=media_asset_id,
        limit=limit, offset=offset)
    ctx.send_json(200, {"ok": True, **data})


def _handle_tv_assets_download(ctx: _Ctx) -> None:
    from tv.api import ensure_tv_local_schema, run_tv_asset_download
    ensure_tv_local_schema()
    import threading as _thr

    body = ctx.body() if hasattr(ctx, "body_json") else {}
    screen_id = ctx.q_int("screenId", default=0) or int(body.get("screenId") or 0) if isinstance(body, dict) else 0
    snapshot_id = str(ctx.param("snapshotId") or "").strip()
    if not snapshot_id and isinstance(body, dict):
        snapshot_id = str(body.get("snapshotId") or "").strip()

    def _run():
        try:
            result = run_tv_asset_download(
                snapshot_id=snapshot_id, screen_id=screen_id, app=ctx.app)
            ctx.app.logger.info(
                "[TvDownload] Manual download result: ok=%s total=%s downloaded=%s",
                result.get("ok"), result.get("total"), result.get("downloaded"))
        except Exception as e:
            ctx.app.logger.exception("[TvDownload] Manual download failed: %s", e)

    _thr.Thread(target=_run, daemon=True).start()
    ctx.send_json(202, {"ok": True, "message": "Asset download started in background"})


def _handle_tv_asset_detail(ctx: _Ctx) -> None:
    from tv.api import (ensure_tv_local_schema,
        load_tv_local_asset_state)
    ensure_tv_local_schema()
    media_asset_id = str(ctx.param("mediaAssetId") or "").strip()
    if not media_asset_id:
        ctx.send_json(400, {"ok": False, "error": "mediaAssetId is required"})
        return
    row = load_tv_local_asset_state(media_asset_id=media_asset_id)
    if not row:
        ctx.send_json(404, {"ok": False, "error": "asset not found"})
        return
    ctx.send_json(200, {"ok": True, "asset": row})


# ---------------------------------------------------------------------------
# TV Readiness Engine (A4)
# ---------------------------------------------------------------------------

def _handle_tv_readiness_list(ctx: _Ctx) -> None:
    from tv.api import ensure_tv_local_schema, list_tv_snapshot_readiness
    ensure_tv_local_schema()
    screen_id = ctx.q_int("screenId", default=0)
    limit = max(1, min(ctx.q_int("limit", default=100), 500))
    offset = max(0, ctx.q_int("offset", default=0))
    data = list_tv_snapshot_readiness(screen_id=screen_id, limit=limit, offset=offset)
    ctx.send_json(200, {"ok": True, **data})


def _handle_tv_readiness_latest(ctx: _Ctx) -> None:
    from tv.api import ensure_tv_local_schema, load_tv_latest_readiness
    ensure_tv_local_schema()
    screen_id = ctx.q_int("screenId", default=0)
    if screen_id <= 0:
        ctx.send_json(400, {"ok": False, "error": "screenId is required"})
        return
    row = load_tv_latest_readiness(screen_id=screen_id)
    if not row:
        ctx.send_json(404, {"ok": False, "error": "Readiness state not found for screen."})
        return
    ctx.send_json(200, {"ok": True, "readiness": row})


def _handle_tv_readiness_recompute(ctx: _Ctx) -> None:
    from tv.api import ensure_tv_local_schema, run_tv_readiness_computation
    import threading as _thr
    ensure_tv_local_schema()
    body = ctx.body() if hasattr(ctx, "body_json") else {}
    screen_id = ctx.q_int("screenId", default=0) or int(body.get("screenId") or 0) if isinstance(body, dict) else 0

    def _run():
        try:
            res = run_tv_readiness_computation(screen_id=screen_id)
            ctx.app.logger.info("[TvReadiness] Batch recompute complete. Computed %s screens.", res.get("computed_count"))
        except Exception as e:
            ctx.app.logger.exception("[TvReadiness] Recompute failed: %s", e)

    _thr.Thread(target=_run, daemon=True).start()
    ctx.send_json(202, {"ok": True, "message": "Readiness engine recompute started in background."})


# ---------------------------------------------------------------------------
# TV Activation Engine (A5)
# ---------------------------------------------------------------------------

def _handle_tv_activation_list(ctx: _Ctx) -> None:
    from tv.api import ensure_tv_local_schema, list_tv_activation_states
    ensure_tv_local_schema()
    limit = max(1, min(ctx.q_int("limit", default=100), 500))
    offset = max(0, ctx.q_int("offset", default=0))
    states = list_tv_activation_states(limit=limit, offset=offset)
    ctx.send_json(200, {"ok": True, "limit": limit, "offset": offset, "activation_states": states})


def _handle_tv_activation_latest(ctx: _Ctx) -> None:
    from tv.api import ensure_tv_local_schema, load_tv_activation_state
    ensure_tv_local_schema()
    screen_id = ctx.q_int("screenId", default=0)
    if screen_id <= 0:
        ctx.send_json(400, {"ok": False, "error": "screenId is required"})
        return
    st = load_tv_activation_state(screen_id=screen_id)
    if not st:
        ctx.send_json(404, {"ok": False, "error": "Activation state not found for screen."})
        return
    ctx.send_json(200, {"ok": True, "state": st})


def _handle_tv_activation_evaluate(ctx: _Ctx) -> None:
    from tv.api import ensure_tv_local_schema, run_tv_activation_evaluation
    import threading as _thr
    ensure_tv_local_schema()
    body = ctx.body() if hasattr(ctx, "body_json") else {}
    screen_id = ctx.q_int("screenId", default=0) or int(body.get("screenId") or 0) if isinstance(body, dict) else 0

    def _run():
        try:
            res = run_tv_activation_evaluation(screen_id=screen_id)
            ctx.app.logger.info("[TvActivation] Evaluation complete: %s evaluated.", res.get("evaluated_count"))
        except Exception as e:
            ctx.app.logger.exception("[TvActivation] Evaluation failed: %s", e)

    _thr.Thread(target=_run, daemon=True).start()
    ctx.send_json(202, {"ok": True, "message": "Activation evaluation started in background."})


def _handle_tv_activation_activate_latest_ready(ctx: _Ctx) -> None:
    from tv.api import ensure_tv_local_schema, activate_tv_ready_snapshot
    ensure_tv_local_schema()
    
    body = ctx.body() if hasattr(ctx, "body_json") else {}
    screen_id = ctx.q_int("screenId", default=0) or int(body.get("screenId") or 0) if isinstance(body, dict) else 0
    
    if screen_id <= 0:
        ctx.send_json(400, {"ok": False, "error": "screenId is required"})
        return
        
    try:
        res = activate_tv_ready_snapshot(screen_id=screen_id, trigger_source="API_MANUAL")
        status_code = 200 if res["ok"] else 400
        ctx.send_json(status_code, res)
    except Exception as e:
        ctx.app.logger.exception(f"[TvActivation] Error activating for screen {screen_id}")
        ctx.send_json(500, {"ok": False, "error": str(e)})


def _handle_tv_activation_attempts(ctx: _Ctx) -> None:
    from tv.api import ensure_tv_local_schema, list_tv_activation_attempts
    ensure_tv_local_schema()
    screen_id = ctx.q_int("screenId", default=0)
    limit = max(1, min(ctx.q_int("limit", default=100), 500))
    offset = max(0, ctx.q_int("offset", default=0))
    rows = list_tv_activation_attempts(screen_id=screen_id, limit=limit, offset=offset)
    ctx.send_json(200, {"ok": True, "limit": limit, "offset": offset, "attempts": rows})


# ---------------------------------------------------------------------------
# Router setup
# ---------------------------------------------------------------------------

def _build_router(scope: str = "combined") -> _Router:
    # Phase 3 keeps the handler implementation shared, but the server can now
    # expose access-only, tv-only, or combined route scopes.
    from access.api import register_access_local_api_routes
    from tv.api import register_tv_local_api_routes

    normalized = str(scope or "combined").strip().lower() or "combined"
    r = _Router()
    if normalized in {"access", "combined"}:
        register_access_local_api_routes(r)
    if normalized in {"tv", "combined"}:
        register_tv_local_api_routes(r)
    return r


def _build_access_router() -> _Router:
    return _build_router("access")


def _build_tv_router() -> _Router:
    return _build_router("tv")


# ---------------------------------------------------------------------------
# Server class (public interface)
# ---------------------------------------------------------------------------

class LocalApiServerV2:
    """
    Local REST + SSE server for Tauri+React UI.

    The handler implementation remains shared for now, but the server can
    expose access-only, tv-only, or combined route scopes.
    """

    def __init__(
        self,
        *,
        app,
        host: str = "127.0.0.1",
        port: int = 8788,
        route_scope: str = "combined",
        server_name: str = "LocalApiServerV2",
    ):
        self.app = app
        self.host = host
        self.port = int(port)
        self.route_scope = str(route_scope or "combined").strip().lower() or "combined"
        self.server_name = str(server_name or "LocalApiServerV2")
        self._httpd: Optional[_AppHTTPServerV2] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._httpd is not None:
            return

        router = _build_router(self.route_scope)
        server = self

        class Handler(BaseHTTPRequestHandler):
            def _dispatch(self, method: str) -> None:
                import time as _dispatch_time
                _t0 = _dispatch_time.monotonic()
                try:
                    parsed = urlparse(self.path)
                    path = parsed.path or ""
                    qs = parse_qs(parsed.query or "")

                    handler_fn, params = router.match(method, path)
                    if handler_fn is None:
                        body = _json_bytes({"ok": False, "error": "Not found", "path": path})
                        self.send_response(404)
                        _cors_headers(self)
                        self.send_header("Content-Type", "application/json; charset=utf-8")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return

                    ctx = _Ctx(self, params, qs, server.app)

                    # B-001: Validate local API token on every non-exempt request.
                    # The token is generated per-session by MainApp and passed to
                    # Tauri via MONCLUB_LOCAL_API_TOKEN env var. The client sends it
                    # as X-Local-Token header (REST) or ?token= query param (SSE).
                    _AUTH_EXEMPT = {
                        "_handle_auth_login", "_handle_auth_status",
                        "_handle_tv_auth_login", "_handle_tv_auth_status",
                        "_handle_health", "_handle_v1_health",
                        # Dashboard (browser) callers cannot obtain the session token.
                        # sync/now is harmless (just triggers a data fetch).
                        # enroll/start still requires physical ZK device interaction.
                        "_handle_sync_now", "_handle_enroll_start", "_handle_enroll_retry_push",
                    }
                    fn_name = getattr(handler_fn, "__name__", "")
                    if fn_name not in _AUTH_EXEMPT:
                        _expected_token = getattr(server.app, "_local_api_token", None)
                        _caller_token = (
                            self.headers.get("X-Local-Token", "").strip()
                            or _qs_first(qs, "token", default="").strip()
                        )
                        if not _expected_token or not _caller_token or _caller_token != _expected_token:
                            body = _json_bytes({"ok": False, "error": "Local API token invalid or missing"})
                            self.send_response(401)
                            _cors_headers(self)
                            self.send_header("Content-Type", "application/json; charset=utf-8")
                            self.send_header("Content-Length", str(len(body)))
                            self.end_headers()
                            self.wfile.write(body)
                            return

                    try:
                        server.app.logger.debug(
                            "[LocalAPI] >> %s %s handler=%s",
                            method, path, getattr(handler_fn, "__name__", "?"),
                        )
                    except Exception:
                        pass
                    handler_fn(ctx)
                    try:
                        _elapsed = (_dispatch_time.monotonic() - _t0) * 1000
                        server.app.logger.debug(
                            "[LocalAPI] << %s %s handler=%s %.0fms",
                            method, path, fn_name, _elapsed,
                        )
                    except Exception:
                        pass
                except Exception as e:
                    try:
                        body = _json_bytes({"ok": False, "error": str(e)})
                        self.send_response(500)
                        _cors_headers(self)
                        self.send_header("Content-Type", "application/json; charset=utf-8")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                    except Exception:
                        pass

            def do_OPTIONS(self):
                self.send_response(204)
                _cors_headers(self)
                self.end_headers()

            def do_GET(self):
                self._dispatch("GET")

            def do_POST(self):
                self._dispatch("POST")

            def do_PATCH(self):
                self._dispatch("PATCH")

            def do_PUT(self):
                self._dispatch("PUT")

            def do_DELETE(self):
                self._dispatch("DELETE")

            def log_message(self, fmt, *args):
                try:
                    server.app.logger.debug("[LocalAPI v2] " + fmt, *args)
                except Exception:
                    pass

        self._httpd = _AppHTTPServerV2(
            (self.host, self.port), Handler, app=self.app, router=router
        )

        t = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        t.start()
        self._thread = t

        try:
            self.app.logger.info(
                "%s started on http://%s:%s", self.server_name, self.host, self.port
            )
        except Exception:
            pass

    def stop(self) -> None:
        if not self._httpd:
            return
        try:
            self._httpd.shutdown()
            self._httpd.server_close()
        except Exception:
            pass
        self._httpd = None
        self._thread = None
        # Clean up SDK pool
        with _device_sdk_lock:
            for sdk in _device_sdk_pool.values():
                try:
                    sdk.disconnect()
                except Exception:
                    pass
            _device_sdk_pool.clear()
        try:
            self.app.logger.info("%s stopped.", self.server_name)
        except Exception:
            pass


class LocalAccessApiServerV2(LocalApiServerV2):
    def __init__(self, *, app, host: str = "127.0.0.1", port: int = 8788):
        super().__init__(
            app=app,
            host=host,
            port=port,
            route_scope="access",
            server_name="LocalAccessApiServerV2",
        )


class LocalCombinedApiServerV2(LocalApiServerV2):
    def __init__(self, *, app, host: str = "127.0.0.1", port: int = 8788):
        super().__init__(
            app=app,
            host=host,
            port=port,
            route_scope="combined",
            server_name="LocalCombinedApiServerV2",
        )
















































# monclub_access_python/app/core/config.py
from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any, Dict, Optional

from app.core.utils import CONFIG_PATH, load_json, save_json


def _safe_int(v, default: int) -> int:
    try:
        return int(str(v).strip())
    except Exception:
        return default


def _safe_float(v, default: float) -> float:
    try:
        return float(str(v).strip())
    except Exception:
        return default


def _safe_str(v, default: str = "") -> str:
    if v is None:
        return default
    try:
        s = str(v)
    except Exception:
        return default
    return s


def _normalize_device_dict(d: Any) -> Dict[str, Any]:
    if d is None:
        return {}
    if isinstance(d, dict):
        return d
    try:
        return dict(d)
    except Exception:
        pass
    try:
        return dict(d.__dict__)
    except Exception:
        return {}


def _extract_device_conn(d: Dict[str, Any]) -> tuple[str, int, str]:
    ip = _safe_str(d.get("ip_address") or d.get("ipAddress") or d.get("ip") or d.get("ipAddressValue") or "").strip()

    port_raw = d.get("port_number") or d.get("portNumber") or d.get("port") or 4370
    port = _safe_int(port_raw, 4370)

    pwd = _safe_str(d.get("password") or d.get("comm_password") or d.get("commPassword") or "", "")

    return ip, port, pwd


def _normalize_data_mode(v: Any) -> str:
    if isinstance(v, bool):
        return "DEVICE" if v else "AGENT"

    s = _safe_str(v, "").strip().upper()
    if s in ("DEVICE", "DEVICE_DATA", "DEVICE_MODE", "IN_DEVICE_DATA", "1", "TRUE", "YES", "ON"):
        return "DEVICE"
    if s in ("AGENT", "AGENT_DATA", "AGENT_MODE", "IN_AGENT_DATA", "2", "FALSE", "NO", "OFF"):
        return "AGENT"
    return "DEVICE"


def _ensure_dict(v: Any) -> Dict[str, Any]:
    if isinstance(v, dict):
        return v
    return {}


def _ensure_bool(v: Any, default: bool) -> bool:
    if isinstance(v, bool):
        return v
    s = _safe_str(v, "").strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    return default


def _clamp_int(v: Any, default: int, lo: int, hi: int) -> int:
    x = _safe_int(v, default)
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x


def _clamp_float(v: Any, default: float, lo: float, hi: float) -> float:
    x = _safe_float(v, default)
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x


@dataclass
class AppConfig:
    # -------------------------
    # Selected MonClub device ID from sync_devices (main device)
    # -------------------------
    selected_device_id: Optional[int] = None

    # -------------------------
    # Data mode:
    #   - DEVICE: existing flow (controllers sync + logs pull/push)
    #   - AGENT : backend pull + local cache + realtime RTLog (this new engine)
    # -------------------------
    data_mode: str = "DEVICE"

    # PullSDK connect timeout (ms) (generic knob, not per-device unless overridden)
    device_timeout_ms: int = 5000

    # -------------------------
    # Local API (dashboard -> PC trigger)
    # -------------------------
    local_api_enabled: bool = True
    local_api_host: str = "127.0.0.1"
    local_api_port: int = 8788

    # -------------------------
    # Finger template
    # -------------------------
    template_version: int = 10
    template_encoding: str = "base64"

    # -------------------------
    # DLL paths
    # -------------------------
    plcomm_dll_path: str = r".\plcommpro.dll"
    zkfp_dll_path: str = r".\libzkfp.dll"

    # -------------------------
    # UI / logging
    # -------------------------
    log_level: str = "DEBUG"

    # -------------------------
    # MonClub API
    # -------------------------
    api_login_url: str = "http://localhost:5000/api/v1/public/access/v1/gym/login"
    api_sync_url: str = "http://localhost:5000/api/v1/manager/gym/access/v1/users/get_gym_users"
    api_create_user_fingerprint_url: str = "http://localhost:5000/api/v1/manager/userFingerprint/create"

    # -------------------------
    # Sync schedule (seconds)
    # -------------------------
    sync_interval_sec: int = 60
    max_login_age_minutes: int = 60

    # Enable controller sync engine (DEVICE mode only)
    device_sync_enabled: bool = True

    # -------------------------
    # AGENT realtime RTLog engine (AGENT mode only)
    # -------------------------
    agent_realtime_enabled: bool = True

    # Global settings for realtime engine (persisted in config.json)
    agent_global: Dict[str, Any] = field(
        default_factory=lambda: {
            "notification_rate_limit_per_minute": 30,  # toasts/min
            "notification_dedupe_window_sec": 30,
            "history_retention_days": 30,
            "event_queue_max": 5000,
            "decision_workers": 1,
            "notification_queue_max": 2000,  # Added: consistent with UI
            "history_queue_max": 5000,       # Added: consistent with UI
            "decision_ema_alpha": 0.2,       # Added: consistent with UI
            "notification_service_enabled": True,
            "history_service_enabled": True,
            "image_cache_enabled": True,
            "image_cache_timeout_sec": 2.0,
            "image_cache_max_bytes": 5242880,  # 5MB
            "image_cache_max_files": 1000,
            "show_notifications": True,
        }
    )

    # Per-device overrides keyed by deviceId string: {"12": {...}}
    agent_devices: Dict[str, Any] = field(default_factory=dict)

    # -------------------------
    # Tray behavior (Windows)
    # -------------------------
    tray_enabled: bool = True
    minimize_to_tray_on_close: bool = True
    start_minimized_to_tray: bool = False

    # Convenience: remember last email typed (NOT password)
    login_email: str = ""

    # -------------------------
    # Backward-compatible accessors
    # -------------------------
    @property
    def ip(self) -> str:
        ip, _, _ = self._resolve_active_device_conn()
        return ip

    @property
    def port(self) -> int:
        _, port, _ = self._resolve_active_device_conn()
        return port

    @property
    def password(self) -> str:
        _, _, pwd = self._resolve_active_device_conn()
        return pwd

    @property
    def timeout_ms(self) -> int:
        try:
            v = int(self.device_timeout_ms)
        except Exception:
            v = 5000
        return max(500, v)

    @property
    def is_device_mode(self) -> bool:
        return _normalize_data_mode(self.data_mode) == "DEVICE"

    # -------------------------
    # AGENT realtime helpers
    # -------------------------
    def get_agent_global(self) -> Dict[str, Any]:
        g = dict(self.agent_global or {})
        g["notification_rate_limit_per_minute"] = _clamp_int(
            g.get("notification_rate_limit_per_minute", 30), 30, 0, 600
        )
        g["notification_dedupe_window_sec"] = _clamp_int(g.get("notification_dedupe_window_sec", 30), 30, 0, 600)
        g["history_retention_days"] = _clamp_int(g.get("history_retention_days", 30), 30, 1, 3650)
        g["event_queue_max"] = _clamp_int(g.get("event_queue_max", 5000), 5000, 100, 200000)
        g["decision_workers"] = _clamp_int(g.get("decision_workers", 1), 1, 1, 16)
        g["notification_queue_max"] = _clamp_int(g.get("notification_queue_max", 2000), 2000, 100, 20000)
        g["history_queue_max"] = _clamp_int(g.get("history_queue_max", 5000), 5000, 100, 50000)
        g["decision_ema_alpha"] = _clamp_float(g.get("decision_ema_alpha", 0.2), 0.2, 0.01, 1.0)
        g["notification_service_enabled"] = _ensure_bool(g.get("notification_service_enabled", True), True)
        g["history_service_enabled"] = _ensure_bool(g.get("history_service_enabled", True), True)
        g["image_cache_enabled"] = _ensure_bool(g.get("image_cache_enabled", True), True)
        g["image_cache_timeout_sec"] = _clamp_float(g.get("image_cache_timeout_sec", 2.0), 2.0, 0.1, 60.0)
        g["image_cache_max_bytes"] = _clamp_int(g.get("image_cache_max_bytes", 5242880), 5242880, 1024, 104857600)  # 100MB max
        g["image_cache_max_files"] = _clamp_int(g.get("image_cache_max_files", 1000), 1000, 1, 10000)
        g["show_notifications"] = _ensure_bool(g.get("show_notifications", True), True)
        return g

    def get_agent_device_settings(self, device_id: int) -> Dict[str, Any]:
        did = str(int(device_id))
        base = {
            "enabled": True,
            "adaptive_sleep": True,
            "busy_sleep_min_ms": 0,
            "busy_sleep_max_ms": 50,
            "empty_sleep_min_ms": 200,
            "empty_sleep_max_ms": 500,
            "empty_backoff_factor": 1.35,
            "empty_backoff_max_ms": 2000,
            "platform": "",
            "timeout_ms": int(self.device_timeout_ms),
            "rtlog_table": "rtlog",
            "door_entry_id": 1,
            "door_close_id": None,
            "pulse_time_ms": 3000,
            "save_history": True,
            "show_notifications": True,
            "replay_block_window_seconds": 10,
            "replay_lru_size": 2000,
            "cmd_timeout_ms": 4000,
            "poll_ema_alpha": 0.2,
            "cmd_ema_alpha": 0.2,
            "totp_enabled": True,
            "totp_digits": 8,
            "totp_period_seconds": 30,
            "totp_drift_steps": 1,
            "totp_max_past_age_seconds": 32,
            "totp_max_future_skew_seconds": 3,
            "totp_prefix": "9",
            "rfid_enabled": True,
            "rfid_digits": 8,
        }

        o = _ensure_dict((self.agent_devices or {}).get(did, {}))
        out = dict(base)
        out.update(o)

        out["enabled"] = _ensure_bool(out.get("enabled"), True)
        out["adaptive_sleep"] = _ensure_bool(out.get("adaptive_sleep"), True)
        out["totp_enabled"] = _ensure_bool(out.get("totp_enabled"), True)
        out["rfid_enabled"] = _ensure_bool(out.get("rfid_enabled"), True)

        out["busy_sleep_min_ms"] = _clamp_int(out.get("busy_sleep_min_ms"), 0, 0, 500)
        out["busy_sleep_max_ms"] = _clamp_int(out.get("busy_sleep_max_ms"), 50, 0, 2000)
        if out["busy_sleep_max_ms"] < out["busy_sleep_min_ms"]:
            out["busy_sleep_max_ms"] = out["busy_sleep_min_ms"]

        out["empty_sleep_min_ms"] = _clamp_int(out.get("empty_sleep_min_ms"), 200, 0, 60000)
        out["empty_sleep_max_ms"] = _clamp_int(out.get("empty_sleep_max_ms"), 500, 0, 60000)
        if out["empty_sleep_max_ms"] < out["empty_sleep_min_ms"]:
            out["empty_sleep_max_ms"] = out["empty_sleep_min_ms"]

        out["empty_backoff_factor"] = _clamp_float(out.get("empty_backoff_factor"), 1.35, 1.0, 3.0)
        out["empty_backoff_max_ms"] = _clamp_int(out.get("empty_backoff_max_ms"), 2000, 0, 120000)

        out["timeout_ms"] = _clamp_int(out.get("timeout_ms"), int(self.device_timeout_ms), 500, 60000)

        out["rtlog_table"] = _safe_str(out.get("rtlog_table"), "rtlog").strip() or "rtlog"
        out["platform"] = _safe_str(out.get("platform"), "").strip()

        out["door_entry_id"] = _clamp_int(out.get("door_entry_id"), 1, 1, 64)
        dc = out.get("door_close_id", None)
        if dc in ("", None):
            out["door_close_id"] = None
        else:
            out["door_close_id"] = _clamp_int(dc, 1, 1, 64)

        out["pulse_time_ms"] = _clamp_int(out.get("pulse_time_ms"), 3000, 100, 60000)

        out["save_history"] = _ensure_bool(out.get("save_history"), True)
        out["show_notifications"] = _ensure_bool(out.get("show_notifications"), True)

        out["replay_block_window_seconds"] = _clamp_int(out.get("replay_block_window_seconds"), 10, 0, 3600)
        out["replay_lru_size"] = _clamp_int(out.get("replay_lru_size"), 2000, 100, 200000)

        out["cmd_timeout_ms"] = _clamp_int(out.get("cmd_timeout_ms"), 4000, 200, 60000)
        
        out["poll_ema_alpha"] = _clamp_float(out.get("poll_ema_alpha"), 0.2, 0.01, 1.0)
        out["cmd_ema_alpha"] = _clamp_float(out.get("cmd_ema_alpha"), 0.2, 0.01, 1.0)
        
        out["totp_digits"] = _clamp_int(out.get("totp_digits"), 8, 4, 10)
        out["totp_period_seconds"] = _clamp_int(out.get("totp_period_seconds"), 30, 10, 120)
        out["totp_drift_steps"] = _clamp_int(out.get("totp_drift_steps"), 1, 0, 5)
        out["totp_max_past_age_seconds"] = _clamp_int(out.get("totp_max_past_age_seconds"), 32, 1, 300)
        out["totp_max_future_skew_seconds"] = _clamp_int(out.get("totp_max_future_skew_seconds"), 3, 0, 60)
        out["totp_prefix"] = _safe_str(out.get("totp_prefix"), "9").strip()
        if len(out["totp_prefix"]) != 1 or not out["totp_prefix"].isdigit():
            out["totp_prefix"] = "9"
        
        out["rfid_digits"] = _clamp_int(out.get("rfid_digits"), 8, 4, 16)

        return out

    def set_agent_device_override(self, device_id: int, override: Dict[str, Any]) -> None:
        did = str(int(device_id))
        if self.agent_devices is None or not isinstance(self.agent_devices, dict):
            self.agent_devices = {}
        self.agent_devices[did] = dict(override or {})

    # -------------------------
    # Internal: resolve selected device connection from local cache
    # -------------------------
    def _resolve_active_device_conn(self) -> tuple[str, int, str]:
        try:
            from app.core.db import get_sync_device
        except Exception:
            get_sync_device = None  # type: ignore[assignment]

        if self.selected_device_id is not None and get_sync_device is not None:
            try:
                d = get_sync_device(int(self.selected_device_id))
                dd = _normalize_device_dict(d)
                ip, port, pwd = _extract_device_conn(dd)
                if ip:
                    return ip, port, pwd
            except Exception:
                pass

        return "192.168.0.4", 4370, ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "AppConfig":
        cfg = AppConfig()

        fields = set(AppConfig.__dataclass_fields__.keys())
        for k, v in (d or {}).items():
            if k in fields:
                try:
                    setattr(cfg, k, v)
                except Exception:
                    pass

        # selected_device_id
        try:
            if cfg.selected_device_id in ("", None):
                cfg.selected_device_id = None
            else:
                cfg.selected_device_id = int(cfg.selected_device_id)  # type: ignore[arg-type]
        except Exception:
            cfg.selected_device_id = None

        # data_mode
        try:
            cfg.data_mode = _normalize_data_mode(getattr(cfg, "data_mode", "DEVICE"))
        except Exception:
            cfg.data_mode = "DEVICE"

        # device_timeout_ms
        try:
            cfg.device_timeout_ms = int(cfg.device_timeout_ms) if cfg.device_timeout_ms else 5000
        except Exception:
            cfg.device_timeout_ms = 5000
        if cfg.device_timeout_ms < 500:
            cfg.device_timeout_ms = 500

        # local api
        cfg.local_api_enabled = bool(cfg.local_api_enabled) if cfg.local_api_enabled is not None else True
        if cfg.local_api_host is None or not str(cfg.local_api_host).strip():
            cfg.local_api_host = "127.0.0.1"
        else:
            cfg.local_api_host = str(cfg.local_api_host).strip()

        try:
            cfg.local_api_port = int(cfg.local_api_port) if cfg.local_api_port else 8788
        except Exception:
            cfg.local_api_port = 8788
        if cfg.local_api_port < 1 or cfg.local_api_port > 65535:
            cfg.local_api_port = 8788

        # template
        try:
            cfg.template_version = int(cfg.template_version) if cfg.template_version else 10
        except Exception:
            cfg.template_version = 10

        if cfg.template_encoding not in ("base64", "hex"):
            cfg.template_encoding = "base64"

        # log level
        if not cfg.log_level:
            cfg.log_level = "DEBUG"

        # api urls
        if not cfg.api_login_url:
            cfg.api_login_url = AppConfig.api_login_url
        if not cfg.api_sync_url:
            cfg.api_sync_url = AppConfig.api_sync_url
        if not cfg.api_create_user_fingerprint_url:
            cfg.api_create_user_fingerprint_url = AppConfig.api_create_user_fingerprint_url

        # sync interval
        try:
            cfg.sync_interval_sec = int(cfg.sync_interval_sec) if cfg.sync_interval_sec else 60
        except Exception:
            cfg.sync_interval_sec = 60
        if cfg.sync_interval_sec < 10:
            cfg.sync_interval_sec = 10

        # max login age
        try:
            cfg.max_login_age_minutes = int(cfg.max_login_age_minutes) if cfg.max_login_age_minutes else 60
        except Exception:
            cfg.max_login_age_minutes = 60
        if cfg.max_login_age_minutes < 1:
            cfg.max_login_age_minutes = 1

        # device_sync_enabled
        cfg.device_sync_enabled = bool(cfg.device_sync_enabled) if cfg.device_sync_enabled is not None else True

        # agent realtime
        cfg.agent_realtime_enabled = bool(cfg.agent_realtime_enabled) if cfg.agent_realtime_enabled is not None else True
        cfg.agent_global = _ensure_dict(getattr(cfg, "agent_global", {}))
        cfg.agent_devices = _ensure_dict(getattr(cfg, "agent_devices", {}))

        # tray options
        cfg.tray_enabled = bool(cfg.tray_enabled) if cfg.tray_enabled is not None else True
        cfg.minimize_to_tray_on_close = (
            bool(cfg.minimize_to_tray_on_close) if cfg.minimize_to_tray_on_close is not None else True
        )
        cfg.start_minimized_to_tray = bool(cfg.start_minimized_to_tray) if cfg.start_minimized_to_tray is not None else False

        if cfg.login_email is None:
            cfg.login_email = ""

        return cfg


def load_config() -> AppConfig:
    raw = load_json(CONFIG_PATH, default={})
    if isinstance(raw, dict):
        return AppConfig.from_dict(raw)
    return AppConfig()


def save_config(cfg: AppConfig) -> None:
    save_json(CONFIG_PATH, cfg.to_dict())
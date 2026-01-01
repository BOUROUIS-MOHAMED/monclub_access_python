from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional

from app.core.utils import CONFIG_PATH, load_json, save_json


@dataclass
class AppConfig:
    # -------------------------
    # Controller connection (ACTIVE device used by other pages)
    # -------------------------
    ip: str = "192.168.0.4"
    port: int = 4370
    timeout_ms: int = 5000
    password: str = ""  # comm password

    # -------------------------
    # NEW: Selected MonClub device ID from sync_devices
    # -------------------------
    selected_device_id: Optional[int] = None

    # -------------------------
    # Finger template
    # -------------------------
    template_version: int = 10  # 9 or 10 (10 => templatev10)
    template_encoding: str = "base64"  # base64 or hex

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
    api_login_url: str = "https://monclubwigo.tn/api/v1/public/access/v1/gym/login"
    api_sync_url: str = "https://monclubwigo.tn/api/v1/manager/gym/access/v1/users/get_gym_users"
    api_create_user_fingerprint_url: str = "https://monclubwigo.tn/api/v1/manager/userFingerprint/create"

    # Sync schedule (seconds)
    sync_interval_sec: int = 60

    # If last login is older than this => restricted
    max_login_age_minutes: int = 60

    # Convenience: remember last email typed (NOT password)
    login_email: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "AppConfig":
        cfg = AppConfig()

        # Copy known keys only
        for k, v in (d or {}).items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)

        # ---- sanitize / coerce ----
        try:
            cfg.port = int(cfg.port) if cfg.port else 4370
        except Exception:
            cfg.port = 4370

        try:
            cfg.timeout_ms = int(cfg.timeout_ms) if cfg.timeout_ms else 5000
        except Exception:
            cfg.timeout_ms = 5000

        # selected_device_id
        try:
            if cfg.selected_device_id in ("", None):
                cfg.selected_device_id = None
            else:
                cfg.selected_device_id = int(cfg.selected_device_id)  # type: ignore[arg-type]
        except Exception:
            cfg.selected_device_id = None

        try:
            cfg.template_version = int(cfg.template_version) if cfg.template_version else 10
        except Exception:
            cfg.template_version = 10

        if cfg.template_encoding not in ("base64", "hex"):
            cfg.template_encoding = "base64"

        if not cfg.log_level:
            cfg.log_level = "DEBUG"

        if not cfg.api_login_url:
            cfg.api_login_url = AppConfig.api_login_url

        if not cfg.api_sync_url:
            cfg.api_sync_url = AppConfig.api_sync_url

        if not cfg.api_create_user_fingerprint_url:
            cfg.api_create_user_fingerprint_url = AppConfig.api_create_user_fingerprint_url

        try:
            cfg.sync_interval_sec = int(cfg.sync_interval_sec) if cfg.sync_interval_sec else 60
        except Exception:
            cfg.sync_interval_sec = 60
        if cfg.sync_interval_sec < 10:
            cfg.sync_interval_sec = 10  # hard minimum safeguard

        try:
            cfg.max_login_age_minutes = int(cfg.max_login_age_minutes) if cfg.max_login_age_minutes else 60
        except Exception:
            cfg.max_login_age_minutes = 60
        if cfg.max_login_age_minutes < 1:
            cfg.max_login_age_minutes = 1

        if cfg.login_email is None:
            cfg.login_email = ""

        if cfg.ip is None:
            cfg.ip = "192.168.0.4"
        if not isinstance(cfg.ip, str):
            cfg.ip = str(cfg.ip)

        if cfg.password is None:
            cfg.password = ""
        if not isinstance(cfg.password, str):
            cfg.password = str(cfg.password)

        return cfg


def load_config() -> AppConfig:
    raw = load_json(CONFIG_PATH, default={})
    if isinstance(raw, dict):
        return AppConfig.from_dict(raw)
    return AppConfig()


def save_config(cfg: AppConfig) -> None:
    save_json(CONFIG_PATH, cfg.to_dict())

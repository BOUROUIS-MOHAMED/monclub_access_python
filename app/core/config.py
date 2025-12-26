from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict

from app.core.utils import CONFIG_PATH, load_json, save_json


@dataclass
class AppConfig:
    # Controller connection
    ip: str = "192.168.0.4"
    port: int = 4370
    timeout_ms: int = 5000
    password: str = ""  # comm password

    # Finger template
    template_version: int = 10  # 9 or 10 (10 => templatev10)
    template_encoding: str = "base64"  # base64 or hex

    # DLL paths
    plcomm_dll_path: str = r".\plcommpro.dll"
    zkfp_dll_path: str = r".\libzkfp.dll"

    # UI / logging
    log_level: str = "DEBUG"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "AppConfig":
        cfg = AppConfig()
        for k, v in d.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
        # sanitize
        cfg.port = int(cfg.port) if cfg.port else 4370
        cfg.timeout_ms = int(cfg.timeout_ms) if cfg.timeout_ms else 5000
        cfg.template_version = int(cfg.template_version) if cfg.template_version else 10
        if cfg.template_encoding not in ("base64", "hex"):
            cfg.template_encoding = "base64"
        return cfg


def load_config() -> AppConfig:
    raw = load_json(CONFIG_PATH, default={})
    if isinstance(raw, dict):
        return AppConfig.from_dict(raw)
    return AppConfig()


def save_config(cfg: AppConfig) -> None:
    save_json(CONFIG_PATH, cfg.to_dict())

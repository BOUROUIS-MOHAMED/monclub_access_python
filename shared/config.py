"""Shared config model facade used by both Access and TV boundaries in phase 1."""

from app.core.config import AppConfig, load_config, save_config

__all__ = ["AppConfig", "load_config", "save_config"]


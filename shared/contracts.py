"""Shared bootstrap/process descriptors for the desktop separation plan."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Tuple


@dataclass(frozen=True)
class DesktopComponentDescriptor:
    component_id: str
    display_name: str
    entry_module: str
    current_runtime_db_path: Path
    future_runtime_db_path: Path
    owned_capabilities: Tuple[str, ...]
    notes: Tuple[str, ...] = ()


__all__ = ["DesktopComponentDescriptor"]


"""Shared correlation helpers for future Access/TV process separation."""

from __future__ import annotations

import uuid


def new_correlation_id(prefix: str | None = None) -> str:
    base = str(uuid.uuid4())
    clean_prefix = (prefix or "").strip().lower()
    return f"{clean_prefix}-{base}" if clean_prefix else base


__all__ = ["new_correlation_id"]


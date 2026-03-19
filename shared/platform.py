"""Shared platform/runtime facade."""

from app.core.arch import is_64bit_python, platform_summary, require_32bit_python_for_32bit_dll

__all__ = ["is_64bit_python", "platform_summary", "require_32bit_python_for_32bit_dll"]


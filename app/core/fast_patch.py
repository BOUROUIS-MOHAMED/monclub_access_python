from __future__ import annotations

from typing import Any


_SECTION_TYPES = {"SETTINGS", "CREDENTIALS", "INFRASTRUCTURES", "MEMBERSHIP_TYPE"}


def patch_key(entity_type: str, entity_id: Any | None) -> str:
    normalized = str(entity_type or "").strip().upper()
    if normalized in _SECTION_TYPES:
        return f"SECTION:{normalized}"
    return f"{normalized}:{entity_id}"

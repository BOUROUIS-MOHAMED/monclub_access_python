"""Shared component identity metadata used by runtime and delivery boundaries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


DesktopComponentId = Literal["access", "tv"]


@dataclass(frozen=True)
class DesktopComponentIdentity:
    component_id: DesktopComponentId
    display_name: str
    artifact_name: str
    installer_slug: str
    main_exe_name: str
    updater_exe_name: str
    default_install_root_name: str
    legacy_install_root_names: tuple[str, ...]
    default_local_api_host: str
    default_local_api_port: int


_COMPONENTS: dict[DesktopComponentId, DesktopComponentIdentity] = {
    "access": DesktopComponentIdentity(
        component_id="access",
        display_name="MonClub Access",
        artifact_name="MonClubAccess",
        installer_slug="monclub_access",
        main_exe_name="MonClubAccess.exe",
        updater_exe_name="MonClubAccessUpdater.exe",
        default_install_root_name="MonClubAccess",
        legacy_install_root_names=("MonClubAccess", "MonClub Access"),
        default_local_api_host="127.0.0.1",
        default_local_api_port=8788,
    ),
    "tv": DesktopComponentIdentity(
        component_id="tv",
        display_name="MonClub TV",
        artifact_name="MonClubTV",
        installer_slug="monclub_tv",
        main_exe_name="MonClubTV.exe",
        updater_exe_name="MonClubTVUpdater.exe",
        default_install_root_name="MonClubTV",
        legacy_install_root_names=("MonClubTV", "MonClub TV"),
        default_local_api_host="127.0.0.1",
        default_local_api_port=8789,
    ),
}


def get_component_identity(component: DesktopComponentId | str) -> DesktopComponentIdentity:
    normalized = str(component or "access").strip().lower() or "access"
    if normalized not in _COMPONENTS:
        raise KeyError(f"Unknown desktop component identity: {component}")
    return _COMPONENTS[normalized]  # type: ignore[index]


__all__ = ["DesktopComponentIdentity", "DesktopComponentId", "get_component_identity"]

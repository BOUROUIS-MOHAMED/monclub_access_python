"""Access-owned update runtime wrapper."""

from __future__ import annotations

from shared.component_identity import get_component_identity
from shared.update_runtime import ComponentUpdateManager, UpdateStatus


class AccessUpdateManager(ComponentUpdateManager):
    def __init__(self, *, app, cfg, logger, api_factory):
        super().__init__(
            component=get_component_identity("access"),
            app=app,
            cfg=cfg,
            logger=logger,
            api_factory=api_factory,
        )


UpdateManager = AccessUpdateManager


__all__ = ["AccessUpdateManager", "UpdateManager", "UpdateStatus"]

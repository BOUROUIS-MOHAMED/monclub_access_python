"""TV-owned update runtime wrapper."""

from __future__ import annotations

from shared.component_identity import get_component_identity
from shared.update_runtime import ComponentUpdateManager, UpdateStatus


class TvUpdateManager(ComponentUpdateManager):
    def __init__(self, *, app, cfg, logger, api_factory):
        super().__init__(
            component=get_component_identity("tv"),
            app=app,
            cfg=cfg,
            logger=logger,
            api_factory=api_factory,
        )


__all__ = ["TvUpdateManager", "UpdateStatus"]

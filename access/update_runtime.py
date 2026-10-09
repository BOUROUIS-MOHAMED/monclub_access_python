"""Access-owned update runtime wrapper."""

from __future__ import annotations

import datetime as dt
import logging
from typing import Optional

from shared.component_identity import get_component_identity
from shared.update_runtime import ComponentUpdateManager, UpdateStatus

_log = logging.getLogger(__name__)


def access_pc_key() -> Optional[str]:
    """The PC identity of /access-pcs (``pcUuid``, access/pc_identity.py), or None when
    this PC is not registered (the engine then uses a stable ``install-<id>``)."""
    try:
        from access.pc_identity import PcCredentialStore

        credentials = PcCredentialStore().load()
        return credentials.pc_uuid if credentials else None
    except Exception:
        return None


def seconds_since_last_door_event() -> Optional[float]:
    """Seconds since the newest ``access_history`` row was recorded; None when unknown.

    ``created_at`` is when the PC recorded the event (now_iso(): local, "YYYY-MM-DD
    HH:MM:SS"). AGENT and ULTRA rows are written as the event happens; DEVICE-mode rows
    arrive with the attendance pull, so for those the age is the pull's, not the door's
    (the 24 h fallback may then fire up to one pull interval after a passage)."""
    try:
        from app.core.db import get_conn

        with get_conn() as conn:
            row = conn.execute("SELECT created_at FROM access_history ORDER BY id DESC LIMIT 1").fetchone()
        if not row or not row[0]:
            return float("inf")
        recorded = dt.datetime.strptime(str(row[0])[:19], "%Y-%m-%d %H:%M:%S")
        return max(0.0, (dt.datetime.now() - recorded).total_seconds())
    except Exception as exc:
        _log.debug("door idle time unknown: %s", exc)
        return None


class AccessUpdateManager(ComponentUpdateManager):
    def __init__(self, *, app, cfg, logger, api_factory, **kwargs):
        kwargs.setdefault("pc_key_provider", access_pc_key)
        kwargs.setdefault("door_idle_sec_provider", seconds_since_last_door_event)
        super().__init__(
            component=get_component_identity("access"),
            app=app,
            cfg=cfg,
            logger=logger,
            api_factory=api_factory,
            **kwargs,
        )


UpdateManager = AccessUpdateManager


__all__ = ["AccessUpdateManager", "UpdateManager", "UpdateStatus", "access_pc_key", "seconds_since_last_door_event"]

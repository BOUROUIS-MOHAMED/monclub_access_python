"""Access runtime facade over the current implementation modules."""

from app.core.device_sync import DeviceSyncEngine
from app.core.realtime_agent import AgentRealtimeEngine
from app.core.settings_reader import get_backend_global_settings
from app.core.update_manager import UpdateManager, UpdateStatus

__all__ = [
    "AgentRealtimeEngine",
    "DeviceSyncEngine",
    "UpdateManager",
    "UpdateStatus",
    "get_backend_global_settings",
]


"""In service and Keep entry history, read in one place (ULTRA merge, spec 2026-10-02 sections 3, 5).

In service off stops everything MonClub does with the device on its own: no worker (no polling),
no PC decision, no popup, no history, nothing written. Checked where a worker is started
(UltraEngine.start, ultra_worker_pool.reconcile), at each event (UltraDeviceWorker._process_event)
and before a push (device_sync). Operator actions from the local UI stay available (plan 2 OD-6).

"In service" is today's meaning, kept on purpose (plan 2 OD-1): ``active`` AND ``accessDevice``
(settings_reader.normalize_device_settings: ``enabled = active and access_device``).

Keep entry history off: the ULTRA worker writes no history row for the device
(UltraDeviceWorker._enqueue_history).
"""
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

from app.core.settings_reader import _boolish


def out_of_service_reason(device: Any) -> Optional[str]:
    """"active=False" / "accessDevice=False" for a device payload or normalized device that is out
    of service; None when it is in service. A missing key means on."""
    if not isinstance(device, Mapping):
        return None
    if not _boolish(device.get("active", True), True):
        return "active=False"
    access_device = device.get("accessDevice", device.get("access_device", True))
    if not _boolish(access_device, True):
        return "accessDevice=False"
    return None


def device_in_service(device: Any) -> bool:
    return out_of_service_reason(device) is None


def devices_in_service(devices: Any) -> List[Dict[str, Any]]:
    """The device payloads that are in service, in their order."""
    return [d for d in (devices or []) if isinstance(d, dict) and device_in_service(d)]


def in_service(settings: Any) -> bool:
    """In service, from normalized device settings (``enabled``)."""
    return bool((settings or {}).get("enabled", True))


def keeps_history(settings: Any) -> bool:
    """Keep entry history, from normalized device settings (``save_history``)."""
    return bool((settings or {}).get("save_history", True))

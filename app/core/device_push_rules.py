"""What the PC writes into a turnstile for one device, decided from the device row alone (ULTRA
merge, spec 2026-10-02 sections 3 and 8.4). Pure: no SDK, no database.

- door_numbers_and_bitmask: the doors a member is authorised on (userauthorize.AuthorizeDoorId).
- panel_param_items: the C3 door timing (Door{N}Drivertime) and repeat block (Door{N}Intertime)
  a full push writes, and that the device hash covers so a change is pushed at once.
- roster_for_card_mode: the roster the device's card choice allows (OFF / TURNSTILE / PC).

Moved out of device_sync.py (the door block of _resolve_push_context, the panel writes of
_sync_one_device), which now calls here (spec section 9).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Mapping, Set, Tuple

from app.core.settings_reader import CARDS_TURNSTILE, _boolish, _safe_int, effective_card_decision

logger = logging.getLogger("zkapp")

# userauthorize.AuthorizeDoorId bit of door N (spec section 8.4: 1 -> 1, 2 -> 2, 3 -> 4, 4 -> 8).
_DOOR_BITS = {1: 1, 2: 2, 3: 4, 4: 8}
_warned_door_values: Set[Tuple[Any, Tuple[int, ...]]] = set()


def _sorted_ints(values: Any) -> List[int]:
    """Distinct positive ints, sorted (device_sync._norm_int_list's rule)."""
    if not isinstance(values, (list, tuple)):
        return []
    return sorted({n for n in (_safe_int(v, 0) for v in values) if n > 0})


def door_numbers_and_bitmask(device: Mapping[str, Any], default_door_id: int) -> Tuple[List[int], int]:
    """(door numbers, AuthorizeDoorId bitmask) for every member pushed to this device.

    doorIds holds DOOR NUMBERS 1-4 (spec section 8.4, the screen's Door 1-4 boxes): door N is bit
    1 << (N-1). Release 1 is the first reading of them as numbers; before, the push ORed the stored
    values as bitmasks, so [1], [2] and [1, 2] open the same doors under both readings and a value of
    3 or more does not (pre-conversion report row 4, corrected by hand before release 1). A value
    outside 1-4 is ignored with one warning per device and value set; the default door id itself
    (15, the "all doors" bitmask device_sync._filter_users_for_device writes into an empty list)
    is ignored silently.

    No door number: today's meaning of an empty list, unchanged -- the bits of the door presets'
    door numbers, else the default (all four doors).
    """
    stored = _sorted_ints(device.get("doorIds") or [])
    numbers = [n for n in stored if n in _DOOR_BITS]
    ignored = tuple(n for n in stored if n not in _DOOR_BITS and n != int(default_door_id))
    if ignored:
        key = (device.get("id"), ignored)
        if key not in _warned_door_values:
            _warned_door_values.add(key)
            logger.warning(
                "[DeviceSync] device id=%s doorIds %s ignored: doors are numbers 1-4 since the ULTRA "
                "merge (spec 8.4); stored %s",
                device.get("id"), list(ignored), stored,
            )
    if numbers:
        mask = 0
        for n in numbers:
            mask |= _DOOR_BITS[n]
        return numbers, mask
    presets = device.get("doorPresets") or []
    physical_doors = sorted({
        _safe_int(p.get("doorNumber") or p.get("door_number"), 0)
        for p in presets if isinstance(p, dict)
    })
    physical_doors = [d for d in physical_doors if d > 0]
    if physical_doors:
        mask = 0
        for d in physical_doors:
            mask |= 1 << (int(d) - 1)
        return physical_doors, mask
    return [int(default_door_id)], int(default_door_id)


def panel_param_items(device: Mapping[str, Any]) -> Tuple[List[str], str]:
    """The SetDeviceParam items a full push writes to a C3 panel (moved from _sync_one_device).

    One Door{N}Drivertime=S per door preset with a positive pulse, then ONE repeat-block item:
    Door{N}Intertime=D for every preset door when anti_fraude_card is on (D = anti_fraude_duration,
    0 or absent read as 30, capped at the panel's 255), else AntiPassback=0 (inventory 1c; whether
    the panel then keeps an old Intertime is unverified, spec section 12). ``device`` is a
    DeviceSyncEngine._normalize_device dict.
    """
    presets = [p for p in (device.get("doorPresets") or []) if isinstance(p, dict)]
    drivertime: List[str] = []
    for p in presets:
        dn = _safe_int(p.get("doorNumber") or p.get("door_number"), 0)
        ps = _safe_int(p.get("pulseSeconds") or p.get("pulse_seconds"), 0)
        if dn > 0 and ps > 0:
            drivertime.append(f"Door{dn}Drivertime={ps}")
    af_card = bool(device.get("anti_fraude_card", True))
    af_duration = min(_safe_int(device.get("anti_fraude_duration"), 0) or 30, 255)
    af_params: List[str] = []
    if af_card and af_duration > 0:
        for p in presets:
            dn = _safe_int(p.get("doorNumber") or p.get("door_number"), 0)
            if dn > 0:
                af_params.append(f"Door{dn}Intertime={af_duration}")
    return drivertime, (",".join(af_params) if af_params else "AntiPassback=0")

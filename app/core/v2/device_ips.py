"""Turnstile addresses a PC must not touch (owner decision 1: readers never connect).

The engines and the device-session routes are gated by device id (lease_gate). Two desk tools
connect by IP address instead: the card scanner (``/scan/*``, ``/scanner/*``, CARD_SCAN) and the
network discovery. A scanner configured on — or a discovery probe of — a turnstile this PC does
not drive would be a connection to it, so both consult this list.
"""
from __future__ import annotations

from typing import Set

from app.core.v2 import lease_gate


def undriven_ips() -> Set[str]:
    """IP addresses of the gym's turnstiles this PC does not drive (empty without leases)."""
    if lease_gate.current().mode != lease_gate.MODE_LEASED:
        return set()
    out: Set[str] = set()
    try:
        from app.core.db import list_sync_devices_payload
        for d in list_sync_devices_payload():
            ip = str(d.get("ipAddress") or d.get("ip_address") or "").strip()
            if ip and not lease_gate.device_allowed(d.get("id")):
                out.add(ip)
    except Exception:
        return out
    return out


def ip_is_undriven_turnstile(ip: str) -> bool:
    ip = str(ip or "").strip()
    return bool(ip) and ip in undriven_ips()

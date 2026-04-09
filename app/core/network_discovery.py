from __future__ import annotations
"""
Scan local subnet for ZKTeco devices on port 4370.
Uses TCP connect probe + optional pyzk handshake to identify devices.
"""
import ipaddress
import logging
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredDevice:
    ip: str
    port: int = 4370
    serial_number: str = ""
    model: str = ""
    reachable: bool = True


def _get_local_subnet() -> Optional[str]:
    """Detect the local /24 subnet from the default route interface."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return str(net)
    except Exception:
        logger.warning("Could not detect local subnet")
        return None


def _probe_port(ip: str, port: int = 4370, timeout: float = 0.5) -> bool:
    """TCP connect probe to check if port is open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False


def _try_zk_handshake(ip: str, port: int = 4370, timeout: int = 3) -> Optional[DiscoveredDevice]:
    """Attempt pyzk connection to get device info."""
    try:
        from zk import ZK
        zk = ZK(ip, port=port, timeout=timeout)
        conn = zk.connect()
        try:
            serial = conn.get_serialnumber() or ""
            return DiscoveredDevice(ip=ip, port=port, serial_number=serial, model="ZKTeco")
        finally:
            conn.disconnect()
    except Exception as e:
        logger.debug(f"ZK handshake failed for {ip}: {e}")
        # Port was open, so it's likely a ZKTeco device even if handshake failed
        return DiscoveredDevice(ip=ip, port=port, serial_number="", model="unknown")


def scan_subnet(
    subnet: Optional[str] = None,
    port: int = 4370,
    timeout_per_host: float = 0.5,
    max_workers: int = 50,
    do_handshake: bool = True,
    cancel_event: Optional[threading.Event] = None,
) -> List[DiscoveredDevice]:
    """
    Scan a /24 subnet for ZKTeco devices.

    Args:
        subnet: CIDR notation (e.g. "192.168.1.0/24"). Auto-detected if None.
        port: Port to scan (default 4370).
        timeout_per_host: TCP connect timeout per host.
        max_workers: Concurrent scan threads.
        do_handshake: If True, attempt pyzk handshake on open ports.
        cancel_event: threading.Event to cancel scan early.

    Returns:
        List of discovered devices.
    """
    if subnet is None:
        subnet = _get_local_subnet()
        if subnet is None:
            return []

    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
    except ValueError:
        logger.error(f"Invalid subnet: {subnet}")
        return []

    # Limit to /24 max to prevent accidental wide scans
    if network.prefixlen < 24:
        logger.warning(f"Subnet {subnet} too wide, limiting to /24")
        network = ipaddress.IPv4Network(f"{network.network_address}/24", strict=False)

    hosts = [str(h) for h in network.hosts()]
    found: List[DiscoveredDevice] = []

    def probe(ip: str) -> Optional[DiscoveredDevice]:
        if cancel_event and cancel_event.is_set():
            return None
        if not _probe_port(ip, port, timeout_per_host):
            return None
        if do_handshake:
            return _try_zk_handshake(ip, port)
        return DiscoveredDevice(ip=ip, port=port)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(probe, ip): ip for ip in hosts}
        for future in as_completed(futures):
            if cancel_event and cancel_event.is_set():
                break
            try:
                result = future.result(timeout=5)
                if result is not None:
                    found.append(result)
            except Exception:
                pass

    found.sort(key=lambda d: tuple(int(p) for p in d.ip.split(".")))
    return found

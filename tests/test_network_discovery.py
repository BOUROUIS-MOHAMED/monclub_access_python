from __future__ import annotations
import threading
from unittest.mock import patch
from app.core.network_discovery import scan_subnet, _probe_port, DiscoveredDevice


def test_probe_port_closed():
    assert _probe_port("127.0.0.1", 19999, timeout=0.1) is False


def test_scan_subnet_returns_empty_when_no_open_ports():
    with patch("app.core.network_discovery._probe_port", return_value=False):
        result = scan_subnet("192.168.1.0/24", do_handshake=False)
        assert result == []


def test_scan_subnet_finds_device():
    def fake_probe(ip, port, timeout):
        return ip == "192.168.1.201"

    with patch("app.core.network_discovery._probe_port", side_effect=fake_probe):
        result = scan_subnet("192.168.1.0/24", do_handshake=False)
        assert len(result) == 1
        assert result[0].ip == "192.168.1.201"
        assert result[0].port == 4370


def test_scan_cancel():
    cancel = threading.Event()
    cancel.set()
    result = scan_subnet("192.168.1.0/24", cancel_event=cancel, do_handshake=False)
    assert isinstance(result, list)


def test_scan_clamps_wide_subnet():
    with patch("app.core.network_discovery._probe_port", return_value=False):
        # Should not raise, just clamp to /24
        result = scan_subnet("10.0.0.0/16", do_handshake=False)
        assert isinstance(result, list)

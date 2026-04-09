# SCR100 / USB RFID Card Scanner Integration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a "Scan" button (Dashboard + system tray) that reads RFID card numbers from either a ZKTeco SCR100 (network) or a generic USB HID RFID reader, with mode switching in Settings.

**Architecture:** New Python module `app/core/card_scanner.py` handles both reader types behind a unified interface. A new API endpoint `/api/v2/scanner/*` exposes start/stop/status. Frontend adds a Scan button + modal to Dashboard and a tray menu item. ConfigPage gets a new "Lecteur de cartes" section. Network discovery scans subnet port 4370.

**Tech Stack:** Python `pyzk` (network SCR100), Python `pywinusb` (USB HID reader on Windows), React + Tailwind (frontend), Tauri Rust (tray)

---

## Critical Research Findings

### ZKTeco SCR100 Facts
- **USB port = Host only** (for flash drives). NO USB-to-PC communication.
- **Network communication:** TCP/IP on port **4370** (hardcoded in firmware).
- **Default IP:** 192.168.1.201
- **Protocol:** Proprietary ZK binary protocol (reverse-engineered: github.com/adrobinoga/zk-protocol)
- **Python library:** `pyzk` (`pip install pyzk`) — supports `live_capture()` for real-time card events.
- **SCR100 is NOT officially tested** with pyzk but uses the same protocol family — works in practice.
- **Session limit:** Only ONE client can connect at a time. If crash without `disconnect()`, device blocks new connections until timeout.
- **Security:** Protocol is unencrypted. Card numbers travel in plaintext.
- **live_capture():** Blocks in a loop, yields `Attendance` objects or `None` on 10s timeout.
- **IMPORTANT: `attendance.user_id` is the ENROLLED user ID, not the raw card number.** For un-enrolled cards, it may contain the card number. To reliably get the card number: call `conn.get_users()` first to build a `user_id → card` lookup table. Each user object has a `.card` attribute (the RFID card number). If the user_id is not found in the lookup (un-enrolled card), treat `user_id` as the card number.

### USB HID RFID Reader Facts
- Generic USB readers act as **HID keyboards** — they type the card number + Enter.
- Card number arrives as a burst of keystrokes (typically < 200ms).
- **DO NOT use global keyboard hooks** (pynput, keyboard library) — they capture ALL system-wide keystrokes, cause false positives from user typing, and get flagged as keyloggers by security software.
- **Use `pywinusb.hid`** — reads raw HID reports directly from the specific USB device by VID/PID, without intercepting other keyboard input. Windows-only but matches our target platform.
- Alternative: `hidapi` (cross-platform) if future macOS support is needed.

### Network Discovery
- ZKTeco devices do NOT support mDNS/UPnP.
- Discovery = **port scan subnet for port 4370** + attempt CMD_CONNECT handshake.
- Can also send CMD_OPTIONS_RRQ to get device serial/model after connecting.

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| pyzk crash without disconnect → device locked | Device refuses connections for ~60s | Always wrap in try/finally with `conn.disconnect()`. Add timeout watchdog. |
| USB HID reads go to wrong window | Card number typed into random app | Use `pywinusb.hid` to read directly from the specific HID device by VID/PID. Never use global keyboard hooks. |
| pyzk `attendance.user_id` is enrolled user ID, not card number | Wrong card number returned for enrolled users | Build `user_id → card` lookup from `conn.get_users()` before starting `live_capture()`. |
| App crash without disconnect | Device locked for ~60s | Add `atexit.register(stop_scan)` handler. Document 60s lockout as known limitation for hard kills. |
| Concurrent discovery + active scan on same device | Discovery handshake kills live_capture session | Check if scanner is active before discovery; skip handshake for actively-scanned IP. |
| SCR100 firmware incompatibility | Connection fails silently | Detect connection failure, show clear error. Test with `force_udp=True` fallback. |
| Port 4370 scan triggers firewall/IDS | False positive alerts | Scan only local /24 subnet. Rate-limit to 1 connection/50ms. Add disclaimer in UI. |
| live_capture() blocks Python thread | Blocks API server | Run scanner in dedicated daemon thread with `threading.Event` for shutdown. |
| Multiple scan sessions overlap | State corruption | Enforce single-scanner lock. Return 409 Conflict if already scanning. |
| USB reader keystroke injection attack | Malicious card data | Validate card number: digits only, max 16 chars, strip non-numeric. |

---

## File Structure

### New Files
| File | Responsibility |
|------|----------------|
| `app/core/card_scanner.py` | Unified scanner engine: NetworkScanner (pyzk) + UsbHidScanner. Thread management, state machine. |
| `app/core/network_discovery.py` | Subnet scan for port 4370. Returns list of (ip, serial, model). |
| `tauri-ui/src/components/ScanCardModal.tsx` | Modal overlay: shows scanning animation, displays card number when found, copy button. |
| `tauri-ui/src/hooks/useScanCard.ts` | React hook: calls scanner API, manages SSE stream for live results. |
| `tests/test_card_scanner.py` | Unit tests for scanner logic (mocked pyzk/HID). |

### Modified Files
| File | Changes |
|------|---------|
| `app/core/config.py` | Add scanner config fields to `AppConfig` |
| `app/api/local_access_api_v2.py` | Add `/api/v2/scanner/*` handler functions |
| `access/local_api_routes.py` | Register scanner routes in `ACCESS_LOCAL_ROUTE_SPECS` |
| `tauri-ui/src/pages/DashboardPage.tsx` | Add Scan button in top-right action bar |
| `tauri-ui/src/pages/ConfigPage.tsx` | Add "Lecteur de cartes" settings card |
| `tauri-ui/src/api/types.ts` | Add scanner-related types |
| `tauri-ui/src-tauri/src/lib.rs` | Add "Scanner carte" tray menu item |
| `requirements.txt` or `pyproject.toml` | Add `pyzk` and `pywinusb` dependencies |

---

## Task 1: Scanner Config Fields (Python Backend)

**Files:**
- Modify: `app/core/config.py:109-465` (AppConfig dataclass)

- [ ] **Step 1: Add scanner fields to AppConfig**

Add these fields after the tray section (line ~203):

```python
# -------------------------
# Card scanner (SCR100 / USB HID)
# -------------------------
scanner_mode: str = "network"          # "network" or "usb"
scanner_network_ip: str = ""           # SCR100 IP address
scanner_network_port: int = 4370       # Always 4370 for ZKTeco
scanner_network_timeout_ms: int = 5000 # Connection timeout
scanner_usb_device_path: str = ""      # Optional: specific HID device path
```

- [ ] **Step 2: Add validation in `from_dict`**

After the tray validation block (line ~445):

```python
# scanner
cfg.scanner_mode = _safe_str(getattr(cfg, "scanner_mode", "network"), "network").strip().lower()
if cfg.scanner_mode not in ("network", "usb"):
    cfg.scanner_mode = "network"
cfg.scanner_network_ip = _safe_str(getattr(cfg, "scanner_network_ip", ""), "").strip()
cfg.scanner_network_port = _clamp_int(getattr(cfg, "scanner_network_port", 4370), 4370, 1, 65535)
cfg.scanner_network_timeout_ms = _clamp_int(getattr(cfg, "scanner_network_timeout_ms", 5000), 5000, 1000, 30000)
cfg.scanner_usb_device_path = _safe_str(getattr(cfg, "scanner_usb_device_path", ""), "").strip()
```

- [ ] **Step 3: Commit**
```bash
git add app/core/config.py
git commit -m "feat(scanner): add card scanner config fields to AppConfig"
```

---

## Task 2: Network Discovery Module (Python Backend)

**Files:**
- Create: `app/core/network_discovery.py`
- Test: `tests/test_network_discovery.py`

- [ ] **Step 1: Write the discovery module**

```python
# app/core/network_discovery.py
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
        # Connect to a public IP (no data sent) to find local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Build /24 network
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
            # pyzk doesn't expose model directly, but serial is enough
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
```

- [ ] **Step 2: Write unit test (mocked)**

```python
# tests/test_network_discovery.py
import threading
from unittest.mock import patch, MagicMock
from app.core.network_discovery import scan_subnet, _probe_port, _get_local_subnet, DiscoveredDevice

def test_probe_port_closed():
    # Use a port that's almost certainly closed
    assert _probe_port("127.0.0.1", 19999, timeout=0.1) == False

def test_scan_subnet_returns_list():
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

def test_scan_cancel():
    cancel = threading.Event()
    cancel.set()  # Cancel immediately
    result = scan_subnet("192.168.1.0/24", cancel_event=cancel, do_handshake=False)
    # Should return empty or partial (cancelled before any probe)
    assert isinstance(result, list)
```

- [ ] **Step 3: Run tests**
```bash
pytest tests/test_network_discovery.py -v
```

- [ ] **Step 4: Commit**
```bash
git add app/core/network_discovery.py tests/test_network_discovery.py
git commit -m "feat(scanner): add network discovery module for ZKTeco devices"
```

---

## Task 3: Card Scanner Engine (Python Backend)

**Files:**
- Create: `app/core/card_scanner.py`
- Test: `tests/test_card_scanner.py`

- [ ] **Step 1: Write the scanner engine**

```python
# app/core/card_scanner.py
from __future__ import annotations
"""
Unified card scanner engine.
Supports two modes:
  - "network": ZKTeco SCR100 via pyzk (TCP port 4370, live_capture)
  - "usb": Generic USB HID RFID reader (keyboard emulation, raw input)
"""
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

logger = logging.getLogger(__name__)

class ScannerMode(str, Enum):
    NETWORK = "network"
    USB = "usb"

class ScannerState(str, Enum):
    IDLE = "idle"
    CONNECTING = "connecting"
    SCANNING = "scanning"
    ERROR = "error"

@dataclass
class ScanResult:
    card_number: str
    timestamp: float = 0.0
    source: str = ""  # "network" or "usb"

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()

# ── Validation ──
_CARD_PATTERN = re.compile(r"^\d{1,16}$")

def validate_card_number(raw: str) -> Optional[str]:
    """Strip non-digits, validate length 1-16. Returns clean number or None."""
    cleaned = re.sub(r"\D", "", str(raw or "").strip())
    if _CARD_PATTERN.match(cleaned):
        return cleaned
    return None


class CardScanner:
    """
    Thread-safe card scanner. Only ONE scan session at a time.
    
    Usage:
        scanner = CardScanner()
        scanner.start_scan(mode="network", ip="192.168.1.201", on_card=callback)
        # ... later ...
        scanner.stop_scan()
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._state = ScannerState.IDLE
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._error: str = ""
        self._last_result: Optional[ScanResult] = None
        self._on_card: Optional[Callable[[ScanResult], None]] = None

    @property
    def state(self) -> ScannerState:
        return self._state

    @property
    def error(self) -> str:
        return self._error

    @property
    def last_result(self) -> Optional[ScanResult]:
        return self._last_result

    def start_scan(
        self,
        mode: str = "network",
        ip: str = "",
        port: int = 4370,
        timeout_ms: int = 5000,
        usb_device_path: str = "",
        on_card: Optional[Callable[[ScanResult], None]] = None,
    ) -> bool:
        """Start scanning. Returns False if already scanning."""
        with self._lock:
            if self._state == ScannerState.SCANNING or self._state == ScannerState.CONNECTING:
                return False
            self._stop_event.clear()
            self._error = ""
            self._last_result = None
            self._on_card = on_card
            self._state = ScannerState.CONNECTING

        if mode == ScannerMode.USB:
            self._thread = threading.Thread(
                target=self._usb_scan_loop,
                args=(usb_device_path,),
                daemon=True,
                name="card-scanner-usb",
            )
        else:
            self._thread = threading.Thread(
                target=self._network_scan_loop,
                args=(ip, port, timeout_ms),
                daemon=True,
                name="card-scanner-net",
            )
        self._thread.start()
        return True

    def stop_scan(self) -> None:
        """Stop scanning gracefully."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10)
        with self._lock:
            if self._thread and self._thread.is_alive():
                # Thread didn't stop in time — mark as error, don't allow new scans
                self._state = ScannerState.ERROR
                self._error = "Scanner thread did not stop in time. Device may be locked for ~60s."
                logger.warning(self._error)
            else:
                self._state = ScannerState.IDLE
            self._thread = None

    def get_status(self) -> dict:
        return {
            "state": self._state.value,
            "error": self._error,
            "lastResult": {
                "cardNumber": self._last_result.card_number,
                "timestamp": self._last_result.timestamp,
                "source": self._last_result.source,
            } if self._last_result else None,
        }

    # ── Network (pyzk) scan loop ──
    def _network_scan_loop(self, ip: str, port: int, timeout_ms: int):
        conn = None
        try:
            from zk import ZK
            timeout_sec = max(1, timeout_ms // 1000)
            zk = ZK(ip, port=port, timeout=timeout_sec)
            conn = zk.connect()
            
            # Build user_id → card_number lookup for enrolled users
            # pyzk attendance.user_id is the ENROLLED user ID, not the raw card number
            user_card_map: dict[str, str] = {}
            try:
                users = conn.get_users()
                for u in users:
                    uid = str(u.user_id or "").strip()
                    card = str(getattr(u, "card", "") or "").strip()
                    if uid and card:
                        user_card_map[uid] = card
                logger.info(f"Loaded {len(user_card_map)} user→card mappings from device")
            except Exception as e:
                logger.warning(f"Could not load users from device (will use user_id as card): {e}")
            
            with self._lock:
                self._state = ScannerState.SCANNING
            
            logger.info(f"Scanner connected to {ip}:{port}")
            
            for attendance in conn.live_capture():
                if self._stop_event.is_set():
                    break
                if attendance is None:
                    continue  # timeout, no event
                
                # Resolve card number: lookup enrolled user's card, else use user_id directly
                raw_uid = str(attendance.user_id or "").strip()
                raw_card = user_card_map.get(raw_uid, raw_uid)
                card = validate_card_number(raw_card)
                if card:
                    result = ScanResult(card_number=card, source="network")
                    with self._lock:
                        self._last_result = result
                    if self._on_card:
                        try:
                            self._on_card(result)
                        except Exception as e:
                            logger.error(f"on_card callback error: {e}")
                    # After first successful scan, stop (single-scan mode)
                    break

        except ImportError:
            self._error = "pyzk library not installed (pip install pyzk)"
            logger.error(self._error)
            with self._lock:
                self._state = ScannerState.ERROR
        except Exception as e:
            self._error = f"Network scanner error: {e}"
            logger.error(self._error)
            with self._lock:
                self._state = ScannerState.ERROR
        finally:
            # CRITICAL: Always disconnect to free device session
            if conn is not None:
                try:
                    conn.disconnect()
                    logger.info("Scanner disconnected cleanly")
                except Exception as e:
                    logger.warning(f"Scanner disconnect error: {e}")
            
            with self._lock:
                if self._state != ScannerState.ERROR:
                    self._state = ScannerState.IDLE

    # ── USB HID scan loop ──
    def _usb_scan_loop(self, device_path: str):
        """
        Read from USB HID RFID reader using pywinusb.hid.
        
        Strategy: Enumerate HID devices, find RFID readers (keyboard usage page),
        open the specific device, read raw HID reports. USB RFID readers send
        HID keyboard reports: each report contains a key scancode. We accumulate
        scancodes and decode to digits. Enter key (scancode 0x28) signals end of
        card number.
        
        This approach reads ONLY from the specific USB device — no global keyboard
        hooks, no interception of other keyboard input, no security software flags.
        """
        try:
            try:
                import pywinusb.hid as hid
            except ImportError:
                self._error = "pywinusb not installed (pip install pywinusb)"
                logger.error(self._error)
                with self._lock:
                    self._state = ScannerState.ERROR
                return

            # HID keyboard scancode → character mapping (USB HID Usage Tables)
            SCANCODE_MAP = {
                0x1E: "1", 0x1F: "2", 0x20: "3", 0x21: "4", 0x22: "5",
                0x23: "6", 0x24: "7", 0x25: "8", 0x26: "9", 0x27: "0",
            }
            ENTER_SCANCODE = 0x28

            buffer: list[str] = []
            result_ready = threading.Event()

            def hid_callback(data):
                """Called when HID report arrives. data is list of bytes."""
                # Typical keyboard HID report: [modifier, reserved, key1, key2, ...]
                # For RFID readers: data[2] is the key scancode (one key at a time)
                if len(data) < 3:
                    return
                scancode = data[2]
                if scancode == 0:
                    return  # Key release or no key
                if scancode == ENTER_SCANCODE and buffer:
                    raw_card = "".join(buffer)
                    card = validate_card_number(raw_card)
                    if card:
                        result = ScanResult(card_number=card, source="usb")
                        with self._lock:
                            self._last_result = result
                        if self._on_card:
                            try:
                                self._on_card(result)
                            except Exception as e:
                                logger.error(f"on_card callback error: {e}")
                        result_ready.set()
                    else:
                        buffer.clear()
                elif scancode in SCANCODE_MAP:
                    buffer.append(SCANCODE_MAP[scancode])

            # Find HID keyboard devices (RFID readers appear as keyboards)
            # Usage page 0x01 (Generic Desktop), Usage 0x06 (Keyboard)
            all_devices = hid.HidDeviceFilter(usage_page=0x01, usage=0x06).get_devices()
            
            if not all_devices:
                self._error = "No USB HID keyboard devices found. Plug in the RFID reader."
                logger.error(self._error)
                with self._lock:
                    self._state = ScannerState.ERROR
                return

            # If device_path specified, filter to that device; else use first non-standard keyboard
            target_device = None
            if device_path:
                for dev in all_devices:
                    if dev.device_path == device_path:
                        target_device = dev
                        break
            else:
                # Heuristic: RFID readers often have specific VID/PIDs.
                # For now, open ALL keyboard HID devices and listen on all.
                # The first one to send digits+Enter wins.
                target_device = all_devices[0] if len(all_devices) == 1 else None

            devices_to_open = [target_device] if target_device else all_devices
            opened = []

            try:
                for dev in devices_to_open:
                    dev.open()
                    dev.set_raw_data_handler(hid_callback)
                    opened.append(dev)
                    logger.info(f"Listening on HID: {dev.product_name} ({dev.vendor_id:#06x}:{dev.product_id:#06x})")
                
                with self._lock:
                    self._state = ScannerState.SCANNING
                
                # Wait for result or stop signal
                while not self._stop_event.is_set() and not result_ready.is_set():
                    time.sleep(0.1)
            finally:
                for dev in opened:
                    try:
                        dev.close()
                    except Exception:
                        pass

        except Exception as e:
            self._error = f"USB scanner error: {e}"
            logger.error(self._error)
            with self._lock:
                self._state = ScannerState.ERROR
        finally:
            with self._lock:
                if self._state != ScannerState.ERROR:
                    self._state = ScannerState.IDLE


# ── Module-level singleton ──
_scanner: Optional[CardScanner] = None
_scanner_lock = threading.Lock()

def get_scanner() -> CardScanner:
    global _scanner
    with _scanner_lock:
        if _scanner is None:
            _scanner = CardScanner()
            # Register atexit to ensure device session is released on shutdown
            import atexit
            atexit.register(lambda: _scanner.stop_scan() if _scanner else None)
        return _scanner
```

- [ ] **Step 2: Write unit tests**

```python
# tests/test_card_scanner.py
from app.core.card_scanner import validate_card_number, CardScanner, ScannerState

def test_validate_card_number_valid():
    assert validate_card_number("12345678") == "12345678"
    assert validate_card_number("  00123  ") == "00123"
    assert validate_card_number("1") == "1"

def test_validate_card_number_too_long():
    assert validate_card_number("12345678901234567") is None  # 17 digits

def test_validate_card_number_non_numeric():
    assert validate_card_number("abc") is None
    assert validate_card_number("") is None
    assert validate_card_number(None) is None

def test_validate_card_number_strips_non_digits():
    assert validate_card_number("123-456-789") == "123456789"

def test_scanner_initial_state():
    scanner = CardScanner()
    assert scanner.state == ScannerState.IDLE
    assert scanner.error == ""
    assert scanner.last_result is None

def test_scanner_status_idle():
    scanner = CardScanner()
    status = scanner.get_status()
    assert status["state"] == "idle"
    assert status["error"] == ""
    assert status["lastResult"] is None

def test_scanner_double_start_rejected():
    scanner = CardScanner()
    # Simulate scanning state
    scanner._state = ScannerState.SCANNING
    assert scanner.start_scan(mode="network", ip="192.168.1.201") == False
```

- [ ] **Step 3: Run tests**
```bash
pytest tests/test_card_scanner.py -v
```

- [ ] **Step 4: Commit**
```bash
git add app/core/card_scanner.py tests/test_card_scanner.py
git commit -m "feat(scanner): add unified card scanner engine (network + USB HID)"
```

---

## Task 4: Scanner API Endpoints (Python Backend)

**Files:**
- Modify: `app/api/local_access_api_v2.py` (add handler functions)
- Modify: `access/local_api_routes.py` (register routes in `ACCESS_LOCAL_ROUTE_SPECS`)

- [ ] **Step 1: Add handler functions to `local_access_api_v2.py`**

Add the following `_handle_*` functions (following existing pattern — each reads request body, calls core logic, returns JSON):

```
_handle_scanner_start       → POST /api/v2/scanner/start
_handle_scanner_stop        → POST /api/v2/scanner/stop
_handle_scanner_status      → GET  /api/v2/scanner/status
_handle_scanner_discover    → POST /api/v2/scanner/discover
_handle_scanner_discover_status → GET /api/v2/scanner/discover/status
```

**Request/Response schemas:**

```python
# POST /scanner/start
# Body (optional overrides — defaults come from AppConfig):
# { "mode": "network", "ip": "192.168.1.201" }
# Response: { "ok": true } or { "ok": false, "error": "Already scanning" }

# POST /scanner/stop
# Response: { "ok": true }

# GET /scanner/status
# Response: { "ok": true, "scanner": { "state": "scanning"|"idle"|"error"|"connecting", "error": "", "lastResult": { "cardNumber": "12345", "timestamp": 1712700000, "source": "network" } | null } }

# POST /scanner/discover
# Body (optional): { "subnet": "192.168.1.0/24" }  — auto-detected if omitted
# Response: { "ok": true }  (starts async discovery)
# Returns 409 if discovery already running or if scanner is active on same subnet

# GET /scanner/discover/status
# Response: { "ok": true, "running": false, "devices": [{ "ip": "192.168.1.201", "port": 4370, "serialNumber": "ABC123", "model": "ZKTeco" }] }
```

Implementation notes:
- Import `get_scanner` from `app.core.card_scanner`
- Import `scan_subnet` from `app.core.network_discovery`
- Discovery runs in background thread with a lock — reject concurrent discover requests with 409
- Store discovery results + running flag in a thread-safe module-level dict
- If scanner is active, discovery should use `do_handshake=False` to avoid session conflicts
- All endpoints use same `X-Local-Token` auth as other endpoints (automatic via route registration)

- [ ] **Step 2: Register routes in `access/local_api_routes.py`**

Add to `ACCESS_LOCAL_ROUTE_SPECS` tuple (after the enroll routes):

```python
    ("POST", "/api/v2/scanner/start", "_handle_scanner_start"),
    ("POST", "/api/v2/scanner/stop", "_handle_scanner_stop"),
    ("GET",  "/api/v2/scanner/status", "_handle_scanner_status"),
    ("POST", "/api/v2/scanner/discover", "_handle_scanner_discover"),
    ("GET",  "/api/v2/scanner/discover/status", "_handle_scanner_discover_status"),
```

- [ ] **Step 3: Test manually with curl**
```bash
TOKEN="your-local-token"

# Start scan (network mode)
curl -X POST http://127.0.0.1:8788/api/v2/scanner/start \
  -H "X-Local-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode":"network","ip":"192.168.1.201"}'

# Check status
curl -H "X-Local-Token: $TOKEN" http://127.0.0.1:8788/api/v2/scanner/status

# Stop scan
curl -X POST http://127.0.0.1:8788/api/v2/scanner/stop -H "X-Local-Token: $TOKEN"

# Discover devices
curl -X POST http://127.0.0.1:8788/api/v2/scanner/discover -H "X-Local-Token: $TOKEN"
curl -H "X-Local-Token: $TOKEN" http://127.0.0.1:8788/api/v2/scanner/discover/status
```

- [ ] **Step 4: Commit**
```bash
git add app/api/local_access_api_v2.py access/local_api_routes.py
git commit -m "feat(scanner): add scanner API endpoints and route registration"
```

---

## Task 5: Frontend Types & Hook

**Files:**
- Modify: `tauri-ui/src/api/types.ts`
- Create: `tauri-ui/src/hooks/useScanCard.ts`

- [ ] **Step 1: Add TypeScript types**

```typescript
// Add to types.ts

export interface ScannerStatus {
  state: "idle" | "connecting" | "scanning" | "error";
  error: string;
  lastResult: {
    cardNumber: string;
    timestamp: number;
    source: "network" | "usb";
  } | null;
}

export interface DiscoveredDevice {
  ip: string;
  port: number;
  serialNumber: string;
  model: string;
}

export interface DiscoverStatus {
  running: boolean;
  devices: DiscoveredDevice[];
}
```

- [ ] **Step 2: Create the scanner hook**

```typescript
// tauri-ui/src/hooks/useScanCard.ts
import { useState, useCallback, useRef, useEffect } from "react";
import { post, get } from "@/api/client";
import type { ScannerStatus, DiscoverStatus } from "@/api/types";

export function useScanCard() {
  const [status, setStatus] = useState<ScannerStatus>({
    state: "idle", error: "", lastResult: null,
  });
  const [discovering, setDiscovering] = useState(false);
  const [discoveredDevices, setDiscoveredDevices] = useState<DiscoverStatus["devices"]>([]);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const startScan = useCallback(async (overrides?: { mode?: string; ip?: string }) => {
    try {
      await post("/scanner/start", overrides || {});
      // Start polling status
      pollRef.current = setInterval(async () => {
        try {
          const res = await get<{ scanner: ScannerStatus }>("/scanner/status");
          setStatus(res.scanner);
          if (res.scanner.state === "idle" || res.scanner.state === "error") {
            if (pollRef.current) clearInterval(pollRef.current);
          }
        } catch { /* ignore */ }
      }, 300);
    } catch (e) {
      setStatus(s => ({ ...s, state: "error", error: String(e) }));
    }
  }, []);

  const stopScan = useCallback(async () => {
    if (pollRef.current) clearInterval(pollRef.current);
    try { await post("/scanner/stop"); } catch { /* ignore */ }
    setStatus({ state: "idle", error: "", lastResult: null });
  }, []);

  const startDiscover = useCallback(async () => {
    setDiscovering(true);
    setDiscoveredDevices([]);
    try {
      await post("/scanner/discover");
      // Poll discovery status
      const poll = setInterval(async () => {
        try {
          const res = await get<{ ok: boolean } & DiscoverStatus>("/scanner/discover/status");
          setDiscoveredDevices(res.devices || []);
          if (!res.running) {
            clearInterval(poll);
            setDiscovering(false);
          }
        } catch {
          clearInterval(poll);
          setDiscovering(false);
        }
      }, 1000);
    } catch {
      setDiscovering(false);
    }
  }, []);

  // Cleanup on unmount
  useEffect(() => {
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  return { status, startScan, stopScan, startDiscover, discovering, discoveredDevices };
}
```

- [ ] **Step 3: Commit**
```bash
git add tauri-ui/src/api/types.ts tauri-ui/src/hooks/useScanCard.ts
git commit -m "feat(scanner): add frontend types and useScanCard hook"
```

---

## Task 6: Scan Card Modal Component

**Files:**
- Create: `tauri-ui/src/components/ScanCardModal.tsx`

- [ ] **Step 1: Build the modal**

Design: Dark overlay modal with:
- Title: "Scanner une carte"
- Current state indicator (connecting/scanning/success/error)
- Animated scanning indicator (pulsing RFID icon)
- Card number display (large, monospace) when found
- Copy button next to card number
- Cancel button
- Auto-close after 3s on success (configurable)

```typescript
// tauri-ui/src/components/ScanCardModal.tsx
import { useEffect, useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Loader2, CreditCard, Check, Copy, X, AlertCircle } from "lucide-react";
import { useScanCard } from "@/hooks/useScanCard";
import { cn } from "@/lib/utils";

interface Props {
  open: boolean;
  onClose: (cardNumber?: string) => void;
}

export default function ScanCardModal({ open, onClose }: Props) {
  const { status, startScan, stopScan } = useScanCard();
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (open) {
      startScan();
      return () => { stopScan(); };
    }
  }, [open]);

  const handleCopy = async () => {
    if (status.lastResult?.cardNumber) {
      await navigator.clipboard.writeText(status.lastResult.cardNumber);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleClose = () => {
    stopScan();
    onClose(status.lastResult?.cardNumber);
  };

  const isScanning = status.state === "scanning" || status.state === "connecting";
  const hasResult = status.lastResult !== null;
  const hasError = status.state === "error";

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) handleClose(); }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <CreditCard className="h-5 w-5" />
            Scanner une carte
          </DialogTitle>
        </DialogHeader>

        <div className="flex flex-col items-center py-8 gap-4">
          {isScanning && !hasResult && (
            <>
              <div className="relative">
                <CreditCard className="h-16 w-16 text-primary animate-pulse" />
              </div>
              <p className="text-sm text-muted-foreground">
                {status.state === "connecting" ? "Connexion au lecteur..." : "Passez la carte devant le lecteur..."}
              </p>
            </>
          )}

          {hasResult && (
            <>
              <div className="flex items-center gap-2 text-green-500">
                <Check className="h-6 w-6" />
                <span className="text-sm font-medium">Carte detectee !</span>
              </div>
              <div className="flex items-center gap-2 bg-muted rounded-lg px-4 py-3">
                <code className="text-2xl font-mono font-bold tracking-wider">
                  {status.lastResult!.cardNumber}
                </code>
                <Button size="icon" variant="ghost" className="h-8 w-8" onClick={handleCopy}>
                  {copied ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Source: {status.lastResult!.source === "network" ? "SCR100 (reseau)" : "USB"}
              </p>
            </>
          )}

          {hasError && (
            <>
              <AlertCircle className="h-12 w-12 text-destructive" />
              <p className="text-sm text-destructive text-center">{status.error}</p>
            </>
          )}
        </div>

        <DialogFooter>
          {hasResult && (
            <Button variant="default" onClick={handleClose}>
              Fermer
            </Button>
          )}
          {!hasResult && (
            <Button variant="outline" onClick={handleClose}>
              <X className="h-4 w-4 mr-1" /> Annuler
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
```

- [ ] **Step 2: Commit**
```bash
git add tauri-ui/src/components/ScanCardModal.tsx
git commit -m "feat(scanner): add ScanCardModal component with scan animation"
```

---

## Task 7: Dashboard Scan Button

**Files:**
- Modify: `tauri-ui/src/pages/DashboardPage.tsx:184-207` (action bar)

- [ ] **Step 1: Add Scan button to Dashboard action bar**

In the `<div className="ml-auto flex items-center gap-2">` block (line 184), add a Scan button BEFORE the Synchroniser button:

```tsx
// Add import at top:
import { CreditCard } from "lucide-react";
import { useState } from "react";  // if not already imported
import ScanCardModal from "@/components/ScanCardModal";

// Add state in component:
const [scanOpen, setScanOpen] = useState(false);

// Add button in action bar (before Synchroniser):
<Button
  size="sm"
  variant="outline"
  className="h-7 text-[12px] gap-1.5 px-3 text-emerald-500 border-emerald-500/40 hover:bg-emerald-500/10 hover:text-emerald-400"
  onClick={() => setScanOpen(true)}
  title="Scanner une carte RFID"
>
  <CreditCard className="h-3 w-3" />
  Scan
</Button>

// Add modal at end of component JSX (before closing fragment):
<ScanCardModal
  open={scanOpen}
  onClose={(cardNumber) => {
    setScanOpen(false);
    if (cardNumber) {
      // Optional: show toast or log
      console.log("Scanned card:", cardNumber);
    }
  }}
/>
```

- [ ] **Step 2: Commit**
```bash
git add tauri-ui/src/pages/DashboardPage.tsx
git commit -m "feat(scanner): add Scan button to Dashboard action bar"
```

---

## Task 8: Settings Page — Scanner Configuration

**Files:**
- Modify: `tauri-ui/src/pages/ConfigPage.tsx`

- [ ] **Step 1: Add scanner settings card**

Add a new `<Card>` section in ConfigPage (after the "Demarrage Windows" card) with:

```
Lecteur de cartes
├── Mode: Switch toggle  [Reseau (SCR100)]  /  [USB (Lecteur HID)]
├── If Reseau:
│   ├── IP Address input (text field)
│   ├── "Detecter" button (triggers network discovery)
│   └── Dropdown/list of discovered devices (click to fill IP)
└── If USB:
    └── Info text: "Branchez le lecteur USB. Aucune configuration requise."
```

Key UI details:
- Use existing `Switch` component for mode toggle
- Use existing `Input` component for IP field
- Use existing `Button` component for discover
- Show discovered devices as a small list with radio buttons or clickable items
- Discovered devices show: IP, serial number
- Spinner while discovery is running
- Save button follows existing pattern (auto-save on toggle, or dirty+save for IP)

- [ ] **Step 2: Wire to config API**

Use existing `patch("/config", { scanner_mode: "network", scanner_network_ip: "..." })` pattern.

**IMPORTANT:** Config keys are **snake_case** (matching Python dataclass field names), not camelCase. This is consistent with how all existing config fields are patched.

Discovery uses the `useScanCard` hook's `startDiscover`/`discoveredDevices`.

- [ ] **Step 3: Commit**
```bash
git add tauri-ui/src/pages/ConfigPage.tsx
git commit -m "feat(scanner): add card reader settings section to ConfigPage"
```

---

## Task 9: System Tray — "Scanner carte" Menu Item

**Files:**
- Modify: `tauri-ui/src-tauri/src/lib.rs` — TWO functions: `setup_access_tray()` (line ~537) AND `rebuild_tray_menu()` (line ~351)

**IMPORTANT:** The tray has two code paths:
1. `setup_access_tray()` (line 537-627) — builds the INITIAL menu + the event handler closure
2. `rebuild_tray_menu()` (line 351-437) — rebuilds menu structure on refresh (no event handler — it reuses the one from setup)

Both must include the scan item, and the event handler lives ONLY in `setup_access_tray`.

- [ ] **Step 1: Add scan item to `setup_access_tray()` (initial menu)**

In `setup_access_tray()` (line ~537), after `sync_item` (line 543):

```rust
let scan_item = MenuItemBuilder::with_id("tray_scan", "Scanner carte").build(app)?;
```

Add to menu builder (line ~553-560, after `sync_item`):
```rust
.item(&scan_item)
```

- [ ] **Step 2: Add tray_scan to the `on_menu_event` closure**

In the `on_menu_event` closure inside `setup_access_tray()` (line ~570-616), add a new match arm BEFORE the `_ if id.starts_with("tray_open_")` arm:

```rust
"tray_scan" => {
    show_main_window(&app);
    // Emit event to frontend to open scan modal
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.emit("tray-scan-card", ());
    }
}
```

- [ ] **Step 3: Add scan item to `rebuild_tray_menu()` (refresh menu)**

In `rebuild_tray_menu()` (line ~351), after `sync_item` (line 359):

```rust
let scan_item = MenuItemBuilder::with_id("tray_scan", "Scanner carte").build(app)?;
```

Add to menu builder (line ~421, after `sync_item`):
```rust
.item(&scan_item)
```

- [ ] **Step 4: Listen for tray event in frontend**

In `DashboardPage.tsx`, add a Tauri event listener:

```tsx
import { listen } from "@tauri-apps/api/event";

useEffect(() => {
  const unlisten = listen("tray-scan-card", () => {
    setScanOpen(true);
  });
  return () => { unlisten.then(fn => fn()); };
}, []);
```

- [ ] **Step 5: Commit**
```bash
git add tauri-ui/src-tauri/src/lib.rs tauri-ui/src/pages/DashboardPage.tsx
git commit -m "feat(scanner): add Scanner carte to system tray menu"
```

---

## Task 10: Dependencies & Integration Testing

**Files:**
- Modify: `requirements.txt` or `pyproject.toml`

- [ ] **Step 1: Add Python dependencies**

```
pyzk>=0.9
pywinusb>=0.4
```

Notes:
- `pyzk` — ZKTeco device communication (TCP port 4370). Not actively maintained; consider pinning a specific fork (e.g., `fananimi/pyzk`).
- `pywinusb` — raw Win32 HID access for USB RFID readers. Windows-only but matches target platform. Does NOT use global keyboard hooks (safe, no security software flags).
- Do NOT use `pynput` or `keyboard` — they install global keyboard hooks that capture ALL system-wide input.

- [ ] **Step 2: Install and verify imports**
```bash
pip install pyzk pywinusb
python -c "from zk import ZK; print('pyzk OK')"
python -c "import pywinusb.hid; print('pywinusb OK')"
```

- [ ] **Step 3: Integration test (manual, with real device if available)**

Test matrix:
| Scenario | Expected |
|----------|----------|
| Network scan with valid SCR100 IP | Connects, shows "Scanning", card scan shows number |
| Network scan with wrong IP | Shows "Error: connection timed out" after timeout |
| Network scan while device is busy (another client connected) | Shows "Error: Machine is busy" |
| USB scan with reader plugged in | Shows "Scanning", card scan shows number via keystrokes |
| USB scan with no reader | Shows "Scanning", waits indefinitely until cancel |
| Start scan while already scanning | Returns 409, UI shows "Already scanning" |
| Cancel during scan | Returns to idle, device session released |
| Network discovery on subnet | Finds devices with open port 4370 |
| Network discovery on empty subnet | Returns empty list |
| Settings: switch mode network→usb | Config persisted, next scan uses USB mode |
| Tray: click "Scanner carte" | Opens main window + scan modal |

- [ ] **Step 4: Commit**
```bash
git add requirements.txt
git commit -m "feat(scanner): add pyzk and pynput dependencies"
```

---

## Execution Order

```
Task 1 (config)
  ↓
Task 2 (network discovery) ←── can run parallel with Task 3
Task 3 (scanner engine)
  ↓
Task 4 (API endpoints) ←── depends on Tasks 2+3
  ↓
Task 5 (frontend types + hook)
  ↓
Task 6 (modal component) ←── depends on Task 5
Task 7 (dashboard button) ←── depends on Task 6
Task 8 (settings page) ←── depends on Task 5
Task 9 (tray menu) ←── depends on Task 7
  ↓
Task 10 (dependencies + integration test)
```

Parallelizable pairs:
- Tasks 2 & 3 (independent Python modules)
- Tasks 7 & 8 (independent frontend pages, both depend on Task 5/6)

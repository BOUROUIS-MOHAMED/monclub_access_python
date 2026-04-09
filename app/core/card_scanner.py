from __future__ import annotations
"""
Unified card scanner engine.
Supports two modes:
  - "network": ZKTeco SCR100 via pyzk (TCP port 4370, live_capture)
  - "usb": Generic USB HID RFID reader (pywinusb, direct HID report reading)
"""
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional

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

    def __post_init__(self) -> None:
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

    def __init__(self) -> None:
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
            if self._state in (ScannerState.SCANNING, ScannerState.CONNECTING):
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
                # Thread didn't stop in time
                self._state = ScannerState.ERROR
                self._error = "Scanner thread did not stop in time. Device may be locked for ~60s."
                logger.warning(self._error)
            else:
                self._state = ScannerState.IDLE
            self._thread = None

    def get_status(self) -> Dict:
        with self._lock:
            state = self._state
            error = self._error
            last = self._last_result
        return {
            "state": state.value,
            "error": error,
            "lastResult": {
                "cardNumber": last.card_number,
                "timestamp": last.timestamp,
                "source": last.source,
            } if last else None,
        }

    # ── Network (pyzk) scan loop ──
    def _network_scan_loop(self, ip: str, port: int, timeout_ms: int) -> None:
        conn = None
        try:
            from zk import ZK
            timeout_sec = max(1, timeout_ms // 1000)
            zk = ZK(ip, port=port, timeout=timeout_sec)
            conn = zk.connect()

            # Build user_id → card_number lookup for enrolled users.
            # pyzk attendance.user_id is the ENROLLED user ID, not the raw card number.
            user_card_map: Dict[str, str] = {}
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
                    # Single-scan mode: stop after first successful scan
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
    def _usb_scan_loop(self, device_path: str) -> None:
        """
        Read from USB HID RFID reader using pywinusb.hid.

        Reads raw HID reports directly from the specific USB device —
        no global keyboard hooks, no interception of other keyboard input.

        USB HID keyboard report format:
          byte 0: modifier keys
          byte 1: reserved
          byte 2: key scancode (USB HID Usage Tables)
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

            # HID keyboard scancode → digit character (USB HID Usage Tables)
            SCANCODE_MAP: Dict[int, str] = {
                0x1E: "1", 0x1F: "2", 0x20: "3", 0x21: "4", 0x22: "5",
                0x23: "6", 0x24: "7", 0x25: "8", 0x26: "9", 0x27: "0",
            }
            ENTER_SCANCODE = 0x28

            buffer: List[str] = []
            result_ready = threading.Event()

            def hid_callback(data: List[int]) -> None:
                """Called when HID report arrives. data is list of bytes."""
                if len(data) < 3:
                    return
                scancode = data[2]
                if scancode == 0:
                    return  # Key release or no key
                if scancode == ENTER_SCANCODE and buffer:
                    raw_card = "".join(buffer)
                    card = validate_card_number(raw_card)
                    buffer.clear()
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
                elif scancode in SCANCODE_MAP:
                    buffer.append(SCANCODE_MAP[scancode])

            # Find HID keyboard devices (RFID readers appear as keyboards)
            all_devices = hid.HidDeviceFilter(usage_page=0x01, usage=0x06).get_devices()

            if not all_devices:
                self._error = "No USB HID keyboard devices found. Plug in the RFID reader."
                logger.error(self._error)
                with self._lock:
                    self._state = ScannerState.ERROR
                return

            # Filter by device path if specified, else use all HID keyboard devices
            if device_path:
                devices_to_open = [d for d in all_devices if d.device_path == device_path]
                if not devices_to_open:
                    self._error = f"USB device not found at path: {device_path}"
                    logger.error(self._error)
                    with self._lock:
                        self._state = ScannerState.ERROR
                    return
            else:
                devices_to_open = all_devices

            opened: List = []
            try:
                for dev in devices_to_open:
                    dev.open()
                    dev.set_raw_data_handler(hid_callback)
                    opened.append(dev)
                    logger.info(
                        f"Listening on HID: {dev.product_name} "
                        f"({dev.vendor_id:#06x}:{dev.product_id:#06x})"
                    )

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

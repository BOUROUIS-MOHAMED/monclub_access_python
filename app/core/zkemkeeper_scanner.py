from __future__ import annotations

import ctypes
import importlib
import logging
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class ZkemkeeperError(RuntimeError):
    pass


def initialize_com_apartment():
    try:
        ole32 = ctypes.windll.ole32
    except Exception as e:
        raise ZkemkeeperError("COM initialization requires Windows ole32.dll") from e

    ole32.CoInitialize.argtypes = [ctypes.c_void_p]
    ole32.CoInitialize.restype = ctypes.c_long
    ole32.CoUninitialize.argtypes = []
    ole32.CoUninitialize.restype = None

    hr = int(ole32.CoInitialize(None))
    if hr in (0, 1):
        def _cleanup() -> None:
            ole32.CoUninitialize()
        return _cleanup
    if hr == -2147417850:
        return lambda: None

    raise ZkemkeeperError(f"COM initialization failed (HRESULT=0x{hr & 0xFFFFFFFF:08X})")


def create_zkemkeeper_com_object() -> tuple[object, str]:
    try:
        win32_client = importlib.import_module("win32com.client")
        return win32_client.Dispatch("zkemkeeper.CZKEM"), "pywin32"
    except ModuleNotFoundError:
        pass

    try:
        comtypes_client = importlib.import_module("comtypes.client")
        return comtypes_client.CreateObject("zkemkeeper.CZKEM", dynamic=True), "comtypes"
    except ModuleNotFoundError as e:
        raise ZkemkeeperError("ZKEMKeeper COM access requires pywin32 or comtypes") from e


def _extract_card(result) -> tuple[bool, str]:
    """Unpack a zkemkeeper COM return value into (ok, card_string).

    pywin32 Dispatch returns [out] params as a tuple: (BOOL, BSTR).
    comtypes dynamic may return just the BSTR directly.
    """
    if isinstance(result, tuple) and len(result) >= 2:
        return bool(result[0]), str(result[1] or "").strip()
    if isinstance(result, str):
        return bool(result), result.strip()
    if isinstance(result, bool):
        return result, ""
    if isinstance(result, int):
        return bool(result), ""
    return False, ""


def _card_is_real(card: str) -> bool:
    """Return True if card looks like a genuine RFID UID.

    The device returns "0" (or all-zeros) when its buffer is empty/idle.
    Real card UIDs are always at least 2 digits and non-zero.
    """
    if not card:
        return False
    no_zeros = card.lstrip("0")
    return len(no_zeros) >= 1   # at least one non-zero digit


def _read_hid(com) -> str:
    """Call GetHIDEventCardNumAsStr; return card string or '' on failure."""
    try:
        ok, card = _extract_card(com.GetHIDEventCardNumAsStr())
        if ok and _card_is_real(card):
            return card
    except Exception:
        pass
    return ""


def _read_str(com) -> str:
    """Call GetStrCardNumber; return card string or '' on failure."""
    try:
        ok, card = _extract_card(com.GetStrCardNumber())
        if ok and _card_is_real(card):
            return card
    except Exception:
        pass
    return ""


@dataclass
class ZkemkeeperScanner:
    _com: object | None = None

    def _load_com(self) -> object:
        com, _backend = create_zkemkeeper_com_object()
        return com

    def connect(self, *, ip: str, port: int, timeout_ms: int) -> None:
        if not ip:
            raise ZkemkeeperError("SCR100 IP address is required")
        self._com = self._load_com()
        ok = bool(self._com.Connect_Net(ip, int(port)))
        if not ok:
            raise ZkemkeeperError(f"SCR100 connect failed ({ip}:{port})")

        # Flush real-time log so we only see NEW card swipes (mirrors PS1 GetRTLog call).
        try:
            self._com.GetRTLog(1)
        except Exception:
            pass
        _ = timeout_ms

    def disconnect(self) -> None:
        if self._com is None:
            return
        try:
            self._com.Disconnect()
        except Exception:
            pass
        self._com = None

    def read_card_once(self, *, poll_sec: float = 20.0) -> str:
        """Block until a valid RFID card is detected (or timeout).

        Strategy:
          1. Snapshot the current GetStrCardNumber value immediately after connect.
             On idle devices this is "0" or the last-read card.
          2. Poll every 60 ms (same rate as the working PS1 script):
             a. Try GetHIDEventCardNumAsStr — fires when the device has a swipe event.
             b. Try GetStrCardNumber — fires when a card is physically on the reader.
                Accept only if the value CHANGED from the snapshot (edge detection).
          3. Return the first non-idle, non-zero card seen.
        """
        if self._com is None:
            raise ZkemkeeperError("Not connected")

        # Snapshot idle value for edge detection on GetStrCardNumber.
        idle_str = _read_str(self._com) or ""
        logger.debug("[zkemkeeper] idle GetStrCardNumber=%r", idle_str)

        deadline = time.time() + poll_sec
        poll_no  = 0

        while time.time() < deadline:
            # ── GetHIDEventCardNumAsStr (swipe-event based) ──
            hid_card = _read_hid(self._com)
            if hid_card:
                logger.info("[zkemkeeper] HID card: %r (poll #%d)", hid_card, poll_no)
                return hid_card

            # ── GetStrCardNumber (direct read, edge-detected) ──
            str_card = _read_str(self._com)
            if str_card and str_card != idle_str:
                logger.info("[zkemkeeper] STR card: %r (poll #%d)", str_card, poll_no)
                return str_card

            if poll_no % 50 == 0:   # log every ~3 s
                logger.debug(
                    "[zkemkeeper] waiting… poll=%d hid=%r str=%r",
                    poll_no, hid_card, str_card,
                )

            poll_no += 1
            time.sleep(0.06)   # 60 ms — same as PS1

        raise ZkemkeeperError("No card detected before timeout")

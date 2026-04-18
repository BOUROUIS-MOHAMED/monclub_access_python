from __future__ import annotations
"""
Direct Python port of read-card-from-scr100-zkem.ps1 (the working PS1 script).
Uses pythoncom for proper COM init (not raw ole32) so pywin32 state stays consistent.
Pure polling — no COM events, no message pump — exactly like the PS1 script.
"""

import importlib
import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class ZkemkeeperError(RuntimeError):
    pass


def initialize_com_apartment():
    """Initialize STA COM apartment for the current (worker) thread.

    Prefers pythoncom.CoInitialize() so pywin32's internal bookkeeping stays in
    sync with the underlying Windows COM state. Falls back to raw ole32 only if
    pythoncom is not available.
    """
    try:
        pythoncom = importlib.import_module("pythoncom")
    except ImportError:
        pythoncom = None

    if pythoncom is not None:
        try:
            pythoncom.CoInitialize()
        except Exception as e:
            # COM may already be initialized on this thread — not fatal.
            logger.debug("[zkemkeeper] pythoncom.CoInitialize: %s", e)

        def _cleanup() -> None:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass
        return _cleanup

    # Last-resort raw Win32 fallback (no pywin32 installed).
    import ctypes
    ole32 = ctypes.windll.ole32
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
    """Unpack a zkemkeeper COM return value → (ok, card_string).

    pywin32 Dispatch returns a tuple (hresult_as_bool, out_str) when the IDispatch
    method has an [out] parameter. This helper is defensive against other shapes.
    """
    if isinstance(result, tuple) and len(result) >= 2:
        return bool(result[0]), str(result[1] if result[1] is not None else "").strip()
    if isinstance(result, bool):
        return result, ""
    if isinstance(result, int):
        return bool(result), str(result) if result else ""
    if isinstance(result, str):
        return bool(result), result.strip()
    return False, ""


def _card_is_real(card: str) -> bool:
    """True only if `card` is a real RFID UID (not the device's idle "0" sentinel)."""
    if not card:
        return False
    return bool(card.lstrip("0"))


@dataclass
class ZkemkeeperScanner:
    _com: object | None = None
    _backend: str = field(default="", repr=False)

    def connect(self, *, ip: str, port: int, timeout_ms: int) -> None:
        if not ip:
            raise ZkemkeeperError("SCR100 IP address is required")
        self._com, self._backend = create_zkemkeeper_com_object()
        ok = bool(self._com.Connect_Net(ip, int(port)))
        if not ok:
            raise ZkemkeeperError(f"SCR100 connect failed ({ip}:{port})")
        logger.info("[zkemkeeper] connected via %s to %s:%d", self._backend, ip, port)

        # PS1 does exactly these two (best-effort, errors ignored):
        try:
            self._com.RegEvent(1, 0xFFFFFFFF)
        except Exception as e:
            logger.debug("[zkemkeeper] RegEvent failed: %s", e)
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
        """Direct Python port of the PS1 polling loop.

        PS1 works with pure polling: no events, no message pump, no GetRTLog in
        the loop. The COM server maintains its own TCP reader thread and fills
        the internal card buffers; the client just reads them every 60 ms with
        edge-detection on the idle sentinel.
        """
        if self._com is None:
            raise ZkemkeeperError("Not connected")

        logger.info("[zkemkeeper] polling for card (up to %.1fs)...", poll_sec)

        deadline = time.time() + poll_sec
        last_card: str | None = None
        seen_empty = True       # arm first real read
        poll_no = 0
        log_every = max(1, int(3.0 / 0.06))

        while time.time() < deadline:
            card = ""
            source = ""

            # 1) GetHIDEventCardNumAsStr (primary on most firmwares)
            try:
                result = self._com.GetHIDEventCardNumAsStr()
                ok, val = _extract_card(result)
                if ok and val and _card_is_real(val):
                    card, source = val, "HID"
            except Exception as e:
                logger.debug("[zkemkeeper] GetHIDEventCardNumAsStr: %s", e)

            # 2) Fall back to GetStrCardNumber (other firmwares)
            if not card:
                try:
                    result = self._com.GetStrCardNumber()
                    ok, val = _extract_card(result)
                    if ok and val and _card_is_real(val):
                        card, source = val, "STR"
                except Exception as e:
                    logger.debug("[zkemkeeper] GetStrCardNumber: %s", e)

            if card:
                # Edge detection like PS1: accept if NEW card or after empty tick
                if card != last_card or seen_empty:
                    logger.info("[zkemkeeper] CARD via %s: %r (poll #%d)", source, card, poll_no)
                    return card
                # Same card, no empty in between — keep polling
                seen_empty = False
            else:
                seen_empty = True

            if poll_no % log_every == 0:
                logger.debug("[zkemkeeper] poll #%d last=%r empty=%s", poll_no, last_card, seen_empty)

            poll_no += 1
            time.sleep(0.06)   # same interval as PS1 $PollMs = 60

        raise ZkemkeeperError("No card detected before timeout")

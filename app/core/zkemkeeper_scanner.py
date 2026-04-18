from __future__ import annotations

import ctypes
import ctypes.wintypes
import importlib
import logging
import threading
import time
from dataclasses import dataclass, field

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
    """Unpack a zkemkeeper COM return value → (ok, card_string)."""
    if isinstance(result, tuple) and len(result) >= 2:
        return bool(result[0]), str(result[1] if result[1] is not None else "").strip()
    if isinstance(result, str):
        return bool(result), result.strip()
    if isinstance(result, bool):
        return result, ""
    if isinstance(result, int):
        return bool(result), str(result) if result else ""
    return False, ""


def _card_is_real(card: str) -> bool:
    """True if card is a real RFID UID (not the device's idle "0" sentinel)."""
    if not card:
        return False
    return bool(card.lstrip("0"))


def _pump_com_messages() -> None:
    try:
        pythoncom = importlib.import_module("pythoncom")
        pythoncom.PumpWaitingMessages()
        return
    except Exception:
        pass
    try:
        msg = ctypes.wintypes.MSG()
        while ctypes.windll.user32.PeekMessageW(
            ctypes.byref(msg), None, 0, 0, 1
        ):
            ctypes.windll.user32.TranslateMessage(ctypes.byref(msg))
            ctypes.windll.user32.DispatchMessageW(ctypes.byref(msg))
    except Exception:
        pass


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

        try:
            self._com.RegEvent(1, 0xFFFFFFFF)
            logger.info("[zkemkeeper] RegEvent registered successfully")
        except Exception as e:
            logger.warning("[zkemkeeper] RegEvent failed (events may not work): %s", e)

        # Flush any stale events so we only react to NEW card swipes.
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
        """Block until a real RFID card is detected (or timeout).

        Tries pywin32 COM event sinks first (same mechanism PowerShell uses).
        Falls back to polling with message pump if WithEvents is unavailable.
        """
        if self._com is None:
            raise ZkemkeeperError("Not connected")

        if self._backend == "pywin32":
            try:
                return self._read_with_events(poll_sec)
            except ZkemkeeperError:
                raise
            except Exception as e:
                logger.warning("[zkemkeeper] WithEvents approach failed (%s), falling back to polling", e)

        return self._read_with_polling(poll_sec)

    def _read_with_events(self, poll_sec: float) -> str:
        """Use pywin32 WithEvents to receive OnHIDNum / OnAttTransaction COM events.

        This is the correct approach — same mechanism as PowerShell's implicit COM
        event delivery.  Requires an STA thread with a message pump.
        """
        win32com = importlib.import_module("win32com.client")
        pythoncom = importlib.import_module("pythoncom")

        card_found: list[str] = []
        got_card = threading.Event()
        com_obj = self._com

        class _Sink:
            def OnHIDNum(self, machine_no, card):
                c = str(card).strip() if card is not None else ""
                logger.info("[zkemkeeper] OnHIDNum event: machine=%r card=%r", machine_no, c)
                if _card_is_real(c) and not got_card.is_set():
                    card_found.append(c)
                    got_card.set()

            def OnAttTransaction(self, card_str, att_state, verify,
                                  year, month, day, hour, minute, second, work_code):
                c = str(card_str or "").strip()
                logger.info("[zkemkeeper] OnAttTransaction event: card=%r", c)
                if _card_is_real(c) and not got_card.is_set():
                    card_found.append(c)
                    got_card.set()

            def OnNewCard(self, enroll_no, is_registered, machine_no):
                logger.info("[zkemkeeper] OnNewCard event: enroll=%r machine=%r", enroll_no, machine_no)

            def OnConnected(self, machine_no):
                logger.debug("[zkemkeeper] OnConnected: %r", machine_no)

            def OnDisConnected(self, machine_no):
                logger.warning("[zkemkeeper] OnDisConnected: %r", machine_no)

        _connection = win32com.WithEvents(com_obj, _Sink)
        logger.info("[zkemkeeper] COM event sink registered, waiting up to %.0fs for card...", poll_sec)

        deadline = time.time() + poll_sec
        poll_no = 0
        while time.time() < deadline and not got_card.is_set():
            # Deliver any pending COM events to our sink
            pythoncom.PumpWaitingMessages()
            # Ask device to push pending events over TCP
            try:
                com_obj.GetRTLog(1)
            except Exception:
                pass
            if poll_no % 40 == 0:
                logger.debug("[zkemkeeper] still waiting (%.1fs left)", deadline - time.time())
            poll_no += 1
            time.sleep(0.05)

        if card_found:
            logger.info("[zkemkeeper] card detected via COM event: %r", card_found[0])
            return card_found[0]

        raise ZkemkeeperError("No card detected before timeout")

    def _read_with_polling(self, poll_sec: float) -> str:
        """Fallback polling: pump COM messages + GetRTLog + check card buffers."""
        try:
            _, idle_str = _extract_card(self._com.GetStrCardNumber())
        except Exception:
            idle_str = ""
        logger.info("[zkemkeeper] polling fallback — idle card value=%r", idle_str)

        deadline = time.time() + poll_sec
        poll_no = 0
        log_every = max(1, int(3.0 / 0.06))

        while time.time() < deadline:
            _pump_com_messages()

            try:
                self._com.GetRTLog(1)
            except Exception:
                pass

            raw_hid = None
            hid_card = ""
            try:
                raw_hid = self._com.GetHIDEventCardNumAsStr()
                ok_hid, hid_card = _extract_card(raw_hid)
                if not (ok_hid and _card_is_real(hid_card)):
                    hid_card = ""
            except Exception:
                hid_card = ""

            if hid_card:
                logger.info("[zkemkeeper] card via HID: %r (poll #%d)", hid_card, poll_no)
                return hid_card

            raw_str = None
            str_card = ""
            try:
                raw_str = self._com.GetStrCardNumber()
                ok_str, str_card = _extract_card(raw_str)
                if not (ok_str and _card_is_real(str_card) and str_card != idle_str):
                    str_card = ""
            except Exception:
                str_card = ""

            if str_card:
                logger.info("[zkemkeeper] card via STR: %r (poll #%d)", str_card, poll_no)
                return str_card

            if poll_no % log_every == 0:
                logger.debug(
                    "[zkemkeeper] poll #%d — raw_hid=%r raw_str=%r idle=%r",
                    poll_no, raw_hid, raw_str, idle_str,
                )

            poll_no += 1
            time.sleep(0.06)

        raise ZkemkeeperError("No card detected before timeout")

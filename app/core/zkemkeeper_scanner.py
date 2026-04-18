from __future__ import annotations

import ctypes
import importlib
import time
from dataclasses import dataclass


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


def _extract_com_result(result) -> tuple[bool, str]:
    """Unpack a zkemkeeper COM method result into (ok, card_string).

    pywin32 Dispatch returns [out] params as a tuple: (BOOL, BSTR).
    comtypes dynamic may return just the BSTR directly.
    Either way we normalise to (bool, str).
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


def _is_valid_card(card: str) -> bool:
    """Reject empty, whitespace-only, and the "0" sentinel the device returns when idle."""
    if not card:
        return False
    # "0" (and strings of only zeros) are the device's default/cleared buffer value.
    stripped = card.lstrip("0")
    return bool(stripped)


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
        # Arm real-time event log — same as the PS1 script's RegEvent + GetRTLog.
        # Without this, GetHIDEventCardNumAsStr returns stale/default values.
        try:
            self._com.RegEvent(1, 0xFFFFFFFF)
        except Exception:
            pass
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

    def read_card_once(self, *, poll_sec: float = 10.0) -> str:
        """Block until a valid card is detected (or timeout).

        Mirrors the PS1 script logic:
        - Try GetHIDEventCardNumAsStr first.
        - Fall back to GetStrCardNumber if the first returns nothing useful.
        - Reject "0" and all-zero strings (device idle/cleared sentinel).
        - Poll at 60 ms (same as PS1) for snappy detection.
        """
        if self._com is None:
            raise ZkemkeeperError("Not connected")

        deadline = time.time() + poll_sec
        while time.time() < deadline:
            card_str = ""

            # ── Primary: GetHIDEventCardNumAsStr ──
            try:
                ok, card_str = _extract_com_result(
                    self._com.GetHIDEventCardNumAsStr()
                )
                if not (ok and _is_valid_card(card_str)):
                    card_str = ""
            except Exception:
                card_str = ""

            # ── Fallback: GetStrCardNumber ──
            if not card_str:
                try:
                    ok2, card2 = _extract_com_result(
                        self._com.GetStrCardNumber()
                    )
                    if ok2 and _is_valid_card(card2):
                        card_str = card2
                except Exception:
                    pass

            if card_str:
                return card_str

            time.sleep(0.06)  # 60 ms — same poll rate as the working PS1 script

        raise ZkemkeeperError("No card detected before timeout")

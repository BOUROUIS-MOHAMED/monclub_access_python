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
        if self._com is None:
            raise ZkemkeeperError("Not connected")
        deadline = time.time() + poll_sec
        while time.time() < deadline:
            card = ""
            try:
                result = self._com.GetHIDEventCardNumAsStr()
                if isinstance(result, tuple) and len(result) >= 2:
                    ok, card = result[0], result[1]
                elif isinstance(result, bool):
                    ok = result
                    card = ""
                else:
                    ok = False
            except Exception:
                ok = False
                card = ""

            card_str = str(card or "").strip()
            if ok and card_str:
                return card_str

            try:
                fallback = str(self._com.GetStrCardNumber() or "").strip()
                if fallback:
                    return fallback
            except Exception:
                pass

            time.sleep(0.2)
        raise ZkemkeeperError("No card detected before timeout")

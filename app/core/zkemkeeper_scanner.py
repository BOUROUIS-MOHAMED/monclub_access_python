from __future__ import annotations

import time
from dataclasses import dataclass


class ZkemkeeperError(RuntimeError):
    pass


@dataclass
class ZkemkeeperScanner:
    _com: object | None = None

    def _load_com(self) -> object:
        try:
            import win32com.client  # type: ignore
        except Exception as e:
            raise ZkemkeeperError("pywin32 is required for ZKEMKeeper COM access") from e
        return win32com.client.Dispatch("zkemkeeper.CZKEM")

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
            ok, _userid, card, _state, _door, _event, _inout, _time = (
                self._com.GetRTLog()
            )
            if ok and card:
                return str(card).strip()
            time.sleep(0.2)
        raise ZkemkeeperError("No card detected before timeout")

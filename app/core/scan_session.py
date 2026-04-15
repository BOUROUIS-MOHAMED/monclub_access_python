from __future__ import annotations

import queue
import threading
import time
from typing import Optional

from app.core.card_scanner import get_scanner


class ScanSession:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._queue: "queue.Queue[dict]" = queue.Queue()
        self._active = False

    def start(
        self,
        *,
        mode: str,
        ip: str,
        port: int,
        timeout_ms: int,
        usb_device_path: str,
    ) -> bool:
        with self._lock:
            if self._active:
                return False
            self._active = True

        scanner = get_scanner()

        def _on_card(result) -> None:
            self._queue.put({"status": "done", "card": result.card_number})
            self._end()

        started = scanner.start_scan(
            mode=mode,
            ip=ip,
            port=port,
            timeout_ms=timeout_ms,
            usb_device_path=usb_device_path,
            on_card=_on_card,
        )
        if not started:
            self._queue.put({"status": "error", "message": "Scanner already active"})
            self._end()
            return False

        def _timeout() -> None:
            time.sleep(max(1, timeout_ms // 1000))
            with self._lock:
                if not self._active:
                    return
            self._queue.put({"status": "timeout"})
            scanner.stop_scan()
            self._end()

        threading.Thread(target=_timeout, daemon=True).start()
        return True

    def wait_event(self, timeout: float = 1.0) -> Optional[dict]:
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def is_active(self) -> bool:
        with self._lock:
            return self._active

    def _end(self) -> None:
        with self._lock:
            self._active = False


_scan_session = ScanSession()


def get_scan_session() -> ScanSession:
    return _scan_session

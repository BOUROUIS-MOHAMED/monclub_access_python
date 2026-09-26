"""The notice socket loop (P2b §3; backend main c7d4b532).

One daemon thread. It never touches a device, a database write job or an engine lock: every
notice becomes a callback that only schedules work elsewhere (``app.after``, the command
executor's queue, the lease refresh).

* Connect with the PC token in ``Authorization`` and no ``Origin``; the first frame is
  ``welcome`` (a clock sample, the poll interval).
* ``changed``/``rollover``/``command`` notices go to the callbacks; each numbered notice is acked
  (``{"type":"ack","seq":n}``, bookkeeping only).
* Half-open: the server pings every 25 s and closes a silent session after 60-71 s; a socket
  that has received nothing for ``read_idle + 15`` s is dropped and rebuilt here.
* Sleep/resume: when the wall clock jumps against the monotonic clock by more than 30 s between
  two loop turns, the socket is rebuilt (a laptop lid, a PC suspended overnight).
* Reconnect: after a session ends, a random 0-60 s wait (the server's guidance: a redeploy drops
  every PC at once); repeated handshake failures back off up to 15 min; ``Retry-After`` wins.
* Close codes: 4001 -> a new PC token; 4003 (revoked/adopted) -> wait 30 min; 4009 (another copy
  of the app took the socket) -> wait 5 min.
* A handshake answered 404 ``NOT_FOUND`` means the server switch is off: ``on_switched_off``.
"""
from __future__ import annotations

import json
import logging
import random
import threading
import time
from typing import Any, Callable, Dict, Optional

from app.core.v2.ws_client import WebSocketClient, WsError, WsHandshakeError

_log = logging.getLogger("zkapp.v2.notice")

RESUME_JUMP_SEC = 30.0
HALF_OPEN_MARGIN_SEC = 15.0
MAX_BACKOFF_SEC = 900.0


class NoticeCallbacks:
    """Everything the loop reports. Each is called on the loop thread and must return fast."""

    def on_welcome(self, msg: Dict[str, Any], sent_wall: float, recv_wall: float) -> None: ...
    def on_changed(self, scopes: list, msg: Dict[str, Any]) -> None: ...
    def on_rollover(self, msg: Dict[str, Any]) -> None: ...
    def on_command(self, command_id: str, command_type: str, msg: Dict[str, Any]) -> None: ...
    def on_disconnected(self, reason: str) -> None: ...
    def on_switched_off(self) -> None: ...
    def on_token_expired(self) -> None: ...


class NoticeLoop(threading.Thread):
    def __init__(self, *, url: str, headers_provider: Callable[[], Optional[Dict[str, str]]],
                 callbacks: NoticeCallbacks, enabled: Callable[[], bool] = lambda: True,
                 ws_factory: Callable[..., Any] = WebSocketClient, rand: Callable[[], float] = random.random,
                 wall: Callable[[], float] = time.time, mono: Callable[[], float] = time.monotonic,
                 first_delay_max: float = 10.0) -> None:
        super().__init__(name="v2-notice", daemon=True)
        self._url = url
        self._headers = headers_provider
        self._cb = callbacks
        self._enabled = enabled
        self._ws_factory = ws_factory
        self._rand = rand
        self._wall = wall
        self._mono = mono
        self._stop_event = threading.Event()
        self._wake = threading.Event()
        self._ws = None
        self._first_delay_max = float(first_delay_max)
        self._failures = 0
        # state for the status page
        self.connected = False
        self.connected_since: Optional[float] = None
        self.poll_interval_sec = 120
        self.read_idle_sec = 60
        self.half_open_margin_sec = HALF_OPEN_MARGIN_SEC
        self.last_close: Optional[str] = None
        self.last_error: Optional[str] = None
        self.sessions = 0
        self.notices = 0

    # ------------------------------------------------------------------ control
    def stop(self, timeout: float = 3.0) -> None:
        self._stop_event.set()
        self._wake.set()
        ws = self._ws
        if ws is not None:
            try:
                ws.abort()
            except Exception:
                pass
        if self.is_alive():
            self.join(timeout)

    def reconnect_now(self) -> None:
        """Drop the current socket (e.g. identity changed) and connect again soon."""
        ws = self._ws
        if ws is not None:
            try:
                ws.abort()
            except Exception:
                pass
        self._wake.set()

    def _sleep(self, seconds: float) -> bool:
        """False when stopping."""
        if seconds > 0:
            self._wake.wait(seconds)
            self._wake.clear()
        return not self._stop_event.is_set()

    def _jitter(self, low: float, high: float) -> float:
        return low + (high - low) * self._rand()

    # ------------------------------------------------------------------ loop
    def run(self) -> None:
        if not self._sleep(self._jitter(0.0, self._first_delay_max)):
            return
        while not self._stop_event.is_set():
            try:
                wait = self._one_session()
            except Exception as exc:                     # never let the thread die
                self.last_error = f"{type(exc).__name__}: {exc}"
                _log.warning("[V2] notice loop error: %s", self.last_error)
                wait = self._backoff()
            if not self._sleep(wait):
                return

    def _backoff(self, retry_after: Optional[float] = None) -> float:
        self._failures += 1
        base = min(MAX_BACKOFF_SEC, 30.0 * (2 ** min(self._failures - 1, 5)))
        wait = self._jitter(base * 0.5, base)
        if retry_after is not None:
            wait = max(wait, float(retry_after))
        return wait

    def _one_session(self) -> float:
        if not self._enabled():
            return 30.0
        headers = self._headers()
        if not headers:
            return 60.0
        ws = self._ws_factory(self._url, headers)
        sent = self._wall()
        try:
            ws.connect()
        except WsHandshakeError as exc:
            self.last_error = str(exc)
            _log.info("[V2] notice socket refused: %s %s", exc.status, exc.code)
            if exc.status == 404 and exc.code == "NOT_FOUND":
                self._cb.on_switched_off()
                return self._backoff()
            if exc.code in ("ACCESS_PC_TOKEN_EXPIRED", "ACCESS_PC_TOKEN_INVALID", "TOKEN_INVALID"):
                self._cb.on_token_expired()
                return self._backoff(5.0)
            if exc.code in ("ACCESS_PC_REVOKED", "ACCESS_PC_ADOPTED"):
                return 1800.0
            return self._backoff(exc.retry_after)
        except (WsError, OSError) as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            return self._backoff()
        self._ws = ws
        self.connected = True
        self.connected_since = self._wall()
        self.sessions += 1
        self._failures = 0
        reason = "ended"
        try:
            reason = self._pump(ws, sent)
        finally:
            self.connected = False
            self._ws = None
            try:
                ws.abort()
            except Exception:
                pass
            self.last_close = reason
            try:
                self._cb.on_disconnected(reason)
            except Exception:
                pass
        if self._stop_event.is_set():
            return 0.0
        if reason.startswith("close 4003"):
            return 1800.0
        if reason.startswith("close 4009"):
            return 300.0
        if reason.startswith("close 4001"):
            self._cb.on_token_expired()
        return self._jitter(0.0, 60.0)

    def _pump(self, ws, sent_wall: float) -> str:
        skew = self._wall() - self._mono()
        last_rx = self._mono()
        while not self._stop_event.is_set():
            try:
                event = ws.recv(1.0)
            except WsError as exc:
                return f"error {exc}"
            now_mono = self._mono()
            if getattr(ws, "last_rx_mono", 0.0):
                last_rx = max(last_rx, ws.last_rx_mono)
            new_skew = self._wall() - now_mono
            if abs(new_skew - skew) > RESUME_JUMP_SEC:
                return "resume (clock jump)"
            skew = new_skew
            if event is None:
                if now_mono - last_rx > self.read_idle_sec + self.half_open_margin_sec:
                    return "half-open (no frame from the server)"
                continue
            last_rx = now_mono
            if event[0] == "close":
                return f"close {event[1]} {event[2]}"
            if event[0] != "text":
                continue
            try:
                msg = json.loads(event[1])
            except Exception:
                continue
            if not isinstance(msg, dict):
                continue
            self._dispatch(ws, msg, sent_wall)
        return "stopped"

    def _dispatch(self, ws, msg: Dict[str, Any], sent_wall: float) -> None:
        kind = msg.get("type")
        self.notices += 1
        try:
            if kind == "welcome":
                try:
                    self.poll_interval_sec = max(30, int(msg.get("pollIntervalSec") or 120))
                    self.read_idle_sec = max(10, int(msg.get("readIdleTimeoutSec") or 60))
                except (TypeError, ValueError):
                    pass
                self._cb.on_welcome(msg, sent_wall, self._wall())
            elif kind == "changed":
                self._cb.on_changed(list(msg.get("scopes") or []), msg)
            elif kind == "rollover":
                self._cb.on_rollover(msg)
            elif kind == "command":
                cid = str(msg.get("id") or "")
                if cid:
                    self._cb.on_command(cid, str(msg.get("commandType") or ""), msg)
        except Exception as exc:
            _log.warning("[V2] notice handler failed (%s): %s", kind, exc)
        seq = msg.get("seq")
        if isinstance(seq, int) and not isinstance(seq, bool):
            try:
                ws.send_text(json.dumps({"type": "ack", "seq": seq}))
            except Exception:
                pass

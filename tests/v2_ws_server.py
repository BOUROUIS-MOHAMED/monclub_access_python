"""A tiny scripted WebSocket server on localhost for the P3b-2 tests (not a test module).

It speaks the server side of RFC 6455 with the client module's own codec, over a real socket.
Interop with the real backend (Tomcat 10.1) is proven separately by the end-to-end run, not
here: the same codec on both sides cannot prove it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import socket
import struct
import threading
import time
from typing import Callable, List, Optional

from app.core.v2.ws_client import (OP_CLOSE, OP_CONT, OP_PING, OP_PONG, OP_TEXT, _GUID,
                                   decode_frame, encode_frame)


class ScriptedWsServer:
    """Accepts connections; ``on_connect(conn)`` runs per connection on its own thread."""

    def __init__(self, on_connect: Callable[["ServerConn"], None], *, refuse: Optional[tuple] = None):
        self._on_connect = on_connect
        self._refuse = refuse          # (status, json_body_dict, extra_headers)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.requests: List[dict] = []
        self.conns: List["ServerConn"] = []
        self._stop = False
        self._t = threading.Thread(target=self._accept_loop, daemon=True)
        self._t.start()

    @property
    def url(self) -> str:
        return f"ws://127.0.0.1:{self.port}/api/v1/public/access/v2/pc/ws"

    def _accept_loop(self):
        while not self._stop:
            try:
                s, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(s,), daemon=True).start()

    def _serve(self, s: socket.socket):
        s.settimeout(10)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = s.recv(4096)
            if not chunk:
                return
            data += chunk
        head, rest = data.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        headers = {}
        for line in lines[1:]:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        self.requests.append({"line": lines[0], "headers": headers})
        if self._refuse:
            status, body, extra = self._refuse
            raw = json.dumps(body).encode()
            hdr = [f"HTTP/1.1 {status} Refused", "Content-Type: application/json",
                   f"Content-Length: {len(raw)}"] + [f"{k}: {v}" for k, v in (extra or {}).items()]
            s.sendall(("\r\n".join(hdr) + "\r\n\r\n").encode() + raw)
            s.close()
            return
        accept = base64.b64encode(hashlib.sha1((headers["sec-websocket-key"] + _GUID).encode()).digest()).decode()
        s.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
        conn = ServerConn(s, bytearray(rest))
        self.conns.append(conn)
        try:
            self._on_connect(conn)
        except Exception:
            pass

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except Exception:
            pass
        for c in self.conns:
            c.kill()


class ServerConn:
    def __init__(self, s: socket.socket, buf: bytearray):
        self.s = s
        self.buf = buf
        self.received: List[tuple] = []     # (opcode, payload)

    def send_text(self, obj, *, fragments: int = 1, ping_between: bool = False):
        raw = (json.dumps(obj) if not isinstance(obj, str) else obj).encode()
        if fragments <= 1:
            self.s.sendall(encode_frame(OP_TEXT, raw, mask=False))
            return
        size = max(1, len(raw) // fragments)
        parts = [raw[i:i + size] for i in range(0, len(raw), size)]
        for i, part in enumerate(parts):
            op = OP_TEXT if i == 0 else OP_CONT
            self.s.sendall(encode_frame(op, part, mask=False, fin=(i == len(parts) - 1)))
            if ping_between and i == 0:
                self.s.sendall(encode_frame(OP_PING, b"pp", mask=False))

    def send_ping(self, payload=b"12345678"):
        self.s.sendall(encode_frame(OP_PING, payload, mask=False))

    def send_close(self, code: int, reason: str = ""):
        self.s.sendall(encode_frame(OP_CLOSE, struct.pack("!H", code) + reason.encode(), mask=False))

    def read_frame(self, timeout: float = 5.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            fr = decode_frame(self.buf)
            if fr is not None:
                fin, op, payload, used = fr
                del self.buf[:used]
                self.received.append((op, payload))
                return op, payload
            self.s.settimeout(max(0.01, end - time.monotonic()))
            try:
                chunk = self.s.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                return None
            if not chunk:
                return None
            self.buf += chunk
        return None

    def kill(self):
        try:
            self.s.close()
        except Exception:
            pass

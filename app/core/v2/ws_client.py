"""A minimal RFC 6455 WebSocket client on the standard library (P3b-2).

Why not a library: no WebSocket package is installed in the build environment (the packaged
32-bit Python 3.11 under PyInstaller), adding one needs a download and a packaging change,
and the notice socket needs only a small subset: one text message at a time from the server,
server pings, and a close handshake. This module is that subset and nothing else.

What it does:
* ``ws://`` and ``wss://``; TLS through ``ssl.create_default_context(cafile=certifi)`` with the
  host name for SNI and certificate checking (falls back to the system store without certifi).
* System proxies: ``urllib.request.getproxies()`` (environment variables, and on Windows the
  Internet Settings registry), honouring ``proxy_bypass``; ``wss`` goes through an HTTP CONNECT
  tunnel (``Proxy-Authorization: Basic`` when the proxy URL carries credentials).
* Handshake: ``Upgrade``/``Sec-WebSocket-Key``/``Version: 13`` plus the caller's headers; **no
  ``Origin`` header ever** (the backend refuses any: 403 ``ORIGIN_NOT_ALLOWED``). The
  ``Sec-WebSocket-Accept`` answer is checked. A refused handshake raises ``WsHandshakeError``
  with the backend's ``code`` and ``Retry-After`` when the body is its JSON error.
* Frames: client frames masked; text messages reassembled from fragments; a ping is answered
  with a pong at once (also between two fragments); a close is answered and returned.
* ``recv(timeout)`` returns ``None`` on timeout and keeps a partly received frame buffered.
* ``last_rx_mono`` — the monotonic time of the last byte received (pings included): the caller's
  half-open detection.

Sends happen only on the thread that calls ``recv`` (pong, close, ack), so the socket needs no
lock; ``abort()`` may be called from any thread to unblock it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import time
import urllib.parse
import urllib.request
from typing import Dict, Optional, Tuple

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_MESSAGE_BYTES = 1 << 20
_MAX_HEADER_BYTES = 64 * 1024

OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA


class WsError(Exception):
    pass


class WsHandshakeError(WsError):
    def __init__(self, status: int, code: str, message: str = "", retry_after: Optional[float] = None):
        super().__init__(f"handshake refused: {status} {code} {message}".strip())
        self.status = int(status)
        self.code = str(code or "")
        self.message = message
        self.retry_after = retry_after


def _accept_for(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + _GUID).encode("ascii")).digest()).decode("ascii")


def encode_frame(opcode: int, payload: bytes, *, mask: bool = True, fin: bool = True) -> bytes:
    head = bytearray([(0x80 if fin else 0) | (opcode & 0x0F)])
    n = len(payload)
    mbit = 0x80 if mask else 0
    if n < 126:
        head.append(mbit | n)
    elif n < 65536:
        head.append(mbit | 126)
        head += struct.pack("!H", n)
    else:
        head.append(mbit | 127)
        head += struct.pack("!Q", n)
    if not mask:
        return bytes(head) + payload
    key = os.urandom(4)
    masked = bytes(b ^ key[i & 3] for i, b in enumerate(payload))
    return bytes(head) + key + masked


def decode_frame(buf: bytearray) -> Optional[Tuple[bool, int, bytes, int]]:
    """(fin, opcode, payload, consumed) for one complete frame at the start of ``buf``, else None."""
    if len(buf) < 2:
        return None
    b0, b1 = buf[0], buf[1]
    fin, opcode, masked, n = bool(b0 & 0x80), b0 & 0x0F, bool(b1 & 0x80), b1 & 0x7F
    pos = 2
    if n == 126:
        if len(buf) < pos + 2:
            return None
        n = struct.unpack("!H", bytes(buf[pos:pos + 2]))[0]
        pos += 2
    elif n == 127:
        if len(buf) < pos + 8:
            return None
        n = struct.unpack("!Q", bytes(buf[pos:pos + 8]))[0]
        pos += 8
    if n > MAX_MESSAGE_BYTES:
        raise WsError(f"frame of {n} bytes exceeds {MAX_MESSAGE_BYTES}")
    key = b""
    if masked:
        if len(buf) < pos + 4:
            return None
        key = bytes(buf[pos:pos + 4])
        pos += 4
    if len(buf) < pos + n:
        return None
    payload = bytes(buf[pos:pos + n])
    if masked:
        payload = bytes(b ^ key[i & 3] for i, b in enumerate(payload))
    return fin, opcode, payload, pos + n


def _pick_proxy(scheme: str, host: str) -> Optional[str]:
    try:
        if urllib.request.proxy_bypass(host):
            return None
    except Exception:
        pass
    try:
        proxies = urllib.request.getproxies() or {}
    except Exception:
        return None
    key = "https" if scheme == "wss" else "http"
    return proxies.get(key) or proxies.get("http") or None


class WebSocketClient:
    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None, *,
                 connect_timeout: float = 15.0, use_system_proxy: bool = True,
                 ca_file: Optional[str] = None) -> None:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("ws", "wss"):
            raise ValueError(f"not a websocket url: {url}")
        self.url = url
        self._scheme = parsed.scheme
        self._host = parsed.hostname or ""
        self._port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        self._path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
        self._headers = {k: v for k, v in (headers or {}).items() if k.lower() != "origin"}
        self._connect_timeout = float(connect_timeout)
        self._use_proxy = bool(use_system_proxy)
        self._ca_file = ca_file
        self._sock: Optional[socket.socket] = None
        self._buf = bytearray()
        self._fragments: list = []
        self._closed = False
        self.last_rx_mono = 0.0
        self.proxy_used: Optional[str] = None

    # ------------------------------------------------------------------ connect
    def connect(self) -> None:
        proxy = _pick_proxy(self._scheme, self._host) if self._use_proxy else None
        if proxy:
            p = urllib.parse.urlsplit(proxy if "://" in proxy else "http://" + proxy)
            sock = socket.create_connection((p.hostname, p.port or 8080), timeout=self._connect_timeout)
            try:
                self._tunnel(sock, p)
            except Exception:
                sock.close()
                raise
            self.proxy_used = f"{p.hostname}:{p.port or 8080}"
        else:
            sock = socket.create_connection((self._host, self._port), timeout=self._connect_timeout)
        try:
            if self._scheme == "wss":
                cafile = self._ca_file
                if cafile is None:
                    try:
                        import certifi
                        cafile = certifi.where()
                    except Exception:
                        cafile = None
                ctx = ssl.create_default_context(cafile=cafile)
                sock = ctx.wrap_socket(sock, server_hostname=self._host)
            sock.settimeout(self._connect_timeout)
            self._sock = sock
            self._handshake()
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            self._sock = None
            raise

    def _tunnel(self, sock: socket.socket, proxy) -> None:
        target = f"{self._host}:{self._port}"
        lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
        if proxy.username:
            cred = f"{urllib.parse.unquote(proxy.username)}:{urllib.parse.unquote(proxy.password or '')}"
            lines.append("Proxy-Authorization: Basic " + base64.b64encode(cred.encode()).decode())
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        head, _rest = self._read_head(sock)
        status = head.split(b"\r\n", 1)[0].split(b" ")
        if len(status) < 2 or status[1] != b"200":
            raise WsError(f"proxy CONNECT refused: {head.splitlines()[0]!r}")

    @staticmethod
    def _read_head(sock: socket.socket) -> Tuple[bytes, bytes]:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                raise WsError("connection closed during the HTTP exchange")
            data += chunk
            if len(data) > _MAX_HEADER_BYTES:
                raise WsError("HTTP header too large")
        head, rest = data.split(b"\r\n\r\n", 1)
        return head, rest

    def _read_error_body(self, headers: Dict[str, str], rest: bytes) -> bytes:
        """The body of a refused handshake: Content-Length, chunked (Tomcat's own error
        answers -- e.g. 404 NOT_FOUND while the server switch is off, found in the end-to-end
        run), or until close. At most 16 KiB; a read error just ends it."""
        body = rest
        chunked = "chunked" in headers.get("transfer-encoding", "").lower()
        try:
            want = int(headers.get("content-length") or -1)
        except ValueError:
            want = -1
        try:
            self._sock.settimeout(min(self._connect_timeout, 5.0))
            while len(body) < 16384:
                if want >= 0 and len(body) >= want:
                    break
                if chunked and b"\r\n0\r\n\r\n" in b"\r\n" + body:
                    break
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                body += chunk
        except Exception:
            pass
        if not chunked:
            return body if want < 0 else body[:want]
        out, pos = b"", 0
        while pos < len(body):
            line_end = body.find(b"\r\n", pos)
            if line_end < 0:
                break
            try:
                size = int(body[pos:line_end].split(b";")[0].strip() or b"0", 16)
            except ValueError:
                break
            if size == 0:
                break
            out += body[line_end + 2:line_end + 2 + size]
            pos = line_end + 2 + size + 2
        return out

    def _handshake(self) -> None:
        assert self._sock is not None
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        host = self._host if self._port in (80, 443) else f"{self._host}:{self._port}"
        lines = [f"GET {self._path} HTTP/1.1", f"Host: {host}", "Upgrade: websocket",
                 "Connection: Upgrade", f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13"]
        lines += [f"{k}: {v}" for k, v in self._headers.items()]
        self._sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        head, rest = self._read_head(self._sock)
        text = head.decode("latin-1", "replace")
        status_line, _, header_blob = text.partition("\r\n")
        parts = status_line.split(" ", 2)
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        headers = {}
        for line in header_blob.split("\r\n"):
            name, sep, value = line.partition(":")
            if sep:
                headers[name.strip().lower()] = value.strip()
        if status != 101:
            body = self._read_error_body(headers, rest)
            code, message = f"HTTP_{status}", ""
            try:
                obj = json.loads(body.decode("utf-8", "replace") or "null")
                if isinstance(obj, dict) and obj.get("code"):
                    code, message = str(obj["code"]), str(obj.get("errorMsg") or "")
            except Exception:
                pass
            ra = headers.get("retry-after", "")
            retry_after = float(ra) if ra.isdigit() and len(ra) < 9 else None
            raise WsHandshakeError(status, code, message, retry_after)
        if headers.get("sec-websocket-accept", "") != _accept_for(key):
            raise WsError("bad Sec-WebSocket-Accept")
        self._buf = bytearray(rest)
        self.last_rx_mono = time.monotonic()

    # ------------------------------------------------------------------ I/O
    def _send(self, opcode: int, payload: bytes) -> None:
        if self._sock is None:
            raise WsError("not connected")
        self._sock.sendall(encode_frame(opcode, payload))

    def send_text(self, text: str) -> None:
        self._send(OP_TEXT, text.encode("utf-8"))

    def send_ping(self, payload: bytes = b"") -> None:
        self._send(OP_PING, payload)

    def recv(self, timeout: float):
        """One event: ("text", str) | ("close", code, reason) | None (timeout)."""
        if self._sock is None:
            raise WsError("not connected")
        deadline = time.monotonic() + max(0.0, float(timeout))
        while True:
            frame = decode_frame(self._buf)
            if frame is not None:
                fin, opcode, payload, used = frame
                del self._buf[:used]
                event = self._on_frame(fin, opcode, payload)
                if event is not None:
                    return event
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock = self._sock
            if sock is None:
                raise WsError("aborted")
            try:
                sock.settimeout(remaining)
                chunk = sock.recv(65536)
            except socket.timeout:
                return None
            except (OSError, ValueError) as exc:
                raise WsError(f"socket error: {exc}")
            if not chunk:
                raise WsError("connection closed by peer (no close frame)")
            self.last_rx_mono = time.monotonic()
            self._buf += chunk

    def _on_frame(self, fin: bool, opcode: int, payload: bytes):
        if opcode == OP_PING:
            self._send(OP_PONG, payload)
            return None
        if opcode == OP_PONG:
            return None
        if opcode == OP_CLOSE:
            code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 1005
            reason = payload[2:].decode("utf-8", "replace")
            if not self._closed:
                self._closed = True
                try:
                    self._send(OP_CLOSE, payload[:2])
                except Exception:
                    pass
            return ("close", code, reason)
        if opcode in (OP_TEXT, OP_BINARY):
            self._fragments = [(opcode, payload)]
        elif opcode == OP_CONT:
            if not self._fragments:
                raise WsError("continuation frame without a start")
            self._fragments.append((opcode, payload))
        else:
            raise WsError(f"unknown opcode {opcode}")
        if sum(len(p) for _o, p in self._fragments) > MAX_MESSAGE_BYTES:
            raise WsError("message too large")
        if not fin:
            return None
        first_op = self._fragments[0][0]
        data = b"".join(p for _o, p in self._fragments)
        self._fragments = []
        if first_op == OP_BINARY:
            return None                  # the server never sends binary; ignored
        return ("text", data.decode("utf-8", "replace"))

    def close(self, code: int = 1000, reason: str = "") -> None:
        if self._sock is None:
            return
        if not self._closed:
            self._closed = True
            try:
                self._sock.settimeout(2.0)
                self._send(OP_CLOSE, struct.pack("!H", code) + reason.encode("utf-8")[:120])
            except Exception:
                pass
        self.abort()

    def abort(self) -> None:
        sock, self._sock = self._sock, None
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass

"""P3b-2 step 3: the stdlib WebSocket client against a real localhost socket.

TLS and the real backend are not exercised here (UNVERIFIED in the unit suite): the handshake
against the local backend is part of the end-to-end run; production wss through nginx is a
FIELD-TEST.
"""
from __future__ import annotations

import json
import socket
import threading
import time

import pytest

from app.core.v2 import ws_client as wc
from app.core.v2.ws_client import OP_PONG, OP_TEXT, OP_CLOSE, WebSocketClient, WsError, WsHandshakeError
from tests.v2_ws_server import ScriptedWsServer


def _client(server, **kw):
    c = WebSocketClient(server.url, {"Authorization": "Bearer tok", "X-MonClub-Access-Version": "1.4.35",
                                     "Origin": "http://evil"}, use_system_proxy=False, **kw)
    c.connect()
    return c


def test_the_handshake_sends_the_bearer_and_never_an_origin():
    got = []
    srv = ScriptedWsServer(lambda conn: (conn.send_text({"type": "welcome"}), got.append(conn.read_frame(3))))
    try:
        c = _client(srv)
        assert c.recv(3) == ("text", json.dumps({"type": "welcome"}))
        req = srv.requests[0]
        assert req["line"] == "GET /api/v1/public/access/v2/pc/ws HTTP/1.1"
        assert req["headers"]["authorization"] == "Bearer tok"
        assert req["headers"]["x-monclub-access-version"] == "1.4.35"
        assert "origin" not in req["headers"]
        c.close()
    finally:
        srv.close()


def test_a_server_ping_is_answered_with_a_pong_carrying_its_payload():
    pongs = []

    def script(conn):
        conn.send_ping(b"\x00\x00\x01\x8a\xde\xad\xbe\xef")
        pongs.append(conn.read_frame(3))
        conn.send_text({"type": "changed"})

    srv = ScriptedWsServer(script)
    try:
        c = _client(srv)
        assert c.recv(3)[0] == "text"
        assert pongs == [(OP_PONG, b"\x00\x00\x01\x8a\xde\xad\xbe\xef")]
        assert c.last_rx_mono > 0
    finally:
        srv.close()


def test_a_fragmented_message_with_a_ping_in_between_is_reassembled():
    msg = {"type": "changed", "seq": 3, "scopes": ["members", "credentials"], "at": "x" * 60}
    frames = []

    def script(conn):
        conn.send_text(msg, fragments=4, ping_between=True)
        frames.append(conn.read_frame(3))

    srv = ScriptedWsServer(script)
    try:
        c = _client(srv)
        ev = c.recv(3)
        assert ev[0] == "text" and json.loads(ev[1]) == msg
        end = time.monotonic() + 3
        while not frames and time.monotonic() < end:     # the server thread reads the pong
            time.sleep(0.01)
        assert frames and frames[0][0] == OP_PONG
    finally:
        srv.close()


def test_client_frames_are_masked_and_text_arrives_intact():
    seen = []

    def script(conn):
        seen.append(conn.read_frame(3))

    srv = ScriptedWsServer(script)
    try:
        c = _client(srv)
        c.send_text('{"type":"ack","seq":7}')
        time.sleep(0.2)
        assert seen[0] == (OP_TEXT, b'{"type":"ack","seq":7}')
        # the raw bytes on the wire carried the mask bit
        frame = wc.encode_frame(OP_TEXT, b"abc")
        assert frame[1] & 0x80
    finally:
        srv.close()


def test_a_close_from_the_server_is_answered_and_returned():
    answers = []

    def script(conn):
        conn.send_close(4009, "REPLACED")
        answers.append(conn.read_frame(3))

    srv = ScriptedWsServer(script)
    try:
        c = _client(srv)
        assert c.recv(3) == ("close", 4009, "REPLACED")
        time.sleep(0.1)
        assert answers[0][0] == OP_CLOSE
    finally:
        srv.close()


def test_a_timeout_returns_none_and_keeps_a_partial_frame():
    release = threading.Event()

    def script(conn):
        raw = wc.encode_frame(OP_TEXT, b'{"type":"rollover"}', mask=False)
        conn.s.sendall(raw[:5])
        release.wait(3)
        conn.s.sendall(raw[5:])

    srv = ScriptedWsServer(script)
    try:
        c = _client(srv)
        assert c.recv(0.3) is None
        release.set()
        assert c.recv(3) == ("text", '{"type":"rollover"}')
    finally:
        srv.close()


def test_a_dropped_connection_is_an_error_not_a_hang():
    srv = ScriptedWsServer(lambda conn: conn.kill())
    try:
        c = _client(srv)
        with pytest.raises(WsError):
            for _ in range(20):
                c.recv(0.5)
    finally:
        srv.close()


def test_abort_from_another_thread_unblocks_recv():
    hold = threading.Event()
    srv = ScriptedWsServer(lambda conn: hold.wait(5))
    try:
        c = _client(srv)
        threading.Timer(0.3, c.abort).start()
        t0 = time.monotonic()
        with pytest.raises(WsError):
            c.recv(10)
        assert time.monotonic() - t0 < 3
    finally:
        hold.set()
        srv.close()


def test_a_refused_handshake_carries_the_backend_code_and_retry_after():
    srv = ScriptedWsServer(lambda conn: None,
                           refuse=(503, {"status": False, "errorMsg": "restarting", "code": "SERVER_SHUTTING_DOWN"},
                                   {"Retry-After": "5"}))
    try:
        c = WebSocketClient(srv.url, {"Authorization": "Bearer tok"}, use_system_proxy=False)
        with pytest.raises(WsHandshakeError) as ei:
            c.connect()
        assert (ei.value.status, ei.value.code, ei.value.retry_after) == (503, "SERVER_SHUTTING_DOWN", 5.0)
    finally:
        srv.close()


def test_a_wrong_accept_key_is_refused():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]

    def bad():
        conn, _ = s.accept()
        conn.recv(4096)
        conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     b"Sec-WebSocket-Accept: bogus\r\n\r\n")
        time.sleep(0.5)
        conn.close()

    threading.Thread(target=bad, daemon=True).start()
    try:
        c = WebSocketClient(f"ws://127.0.0.1:{port}/x", {}, use_system_proxy=False)
        with pytest.raises(WsError):
            c.connect()
    finally:
        s.close()


def test_the_system_proxy_is_used_through_a_connect_tunnel(monkeypatch):
    welcome = []
    srv = ScriptedWsServer(lambda conn: conn.send_text({"type": "welcome"}))
    proxy = socket.socket()
    proxy.bind(("127.0.0.1", 0))
    proxy.listen(1)
    pport = proxy.getsockname()[1]
    seen = []

    def run_proxy():
        c, _ = proxy.accept()
        data = b""
        while b"\r\n\r\n" not in data:
            data += c.recv(4096)
        seen.append(data.split(b"\r\n")[0])
        upstream = socket.create_connection(("127.0.0.1", srv.port))
        c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

        def pipe(a, b):
            try:
                while True:
                    d = a.recv(4096)
                    if not d:
                        break
                    b.sendall(d)
            except OSError:
                pass

        threading.Thread(target=pipe, args=(c, upstream), daemon=True).start()
        pipe(upstream, c)

    threading.Thread(target=run_proxy, daemon=True).start()
    monkeypatch.setattr(wc.urllib.request, "getproxies", lambda: {"http": f"http://127.0.0.1:{pport}"})
    monkeypatch.setattr(wc.urllib.request, "proxy_bypass", lambda host: False)
    try:
        c = WebSocketClient(srv.url, {"Authorization": "Bearer tok"})
        c.connect()
        assert c.recv(3) == ("text", json.dumps({"type": "welcome"}))
        assert seen[0] == f"CONNECT 127.0.0.1:{srv.port} HTTP/1.1".encode()
        assert c.proxy_used == f"127.0.0.1:{pport}"
    finally:
        srv.close()
        proxy.close()


def test_a_bypassed_host_goes_direct(monkeypatch):
    monkeypatch.setattr(wc.urllib.request, "getproxies", lambda: {"http": "http://10.255.255.1:3128"})
    monkeypatch.setattr(wc.urllib.request, "proxy_bypass", lambda host: True)
    assert wc._pick_proxy("ws", "127.0.0.1") is None


def test_a_chunked_refusal_body_is_read_like_tomcat_sends_it():
    # Found against the real backend with the switch off: Tomcat answers the handshake 404
    # NOT_FOUND with Transfer-Encoding: chunked and no Content-Length.
    srv = ScriptedWsServer(lambda conn: None, chunked=True,
                           refuse=(404, {"status": False, "errorMsg": "Resource not found", "code": "NOT_FOUND",
                                         "details": {"path": "/api/v1/public/access/v2/pc/ws"}}, {}))
    try:
        c = WebSocketClient(srv.url, {"Authorization": "Bearer tok"}, use_system_proxy=False)
        with pytest.raises(WsHandshakeError) as ei:
            c.connect()
        assert (ei.value.status, ei.value.code) == (404, "NOT_FOUND")
    finally:
        srv.close()

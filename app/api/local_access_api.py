from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


def _cors_headers(handler: BaseHTTPRequestHandler) -> None:
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
    handler.send_header("Access-Control-Max-Age", "86400")


class _AppHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, app):
        super().__init__(server_address, RequestHandlerClass)
        self.app = app  # MainApp instance


class LocalAccessApiServer:
    """
    Local REST server that can be called from the dashboard (browser) to trigger
    enrollment on the PC.

    Endpoints:
      - GET /api/v1/access/health
      - GET /api/v1/access/enroll?id=...&fingerId=...&fullName=...&device=zk9500
    """

    def __init__(self, *, app, host: str = "127.0.0.1", port: int = 8788):
        self.app = app
        self.host = host
        self.port = int(port)
        self._httpd: Optional[_AppHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._httpd is not None:
            return

        server = self

        class Handler(BaseHTTPRequestHandler):
            def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
                body = _json_bytes(payload)
                self.send_response(status)
                _cors_headers(self)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_OPTIONS(self):
                self.send_response(204)
                _cors_headers(self)
                self.end_headers()

            def do_GET(self):
                try:
                    parsed = urlparse(self.path)
                    path = parsed.path or ""
                    qs = parse_qs(parsed.query or "")

                    # health
                    if path == "/api/v1/access/health":
                        info = server.app.get_local_api_health()
                        self._send_json(200, info)
                        return

                    # enroll
                    if path == "/api/v1/access/enroll":
                        # tolerate the user's example that accidentally used '?device=' inside fullname
                        # e.g. ...&fullname=mohamed%2Bamine?device=zk9500
                        def q1(*names: str) -> str:
                            for n in names:
                                v = qs.get(n)
                                if v and len(v) > 0:
                                    return (v[0] or "").strip()
                            return ""

                        user_id = q1("id", "userId", "user_id")
                        finger_id = q1("fingerId", "finger_id")
                        full_name = q1("fullName", "fullname", "name")
                        device = q1("device", "scanner")

                        # fix the "fullname contains ?device=" situation
                        if not device and full_name and "?device=" in full_name:
                            left, right = full_name.split("?device=", 1)
                            full_name = left
                            device = right.strip()

                        result = server.app.begin_remote_enroll(
                            user_id=user_id,
                            finger_id=finger_id,
                            full_name=full_name,
                            device=device or "zk9500",
                        )

                        if result.get("ok"):
                            self._send_json(202, result)
                        else:
                            # conflict / bad request
                            code = int(result.get("status") or 400)
                            self._send_json(code, result)
                        return

                    self._send_json(404, {"ok": False, "error": "Not found", "path": path})
                except Exception as e:
                    self._send_json(500, {"ok": False, "error": str(e)})

            def log_message(self, fmt, *args):
                # Keep console quiet; log into app logger if available
                try:
                    server.app.logger.info("[LocalAPI] " + fmt, *args)
                except Exception:
                    pass

        self._httpd = _AppHTTPServer((self.host, self.port), Handler, app=self.app)

        t = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        t.start()
        self._thread = t

        try:
            self.app.logger.info("LocalAccessApiServer started on http://%s:%s", self.host, self.port)
        except Exception:
            pass

    def stop(self) -> None:
        if not self._httpd:
            return
        try:
            self._httpd.shutdown()
            self._httpd.server_close()
        except Exception:
            pass
        self._httpd = None
        self._thread = None
        try:
            self.app.logger.info("LocalAccessApiServer stopped.")
        except Exception:
            pass

import queue
from types import SimpleNamespace

from app.api import local_access_api_v2


class _FakeScanSession:
    def __init__(self) -> None:
        self._events = queue.Queue()
        self.active = False
        self._events.put({"status": "done", "card": "123456"})

    def start(self, **_kwargs) -> bool:
        self.active = True
        self._events.put({"status": "done", "card": "123456"})
        return True

    def wait_event(self, timeout: float = 1.0):
        try:
            return self._events.get(timeout=timeout)
        except queue.Empty:
            return None

    def is_active(self) -> bool:
        return self.active


class _FakeCtx:
    def __init__(self) -> None:
        self._body = {}
        self.status = None
        self.payload = None
        self.events = []
        self.app = SimpleNamespace()

    def body(self):
        return self._body

    def send_json(self, status, payload):
        self.status = status
        self.payload = payload

    def send_sse_start(self):
        return None

    def send_sse_event(self, event, data):
        self.events.append((event, data))
        return True


def test_scan_start_returns_ok(monkeypatch):
    fake = _FakeScanSession()
    monkeypatch.setattr(local_access_api_v2, "get_scan_session", lambda: fake)
    ctx = _FakeCtx()
    local_access_api_v2._handle_scan_start(ctx)
    assert ctx.status == 200
    assert ctx.payload["ok"] is True


def test_scan_stream_emits_done(monkeypatch):
    fake = _FakeScanSession()
    monkeypatch.setattr(local_access_api_v2, "get_scan_session", lambda: fake)
    ctx = _FakeCtx()
    local_access_api_v2._handle_scan_stream(ctx)
    assert ("scan", {"status": "ready"}) in ctx.events
    assert ("scan", {"status": "done", "card": "123456"}) in ctx.events

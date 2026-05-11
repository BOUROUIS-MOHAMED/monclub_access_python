import threading

import pytest

from app.core.zkemkeeper_scanner import ZkemkeeperError, ZkemkeeperScanner


class _FakeStream:
    def __init__(self, lines: list[str], on_eof) -> None:
        self._lines = list(lines)
        self._index = 0
        self._closed = False
        self._on_eof = on_eof

    def readline(self) -> str:
        if self._index < len(self._lines):
            line = self._lines[self._index]
            self._index += 1
            return line

        if not self._closed:
            self._closed = True
            self._on_eof()
        return ""


class _FakePopen:
    def __init__(self, stdout_lines: list[str], stderr_lines: list[str], returncode: int) -> None:
        self._returncode = returncode
        self.returncode = None
        self._open_streams = 2
        self.terminated = False
        self.killed = False
        self.stdout = _FakeStream(stdout_lines, self._mark_stream_closed)
        self.stderr = _FakeStream(stderr_lines, self._mark_stream_closed)

    def _mark_stream_closed(self) -> None:
        self._open_streams -= 1
        if self._open_streams <= 0 and self.returncode is None:
            self.returncode = self._returncode

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            raise TimeoutError("process still running")
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


def test_read_card_once_waits_for_ready_before_returning_card(monkeypatch) -> None:
    fake_proc = _FakePopen(["READY\n", "CARD:8175134\n"], [], 0)

    monkeypatch.setattr("app.core.zkemkeeper_scanner._find_powershell", lambda: "powershell.exe")
    monkeypatch.setattr("app.core.zkemkeeper_scanner.subprocess.Popen", lambda *args, **kwargs: fake_proc)

    scanner = ZkemkeeperScanner()
    scanner.connect(ip="192.168.0.201", port=4370, timeout_ms=5000)
    ready_calls = []

    assert scanner.read_card_once(poll_sec=5.0, on_ready=lambda: ready_calls.append("ready")) == "8175134"
    assert ready_calls == ["ready"]


def test_read_card_once_returns_empty_when_stop_requested(monkeypatch) -> None:
    fake_proc = _FakePopen([], [], 0)

    monkeypatch.setattr("app.core.zkemkeeper_scanner._find_powershell", lambda: "powershell.exe")
    monkeypatch.setattr("app.core.zkemkeeper_scanner.subprocess.Popen", lambda *args, **kwargs: fake_proc)

    scanner = ZkemkeeperScanner()
    scanner.connect(ip="192.168.0.201", port=4370, timeout_ms=5000)
    stop_event = threading.Event()
    stop_event.set()

    assert scanner.read_card_once(poll_sec=5.0, stop_event=stop_event) == ""


def test_read_card_once_times_out_when_powershell_reports_timeout(monkeypatch) -> None:
    fake_proc = _FakePopen(["READY\n", "TIMEOUT\n"], [], 3)

    monkeypatch.setattr("app.core.zkemkeeper_scanner._find_powershell", lambda: "powershell.exe")
    monkeypatch.setattr("app.core.zkemkeeper_scanner.subprocess.Popen", lambda *args, **kwargs: fake_proc)

    scanner = ZkemkeeperScanner()
    scanner.connect(ip="192.168.0.201", port=4370, timeout_ms=5000)

    with pytest.raises(ZkemkeeperError, match="No card detected"):
        scanner.read_card_once(poll_sec=5.0)


def test_read_card_once_raises_connect_fail(monkeypatch) -> None:
    fake_proc = _FakePopen(["ERROR:CONNECT_FAIL\n"], [], 2)

    monkeypatch.setattr("app.core.zkemkeeper_scanner._find_powershell", lambda: "powershell.exe")
    monkeypatch.setattr("app.core.zkemkeeper_scanner.subprocess.Popen", lambda *args, **kwargs: fake_proc)

    scanner = ZkemkeeperScanner()
    scanner.connect(ip="192.168.0.201", port=4370, timeout_ms=5000)

    with pytest.raises(ZkemkeeperError, match="Cannot connect to SCR100"):
        scanner.read_card_once(poll_sec=5.0)

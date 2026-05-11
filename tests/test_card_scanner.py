from __future__ import annotations
from app.core.card_scanner import validate_card_number, CardScanner, ScannerState


def test_validate_card_number_valid():
    assert validate_card_number("12345678") == "12345678"
    assert validate_card_number("  00123  ") == "00123"
    assert validate_card_number("1") == "1"


def test_validate_card_number_too_long():
    assert validate_card_number("12345678901234567") is None  # 17 digits


def test_validate_card_number_non_numeric():
    assert validate_card_number("abc") is None
    assert validate_card_number("") is None
    assert validate_card_number(None) is None  # type: ignore[arg-type]


def test_validate_card_number_strips_non_digits():
    assert validate_card_number("123-456-789") == "123456789"


def test_scanner_initial_state():
    scanner = CardScanner()
    assert scanner.state == ScannerState.IDLE
    assert scanner.error == ""
    assert scanner.last_result is None


def test_scanner_status_idle():
    scanner = CardScanner()
    status = scanner.get_status()
    assert status["state"] == "idle"
    assert status["error"] == ""
    assert status["lastResult"] is None


def test_scanner_double_start_rejected():
    scanner = CardScanner()
    # Simulate scanning state
    scanner._state = ScannerState.SCANNING
    assert scanner.start_scan(mode="network", ip="192.168.1.201") is False


def test_scanner_double_start_rejected_connecting():
    scanner = CardScanner()
    scanner._state = ScannerState.CONNECTING
    assert scanner.start_scan(mode="network", ip="192.168.1.201") is False


def test_validate_16_digit_card():
    assert validate_card_number("1234567890123456") == "1234567890123456"


def test_validate_empty_string():
    assert validate_card_number("") is None


def test_zkemkeeper_scan_loop_waits_for_ready_before_scanning(monkeypatch):
    from app.core import zkemkeeper_scanner as scanner_module

    calls = []
    states = []

    scanner = CardScanner()

    class FakeZkemkeeperScanner:
        def connect(self, *, ip: str, port: int, timeout_ms: int) -> None:
            calls.append(("connect", ip, port, timeout_ms))

        def read_card_once(self, *, poll_sec: float = 10.0, on_ready=None, stop_event=None) -> str:
            calls.append(("read", poll_sec, stop_event is scanner._stop_event))
            states.append(scanner.state)
            assert on_ready is not None
            on_ready()
            states.append(scanner.state)
            return "8175134"

        def disconnect(self) -> None:
            calls.append(("disconnect",))

    def fake_initialize_com_apartment():
        calls.append(("init",))

        def _cleanup() -> None:
            calls.append(("uninit",))

        return _cleanup

    monkeypatch.setattr(
        scanner_module,
        "initialize_com_apartment",
        fake_initialize_com_apartment,
        raising=False,
    )
    monkeypatch.setattr(scanner_module, "ZkemkeeperScanner", FakeZkemkeeperScanner)
    scanner._state = ScannerState.CONNECTING

    scanner._zkemkeeper_scan_loop("192.168.0.201", 4370, 5000)

    assert calls == [
        ("init",),
        ("connect", "192.168.0.201", 4370, 5000),
        ("read", 5.0, True),
        ("disconnect",),
        ("uninit",),
    ]
    assert states == [ScannerState.CONNECTING, ScannerState.SCANNING]
    assert scanner.last_result is not None
    assert scanner.last_result.card_number == "8175134"
    assert scanner.state == ScannerState.IDLE

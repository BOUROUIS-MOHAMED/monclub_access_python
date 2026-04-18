import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.core import zkemkeeper_scanner as scanner_module
from app.core.zkemkeeper_scanner import ZkemkeeperError, ZkemkeeperScanner


def test_read_card_once_prefers_hid_event() -> None:
    com = SimpleNamespace(
        GetHIDEventCardNumAsStr=MagicMock(return_value=(True, "8175134")),
        GetStrCardNumber=MagicMock(return_value="999"),
    )
    scanner = ZkemkeeperScanner(_com=com)
    assert scanner.read_card_once(poll_sec=0.05) == "8175134"


def test_read_card_once_falls_back_to_getstrcardnumber() -> None:
    com = SimpleNamespace(
        GetHIDEventCardNumAsStr=MagicMock(return_value=(False, "")),
        GetStrCardNumber=MagicMock(return_value="445566"),
    )
    scanner = ZkemkeeperScanner(_com=com)
    assert scanner.read_card_once(poll_sec=0.05) == "445566"


def test_read_card_once_times_out() -> None:
    com = SimpleNamespace(
        GetHIDEventCardNumAsStr=MagicMock(return_value=(False, "")),
        GetStrCardNumber=MagicMock(return_value=""),
    )
    scanner = ZkemkeeperScanner(_com=com)
    with pytest.raises(ZkemkeeperError, match="No card detected"):
        scanner.read_card_once(poll_sec=0.02)


def test_load_com_falls_back_to_comtypes_when_pywin32_missing(monkeypatch) -> None:
    fake_com = object()

    def fake_import_module(name: str):
        if name == "win32com.client":
            raise ModuleNotFoundError("No module named 'win32com'")
        if name == "comtypes.client":
            return types.SimpleNamespace(
                CreateObject=MagicMock(return_value=fake_com)
            )
        raise AssertionError(f"unexpected import: {name}")

    monkeypatch.setattr(scanner_module.importlib, "import_module", fake_import_module)

    scanner = ZkemkeeperScanner()

    assert scanner._load_com() is fake_com


def test_load_com_reports_both_missing_dependencies(monkeypatch) -> None:
    def fake_import_module(name: str):
        raise ModuleNotFoundError(f"No module named '{name}'")

    monkeypatch.setattr(scanner_module.importlib, "import_module", fake_import_module)

    scanner = ZkemkeeperScanner()

    with pytest.raises(ZkemkeeperError, match="pywin32 or comtypes"):
        scanner._load_com()

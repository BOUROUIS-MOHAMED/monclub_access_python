from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

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

import types

import pytest

from app.core.zkemkeeper_scanner import ZkemkeeperError, ZkemkeeperScanner


def test_missing_pywin32_raises_clear_error(monkeypatch):
    monkeypatch.setitem(__import__("sys").modules, "win32com", None)
    with pytest.raises(ZkemkeeperError) as exc:
        ZkemkeeperScanner().connect(ip="192.168.0.10", port=4370, timeout_ms=3000)
    assert "pywin32" in str(exc.value).lower()


def test_connect_and_read_card(monkeypatch):
    fake = types.SimpleNamespace()
    fake.Connect_Net = lambda ip, port: True
    fake.GetRTLog = lambda *args, **kwargs: (
        True,
        "0",
        "1234567",
        "0",
        "1",
        "0",
        "0",
        "0",
    )

    class FakeClient:
        def Dispatch(self, _progid):
            return fake

    fake_client_mod = types.SimpleNamespace(Dispatch=FakeClient().Dispatch)
    monkeypatch.setitem(__import__("sys").modules, "win32com.client", fake_client_mod)
    monkeypatch.setitem(
        __import__("sys").modules,
        "win32com",
        types.SimpleNamespace(client=fake_client_mod),
    )

    scanner = ZkemkeeperScanner()
    scanner.connect(ip="192.168.0.10", port=4370, timeout_ms=3000)
    card = scanner.read_card_once()
    assert card == "1234567"

"""An access panel set to ZK_STANDALONE is refused before RegEvent.

[FIELD 2026-11-09] A gym's "Tourniquet 1" was an inBio panel (GetPlatform
"ZEM560_InBIO", product ACP-260) configured in the dashboard as ZK_STANDALONE.
In plain 32-bit PowerShell, with no MonClub code, Connect_Net + RegEvent(1, 1) +
ReadRTLog(1) ended the process with 0xC0000374 (heap corruption in the vendor SDK);
without RegEvent it did not. In the app the engine died seconds after every connect,
so the window went white and every page said "Failed to fetch".

The guard reads the platform right after Connect_Net and, for an inBio panel,
disconnects and fails the connect without ever calling RegEvent.
"""
from __future__ import annotations

from typing import List
from unittest.mock import MagicMock

import pytest

from app.sdk.zk_standalone import ZKStandaloneDevice, access_panel_reason


class _Zkem:
    def __init__(self, *, platform="ZMM220_TFT", platform_raises=False):
        self.calls: List[str] = []
        self._platform = platform
        self._platform_raises = platform_raises

    def SetCommPassword(self, key):
        return True

    def Connect_Net(self, ip, port):
        self.calls.append("Connect_Net")
        return True

    def GetPlatform(self, machine, out):
        self.calls.append("GetPlatform")
        if self._platform_raises:
            raise RuntimeError("not supported")
        # The tuple shape pywin32 returns for a BSTR* out-param.
        return (True, self._platform)

    def RegEvent(self, machine, mask):
        self.calls.append("RegEvent")
        return True

    def EnableDevice(self, machine, enable):
        self.calls.append("EnableDevice")
        return True

    def Disconnect(self):
        self.calls.append("Disconnect")


def _driver():
    drv = ZKStandaloneDevice(
        {"id": 11, "name": "Tourniquet 1", "ipAddress": "192.168.1.201", "portNumber": 4370},
        logger=MagicMock(),
    )
    drv._read_fp_version = lambda _zk: "10"        # type: ignore[method-assign]
    drv._read_device_status = lambda _zk: {}       # type: ignore[method-assign]
    drv._warn_if_device_full = lambda: None        # type: ignore[method-assign]
    return drv


class TestAccessPanelReason:
    @pytest.mark.parametrize("platform", ["ZEM560_InBIO", "zem560_inbio", "InBIO460"])
    def test_inbio_platforms_are_refused(self, platform):
        assert access_panel_reason(platform)

    @pytest.mark.parametrize("platform", ["", None, "ZMM220_TFT", "ZLM60_TFT", "JZ4725_TFT"])
    def test_other_or_unknown_platforms_pass(self, platform):
        assert access_panel_reason(platform) is None


class TestConnectRefusesAnInBioPanel:
    def test_the_field_panel_is_refused_and_never_registers_events(self):
        drv = _driver()
        zk = _Zkem(platform="ZEM560_InBIO")

        assert drv._do_connect(zk) is False
        assert "RegEvent" not in zk.calls, "RegEvent on an inBio panel crashes the process"
        assert "Disconnect" in zk.calls
        assert not any(c == "EnableDevice" for c in zk.calls)

    def test_the_refusal_is_logged_as_an_error_naming_the_fix(self):
        drv = _driver()
        drv._do_connect(_Zkem(platform="ZEM560_InBIO"))

        msg = drv.logger.error.call_args[0][0] % drv.logger.error.call_args[0][1:]
        assert "ZK_PULLSDK" in msg and "ZEM560_InBIO" in msg

    def test_platform_is_read_before_regevent(self):
        drv = _driver()
        zk = _Zkem()

        assert drv._do_connect(zk) is True
        assert zk.calls.index("GetPlatform") < zk.calls.index("RegEvent")

    def test_an_unreadable_platform_never_blocks_a_terminal(self):
        drv = _driver()
        zk = _Zkem(platform_raises=True)

        assert drv._do_connect(zk) is True
        assert "RegEvent" in zk.calls

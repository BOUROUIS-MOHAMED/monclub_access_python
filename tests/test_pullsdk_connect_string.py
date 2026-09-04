"""The PullSDK connection string must contain exactly what the log claims it does.

WHY THIS FILE EXISTS
--------------------
``PullSDK.connect()`` used to accept a ``platform`` keyword. The FIRST version of the
file appended it to the connection string::

    if platform and str(platform).strip():
        parts.append(f"platform={str(platform).strip()}")

Commit 0548a1d removed that append but left BOTH the signature and this log fragment::

    (f",platform={platform}" if platform else ""),

So for every release since, a caller could pass ``platform=...``, the INFO log would
render ``,platform=X`` as though it had been sent, and the bytes handed to
``plcommpro.dll`` would never contain it. ``PullSDKDevice.connect()`` did pass a real
value, so a caller genuinely depended on an effect that did not occur.

The parameter was REMOVED rather than re-wired, because the DLL has no such key:
every one of the 101 ``plcommpro.dll`` copies in this repo is the same build
(sha256 82bda08d..., 254464 bytes) and contains ZERO occurrences of the byte string
"platform" in any casing, while its connection-key table sits contiguously in .rdata
as ``ipaddress port deviceid baudrate passwd protocol``.

These tests pin the invariant that actually matters -- **the log must not claim
anything the connection string does not carry** -- rather than just the absence of one
keyword, so the next person to add a connection option cannot recreate the same class
of bug.
"""

from __future__ import annotations

import inspect
import logging
import re

import pytest

from app.sdk.pullsdk import PullSDK, PullSDKDevice


class _RecordingLogger:
    """Captures the rendered INFO lines so we can compare them to the real bytes."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def _record(self, msg, *args):
        try:
            self.lines.append(str(msg) % args if args else str(msg))
        except Exception:  # pragma: no cover - a format mismatch is its own failure
            self.lines.append(f"{msg!r} % {args!r}")

    info = _record
    debug = _record
    warning = _record
    error = _record

    def exception(self, msg, *args, **kw):  # pragma: no cover
        self._record(msg, *args)


class _FakeDLL:
    """Stands in for plcommpro.dll, capturing the exact bytes passed to Connect()."""

    def __init__(self) -> None:
        self.conn_str: bytes | None = None

    def Connect(self, conn_str_bytes):
        self.conn_str = conn_str_bytes
        return 0x1234  # a truthy handle

    def Disconnect(self, _h):
        return 0

    def PullLastError(self):  # pragma: no cover - only on the failure path
        return 0


def _connected_sdk():
    """A PullSDK wired to a fake DLL, with load() neutralised."""
    logger = _RecordingLogger()
    sdk = PullSDK("fake.dll", logger)
    dll = _FakeDLL()
    sdk._dll = dll  # bypass the real WinDLL load
    sdk.load = lambda: None  # type: ignore[method-assign]
    return sdk, dll, logger


class TestConnectionStringContents:
    def test_connect_string_carries_the_five_documented_keys(self):
        sdk, dll, _ = _connected_sdk()
        sdk.connect(ip="192.168.1.201", port=4370, timeout_ms=3000, password="secret")

        assert dll.conn_str is not None, "Connect() was never called"
        sent = dll.conn_str.decode("mbcs")
        assert sent == (
            "protocol=TCP,ipaddress=192.168.1.201,port=4370,timeout=3000,passwd=secret"
        )

    def test_connect_string_never_contains_platform(self):
        """The regression itself: plcommpro.dll has no `platform` connection key."""
        sdk, dll, _ = _connected_sdk()
        sdk.connect(ip="10.0.0.5", port=4370, timeout_ms=3000, password="")

        assert b"platform" not in (dll.conn_str or b"").lower()

    def test_connect_no_longer_accepts_a_platform_argument(self):
        """A caller passing it must fail loudly, not be silently ignored.

        Silent acceptance is exactly what made the original bug survive releases.
        """
        sdk, _, _ = _connected_sdk()
        with pytest.raises(TypeError):
            sdk.connect(  # type: ignore[call-arg]
                ip="10.0.0.5", port=4370, timeout_ms=3000, password="", platform="X"
            )

    def test_platform_is_not_in_the_signature(self):
        params = inspect.signature(PullSDK.connect).parameters
        assert "platform" not in params
        assert set(params) == {"self", "ip", "port", "timeout_ms", "password"}


class TestLogMatchesTheWire:
    """The invariant that generalises: the log must not overstate the wire."""

    def test_logged_keys_are_exactly_the_sent_keys(self):
        sdk, dll, logger = _connected_sdk()
        sdk.connect(ip="192.168.1.201", port=4370, timeout_ms=3000, password="hunter2")

        sent = (dll.conn_str or b"").decode("mbcs")
        sent_keys = {p.split("=", 1)[0] for p in sent.split(",") if "=" in p}

        connect_lines = [ln for ln in logger.lines if "PullSDK Connect:" in ln]
        assert connect_lines, "the connect line was not logged"
        logged = connect_lines[0].split("PullSDK Connect:", 1)[1]
        logged_keys = {
            m.group(1) for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)=", logged)
        }

        assert logged_keys == sent_keys, (
            "the connect log advertises keys the panel never received (or omits ones "
            f"it did): logged={sorted(logged_keys)} sent={sorted(sent_keys)}"
        )

    def test_password_is_masked_in_the_log_but_real_on_the_wire(self):
        sdk, dll, logger = _connected_sdk()
        sdk.connect(ip="10.0.0.5", port=4370, timeout_ms=3000, password="hunter2")

        line = next(ln for ln in logger.lines if "PullSDK Connect:" in ln)
        assert "hunter2" not in line
        assert "passwd=hunter2" in (dll.conn_str or b"").decode("mbcs")


class TestDriverDoesNotPlumbPlatform:
    def test_driver_does_not_pass_platform_to_the_low_level_connect(self):
        """PullSDKDevice.connect() must not resurrect the dead keyword."""
        src = inspect.getsource(PullSDKDevice.connect)
        assert "platform=" not in src

    def test_driver_exposes_no_platform_attribute(self):
        """The attribute existed only to feed the dropped parameter.

        The backend `platform` field and its UI display are deliberately untouched --
        this asserts only that the DRIVER no longer implies it reaches the SDK.
        """
        drv = PullSDKDevice({"id": 1, "name": "d", "ipAddress": "10.0.0.5",
                             "portNumber": 4370, "platform": "PULLSDK"},
                            logger=logging.getLogger("test-pullsdk-connect"))
        assert not hasattr(drv, "platform")

    def test_a_payload_carrying_platform_still_constructs_and_is_ignored(self):
        """Backward compatibility: the extra key must not break construction."""
        drv = PullSDKDevice({"id": 7, "name": "Entree", "ipAddress": "192.168.1.201",
                             "portNumber": 4370, "password": "", "platform": "PULLSDK",
                             "devicePlatform": "anything"},
                            logger=logging.getLogger("test-pullsdk-connect"))
        assert drv.ip == "192.168.1.201"
        assert drv.port == 4370
        assert drv.is_connected is False

"""The plcommpro session handle must never be freed under an in-flight call.

``PullSDK._h`` is a RAW native pointer. Every SDK wrapper captures it into a
local before entering the DLL::

    h = self._require_handle()
    ...
    rc = int(self._dll.GetRTLogExt(c_void_p(h), buf, sz))

so setting ``_h = None`` fences nothing that is already inside plcommpro.dll.

Both poll watchdogs -- ``ultra_engine._poll_with_watchdog`` and the inline one in
``realtime_agent`` -- give up on a blocked poll, LEAVE that thread running, and
then call ``disconnect()`` from another thread, deliberately: the comment said
"the SDK disconnect should unblock the orphan thread". Freeing the session that
way is a use-after-free in native code -- the DLL goes on to write the RTLog
payload through a context that has been released. It is the same class of defect,
with the same delayed access-violation signature, as the zkemkeeper apartment
teardown fixed in test_zk_standalone_com_teardown.py.

``disconnect()`` was also the ONLY method on PullSDKDevice that skipped
``_sdk_lock`` -- and simply adding that lock is not the fix, because it would
block the watchdog forever behind the very call it is trying to escape.

The invariant here: no ``Disconnect(h)`` while a call holding ``h`` is in flight;
the free is handed to whoever leaves last.

NOTE ON SCOPE: these are the PullSDK (C2/C3/C4/inBio) paths. They are NOT
exercised by the ZK_STANDALONE/zkemkeeper terminals at the gym whose crash
prompted this work -- their ``poll_rtlog_once`` is a queue drain that cannot
block. This fix is unvalidated against real PullSDK hardware.
"""

from __future__ import annotations

import threading
from unittest.mock import MagicMock

import pytest

from app.sdk.pullsdk import PullSDK


class _FakeDll:
    """Records native calls; GetRTLogExt can be made to block on demand."""

    def __init__(self):
        self.calls: list = []
        self.block = threading.Event()      # set -> let a blocked call finish
        self.entered = threading.Event()    # set once a call is inside
        self.disconnected: list = []

    def Disconnect(self, h):
        # h arrives as c_void_p; .value is the raw integer.
        self.disconnected.append(getattr(h, "value", h))
        self.calls.append("Disconnect")
        return 0

    def GetRTLogExt(self, h, buf, sz):
        self.calls.append("GetRTLogExt")
        self.entered.set()
        self.block.wait(timeout=10)
        return 0

    # get_rtlog_ext_text checks hasattr(self._dll, "GetRTLogExt")


def _sdk(dll: _FakeDll, handle: int = 0x1234) -> PullSDK:
    s = PullSDK(dll_path="fake.dll", logger=MagicMock())
    s._dll = dll
    s._h = handle
    s.load = lambda: None          # type: ignore[method-assign]
    return s


class TestDisconnectIsDeferredWhileACallIsInFlight:
    def test_no_native_disconnect_while_a_call_holds_the_handle(self):
        """The core invariant. Fails against the pre-fix code."""
        dll = _FakeDll()
        sdk = _sdk(dll)

        t = threading.Thread(target=lambda: sdk.get_rtlog_ext_text(), daemon=True)
        t.start()
        assert dll.entered.wait(timeout=5), "the fake call never started"

        # Another thread (the watchdog) gives up and disconnects.
        sdk.disconnect()

        assert dll.disconnected == [], (
            "Disconnect() ran while GetRTLogExt was still inside the DLL -- "
            "that is the use-after-free"
        )

        # Let the in-flight call finish; the deferred free must happen then.
        dll.block.set()
        t.join(timeout=5)
        assert not t.is_alive()
        assert dll.disconnected == [0x1234], (
            f"the deferred free did not run when the last caller returned: {dll.disconnected}"
        )

    def test_handle_is_invalidated_immediately_so_no_new_call_can_take_it(self):
        """Deferring the FREE must not mean deferring the INVALIDATION."""
        dll = _FakeDll()
        sdk = _sdk(dll)

        t = threading.Thread(target=lambda: sdk.get_rtlog_ext_text(), daemon=True)
        t.start()
        assert dll.entered.wait(timeout=5)

        sdk.disconnect()

        assert sdk._h is None
        with pytest.raises(Exception):
            sdk.set_device_data(table="user", data="x=1")

        dll.block.set()
        t.join(timeout=5)

    def test_disconnect_with_nothing_in_flight_frees_immediately(self):
        """The ordinary path must not regress into a deferred free."""
        dll = _FakeDll()
        sdk = _sdk(dll)

        sdk.disconnect()

        assert dll.disconnected == [0x1234]
        assert sdk._h is None

    def test_second_disconnect_is_a_noop(self):
        dll = _FakeDll()
        sdk = _sdk(dll)
        sdk.disconnect()
        sdk.disconnect()
        assert dll.disconnected == [0x1234], "double free"

    def test_lease_is_released_even_when_the_call_raises(self):
        """A leaked lease would defer the free forever."""
        dll = _FakeDll()
        sdk = _sdk(dll)

        def _boom(h, table, data, options):
            raise RuntimeError("SDK exploded")

        dll.SetDeviceData = _boom
        with pytest.raises(Exception):
            sdk.set_device_data(table="user", data="x=1")

        assert sdk.has_inflight_calls() is False
        sdk.disconnect()
        assert dll.disconnected == [0x1234], "the free was deferred by a leaked lease"


class TestEveryHandleUserTakesALease:
    """A method that enters the DLL without a lease reopens the whole defect."""

    def test_all_require_handle_methods_are_decorated(self):
        import ast
        import pathlib

        import app.sdk.pullsdk as mod

        tree = ast.parse(pathlib.Path(mod.__file__).read_text(encoding="utf-8"))
        cls = next(n for n in tree.body
                   if isinstance(n, ast.ClassDef) and n.name == "PullSDK")

        undecorated = []
        for node in cls.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            if node.name == "_require_handle":
                continue
            body = ast.dump(node)
            if "_require_handle" not in body:
                continue
            names = {getattr(d, "id", "") for d in node.decorator_list}
            if "_holds_handle" not in names:
                undecorated.append(node.name)

        assert not undecorated, (
            f"these methods enter plcommpro.dll holding the session handle but take no "
            f"lease, so disconnect() could free it underneath them: {undecorated}"
        )


class TestInflightAccounting:
    def test_concurrent_calls_both_have_to_return_before_the_free(self):
        dll = _FakeDll()
        sdk = _sdk(dll)

        started = threading.Barrier(3, timeout=10)

        def _one():
            sdk._enter_handle_use()
            started.wait()
            release.wait(timeout=10)
            sdk._exit_handle_use()

        release = threading.Event()
        threads = [threading.Thread(target=_one, daemon=True) for _ in range(2)]
        for t in threads:
            t.start()
        started.wait()

        sdk.disconnect()
        assert dll.disconnected == []

        release.set()
        for t in threads:
            t.join(timeout=5)

        assert dll.disconnected == [0x1234], (
            "the free must run exactly once, when the LAST holder leaves"
        )

    def test_exit_without_enter_does_not_go_negative(self):
        dll = _FakeDll()
        sdk = _sdk(dll)
        sdk._exit_handle_use()
        assert sdk.has_inflight_calls() is False
        sdk.disconnect()
        assert dll.disconnected == [0x1234]

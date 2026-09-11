"""The COM teardown ORDER invariant for the zkemkeeper STA thread.

Background -- this is the bug that crashed the gym PC roughly every 30 minutes
(Windows Application Error, faulting module ntdll.dll, exception code
0xc0000005), always within ~20s of the ``CONN_REFRESH`` / "persistent
connection: safety refresh after 1800s" line in app.log:

  ``DispatchWithEvents`` returns a pywin32 ``EventsProxy``. Its ``__del__``
  calls ``_obj_.close()``, and the makepy-generated ``close()`` runs
  ``cp.Unadvise(cookie)`` on the connection point before the final ``IDispatch``
  ``Release``. If the driver's ``zk`` reference is still alive when
  ``CoUninitialize()`` runs, both of those land in an apartment that no longer
  exists -- corrupting the heap, which ntdll then faults on at the next
  significant alloc/free (in practice the *next* STA thread's
  ``CoInitialize``/``DispatchWithEvents``, seconds later).

So the invariant under test is an ORDER, not an outcome: on EVERY path out of
``_sta_main``, the COM object must be Disconnected, ``close()``d (Unadvise) and
dropped BEFORE ``CoUninitialize``. "The driver still works" does not test this;
only the recorded call sequence does.
"""
from __future__ import annotations

import gc
import time
import weakref
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from app.sdk.zk_standalone import _Cmd, ZKStandaloneDevice


class _RecordingZkem:
    """Minimal fake zkemkeeper that records teardown calls into a shared trace."""

    def __init__(self, trace: List[str]):
        self._trace = trace
        self.close_calls = 0

    # --- connect surface (enough for _do_connect to succeed) ---
    def SetCommPassword(self, key):
        return True

    def Connect_Net(self, ip, port):
        self._trace.append("Connect_Net")
        return True

    def RegEvent(self, machine, mask):
        return True

    def ReadRTLog(self, machine):
        return False

    def GetRTLog(self, machine):
        return False

    # --- teardown surface: the part that matters ---
    def Disconnect(self):
        self._trace.append("Disconnect")

    def close(self):
        # The real makepy-generated close() nulls _olecp before Unadvise, so a
        # second call is a no-op. Model that, because the driver's explicit
        # close() is necessarily followed by EventsProxy.__del__ calling it again.
        self.close_calls += 1
        self._trace.append("close" if self.close_calls == 1 else "close:noop")


def _make_recording_driver(payload_extra: Dict[str, Any] | None = None):
    """Driver wired to a fake COM object, with every COM-runtime hook traced."""
    trace: List[str] = []
    payload = {
        "id": 9, "name": "Entree 1", "ipAddress": "192.168.9.10", "portNumber": 4370,
    }
    payload.update(payload_extra or {})
    drv = ZKStandaloneDevice(payload, logger=MagicMock())
    zk = _RecordingZkem(trace)

    drv._com_factory = lambda: zk
    drv._co_init = lambda: trace.append("CoInitialize")
    drv._co_uninit = lambda: trace.append("CoUninitialize")
    drv._pump = lambda: None
    drv._refresh_pin_card_map = lambda: None            # type: ignore[method-assign]
    drv._read_device_status = lambda _zk: {}            # type: ignore[method-assign]
    drv._read_fp_version = lambda _zk: ""               # type: ignore[method-assign]
    drv._warn_if_device_full = lambda: None             # type: ignore[method-assign]
    return drv, zk, trace


def _walk_tb(tb):
    """Yield every traceback entry in a chain (empty when it has been stripped)."""
    while tb is not None:
        yield tb
        tb = tb.tb_next


def _assert_teardown_order(trace: List[str], *, expect_connected: bool = True) -> None:
    """The whole point of this module: close() strictly before CoUninitialize."""
    assert "CoUninitialize" in trace, f"apartment was never torn down: {trace}"
    uninit = trace.index("CoUninitialize")

    if expect_connected:
        assert "close" in trace, (
            "the COM event sink was never Unadvise()d -- EventsProxy.__del__ would "
            f"do it AFTER CoUninitialize, which is the 0xc0000005 crash: {trace}"
        )
        assert trace.index("close") < uninit, (
            "close()/Unadvise ran AFTER CoUninitialize -- this is exactly the "
            f"apartment-outlived-by-its-COM-object crash: {trace}"
        )
        assert "Disconnect" in trace and trace.index("Disconnect") < trace.index("close"), (
            f"Disconnect must precede Unadvise: {trace}"
        )

    # Nothing COM-ish may follow the apartment teardown.
    assert all(ev in ("CoUninitialize", "close:noop") for ev in trace[uninit:]), (
        f"COM work recorded after CoUninitialize: {trace[uninit:]} (full: {trace})"
    )


class TestComTeardownOrdering:
    def test_clean_disconnect_unadvises_before_couninitialize(self):
        """The ordinary path: the 1800s safety refresh calling disconnect()."""
        drv, zk, trace = _make_recording_driver()
        assert drv.connect() is True
        drv.disconnect()

        assert drv._sta_thread is None
        _assert_teardown_order(trace)

    def test_teardown_order_holds_when_never_connected(self):
        """Thread started but no COM object was ever built -- must still be clean."""
        drv, zk, trace = _make_recording_driver()
        drv._ensure_sta_thread()
        time.sleep(0.1)
        drv.disconnect()

        _assert_teardown_order(trace, expect_connected=False)
        assert "close" not in trace          # nothing to unadvise
        assert trace == ["CoInitialize", "CoUninitialize"]

    def test_superseded_generation_exit_still_unadvises_first(self):
        """_abandon_sta_thread bumps the gen; the zombie must tear down correctly.

        Without the fix this is a SECOND crash site: the abandoned thread
        eventually reaches the same finally block.
        """
        drv, zk, trace = _make_recording_driver()
        assert drv.connect() is True
        t = drv._sta_thread
        assert t is not None

        drv._abandon_sta_thread("simulated wedge")     # bumps _sta_gen
        t.join(timeout=5.0)
        assert not t.is_alive(), "superseded STA thread never exited"

        _assert_teardown_order(trace)

    def test_handed_back_command_exit_still_unadvises_first(self):
        """Gen changes BETWEEN the top-of-loop check and the dequeue.

        Driven deterministically by bumping the generation from inside the
        queue's get(), which is precisely the window the driver guards against.
        """
        drv, zk, trace = _make_recording_driver()

        class _GenBumpingQueue:
            """Bumps the STA generation as it hands back a `get_time` command.

            Installed before connect() so the STA thread can never be parked
            inside the *inner* queue when the swap happens -- otherwise the
            command is dequeued behind the wrapper's back and the window this
            test exists to cover is silently skipped.
            """

            def __init__(self, inner):
                self._inner = inner

            def get(self, *a, **kw):
                cmd = self._inner.get(*a, **kw)
                if getattr(cmd, "op", None) == "get_time":
                    drv._sta_gen += 1        # supersede, mid-dequeue
                return cmd

            def __getattr__(self, name):
                return getattr(self._inner, name)

        drv._cmd_queue = _GenBumpingQueue(drv._cmd_queue)   # type: ignore[assignment]
        assert drv.connect() is True
        t = drv._sta_thread
        assert t is not None

        # Exists only to be handed back to the (nonexistent) successor thread.
        drv._cmd_queue.put(_Cmd("get_time"))

        t.join(timeout=5.0)
        assert not t.is_alive(), "handed-back-command STA thread never exited"

        _assert_teardown_order(trace)

    @pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
    def test_unexpected_exception_exit_still_unadvises_first(self):
        """A BaseException escaping the loop must not skip the COM teardown.

        The KeyboardInterrupt is deliberate, so its unhandled-thread warning is
        expected noise rather than a signal.
        """
        drv, zk, trace = _make_recording_driver()
        assert drv.connect() is True
        t = drv._sta_thread
        assert t is not None

        def _boom():
            raise KeyboardInterrupt("simulated hard interrupt")

        drv._pump = _boom          # not caught by `except Exception`
        t.join(timeout=5.0)
        assert not t.is_alive(), "STA thread survived a BaseException"

        _assert_teardown_order(trace)

    def test_a_failed_op_does_not_export_the_com_object_to_the_caller(self):
        """A raising op must not hand its ``zk``-bound frame across the thread boundary.

        The dispatch loop stores ``cmd.error = exc`` and ``_call`` re-raises that
        SAME object on the CALLING thread. An exception carries its frames on
        ``__traceback__``, so a ``_do_*`` that takes ``zk`` and lets an error escape
        keeps the COM proxy alive on the caller's stack -- for exactly as long as
        that thread holds the exception, e.g. while logging it.

        ``zk = None; gc.collect()`` in the STA teardown cannot free an object that
        still has a live referrer on another thread, and the finally block never
        checks: CoUninitialize runs regardless, and the final Release lands on the
        wrong thread after the apartment is gone. That is the 0xc0000005 this file
        exists to prevent, reached through a failed door-unlock instead of the
        ordinary refresh.

        ``_do_open_door`` is the real instance -- the one ``_do_*`` with no
        try/except of its own -- but the guard belongs to the dispatch loop, so
        this pins it there and covers every op.
        """
        drv, zk, trace = _make_recording_driver()
        assert drv.connect() is True

        def _boom(zk, delay_ds):           # noqa: ARG001 - zk bound ON PURPOSE
            raise RuntimeError("simulated ACUnlock COM failure")

        drv._do_open_door = _boom          # type: ignore[method-assign]

        held: List[BaseException] = []
        try:
            drv._call("open_door", args={"delay_ds": 5}, timeout=5.0)
        except Exception as exc:           # what open_door's own handler does
            held.append(exc)

        assert held, "the failing op did not surface an error to the caller"

        ref = weakref.ref(zk)
        drv._com_factory = lambda: None
        del zk

        # The caller is STILL holding the exception here -- that is the whole
        # point. Teardown must survive it.
        drv.disconnect()
        gc.collect()

        assert ref() is None, (
            "the caller's exception still reaches the COM object (via "
            "__traceback__ -> the failing op's frame -> zk), so its final Release "
            "would run on the wrong thread after CoUninitialize"
        )
        assert held[0].__traceback__ is None or not any(
            "zk" in (tb.tb_frame.f_locals or {})
            for tb in _walk_tb(held[0].__traceback__)
        ), "a frame holding `zk` is still reachable from the caller's exception"
        _assert_teardown_order(trace)

    def test_com_object_reference_is_dropped_before_couninitialize(self):
        """No strong reference to the COM object may survive into CoUninitialize.

        Guards the ``zk = None`` half of the fix: close() alone still leaves the
        IDispatch Release owed until after the apartment is gone.
        """
        drv, zk, trace = _make_recording_driver()
        assert drv.connect() is True

        ref = weakref.ref(zk)
        drv._com_factory = lambda: None        # drop the closure's strong ref
        del zk

        drv.disconnect()
        gc.collect()

        assert ref() is None, (
            "the STA thread still holds the COM object after teardown -- its final "
            "Release would run outside the apartment"
        )
        _assert_teardown_order(trace)

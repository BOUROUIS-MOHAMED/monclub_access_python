"""A terminal must never stay locked because a push died mid-bracket (F13).

THE DEFECT
----------
The 22:00 / manual full reconcile brackets the WHOLE roster in
``EnableDevice(1, False)`` -- deliberately, so the roster is one atomic command.
The driver's own docstring says what that costs::

    bracket_enable_device: ONLY the 22:00/manual full reconcile may set this --
    EnableDevice(False) locks the terminal UI and it is the gym's sole verifier.

The re-enable lives in a ``finally``, which covers a normal exception. It does NOT
cover the two failure modes this driver actually has:

  * the STA thread **wedges** on a COM call inside the bracket -- the zombie never
    reaches the ``finally`` (``_PUSH_MAX_CONSECUTIVE_WEDGES`` exists precisely
    because wedging is a real, observed state), or
  * the **process crashes** mid-bracket.

Either way the terminal stays locked. And a failed re-enable was only appended to a
5-entry capped ``errors`` list -- it did not affect ``ok``, there was no ERROR-level
alarm, and ``_do_connect`` had no safety net. So the lockout persisted until the
NEXT bracketed push completed end to end: the following night, or a manual trigger.
For a gym whose MB2000 is the only thing on the door, that is the whole day.

THE FIX, and why it is the connect path
---------------------------------------
``EnableDevice(1, True)`` is idempotent -- enabling an enabled terminal is a no-op --
so it is safe to issue unconditionally on every successful connect. That turns every
reconnection into a recovery: the 1800 s CONN_REFRESH, the wedge-recovery reconnect
inside ``push_roster``, and a worker restart all now un-stick a locked terminal.

The bound on a lockout therefore drops from "until the next nightly bracket" to
"until the next reconnect".

A failed re-enable is also escalated to ERROR with telemetry, because the capped
errors list was not something anyone would find.
"""
from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from app.sdk.zk_standalone import ZKStandaloneDevice


class _Zkem:
    """Fake zkemkeeper recording the calls this test cares about."""

    def __init__(self, *, connect_ok=True, enable_raises=False):
        self.calls: List[str] = []
        self._connect_ok = connect_ok
        self._enable_raises = enable_raises
        self.enable_args: List[Any] = []

    def SetCommPassword(self, key):
        return True

    def Connect_Net(self, ip, port):
        self.calls.append("Connect_Net")
        return self._connect_ok

    def RegEvent(self, machine, mask):
        self.calls.append("RegEvent")
        return True

    def EnableDevice(self, machine, enable):
        self.calls.append(f"EnableDevice({enable})")
        self.enable_args.append(enable)
        if self._enable_raises:
            raise RuntimeError("terminal refused EnableDevice")
        return True


def _driver(**kw):
    drv = ZKStandaloneDevice(
        {"id": 9, "name": "Entree 1", "ipAddress": "192.168.9.10", "portNumber": 4370},
        logger=MagicMock(),
    )
    drv._read_fp_version = lambda _zk: "10"        # type: ignore[method-assign]
    drv._read_device_status = lambda _zk: {}       # type: ignore[method-assign]
    drv._warn_if_device_full = lambda: None        # type: ignore[method-assign]
    return drv


class TestConnectReleasesAnyStuckLock:
    def test_a_successful_connect_re_enables_the_terminal(self):
        """The recovery net. Without it, a terminal locked by a wedged or crashed
        bracket stays locked until the next nightly reconcile."""
        drv = _driver()
        zk = _Zkem()

        assert drv._do_connect(zk) is True
        assert "EnableDevice(True)" in zk.calls, (
            "every successful connect must clear a possible stuck lock"
        )

    def test_it_is_issued_with_the_enable_flag_not_the_disable_flag(self):
        """Getting this argument backwards would LOCK every terminal on connect --
        the worst possible regression for this fix."""
        drv = _driver()
        zk = _Zkem()

        drv._do_connect(zk)

        assert zk.enable_args == [True]
        assert False not in zk.enable_args

    def test_a_failed_connect_does_not_touch_the_device(self):
        drv = _driver()
        zk = _Zkem(connect_ok=False)

        assert drv._do_connect(zk) is False
        assert not any(c.startswith("EnableDevice") for c in zk.calls)

    def test_a_refused_re_enable_does_not_break_the_connect(self):
        """Best-effort: the connection is still usable, and the next reconnect
        tries again. Failing the connect over it would be worse -- the worker would
        never come up to retry."""
        drv = _driver()
        zk = _Zkem(enable_raises=True)

        assert drv._do_connect(zk) is True

    def test_the_unlock_precedes_normal_use(self):
        """It must happen on connect, not lazily before a push: a locked terminal
        with no push scheduled would otherwise stay locked indefinitely."""
        drv = _driver()
        zk = _Zkem()

        drv._do_connect(zk)

        assert zk.calls.index("EnableDevice(True)") > zk.calls.index("Connect_Net")

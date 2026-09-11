"""A wedged poll thread must not stop the device being polled ever again.

This is the half of the PullSDK handle fix that makes the other half safe.

``PullSDK.disconnect()`` no longer frees the native session while a call is
inside the DLL -- doing that was a use-after-free (see
test_pullsdk_handle_lifetime.py). But the poll watchdogs USED that free as their
recovery mechanism: the comment at the top of ``_poll_with_watchdog`` says "the
SDK disconnect should unblock the orphan thread", and on that basis the method
returned ``None`` every cycle for as long as the old thread was alive, refusing
to start another.

Deferring the free without changing that would have been strictly WORSE than the
bug it fixed: nothing unblocks the orphan any more, so the device would never be
polled again -- a turnstile that is silently dead rather than one that crashes.

So the watchdog now retires a hung poll thread as a BOUNDED orphan and polls on
the fresh connection the run loop has already rebuilt. These tests pin that:
progress continues while an orphan is stuck, and orphans cannot accumulate
without limit.
"""

from __future__ import annotations

import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.core.ultra_engine import UltraDeviceWorker

_KEEP_ALIVE: list = []


def _never_ending_thread() -> threading.Thread:
    """A live thread standing in for a poll wedged inside the SDK."""
    stop = threading.Event()
    t = threading.Thread(target=stop.wait, daemon=True)
    t.start()
    _KEEP_ALIVE.append(stop)          # released by the session-end fixture
    return t


@pytest.fixture(scope="session", autouse=True)
def _release_stand_in_threads():
    yield
    for stop in _KEEP_ALIVE:
        stop.set()


class _BlockingDriver:
    """poll_rtlog_once blocks until released -- a wedged plcommpro call."""

    def __init__(self):
        self.release = threading.Event()
        self.entered = threading.Event()
        self.calls = 0

    def poll_rtlog_once(self):
        self.calls += 1
        self.entered.set()
        self.release.wait(timeout=30)
        return []


class _LiveDriver:
    """A healthy replacement, as the run loop's reconnect would produce."""

    def __init__(self, events=None):
        self.events = events if events is not None else [{"cardNo": "1"}]
        self.calls = 0

    def poll_rtlog_once(self):
        self.calls += 1
        return list(self.events)


def _worker(sdk) -> SimpleNamespace:
    """The exact attribute surface _poll_with_watchdog touches."""
    return SimpleNamespace(
        _sdk=sdk,
        _device_id=8,
        _prefix="[ULTRA:8]",
        _poll_timeout_sec=0.3,          # keep the tests fast
        _poll_ema_ms=0.0,
        _watchdog_thread=None,
        _orphan_poll_threads=[],
        _MAX_ORPHAN_POLL_THREADS=UltraDeviceWorker._MAX_ORPHAN_POLL_THREADS,
        _seen_event_ids=set(),
        logger=MagicMock(),
    )


def _poll(w):
    return UltraDeviceWorker._poll_with_watchdog(w)


@pytest.fixture
def blocked():
    """A worker whose first poll is wedged inside the SDK."""
    drv = _BlockingDriver()
    w = _worker(drv)
    assert _poll(w) is None, "a blocked poll must report failure"
    assert drv.entered.wait(timeout=5)
    yield w, drv
    drv.release.set()


class TestProgressContinuesWhileAnOrphanIsStuck:
    def test_polling_resumes_on_the_new_connection(self, blocked):
        """The whole argument for the design, in one test.

        Fails against the pre-fix code, which returned None forever.
        """
        w, drv = blocked

        # What the run loop does next: _disconnect() + _connect() install a
        # brand-new driver. The orphan still holds the OLD one.
        live = _LiveDriver(events=[{"cardNo": "4242"}])
        w._sdk = live

        events = _poll(w)

        assert events == [{"cardNo": "4242"}], (
            f"the device was not polled on the new connection: {events!r} -- with the "
            f"deferred free in place this means it would never be polled again"
        )
        assert live.calls == 1
        assert len(w._orphan_poll_threads) == 1, "the wedged thread was not retired as an orphan"

    def test_the_wedged_thread_is_not_waited_on(self, blocked):
        """It must be retired, not re-detected as 'still hung' forever."""
        w, drv = blocked
        w._sdk = _LiveDriver()

        _poll(w)

        assert w._watchdog_thread is not drv, "still pointing at the wedged poll"
        assert all(t.is_alive() for t in w._orphan_poll_threads)

    def test_a_returning_orphan_is_dropped_from_the_list(self, blocked):
        """A recovered orphan frees its PullSDK lease and must stop being counted."""
        w, drv = blocked
        w._sdk = _LiveDriver()
        _poll(w)
        assert len(w._orphan_poll_threads) == 1

        drv.release.set()                       # the wedged call finally returns
        for t in list(w._orphan_poll_threads):
            t.join(timeout=5)

        _poll(w)
        assert w._orphan_poll_threads == [], (
            "a returned orphan is still being counted against the limit"
        )


class TestOrphansAreBounded:
    def test_refuses_to_start_another_once_the_limit_is_reached(self):
        """Orphans cost a thread and a leaked session each -- they cannot be unbounded."""
        drivers = []
        w = _worker(None)

        limit = UltraDeviceWorker._MAX_ORPHAN_POLL_THREADS
        for _ in range(limit):
            drv = _BlockingDriver()
            drivers.append(drv)
            w._sdk = drv
            assert _poll(w) is None
            assert drv.entered.wait(timeout=5)

        # One more attempt, this time with a perfectly healthy driver: it must be
        # refused, because the process cannot keep leaking threads and sessions.
        live = _LiveDriver()
        w._sdk = live
        result = _poll(w)

        assert result is None, "kept spawning poll threads past the orphan limit"
        assert live.calls == 0, "a new poll thread was started past the limit"
        assert len(w._orphan_poll_threads) >= limit

        for drv in drivers:
            drv.release.set()

    def test_healthy_polling_never_accumulates_orphans(self):
        """The ordinary path must not drift into the orphan machinery."""
        live = _LiveDriver()
        w = _worker(live)

        for _ in range(5):
            assert _poll(w) == [{"cardNo": "1"}]

        assert w._orphan_poll_threads == []
        assert w._watchdog_thread is None


class TestAgentWatchdogIsAlsoBounded:
    """realtime_agent had the same defect in a worse form: it spawned its poll
    thread into a LOCAL each iteration, so the next iteration stacked another on
    top of the stuck one with no guard at all."""

    def test_a_wedge_replaces_the_driver_rather_than_reusing_it(self):
        """The orphan keeps _sdk_lock, so the device object must not be reused.

        PullSDKDevice.connect() builds a fresh PullSDK but never rebuilds
        _sdk_lock, which lives on the device object the agent creates once in
        __init__. A poll wedged inside poll_rtlog_once holds that lock forever --
        and open_door takes the SAME lock, so reusing the object leaves the door
        permanently unopenable and hangs whoever asks. ultra_engine gets a new
        driver per connect cycle for free; the agent has to swap explicitly.
        """
        import app.core.realtime_agent as ra

        old = _BlockingDriver()
        built: list = []

        def _fake_get_driver(payload, logger=None):
            made = _LiveDriver()
            built.append(made)
            return made

        w = SimpleNamespace(
            _device=old,
            device_payload={"id": 8},
            device_id=8,
            logger=MagicMock(),
        )
        with patch.object(ra, "get_driver", _fake_get_driver):
            ra.DeviceWorker._retire_orphan_and_rebuild(w)

        assert built, "no replacement driver was built after the wedge"
        assert w._device is not old, (
            "the agent reused the wedged device -- every later call, open_door "
            "included, would queue behind a lock the orphan never releases"
        )
        assert w._device is built[-1]

    def test_a_failed_rebuild_does_not_kill_the_worker(self):
        """A driver-factory failure must not escape into the run loop."""
        import app.core.realtime_agent as ra

        def _boom(payload, logger=None):
            raise RuntimeError("factory down")

        w = SimpleNamespace(
            _device=_BlockingDriver(), device_payload={"id": 8},
            device_id=8, logger=MagicMock(),
        )
        with patch.object(ra, "get_driver", _boom):
            ra.DeviceWorker._retire_orphan_and_rebuild(w)   # must not raise

    def test_at_the_cap_it_waits_before_refusing(self):
        """The cap must not remove the throttle the 15s join used to provide.

        Raising straight away lands in run()'s outer except, which sleeps only
        0.25s and then reconnects successfully -- the panel is healthy, only our
        threads are stuck -- so the connect-failure backoff never arms. That is a
        ~4 Connect/Disconnect per second storm, and plcommpro leaks a handle and
        ~280KB on every cycle.
        """
        import app.core.realtime_agent as ra

        alive = [_never_ending_thread() for _ in range(ra._MAX_ORPHAN_POLL_THREADS)]
        waits: list = []
        w = SimpleNamespace(
            _orphan_poll_threads=list(alive),
            stop_event=SimpleNamespace(wait=lambda timeout=None: waits.append(timeout)),
            device_id=8,
            logger=MagicMock(),
        )

        with pytest.raises(RuntimeError):
            ra.DeviceWorker._refuse_if_orphans_at_cap(w, 15.0)

        assert waits == [15.0], (
            f"expected one 15s wait before refusing, got {waits!r} -- without it the "
            f"run loop spins Connect/Disconnect roughly four times a second"
        )

    def test_below_the_cap_it_neither_waits_nor_raises(self):
        import app.core.realtime_agent as ra

        waits: list = []
        w = SimpleNamespace(
            _orphan_poll_threads=[_never_ending_thread()],
            stop_event=SimpleNamespace(wait=lambda timeout=None: waits.append(timeout)),
            device_id=8,
            logger=MagicMock(),
        )
        ra.DeviceWorker._refuse_if_orphans_at_cap(w, 15.0)
        assert waits == [], "a single orphan must not throttle the poll loop"

    def test_retired_orphans_are_pruned_so_a_device_recovers(self):
        """Threads that came back must not count forever against the cap."""
        import app.core.realtime_agent as ra

        dead = threading.Thread(target=lambda: None)
        dead.start()
        dead.join()

        waits: list = []
        w = SimpleNamespace(
            _orphan_poll_threads=[dead] * (ra._MAX_ORPHAN_POLL_THREADS + 2),
            stop_event=SimpleNamespace(wait=lambda timeout=None: waits.append(timeout)),
            device_id=8,
            logger=MagicMock(),
        )
        ra.DeviceWorker._refuse_if_orphans_at_cap(w, 15.0)
        assert w._orphan_poll_threads == [], "finished orphans were never pruned"
        assert waits == []

    def test_agent_module_tracks_and_caps_orphan_poll_threads(self):
        import inspect

        import app.core.realtime_agent as ra

        assert hasattr(ra, "_MAX_ORPHAN_POLL_THREADS"), (
            "the agent has no orphan cap -- it will stack poll threads without limit"
        )
        assert ra._MAX_ORPHAN_POLL_THREADS > 0

        src = inspect.getsource(ra)
        assert "_orphan_poll_threads" in src, (
            "the agent still drops its poll thread into a local and forgets it"
        )
        # The cap has to actually gate the spawn, not merely be defined.
        spawn = src.index("_poll_thread = threading.Thread(")
        guard = src.index("_MAX_ORPHAN_POLL_THREADS")
        assert guard < spawn, (
            "the orphan cap is not checked before starting another poll thread"
        )

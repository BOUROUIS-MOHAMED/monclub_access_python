"""The headless MainApp loop must rest between callbacks, yet run them promptly.

``MainApp.mainloop`` is the production event loop (``run_app`` / ``access.bootstrap``). It
used to re-scan its schedule continuously — its only wait sat after the ``while`` — burning a
full CPU core and, through the GIL, slowing every other Python thread in the process.

These tests build a MainApp without running ``__init__`` (no database, devices or network)
and drive the real ``after`` / ``after_cancel`` / ``mainloop`` / ``quit`` / ``destroy`` in a
background thread.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, List
from unittest.mock import MagicMock

from app.ui.app import MainApp


def _bare_app() -> MainApp:
    app = object.__new__(MainApp)
    app.logger = MagicMock()
    app._stop_event = threading.Event()
    MainApp._init_scheduler(app)
    return app


class _LoopThread:
    """Runs app.mainloop() in a thread and records that thread's CPU time."""

    def __init__(self, app: MainApp) -> None:
        self.app = app
        self.cpu_s = 0.0
        self.done = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        t0 = time.thread_time()
        try:
            self.app.mainloop()
        finally:
            self.cpu_s = time.thread_time() - t0
            self.done.set()

    def start(self) -> "_LoopThread":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.app.quit()
        assert self.done.wait(2.0), "mainloop did not exit after quit()"


def _best_of(attempts: int, measure: Callable[[], float]) -> float:
    """Smallest of a few independent measurements.

    Wall-clock bounds fail when the OS does not schedule a thread in time (a busy CI box), not
    only when the loop misbehaves. A missing wake-up fails every attempt; contention rarely does.
    """
    return min(measure() for _ in range(attempts))


def _wait_for(pred: Callable[[], bool], timeout: float = 2.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.002)
    return pred()


# ── CPU: the loop rests ─────────────────────────────────────────────────────────────


def test_idle_loop_does_not_spin() -> None:
    loop = _LoopThread(_bare_app()).start()
    time.sleep(1.0)
    loop.stop()

    # Before the fix this was ~1.0 s of CPU per 1.0 s of wall time.
    assert loop.cpu_s < 0.2, f"idle mainloop used {loop.cpu_s:.3f}s CPU in 1s"


def test_loop_with_a_periodic_poll_does_not_spin() -> None:
    app = _bare_app()
    ticks: List[float] = []

    def poll() -> None:
        ticks.append(time.monotonic())
        app.after(200, poll)

    app.after(200, poll)
    loop = _LoopThread(app).start()
    time.sleep(1.1)
    loop.stop()

    assert loop.cpu_s < 0.2, f"mainloop used {loop.cpu_s:.3f}s CPU with a 200 ms poll"
    assert 4 <= len(ticks) <= 6


def test_a_zero_delay_self_rescheduling_callback_is_not_a_hot_loop() -> None:
    app = _bare_app()
    count = [0]

    def again() -> None:
        count[0] += 1
        app.after(0, again)

    app.after(0, again)
    loop = _LoopThread(app).start()
    time.sleep(0.5)
    loop.stop()

    # The loop always yields at least ~1 ms (time.sleep) between passes; the old spin managed
    # hundreds of thousands of passes per second here.
    assert 0 < count[0] <= 1000, f"{count[0]} passes in 0.5 s"


def test_after_zero_from_inside_a_callback_runs_within_a_few_ms() -> None:
    """A callback's own after(0, ...) is not left to a Condition wait, which rounds up to the
    ~15.6 ms Windows timer tick: a 20-hop chain took ~290 ms that way."""

    def chain_seconds() -> float:
        app = _bare_app()
        hops = [0]
        done = threading.Event()
        t0 = [0.0]

        def hop() -> None:
            hops[0] += 1
            if hops[0] == 20:
                done.set()
            else:
                app.after(0, hop)

        loop = _LoopThread(app).start()
        time.sleep(0.1)
        t0[0] = time.perf_counter()
        app.after(0, hop)
        assert done.wait(2.0)
        elapsed = time.perf_counter() - t0[0]
        loop.stop()
        return elapsed

    assert _best_of(3, chain_seconds) < 0.15


# ── Latency: callbacks are not delayed ──────────────────────────────────────────────


def test_after_zero_from_another_thread_wakes_the_sleeping_loop() -> None:
    app = _bare_app()
    app.after(60_000, lambda: None)  # the loop's only deadline is a minute away
    ran = threading.Event()
    loop = _LoopThread(app).start()
    time.sleep(0.2)

    latencies = []
    for _ in range(5):
        ran.clear()
        t0 = time.perf_counter()
        app.after(0, ran.set)
        assert ran.wait(1.0)
        latencies.append(time.perf_counter() - t0)
        time.sleep(0.07)
    loop.stop()

    # Woken by after(); not left to the 50 ms safety bound (without the notify every sample is
    # ~50 ms). The median tolerates one sample delayed by CPU contention.
    assert sorted(latencies)[2] < 0.03, latencies


def test_a_timed_callback_runs_on_time() -> None:
    def lateness() -> float:
        app = _bare_app()
        fired: List[float] = []
        loop = _LoopThread(app).start()
        time.sleep(0.1)
        t0 = time.monotonic()
        app.after(300, lambda: fired.append(time.monotonic()))
        assert _wait_for(lambda: bool(fired), 2.0)
        loop.stop()
        late = fired[0] - t0 - 0.300
        assert late >= -0.005, late  # never early
        return late

    assert _best_of(3, lateness) < 0.05


def test_after_cancel_prevents_the_callback() -> None:
    app = _bare_app()
    fired = []
    loop = _LoopThread(app).start()
    sid = app.after(100, lambda: fired.append(1))
    app.after_cancel(sid)
    time.sleep(0.25)
    loop.stop()

    assert fired == []


# ── Semantics kept from the original loop ───────────────────────────────────────────


def test_callbacks_due_in_the_same_pass_run_in_insertion_order() -> None:
    app = _bare_app()
    order: List[str] = []
    app.after(20, lambda: order.append("a"))  # later deadline, inserted first
    app.after(10, lambda: order.append("b"))
    time.sleep(0.05)  # both overdue before the loop's first scan
    loop = _LoopThread(app).start()
    assert _wait_for(lambda: len(order) == 2)
    loop.stop()

    assert order == ["a", "b"]


def test_a_raising_callback_is_logged_and_the_loop_keeps_running() -> None:
    app = _bare_app()
    ran = threading.Event()

    def boom() -> None:
        raise RuntimeError("boom")

    app.after(0, boom)
    app.after(30, ran.set)
    loop = _LoopThread(app).start()
    assert ran.wait(1.0)
    loop.stop()

    app.logger.exception.assert_called_once_with("Scheduled callback error")


# ── Stop latency ────────────────────────────────────────────────────────────────────


def test_quit_from_another_thread_wakes_the_loop_immediately() -> None:
    def stop_seconds() -> float:
        app = _bare_app()
        app.after(60_000, lambda: None)
        loop = _LoopThread(app).start()
        time.sleep(0.2)
        t0 = time.perf_counter()
        app.quit()
        assert loop.done.wait(1.0)
        return time.perf_counter() - t0

    assert _best_of(3, stop_seconds) < 0.03


def test_destroy_from_another_thread_stops_the_loop() -> None:
    def stop_seconds() -> float:
        app = _bare_app()
        app._change_detector = None
        app._log_sync_poller = None
        app._device_sync_engine = MagicMock()
        app._ultra_lock = threading.Lock()
        app._ultra_engine = None
        app._ultra_history_consumer = None
        loop = _LoopThread(app).start()
        time.sleep(0.2)
        t0 = time.perf_counter()
        app.destroy()
        assert loop.done.wait(1.0)
        return time.perf_counter() - t0

    assert _best_of(3, stop_seconds) < 0.03


def test_a_callback_that_stops_the_loop_ends_it_after_its_pass() -> None:
    app = _bare_app()
    later = []
    app.after(0, app.quit)
    app.after(500, lambda: later.append(1))
    loop = _LoopThread(app).start()
    assert loop.done.wait(1.0)

    assert later == []

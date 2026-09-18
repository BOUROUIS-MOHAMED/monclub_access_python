"""An operator SDK call the caller already gave up on must never run later.

``UltraDeviceWorker.request_run_sdk`` (the DevicesPage control panel through
``local_access_api_v2.py::_run_on_device_sdk``: ``settings_get``, ``reentry_set`` =
``SetDeviceParam`` ``Door{n}Intertime``, ``clock_get``, ``clock_sync``) queues ``fn`` and
waits ``timeout`` for the worker to run it on its held connection. Until 2026-09-19
``_drain_sdk_commands`` skipped an entry only when ``time.monotonic() > deadline``.
``Event.wait`` is not timed by ``time.monotonic`` and can end while ``monotonic()`` is still
before the deadline, so a drain in that gap ran a write whose caller had already answered
"timeout".

Each entry now carries the ``_CommandClaim`` the door queue uses (guide §3.1a): exactly one
side takes it -- the worker (it runs ``fn``) or the caller (it answers "timeout"). The
ordering tests script the caller's wait instead of relying on sleeps or the clock.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

from app.core import ultra_engine
from tests.test_door_open_deadline import _scripted_caller_waits
from tests.test_ultra_engine import _make_worker


def _connected_worker():
    worker = _make_worker()
    worker._connected = True
    worker._sdk = MagicMock()
    return worker


def _held_in_the_sdk():
    """An ``fn`` that blocks inside the SDK until ``release``; ``in_sdk`` marks entry."""
    in_sdk, release, calls = threading.Event(), threading.Event(), []

    def fn(sdk):
        calls.append(sdk)
        in_sdk.set()
        release.wait(10.0)
        return "applied"

    return fn, in_sdk, release, calls


def test_an_sdk_call_the_caller_gave_up_on_is_never_run_later() -> None:
    # The wait ends at once, 60 s before the deadline, so only the caller's own give-up
    # can stop the call -- not the clock. Before, the drain below ran the write.
    worker = _connected_worker()
    ran = []
    with _scripted_caller_waits(lambda real_wait, timeout: False):
        box = worker.request_run_sdk(lambda sdk: ran.append(1), label="reentry_set", timeout=60.0)
    assert box == {"ok": False, "result": None, "error": "timeout", "label": "reentry_set"}

    worker._drain_sdk_commands()

    assert ran == []
    assert worker._sdk_cmd_queue.empty()


def test_an_sdk_call_the_worker_took_first_is_answered_with_its_result_not_timeout() -> None:
    # The worker took the call inside the deadline and is running it when the caller's
    # wait runs out. "timeout" would tell the operator nothing was done -- a write may be
    # landing -- so the caller waits for the worker's answer instead.
    worker = _connected_worker()
    fn, in_sdk, release, calls = _held_in_the_sdk()
    drainer = threading.Thread(target=worker._drain_sdk_commands)

    def wait_runs_out_while_the_call_is_running(real_wait, timeout):
        drainer.start()
        assert in_sdk.wait(10.0)
        return False

    def the_worker_answers(real_wait, timeout):
        release.set()
        return real_wait(timeout)

    try:
        with _scripted_caller_waits(wait_runs_out_while_the_call_is_running, the_worker_answers):
            box = worker.request_run_sdk(fn, label="reentry_set", timeout=60.0)
        answered = dict(box)  # what the caller returned, before the worker is released below
    finally:
        release.set()
        drainer.join(10.0)

    assert len(calls) == 1
    assert answered == {"ok": True, "result": "applied", "error": "", "label": "reentry_set"}


def test_an_sdk_call_still_running_after_the_in_flight_wait_is_not_called_a_timeout() -> None:
    # The worker is inside fn and stays there past the caller's second wait, which is
    # bounded by the caller's own timeout. The answer says the call was sent.
    worker = _connected_worker()
    fn, in_sdk, release, calls = _held_in_the_sdk()
    drainer = threading.Thread(target=worker._drain_sdk_commands)
    in_flight_waits = []

    def wait_runs_out_while_the_call_is_running(real_wait, timeout):
        drainer.start()
        assert in_sdk.wait(10.0)
        return False

    def the_worker_never_answers(real_wait, timeout):
        in_flight_waits.append(timeout)
        return False

    try:
        with _scripted_caller_waits(wait_runs_out_while_the_call_is_running,
                                    the_worker_never_answers):
            box = worker.request_run_sdk(fn, label="clock_sync", timeout=25.0)
        answered = dict(box)
    finally:
        release.set()
        drainer.join(10.0)

    assert answered == {"ok": False, "result": None, "error": "sent, no answer", "label": "clock_sync"}
    assert in_flight_waits == [25.0]
    assert len(calls) == 1


def test_an_sdk_call_the_worker_answered_as_the_wait_ran_out_returns_that_answer() -> None:
    # The worker takes the call, finds itself disconnected and answers, just as the
    # caller's wait runs out. Nothing was sent, and the answer says why.
    worker = _make_worker()
    worker._connected = False
    worker._sdk = MagicMock()

    def the_worker_answers_as_the_wait_runs_out(real_wait, timeout):
        worker._drain_sdk_commands()
        return False

    with _scripted_caller_waits(the_worker_answers_as_the_wait_runs_out):
        box = worker.request_run_sdk(lambda sdk: "x", label="clock_get", timeout=15.0)

    assert box == {"ok": False, "result": None, "error": "device not connected", "label": "clock_get"}


def test_the_caller_gets_a_copy_not_the_live_box() -> None:
    worker = _connected_worker()
    with _scripted_caller_waits(lambda real_wait, timeout: False):
        box = worker.request_run_sdk(lambda sdk: "late", label="settings_get", timeout=15.0)
    live = worker._sdk_cmd_queue.queue[0][3]
    assert box is not live

    worker._drain_sdk_commands()

    assert box == {"ok": False, "result": None, "error": "timeout", "label": "settings_get"}


def test_each_sdk_call_is_decided_by_a_claim_its_caller_can_see() -> None:
    worker = _connected_worker()
    with _scripted_caller_waits(lambda real_wait, timeout: False):
        worker.request_run_sdk(lambda sdk: None, label="clock_get", timeout=15.0)
    claim = worker._sdk_cmd_queue.queue[0][5]
    assert isinstance(claim, ultra_engine._CommandClaim)
    assert claim.take_for_worker() is False  # its caller already gave up


class _RecordingBox(dict):
    """A result box that records how the worker writes into it."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.writes = []

    def __setitem__(self, key, value) -> None:
        self.writes.append(("setitem", key))
        super().__setitem__(key, value)

    def update(self, *args, **kwargs) -> None:
        self.writes.append(("update", dict(*args, **kwargs)))
        super().update(*args, **kwargs)


def _enqueue(worker, fn, *, deadline=None):
    ev = threading.Event()
    box = _RecordingBox({"ok": False, "result": None, "error": "timeout", "label": "op"})
    if deadline is None:
        deadline = time.monotonic() + 60.0
    worker._sdk_cmd_queue.put_nowait((fn, "op", ev, box, deadline, ultra_engine._CommandClaim()))
    return ev, box


def test_the_worker_writes_each_outcome_in_one_update() -> None:
    # The caller copies the box when its wait ends; a pair written in two statements
    # could be copied half-written (ok=True with the old "timeout" error, or the reverse).
    def boom(sdk):
        raise RuntimeError("SetDeviceParam FAILED rc=-201")

    worker = _connected_worker()
    _, ran = _enqueue(worker, lambda sdk: "value")
    _, failed = _enqueue(worker, boom)
    _, expired = _enqueue(worker, lambda sdk: "never", deadline=time.monotonic() - 0.001)
    worker._drain_sdk_commands()

    worker._connected = False
    _, offline = _enqueue(worker, lambda sdk: "never")
    worker._drain_sdk_commands()

    assert ran.writes == [("update", {"ok": True, "result": "value", "error": ""})]
    assert failed.writes == [("update", {"ok": False, "error": "SetDeviceParam FAILED rc=-201"})]
    assert expired.writes == [("update", {"ok": False, "error": "expired (not executed)"})]
    assert offline.writes == [("update", {"ok": False, "error": "device not connected"})]


def test_an_expiry_the_caller_reads_is_still_reported_as_not_executed() -> None:
    # The worker's clock can pass the deadline while the caller's wait is still running.
    # It then skips the call and wakes the caller, who reports that answer (the local API
    # answers 503 for it, as for "timeout").
    worker = _connected_worker()
    ran = []

    def the_worker_expires_it_while_the_caller_waits(real_wait, timeout):
        entry = worker._sdk_cmd_queue.get_nowait()
        worker._sdk_cmd_queue.put_nowait(entry[:4] + (time.monotonic() - 0.001,) + entry[5:])
        worker._drain_sdk_commands()
        return real_wait(timeout)

    with _scripted_caller_waits(the_worker_expires_it_while_the_caller_waits):
        box = worker.request_run_sdk(lambda sdk: ran.append(1), label="reentry_set", timeout=5.0)

    assert ran == []
    assert box == {"ok": False, "result": None, "error": "expired (not executed)", "label": "reentry_set"}


def _ultra_ctx(answer):
    worker = SimpleNamespace(
        _connected=True,
        _down_for_seconds=lambda: 0.0,
        request_run_sdk=lambda fn, *, label, timeout: dict(answer),
    )
    engine = SimpleNamespace(running=True, _workers={7: worker})
    return SimpleNamespace(app=SimpleNamespace(_ultra_engine=engine))


def test_the_control_panel_does_not_call_an_unanswered_call_unreachable() -> None:
    # 503 is the local API's "nothing was done" group (timeout, not connected, expired).
    # A call the worker sent may have been applied, so it must stay outside that group.
    from app.api.local_access_api_v2 import _run_on_device_sdk

    sent = _run_on_device_sdk(_ultra_ctx({"ok": False, "error": "sent, no answer"}),
                              7, lambda sdk: None, label="reentry_set")
    gave_up = _run_on_device_sdk(_ultra_ctx({"ok": False, "error": "timeout"}),
                                 7, lambda sdk: None, label="reentry_set")

    assert (sent["status"], sent["error"]) == (500, "sent, no answer")
    assert (gave_up["status"], gave_up["error"]) == (503, "timeout")

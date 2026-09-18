"""A queued door-open the caller already gave up on must never open the door later.

``UltraDeviceWorker.request_door_open`` (the operator "Open door" button: Tauri UI,
tray and favourite shortcuts -> local API ``_handle_device_door_open``) queues the
command and waits ``timeout`` (2 s) for the worker to execute it. Until 2026-09-18 the
queued entry had no deadline: when the worker reached its queue late -- a reconnect,
a sync hand-off, a long inline push -- ``_drain_commands`` still opened the door,
minutes after the desk had been told "device unreachable (command timed out)".

The deadline alone could not keep that promise: ``Event.wait`` can end while
``time.monotonic()`` is still before the deadline. Since 2026-09-19 each entry carries a
``_CommandClaim`` that exactly one side takes -- the worker (it sends the open) or the
caller (it answers "timeout") -- and the ordering tests below script the caller's wait
instead of relying on sleeps or the clock.

QR/TOTP and staff-RFID rescue opens do not use this queue (``_open_door_with_retry``
calls the SDK directly on the worker thread); the last test pins that.
"""

from __future__ import annotations

import contextlib
import threading
import time
from unittest.mock import MagicMock, patch

from app.core import ultra_engine
from tests.test_ultra_engine import _make_worker


def _connected_worker():
    worker = _make_worker()
    worker._connected = True
    worker._sdk = MagicMock()
    worker._sdk.open_door.return_value = True
    return worker


class _ThreadingWithEvent:
    """ultra_engine's ``threading`` with only ``Event`` replaced."""

    def __init__(self, event_cls) -> None:
        self.Event = event_cls

    def __getattr__(self, name):
        return getattr(threading, name)


@contextlib.contextmanager
def _scripted_caller_waits(*steps):
    """Script the successive ``wait()`` calls on request_door_open's result event.

    Each step is ``step(real_wait, timeout) -> bool``; once the steps run out, the real
    wait is used. This drives the caller/worker ordering without sleeps or clock luck.
    """

    class _Event(threading.Event):
        def __init__(self) -> None:
            super().__init__()
            self._steps = list(steps)

        def wait(self, timeout=None):
            if self._steps:
                return self._steps.pop(0)(super().wait, timeout)
            return super().wait(timeout)

    with patch.object(ultra_engine, "threading", _ThreadingWithEvent(_Event)):
        yield


def test_a_door_open_the_caller_gave_up_on_is_never_executed_later() -> None:
    worker = _connected_worker()

    box = worker.request_door_open(door_id=1, pulse_ms=3000, timeout=0.05)
    assert box["ok"] is False and box["error"] == "timeout"

    worker._drain_commands()  # the worker reaches its queue after the caller left

    worker._sdk.open_door.assert_not_called()
    assert worker._cmd_queue.empty()


def test_a_wait_that_ends_before_the_deadline_still_never_opens_later() -> None:
    # Event.wait is not timed by time.monotonic: on Windows it can end while monotonic()
    # is still <= deadline, and a drain in that gap opened the door (23 of 300 runs of
    # the test above, 32-bit 3.11 venv). Here the wait ends at once, 60 s before the
    # deadline, so only the caller's own give-up can stop the open -- not the clock.
    worker = _connected_worker()
    with _scripted_caller_waits(lambda real_wait, timeout: False):
        box = worker.request_door_open(door_id=1, pulse_ms=3000, timeout=60.0)
    assert box == {"ok": False, "error": "timeout"}

    worker._drain_commands()

    worker._sdk.open_door.assert_not_called()
    assert worker._cmd_queue.empty()


def _open_door_held_in_the_sdk(worker):
    """open_door blocks inside the SDK until ``release`` is set; ``in_sdk`` marks entry."""
    in_sdk, release = threading.Event(), threading.Event()

    def open_door(**_kw):
        in_sdk.set()
        release.wait(10.0)
        return True

    worker._sdk.open_door.side_effect = open_door
    return in_sdk, release


def test_an_open_the_worker_took_first_is_answered_with_its_result_not_timeout() -> None:
    # The worker took the entry inside the deadline and is sending it when the caller's
    # wait runs out. The caller must not answer "timeout" -- the door is opening -- so it
    # waits for the worker's answer instead.
    worker = _connected_worker()
    in_sdk, release = _open_door_held_in_the_sdk(worker)
    drainer = threading.Thread(target=worker._drain_commands)

    def wait_runs_out_while_the_open_is_being_sent(real_wait, timeout):
        drainer.start()
        assert in_sdk.wait(10.0)
        return False

    def the_worker_answers(real_wait, timeout):
        release.set()
        return real_wait(timeout)

    try:
        with _scripted_caller_waits(wait_runs_out_while_the_open_is_being_sent, the_worker_answers):
            box = worker.request_door_open(door_id=1, pulse_ms=3000, timeout=60.0)
    finally:
        release.set()
        drainer.join(10.0)

    worker._sdk.open_door.assert_called_once_with(door_id=1, pulse_time_ms=3000, timeout_ms=4000)
    assert box == {"ok": True, "error": ""}


def test_an_open_still_being_sent_after_the_in_flight_wait_is_not_called_a_timeout() -> None:
    # The worker is inside the SDK call and stays there past the caller's second, bounded
    # wait. "timeout" would tell the desk nothing was sent; the answer says it was.
    worker = _connected_worker()
    in_sdk, release = _open_door_held_in_the_sdk(worker)
    drainer = threading.Thread(target=worker._drain_commands)
    in_flight_waits = []

    def wait_runs_out_while_the_open_is_being_sent(real_wait, timeout):
        drainer.start()
        assert in_sdk.wait(10.0)
        return False

    def the_worker_never_answers(real_wait, timeout):
        in_flight_waits.append(timeout)
        return False

    try:
        with _scripted_caller_waits(wait_runs_out_while_the_open_is_being_sent,
                                    the_worker_never_answers):
            box = worker.request_door_open(door_id=1, pulse_ms=3000, timeout=60.0)
    finally:
        release.set()
        drainer.join(10.0)

    assert box == {"ok": False, "error": "sent, no answer"}
    assert in_flight_waits == [ultra_engine._DOOR_OPEN_IN_FLIGHT_WAIT_SEC]
    worker._sdk.open_door.assert_called_once()


def test_a_queued_door_open_is_decided_once_by_its_worker_or_its_caller() -> None:
    sent = ultra_engine._CommandClaim()
    assert sent.take_for_worker() is True
    assert sent.give_up() is False          # an open being sent cannot become a "timeout"
    assert sent.take_for_worker() is True   # asking again does not change the owner

    abandoned = ultra_engine._CommandClaim()
    assert abandoned.give_up() is True
    assert abandoned.take_for_worker() is False  # an open its caller gave up is never sent
    assert abandoned.give_up() is True


def test_the_desk_is_told_an_unanswered_open_was_sent() -> None:
    from app.api.local_access_api_v2 import _door_open_error_fr

    text = _door_open_error_fr("sent, no answer")
    assert "envoyée" in text and not text.startswith("échec")


def test_an_expired_open_is_reported_expired_and_releases_its_waiter() -> None:
    worker = _connected_worker()
    ev, box = threading.Event(), {"ok": False, "error": "timeout"}
    worker._cmd_queue.put_nowait(
        (1, 3000, ev, box, time.monotonic() - 0.001, ultra_engine._CommandClaim()))

    with patch("app.core.ultra_engine._tel.event") as tel:
        worker._drain_commands()

    worker._sdk.open_door.assert_not_called()
    assert ev.is_set()
    assert box == {"ok": False, "error": "expired (not executed)"}
    assert [c.args[0] for c in tel.call_args_list] == ["DOOR_CMD_EXPIRED"]


def test_an_open_drained_within_its_deadline_still_runs() -> None:
    worker = _connected_worker()
    holder = {}

    def caller():
        holder["box"] = worker.request_door_open(door_id=2, pulse_ms=1500, timeout=2.0)

    t = threading.Thread(target=caller)
    t.start()
    for _ in range(400):
        if not worker._cmd_queue.empty():
            break
        time.sleep(0.005)
    worker._drain_commands()
    t.join(timeout=2.0)

    worker._sdk.open_door.assert_called_once_with(door_id=2, pulse_time_ms=1500, timeout_ms=4000)
    assert holder["box"] == {"ok": True, "error": ""}


def test_a_newer_press_supersedes_a_queued_one_without_error() -> None:
    worker = _connected_worker()
    first = worker.request_door_open(door_id=1, pulse_ms=3000, timeout=0.05)
    assert first["error"] == "timeout"
    stale_ev, stale_box = worker._cmd_queue.queue[0][2], worker._cmd_queue.queue[0][3]

    second = worker.request_door_open(door_id=1, pulse_ms=3000, timeout=0.05)

    assert stale_ev.is_set() and stale_box["error"] == "superseded"
    assert second["error"] == "timeout"
    assert worker._cmd_queue.qsize() == 1  # only the newest press is left
    worker._drain_commands()
    worker._sdk.open_door.assert_not_called()  # and it expired too


def test_the_caller_gets_a_copy_not_the_live_box() -> None:
    worker = _connected_worker()
    box = worker.request_door_open(door_id=1, pulse_ms=3000, timeout=0.05)
    live = worker._cmd_queue.queue[0][3]
    assert box is not live
    worker._drain_commands()
    assert box == {"ok": False, "error": "timeout"}  # a later write cannot reach it


def test_the_mid_push_door_yield_also_skips_an_expired_open() -> None:
    worker = _connected_worker()
    worker._settings["ultra_sync_yield_to_doors"] = True
    ev, box = threading.Event(), {"ok": False, "error": "timeout"}
    worker._cmd_queue.put_nowait(
        (1, 3000, ev, box, time.monotonic() - 0.001, ultra_engine._CommandClaim()))

    worker._sync_yield_to_doors()

    worker._sdk.open_door.assert_not_called()
    assert ev.is_set() and box["error"] == "expired (not executed)"


def test_an_expiry_the_caller_reads_is_reported_as_its_timeout() -> None:
    # The worker's clock can pass the deadline while the caller's wait is still running
    # (Event.wait is not timed by time.monotonic), so the worker can mark the entry
    # expired just before the caller copies the box. The local API maps only "timeout"
    # to its 503; anything else became a generic 500 with an English internal string.
    worker = _connected_worker()
    holder = {}

    def caller():
        holder["box"] = worker.request_door_open(door_id=1, pulse_ms=3000, timeout=2.0)

    t = threading.Thread(target=caller)
    t.start()
    for _ in range(400):
        if not worker._cmd_queue.empty():
            break
        time.sleep(0.005)
    door, pulse, ev, box, _deadline, claim = worker._cmd_queue.get_nowait()
    worker._cmd_queue.put_nowait((door, pulse, ev, box, time.monotonic() - 0.001, claim))
    worker._drain_commands()  # marks it expired and wakes the caller early
    t.join(timeout=2.0)

    worker._sdk.open_door.assert_not_called()
    assert holder["box"] == {"ok": False, "error": "timeout"}


def test_the_mid_push_yield_event_counts_expired_opens_apart() -> None:
    worker = _connected_worker()
    worker._settings["ultra_sync_yield_to_doors"] = True
    worker._cmd_queue.put_nowait(
        (1, 3000, threading.Event(), {}, time.monotonic() - 0.001, ultra_engine._CommandClaim()))
    worker._cmd_queue.put_nowait(
        (2, 3000, threading.Event(), {}, time.monotonic() + 60.0, ultra_engine._CommandClaim()))

    with patch("app.core.ultra_engine._tel.event") as tel:
        worker._sync_yield_to_doors()

    yields = [c.kwargs for c in tel.call_args_list if c.args[0] == "SYNC_DOOR_YIELD"]
    assert yields == [{"worker": worker._tel_wid, "opened": 1, "expired": 1}]
    worker._sdk.open_door.assert_called_once_with(door_id=2, pulse_time_ms=3000, timeout_ms=4000)


def test_rescue_opens_do_not_use_the_queue() -> None:
    worker = _connected_worker()
    assert worker._open_door_with_retry(door_id=1) is True
    worker._sdk.open_door.assert_called_once()
    assert worker._cmd_queue.empty()

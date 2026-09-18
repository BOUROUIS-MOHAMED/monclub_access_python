"""A queued door-open the caller already gave up on must never open the door later.

``UltraDeviceWorker.request_door_open`` (the operator "Open door" button: Tauri UI,
tray and favourite shortcuts -> local API ``_handle_device_door_open``) queues the
command and waits ``timeout`` (2 s) for the worker to execute it. Until 2026-09-18 the
queued entry had no deadline: when the worker reached its queue late -- a reconnect,
a sync hand-off, a long inline push -- ``_drain_commands`` still opened the door,
minutes after the desk had been told "device unreachable (command timed out)".

QR/TOTP and staff-RFID rescue opens do not use this queue (``_open_door_with_retry``
calls the SDK directly on the worker thread); the last test pins that.
"""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock, patch

from tests.test_ultra_engine import _make_worker


def _connected_worker():
    worker = _make_worker()
    worker._connected = True
    worker._sdk = MagicMock()
    worker._sdk.open_door.return_value = True
    return worker


def test_a_door_open_the_caller_gave_up_on_is_never_executed_later() -> None:
    worker = _connected_worker()

    box = worker.request_door_open(door_id=1, pulse_ms=3000, timeout=0.05)
    assert box["ok"] is False and box["error"] == "timeout"

    worker._drain_commands()  # the worker reaches its queue after the caller left

    worker._sdk.open_door.assert_not_called()
    assert worker._cmd_queue.empty()


def test_an_expired_open_is_reported_expired_and_releases_its_waiter() -> None:
    worker = _connected_worker()
    ev, box = threading.Event(), {"ok": False, "error": "timeout"}
    worker._cmd_queue.put_nowait((1, 3000, ev, box, time.monotonic() - 0.001))

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
    worker._cmd_queue.put_nowait((1, 3000, ev, box, time.monotonic() - 0.001))

    worker._sync_yield_to_doors()

    worker._sdk.open_door.assert_not_called()
    assert ev.is_set() and box["error"] == "expired (not executed)"


def test_rescue_opens_do_not_use_the_queue() -> None:
    worker = _connected_worker()
    assert worker._open_door_with_retry(door_id=1) is True
    worker._sdk.open_door.assert_called_once()
    assert worker._cmd_queue.empty()

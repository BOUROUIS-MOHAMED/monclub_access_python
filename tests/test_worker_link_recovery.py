"""P3a-2 review round 1 (R1-21): a dead standalone link is rebuilt by the worker.

When a zkemkeeper COM call outlives its deadline the driver abandons its STA thread and
reports itself disconnected (``is_connected`` False). The worker never looked: its only
reconnect trigger is a poll that returns None, and the standalone poll is a plain queue
drain that never fails. So after the daily intent read-back, a sweep command or a door
open timed out, nothing pumped the terminal's events any more -- no QR/TOTP rescue, no
desk open -- until an unrelated push or the 30-minute connection refresh. P3a-2 added two
of those long commands (the read-back and the sweep), so it now checks.

The real ``UltraDeviceWorker.run()`` loop over the fake COM terminal.
"""
from __future__ import annotations

import queue
import threading
import time

import pytest

import app.core.db as dbmod
import app.core.ultra_engine as ue
from tests.test_zk_standalone_driver import _make_driver


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "link.db"), raising=False)
    dbmod.init_db()
    yield dbmod
    dbmod._shutdown_db_writer_for_tests()


def _wait(cond, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_an_abandoned_sta_thread_is_rebuilt_by_the_worker(db, monkeypatch):
    drivers = []

    def factory(device_payload=None, logger=None):
        drv, _zk = _make_driver()
        drivers.append(drv)
        return drv

    monkeypatch.setattr(ue, "get_driver", factory)
    stop = threading.Event()
    device = {"id": 9, "name": "Entree 1", "ipAddress": "192.168.9.10", "portNumber": 4370,
              "deviceProtocol": "ZK_STANDALONE", "accessDataMode": "ULTRA"}
    w = ue.UltraDeviceWorker(device, {}, queue.Queue(), queue.Queue(), stop)
    w.start()
    try:
        assert _wait(lambda: w._connected and len(drivers) == 1)
        drivers[0]._abandon_sta_thread("test: a COM call never returned")
        assert _wait(lambda: len(drivers) >= 2 and w._connected), (
            "the worker kept a dead link: no events, no door, until the 30-min refresh")
        assert drivers[-1].is_connected
    finally:
        stop.set()
        w.join(10)
        for d in drivers:
            try:
                d.disconnect()
            except Exception:
                pass

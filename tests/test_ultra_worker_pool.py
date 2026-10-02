"""Single ULTRA workers start and stop while the engine runs (ULTRA merge plan 2, Task 12;
spec section 6 "Taking effect", section 3 In service)."""
from __future__ import annotations

import logging
import threading

import pytest

import app.core.ultra_engine as ue
import app.core.ultra_worker_pool as pool


class _FakeWorker:
    def __init__(self, started, **kw):
        self._device, self._settings, self._stop_evt = kw["device"], kw["settings"], kw["stop_event"]
        self._alive = False
        self.updates = []
        started.append(int(self._device["id"]))

    def start(self):
        self._alive = True

    def is_alive(self):
        return self._alive and not self._stop_evt.is_set()

    def join(self, timeout=None):
        pass

    def update_device(self, device, settings):
        self._device, self._settings = device, settings
        self.updates.append(device)


def _dev(did, mode="ULTRA", **extra):
    d = {"id": did, "name": f"d{did}", "ipAddress": f"10.0.0.{did}", "accessDataMode": mode,
         "deviceProtocol": "ZK_PULLSDK", "active": True, "accessDevice": True}
    d.update(extra)
    return d


@pytest.fixture
def engine(monkeypatch):
    log = logging.getLogger("test.pool")
    eng = ue.UltraEngine(cfg=None, logger_inst=log)
    eng._running = True
    eng._sync_scheduler = ue.UltraSyncScheduler(None, log)
    eng.started = []
    monkeypatch.setattr(eng, "_new_worker", lambda **kw: _FakeWorker(eng.started, **kw))
    return eng


def _scheduled(eng):
    return sorted(d.get("id") for d in eng._sync_scheduler._devices)


def test_a_device_that_became_ultra_gets_a_worker_and_the_others_none(engine):
    counts = engine.reconcile_devices([_dev(1), _dev(2, "AGENT"), _dev(3, active=False),
                                       _dev(4, accessDevice=False)], stop_undriven=True)
    assert engine.started == [1]
    assert counts == {"started": 1, "stopped": 0, "refreshed": 1}
    assert sorted(engine._workers) == [1] and _scheduled(engine) == [1]


def test_a_device_that_left_ultra_loses_its_worker_and_only_that_one(engine):
    engine.reconcile_devices([_dev(1), _dev(2)], stop_undriven=True)
    first = engine._workers[1]
    counts = engine.reconcile_devices([_dev(1, "AGENT"), _dev(2)], stop_undriven=False)
    assert counts["stopped"] == 1 and sorted(engine._workers) == [2]
    assert first._stop_evt.is_set() and not engine._stop_event.is_set()
    assert engine.started == [1, 2]


def test_out_of_service_stops_the_worker(engine):
    engine.reconcile_devices([_dev(1)], stop_undriven=True)
    engine.reconcile_devices([_dev(1, active=False)], stop_undriven=False)
    assert engine._workers == {}


def test_an_unchanged_set_starts_nothing_and_refreshes_the_copies(engine):
    engine.reconcile_devices([_dev(1)], stop_undriven=True)
    counts = engine.reconcile_devices([_dev(1, name="renamed")], stop_undriven=True)
    assert counts == {"started": 0, "stopped": 0, "refreshed": 1}
    assert engine._workers[1]._device["name"] == "renamed"
    assert engine.started == [1]


def test_a_lease_away_worker_is_kept_on_the_fast_path_and_stopped_on_the_tick(engine, monkeypatch):
    engine.reconcile_devices([_dev(1)], stop_undriven=True)
    monkeypatch.setattr(pool._lease_gate, "filter_devices", lambda devices: [])
    engine.reconcile_devices([_dev(1)], stop_undriven=False)
    assert sorted(engine._workers) == [1] and _scheduled(engine) == [1]   # R1-F5, R2-4
    engine.reconcile_devices([_dev(1)], stop_undriven=True)
    assert engine._workers == {}


def test_the_watchdog_never_restarts_a_worker_removed_on_purpose(engine):
    engine.reconcile_devices([_dev(1)], stop_undriven=True)
    removed = engine._workers[1]
    engine.reconcile_devices([], stop_undriven=True)
    pool.restart_if_dead(engine, 1, removed)
    assert engine._workers == {} and engine.started == [1]


def test_the_watchdog_restarts_a_dead_worker_with_its_own_stop_flag(engine):
    engine.reconcile_devices([_dev(1)], stop_undriven=True)
    dead = engine._workers[1]
    dead._alive = False
    pool.restart_if_dead(engine, 1, dead)
    assert engine.started == [1, 1]
    assert engine._workers[1] is not dead and engine._workers[1]._stop_evt is dead._stop_evt


def test_a_worker_stop_flag_follows_the_engine():
    engine_stop = threading.Event()
    a, b = pool.WorkerStop(engine_stop), pool.WorkerStop(engine_stop)
    a.set()
    assert a.is_set() and not b.is_set() and a.wait(5) is True
    assert b.wait(0.01) is False
    engine_stop.set()
    assert b.is_set() and b.wait(5) is True


def test_start_gives_no_worker_to_an_out_of_service_device(monkeypatch):
    eng = ue.UltraEngine(cfg=None, logger_inst=logging.getLogger("test.pool"))
    monkeypatch.setattr(eng, "_new_worker", lambda **kw: pytest.fail("no worker for it"))
    eng.start([_dev(5, active=False), _dev(6, accessDevice=False)])
    assert eng._workers == {} and not eng.running


def test_devices_to_drive_is_ultra_in_service_and_driven():
    assert [d["id"] for d in pool.devices_to_drive([_dev(1), _dev(2, "AGENT"), _dev(3, active=False)])] == [1]


def test_a_started_worker_gets_its_first_pass(engine, monkeypatch):
    calls = []
    monkeypatch.setattr(engine._sync_scheduler, "request_sync_now", lambda **kw: calls.append(kw))
    monkeypatch.setattr(engine._sync_scheduler, "_manual_sync_mode", lambda: False)
    engine.reconcile_devices([_dev(1), _dev(2)], stop_undriven=True)
    assert calls == [{"device_ids": {1, 2}, "reason": "worker-started"}]
    engine.reconcile_devices([_dev(1), _dev(2)], stop_undriven=True)
    assert len(calls) == 1


def test_no_first_pass_in_manual_sync_mode(engine, monkeypatch):
    calls = []
    monkeypatch.setattr(engine._sync_scheduler, "request_sync_now", lambda **kw: calls.append(kw))
    monkeypatch.setattr(engine._sync_scheduler, "_manual_sync_mode", lambda: True)
    engine.reconcile_devices([_dev(1)], stop_undriven=True)
    assert calls == []


def test_a_stopped_device_leaves_the_scheduler_list_even_when_not_every_worker_is_driven(engine, monkeypatch):
    engine.reconcile_devices([_dev(1), _dev(2)], stop_undriven=True)
    assert _scheduled(engine) == [1, 2]
    monkeypatch.setattr(pool._lease_gate, "filter_devices", lambda devices: [d for d in devices if d["id"] != 1])
    engine.reconcile_devices([_dev(1), _dev(2, "AGENT")], stop_undriven=False)
    assert sorted(engine._workers) == [1] and _scheduled(engine) == [1]

"""The removal-request lifecycle (ULTRA merge plan 3, Task 6): run once on the driving PC, re-check
the payload, record durably, acknowledge, retry only the acknowledgement. Fake panel and worker, a
real temp SQLite; the acknowledgement is injected (no network)."""
from __future__ import annotations

import threading
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

import app.core.db as dbmod
from app.api.monclub_api import ACK_DONE, ACK_GONE, ACK_RETRY
from app.core import removal_requests as rr
from tests.test_removal_executors import FakePanel, _own, _panel

FP_ID = "0f8fad5b-d9cb-469f-a165-70867728950e"
CARD_ID = "7c9e6679-7425-40de-944b-e07fc1f90ae7"


@pytest.fixture
def sqlite_db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "requests.db"), raising=False)
    dbmod.init_db()
    yield dbmod
    dbmod._shutdown_db_writer_for_tests()


class FakeWorker:
    def __init__(self, drv, device, settings):
        self.drv = drv
        self._device = device
        self._settings = settings
        self._device_id = int(device["id"])
        self._connected = True
        self._connected_addr = (device["ipAddress"], int(device["portNumber"]))
        self._full_sync_running = False
        self.full_sync_requests: List[str] = []

    def request_run_sdk(self, fn, *, label, timeout):
        try:
            return {"ok": True, "result": fn(self.drv), "error": ""}
        except Exception as exc:
            return {"ok": False, "result": None, "error": str(exc)}

    def request_full_sync(self, reason="manual", **kw):
        self.full_sync_requests.append(reason)
        return True


class FakeSched:
    def __init__(self):
        self.forced: List[int] = []

    def force_resync(self, did):
        self.forced.append(int(did))


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _device(**kw):
    d = {"id": 5, "name": "Entree", "ipAddress": "192.168.0.202", "portNumber": 4370,
         "deviceProtocol": "ZK_PULLSDK", "accessDataMode": "ULTRA", "cardDecision": "PC",
         "fingerprintEnabled": False}
    d.update(kw)
    return d


def _settings(device):
    from app.core.settings_reader import normalize_device_settings
    return normalize_device_settings(device)


@pytest.fixture
def world(sqlite_db, monkeypatch):
    """One C3 worker; the stored payload is ``world.payload`` (what get_sync_device_payload reads)."""
    device = _device(fingerprintEraseRequestId=FP_ID.upper())
    payload = {"current": dict(device)}
    monkeypatch.setattr(dbmod, "get_sync_device_payload",
                        lambda did: dict(payload["current"]) if int(did) == 5 else None)
    panel = _panel()
    worker = FakeWorker(panel, device, _settings(device))
    engine = SimpleNamespace(_workers={5: worker}, _sync_scheduler=FakeSched(), _running=True,
                             _stop_event=threading.Event())
    acks: List[tuple] = []
    answers: List[Dict[str, Any]] = []

    def ack(did, rid, code, detail):
        acks.append((did, rid, code, detail))
        return answers.pop(0) if answers else {"outcome": ACK_DONE, "status": "DONE"}

    clock = Clock()
    runner = rr.RemovalRequestRunner(engine, ack=ack, mono=clock, grace_sec=0)
    return SimpleNamespace(engine=engine, worker=worker, panel=panel, payload=payload, acks=acks,
                           answers=answers, clock=clock, runner=runner, db=sqlite_db)


def _erases(panel):
    return [c for c in panel.calls if c[0] == "erase"]


def _hashes(db):
    with db.get_conn() as conn:
        return {str(r[0]): r[1] for r in conn.execute(
            "SELECT pin, desired_hash FROM device_sync_state WHERE device_id=5")}


def test_a_fingerprint_erase_runs_once_and_is_acknowledged_once(world):
    _own(world.db, 5, ["101"])
    assert [r["state"] for r in world.runner.tick()] == ["ACK_DONE"]
    assert world.panel.tables["templatev10"] == [] and world.panel.tables["template"] == []
    assert world.acks == [(5, FP_ID, "ERASED", "templatev10=2 template=1")]
    run = rr.get_run(FP_ID)
    assert run["kind"] == "FINGERPRINTS" and run["acked_at"] and run["ack_outcome"] == ACK_DONE
    assert [r["state"] for r in world.runner.tick()] == ["ACKED"]
    assert len(_erases(world.panel)) == 2 and len(world.acks) == 1
    # the turnstile changed: every hash cleared, a pass asked for (removal_executors docstring)
    assert _hashes(world.db) == {"101": None}
    assert world.engine._sync_scheduler.forced == [5]
    assert world.worker.full_sync_requests == ["removal-request"]


def test_the_worker_thread_check_reads_no_database(world, monkeypatch):
    on_worker = {"now": False}
    real_run = world.worker.request_run_sdk

    def run_sdk(fn, *, label, timeout):
        on_worker["now"] = True
        try:
            return real_run(fn, label=label, timeout=timeout)
        finally:
            on_worker["now"] = False

    real_payload = dbmod.get_sync_device_payload

    def payload(did):
        assert not on_worker["now"], "a database read on the worker thread"
        return real_payload(did)

    world.worker.request_run_sdk = run_sdk
    monkeypatch.setattr(dbmod, "get_sync_device_payload", payload)
    assert world.runner.tick()[0]["state"] == "ACK_DONE"


def test_a_cancellation_seen_by_the_worker_stops_the_next_write(world):
    real_run = world.worker.request_run_sdk

    def cancel_then_run(fn, *, label, timeout):
        world.worker._settings = dict(world.worker._settings, fingerprint_erase_request_id=None)
        return real_run(fn, label=label, timeout=timeout)

    world.worker.request_run_sdk = cancel_then_run
    [out] = world.runner.tick()
    assert (out["state"], out["code"]) == ("FAILED", "CANCELLED")
    assert _erases(world.panel) == [] and world.acks == []


def test_a_new_request_waits_the_grace_period(world):
    runner = rr.RemovalRequestRunner(world.engine, ack=lambda *a: {"outcome": ACK_DONE},
                                     mono=world.clock)
    assert [r["state"] for r in runner.tick()] == ["WAITING"]
    world.clock.t += rr.GRACE_SEC - 1
    assert [r["state"] for r in runner.tick()] == ["WAITING"]
    assert _erases(world.panel) == []
    world.clock.t += 1
    assert [r["state"] for r in runner.tick()] == ["ACK_DONE"]


def test_a_request_the_payload_no_longer_names_is_never_run(world):
    world.payload["current"].pop("fingerprintEraseRequestId")
    [out] = world.runner.tick()
    assert (out["state"], out["code"]) == ("REFUSED", "CANCELLED")
    assert _erases(world.panel) == [] and world.acks == []


@pytest.mark.parametrize("patch_target,value,code", [
    ("device_allowed", False, "NOT_DRIVER"),
    ("writes_frozen", True, "HANDOVER_IN_PROGRESS"),
    ("removals_blocked", "handoverForced", "ADD_ONLY"),
])
def test_the_lease_decides_who_runs(world, monkeypatch, patch_target, value, code):
    monkeypatch.setattr(rr._lease_gate, patch_target, lambda did: value)
    [out] = world.runner.tick()
    assert (out["state"], out["code"]) == ("REFUSED", code)
    assert _erases(world.panel) == []


def test_nothing_runs_while_the_erase_wizard_holds_the_turnstile(world, monkeypatch):
    monkeypatch.setattr(rr._device_hold, "is_held", lambda did: True)
    assert world.runner.tick()[0]["code"] == "ON_HOLD"


@pytest.mark.parametrize("change,code", [
    (lambda w: w._settings.update(fingerprint_enabled=True), "FINGERPRINTS_ON"),
    (lambda w: setattr(w, "_connected", False), "NOT_CONNECTED"),
    (lambda w: setattr(w, "_connected_addr", ("192.168.0.9", 4370)), "ADDRESS_CHANGED"),
    (lambda w: setattr(w, "_full_sync_running", True), "BUSY"),
])
def test_the_worker_must_be_ready(world, change, code):
    change(world.worker)
    assert world.runner.tick()[0]["code"] == code
    assert _erases(world.panel) == []


def test_an_ack_the_server_did_not_take_is_retried_later_never_the_erase(world):
    world.answers.append({"outcome": ACK_RETRY, "detail": "HTTP 503"})
    assert world.runner.tick()[0]["state"] == "ACK_RETRY"
    assert world.runner.tick() == []                       # inside ACK_RETRY_SEC
    world.clock.t += rr.ACK_RETRY_SEC
    assert world.runner.tick()[0]["state"] == "ACK_DONE"
    assert len(_erases(world.panel)) == 2 and len(world.acks) == 2


def test_a_404_stops_the_acknowledgements(world):
    world.answers.append({"outcome": ACK_GONE, "detail": "REMOVAL_REQUEST_NOT_FOUND"})
    assert world.runner.tick()[0]["state"] == "ACK_GONE"
    world.clock.t += rr.ACK_RETRY_SEC
    assert world.runner.tick()[0]["state"] == "ACKED"
    assert len(world.acks) == 1


def test_a_run_recorded_before_a_restart_is_only_acknowledged_again(world):
    world.answers.append({"outcome": ACK_RETRY, "detail": "offline"})
    world.runner.tick()
    fresh = rr.RemovalRequestRunner(world.engine, ack=lambda *a: world.acks.append(a) or
                                    {"outcome": ACK_DONE}, mono=world.clock, grace_sec=0)
    assert fresh.tick()[0]["state"] == "ACK_DONE"
    assert len(_erases(world.panel)) == 2


def test_a_failed_run_waits_before_the_next_try(world):
    world.panel.refuse_erase.add("templatev10")
    assert world.runner.tick()[0]["code"] == "NOT_ERASED"
    assert world.runner.tick() == []
    world.panel.refuse_erase.clear()
    world.clock.t += rr.FAIL_RETRY_SEC
    assert world.runner.tick()[0]["state"] == "ACK_DONE"
    assert rr.get_run(FP_ID)["result_code"] == "ERASED"


def test_a_card_removal_forces_the_pass_and_runs_after_the_erase(world):
    _own(world.db, 5, ["101", "102"])
    world.payload["current"]["cardRemovalRequestId"] = CARD_ID
    world.worker._device = dict(world.payload["current"])
    world.worker._settings = _settings(world.worker._device)
    assert [r["state"] for r in world.runner.tick()] == ["ACK_DONE", "ACK_DONE"]
    assert [a[2] for a in world.acks] == ["ERASED", "REMOVED"]
    assert [r["Pin"] for r in world.panel.tables["user"]] == ["777"]
    assert world.engine._sync_scheduler.forced == [5, 5]
    assert world.worker.full_sync_requests == ["removal-request", "removal-request"]


def test_a_card_removal_stopped_halfway_still_clears_the_hashes_and_asks_for_a_pass(world):
    _own(world.db, 5, ["101", "102"])
    world.payload["current"].pop("fingerprintEraseRequestId")
    world.payload["current"]["cardRemovalRequestId"] = CARD_ID
    world.worker._device = dict(world.payload["current"])
    world.worker._settings = _settings(world.worker._device)
    world.panel.refuse_delete.add("user")
    assert world.runner.tick()[0]["code"] == "DELETE_FAILED"
    assert world.panel.tables["userauthorize"] == [{"Pin": "777"}]   # rights went, users did not
    assert _hashes(world.db) == {"101": None, "102": None}           # so the next pass rewrites them
    assert world.engine._sync_scheduler.forced == [5]
    assert world.worker.full_sync_requests == ["removal-request"]
    assert world.acks == [] and rr.get_run(CARD_ID) is None


def test_a_card_removal_waits_while_cards_are_back_on_the_turnstile(world):
    world.payload["current"]["cardRemovalRequestId"] = CARD_ID
    world.payload["current"].pop("fingerprintEraseRequestId")
    world.worker._device = dict(world.payload["current"], cardDecision="TURNSTILE")
    world.worker._settings = _settings(world.worker._device)
    assert world.runner.tick()[0]["code"] == "CARDS_ON_TURNSTILE"


def test_the_runner_thread_is_started_once_and_ends_with_the_engine(monkeypatch):
    monkeypatch.setattr(rr, "POLL_SEC", 0.01)
    engine = SimpleNamespace(_workers={}, _running=True, _stop_event=threading.Event())
    first = rr.start_runner(engine)
    assert rr.start_runner(engine) is first and first.is_alive()
    engine._stop_event.set()
    first.join(timeout=2)
    assert not first.is_alive()

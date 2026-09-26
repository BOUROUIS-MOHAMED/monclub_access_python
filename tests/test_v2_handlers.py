"""P3b-2 step 4: what each remote command does, through the desk's own code paths."""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

from app.core.v2 import lease_gate as lg
from app.core.v2.commands import CommandRun
from app.core.v2.handlers import CommandHandlers
import app.api.local_access_api_v2 as la2


@pytest.fixture(autouse=True)
def _gate():
    lg.reset_for_tests()
    yield
    lg.reset_for_tests()


def _run(ctype, *, device=8, payload=None, remaining=20.0):
    return CommandRun(id="c-" + ctype.lower(), type=ctype, gym_device_id=device, payload=payload,
                      deadline_mono=time.monotonic() + remaining, claim_token="t" * 16)


def _reader():
    lg.install(lg.snapshot_from_assignment({"gymUsesAssignments": True, "role": "READER", "drive": [],
                                            "release": [], "readerOf": []}, source="server"))


@pytest.mark.parametrize("status,payload,code", [
    (200, {"ok": True, "source": "ultra"}, ("SUCCEEDED", "OPENED")),
    (503, {"ok": False, "error": "device unreachable"}, ("FAILED", "DEVICE_UNREACHABLE")),
    (500, {"ok": False, "error": "x", "detail": "sent, no answer"}, ("FAILED", "SENT_NO_ANSWER")),
    (409, {"ok": False, "unsupported": True}, ("FAILED", "DOOR_OPEN_DISABLED")),
    (429, {"ok": False}, ("FAILED", "RATE_LIMITED")),
    (500, {"ok": False, "error": "refused", "detail": "false"}, ("FAILED", "REFUSED")),
])
def test_door_open_maps_the_desk_answer(monkeypatch, status, payload, code):
    seen = []

    def fake(ctx):
        seen.append((ctx.param_int("deviceId"), ctx.body()))
        ctx.send_json(status, payload)

    monkeypatch.setattr(la2, "_handle_device_door_open", fake)
    out = CommandHandlers(SimpleNamespace()).door_open(_run("DOOR_OPEN", payload={"doorNumber": 2}))
    assert out[:2] == code
    assert seen == [(8, {"doorNumber": 2, "pulseSeconds": 3})]


def test_door_open_on_a_turnstile_this_pc_does_not_drive_touches_nothing(monkeypatch):
    _reader()
    monkeypatch.setattr(la2, "_handle_device_door_open", lambda ctx: pytest.fail("the door handler ran"))
    assert CommandHandlers(SimpleNamespace()).door_open(_run("DOOR_OPEN"))[:2] == ("FAILED", "NOT_DRIVER")


class EnrollApp:
    def __init__(self, outcome="ok", steps=3):
        self._enroll_running = False
        self._last_enroll_outcome = None
        self.cancelled = threading.Event()
        self.outcome = outcome
        self.steps = steps
        self.started = []

    def begin_remote_enroll(self, **kw):
        self.started.append(kw)
        self._enroll_running = True

        def work():
            for _ in range(self.steps):
                if self.cancelled.is_set():
                    break
                time.sleep(0.05)
            self._last_enroll_outcome = {"enrollId": "e1", "outcome": "cancelled" if self.cancelled.is_set()
                                         else self.outcome}
            self._enroll_running = False

        threading.Thread(target=work, daemon=True).start()
        return {"ok": True, "enrollId": "e1"}

    def cancel_enroll(self):
        self.cancelled.set()


ENROLL = {"type": "BACKEND", "userId": "35", "activeMembershipId": "29849", "fingerId": "3", "fullName": "Ali"}


def test_enroll_start_runs_the_local_enrolment_with_the_payload_as_its_body():
    app = EnrollApp()
    out = CommandHandlers(app, sleep=lambda s: time.sleep(0.01)).enroll_start(_run("ENROLL_START", device=None,
                                                                                  payload=ENROLL, remaining=60))
    assert out[:2] == ("SUCCEEDED", "SAVED")
    assert app.started == [{"user_id": "35", "finger_id": "3", "full_name": "Ali", "device": "zk9500",
                            "active_membership_id": "29849"}]


@pytest.mark.parametrize("outcome,code", [("ok_deferred_offline", ("SUCCEEDED", "SAVED_OFFLINE")),
                                          ("capture_failed", ("FAILED", "CAPTURE_FAILED")),
                                          ("backend_rejected", ("FAILED", "BACKEND_REJECTED"))])
def test_enroll_outcomes(outcome, code):
    app = EnrollApp(outcome=outcome)
    out = CommandHandlers(app, sleep=lambda s: time.sleep(0.01)).enroll_start(
        _run("ENROLL_START", device=None, payload=ENROLL, remaining=60))
    assert out[:2] == code


def test_enroll_cancel_stops_only_the_enrolment_that_command_started():
    app = EnrollApp(steps=200)
    running = {}
    h = CommandHandlers(app, running_commands=lambda: running, sleep=lambda s: time.sleep(0.01))
    start = _run("ENROLL_START", device=None, payload=ENROLL, remaining=60)
    running[start.id] = start
    result = {}
    t = threading.Thread(target=lambda: result.update(out=h.enroll_start(start)))
    t.start()
    time.sleep(0.1)
    cancel = h.enroll_cancel(_run("ENROLL_CANCEL", device=None, payload={"enrollCommandId": start.id}))
    assert cancel[:2] == ("SUCCEEDED", "CANCEL_REQUESTED")
    t.join(5)
    assert result["out"][:2] == ("FAILED", "CANCELLED")


def test_enroll_cancel_never_stops_a_desk_enrolment():
    app = EnrollApp()
    app._enroll_running = True
    out = CommandHandlers(app).enroll_cancel(_run("ENROLL_CANCEL", payload={"enrollCommandId": "zzz"}))
    assert out[:2] == ("FAILED", "NOT_THAT_ENROLMENT") and not app.cancelled.is_set()


def test_an_enrolment_near_its_deadline_is_cancelled_and_reported_expired():
    app = EnrollApp(steps=400)
    out = CommandHandlers(app, sleep=lambda s: time.sleep(0.01)).enroll_start(
        _run("ENROLL_START", device=None, payload=ENROLL, remaining=3.3))
    assert out[:2] == ("FAILED", "EXPIRED") and app.cancelled.is_set()


class SyncApp:
    def __init__(self):
        self._sync_work_running = False
        self._last_sync_ok = True
        self.requests = []
        self.ultra = []
        self._log_upload_queue = SimpleNamespace(flush_now=lambda: {"rotated": True, "activeBefore": 1,
                                                                    "pendingNow": 2, "other": 3})

    def after(self, ms, fn):
        fn()

    def request_sync_now(self, **kw):
        self.requests.append(kw)

        def run():
            self._sync_work_running = True
            time.sleep(0.1)
            self._sync_work_running = False

        threading.Thread(target=run, daemon=True).start()

    def _request_running_ultra_sync(self, **kw):
        self.ultra.append(kw)
        return True


def test_members_resync_is_an_explicit_sync_only_for_user_sync():
    app = SyncApp()
    h = CommandHandlers(app, sleep=lambda s: time.sleep(0.02))
    assert h.members_resync(_run("MEMBERS_RESYNC", payload={"reason": "user-sync"}))[:2] == ("SUCCEEDED", "SYNC_DONE")
    assert app.requests[0] == {"trigger_source": "SYNC_NOW_API", "trigger_hint": {"reason": "user-sync"}}
    h.members_resync(_run("MEMBERS_RESYNC", payload=None))
    assert app.requests[1]["trigger_source"] == "REMOTE_COMMAND"


def test_device_reconcile_is_an_explicit_full_reconcile_of_that_turnstile_only():
    app = SyncApp()
    out = CommandHandlers(app).device_reconcile(_run("DEVICE_RECONCILE"))
    assert out[:2] == ("SUCCEEDED", "RECONCILE_REQUESTED")
    assert app.ultra[0]["device_ids"] == {8} and app.ultra[0]["full_reconcile"] is True


def test_device_reconcile_refuses_a_turnstile_being_handed_over():
    lg.install(lg.snapshot_from_assignment({"gymUsesAssignments": True, "role": "DRIVER", "readerOf": [],
                                            "drive": [], "release": [{"gymDeviceId": 8, "generation": 2}]},
                                           source="server"))
    assert CommandHandlers(SyncApp()).device_reconcile(_run("DEVICE_RECONCILE"))[:2] == ("FAILED", "HANDOVER_IN_PROGRESS")


def test_logs_flush_returns_only_the_known_counters():
    out = CommandHandlers(SyncApp()).logs_flush(_run("LOGS_FLUSH", device=None))
    assert out == ("SUCCEEDED", "FLUSHED", {"rotated": True, "activeBefore": 1, "pendingNow": 2})


def test_device_audit_compares_the_listing_with_what_monclub_owns(monkeypatch):
    worker = SimpleNamespace(request_run_sdk=lambda fn, label, timeout: {
        "ok": True, "result": fn(SimpleNamespace(list_device_users=lambda timeout_sec: {
            "ok": True, "users": [{"pin": "1"}, {"pin": "2"}, {"pin": "900"}]}))})
    app = SimpleNamespace(_ultra_engine=SimpleNamespace(running=True, _workers={8: worker}))
    monkeypatch.setattr("app.core.db.list_confirmed_device_sync_pins", lambda device_id: {"1", "2", "3"})
    out = CommandHandlers(app).device_audit(_run("DEVICE_AUDIT"))
    assert out[0] == "SUCCEEDED"
    d = out[2]
    assert (d["onDevice"], d["owned"], d["ownedOnDevice"], d["ownedMissing"], d["notMonClub"]) == (3, 3, 2, 1, 1)
    assert d["ownedMissingSample"] == ["3"] and d["notMonClubSample"] == ["900"]


def test_a_failed_listing_is_a_failure_never_an_empty_turnstile():
    worker = SimpleNamespace(request_run_sdk=lambda fn, label, timeout: {"ok": False, "error": "timeout"})
    app = SimpleNamespace(_ultra_engine=SimpleNamespace(running=True, _workers={8: worker}))
    assert CommandHandlers(app).device_audit(_run("DEVICE_AUDIT"))[:2] == ("FAILED", "LIST_FAILED")


def test_a_card_scan_never_uses_a_turnstile_this_pc_does_not_drive(monkeypatch):
    _reader()
    monkeypatch.setattr(la2, "_get_runtime_access_config",
                        lambda ctx: SimpleNamespace(scanner_network_ip="192.168.1.8", scanner_mode="zkemkeeper"))
    monkeypatch.setattr("app.core.db.list_sync_devices_payload", lambda: [{"id": 8, "ipAddress": "192.168.1.8"}])
    monkeypatch.setattr(la2, "_handle_scan_quick", lambda ctx: pytest.fail("the scanner connected"))
    assert CommandHandlers(SimpleNamespace()).card_scan(_run("CARD_SCAN", device=None))[:2] == \
        ("FAILED", "SCANNER_IS_A_TURNSTILE")


def test_a_card_scan_returns_the_card(monkeypatch):
    monkeypatch.setattr(la2, "_get_runtime_access_config",
                        lambda ctx: SimpleNamespace(scanner_network_ip="192.168.1.50", scanner_mode="zkemkeeper"))
    monkeypatch.setattr("app.core.db.list_sync_devices_payload", lambda: [])
    monkeypatch.setattr(la2, "_handle_scan_quick", lambda ctx: ctx.send_json(200, {"ok": True, "card": "0012345"}))
    assert CommandHandlers(SimpleNamespace()).card_scan(_run("CARD_SCAN", device=None)) == \
        ("SUCCEEDED", "CARD_READ", {"card": "0012345"})

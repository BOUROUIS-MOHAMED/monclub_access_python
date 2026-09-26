"""P3b-2 step 6: turnstile problem reports and "Confirm removal" (REMOVAL_CONFIRM)."""
from __future__ import annotations

import hashlib
import threading
import time
from types import SimpleNamespace

import pytest

import app.core.push_safety as ps
from app.core.v2 import lease_gate as lg
from app.core.v2 import problems as pr
from app.core.v2 import timefmt
from app.core.v2.api import V2ApiError
from app.core.v2.commands import CommandRun
from app.core.v2.handlers import CommandHandlers
from app.core.v2.reports import ProblemReporter
from app.core.v2.server_clock import ServerClock


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    lg.reset_for_tests()
    pr.registry.reset_for_tests()
    yield
    lg.reset_for_tests()
    pr.registry.reset_for_tests()


def test_the_pin_set_hash_is_the_servers_canonical_one():
    # AccessPinSets.canonicalHash: trimmed, de-duplicated, sorted as strings, "\n", sha-256 hex.
    pins = [" 9", "10", "9", "0010"]
    expected = hashlib.sha256("0010\n10\n9".encode()).hexdigest()
    assert pr.canonical_hash(pins) == expected
    assert pr.canonical_hash([]) == hashlib.sha256(b"").hexdigest()


def test_a_snapshot_carries_each_code_within_the_servers_limits():
    ps.check_bulk_removal(count=30, roster_count=100, path="stale", device_id=8,
                          sample=[str(i) for i in range(30)])
    pr.registry.skipped_not_owned(8, ["7", "8"])
    pr.registry.set_code(8, pr.CAPACITY_FULL, [str(i) for i in range(700)], count=700)
    pr.registry.update_code_pins(8, pr.TEMPLATE_VERSION_MISMATCH, add=["5"])
    snap = {p["code"]: p for p in pr.registry.snapshot(8)}
    assert set(snap) == {"REVOKE_ABORTED", "SKIPPED_NOT_OWNED", "CAPACITY_FULL", "TEMPLATE_VERSION_MISMATCH"}
    ra = snap["REVOKE_ABORTED"]
    assert ra["count"] == len(ra["pins"]) == 30 and ra["reason"] == "above_ceiling" and ra["path"] == "stale"
    cap = snap["CAPACITY_FULL"]
    assert len(cap["pins"]) == 500 and cap["count"] == 700, "other codes: at most 500 pins, count may be larger"


def test_codes_resolve_where_their_step_runs():
    pr.registry.set_code(8, pr.CAPACITY_FULL, ["1"])
    pr.registry.clear_code(8, pr.CAPACITY_FULL)
    pr.registry.update_code_pins(8, pr.TEMPLATE_VERSION_MISMATCH, add=["1", "2"])
    pr.registry.update_code_pins(8, pr.TEMPLATE_VERSION_MISMATCH, remove=["1", "2"])
    assert pr.registry.snapshot(8) == []


class FakeApi:
    def __init__(self, error=None):
        self.bodies = []
        self.error = error

    def turnstile_problems(self, body):
        if self.error:
            raise self.error
        self.bodies.append(body)
        return {"stale": False, "ignoredCodes": []}


def _reporter(api):
    clock = ServerClock()
    now = time.time()
    clock.add_sample(now + 30, now, now, source="t")
    rt = SimpleNamespace(api=api, clock=clock)
    r = ProblemReporter(rt)
    r._scheme = lambda did: "MEMBERSHIP"
    return r


def test_a_report_is_sent_on_change_and_not_repeated():
    api = FakeApi()
    rep = _reporter(api)
    pr.registry.skipped_not_owned(8, ["7"])
    rep.tick(None)
    [body] = api.bodies
    assert (body["gymDeviceId"], body["pinScheme"]) == (8, "MEMBERSHIP")
    assert timefmt.to_epoch(body["observedAt"]) == pytest.approx(time.time() + 30, abs=2)
    rep._next_check = 0
    rep.tick(None)
    assert len(api.bodies) == 1, "unchanged content is not re-sent before the hourly refresh"


def test_a_turnstile_this_pc_does_not_drive_is_never_reported():
    lg.install(lg.snapshot_from_assignment({"gymUsesAssignments": True, "role": "READER", "drive": [],
                                            "release": [], "readerOf": []}, source="server"))
    api = FakeApi()
    pr.registry.skipped_not_owned(8, ["7"])
    _reporter(api).tick(None)
    assert api.bodies == []


def test_a_restart_sends_an_empty_snapshot_only_after_the_removal_step_ran():
    api = FakeApi()
    rep = _reporter(api)
    rep.tick(None)
    assert api.bodies == [], "nothing known yet: the server's last snapshot stays"
    pr.registry.removal_allowed(8, "standalone_revoke")      # the first pass's removal step ran
    rep._next_check = 0
    rep.tick(None)
    assert api.bodies and api.bodies[0]["problems"] == []


def test_a_refused_report_is_not_resent_every_minute():
    api = FakeApi(error=V2ApiError(400, "PROBLEM_INVALID", backend=True))
    rep = _reporter(api)
    pr.registry.skipped_not_owned(8, ["7"])
    rep.tick(None)
    api.error = None
    rep._next_check = 0
    rep._retry.clear()
    rep.tick(None)
    assert api.bodies == []


# --------------------------------------------------------------------------- REMOVAL_CONFIRM

PINS = [str(1000 + i) for i in range(30)]


def _run(payload, remaining=10.0):
    return CommandRun(id="rc", type="REMOVAL_CONFIRM", gym_device_id=8, payload=payload,
                      deadline_mono=time.monotonic() + remaining, claim_token="t" * 16)


def _refused(pins=PINS, roster=100, reason_roster=None):
    ps.check_bulk_removal(count=len(pins), roster_count=roster if reason_roster is None else reason_roster,
                          path="standalone_revoke", device_id=8, sample=pins)


class PassApp:
    """A worker whose requested pass runs the same removal step with ``pins_then``."""

    def __init__(self, pins_then):
        self.pins_then = pins_then
        worker = SimpleNamespace(request_full_sync=self._pass)
        self._ultra_engine = SimpleNamespace(running=True, _workers={8: worker})
        self.verdicts = []

    def _pass(self, reason):
        def run():
            time.sleep(0.05)
            self.verdicts.append(ps.check_bulk_removal(count=len(self.pins_then), roster_count=100,
                                                       path="standalone_revoke", device_id=8,
                                                       sample=self.pins_then))
        threading.Thread(target=run, daemon=True).start()
        return True


def test_confirm_removal_runs_the_step_for_exactly_the_bound_list():
    _refused()
    app = PassApp(PINS)
    out = CommandHandlers(app, sleep=lambda s: time.sleep(0.02)).removal_confirm(
        _run({"expectedCount": 30, "pinSetHash": pr.canonical_hash(PINS)}))
    assert out[:2] == ("SUCCEEDED", "REMOVAL_RAN")
    assert app.verdicts and app.verdicts[0].allowed


def test_a_list_that_changed_before_the_command_is_refused():
    _refused()
    stale_hash = pr.canonical_hash(PINS[:-1])
    out = CommandHandlers(PassApp(PINS)).removal_confirm(_run({"expectedCount": 29, "pinSetHash": stale_hash}))
    assert out[:2] == ("FAILED", "REMOVAL_LIST_CHANGED")
    assert out[2]["currentPinSetHash"] == pr.canonical_hash(PINS)


def test_a_list_that_changes_in_the_pass_is_not_removed():
    _refused()
    app = PassApp(PINS + ["2000"])                      # one more member left meanwhile
    out = CommandHandlers(app, sleep=lambda s: time.sleep(0.02)).removal_confirm(
        _run({"expectedCount": 30, "pinSetHash": pr.canonical_hash(PINS)}, remaining=3))
    assert out[:2] == ("FAILED", "REMOVAL_LIST_CHANGED")
    assert app.verdicts and not app.verdicts[0].allowed


def test_nothing_pending_or_an_empty_roster_is_never_confirmed():
    h = CommandHandlers(PassApp(PINS))
    assert h.removal_confirm(_run({"expectedCount": 30, "pinSetHash": pr.canonical_hash(PINS)}))[:2] == \
        ("FAILED", "NO_REMOVAL_PENDING")
    _refused(reason_roster=0)
    assert h.removal_confirm(_run({"expectedCount": 30, "pinSetHash": pr.canonical_hash(PINS)}))[:2] == \
        ("FAILED", "REMOVAL_NOT_CONFIRMABLE")


def test_confirm_removal_is_refused_on_an_add_only_turnstile():
    _refused()
    lg.install(lg.snapshot_from_assignment({"gymUsesAssignments": True, "role": "DRIVER", "readerOf": [],
                                            "release": [], "drive": [{"gymDeviceId": 8, "generation": 1,
                                                                      "state": "DRIVE", "handoverForced": True}]},
                                           source="server"))
    out = CommandHandlers(PassApp(PINS)).removal_confirm(_run({"expectedCount": 30,
                                                                "pinSetHash": pr.canonical_hash(PINS)}))
    assert out[:2] == ("FAILED", "REMOVALS_DEFERRED")

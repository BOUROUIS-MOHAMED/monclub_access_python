"""P3b-2 step 4: the remote command executor — claim, at most once, deadlines, results.

Server rules modelled from backend main c7d4b532 (AccessPcCommandService): the same claim
token may re-claim until finishBy; 404/409 on claim means nothing may run; a result is
accepted while the row is CLAIMED (late ones flagged); the claim answer carries
``serverTime`` and ``finishBy`` in the server's Tunis local clock.
"""
from __future__ import annotations

import threading
import time

import pytest

from app.core.db import _run_db_write_sync
from app.core.v2.api import V2ApiError
from app.core.v2.commands import CommandExecutor, Journal, STARTED, DONE


CID = "0b0f9a5e-1111-4222-8333-444455556666"


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as dbmod
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "v2cmd.db"), raising=False)
    dbmod.init_db()
    yield dbmod
    dbmod._shutdown_db_writer_for_tests()


class FakeApi:
    def __init__(self, *, finish_in=20.0, claim_error=None, ctype="DOOR_OPEN", payload=None):
        self.finish_in = finish_in
        self.claim_error = claim_error
        self.ctype = ctype
        self.payload = payload
        self.claims = []
        self.results = []
        self.progress_calls = []
        self.result_errors = []

    def claim(self, cid, token):
        self.claims.append((cid, token))
        if self.claim_error:
            raise self.claim_error
        fin = 10 + self.finish_in
        return {"command": {"id": cid, "type": self.ctype, "gymDeviceId": 8, "payload": self.payload,
                            "claimBy": "2026-09-26T10:00:15", "finishBy": f"2026-09-26T10:00:{fin:06.3f}",
                            "claimCount": 1, "serverTime": "2026-09-26T10:00:10.000"},
                "pollIntervalSec": 120}

    def result(self, cid, token, outcome, code, detail):
        if self.result_errors:
            raise self.result_errors.pop(0)
        self.results.append((cid, token, outcome, code, detail))
        return {}

    def progress(self, cid, token, value):
        self.progress_calls.append(value)
        return {}

    def pending(self):
        return {"commands": [{"id": CID.upper(), "type": self.ctype}]}


def _wait(cond, t=5.0):
    end = time.monotonic() + t
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def _exec(api, handlers, **kw):
    return CommandExecutor(api=api, handlers=handlers, token_factory=lambda: "tok-" + "a" * 20, **kw)


def test_a_claimed_command_runs_once_and_reports_its_result(db):
    api = FakeApi()
    ran = []
    ex = _exec(api, {"DOOR_OPEN": lambda run: (ran.append(run.remaining()), ("SUCCEEDED", "OPENED", {"door": 1}))[1]})
    ex.process(CID)
    assert _wait(lambda: api.results)
    assert api.results == [(CID, "tok-" + "a" * 20, "SUCCEEDED", "OPENED", {"door": 1})]
    assert 15.0 < ran[0] <= 10.0 + 10.0, "the deadline is finishBy - serverTime, measured from the answer"
    row = Journal().get(CID)
    assert row["state"] == DONE and row["reported"] == 1
    # A second notice for the same id runs nothing.
    ex.process(CID)
    assert len(ran) == 1 and len(api.claims) == 1


@pytest.mark.parametrize("code,status", [("COMMAND_EXPIRED", 409), ("COMMAND_FINISHED", 409),
                                         ("COMMAND_ALREADY_CLAIMED", 409), ("COMMAND_NOT_FOUND", 404),
                                         ("NOT_DEVICE_DRIVER", 409)])
def test_a_refused_claim_runs_nothing(db, code, status):
    api = FakeApi(claim_error=V2ApiError(status, code, backend=True))
    ran = []
    ex = _exec(api, {"DOOR_OPEN": lambda run: ran.append(1)})
    ex.process(CID)
    assert ran == [] and api.results == []
    assert Journal().get(CID)["state"] == DONE


def test_an_unreachable_claim_is_retried_with_the_same_token(db):
    api = FakeApi(claim_error=V2ApiError(0, "UNREACHABLE"))
    ex = _exec(api, {"DOOR_OPEN": lambda run: ("SUCCEEDED", "OPENED", None)})
    with pytest.raises(V2ApiError):
        ex.process(CID)
    ex._token_factory = lambda: "another-token-xxxxxxxx"
    api.claim_error = None
    ex.process(CID)
    assert _wait(lambda: api.results)
    assert {t for _c, t in api.claims} == {"tok-" + "a" * 20}, "a lost claim answer is re-claimed, same token"


def test_a_command_with_too_little_time_left_is_not_started(db):
    api = FakeApi(finish_in=1.0)              # 1 s left < the 3 s a door needs
    ran = []
    ex = _exec(api, {"DOOR_OPEN": lambda run: ran.append(1)})
    ex.process(CID)
    assert _wait(lambda: api.results)
    assert ran == [] and api.results[0][2:4] == ("FAILED", "EXPIRED")


def test_the_started_mark_is_written_before_the_command_acts(db):
    api = FakeApi()
    seen = []
    ex = _exec(api, {"DOOR_OPEN": lambda run: (seen.append(Journal().get(CID)["state"]), ("SUCCEEDED", "OPENED", None))[1]})
    ex.process(CID)
    assert _wait(lambda: api.results)
    assert seen == [STARTED]


def test_a_command_interrupted_by_a_restart_is_never_run_again(db):
    j = Journal()
    j.insert_seen(CID, "", "tok-" + "a" * 20)
    j.mark_started(CID, "DOOR_OPEN", 8, None, "2026-09-26T10:00:30")     # the PC died here
    api = FakeApi()
    ran = []
    ex = _exec(api, {"DOOR_OPEN": lambda run: ran.append(1)})
    ex._recover_interrupted()
    ex.process(CID)
    assert ran == [] and api.claims == []
    assert api.results[0][2:4] == ("FAILED", "INTERRUPTED")


def test_a_result_that_did_not_reach_the_server_is_sent_again(db):
    api = FakeApi()
    api.result_errors = [V2ApiError(0, "UNREACHABLE")]
    ex = _exec(api, {"DOOR_OPEN": lambda run: ("SUCCEEDED", "OPENED", None)})
    ex.process(CID)
    assert _wait(lambda: Journal().get(CID)["outcome"] == "SUCCEEDED")
    time.sleep(0.2)
    assert api.results == []
    ex._report_sweep()
    assert api.results and api.results[0][2] == "SUCCEEDED"
    assert Journal().get(CID)["reported"] == 1


def test_an_unknown_type_is_answered_not_ignored(db):
    api = FakeApi(ctype="SOMETHING_NEW")
    ex = _exec(api, {})
    ex.process(CID)
    assert api.results[0][2:4] == ("FAILED", "UNSUPPORTED_TYPE")


def test_the_pending_poll_offers_each_command_once(db):
    api = FakeApi()
    ex = _exec(api, {"DOOR_OPEN": lambda run: ("SUCCEEDED", "OPENED", None)})
    assert ex.poll_pending() == 1
    ex.offer(CID)
    assert ex._q.qsize() == 1, "ids are lower-cased and de-duplicated while queued"


def test_a_long_command_does_not_block_a_door_open(db):
    gate = threading.Event()
    api = FakeApi(ctype="ENROLL_START", finish_in=40.0)
    ex = _exec(api, {"ENROLL_START": lambda run: (gate.wait(5), ("SUCCEEDED", "ok", None))[1],
                     "DOOR_OPEN": lambda run: ("SUCCEEDED", "OPENED", None)})
    ex.process(CID)                                       # the enrolment waits on the gate
    api.ctype = "DOOR_OPEN"
    t0 = time.monotonic()
    ex.process("11111111-2222-4333-8444-555566667777")
    assert _wait(lambda: any(r[3] == "OPENED" for r in api.results), 2.0)
    assert time.monotonic() - t0 < 2.0
    gate.set()
    assert _wait(lambda: len(api.results) == 2)


def test_progress_is_throttled_to_one_a_second(db):
    api = FakeApi(ctype="ENROLL_START", finish_in=40.0)

    def handler(run):
        for i in range(5):
            run.progress({"step": i})
        return ("SUCCEEDED", "ok", None)

    ex = _exec(api, {"ENROLL_START": handler})
    ex.process(CID)
    assert _wait(lambda: api.results)
    assert api.progress_calls == [{"step": 0}]

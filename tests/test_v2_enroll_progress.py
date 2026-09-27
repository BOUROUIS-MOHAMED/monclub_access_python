"""Lane 1 item 2: a remote enrolment reports "Scan 2 of 3".

Before: ``CommandHandlers.enroll_start`` posted ``{step, enrollId}`` as the command's progress,
``step`` being the desk's free-text line (``local_access_api_v2._enroll_step``), which carries
mojibake from ``app/ui/app.py``. The dashboard reads ``{scansDone, scansNeeded, message}``
(``mon_club_dashboard`` ``command-outcome.ts::progressSummary``) and so never showed a scan count.

Now the progress is ``{enrollId, scansDone, scansNeeded: 3}``, taken from the structured phase
the scanner reports (``zkfinger.enroll_3_samples`` -> ``_enroll_set_phase``: ``wait_finger`` /
``sample_rejected`` / ``sample_captured`` with ``sampleNum``, then ``processing``). No free text
is forwarded. Before the capture starts there is no scan count to report: only ``enrollId``.
"""
from __future__ import annotations

import threading
import time

import pytest

import app.api.local_access_api_v2 as la2
from app.core.v2 import lease_gate as lg
from app.core.v2.commands import CommandRun
from app.core.v2.handlers import CommandHandlers, enroll_progress

MOJIBAKE = "Scanner initialized ÃƒÆ’Ã†â€™"


@pytest.fixture(autouse=True)
def _clean():
    lg.reset_for_tests()
    la2._enroll_reset()
    yield
    la2._enroll_reset()
    lg.reset_for_tests()


def _run(remaining=30.0):
    return CommandRun(id="c-enroll", type="ENROLL_START", gym_device_id=None,
                      payload={"type": "BACKEND", "userId": "35", "activeMembershipId": "29849",
                               "fingerId": "3", "fullName": "Ali"},
                      deadline_mono=time.monotonic() + remaining, claim_token="t" * 16)


@pytest.mark.parametrize("phase,done", [
    ({"phase": "wait_finger", "sampleNum": 1}, 0),
    ({"phase": "sample_rejected", "sampleNum": 1, "score": 0}, 0),
    ({"phase": "sample_captured", "sampleNum": 1}, 1),
    ({"phase": "wait_finger", "sampleNum": 2}, 1),
    ({"phase": "sample_rejected", "sampleNum": 2, "score": 0}, 1),
    ({"phase": "sample_captured", "sampleNum": 2}, 2),
    ({"phase": "wait_finger", "sampleNum": 3}, 2),
    ({"phase": "sample_captured", "sampleNum": 3}, 3),
    ({"phase": "processing"}, 3),
])
def test_the_scan_count_follows_the_capture_phases(phase, done):
    assert enroll_progress({**phase, "_seq": 4}, "e1") == {
        "enrollId": "e1", "scansDone": done, "scansNeeded": 3}


@pytest.mark.parametrize("phase", [
    None, {}, {"phase": "wait_finger"}, {"phase": "wait_finger", "sampleNum": "x"},
    {"phase": "something_new", "sampleNum": 2}, {"phase": "sample_captured", "sampleNum": 9},
    {"phase": "wait_finger", "sampleNum": 0}, "processing",
])
def test_anything_else_reports_no_scan_count(phase):
    assert enroll_progress(phase, "e1") == {"enrollId": "e1"}


class _PhasedEnrollApp:
    """Plays a scanner through the desk's own phase globals, like _remote_enroll_worker."""

    def __init__(self, phases, *, reset_delay=0.0):
        self._enroll_running = False
        self._last_enroll_outcome = None
        self.cancelled = threading.Event()
        self.phases = phases
        self.reset_delay = reset_delay

    def cancel_enroll(self):
        self.cancelled.set()

    def begin_remote_enroll(self, **kw):
        self._enroll_running = True

        def work():
            time.sleep(self.reset_delay)
            la2._enroll_reset()                         # the worker's first action
            la2._enroll_set_step(MOJIBAKE)
            for ph in self.phases:
                time.sleep(0.08)
                la2._enroll_set_phase(ph)
                la2._enroll_set_step(MOJIBAKE + " step")
            time.sleep(0.08)
            self._last_enroll_outcome = {"enrollId": "e1", "outcome": "ok"}
            self._enroll_running = False

        threading.Thread(target=work, daemon=True).start()
        return {"ok": True, "enrollId": "e1"}


def _enrol(app):
    sent = []
    run = _run()
    run.progress = lambda value: sent.append(dict(value))
    out = CommandHandlers(app, sleep=lambda s: time.sleep(0.01)).enroll_start(run)
    return out, sent


PHASES = [
    {"phase": "wait_finger", "sampleNum": 1},
    {"phase": "sample_captured", "sampleNum": 1},
    {"phase": "wait_finger", "sampleNum": 2},
    {"phase": "sample_captured", "sampleNum": 2},
    {"phase": "wait_finger", "sampleNum": 3},
    {"phase": "sample_captured", "sampleNum": 3},
    {"phase": "processing"},
]


def test_the_remote_enrolment_reports_scans_never_the_step_text():
    out, sent = _enrol(_PhasedEnrollApp(PHASES))
    assert out[:2] == ("SUCCEEDED", "SAVED")
    assert sent, "progress was reported"
    for value in sent:
        assert set(value) <= {"enrollId", "scansDone", "scansNeeded"}, value
        assert value["enrollId"] == "e1"
    counts = [v["scansDone"] for v in sent if "scansDone" in v]
    assert counts == sorted(counts), "the count never goes back"
    assert {0, 1, 2, 3} <= set(counts)
    assert all(v["scansNeeded"] == 3 for v in sent if "scansDone" in v)


def test_a_phase_left_by_the_previous_enrolment_is_never_reported():
    """The worker resets the phase as its first action, on its own thread: until it runs,
    the globals still hold the last enrolment's "processing" (Scan 3 of 3)."""
    la2._enroll_set_phase({"phase": "processing"})
    out, sent = _enrol(_PhasedEnrollApp([{"phase": "wait_finger", "sampleNum": 1}],
                                        reset_delay=0.15))
    assert out[:2] == ("SUCCEEDED", "SAVED")
    counts = [v["scansDone"] for v in sent if "scansDone" in v]
    assert counts and set(counts) == {0}, sent

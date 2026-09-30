"""MB2000 events replayed after the 30-min reconnect are recognised by their content.

Gym 45 (2026-09-30). Device 10 processed a scan live at 15:56:54 as
``2026-09-30 15:56:55|ZKPIN:69048|0|1|69048|zkem|10``; after the safety refresh reconnect
(16:08:01) the terminal delivered it again and it was processed a second time as
``...|zkem|1`` -- a second ALLOW, popup and history row. The event id ends in the driver's
per-connection counter (``zk_standalone.py`` ``_event_seq``, reset for every new driver), so
the worker's ``_is_seen`` never matched. Same at 16:08:08 on device 8 and 16:38:12 on both.

The replay is now dropped by content -- pin, device time, door, verify method -- in a bounded
per-turnstile memory; a real re-scan has another device time and is processed.
"""
from __future__ import annotations

import time

import pytest

import app.core.zkem_rtlog_filter as rf
from app.sdk.zk_standalone import normalize_att_event
from tests.test_ultra_engine import _make_worker


@pytest.fixture(autouse=True)
def _clean():
    rf.reset_for_tests()
    yield
    rf.reset_for_tests()


def _scan(seq, *, pin="69048", when=(2026, 9, 30, 15, 56, 55), verify=1, invalid=0):
    y, mo, d, h, mi, s = when
    return normalize_att_event(enroll_number=pin, is_invalid=invalid, att_state=0,
                               verify_method=verify, y=y, mo=mo, d=d, h=h, mi=mi, s=s,
                               seq=seq, pin_to_card={}, device_id=10)


@pytest.fixture
def worker(monkeypatch):
    w = _make_worker()
    w.handled = []
    w._handle_allow = lambda *a, **k: w.handled.append(a)      # type: ignore[method-assign]
    w._handle_rfid_rescue = lambda *a, **k: w.handled.append(a)  # type: ignore[method-assign]
    w._effective_card_cooldown_sec = lambda card: 0.0           # re-scans are not debounced here
    w.ages = []
    real_age = w._record_event_age
    w._record_event_age = lambda epoch: (w.ages.append(epoch), real_age(epoch))  # type: ignore
    return w


def test_the_reconnect_replay_is_not_processed_again(worker):
    live, replay = _scan(10), _scan(1)
    assert live["eventId"] != replay["eventId"], "the counter differs: the old dedupe missed it"
    worker._process_event(live)
    worker._process_event(replay)
    assert len(worker.handled) == 1, "16:08:08: a second ALLOW, popup and history row"
    assert len(worker.ages) == 1, "and no stale-event (CLOCK_SKEW) reading for the replay"


def test_a_real_re_scan_one_second_later_is_processed(worker):
    worker._process_event(_scan(10))
    worker._process_event(_scan(11, when=(2026, 9, 30, 15, 56, 56)))
    assert len(worker.handled) == 2


def test_another_door_member_or_verify_method_is_another_event(worker):
    worker._process_event(_scan(1))
    worker._process_event(_scan(2, pin="68908"))
    worker._process_event(_scan(3, verify=15))
    other_door = _scan(4)
    other_door["doorId"] = 2
    worker._process_event(other_door)
    assert len(worker.handled) == 4


def test_the_memory_is_per_turnstile():
    evt = _scan(1)
    assert rf.skip(10, evt, "[ULTRA:10]") is False
    assert rf.skip(8, evt, "[ULTRA:8]") is False, "the same second on the other terminal"
    assert rf.skip(10, evt, "[ULTRA:10]") is True


def test_the_memory_is_bounded_oldest_first():
    first = _scan(1, when=(2026, 9, 30, 8, 0, 0))
    assert rf.skip(10, first, "") is False
    for i in range(rf.MAX_KEYS):
        t = time.localtime(time.mktime((2026, 9, 30, 9, 0, 0, 0, 0, -1)) + i)
        assert rf.skip(10, _scan(i + 2, when=tuple(t[:6])), "") is False
    assert rf.skip(10, first, "") is False, "evicted: the oldest key goes first"
    assert len(rf._seen[10]) == rf.MAX_KEYS


def test_pullsdk_events_are_untouched(worker):
    pull = {"eventId": "2026-09-30 15:56:55|555|0|1", "cardNo": "555", "eventType": 0,
            "eventTime": "2026-09-30 15:56:55", "doorId": 1, "rawRow": {}}
    worker._process_event(dict(pull))
    worker._process_event(dict(pull, eventId="2026-09-30 15:56:55|555|0|1|b"))
    assert len(worker.handled) == 2, "C3 events keep their own event-id dedupe only"

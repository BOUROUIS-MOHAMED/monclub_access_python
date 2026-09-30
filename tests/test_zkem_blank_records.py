"""Blank MB2000 RTLog records are not accesses: never recorded, never a popup.

Gym 45 (2026-09-30, both MB2000s). 282 ``OnAttTransactionEx`` callbacks carried
EnrollNumber '' (``pin=``), IsInValid 0 (``type='0'``), VerifyMethod 0 and the date
2000-00-00 00:00:00 -- no user and no calendar date. Each one came in the same GetRTLog
drain right after a real verification on that terminal. ``normalize_att_event`` turned
them into ``eventType "0"`` (ALLOW): 66 were processed as "ALLOW, user NOT found" with a
popup and a history row (the other 216 were only stopped because their counter-based id
happened to repeat), and every 5-s dashboard poll re-warned "unparseable event time" for
each such row among the last 40 (8403 warnings).

They are now dropped at the worker with one DEBUG line. A record with no pin but a real
date (e.g. a finger the terminal did not recognise) is still processed.
"""
from __future__ import annotations

import logging

import pytest

import app.core.device_attendance as da
from app.sdk.zk_standalone import normalize_att_event
from tests.test_ultra_engine import _make_worker


def _evt(seq, *, pin="", when=(2000, 0, 0, 0, 0, 0), verify=0, invalid=0):
    y, mo, d, h, mi, s = when
    return normalize_att_event(enroll_number=pin, is_invalid=invalid, att_state=0,
                               verify_method=verify, y=y, mo=mo, d=d, h=h, mi=mi, s=s,
                               seq=seq, pin_to_card={}, device_id=10)


@pytest.fixture
def worker():
    w = _make_worker()
    w.handled = []
    w._handle_allow = lambda *a, **k: w.handled.append(("allow",) + a)       # type: ignore
    w._handle_rfid_rescue = lambda *a, **k: w.handled.append(("deny",) + a)  # type: ignore
    w._effective_card_cooldown_sec = lambda card: 0.0
    return w


def test_the_blank_record_after_a_scan_is_dropped(worker, caplog):
    real = _evt(10, pin="69048", when=(2026, 9, 30, 15, 56, 55), verify=1)
    blank = _evt(11)
    assert blank["eventTime"] == "2000-00-00 00:00:00" and blank["eventType"] == "0"
    with caplog.at_level(logging.DEBUG):
        worker._process_event(real)
        worker._process_event(blank)
        worker._process_event(_evt(12))          # the next one, another counter value
    assert [h[0] for h in worker.handled] == ["allow"], "15:48:14: ALLOW with an empty user"
    assert worker._events_processed == 1
    lines = [r for r in caplog.records if "blank" in r.getMessage()]
    assert len(lines) == 2 and all(r.levelno == logging.DEBUG for r in lines), (
        "one DEBUG line per blank record, no warning")
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_no_pin_with_a_real_date_is_still_an_event(worker):
    """A refused unknown finger has no pin but a real time: it stays visible."""
    worker._process_event(_evt(1, when=(2026, 9, 30, 16, 0, 0), verify=1, invalid=1))
    assert [h[0] for h in worker.handled] == ["deny"]


def test_a_pin_with_a_zero_date_is_not_called_blank(worker):
    worker._process_event(_evt(1, pin="85", verify=1))
    assert len(worker.handled) == 1, "only 'no pin AND no date' is proven blank"


def test_the_dashboard_warns_once_per_junk_time_not_every_poll(caplog):
    """Rows already in a gym's history keep being read by the 5-s overview poll."""
    getattr(da, "_unparseable_times_warned", set()).clear()
    with caplog.at_level(logging.DEBUG, logger="zkapp"):
        for _ in range(3):
            assert da._normalize_datetime_text("2000-00-00 00:00:00",
                                               fallback="2026-09-30 15:48:14") == "2026-09-30T15:48:14"
    lines = [r for r in caplog.records if "unparseable event time" in r.getMessage()]
    assert [r.levelno for r in lines] == [logging.WARNING, logging.DEBUG, logging.DEBUG]

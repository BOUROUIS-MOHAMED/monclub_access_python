"""PIN length watch (app/core/pin_length_watch.py), fed from db.record_push_results.

It only reports: the first confirmed push of a PIN longer than any confirmed on a turnstile, and
a failed push of such a PIN. These tests also pin that it never changes what is stored and never
fails the write it watches.
"""
from __future__ import annotations

import pytest

import app.core.db as dbmod
import app.core.pin_length_watch as watch


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "pinlen.db"), raising=False)
    dbmod.init_db()
    watch.reset_for_tests()
    yield dbmod
    watch.reset_for_tests()
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


@pytest.fixture
def said(monkeypatch):
    lines = []
    monkeypatch.setattr(watch._tel, "event", lambda name, **f: lines.append(("event", name, f)))
    monkeypatch.setattr(watch._tel, "warn", lambda name, **f: lines.append(("warn", name, f)))
    return lines


def _named(lines, name):
    return [f for _level, n, f in lines if n == name]


def test_first_confirmed_longer_pin_is_said_once(db, said):
    db.record_push_results(device_id=8, rows=[("79276", True, None), ("512", True, None)])
    said.clear()

    db.record_push_results(device_id=8, rows=[("100001", True, None)])
    db.record_push_results(device_id=8, rows=[("100002", True, None)])

    first = _named(said, "PIN_LENGTH_FIRST_PUSH_OK")
    assert first == [{"device_id": 8, "digits": 6, "previous": 5, "pin": "100001"}]
    assert _named(said, "PIN_LENGTH_PUSH_FAILED") == []


def test_failed_longer_pin_warns_once_per_length_and_code(db, said):
    db.record_push_results(device_id=8, rows=[("79276", True, None)])
    said.clear()

    db.record_push_results(device_id=8, rows=[("100001", False, "USER_WRITE_FAILED"),
                                              ("100002", False, "USER_WRITE_FAILED")])
    db.record_push_results(device_id=8, rows=[("100001", False, "USER_WRITE_FAILED")])

    failed = _named(said, "PIN_LENGTH_PUSH_FAILED")
    assert failed == [{"device_id": 8, "digits": 6, "longest_ok": 5,
                       "code": "USER_WRITE_FAILED", "count": 2, "pin": "100001"}]
    assert [level for level, n, _f in said if n == "PIN_LENGTH_PUSH_FAILED"] == ["warn"]

    # Another code for the same length is another fact, said once too.
    db.record_push_results(device_id=8, rows=[("100003", False, "TIMEOUT")])
    assert len(_named(said, "PIN_LENGTH_PUSH_FAILED")) == 2


def test_failed_pin_of_a_confirmed_length_is_not_a_length_matter(db, said):
    db.record_push_results(device_id=8, rows=[("79276", True, None)])
    said.clear()

    db.record_push_results(device_id=8, rows=[("79277", False, "USER_WRITE_FAILED"),
                                              ("42", False, "TIMEOUT")])

    assert said == []


def test_confirmed_and_failed_in_one_batch(db, said):
    db.record_push_results(device_id=8, rows=[("79276", True, None)])
    said.clear()

    db.record_push_results(device_id=8, rows=[("100001", True, None),
                                              ("100002", False, "USER_WRITE_FAILED"),
                                              ("1000001", False, "USER_WRITE_FAILED")])

    assert _named(said, "PIN_LENGTH_FIRST_PUSH_OK") == [
        {"device_id": 8, "digits": 6, "previous": 5, "pin": "100001"}]
    # 6 digits were confirmed in this very batch, so only the 7-digit failure is about length.
    assert _named(said, "PIN_LENGTH_PUSH_FAILED") == [
        {"device_id": 8, "digits": 7, "longest_ok": 6, "code": "USER_WRITE_FAILED",
         "count": 1, "pin": "1000001"}]


def test_turnstiles_are_watched_apart(db, said):
    db.record_push_results(device_id=8, rows=[("100001", True, None)])
    said.clear()

    db.record_push_results(device_id=12, rows=[("79276", True, None)])
    db.record_push_results(device_id=12, rows=[("100001", False, "OTHER")])

    assert _named(said, "PIN_LENGTH_FIRST_PUSH_OK") == [
        {"device_id": 12, "digits": 5, "previous": 0, "pin": "79276"}]
    assert _named(said, "PIN_LENGTH_PUSH_FAILED")[0]["device_id"] == 12


def test_baseline_is_read_from_storage_after_a_restart(db, said):
    db.record_push_results(device_id=8, rows=[("100001", True, None)])
    watch.reset_for_tests()          # a new process: nothing in memory
    said.clear()

    db.record_push_results(device_id=8, rows=[("100002", True, None)])
    db.record_push_results(device_id=8, rows=[("1000001", False, "OTHER")])

    assert _named(said, "PIN_LENGTH_FIRST_PUSH_OK") == []
    assert _named(said, "PIN_LENGTH_PUSH_FAILED")[0]["longest_ok"] == 6


def test_a_failed_or_unknown_result_is_not_a_baseline(db, said):
    db.record_push_results(device_id=8, rows=[("79276", True, None),
                                              ("100001", False, "OTHER")])
    db.reset_push_results_for_pins(device_id=8, pins=["79276"])     # now unknown
    watch.reset_for_tests()
    said.clear()

    db.record_push_results(device_id=8, rows=[("512", True, None)])

    assert _named(said, "PIN_LENGTH_FIRST_PUSH_OK") == [
        {"device_id": 8, "digits": 3, "previous": 0, "pin": "512"}]


def test_non_numeric_pins_are_ignored(db, said):
    db.record_push_results(device_id=8, rows=[("79276", True, None)])
    said.clear()

    db.record_push_results(device_id=8, rows=[("ABCDEFGH", True, None),
                                              ("-1234567", False, "OTHER")])

    assert said == []


def test_the_watch_never_changes_or_fails_the_write(db, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("watch broken")

    monkeypatch.setattr(watch, "baseline", boom)
    monkeypatch.setattr(watch, "observe", boom)

    written = db.record_push_results(device_id=8, rows=[("100001", True, None),
                                                        ("100002", False, "USER_WRITE_FAILED")])

    assert written == 2
    stored = {p: (r[0], r[3]) for p, r in db.list_push_results(device_id=8).items()}
    assert stored == {"100001": (True, None), "100002": (False, "USER_WRITE_FAILED")}


def test_observe_and_baseline_swallow_their_own_errors(said):
    watch.reset_for_tests()

    def bad_load(_did):
        raise RuntimeError("no database")

    assert watch.baseline(8, bad_load) is None
    assert watch.baseline("not a device", lambda _d: 5) is None
    watch.observe(8, [("100001", True, None)], None)        # baseline unknown: says nothing
    watch.observe(8, [None, (), ("x",)], 5)                 # garbage rows
    watch.observe(object(), [("100001", True, None)], 5)    # garbage device
    assert said == []

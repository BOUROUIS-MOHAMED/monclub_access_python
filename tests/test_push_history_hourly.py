"""Historique push hour x device chart: GET /api/v2/push-history/hourly (db.push_batch_hourly).

push_batch_history.created_at is UTC in two spellings ("...Z" from the ULTRA standalone /
MIRROR writers, "+00:00" from device_sync.py). The aggregate must read both, cut the day
in LOCAL time, group by local hour, and only count what the rows store.
"""
from __future__ import annotations

import importlib
from datetime import timedelta, timezone

import pytest

TUNIS = timezone(timedelta(hours=1))


@pytest.fixture()
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    importlib.reload(db_module)
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()
    return db_module


def _batch(db, *, device_id, name, created_at, status, attempted=0, success=0, failed=0):
    batch_id = db.insert_push_batch(
        sync_run_id=None, device_id=device_id, device_name=name, policy="PRESERVE",
        status="IN_PROGRESS", created_at=created_at,
    )
    if status != "IN_PROGRESS":
        db.update_push_batch(
            id=batch_id, pins_attempted=attempted, pins_success=success, pins_failed=failed,
            status=status, duration_ms=10,
        )
    return batch_id


def test_both_utc_spellings_are_grouped_by_local_hour(db):
    # 2026-10-15 in UTC+1 runs from 2026-10-14T23:00Z to 2026-10-15T23:00Z.
    _batch(db, device_id=1, name="Porte A", created_at="2026-10-14T22:59:59Z", status="SUCCESS")  # 14th local
    _batch(db, device_id=1, name="Porte A", created_at="2026-10-14T23:00:00Z", status="SUCCESS",
           attempted=3, success=3)                                                               # 00 h
    _batch(db, device_id=1, name="Porte A", created_at="2026-10-15T08:10:00+00:00", status="PARTIAL",
           attempted=4, success=3, failed=1)                                                     # 09 h
    _batch(db, device_id=1, name="Porte A", created_at="2026-10-15T08:50:00Z", status="FAILED",
           attempted=2, success=0, failed=2)                                                     # 09 h
    _batch(db, device_id=2, name="MB2000", created_at="2026-10-15T22:59:59+00:00", status="SUCCESS")  # 23 h
    _batch(db, device_id=2, name="MB2000", created_at="2026-10-15T23:00:00Z", status="SUCCESS")  # 16th local

    out = db.push_batch_hourly(day="2026-10-15", tz=TUNIS)

    assert out["date"] == "2026-10-15"
    assert out["fromUtc"] == "2026-10-14T23:00:00+00:00"
    assert out["toUtc"] == "2026-10-15T23:00:00+00:00"
    by_id = {d["deviceId"]: d for d in out["devices"]}
    assert set(by_id) == {1, 2}
    hours_a = {c["hour"]: c for c in by_id[1]["hours"]}
    assert sorted(hours_a) == [0, 9]
    assert hours_a[0]["success"] == 1 and hours_a[0]["pinsAttempted"] == 3
    nine = hours_a[9]
    assert (nine["batches"], nine["partial"], nine["failed"], nine["success"]) == (2, 1, 1, 0)
    assert (nine["pinsAttempted"], nine["pinsSuccess"], nine["pinsFailed"]) == (6, 3, 3)
    assert [c["hour"] for c in by_id[2]["hours"]] == [23]
    assert out["totals"] == {"batches": 4, "pinsAttempted": 9, "pinsSuccess": 6, "pinsFailed": 3}


def test_in_progress_unknown_status_and_zero_pin_success_are_counted_as_stored(db):
    _batch(db, device_id=5, name="Porte", created_at="2026-10-15T10:00:00Z", status="IN_PROGRESS")
    _batch(db, device_id=5, name="Porte", created_at="2026-10-15T10:05:00Z", status="SUCCESS")  # 0 pins
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO push_batch_history (sync_run_id, device_id, device_name, policy, status, created_at)"
            " VALUES (NULL, 5, 'Porte', 'PRESERVE', 'INTERRUPTED', '2026-10-15T10:30:00Z')"
        )
        conn.commit()

    cell = db.push_batch_hourly(day="2026-10-15", tz=timezone.utc)["devices"][0]["hours"][0]

    assert cell["hour"] == 10
    assert (cell["batches"], cell["inProgress"], cell["success"], cell["other"]) == (3, 1, 1, 1)
    assert cell["pinsAttempted"] == 0


def test_latest_device_name_wins_and_unparsable_rows_are_left_out(db):
    _batch(db, device_id=3, name="Ancien nom", created_at="2026-10-15T07:00:00Z", status="SUCCESS")
    _batch(db, device_id=3, name="Nouveau nom", created_at="2026-10-15T07:30:00Z", status="SUCCESS")
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO push_batch_history (sync_run_id, device_id, device_name, policy, status, created_at)"
            " VALUES (NULL, 3, 'X', 'PRESERVE', 'SUCCESS', '2026-10-15Tgarbage')"
        )
        conn.commit()

    out = db.push_batch_hourly(day="2026-10-15", tz=timezone.utc)

    assert out["devices"][0]["deviceName"] == "Nouveau nom"
    assert out["totals"]["batches"] == 2


def test_empty_day(db):
    out = db.push_batch_hourly(day="2026-01-01", tz=timezone.utc)
    assert out["devices"] == [] and out["totals"]["batches"] == 0


class _Ctx:
    def __init__(self, query):
        self._q = query
        self.sent = None

    def q(self, *names, default=""):
        for name in names:
            if name in self._q:
                return self._q[name]
        return default

    def send_json(self, status, payload):
        self.sent = (status, payload)


def test_handler_rejects_a_bad_date_and_answers_a_good_one(db):
    from app.api import local_access_api_v2 as api

    bad = _Ctx({"date": "15/10/2026"})
    api._handle_push_history_hourly(bad)
    assert bad.sent[0] == 400

    good = _Ctx({"date": "2026-10-15"})
    api._handle_push_history_hourly(good)
    status, payload = good.sent
    assert status == 200 and payload["ok"] is True and payload["date"] == "2026-10-15"


def test_route_is_registered():
    from access.local_api_routes import ACCESS_LOCAL_ROUTE_SPECS

    assert ("GET", "/api/v2/push-history/hourly", "_handle_push_history_hourly") in ACCESS_LOCAL_ROUTE_SPECS

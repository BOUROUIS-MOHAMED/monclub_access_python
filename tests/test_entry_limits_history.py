from types import SimpleNamespace

from app.core.ultra_engine import UltraDeviceWorker
from tests.test_entry_limits_db import db, seed, row, hold, usage
from tests.test_protocol2_save_and_flip import _exec


def enqueue(worker, uid, event="pass"):
    UltraDeviceWorker._enqueue_history(worker, event_id=event, allowed=True, reason="ALLOW",
        event_type="CARD", card_no="123", event_time="2026-11-02T05:00:00", user_id=uid)


def test_history_off_records_limited_member_and_skips_unlimited(db):
    seed(db, users=[row(), row(2, entryLimits=None, entryUsage=None)])
    recorded = []
    worker = SimpleNamespace(_settings={"save_history": False}, _poll_ema_ms=0,
                             _write_history_item=recorded.append)
    enqueue(worker, 7001)
    enqueue(worker, 7002, "unlimited")
    enqueue(worker, None, "desk")
    assert len(recorded) == 1
    assert recorded[0]["user_id"] == 7001 and recorded[0]["allowed"] is True


def test_history_on_still_records_every_member(db):
    seed(db, users=[row(entryLimits=None, entryUsage=None)])
    recorded = []
    worker = SimpleNamespace(_settings={"save_history": True}, _poll_ema_ms=0,
                             _write_history_item=recorded.append)
    enqueue(worker, 7001)
    assert len(recorded) == 1


def test_limited_user_set_includes_held_members(db):
    seed(db, users=[row(entryUsage=usage(visits=["2026-11-02T05:00:00"]))])
    hold(db)
    assert db.limited_user_ids() == frozenset({7001})


def test_limited_user_cache_recomputes_only_on_generation(db):
    seed(db)
    assert db.limited_user_ids() == frozenset({7001})
    _exec("UPDATE member_access_window SET entry_limits_json=NULL")
    assert db.limited_user_ids() == frozenset({7001})
    db.bump_local_state_generation()
    assert db.limited_user_ids() == frozenset()


def test_limited_user_read_error_returns_empty(db, monkeypatch):
    seed(db)
    db.bump_local_state_generation()
    def fail():
        raise OSError("unreadable windows")
    monkeypatch.setattr(db, "get_conn", fail)
    assert db.limited_user_ids() == frozenset()

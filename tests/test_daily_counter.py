"""Verify count_today_for_user_door() counts correctly per (user, door, day)."""
import uuid
from datetime import datetime, timedelta

import pytest

from app.core.db import (
    count_today_for_user_door,
    get_conn,
    init_db,
    insert_access_history,
)


@pytest.fixture(autouse=True, scope="module")
def _ensure_db():
    init_db()


def _unique_eid() -> str:
    return f"daily-counter-test-{uuid.uuid4().hex}"


def _insert(
    *,
    user_id: int | None,
    device_id: int = 1,
    door_id: int = 1,
    allowed: bool = True,
    created_at: datetime | None = None,
) -> str:
    """Insert a row and (if created_at given) rewrite created_at to simulate past days."""
    eid = _unique_eid()
    insert_access_history(
        event_id=eid,
        device_id=device_id,
        door_id=door_id,
        card_no="CARD-TEST",
        event_time="2026-04-15T10:00:00",
        event_type="scan",
        allowed=allowed,
        reason=None,
        poll_ms=None,
        decision_ms=None,
        cmd_ms=None,
        cmd_ok=None,
        cmd_error=None,
        raw=None,
        user_id=user_id,
    )
    if created_at is not None:
        with get_conn() as conn:
            conn.execute(
                "UPDATE access_history SET created_at=? WHERE event_id=?",
                (created_at.isoformat(sep=" "), eid),
            )
            conn.commit()
    return eid


def _cleanup(eids: list[str]) -> None:
    with get_conn() as conn:
        conn.executemany(
            "DELETE FROM access_history WHERE event_id=?",
            [(e,) for e in eids],
        )
        conn.commit()


def test_count_today_zero_when_no_entries():
    assert count_today_for_user_door(user_id=990001, device_id=1, door_id=1) == 0


def test_count_today_ignores_denied_rows():
    eids = [_insert(user_id=990002, allowed=False) for _ in range(3)]
    try:
        assert count_today_for_user_door(user_id=990002, device_id=1, door_id=1) == 0
    finally:
        _cleanup(eids)


def test_count_today_ignores_yesterday():
    yesterday = datetime.now() - timedelta(days=1)
    eids = [
        _insert(user_id=990003, allowed=True, created_at=yesterday)
        for _ in range(2)
    ]
    try:
        assert count_today_for_user_door(user_id=990003, device_id=1, door_id=1) == 0
    finally:
        _cleanup(eids)


def test_count_today_counts_only_matching_door():
    eids = [_insert(user_id=990004, door_id=2, allowed=True) for _ in range(3)]
    try:
        # Asking about door 1 returns 0 because all entries were on door 2
        assert count_today_for_user_door(user_id=990004, device_id=1, door_id=1) == 0
        # Asking about door 2 returns 3
        assert count_today_for_user_door(user_id=990004, device_id=1, door_id=2) == 3
    finally:
        _cleanup(eids)


def test_count_today_counts_only_matching_user():
    eids = [_insert(user_id=990005, allowed=True) for _ in range(2)]
    try:
        assert count_today_for_user_door(user_id=990005, device_id=1, door_id=1) == 2
        # Different user_id → 0
        assert count_today_for_user_door(user_id=990006, device_id=1, door_id=1) == 0
    finally:
        _cleanup(eids)


def test_count_today_counts_only_matching_device():
    eids = [_insert(user_id=990007, device_id=2, allowed=True) for _ in range(4)]
    try:
        assert count_today_for_user_door(user_id=990007, device_id=1, door_id=1) == 0
        assert count_today_for_user_door(user_id=990007, device_id=2, door_id=1) == 4
    finally:
        _cleanup(eids)


def test_count_today_counts_multiple_allowed_entries_today():
    eids = [_insert(user_id=990008, allowed=True) for _ in range(5)]
    try:
        assert count_today_for_user_door(user_id=990008, device_id=1, door_id=1) == 5
    finally:
        _cleanup(eids)


def test_count_today_ignores_null_user_id():
    """Historical rows without user_id must not be counted (data-quality guard)."""
    eids = [_insert(user_id=None, allowed=True) for _ in range(3)]
    try:
        # None in query itself returns 0 because WHERE user_id = NULL never matches
        assert count_today_for_user_door(user_id=990009, device_id=1, door_id=1) == 0
    finally:
        _cleanup(eids)

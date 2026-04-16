"""Verify insert_access_history accepts user_id and persists it."""
import uuid

import pytest

from app.core.db import get_conn, init_db, insert_access_history


@pytest.fixture(autouse=True, scope="module")
def _ensure_db():
    init_db()


def _unique_event_id() -> str:
    return f"user-id-test-{uuid.uuid4().hex}"


def test_insert_access_history_persists_user_id():
    eid = _unique_event_id()
    rc = insert_access_history(
        event_id=eid,
        device_id=1,
        door_id=1,
        card_no="CARD-TEST",
        event_time="2026-04-15T10:00:00",
        event_type="scan",
        allowed=True,
        reason=None,
        poll_ms=None,
        decision_ms=None,
        cmd_ms=None,
        cmd_ok=None,
        cmd_error=None,
        raw=None,
        user_id=42,
    )
    assert rc == 1

    with get_conn() as conn:
        row = conn.execute(
            "SELECT user_id FROM access_history WHERE event_id=?", (eid,)
        ).fetchone()
        conn.execute("DELETE FROM access_history WHERE event_id=?", (eid,))
        conn.commit()
    assert row is not None
    assert row["user_id"] == 42


def test_insert_access_history_user_id_defaults_to_null():
    """Existing callers that don't pass user_id should keep working; row gets NULL."""
    eid = _unique_event_id()
    rc = insert_access_history(
        event_id=eid,
        device_id=1,
        door_id=1,
        card_no="CARD-TEST",
        event_time="2026-04-15T10:00:00",
        event_type="scan",
        allowed=True,
        reason=None,
        poll_ms=None,
        decision_ms=None,
        cmd_ms=None,
        cmd_ok=None,
        cmd_error=None,
        raw=None,
    )
    assert rc == 1

    with get_conn() as conn:
        row = conn.execute(
            "SELECT user_id FROM access_history WHERE event_id=?", (eid,)
        ).fetchone()
        conn.execute("DELETE FROM access_history WHERE event_id=?", (eid,))
        conn.commit()
    assert row is not None
    assert row["user_id"] is None

"""Regression: a FAILED_RETRYABLE access-history row must become due again once
its retry_after window elapses -- not only after local midnight.

`mark_access_history_sync_failure()` used to persist `backend_next_retry_at`
with `datetime.isoformat()` ("2026-09-03T17:02:50"), while
`list_pending_access_history_for_sync()` compares that TEXT column against
`now_iso()` ("2026-09-03 17:02:50"). SQLite compares TEXT bytewise, and 'T'
(0x54) sorts above ' ' (0x20) at index 10, so a T-separated value was always
greater than any same-day space-separated `now`. The row therefore stayed
invisible to the uploader until the *date* component rolled over -- delaying
door-event upload by up to ~24h.

Both tests below fail on the pre-fix code:
  * the write-path test, because a fresh failure still stores 'T';
  * the migration test, because rows already stuck in the T-separated form
    are never rewritten.

Uses the documented `_DB_PATH` temp-database override so nothing touches the
real runtime store.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.core.db import (
    ACCESS_HISTORY_SYNC_FAILED_RETRYABLE,
    ACCESS_HISTORY_SYNC_PENDING,
)
from app.core.utils import now_iso


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "retry.db"), raising=False)
    db_module.init_db()
    return db_module


def _insert_pending(db, event_id: str) -> int:
    rc = db.insert_access_history(
        event_id=event_id,
        device_id=1,
        door_id=1,
        card_no="CARD-RETRY",
        event_time="2026-04-15 10:00:00",
        event_type="scan",
        allowed=True,
        reason=None,
        poll_ms=None,
        decision_ms=None,
        cmd_ms=None,
        cmd_ok=None,
        cmd_error=None,
        raw=None,
        backend_sync_state=ACCESS_HISTORY_SYNC_PENDING,
    )
    assert rc == 1
    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT id FROM access_history WHERE event_id=?", (event_id,)
        ).fetchone()
    assert row is not None
    return int(row["id"])


def _stored_retry_at(db, row_id: int) -> str | None:
    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT backend_next_retry_at FROM access_history WHERE id=?", (row_id,)
        ).fetchone()
    assert row is not None
    return row["backend_next_retry_at"]


def test_failed_retryable_row_is_due_once_the_backoff_window_elapses(db) -> None:
    """A batch that failed 120s ago with a 30s backoff must be picked up now."""
    row_id = _insert_pending(db, "retry-due-write-path")

    # Same-day, in the past: retry_at lands ~90s before now, so the row is due.
    # Deriving it from the clock (not a literal) is what makes this test
    # discriminating -- a hardcoded past *date* would be selected even with the
    # bug present, because the differing date byte decides the comparison first.
    attempted_at = (datetime.now() - timedelta(seconds=120)).strftime("%Y-%m-%d %H:%M:%S")

    affected = db.mark_access_history_sync_failure(
        row_ids=[row_id],
        error="upload failed",
        retry_after_seconds=30,  # clamped floor: max(30, ...)
        terminal=False,
        attempted_at=attempted_at,
    )
    assert affected == 1

    stored = _stored_retry_at(db, row_id)
    assert stored is not None
    # The defect only manifests inside a single calendar day; if the suite runs
    # across local midnight this assert says so loudly instead of green-washing.
    assert stored[:10] == now_iso()[:10], (
        "test ran across local midnight; retry_at and now no longer share a date"
    )
    assert "T" not in stored, f"backend_next_retry_at must match now_iso() shape, got {stored!r}"
    assert stored == (
        datetime.strptime(attempted_at, "%Y-%m-%d %H:%M:%S") + timedelta(seconds=30)
    ).strftime("%Y-%m-%d %H:%M:%S")

    with db.get_conn() as conn:
        state = conn.execute(
            "SELECT backend_sync_state FROM access_history WHERE id=?", (row_id,)
        ).fetchone()["backend_sync_state"]
    assert state == ACCESS_HISTORY_SYNC_FAILED_RETRYABLE

    due_ids = [r.id for r in db.list_pending_access_history_for_sync(limit=50)]
    assert row_id in due_ids, (
        f"row not due although its retry window elapsed; stored={stored!r} now={now_iso()!r}"
    )


def test_future_backoff_still_hides_the_row(db) -> None:
    """Guard the other direction: a retry window that has NOT elapsed stays hidden."""
    row_id = _insert_pending(db, "retry-due-future")

    affected = db.mark_access_history_sync_failure(
        row_ids=[row_id],
        error="upload failed",
        retry_after_seconds=3600,
        terminal=False,
        attempted_at=now_iso(),
    )
    assert affected == 1

    due_ids = [r.id for r in db.list_pending_access_history_for_sync(limit=50)]
    assert row_id not in due_ids


def test_init_db_normalises_legacy_t_separated_retry_at(db) -> None:
    """Rows already stuck in the pre-fix 'T' form must be rewritten by init_db()."""
    row_id = _insert_pending(db, "retry-due-legacy-row")

    legacy = (datetime.now() - timedelta(seconds=90)).strftime("%Y-%m-%dT%H:%M:%S")
    with db.get_conn() as conn:
        conn.execute(
            "UPDATE access_history SET backend_sync_state=?, backend_next_retry_at=? WHERE id=?",
            (ACCESS_HISTORY_SYNC_FAILED_RETRYABLE, legacy, row_id),
        )
        conn.commit()

    assert legacy[:10] == now_iso()[:10], (
        "test ran across local midnight; legacy retry_at and now no longer share a date"
    )
    # Pre-condition: the stuck row is invisible while it holds the 'T' form.
    assert row_id not in [r.id for r in db.list_pending_access_history_for_sync(limit=50)]

    db.init_db()  # idempotent; carries the one-time normalisation

    normalised = _stored_retry_at(db, row_id)
    assert normalised == legacy.replace("T", " ", 1)
    assert row_id in [r.id for r in db.list_pending_access_history_for_sync(limit=50)]


@pytest.mark.parametrize(
    "suffix_fmt",
    [
        "%Y-%m-%dT%H:%M:%S.%f",  # isoformat() when attempted_at carried microseconds
        "%Y-%m-%dT%H:%M:%S+00:00",  # isoformat() when attempted_at carried an offset
    ],
    ids=["microseconds", "utc-offset"],
)
def test_init_db_normalises_every_shape_the_old_writer_could_emit(db, suffix_fmt) -> None:
    """The old writer was `retry_dt.isoformat()` on a value parsed from
    `ts.replace("Z", "+00:00")`, so a stuck row may carry fractional seconds or a
    UTC offset as well as the bare 19-char form. All must normalise to the
    canonical second-precision shape."""
    row_id = _insert_pending(db, f"retry-due-legacy-{suffix_fmt}")

    moment = datetime.now() - timedelta(seconds=90)
    legacy = moment.strftime(suffix_fmt)
    assert "T" in legacy and len(legacy) > 19

    with db.get_conn() as conn:
        conn.execute(
            "UPDATE access_history SET backend_sync_state=?, backend_next_retry_at=? WHERE id=?",
            (ACCESS_HISTORY_SYNC_FAILED_RETRYABLE, legacy, row_id),
        )
        conn.commit()

    assert legacy[:10] == now_iso()[:10], (
        "test ran across local midnight; legacy retry_at and now no longer share a date"
    )
    assert row_id not in [r.id for r in db.list_pending_access_history_for_sync(limit=50)]

    db.init_db()

    assert _stored_retry_at(db, row_id) == moment.strftime("%Y-%m-%d %H:%M:%S")
    assert row_id in [r.id for r in db.list_pending_access_history_for_sync(limit=50)]


def test_init_db_normalisation_leaves_clean_and_empty_values_alone(db) -> None:
    """The migration must not touch NULL, '' or already-canonical values."""
    canonical = (datetime.now() - timedelta(seconds=90)).strftime("%Y-%m-%d %H:%M:%S")
    null_id = _insert_pending(db, "retry-due-null")
    empty_id = _insert_pending(db, "retry-due-empty")
    clean_id = _insert_pending(db, "retry-due-clean")

    with db.get_conn() as conn:
        conn.execute(
            "UPDATE access_history SET backend_next_retry_at=NULL WHERE id=?", (null_id,)
        )
        conn.execute(
            "UPDATE access_history SET backend_next_retry_at='' WHERE id=?", (empty_id,)
        )
        conn.execute(
            "UPDATE access_history SET backend_next_retry_at=? WHERE id=?", (canonical, clean_id)
        )
        conn.commit()

    db.init_db()

    assert _stored_retry_at(db, null_id) is None
    assert _stored_retry_at(db, empty_id) == ""
    assert _stored_retry_at(db, clean_id) == canonical

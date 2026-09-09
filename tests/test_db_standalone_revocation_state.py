"""Atomic cleanup of standalone revocation ownership and mirror state."""
from __future__ import annotations

import pytest


@pytest.fixture()
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    monkeypatch.setattr(
        db_module,
        "_DB_PATH",
        str(tmp_path / "standalone-revocation.db"),
        raising=False,
    )
    db_module.init_db()
    return db_module


def _seed_both(db, *, device_id: int = 9, pin: str = "34439") -> None:
    db.save_device_sync_state_batch(
        device_id=device_id,
        rows=[(pin, "old-hash", True, None, db.encode_pushed_finger_ids({0, 2}))],
    )
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO device_content_mirror
                (device_id, pin, full_name, card_no, door_bitmask,
                 authorize_tz_id, fp_count, pushed_at, push_ok)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (device_id, pin, "Member", "123", 1, 1, 2, "2026-09-08T00:00:00Z", 1),
        )
        conn.commit()


def _row_counts(db, *, device_id: int = 9, pin: str = "34439") -> tuple[int, int]:
    with db.get_conn() as conn:
        sync_count = conn.execute(
            "SELECT COUNT(*) FROM device_sync_state WHERE device_id=? AND pin=?",
            (device_id, pin),
        ).fetchone()[0]
        mirror_count = conn.execute(
            "SELECT COUNT(*) FROM device_content_mirror WHERE device_id=? AND pin=?",
            (device_id, pin),
        ).fetchone()[0]
    return int(sync_count), int(mirror_count)


def test_atomic_cleanup_deletes_sync_and_mirror_rows(db):
    _seed_both(db)

    db.clear_device_revocation_state(device_id=9, pin="34439")

    assert _row_counts(db) == (0, 0)


def test_atomic_cleanup_rolls_back_both_rows_when_second_delete_fails(db):
    _seed_both(db)
    with db.get_conn() as conn:
        conn.execute(
            """
            CREATE TRIGGER fail_mirror_revoke
            BEFORE DELETE ON device_content_mirror
            BEGIN
                SELECT RAISE(ABORT, 'mirror delete failed');
            END
            """
        )
        conn.commit()

    with pytest.raises(Exception, match="mirror delete failed"):
        db.clear_device_revocation_state(device_id=9, pin="34439")

    assert _row_counts(db) == (1, 1)


def test_failed_first_push_does_not_create_ownership_proof(db):
    db.save_device_sync_state_batch(
        device_id=9,
        rows=[("34439", "attempted-hash", False, "device rejected", None)],
    )

    assert db.list_confirmed_device_sync_pins(device_id=9) == set()


def test_success_creates_ownership_proof_that_survives_a_later_failure(db):
    db.save_device_sync_state_batch(
        device_id=9,
        rows=[("34439", "confirmed-hash", True, None, "")],
    )
    db.save_device_sync_state_batch(
        device_id=9,
        rows=[("34439", "new-attempt", False, "timeout", None)],
    )

    assert db.list_confirmed_device_sync_pins(device_id=9) == {"34439"}


def test_forced_resync_invalidates_hash_without_losing_ownership_or_fingers(db):
    db.save_device_sync_state_batch(
        device_id=9,
        rows=[("34439", "confirmed-hash", True, None, "0,2")],
    )

    assert db.clear_device_sync_hashes(device_id=9) == 1

    with db.get_conn() as conn:
        row = conn.execute(
            """
            SELECT desired_hash, last_ok, pushed_finger_ids, ownership_confirmed
            FROM device_sync_state
            WHERE device_id=? AND pin=?
            """,
            (9, "34439"),
        ).fetchone()
    assert row["desired_hash"] is None
    assert row["last_ok"] == 0
    assert row["pushed_finger_ids"] == "0,2"
    assert row["ownership_confirmed"] == 1
    assert db.list_confirmed_device_sync_pins(device_id=9) == {"34439"}

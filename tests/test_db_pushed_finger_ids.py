"""device_sync_state.pushed_finger_ids — real SQLite round-trip.

The engine-level tests for finger-slot removal drive an in-memory fake, so the
SQL that actually decides what survives a failed push is not exercised there.
This module runs the REAL writer and reader against a temp database, because two
properties of that statement are load-bearing and easy to get wrong:

  * NULL (unknown) must stay distinguishable from '' (known-empty). Collapsing
    them makes every legacy pin's removal set empty and silently preserves the
    write-only-mirror bug the column exists to fix.
  * a FAILED push must not overwrite the stored value -- it is the only record of
    what is actually resident on the terminal.

Uses the documented ``_DB_PATH`` override, so nothing touches the real
C:\\ProgramData database.
"""
from __future__ import annotations

import pytest


@pytest.fixture()
def db(tmp_path, monkeypatch):
    import app.core.db as db_module
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "fingers.db"), raising=False)
    db_module.init_db()
    return db_module


def _fingers(db, device_id=9):
    return db.list_device_pushed_fingers(device_id=device_id)


class TestSchema:
    def test_column_exists_after_migration(self, db):
        with db.get_conn() as conn:
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(device_sync_state)")}
        assert "pushed_finger_ids" in cols


class TestRoundTrip:
    def test_a_finger_set_round_trips(self, db):
        db.save_device_sync_state_batch(
            device_id=9, rows=[("117", "h1", True, None, db.encode_pushed_finger_ids({2, 0}))],
        )
        assert _fingers(db)["117"] == {0, 2}

    def test_empty_set_is_known_not_unknown(self, db):
        """The state after a revocation: we KNOW the pin has no fingers."""
        db.save_device_sync_state_batch(
            device_id=9, rows=[("117", "h1", True, None, db.encode_pushed_finger_ids(set()))],
        )
        assert _fingers(db)["117"] == set()
        assert _fingers(db)["117"] is not None

    def test_a_legacy_row_reads_as_unknown(self, db):
        """A row written by the old 4-tuple caller (still used by PullSDK)."""
        db.save_device_sync_state_batch(device_id=9, rows=[("117", "h1", True, None)])
        assert _fingers(db)["117"] is None

    def test_unknown_and_empty_are_different_values(self, db):
        db.save_device_sync_state_batch(device_id=9, rows=[
            ("117", "h1", True, None),                                        # unknown
            ("118", "h1", True, None, db.encode_pushed_finger_ids(set())),    # known-empty
        ])
        got = _fingers(db)
        assert got["117"] is None
        assert got["118"] == set()

    def test_encode_none_is_null_not_empty_string(self, db):
        assert db.encode_pushed_finger_ids(None) is None
        assert db.encode_pushed_finger_ids(set()) == ""
        assert db.encode_pushed_finger_ids([2, 0, 2]) == "0,2"


class TestFailedPushDoesNotDestroyState:
    def test_a_failed_push_keeps_the_previous_finger_set(self, db):
        db.save_device_sync_state_batch(
            device_id=9, rows=[("117", "h1", True, None, db.encode_pushed_finger_ids({0}))],
        )
        db.save_device_sync_state_batch(
            device_id=9, rows=[("117", "h2", False, "refused", db.encode_pushed_finger_ids(set()))],
        )
        assert _fingers(db)["117"] == {0}, (
            "a failed push must not claim the slot was cleared"
        )

    def test_none_means_no_opinion_and_leaves_the_value_alone(self, db):
        """The PullSDK caller still sends 4-tuples; that must not wipe the column."""
        db.save_device_sync_state_batch(
            device_id=9, rows=[("117", "h1", True, None, db.encode_pushed_finger_ids({0, 1}))],
        )
        db.save_device_sync_state_batch(device_id=9, rows=[("117", "h2", True, None)])
        assert _fingers(db)["117"] == {0, 1}

    def test_a_successful_push_does_update_the_value(self, db):
        db.save_device_sync_state_batch(
            device_id=9, rows=[("117", "h1", True, None, db.encode_pushed_finger_ids({0, 1}))],
        )
        db.save_device_sync_state_batch(
            device_id=9, rows=[("117", "h2", True, None, db.encode_pushed_finger_ids({0}))],
        )
        assert _fingers(db)["117"] == {0}


class TestIsolationBetweenDevices:
    def test_finger_state_is_per_device(self, db):
        """Two terminals at one gym are pushed independently; one clearing a slot
        says nothing about the other."""
        db.save_device_sync_state_batch(
            device_id=8, rows=[("117", "h1", True, None, db.encode_pushed_finger_ids({0}))],
        )
        db.save_device_sync_state_batch(
            device_id=9, rows=[("117", "h1", True, None, db.encode_pushed_finger_ids(set()))],
        )
        assert _fingers(db, 8)["117"] == {0}
        assert _fingers(db, 9)["117"] == set()

"""Bounded retry for a pin that keeps failing on UNCHANGED content (F0 Part B).

WHY THIS EXISTS
---------------
Part A of the same change makes a refused fingerprint template count as a FAILED
sync instead of being stamped SUCCESS. That is correct, and on its own it is a
severe field regression, because two things compound:

  * ``save_device_sync_state`` deliberately does NOT store ``desired_hash`` when
    ``ok=0`` -- so a failed pin keeps a stale hash, and
  * the retry gate re-selects a pin when ``prev_hash != dh OR not prev_ok``.

Both disjuncts are then permanently true, so a pin that can never succeed (a
v9/v10 algorithm mismatch refuses every finger on the roster) is re-pushed on
EVERY sync run forever. Each refused template costs a firmware-cache clear plus a
ten-call probe inside ``_push_templates`` -- inline on the ULTRA worker, with
RTLog polling and door commands blocked.

So Part A must never ship without Part B. These tests pin Part B.

THE TWO INVARIANTS THAT MATTER MOST
-----------------------------------
1. **New content is never delayed.** The backoff keys on
   ``last_attempt_hash == desired_hash``. A re-enrolment changes the hash, so a
   member who re-registers their finger is pushed immediately regardless of how
   many times the old template was refused. A backoff that could strand a
   re-enrolment would be worse than the storm it prevents.

2. **A deferral is not a failure.** ``ultra_engine._flag_pin_for_retry`` writes
   ``ok=0`` with an EMPTY hash to mean "member not in sync_users yet, retry
   later". Counting those would burn a member's free attempts, so their first
   GENUINE failure would land already inside a multi-hour backoff.

``_retry_due`` fails OPEN everywhere (unparseable timestamp, future timestamp,
clock moved backwards): stranding a member's fingerprint is worse than one
wasted push.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from app.core.device_sync import (
    DeviceSyncEngine,
    _SYNC_RETRY_BASE_SEC,
    _SYNC_RETRY_FREE_ATTEMPTS,
    _SYNC_RETRY_MAX_SEC,
)


@pytest.fixture()
def db(tmp_path, monkeypatch):
    import app.core.db as db_module
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "test.db"), raising=False)
    db_module.init_db()
    return db_module


def _stamp(delta_sec: float) -> str:
    """A now_iso()-shaped timestamp `delta_sec` in the past. Local and naive."""
    return (datetime.now() - timedelta(seconds=delta_sec)).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# _retry_due
# ---------------------------------------------------------------------------

class TestRetryDue:
    def test_free_attempts_always_retry_immediately(self):
        """The first N failures behave exactly as before this change."""
        for streak in range(0, _SYNC_RETRY_FREE_ATTEMPTS + 1):
            assert DeviceSyncEngine._retry_due(fail_streak=streak, updated_at=_stamp(0)) is True

    def test_backoff_engages_after_the_free_attempts(self):
        just_failed = _stamp(1)
        assert DeviceSyncEngine._retry_due(
            fail_streak=_SYNC_RETRY_FREE_ATTEMPTS + 1, updated_at=just_failed) is False

    def test_backoff_expires(self):
        long_ago = _stamp(_SYNC_RETRY_BASE_SEC + 60)
        assert DeviceSyncEngine._retry_due(
            fail_streak=_SYNC_RETRY_FREE_ATTEMPTS + 1, updated_at=long_ago) is True

    def test_delay_doubles_then_caps(self):
        """Streak 4 -> 15 min, 5 -> 30 min, ... never beyond the 24 h cap."""
        s1 = _SYNC_RETRY_FREE_ATTEMPTS + 1
        # one second short of the first delay: not due
        assert DeviceSyncEngine._retry_due(
            fail_streak=s1, updated_at=_stamp(_SYNC_RETRY_BASE_SEC - 5)) is False
        # the next streak needs twice as long
        assert DeviceSyncEngine._retry_due(
            fail_streak=s1 + 1, updated_at=_stamp(_SYNC_RETRY_BASE_SEC + 60)) is False
        assert DeviceSyncEngine._retry_due(
            fail_streak=s1 + 1, updated_at=_stamp(2 * _SYNC_RETRY_BASE_SEC + 60)) is True
        # and an enormous streak must not overflow into "never" -- the cap holds
        assert DeviceSyncEngine._retry_due(
            fail_streak=500, updated_at=_stamp(_SYNC_RETRY_MAX_SEC + 60)) is True

    @pytest.mark.parametrize("bad", [None, "", "not-a-date", "2026-13-45 99:99:99"])
    def test_fails_open_on_an_unusable_timestamp(self, bad):
        """Stranding a fingerprint is worse than one wasted push."""
        assert DeviceSyncEngine._retry_due(fail_streak=999, updated_at=bad) is True

    def test_fails_open_when_the_clock_moved_backwards(self):
        future = (datetime.now() + timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S")
        assert DeviceSyncEngine._retry_due(fail_streak=999, updated_at=future) is True


# ---------------------------------------------------------------------------
# storage: fail_streak accounting
# ---------------------------------------------------------------------------

class TestFailStreakAccounting:
    def test_columns_exist_after_init_db(self, db):
        with db.get_conn() as conn:
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(device_sync_state)")}
        assert "fail_streak" in cols
        assert "last_attempt_hash" in cols

    def test_failures_increment_and_success_resets(self, db):
        for _ in range(3):
            db.save_device_sync_state(device_id=1, pin="100", desired_hash="H1",
                                      ok=False, error="template refused")
        st = db.list_device_sync_retry_state(device_id=1)
        assert st["100"][2] == 3, "three failures on the same content must count three"
        assert st["100"][3] == "H1", "last_attempt_hash records what we TRIED"

        db.save_device_sync_state(device_id=1, pin="100", desired_hash="H1",
                                  ok=True, error=None)
        st = db.list_device_sync_retry_state(device_id=1)
        assert st["100"][2] == 0, "any success clears the streak"

    def test_batch_upsert_tracks_the_streak_too(self, db):
        for _ in range(2):
            db.save_device_sync_state_batch(
                device_id=2, rows=[("200", "HB", False, "refused", None)])
        st = db.list_device_sync_retry_state(device_id=2)
        assert st["200"][2] == 2
        assert st["200"][3] == "HB"

    def test_a_deferral_signal_does_not_inflate_the_streak(self, db):
        """ultra_engine._flag_pin_for_retry writes ok=0 with an EMPTY hash to mean
        'not ready yet, retry later'. That is not a push failure.

        Without the empty-hash guard, a repeatedly-deferred member would arrive at
        their FIRST genuine failure already past the free attempts, and go straight
        into a multi-hour backoff.
        """
        db.save_device_sync_state(device_id=3, pin="300", desired_hash="H3",
                                  ok=False, error="refused")
        before = db.list_device_sync_retry_state(device_id=3)["300"]
        assert before[2] == 1

        # exactly what _flag_pin_for_retry sends, twice
        for _ in range(2):
            db.save_device_sync_state_batch(
                device_id=3, rows=[("300", "", False, "deferred: not in sync_users", None)])

        after = db.list_device_sync_retry_state(device_id=3)["300"]
        assert after[2] == 1, "a deferral must not increment fail_streak"
        assert after[3] == "H3", "a deferral must not erase the last real attempt hash"

    def test_old_shape_insert_still_works_after_migration(self, db):
        """1.4.x downgrade safety: an older binary's INSERT omits the new columns.

        Both are added by _ensure_column WITH a default, so the old statement must
        still succeed. This is the one downgrade path that could bite a field PC
        that gets rolled back after an upgrade.
        """
        with db.get_conn() as conn:
            conn.execute(
                """
                INSERT INTO device_sync_state
                    (device_id, pin, desired_hash, last_ok, last_error, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (9, "900", "HOLD", 1, None, "2026-09-11 10:00:00"),
            )
            conn.commit()
            row = conn.execute(
                "SELECT fail_streak, last_attempt_hash FROM device_sync_state "
                "WHERE device_id=9 AND pin='900'"
            ).fetchone()
        assert row["fail_streak"] == 0, "the DEFAULT must apply for an old-shape INSERT"
        assert row["last_attempt_hash"] is None


# ---------------------------------------------------------------------------
# the gate itself
# ---------------------------------------------------------------------------

class TestRetryGate:
    def _engine(self):
        return DeviceSyncEngine(cfg=MagicMock(), logger=logging.getLogger("test"))

    def test_new_content_is_never_delayed(self, db):
        """THE invariant: a re-enrolment must push immediately, however many times
        the PREVIOUS template was refused."""
        for _ in range(50):
            db.save_device_sync_state(device_id=4, pin="400", desired_hash="OLD",
                                      ok=False, error="refused")
        st = db.list_device_sync_retry_state(device_id=4)["400"]
        prev_hash, prev_ok, streak, attempt_hash, seen = st

        assert streak > _SYNC_RETRY_FREE_ATTEMPTS
        assert self._engine()._retry_due(fail_streak=streak, updated_at=seen) is False

        # ...but the gate's own predicate requires attempt_hash == the NEW hash,
        # and a re-enrolment changes it, so the pin is pushed.
        assert attempt_hash == "OLD"
        assert attempt_hash != "NEW_AFTER_REENROL"

    def test_same_content_repeatedly_refused_is_eventually_held_back(self, db):
        for _ in range(_SYNC_RETRY_FREE_ATTEMPTS + 2):
            db.save_device_sync_state(device_id=5, pin="500", desired_hash="SAME",
                                      ok=False, error="refused")
        _h, ok, streak, attempt_hash, seen = db.list_device_sync_retry_state(device_id=5)["500"]

        assert ok is False
        assert attempt_hash == "SAME"
        assert self._engine()._retry_due(fail_streak=streak, updated_at=seen) is False

    def test_an_unknown_pin_defaults_to_push(self, db):
        """A pin with no state row must be pushed, not held back."""
        st = db.list_device_sync_retry_state(device_id=6)
        assert st == {}
        prev_hash, prev_ok, streak, attempt_hash, seen = st.get("999", ("", True, 0, None, None))
        assert prev_ok is True and streak == 0

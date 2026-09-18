"""P3a-2 foundation: the shared removal ceiling, durable writes, the write-ahead
intent table and the ownership point lookup.

Every test that touches SQLite points ``app.core.db._DB_PATH`` at a temp file and
shuts the DbWriter down afterwards, so the installed gym database is never opened.
"""
from __future__ import annotations

import pytest

import app.core.telemetry as tel
from app.core import push_safety as ps


@pytest.fixture()
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "p3a2-foundation.db"), raising=False)
    db_module.init_db()
    yield db_module
    db_module._shutdown_db_writer_for_tests()


@pytest.fixture()
def warns(monkeypatch):
    seen: list[tuple[str, dict]] = []
    monkeypatch.setattr(tel, "warn", lambda name, **f: seen.append((name, f)))
    return seen


# --------------------------------------------------------------------------- #
# One removal ceiling
# --------------------------------------------------------------------------- #

class TestRemovalCeiling:
    def test_the_ceiling_is_the_standalone_rule(self):
        assert ps.removal_ceiling(0) == 10
        assert ps.removal_ceiling(3) == 10
        assert ps.removal_ceiling(40) == 10
        assert ps.removal_ceiling(100) == 25
        assert ps.removal_ceiling(928) == 232

    def test_nothing_to_remove_is_always_allowed(self, warns):
        v = ps.check_bulk_removal(count=0, roster_count=0, path="stale")
        assert v.allowed is True and warns == []

    def test_an_empty_roster_refuses_any_removal(self, warns):
        v = ps.check_bulk_removal(count=1, roster_count=0, path="stale", device_id=5)
        assert v.allowed is False and v.reason == "empty_roster"
        assert [n for n, _ in warns] == ["REVOKE_ABORTED"]
        assert warns[0][1]["count"] == 1 and warns[0][1]["device_id"] == 5

    def test_at_the_ceiling_is_allowed_above_is_refused(self, warns):
        assert ps.check_bulk_removal(count=10, roster_count=3, path="stale").allowed is True
        v = ps.check_bulk_removal(count=11, roster_count=3, path="stale", protocol="ZK_PULLSDK")
        assert v.allowed is False and v.reason == "above_ceiling" and v.ceiling == 10
        name, f = warns[-1]
        assert name == "REVOKE_ABORTED"
        assert f["count"] == 11 and f["roster"] == 3 and f["path"] == "stale"

    def test_the_old_nuke_trigger_is_always_above_the_ceiling(self):
        """stale > desired and stale > 10 (the INCREMENTAL wipe) never passes."""
        for desired in range(0, 400):
            stale = max(desired, 10) + 1
            assert not ps.check_bulk_removal(count=stale, roster_count=desired, path="x").allowed

    def test_ultra_engine_keeps_its_names_as_aliases(self):
        import app.core.ultra_engine as ue
        assert ue._REVOKE_ABSOLUTE_FLOOR == ps.REVOKE_ABSOLUTE_FLOOR
        assert ue._MIRROR_MAX_DELETE_FRACTION == ps.MAX_DELETE_FRACTION


# --------------------------------------------------------------------------- #
# Durable write: synchronous=FULL for that job only
# --------------------------------------------------------------------------- #

class TestDurableWrite:
    def test_a_durable_job_commits_with_synchronous_full_and_restores_normal(self, db):
        seen = {}

        def _probe(conn, profile):
            seen["during"] = conn.execute("PRAGMA synchronous").fetchone()[0]
            return True

        db._run_db_write_sync("probe_durable", _probe, durable=True)
        db._run_db_write_sync("probe_after", lambda c, p: seen.setdefault(
            "after", c.execute("PRAGMA synchronous").fetchone()[0]))
        assert seen["during"] == 2, "FULL (2) while the durable job commits"
        assert seen["after"] == 1, "back to NORMAL (1) for every other job"

    def test_a_durable_job_cannot_nest_inside_another_write_job(self, db):
        def _outer(conn, profile):
            return db._run_db_write_sync("inner", lambda c, p: 1, durable=True)

        with pytest.raises(RuntimeError, match="cannot run inside another write job"):
            db._run_db_write_sync("outer", _outer)

    def test_the_intent_write_is_durable(self, db):
        db.record_push_intents(device_id=8, rows=[("101", "ALI", "123", "h1")],
                               protocol="ZK_STANDALONE")
        prof = db.get_last_db_write_profile("record_push_intents")
        assert prof and prof.get("durable") is True


# --------------------------------------------------------------------------- #
# Write-ahead intent table
# --------------------------------------------------------------------------- #

class TestPushIntents:
    def test_record_and_read_back(self, db):
        n = db.record_push_intents(
            device_id=8, rows=[("101", "ALI", "123", "h1"), ("102", "SONIA", "", "h2"),
                               ("101", "dup", "x", "y")],
            protocol="ZK_STANDALONE",
        )
        assert n == 2, "a duplicate pin in one call is recorded once (first wins)"
        got = db.list_push_intents(device_id=8)
        assert set(got) == {"101", "102"}
        assert got["101"]["name"] == "ALI" and got["101"]["card"] == "123"
        assert got["101"]["protocol"] == "ZK_STANDALONE"
        assert db.get_push_intent(device_id=8, pin="102")["name"] == "SONIA"
        assert db.list_push_intents(device_id=9) == {}

    def test_a_confirmed_state_write_resolves_the_intent(self, db):
        db.record_push_intents(device_id=8, rows=[("101", "A", "1", "h"), ("102", "B", "2", "h")],
                               protocol="ZK_STANDALONE")
        db.save_device_sync_state_batch(device_id=8, rows=[("101", "h", True, None),
                                                           ("102", "h", False, "refused")])
        assert set(db.list_push_intents(device_id=8)) == {"102"}, (
            "ok=1 confirms ownership and clears the intent; a failed push keeps it"
        )
        db.save_device_sync_state(device_id=8, pin="102", desired_hash="h", ok=True, error=None)
        assert db.list_push_intents(device_id=8) == {}

    def test_removal_clears_the_intent(self, db):
        db.record_push_intents(device_id=8, rows=[("101", "A", "1", "h"), ("102", "B", "2", "h")],
                               protocol="ZK_STANDALONE")
        db.clear_device_revocation_state(device_id=8, pin="101")
        db.delete_device_sync_state(device_id=8, pin="102")
        assert db.list_push_intents(device_id=8) == {}

    def test_prune_and_the_boot_migration_never_touch_an_intent(self, db):
        db.record_push_intents(device_id=8, rows=[("777", "A", "1", "h")], protocol="ZK_STANDALONE")
        db.prune_device_sync_state(device_id=8, keep_pins=[])
        db.init_db()                     # runs the every-start ownership migration
        assert set(db.list_push_intents(device_id=8)) == {"777"}
        assert "777" not in db.list_confirmed_device_sync_pins(device_id=8), (
            "an intent is never ownership by itself"
        )

    def test_promotion_mints_ownership_only_for_a_pin_with_an_intent(self, db):
        db.record_push_intents(device_id=8, rows=[("101", "A", "1", "h")], protocol="ZK_STANDALONE")
        assert db.promote_push_intents(device_id=8, pins=["101", "999"]) == 1
        assert db.list_confirmed_device_sync_pins(device_id=8) == {"101"}
        assert db.list_push_intents(device_id=8) == {}
        state = db.list_device_sync_hashes_and_status(device_id=8)
        assert state["101"] == ("", False), "re-evaluated next pass, never assumed in sync"
        assert "999" not in state, "no intent, no row: ownership is never invented"

    def test_promotion_keeps_an_existing_rows_history(self, db):
        db.save_device_sync_state(device_id=8, pin="101", desired_hash="old", ok=False, error="x")
        db.record_push_intents(device_id=8, rows=[("101", "A", "1", "new")], protocol="ZK_STANDALONE")
        db.promote_push_intents(device_id=8, pins=["101"])
        assert db.get_device_sync_ownership_for_pin(device_id=8, pin="101") is True

    def test_drop_and_misses(self, db):
        db.record_push_intents(device_id=8, rows=[("101", "A", "1", "h"), ("102", "B", "2", "h")],
                               protocol="ZK_STANDALONE")
        assert db.note_push_intent_misses(device_id=8, pins=["102"]) == 1
        assert db.list_push_intents(device_id=8)["102"]["readback_misses"] == 1
        # re-recording (a new push attempt) resets the miss count
        db.record_push_intents(device_id=8, rows=[("102", "B", "2", "h")], protocol="ZK_STANDALONE")
        assert db.list_push_intents(device_id=8)["102"]["readback_misses"] == 0
        assert db.drop_push_intents(device_id=8, pins=["101", "nope"]) == 1
        assert set(db.list_push_intents(device_id=8)) == {"102"}


class TestOwnershipPointLookup:
    def test_owned_unowned_and_absent(self, db):
        db.save_device_sync_state(device_id=5, pin="1", desired_hash="h", ok=True, error=None)
        db.save_device_sync_state(device_id=5, pin="2", desired_hash="h", ok=False, error="x")
        assert db.get_device_sync_ownership_for_pin(device_id=5, pin="1") is True
        assert db.get_device_sync_ownership_for_pin(device_id=5, pin="2") is False
        assert db.get_device_sync_ownership_for_pin(device_id=5, pin="3") is False
        assert db.get_device_sync_ownership_for_pin(device_id=6, pin="1") is False

    def test_a_database_error_raises_rather_than_reading_as_not_owned(self, db, monkeypatch):
        from contextlib import contextmanager

        @contextmanager
        def _broken():
            raise RuntimeError("db locked")
            yield  # pragma: no cover

        monkeypatch.setattr(db, "get_conn", _broken)
        with pytest.raises(RuntimeError):
            db.get_device_sync_ownership_for_pin(device_id=5, pin="1")

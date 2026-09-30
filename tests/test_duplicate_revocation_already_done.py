"""A revocation of a pin MonClub itself removed moments earlier is DONE, not SKIPPED_NOT_OWNED.

Gym 45 (2026-09-30, two MB2000s, pinScheme=ACCOUNT). The same revocation reached the worker
twice: a fast-patch bundle (18:03:36), then the pull delta that re-derived the deletion
(18:03:44). The first one deleted the pin and, in the same transaction, its ownership row
(``clear_device_revocation_state``); the second found no row and reported "no MonClub ownership
proof" -- a false "Problème signalé" on both turnstiles. At 00:00 the date-flip pass removed the
departed members (roster diff), then the change detector's revocations of the same members
(targeted, 00:00:59) and a full sync's explicit revocations (00:01:07) were all reported the same
way.

The removal is recorded (``v2_removal_log``, the ownership backup's ``REMOVED`` fact). A pin with
that fact -- removed by MonClub, not written since, under the current pin scheme -- is already
revoked. Every other not-owned pin is still never deleted and still reported.

Real temp SQLite (never the installed database); the terminal is a recording fake.
"""
from __future__ import annotations

import pytest

import app.core.db as dbmod
import app.core.telemetry as tel
from app.core.v2 import lease_gate as lg
from app.core.v2 import problems as pr
from tests.test_account_pin_device_sites import sqlite_db  # noqa: F401  (fixture)
from tests.test_standalone_incremental_sync import _user, _worker
from tests.test_standalone_revoked_pin_removal import RevokeDriver, _authoritative_full_sync

DEVICE = 9          # _worker's device
PIN = "34439"       # MEMBERSHIP scheme: the pin is the membership id


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "already-done.db"), raising=False)
    dbmod.init_db()
    lg.reset_for_tests()
    pr.registry.reset_for_tests()
    yield dbmod
    pr.registry.reset_for_tests()
    lg.reset_for_tests()
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


@pytest.fixture
def tel_log(monkeypatch):
    seen: list[tuple[str, dict]] = []
    monkeypatch.setattr(tel, "warn", lambda name, **f: seen.append((name, f)))
    monkeypatch.setattr(tel, "event", lambda name, **f: seen.append((name, f)))
    return seen


def _named(log, name):
    return [f for n, f in log if n == name]


def _own(db, pin=PIN):
    db.save_device_sync_state(device_id=DEVICE, pin=pin, desired_hash="h", ok=True, error=None)


def _skipped_problem(device=DEVICE):
    return [p for p in pr.registry.snapshot(device) if p["code"] == pr.SKIPPED_NOT_OWNED]


class TestTargetedRevokeTwice:

    def test_the_second_revocation_of_a_removed_pin_is_done(self, db, monkeypatch, tel_log):
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[])
        _own(db)
        assert w._run_standalone_member_revoke(int(PIN)) is True
        assert drv.delete_calls == [[PIN]], "first revocation: the owned pin is deleted"

        assert w._run_standalone_member_revoke(int(PIN)) is True
        assert drv.delete_calls == [[PIN]], "nothing is deleted a second time"
        assert _named(tel_log, "MEMBER_REVOKE_SKIPPED_NOT_OWNED") == [], (
            "18:03:44: the duplicate was reported as 'no MonClub ownership proof'")
        assert _skipped_problem() == [], "no turnstile problem for a revocation already done"
        done = _named(tel_log, "MEMBER_REVOKE_DONE")
        assert [d["mode"] for d in done] == ["deleted", "already_removed"]
        assert getattr(w, "_skipped_revoke_ids", []) == [], "not noted as a skip either"

    def test_a_roster_removal_then_a_targeted_revocation_is_done(self, db, monkeypatch, tel_log):
        """00:00:08 date-flip pass removed the departed pin; 00:00:59 its revocation arrived."""
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "active", "")])
        _own(db)
        w.request_full_sync(reason="date-flip", fingerprint_hash="h1")
        assert w._drain_full_sync_commands(limit=1) == 1
        assert [PIN] in drv.delete_calls, "the departed owned pin left with the roster diff"

        assert w._run_standalone_member_revoke(int(PIN)) is True
        assert _named(tel_log, "MEMBER_REVOKE_SKIPPED_NOT_OWNED") == []
        assert _skipped_problem() == []


class TestFullSyncExplicitRevocationOfARemovedPin:

    def test_it_is_finished_without_a_skip_report(self, db, monkeypatch, tel_log):
        """00:01:07: a full sync's explicit revocations of pins removed at 00:00:08."""
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "active", "")])
        _own(db)
        w.request_full_sync(reason="date-flip", fingerprint_hash="h1")
        assert w._drain_full_sync_commands(limit=1) == 1
        deletes_before = len(drv.delete_calls)

        result = _authoritative_full_sync(w, int(PIN))
        assert len(drv.delete_calls) == deletes_before, "nothing deleted again"
        assert result["ok"] is True and "revoked_ids" not in result, "the revocation is finished"
        assert w._full_sync_revocation_phase == {}
        assert _named(tel_log, "MEMBER_REVOKE_SKIPPED_NOT_OWNED") == []
        assert _skipped_problem() == []
        assert "SKIPPED_NOT_OWNED" not in (w._push_batch_updates[-1].get("error_message") or ""), (
            "the push history must not show it either")


class TestTheSafetyRuleIsUnchanged:
    """A pin MonClub cannot prove it wrote is never deleted -- and still reported."""

    def _second_revoke(self, w):
        assert w._run_standalone_member_revoke(int(PIN)) is True

    def test_a_pin_never_written(self, db, monkeypatch, tel_log):
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[])
        self._second_revoke(w)
        assert drv.delete_calls == []
        assert [s["pin"] for s in _named(tel_log, "MEMBER_REVOKE_SKIPPED_NOT_OWNED")] == [PIN]
        assert _skipped_problem()[0]["pins"] == [PIN]

    def _removed_then(self, db, monkeypatch, then):
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[])
        _own(db)
        assert w._run_standalone_member_revoke(int(PIN)) is True
        then(db)
        return w, drv

    def test_removed_then_a_failed_write(self, db, monkeypatch, tel_log):
        """A later push that was not confirmed: the pin may be on the terminal again."""
        w, drv = self._removed_then(db, monkeypatch, lambda d: d.save_device_sync_state(
            device_id=DEVICE, pin=PIN, desired_hash="h2", ok=False, error="refused"))
        self._second_revoke(w)
        assert drv.delete_calls == [[PIN]]
        assert [s["pin"] for s in _named(tel_log, "MEMBER_REVOKE_SKIPPED_NOT_OWNED")] == [PIN]

    def test_removed_then_a_write_ahead_intent(self, db, monkeypatch, tel_log):
        """A push started (intent committed) and never confirmed."""
        w, drv = self._removed_then(db, monkeypatch, lambda d: d.record_push_intents(
            device_id=DEVICE, protocol="ZK_STANDALONE", rows=[(PIN, "Member", "", "h2")]))
        self._second_revoke(w)
        assert drv.delete_calls == [[PIN]]
        assert [s["pin"] for s in _named(tel_log, "MEMBER_REVOKE_SKIPPED_NOT_OWNED")] == [PIN]

    def test_removed_under_the_previous_pin_scheme(self, db, monkeypatch, tel_log):
        """The same digits name another person after a pin-scheme switch."""
        def _switch_after(d):
            with d.get_conn() as conn:
                conn.execute("UPDATE v2_removal_log SET removed_at = removed_at - 7200")
                conn.execute(
                    "INSERT INTO device_pin_scheme_switch (device_id, previous_scheme, scheme, "
                    "switched_at, cleared_rows) VALUES (?, 'MEMBERSHIP', 'ACCOUNT', ?, 0)",
                    (DEVICE, d.now_iso()))
                conn.commit()
        w, drv = self._removed_then(db, monkeypatch, _switch_after)
        self._second_revoke(w)
        assert drv.delete_calls == [[PIN]]
        assert [s["pin"] for s in _named(tel_log, "MEMBER_REVOKE_SKIPPED_NOT_OWNED")] == [PIN]

    def test_an_unreadable_removal_record_reports_as_before(self, db, monkeypatch, tel_log):
        from app.core.v2 import ownership
        w, drv = self._removed_then(db, monkeypatch, lambda d: None)
        monkeypatch.setattr(ownership, "local_facts",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("locked")))
        self._second_revoke(w)
        assert drv.delete_calls == [[PIN]]
        assert [s["pin"] for s in _named(tel_log, "MEMBER_REVOKE_SKIPPED_NOT_OWNED")] == [PIN]


class TestUnderTheAccountScheme:
    """Gym 45 runs pinScheme=ACCOUNT: membership 34439 was revoked as person pin 85. The
    removal record is keyed by that person pin, which the second revocation maps to again."""

    def test_the_second_revocation_of_a_removed_person_pin_is_done(self, db, monkeypatch, tel_log):
        from tests.test_account_pin_device_sites import _People, _account_worker, _ali_gym, _sonia
        people = _People(monkeypatch, [_ali_gym(), _sonia()])     # membership 5 -> person pin 777
        _own(db, pin="777")
        _own(db, pin="5")                                          # the other person's pin 5
        drv = RevokeDriver()
        w, _c = _account_worker(monkeypatch, users=people.users, driver=drv)
        people.revoke(5)

        assert w._run_standalone_member_revoke(5) is True
        assert w._run_standalone_member_revoke(5) is True
        assert drv.delete_calls == [["777"]], "the person pin, once; never pin 5"
        assert _named(tel_log, "MEMBER_REVOKE_SKIPPED_NOT_OWNED") == []
        assert [(d["pin"], d["mode"]) for d in _named(tel_log, "MEMBER_REVOKE_DONE")] == [
            ("777", "deleted"), ("777", "already_removed")]
        assert _skipped_problem() == []


class TestOnlyARecentStandingRemovalCounts:
    """v2_removal_log rows are never deleted and a vanished state row reads REMOVED whatever
    happened after (review 2026-09-30): an OLD removal, or one followed by another write of the
    pin, proves nothing about the terminal now -- another PC may have written it after a
    handover, or the terminal was refilled after a retire. Those are still reported."""

    def _removed(self, db, monkeypatch):
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[])
        _own(db)
        assert w._run_standalone_member_revoke(int(PIN)) is True
        return w, drv

    def test_a_removal_older_than_a_day_is_not_proof(self, db, monkeypatch, tel_log):
        w, drv = self._removed(db, monkeypatch)
        with db.get_conn() as conn:
            conn.execute("UPDATE v2_removal_log SET removed_at = removed_at - ?", (25 * 3600,))
            conn.commit()
        assert w._run_standalone_member_revoke(int(PIN)) is True
        assert drv.delete_calls == [[PIN]], "still nothing deleted"
        assert [s["pin"] for s in _named(tel_log, "MEMBER_REVOKE_SKIPPED_NOT_OWNED")] == [PIN]

    def test_removed_then_written_again_then_the_row_gone_is_not_proof(self, db, monkeypatch,
                                                                         tel_log):
        import time as _t
        w, drv = self._removed(db, monkeypatch)
        _t.sleep(0.02)
        db.record_push_results(device_id=DEVICE, rows=[(PIN, True, None)])   # a later write
        with db.get_conn() as conn:                                           # its row vanished
            conn.execute("DELETE FROM device_sync_state WHERE device_id=? AND pin=?", (DEVICE, PIN))
            conn.commit()
        assert w._run_standalone_member_revoke(int(PIN)) is True
        assert drv.delete_calls == [[PIN]]
        assert [s["pin"] for s in _named(tel_log, "MEMBER_REVOKE_SKIPPED_NOT_OWNED")] == [PIN]

    def test_the_age_of_a_server_clock_removal_is_read_on_that_clock(self, db, monkeypatch,
                                                                      tel_log):
        """Removal stamped on the server clock (corrected=1), server 2 h behind this PC: 23 h
        old on its own clock (recent), 25 h if compared with the PC's clock."""
        import time as _t
        from app.core.v2 import server_clock
        clock = server_clock.ServerClock()
        now = _t.time()
        clock.add_sample(now - 7200, now, now, source="t")
        monkeypatch.setattr(server_clock, "_default", clock)
        w, drv = self._removed(db, monkeypatch)
        with db.get_conn() as conn:
            assert conn.execute("SELECT corrected FROM v2_removal_log").fetchone()[0] == 1
            conn.execute("UPDATE v2_removal_log SET removed_at = removed_at - ?", (23 * 3600,))
            conn.commit()
        assert w._run_standalone_member_revoke(int(PIN)) is True
        assert _named(tel_log, "MEMBER_REVOKE_SKIPPED_NOT_OWNED") == []
        assert _named(tel_log, "MEMBER_REVOKE_DONE")[-1]["mode"] == "already_removed"


class TestPullSdkTargetedRevokeTwice:
    """The C3 path (device_sync.sync_member_on_connected_sdk) had the same shape: its delete
    clears the ownership row, so a duplicate revocation logged CRITICAL SKIPPED_NOT_OWNED and
    raised a turnstile problem. Same rule; an unowned pin is still never deleted."""

    @pytest.fixture(autouse=True)
    def _clean(self):
        lg.reset_for_tests()
        pr.registry.reset_for_tests()
        yield
        pr.registry.reset_for_tests()
        lg.reset_for_tests()

    def _revoke(self, sqlite_db, sdk):
        from tests.test_account_pin_device_sites import _engine, _pullsdk_device
        eng = _engine()
        ok = eng.sync_member_on_connected_sdk(sdk=sdk, device=_pullsdk_device(pinScheme="ACCOUNT"),
                                              member_id=5, revocation=True)
        return eng, ok

    def _setup(self, sqlite_db):
        from tests.test_account_pin_device_sites import _ali_gym, _cache, _sonia
        _cache(sqlite_db, [_ali_gym(), _sonia()])
        _cache(sqlite_db, [], valid_ids=[31000])               # Sonia (person pin 777) revoked
        sqlite_db.save_device_sync_state(device_id=1, pin="777", desired_hash="h", ok=True, error=None)

    def test_the_second_revocation_is_done(self, sqlite_db, tel_log):
        from tests.test_account_pin_device_sites import _deleted_pins, _removed_pins, _sdk
        self._setup(sqlite_db)
        sdk1, sdk2 = _sdk(), _sdk()
        eng, ok = self._revoke(sqlite_db, sdk1)
        assert ok is True and _removed_pins(sdk1) == {"777"}
        eng, ok = self._revoke(sqlite_db, sdk2)
        assert ok is True, "the revocation is finished"
        assert eng._last_member_sync_outcome == "ALREADY_REMOVED"
        assert _deleted_pins(sdk2) == [], "nothing deleted a second time"
        assert _named(tel_log, "MEMBER_REVOKE_SKIPPED_NOT_OWNED") == []
        assert [d["mode"] for d in _named(tel_log, "MEMBER_REVOKE_DONE")] == ["already_removed"]
        assert _skipped_problem(1) == []

    def test_an_old_removal_is_still_reported_and_nothing_deleted(self, sqlite_db, tel_log):
        from tests.test_account_pin_device_sites import _deleted_pins, _sdk
        self._setup(sqlite_db)
        self._revoke(sqlite_db, _sdk())
        with sqlite_db.get_conn() as conn:
            conn.execute("UPDATE v2_removal_log SET removed_at = removed_at - ?", (25 * 3600,))
            conn.commit()
        sdk2 = _sdk()
        eng, ok = self._revoke(sqlite_db, sdk2)
        assert ok is False and eng._last_member_sync_outcome == "SKIPPED_NOT_OWNED"
        assert _deleted_pins(sdk2) == []
        assert [s["pin"] for s in _named(tel_log, "MEMBER_REVOKE_SKIPPED_NOT_OWNED")] == ["777"]
        assert _skipped_problem(1)[0]["pins"] == ["777"]

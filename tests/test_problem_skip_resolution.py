"""A SKIPPED_NOT_OWNED turnstile problem clears once it is resolved, and the server is told.

Gym 45 (2026-09-30): pin 85 was reported SKIPPED_NOT_OWNED at 18:03:44 and re-pushed with
every write OK at 18:08; the banner stayed. ``problems.py`` only ever ADDED such pins and
dropped them after 7 days (``SKIPPED_TTL_SEC``); the registry lives in memory, so the entry
stayed until a restart or a week later. The report contract (``reports.py``, backend
p2c2-ownership-reports §2): a snapshot REPLACES the PC's previous one, a code left out is
resolved -- no new field.

Resolved = MonClub owns the pin again (re-pushed and confirmed, or proven by the read-back),
MonClub removed it since, or a COMPLETE listing of the terminal shows it absent.
Real temp SQLite; the installed database is never opened.
"""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

import app.core.db as dbmod
from app.core.v2 import lease_gate as lg
from app.core.v2 import loss
from app.core.v2 import problems as pr
from app.core.v2 import removed_pins
from app.core.v2.reports import ProblemReporter
from app.core.v2.server_clock import ServerClock

DEVICE = 8


@pytest.fixture(autouse=True)
def _clean():
    lg.reset_for_tests()
    pr.registry.reset_for_tests()
    yield
    lg.reset_for_tests()
    pr.registry.reset_for_tests()


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "skip-resolution.db"), raising=False)
    dbmod.init_db()
    yield dbmod
    dbmod._shutdown_db_writer_for_tests()


def _skipped(device=DEVICE):
    return [p["pins"] for p in pr.registry.snapshot(device) if p["code"] == pr.SKIPPED_NOT_OWNED]


class TestRegistry:

    def test_a_resolved_pin_leaves_the_report_and_marks_it_changed(self):
        pr.registry.skipped_not_owned(DEVICE, ["85", "86"])
        before = pr.registry.changed_at(DEVICE)
        time.sleep(0.01)
        pr.registry.resolve_skipped(DEVICE, ["85"])
        assert _skipped() == [["86"]]
        assert pr.registry.changed_at(DEVICE) > before, "the reporter sends a changed snapshot"
        pr.registry.resolve_skipped(DEVICE, ["86"])
        assert pr.registry.snapshot(DEVICE) == [], "the code is left out: resolved on the server"

    def test_a_skip_recorded_after_the_check_survives(self):
        pr.registry.skipped_not_owned(DEVICE, ["85"])
        checked_at = time.time() - 60          # the facts were read before this skip landed
        pr.registry.resolve_skipped(DEVICE, ["85"], recorded_before=checked_at)
        assert _skipped() == [["85"]]


class TestSettledFromTheLocalRecord:

    def test_re_pushed_or_removed_since_resolves_nothing_else_does(self, db):
        db.save_device_sync_state(device_id=DEVICE, pin="102", desired_hash="h", ok=True, error=None)
        pr.registry.skipped_not_owned(DEVICE, ["101", "102", "103", "104"])
        time.sleep(0.01)
        db.save_device_sync_state(device_id=DEVICE, pin="101", desired_hash="h", ok=True, error=None)
        db.clear_device_revocation_state(device_id=DEVICE, pin="102")
        db.save_device_sync_state(device_id=DEVICE, pin="104", desired_hash="h2", ok=False, error="x")

        assert removed_pins.settle_skipped(DEVICE) == ["101", "102"]
        assert _skipped() == [["103", "104"]], (
            "103: no fact at all; 104: a write that was not confirmed -- still unproven")

    def test_an_unreadable_record_resolves_nothing(self, monkeypatch):
        def _boom(*a, **k):
            raise RuntimeError("database is locked")
        monkeypatch.setattr(removed_pins, "pin_states", _boom)
        pr.registry.skipped_not_owned(DEVICE, ["85"])
        assert removed_pins.settle_skipped(DEVICE) == []
        assert _skipped() == [["85"]]


class FakeApi:
    def __init__(self):
        self.bodies = []

    def turnstile_problems(self, body):
        self.bodies.append(body)
        return {"stale": False, "ignoredCodes": []}


def _reporter(api):
    clock = ServerClock()
    now = time.time()
    clock.add_sample(now, now, now, source="t")
    rep = ProblemReporter(SimpleNamespace(api=api, clock=clock))
    rep._scheme = lambda did: "ACCOUNT"
    return rep


def test_the_next_report_tells_the_server(db):
    """18:03:44 skip, 18:08 re-push: the next report no longer carries the problem."""
    api = FakeApi()
    rep = _reporter(api)
    pr.registry.removal_allowed(DEVICE, "standalone_revoke")
    pr.registry.skipped_not_owned(DEVICE, ["85"])
    rep.tick(None)
    assert [p["code"] for p in api.bodies[-1]["problems"]] == ["SKIPPED_NOT_OWNED"]

    time.sleep(0.01)
    db.save_device_sync_state(device_id=DEVICE, pin="85", desired_hash="h", ok=True, error=None)
    rep._next_check = 0
    rep.tick(None)
    assert len(api.bodies) == 2 and api.bodies[-1]["problems"] == []


class TestAbsentFromACompleteListing:

    def _listing(self, on_device):
        return loss.evaluate_listing(DEVICE, on_device=on_device, owned={"1", "2"}, desired=None)

    def test_a_complete_listing_without_the_pin_resolves_it(self):
        pr.registry.skipped_not_owned(DEVICE, ["85", "86"])
        self._listing({"1", "2", "86"})
        assert _skipped() == [["86"]], "85 is not on the terminal: nothing left to revoke"

    def test_a_listing_missing_an_owned_pin_proves_no_absence(self):
        pr.registry.skipped_not_owned(DEVICE, ["85"])
        self._listing({"1"})                    # owned pin 2 missing: maybe cut short
        assert _skipped() == [["85"]]

    def test_an_untrusted_listing_changes_nothing(self):
        pr.registry.skipped_not_owned(DEVICE, ["85"])
        self._listing({"9"})                    # shows none of MonClub's pins
        assert _skipped() == [["85"]]

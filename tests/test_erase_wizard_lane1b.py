"""Lane 1b (2026-09-27): the Erase-content wizard's safety fixes after the master review.

Guide §3.2h, §3.10. Each class pins one finding of the review (F = confirmed, C = critic), against
the same fakes as tests/test_erase_wizard.py -- nothing reaches a device:
* C0  the hold binds this PC only: an erase needs "every other PC closed" confirmed;
* C1  no erase the refill could not undo: no member list, a failed sync, an empty roster or
      withheld ACCOUNT rows refuse it (for "hold", under ACCOUNT too);
* F12 the erase makes every recorded pin's last push result unknown BEFORE its first delete;
* F0  a held turnstile's heartbeat line says ``held`` and counts its whole roster waiting;
* C5  a C3 table that counted 0 gets no DeleteDeviceData;
* F1  a hold whose run stopped before any delete is released at the next start, never another;
* F2  a second run never releases an earlier "hold until Refill";
* F8  a release asks the pass the hold cut short again;
* C4  an MB2000 administrator pin that the refill would write as a member refuses the erase.
"""
from __future__ import annotations

import json
import logging
import time
from types import SimpleNamespace
from typing import List

import pytest

import app.core.db as dbmod
import app.core.erase_wizard as ew
from app.core import device_hold
from app.core.v2 import lease_gate as lg
from app.core.erase_wizard import check_erase_switch as _real_check_erase_switch
from tests.test_erase_wizard import (  # noqa: F401 -- fixtures are used by name
    FakePanel, _app, _body, _device, _devices, _mb_body, _mb_setup, _own, _panel, _pw_ok,
    _refill_body, _removed, _setup_c3, _state, _terminal, _wizard, erase_switch_on, refill_cache,
    sqlite_db,
)


def _results(did):
    return {p: (r[0], r[3]) for p, r in dbmod.list_push_results(device_id=did).items()}


def _hold_reason(did):
    return (dbmod.list_device_write_holds().get(did) or {}).get("reason")


def _preview(wiz, did):
    status, pv = wiz.preview(did)
    assert status == 200, pv
    return pv


# ─────────────────────────── C0: several PCs ───────────────────────────

class TestEveryOtherPcMustBeClosed:

    def test_an_erase_is_refused_until_the_other_pcs_are_confirmed_closed(
            self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        body = _body(pv["previewId"])
        del body["otherPcsClosed"]
        status, out = wiz.start(5, body, verify_password=_pw_ok)
        assert status == 400 and out["code"] == "OTHER_PCS_NOT_CONFIRMED"
        status, out = wiz.start(5, _body(pv["previewId"], otherPcsClosed="yes"),
                                verify_password=_pw_ok)
        assert status == 400 and out["code"] == "OTHER_PCS_NOT_CONFIRMED", "only a real true"
        assert not device_hold.is_held(5)
        # Step 1's counts and user list (lane 1c) only: no backup read, no erase.
        assert {c for c in panel.calls if c[0] != "count"} == {("read", "user")}

    def test_a_backup_only_rehearsal_does_not_need_it(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        body = _body(pv["previewId"], backupOnly=True)
        del body["otherPcsClosed"]
        assert wiz.start(5, body, verify_password=_pw_ok)[0] == 202
        assert wiz.status()["run"]["state"] == "DONE"

    def test_the_run_records_the_confirmation(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert wiz.status()["run"]["otherPcsClosed"] is True


# ─────────────────────────── C1: can the refill really refill? ───────────────────────────

class TestTheRefillMustBeAbleToRefill:

    def test_the_preview_says_how_many_members_the_refill_writes(self, sqlite_db, monkeypatch,
                                                                 tmp_path):
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        refill = _preview(wiz, 5)["refill"]
        assert refill["scheme"] == "MEMBERSHIP" and refill["members"] == 4
        assert refill["withheld"] == 0 and refill["problem"] is None
        assert refill["ifAccount"] == {"members": 4, "withheld": 0}
        assert refill["accountProblem"] is None and refill["lastSyncOk"] is True
        assert refill["cacheUpdatedAt"] == "2026-09-27T10:00:00"
        assert "_pins" not in refill, "pins stay on the server"

    @pytest.mark.parametrize("case, code", [
        ("missing", "REFILL_SOURCE_MISSING"),
        ("unreadable", "REFILL_SOURCE_MISSING"),
        ("stale", "REFILL_SOURCE_STALE"),
        ("empty", "REFILL_SOURCE_EMPTY"),
    ])
    def test_no_erase_the_refill_could_not_undo(self, sqlite_db, monkeypatch, tmp_path,
                                                refill_cache, case, code):
        wiz, _w, panel, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        if case == "missing":
            monkeypatch.setattr(dbmod, "load_sync_cache", lambda: None)
        elif case == "unreadable":
            def _boom():
                raise RuntimeError("database is locked")
            monkeypatch.setattr(dbmod, "load_sync_cache", _boom)
        elif case == "stale":
            app._last_sync_ok = False
        else:
            refill_cache.users = []
        for refill in ("now", "auto", "hold"):
            status, out = wiz.start(5, _body(pv["previewId"], refill=refill),
                                    verify_password=_pw_ok)
            assert status == 409 and out["code"] == code, (refill, out)
        assert not device_hold.is_held(5) and wiz.status()["run"] is None
        assert {c for c in panel.calls if c[0] != "count"} == {("read", "user")}, (
            "nothing read beyond step 1 (its counts and user list, lane 1c), nothing erased")

    def test_a_process_that_never_synced_is_stale(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, _p, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        del app._last_sync_ok
        pv = _preview(wiz, 5)
        assert pv["refill"]["problem"] == "REFILL_SOURCE_STALE"
        assert wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)[1]["code"] == (
            "REFILL_SOURCE_STALE")

    def test_withheld_account_rows_refuse_an_account_turnstile(self, sqlite_db, monkeypatch,
                                                               tmp_path, refill_cache):
        panel = _panel()
        worker_app = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=panel)
        wiz = worker_app[0]
        _devices(monkeypatch, dict(_device(), pinScheme="ACCOUNT"))
        refill_cache.users.append({"userId": 15, "activeMembershipId": 103, "fullName": "No acct"})
        pv = _preview(wiz, 5)
        assert pv["refill"]["withheld"] == 1 and pv["refill"]["problem"] == "REFILL_WITHHELD"
        status, out = wiz.start(5, _body(pv["previewId"], refill="now"), verify_password=_pw_ok)
        assert status == 409 and out["code"] == "REFILL_WITHHELD" and out["withheld"] == 1
        assert out["pinScheme"] == "ACCOUNT" and not device_hold.is_held(5)

    def test_hold_is_checked_under_account_too(self, sqlite_db, monkeypatch, tmp_path,
                                               refill_cache):
        """The cutover: erase under MEMBERSHIP, switch to ACCOUNT, Refill. A row with no
        mainAccountId is written under MEMBERSHIP but withheld under ACCOUNT."""
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        refill_cache.users.append({"userId": 15, "activeMembershipId": 103, "fullName": "No acct"})
        pv = _preview(wiz, 5)
        assert pv["refill"]["problem"] is None and pv["refill"]["members"] == 5
        assert pv["refill"]["ifAccount"] == {"members": 4, "withheld": 1}
        assert pv["refill"]["accountProblem"] == "REFILL_WITHHELD"
        status, out = wiz.start(5, _body(pv["previewId"], refill="hold"), verify_password=_pw_ok)
        assert status == 409 and out["code"] == "REFILL_WITHHELD" and out["pinScheme"] == "ACCOUNT"
        # Refilled now, under the scheme recorded now: every member is written.
        status, _ = wiz.start(5, _body(pv["previewId"], refill="now"), verify_password=_pw_ok)
        assert status == 202 and wiz.status()["run"]["state"] == "DONE"

    def test_backup_only_needs_no_refill(self, sqlite_db, monkeypatch, tmp_path, refill_cache):
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        refill_cache.users = []
        pv = _preview(wiz, 5)
        assert wiz.start(5, _body(pv["previewId"], backupOnly=True),
                         verify_password=_pw_ok)[0] == 202

    def test_counting_is_quiet(self, sqlite_db, monkeypatch, tmp_path, refill_cache, caplog):
        """The refill check never logs the withheld WARNING nor emits its [T] event: the
        runbook reads PIN_SCHEME_ACCOUNT_WITHHELD as one line per real pass."""
        events: List[str] = []
        monkeypatch.setattr("app.core.telemetry.warn", lambda name, **k: events.append(name))
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        refill_cache.users.append({"userId": 15, "activeMembershipId": 103, "fullName": "No acct"})
        with caplog.at_level(logging.WARNING):
            _preview(wiz, 5)
        assert "PIN_SCHEME_ACCOUNT_WITHHELD" not in events
        assert "WITHHELD" not in caplog.text

    def test_the_roster_is_the_passes_own_filter_on_a_copy(self):
        device = {"id": 5, "allowedMemberships": [7], "pinScheme": "MEMBERSHIP"}
        cache = SimpleNamespace(users=[
            {"userId": 1, "activeMembershipId": 101, "membershipId": 7},
            {"userId": 2, "activeMembershipId": 102, "membershipId": 8},     # not for this device
        ])
        out = ew.refill_roster(device, cache)
        assert out["members"] == 1 and out["pins"] == frozenset({"101"})
        assert "doorIds" not in device, "the filter writes doorIds into a COPY only"


# ─────────────────────────── F12: the last push result ───────────────────────────

class TestTheEraseMakesEveryResultUnknown:

    def test_an_incomplete_erase_leaves_no_true_standing(self, sqlite_db, monkeypatch, tmp_path):
        """F12 case 1: INCOMPLETE used to keep lastPushOk=true for pins it may have erased."""
        _own(sqlite_db, 5, ["101", "102"])
        sqlite_db.record_push_results(device_id=5, rows=[("101", True, None), ("102", True, None)])
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        panel.refuse_erase = {"user"}
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], forget=False), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "INCOMPLETE"
        res = sqlite_db.list_push_results(device_id=5)
        for pin in ("101", "102"):
            ok, at, _corrected, err = res[pin]
            assert ok is None and err is None and at is not None, (pin, res[pin])

    def test_the_reset_is_uploaded_as_null(self, sqlite_db, monkeypatch, tmp_path):
        from app.core.v2 import ownership as own
        from tests.test_v2_ownership import FakeApi, _rt
        _own(sqlite_db, 5, ["101"])
        sqlite_db.record_push_results(device_id=5, rows=[("101", True, None)])
        api = FakeApi()
        sync = own.OwnershipSync(_rt(api))
        sync.upload(5)
        assert {r["pin"]: r for r in api.uploads[-1]["rows"]}["101"]["lastPushOk"] is True
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        panel.refuse_erase = {"user"}
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], forget=False), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "INCOMPLETE"
        sync.upload(5)
        row = {r["pin"]: r for r in api.uploads[-1]["rows"]}["101"]
        assert row["lastPushOk"] is None and row["state"] == "APPLIED"

    def test_a_rights_only_keep_erase_resets_too(self, sqlite_db, monkeypatch, tmp_path):
        """F12 case 2: a C3 erase of userauthorize alone, records kept."""
        _own(sqlite_db, 5, ["101"])
        sqlite_db.record_push_results(device_id=5, rows=[("101", True, None)])
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], tables=["userauthorize"], forget=False, refill="now"),
                  verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "DONE"
        assert _results(5)["101"] == (None, None)

    def test_the_reset_is_durable_before_the_first_delete(self, sqlite_db, monkeypatch, tmp_path):
        _own(sqlite_db, 5, ["101"])
        sqlite_db.record_push_results(device_id=5, rows=[("101", True, None)])
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        seen = []
        panel.on_erase = lambda table: seen.append((table, _results(5)["101"], _hold_reason(5)))
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert seen and seen[0] == ("templatev10", (None, None), "erase"), seen

    def test_no_reset_no_erase(self, sqlite_db, monkeypatch, tmp_path):
        _own(sqlite_db, 5, ["101"])
        sqlite_db.record_push_results(device_id=5, rows=[("101", True, None)])

        def _fails(*a, **k):
            raise RuntimeError("disk I/O error")
        monkeypatch.setattr(ew, "_begin_erase", _fails)
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "RESULTS_NOT_RESET" in run["error"]
        assert not [c for c in panel.calls if c[0] == "erase"]
        assert not device_hold.is_held(5) and _results(5)["101"] == (True, None)

    def test_a_rehearsal_resets_nothing(self, sqlite_db, monkeypatch, tmp_path):
        _own(sqlite_db, 5, ["101"])
        sqlite_db.record_push_results(device_id=5, rows=[("101", True, None)])
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], backupOnly=True), verify_password=_pw_ok)
        assert _results(5)["101"] == (True, None)

    def test_the_kept_mb2000_admin_keeps_its_result(self, sqlite_db, monkeypatch, tmp_path):
        _own(sqlite_db, 8, ["1", "30001"])
        sqlite_db.record_push_results(device_id=8, rows=[("1", True, None), ("30001", True, None)])
        wiz, _w, drv = _mb_setup(monkeypatch, tmp_path, _terminal())
        try:
            pv = _preview(wiz, 8)
            wiz.start(8, _mb_body(pv["previewId"]), verify_password=_pw_ok)
        finally:
            drv.disconnect()
        assert wiz.status()["run"]["state"] == "DONE"
        assert _results(8)["1"] == (True, None), "the admin stays on the terminal"
        assert "30001" not in _results(8), "forget deleted the member's row after the reset"


# ─────────────────────────── F0: the heartbeat of a held turnstile ───────────────────────────

def _heartbeat_app(monkeypatch, refill_cache, *devices):
    from app.core import db as _db
    refill_cache.devices = [dict(d) for d in devices]
    monkeypatch.setattr(_db, "peek_sync_cache", lambda: refill_cache)
    snap = {int(d["id"]): {"connected": True, "failed_pins": 0} for d in devices}
    return SimpleNamespace(
        _update_manager=SimpleNamespace(get_current_version=lambda: "9.9.9"),
        _agent_engine=SimpleNamespace(get_status_snapshot=lambda: {}),
        _ultra_engine=SimpleNamespace(get_status=lambda: {"devices": snap}),
        _last_sync_at=None, _last_sync_ok=True)


class TestTheHeartbeatOfAHeldTurnstile:

    def test_a_held_line_counts_its_whole_roster_and_says_held(self, sqlite_db, monkeypatch,
                                                               refill_cache):
        from access.pc_identity import build_heartbeat_payload
        app = _heartbeat_app(monkeypatch, refill_cache, _device(did=5), _device(did=6, name="B"))
        device_hold.hold(5, reason="erase", run_id="r")
        lines = {t["gymDeviceId"]: t for t in build_heartbeat_payload(app)["turnstiles"]}
        assert lines[5]["held"] is True and lines[5]["failedPins"] == 4
        assert lines[6] == {"gymDeviceId": 6, "reachable": True, "failedPins": 0, "mode": "ULTRA"}

    def test_it_survives_a_restart(self, sqlite_db, monkeypatch, refill_cache):
        from access.pc_identity import build_heartbeat_payload
        app = _heartbeat_app(monkeypatch, refill_cache, _device(did=5))
        device_hold.hold(5, reason="erase", run_id="r")
        device_hold.reset_for_tests()                     # the process ends
        device_hold.load(release_unstarted=True)          # the next start
        line = build_heartbeat_payload(app)["turnstiles"][0]
        assert line["held"] is True and line["failedPins"] == 4

    def test_unreadable_holds_report_every_line_held(self, sqlite_db, monkeypatch, refill_cache):
        from access.pc_identity import build_heartbeat_payload
        app = _heartbeat_app(monkeypatch, refill_cache, _device(did=5), _device(did=6, name="B"))
        monkeypatch.setattr(device_hold, "_load_failed", True)
        lines = build_heartbeat_payload(app)["turnstiles"]
        assert all(t["held"] is True and t["failedPins"] == 4 for t in lines)

    def test_no_cache_in_memory_keeps_the_figure_and_still_says_held(self, sqlite_db,
                                                                     monkeypatch, refill_cache):
        from access.pc_identity import build_heartbeat_payload
        app = _heartbeat_app(monkeypatch, refill_cache, _device(did=5))
        monkeypatch.setattr(dbmod, "peek_sync_cache", lambda: None)
        device_hold.hold(5, reason="erase", run_id="r")
        line = build_heartbeat_payload(app)["turnstiles"]
        assert line == [{"gymDeviceId": 5, "reachable": True, "failedPins": 0, "mode": "ULTRA",
                         "held": True}], "the size cannot be told: the worker's figure stays"

    def test_the_cache_row_is_filtered_as_the_passes_filter_it(self, sqlite_db, monkeypatch,
                                                               refill_cache):
        """The sync cache keeps the DB row (snake_case). The passes filter the payload shape:
        ``allowedMemberships`` read from a snake_case row would be missed and every member
        counted (found in review of this lane)."""
        from access.pc_identity import build_heartbeat_payload
        refill_cache.users = [
            {"userId": 1, "activeMembershipId": 101, "mainAccountId": 9101, "membershipId": 7},
            {"userId": 2, "activeMembershipId": 102, "mainAccountId": 9102, "membershipId": 8},
            {"userId": 3, "activeMembershipId": 103, "membershipId": 7},          # no account id
        ]
        row = {"id": 5, "name": "Entrée 1", "ip_address": "192.168.0.202", "port_number": 4370,
               "access_data_mode": "ULTRA", "allowed_memberships": [7], "pin_scheme": "ACCOUNT"}
        app = _heartbeat_app(monkeypatch, refill_cache, _device(did=5))
        refill_cache.devices = [row]
        device_hold.hold(5, reason="erase", run_id="r")
        line = build_heartbeat_payload(app)["turnstiles"][0]
        assert line["held"] is True and line["failedPins"] == 1, (
            "membership 7 only, under ACCOUNT: 101's person; 103 is withheld")

    def test_the_run_leaves_the_roster_waiting_not_none(self, sqlite_db, monkeypatch, tmp_path):
        """F0: _records used to set None, which the heartbeat sends as 0."""
        wiz, worker, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], refill="now"), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "DONE"
        assert worker._waiting_pins == 4

    def test_refill_sets_the_roster_waiting_too(self, sqlite_db, monkeypatch, tmp_path):
        wiz, worker, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        device_hold.hold(5, reason="erase", run_id="r")
        worker._waiting_pins = 0
        status, _ = wiz.refill(5, _refill_body(), verify_password=_pw_ok)
        assert status == 200 and worker._waiting_pins == 4


# ─────────────────────────── C5: a table that counted 0 ───────────────────────────

class _RefusingPanel(FakePanel):
    """A C3 whose DeleteDeviceData refuses some tables (rc < 0: clear_device_table raises)."""

    def __init__(self, tables, refuse):
        super().__init__(tables)
        self.refuse = set(refuse)

    def erase_table(self, *, table):
        if table in self.refuse:
            self.calls.append(("erase", table))
            raise RuntimeError(f"DeleteDeviceData FAILED table={table} rc=-2")
        return super().erase_table(table=table)


class TestAnEmptyTableGetsNoDelete:

    def test_an_empty_v9_template_table_is_not_sent_a_delete(self, sqlite_db, monkeypatch,
                                                             tmp_path):
        tables = dict(_panel().tables, template=[])
        panel = _RefusingPanel(tables, refuse={"template"})
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=panel)
        pv = _preview(wiz, 5)
        body = _body(pv["previewId"], tables=["user", "userauthorize", "templatev10", "template"])
        wiz.start(5, body, verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "DONE", run["error"]
        assert ("erase", "template") not in panel.calls
        step = [s for s in run["steps"] if s["step"] == "erase_template"][0]
        assert step["skipped"] == "empty"

    def test_a_table_that_had_rows_is_still_erased_and_verified(self, sqlite_db, monkeypatch,
                                                                tmp_path):
        tables = dict(_panel().tables, template=[{"Pin": "101", "FingerID": "1"}])
        panel = FakePanel(tables)
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=panel)
        pv = _preview(wiz, 5)
        body = _body(pv["previewId"], tables=["user", "userauthorize", "templatev10", "template"])
        wiz.start(5, body, verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "DONE"
        assert [c[1] for c in panel.calls if c[0] == "erase"] == [
            "templatev10", "template", "userauthorize", "user"]
        assert panel.tables["template"] == []

    def test_rows_that_appear_in_a_skipped_table_are_caught_by_the_verify(
            self, sqlite_db, monkeypatch, tmp_path):
        tables = dict(_panel().tables, template=[])
        panel = FakePanel(tables)

        def _someone_writes(table):
            if table == "templatev10":
                panel.tables["template"].append({"Pin": "101", "FingerID": "1"})
        panel.on_erase = _someone_writes
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=panel)
        pv = _preview(wiz, 5)
        body = _body(pv["previewId"], tables=["user", "userauthorize", "templatev10", "template"])
        wiz.start(5, body, verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "INCOMPLETE" and "template" in run["error"]


# ─────────────────────────── F1: the hold of a run that never erased ───────────────────────────

class TestAHoldThatNeverErased:

    def test_a_backup_holds_in_the_preparation_phase(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        seen = []
        real = panel.read_table_strict

        def _read(*, table, fields="*"):
            seen.append(_hold_reason(5))
            return real(table=table, fields=fields)
        pv = _preview(wiz, 5)                        # step 1 reads too (lane 1c): hook the run only
        panel.read_table_strict = _read
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert seen and set(seen) == {"erase-prep"}, "no delete issued during the backup"
        assert _hold_reason(5) == "erase", "a delete ran: kept until Refill"

    def test_the_next_start_releases_a_run_stopped_before_any_delete(self, sqlite_db):
        device_hold.hold(5, reason=device_hold.REASON_ERASE_PREP, run_id="power-cut")
        device_hold.hold(6, reason=device_hold.REASON_ERASE, run_id="mid-erase")
        device_hold.reset_for_tests()                                  # the process dies
        assert device_hold.load(release_unstarted=True) == frozenset({6})
        assert not device_hold.is_held(5) and device_hold.is_held(6)
        assert set(sqlite_db.list_device_write_holds()) == {6}

    def test_a_plain_load_releases_nothing(self, sqlite_db):
        device_hold.hold(5, reason=device_hold.REASON_ERASE_PREP, run_id="r")
        device_hold.reset_for_tests()
        assert device_hold.load() == frozenset({5})

    def test_a_retried_load_releases_too(self, sqlite_db, monkeypatch):
        device_hold.hold(5, reason=device_hold.REASON_ERASE_PREP, run_id="r")
        device_hold.reset_for_tests()
        monkeypatch.setattr(device_hold, "_load_failed", True)
        assert device_hold.ensure_loaded() is True
        assert not device_hold.is_held(5)

    def test_a_second_run_never_downgrades_a_real_erase(self, sqlite_db, monkeypatch, tmp_path):
        """A turnstile an earlier run may have emptied, then a backup-only run that dies: the
        next start must NOT release it."""
        device_hold.hold(5, reason=device_hold.REASON_ERASE, run_id="earlier")
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], backupOnly=True), verify_password=_pw_ok)
        assert _hold_reason(5) == "erase"
        device_hold.reset_for_tests()
        assert device_hold.load(release_unstarted=True) == frozenset({5})

    def test_the_sql_keeps_the_stronger_phase(self, sqlite_db):
        device_hold.hold(5, reason=device_hold.REASON_ERASE, run_id="a")
        device_hold.hold(5, reason=device_hold.REASON_ERASE_PREP, run_id="b")
        row = sqlite_db.list_device_write_holds()[5]
        assert row["reason"] == "erase" and row["runId"] == "b"
        device_hold.hold(6, reason=device_hold.REASON_ERASE_PREP, run_id="c")
        device_hold.hold(6, reason=device_hold.REASON_ERASE, run_id="c")
        assert sqlite_db.list_device_write_holds()[6]["reason"] == "erase"

    def test_the_phase_moves_only_for_this_runs_hold(self, sqlite_db):
        device_hold.hold(5, reason=device_hold.REASON_ERASE_PREP, run_id="mine")
        with pytest.raises(RuntimeError):
            sqlite_db.begin_device_erase(device_id=5, run_id="another", keep_pins=())
        assert _hold_reason(5) == "erase-prep"


# ─────────────────────────── F2: a second run and an earlier hold ───────────────────────────

class TestAnEarlierHoldIsReleasedOnlyByRefill:

    @pytest.mark.parametrize("refill", ["now", "auto"])
    def test_now_or_auto_is_refused_on_a_held_turnstile(self, sqlite_db, monkeypatch, tmp_path,
                                                         refill):
        device_hold.hold(5, reason="erase", run_id="earlier")
        wiz, worker, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        status, out = wiz.start(5, _body(pv["previewId"], refill=refill), verify_password=_pw_ok)
        assert status == 409 and out["code"] == "HELD_USE_REFILL"
        assert device_hold.is_held(5) and not [c for c in panel.calls if c[0] == "erase"]

    def test_hold_is_allowed_and_keeps_it(self, sqlite_db, monkeypatch, tmp_path):
        device_hold.hold(5, reason="erase", run_id="earlier")
        wiz, worker, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        assert wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)[0] == 202
        assert wiz.status()["run"]["state"] == "DONE" and device_hold.is_held(5)
        assert worker.full_sync_requests == []

    def test_the_run_itself_never_releases_an_earlier_hold(self, sqlite_db, monkeypatch, tmp_path):
        """The backstop behind start()'s refusal."""
        wiz, worker, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        real_is_held = device_hold.is_held
        calls = {"n": 0}

        def _held_from_the_run_on(did):
            calls["n"] += 1
            return True if calls["n"] > 1 else real_is_held(did)
        # start() sees no hold; the run thread's held_before read sees one.
        monkeypatch.setattr(device_hold, "is_held", _held_from_the_run_on)
        wiz.start(5, _body(pv["previewId"], refill="now"), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "DONE" and run["holdKept"] is True
        assert any(str(s.get("note", "")).startswith("HELD_BEFORE:") for s in run["steps"])
        assert worker.full_sync_requests == []
        assert 5 in dbmod.list_device_write_holds(), "the durable row is still there"


# ─────────────────────────── F8: a release asks the cut pass again ───────────────────────────

class TestAReleaseAsksThePassAgain:

    def test_a_failed_run(self, sqlite_db, monkeypatch, tmp_path):
        wiz, worker, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        panel.short_read = {"user"}
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "FAILED"
        assert worker.full_sync_requests == ["erase-released"]

    def test_a_rehearsal(self, sqlite_db, monkeypatch, tmp_path):
        wiz, worker, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], backupOnly=True), verify_password=_pw_ok)
        assert worker.full_sync_requests == ["erase-released"]

    def test_an_earlier_hold_kept_asks_nothing(self, sqlite_db, monkeypatch, tmp_path):
        device_hold.hold(5, reason="erase", run_id="earlier")
        wiz, worker, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], backupOnly=True), verify_password=_pw_ok)
        assert device_hold.is_held(5) and worker.full_sync_requests == []


# ─────────────────────────── C4: an MB2000 admin pin in the roster ───────────────────────────

class TestAnAdminPinTheRefillWouldOverwrite:

    def test_a_member_on_the_admins_pin_refuses_the_erase(self, sqlite_db, monkeypatch, tmp_path,
                                                         refill_cache):
        refill_cache.users.append({"userId": 16, "activeMembershipId": 1, "mainAccountId": 9001,
                                   "fullName": "Member one"})
        term = _terminal()                                   # admin pin "1"
        wiz, _w, drv = _mb_setup(monkeypatch, tmp_path, term)
        try:
            pv = _preview(wiz, 8)
            wiz.start(8, _mb_body(pv["previewId"], refill="now"), verify_password=_pw_ok)
        finally:
            drv.disconnect()
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "ADMIN_PIN_IN_ROSTER" in run["error"]
        assert len(term.users) == 4 and not device_hold.is_held(8), "nothing erased, released"

    def test_under_hold_the_account_roster_is_checked_too(self, sqlite_db, monkeypatch, tmp_path,
                                                         refill_cache):
        refill_cache.users.append({"userId": 16, "activeMembershipId": 40000, "mainAccountId": 1,
                                   "fullName": "Account one"})
        for refill, state in (("now", "DONE"), ("hold", "FAILED")):
            term = _terminal()
            wiz, _w, drv = _mb_setup(monkeypatch, tmp_path, term)
            try:
                pv = _preview(wiz, 8)
                wiz.start(8, _mb_body(pv["previewId"], refill=refill), verify_password=_pw_ok)
            finally:
                drv.disconnect()
            run = wiz.status()["run"]
            assert run["state"] == state, (refill, run["error"])
            if state == "FAILED":
                assert "ADMIN_PIN_IN_ROSTER" in run["error"] and len(term.users) == 4
            device_hold.reset_for_tests()

    def test_the_fingerprints_only_erase_is_checked_too(self, sqlite_db, monkeypatch, tmp_path,
                                                        refill_cache):
        refill_cache.users.append({"userId": 16, "activeMembershipId": 1, "mainAccountId": 9001,
                                   "fullName": "Member one"})
        term = _terminal()
        wiz, _w, drv = _mb_setup(monkeypatch, tmp_path, term)
        try:
            pv = _preview(wiz, 8)
            wiz.start(8, _mb_body(pv["previewId"], tables=["fingerprints"], forget=False,
                                  refill="now"), verify_password=_pw_ok)
        finally:
            drv.disconnect()
        assert "ADMIN_PIN_IN_ROSTER" in (wiz.status()["run"]["error"] or "")
        assert len(term.fingers) == 5


# ─────────────────────────── the password check offline (F25) ───────────────────────────

class TestOfflineIsNotAWrongPassword:

    def test_start_and_refill_say_the_password_could_not_be_checked(self, sqlite_db, monkeypatch,
                                                                    tmp_path):
        offline = lambda _p: (False, 503, "the admin password could not be checked: offline")
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        status, out = wiz.start(5, _body(pv["previewId"]), verify_password=offline)
        assert status == 503 and out["code"] == "ADMIN_PASSWORD_UNCHECKABLE"
        device_hold.hold(5, reason="erase", run_id="r")
        status, out = wiz.refill(5, _refill_body(), verify_password=offline)
        assert status == 503 and out["code"] == "ADMIN_PASSWORD_UNCHECKABLE"
        status, out = wiz.refill(5, _refill_body(),
                                 verify_password=lambda _p: (False, 401, "Mot de passe incorrect"))
        assert status == 401 and out["code"] == "ADMIN_PASSWORD"

    def test_the_verify_route_answers_503_with_a_code_offline(self, monkeypatch):
        from app.api import local_access_api_v2 as api_mod
        from app.api.monclub_api import MonClubApiError

        class _Api:
            def validate_statistics_password(self, **k):
                raise MonClubApiError("validate_statistics_password request failed: Max retries")

        monkeypatch.setattr("access.store.load_auth_token", lambda: SimpleNamespace(token="t"))
        sent = {}
        ctx = SimpleNamespace(body=lambda: {"password": "pw"},
                              app=SimpleNamespace(_api=lambda: _Api(), logger=logging.getLogger("t")),
                              send_json=lambda s, p: sent.update(status=s, payload=p))
        api_mod._handle_auth_verify_admin_password(ctx)
        assert sent["status"] == 503
        assert sent["payload"]["code"] == "ADMIN_PASSWORD_UNCHECKABLE"
        assert "Internet" in sent["payload"]["error"]


# ─────────────────────────── owner decision NEW 2: the gym's server switch ───────────────────────────

class _Resp:
    def __init__(self, status, body=None, text=None):
        self.status_code = status
        self._body = body
        self.text = text if text is not None else ("" if body is None else str(body))

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class _Session:
    def __init__(self, answer):
        self.answer = answer
        self.calls = []

    def get(self, url, headers=None, timeout=None):
        self.calls.append((url, dict(headers or {}), timeout))
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def _real_api(answer):
    from app.api.monclub_api import ApiEndpoints, MonClubApi
    api = MonClubApi(ApiEndpoints(login_url="https://api.example.test/api/v1/public/access/v1/gym/login",
                                  sync_url="", create_user_fingerprint_url="", latest_release_url=""),
                     logging.getLogger("t"))
    api._session = _Session(answer)
    return api


class TestTheGymsServerSwitch:
    """Only a 200 with the JSON boolean ``enabled: true`` enables a start; Refill is never gated."""

    def _check(self, monkeypatch, answer, token="jwt"):
        monkeypatch.setattr("access.store.load_auth_token",
                            lambda: SimpleNamespace(token=token) if token else None)
        api = _real_api(answer)
        return _real_check_erase_switch(SimpleNamespace(_api=lambda: api)), api._session.calls

    @pytest.mark.parametrize("answer, enabled, code", [
        (_Resp(200, {"enabled": True, "updatedAt": "2026-09-27T21:00:00"}), True, None),
        (_Resp(200, {"enabled": False, "updatedAt": None}), False, "ERASE_NOT_ENABLED"),
        # Lane 1c (review F4): a backend without the route is not "no internet".
        (_Resp(404, text='{"status":false,"code":"NOT_FOUND"}'), False, "ERASE_SWITCH_MISSING"),
        (_Resp(405, text="method not allowed"), False, "ERASE_SWITCH_MISSING"),
        (_Resp(401, text="unauthorized"), False, "ERASE_SWITCH_UNCHECKED"),
        (_Resp(403, text="forbidden"), False, "ERASE_SWITCH_UNCHECKED"),
        (_Resp(500, text="boom"), False, "ERASE_SWITCH_UNCHECKED"),
        (_Resp(502, text="bad gateway"), False, "ERASE_SWITCH_UNCHECKED"),
        (TimeoutError("read timed out"), False, "ERASE_SWITCH_UNREACHABLE"),
        (__import__("requests").exceptions.ReadTimeout("read timed out"), False,
         "ERASE_SWITCH_UNREACHABLE"),
        (__import__("requests").exceptions.ConnectionError("no route"), False,
         "ERASE_SWITCH_UNREACHABLE"),
        (_Resp(200, ValueError("not json"), text="<html>"), False, "ERASE_SWITCH_UNCHECKED"),
        # requests' own JSON error derives from OSError: it got an answer all the same.
        (_Resp(200, __import__("requests").exceptions.JSONDecodeError("Expecting value", "<", 0),
               text="<html>"), False, "ERASE_SWITCH_UNCHECKED"),
        (_Resp(200, {"enabled": "true"}), False, "ERASE_SWITCH_UNCHECKED"),
        (_Resp(200, {"enabled": 1}), False, "ERASE_SWITCH_UNCHECKED"),
        (_Resp(200, [True]), False, "ERASE_SWITCH_UNCHECKED"),
    ])
    def test_only_an_explicit_true_enables(self, monkeypatch, answer, enabled, code):
        (ok, got_code, _why), calls = self._check(monkeypatch, answer)
        assert (ok, got_code) == (enabled, code)
        url, headers, timeout = calls[0]
        assert url == "https://api.example.test/api/v1/manager/gym/access/erase-wizard"
        assert headers["Authorization"] == "Bearer jwt" and timeout == 15

    def test_no_token_is_unchecked_and_asks_nothing(self, monkeypatch):
        (ok, code, _w), calls = self._check(monkeypatch, _Resp(200, {"enabled": True}), token=None)
        assert (ok, code) == (False, "ERASE_SWITCH_UNCHECKED") and calls == []

    @pytest.mark.parametrize("answer, status, code, says", [
        ((False, "ERASE_NOT_ENABLED", "off"), 403, "ERASE_NOT_ENABLED", "not enabled"),
        ((False, "ERASE_SWITCH_UNCHECKED", "HTTP 500"), 503, "ERASE_SWITCH_UNCHECKED",
         "could not be checked"),
        ((False, "ERASE_SWITCH_MISSING", "HTTP 404"), 503, "ERASE_SWITCH_MISSING",
         "does not offer"),
        ((False, "ERASE_SWITCH_UNREACHABLE", "timeout"), 503, "ERASE_SWITCH_UNREACHABLE",
         "internet"),
    ])
    def test_a_start_is_refused_unless_the_switch_is_on(self, sqlite_db, monkeypatch, tmp_path,
                                                        answer, status, code, says):
        monkeypatch.setattr(ew, "check_erase_switch", lambda app: answer)
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        for body in (_body(pv["previewId"]), _body(pv["previewId"], backupOnly=True)):
            got, out = wiz.start(5, body, verify_password=_pw_ok)
            assert (got, out["code"]) == (status, code)
            assert says in out["error"], out["error"]
        assert not device_hold.is_held(5) and wiz.status()["run"] is None
        assert {c for c in panel.calls if c[0] != "count"} == {("read", "user")}, "step 1 only"

    def test_a_wrong_password_is_said_first_and_the_switch_not_asked(self, sqlite_db, monkeypatch,
                                                                     tmp_path):
        asked = []
        monkeypatch.setattr(ew, "check_erase_switch",
                            lambda app: asked.append(1) or (False, "ERASE_NOT_ENABLED", "off"))
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        status, out = wiz.start(5, _body(pv["previewId"]),
                                verify_password=lambda _p: (False, 401, "Mot de passe incorrect"))
        assert status == 401 and out["code"] == "ADMIN_PASSWORD" and asked == []

    def test_preview_and_refill_are_never_gated(self, sqlite_db, monkeypatch, tmp_path):
        asked = []
        monkeypatch.setattr(ew, "check_erase_switch",
                            lambda app: asked.append(1) or (False, "ERASE_NOT_ENABLED", "off"))
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        assert wiz.preview(5)[0] == 200
        device_hold.hold(5, reason="erase", run_id="r")
        assert wiz.refill(5, _refill_body(), verify_password=_pw_ok)[0] == 200
        assert asked == [] and not device_hold.is_held(5)


# ─────────────────────────── owner decision NEW 1: backups kept 30 days ───────────────────────────

def _run_folder(root, run_id, did, state="DONE", with_run=True, names=("Ali Ben Salah",)):
    """A run folder whose files were last written at the run's own start (its run id)."""
    import os
    folder = root / f"{run_id}_device{did}"
    folder.mkdir(parents=True)
    users = ",".join(json.dumps({"name": n}) for n in names)
    (folder / "backup.json").write_text('{"users": [' + users + ']}', encoding="utf-8")
    if with_run:
        (folder / "run.json").write_text(json.dumps({"state": state}), encoding="utf-8")
    at = time.mktime(time.strptime(run_id[:15], "%Y%m%d-%H%M%S"))
    for f in folder.iterdir():
        os.utime(f, (at, at))
    return folder


OLD = "20261001-101500-aaaaaa"          # 45 days before NOW
RECENT = "20261101-101500-bbbbbb"
NOW = time.mktime(time.strptime("20261115-120000", "%Y%m%d-%H%M%S"))


class TestBackupsAreKeptThirtyDays:

    def test_an_old_finished_run_goes_a_recent_one_stays(self, sqlite_db, tmp_path, caplog):
        root = tmp_path / "erase_backups"
        old = _run_folder(root, OLD, 5)
        recent = _run_folder(root, RECENT, 5)
        with caplog.at_level(logging.WARNING):
            assert ew.prune_erase_backups(root, now=NOW) == [OLD]
        assert not old.exists() and recent.exists()
        assert "Ali" not in caplog.text and OLD in caplog.text, "run id, turnstile, state only"

    @pytest.mark.parametrize("state", ["DONE", "FAILED", "INCOMPLETE"])
    def test_a_held_turnstiles_runs_are_never_deleted(self, sqlite_db, tmp_path, state):
        root = tmp_path / "erase_backups"
        folder = _run_folder(root, OLD, 5, state=state)
        device_hold.hold(5, reason="erase", run_id="r")
        assert ew.prune_erase_backups(root, now=NOW) == [] and folder.exists()

    def test_the_30_days_count_from_the_refill(self, sqlite_db, tmp_path, monkeypatch):
        """Review round 2, finding 1: a turnstile held longer than 30 days keeps its backup for
        30 days after Refill, not until the next prune."""
        # Runs 45 days before the real clock (the refill mark is written with it).
        monkeypatch.setattr(ew, "_NO_RUN_BEFORE", "20000101")
        run = time.strftime("%Y%m%d-%H%M%S", time.localtime(time.time() - 45 * 86400))
        mine, theirs = f"{run}-aaaaaa", f"{run}-cccccc"
        root = tmp_path / "erase_backups"
        folder = _run_folder(root, mine, 5, state="INCOMPLETE")
        other = _run_folder(root, theirs, 6)
        device_hold.hold(5, reason="erase", run_id=mine)
        wiz = ew.EraseWizard(_app({}), backup_root=root, spawn=lambda fn: fn(),
                             sleep=lambda s: None)
        monkeypatch.setattr(dbmod, "get_device_pin_scheme", lambda did: None)
        assert wiz.refill(5, _refill_body(), verify_password=_pw_ok)[0] == 200
        assert (folder / ew.REFILLED_MARK).exists() and not (other / ew.REFILLED_MARK).exists()
        refilled_at = (folder / ew.REFILLED_MARK).stat().st_mtime
        assert ew.prune_erase_backups(root, now=refilled_at + 29 * 86400) == [theirs]
        assert folder.exists(), "29 days after the refill: kept"
        assert ew.prune_erase_backups(root, now=refilled_at + 31 * 86400) == [mine]

    def test_the_mark_is_written_before_the_release(self, sqlite_db, tmp_path, monkeypatch):
        """Review round 3: a prune landing between the release and the mark found the folder
        neither held nor marked."""
        monkeypatch.setattr(ew, "_NO_RUN_BEFORE", "20000101")
        run = time.strftime("%Y%m%d-%H%M%S", time.localtime(time.time() - 45 * 86400))
        root = tmp_path / "erase_backups"
        folder = _run_folder(root, f"{run}-aaaaaa", 5, state="INCOMPLETE")
        device_hold.hold(5, reason="erase", run_id=f"{run}-aaaaaa")
        wiz = ew.EraseWizard(_app({}), backup_root=root, spawn=lambda fn: fn(),
                             sleep=lambda s: None)
        monkeypatch.setattr(dbmod, "get_device_pin_scheme", lambda did: None)
        pruned = []
        real_release = device_hold.release

        def _release_then_prune(did):
            out = real_release(did)
            pruned.extend(ew.prune_erase_backups(root))      # a prune in the gap
            return out
        monkeypatch.setattr(device_hold, "release", _release_then_prune)
        status, out = wiz.refill(5, _refill_body(), verify_password=_pw_ok)
        assert status == 200 and out["backupsMarked"] is True
        assert pruned == [] and folder.exists()

    def test_a_mark_that_cannot_be_written_is_reported_and_refill_still_goes(
            self, sqlite_db, tmp_path, monkeypatch):
        root = tmp_path / "erase_backups"
        _run_folder(root, OLD, 5, state="INCOMPLETE")
        device_hold.hold(5, reason="erase", run_id=OLD)
        wiz = ew.EraseWizard(_app({}), backup_root=root, spawn=lambda fn: fn(),
                             sleep=lambda s: None)
        monkeypatch.setattr(dbmod, "get_device_pin_scheme", lambda did: None)
        from pathlib import Path
        real = Path.write_bytes

        def _refuse(self, data):
            if self.name == ew.REFILLED_MARK:
                raise PermissionError("denied")
            return real(self, data)
        monkeypatch.setattr(Path, "write_bytes", _refuse)
        status, out = wiz.refill(5, _refill_body(), verify_password=_pw_ok)
        assert status == 200 and out["backupsMarked"] is False and not device_hold.is_held(5)

    def test_a_run_dated_before_the_wizard_is_a_wrong_clock_and_is_kept(self, sqlite_db,
                                                                        tmp_path):
        """Review round 2, finding 2: a dead CMOS battery stamps a run in 2000; once the clock
        is corrected its age cannot be told."""
        root = tmp_path / "erase_backups"
        folder = _run_folder(root, "20000101-000000-dddddd", 5)
        assert ew.prune_erase_backups(root, now=NOW) == [] and folder.exists()

    @pytest.mark.parametrize("case", ["running", "no_run_json", "bad_run_json"])
    def test_a_run_a_power_cut_ended_goes_after_30_days(self, sqlite_db, tmp_path, case):
        """Review round 2, finding 3: no run of this process is 30 days old, so a RUNNING or
        unreadable record is a dead run -- its biometric copy is not kept forever."""
        import os
        root = tmp_path / "erase_backups"
        if case == "running":
            folder = _run_folder(root, OLD, 5, state="RUNNING")
        else:
            folder = _run_folder(root, OLD, 5, with_run=False)
            if case == "bad_run_json":
                (folder / "run.json").write_text("{not json", encoding="utf-8")
                at = time.mktime(time.strptime(OLD[:15], "%Y%m%d-%H%M%S"))
                os.utime(folder / "run.json", (at, at))
        assert ew.prune_erase_backups(root, now=NOW) == [OLD] and not folder.exists()

    def test_nothing_goes_while_the_holds_cannot_be_read(self, sqlite_db, tmp_path, monkeypatch):
        root = tmp_path / "erase_backups"
        folder = _run_folder(root, OLD, 5)
        monkeypatch.setattr(device_hold, "_load_failed", True)
        assert ew.prune_erase_backups(root, now=NOW) == [] and folder.exists()

    @pytest.mark.parametrize("case", ["not_a_run", "the_run_in_progress", "a_file_written_lately"])
    def test_what_is_never_deleted(self, sqlite_db, tmp_path, case):
        root = tmp_path / "erase_backups"
        if case == "not_a_run":
            folder = root / "my_copy_of_a_backup"
            folder.mkdir(parents=True)
        else:
            folder = _run_folder(root, OLD, 5)
        if case == "a_file_written_lately":
            import os
            os.utime(folder / "run.json", (NOW - 86400, NOW - 86400))       # the day before
        keep = OLD if case == "the_run_in_progress" else None
        assert ew.prune_erase_backups(root, now=NOW, keep_run_id=keep) == []
        assert folder.exists()

    def test_a_run_prunes_the_old_backups_when_it_ends(self, sqlite_db, monkeypatch, tmp_path):
        monkeypatch.setattr(ew, "_NO_RUN_BEFORE", "20000101")
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        old = _run_folder(wiz.backup_root(), "20200101-000000-cccccc", 6)
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], backupOnly=True), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "DONE"
        assert not old.exists()
        assert (wiz.backup_root() / f"{wiz.status()['run']['runId']}_device5").exists()

    def test_the_app_prunes_at_start_up_after_the_holds_are_loaded(self, tmp_path, monkeypatch):
        import app.ui.app as app_module
        from tests.test_p3b1_app_wiring import _stub_heavy_init

        monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "init.db"), raising=False)
        _stub_heavy_init(monkeypatch)
        order: List[str] = []

        class StopInit(Exception):
            pass

        monkeypatch.setattr(app_module.MainApp, "_apply_date_flips", lambda self, source, **k: None)
        monkeypatch.setattr(device_hold, "load", lambda **kw: order.append("holds") or frozenset())
        # Lane 1d (master review F1): the start-up entry point, which waits for the server clock
        # before it runs prune_erase_backups (tests/test_erase_wizard_lane1d.py).
        monkeypatch.setattr(ew, "prune_erase_backups_at_startup",
                            lambda *a, **k: order.append("prune") or [])

        def recording_after(self, delay_ms, callback):
            if getattr(callback, "__name__", "") == "_sync_tick":
                order.append("first_sync_tick")
                raise StopInit
            return 1

        monkeypatch.setattr(app_module.MainApp, "after", recording_after)
        with pytest.raises(StopInit):
            app_module.MainApp()
        deadline = time.monotonic() + 5
        while "prune" not in order and time.monotonic() < deadline:
            time.sleep(0.01)
        assert order.index("holds") < order.index("prune")
        dbmod._shutdown_db_writer_for_tests()


# ─────────────────────────── lane 1b review round 1 ───────────────────────────

class TestReviewRound1:

    def test_the_refill_is_checked_again_right_before_the_first_delete(self, sqlite_db,
                                                                        monkeypatch, tmp_path,
                                                                        refill_cache):
        """Finding 1: a sync that empties the member list during the backup stops the run."""
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        real = panel.read_table_strict

        def _read(*, table, fields="*"):
            refill_cache.users = []                      # a successful sync emptied it
            return real(table=table, fields=fields)
        pv = _preview(wiz, 5)                        # step 1 reads too (lane 1c): hook the run only
        panel.read_table_strict = _read
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "REFILL_SOURCE_EMPTY" in run["error"]
        assert not [c for c in panel.calls if c[0] == "erase"] and not device_hold.is_held(5)

    def test_withheld_rows_arriving_during_a_hold_run_stop_it(self, sqlite_db, monkeypatch,
                                                              tmp_path, refill_cache):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        real = panel.read_table_strict

        def _read(*, table, fields="*"):
            if not any(u.get("userId") == 99 for u in refill_cache.users):
                refill_cache.users.append({"userId": 99, "activeMembershipId": 199})
            return real(table=table, fields=fields)
        pv = _preview(wiz, 5)                        # step 1 reads too (lane 1c): hook the run only
        panel.read_table_strict = _read
        wiz.start(5, _body(pv["previewId"], refill="hold"), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "REFILL_WITHHELD" in run["error"]
        assert not [c for c in panel.calls if c[0] == "erase"]

    def test_a_failed_sync_during_the_backup_does_not_stop_the_run(self, sqlite_db, monkeypatch,
                                                                   tmp_path):
        wiz, _w, panel, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        real = panel.read_table_strict

        def _read(*, table, fields="*"):
            app._last_sync_ok = False                    # a network blip during the backup
            return real(table=table, fields=fields)
        pv = _preview(wiz, 5)                        # step 1 reads too (lane 1c): hook the run only
        panel.read_table_strict = _read
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "DONE"

    def test_a_rehearsal_on_a_held_turnstile_leaves_its_hold_row_alone(self, sqlite_db,
                                                                       monkeypatch, tmp_path):
        """Finding 4: the row keeps naming the run that may have erased, and its time."""
        device_hold.hold(5, reason="erase", run_id="earlier-erase")
        before = dict(sqlite_db.list_device_write_holds()[5])
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], backupOnly=True), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "DONE"
        assert sqlite_db.list_device_write_holds()[5] == before

    def test_a_held_row_keeps_its_since_when_a_real_erase_takes_it_over(self, sqlite_db):
        device_hold.hold(5, reason="erase", run_id="a")
        since = sqlite_db.list_device_write_holds()[5]["since"]
        device_hold.hold(5, reason=device_hold.REASON_ERASE_PREP, run_id="b")
        row = sqlite_db.list_device_write_holds()[5]
        # terminalScheme since lane 1e (the scheme the first hold recorded; none here).
        assert row == {"reason": "erase", "runId": "b", "since": since, "terminalScheme": None}

    def test_an_agent_line_is_never_reported_held(self, sqlite_db, monkeypatch, refill_cache):
        """Finding 9: no engine writes a pin to an AGENT turnstile."""
        from access.pc_identity import build_heartbeat_payload
        app = _heartbeat_app(monkeypatch, refill_cache, _device(did=5))
        app._ultra_engine = SimpleNamespace(get_status=lambda: {"devices": {}})
        app._agent_engine = SimpleNamespace(
            get_status_snapshot=lambda: {5: {"connected": True, "failedPins": 0}})
        monkeypatch.setattr(device_hold, "_load_failed", True)
        line = build_heartbeat_payload(app)["turnstiles"][0]
        assert line == {"gymDeviceId": 5, "reachable": True, "failedPins": 0, "mode": "AGENT"}

    @pytest.mark.parametrize("moved", ["ADDRESS_CHANGED", "ADDRESS_UNKNOWN"])
    def test_no_pass_is_asked_through_a_worker_on_another_address(self, sqlite_db, monkeypatch,
                                                                  tmp_path, moved):
        """Finding 12: after the idle wait the worker is on another address -- FAILED, released,
        and no pass requested through that worker."""
        wiz, worker, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        real_wait = wiz._wait_idle

        def _wait(did):
            w = real_wait(did)
            w._connected_addr = ("192.168.0.99", 4370) if moved == "ADDRESS_CHANGED" else None
            return w
        monkeypatch.setattr(wiz, "_wait_idle", _wait)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and moved in run["error"]
        assert not device_hold.is_held(5) and worker.full_sync_requests == []

    def test_a_pc_with_no_gym_token_is_not_told_there_is_no_internet(self, sqlite_db,
                                                                     monkeypatch, tmp_path):
        """Review round 2 nit: the verifier's no-token answer has its own code."""
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        status, out = wiz.start(5, _body(pv["previewId"]), verify_password=lambda _p: (
            False, 503, f"{ew.NOT_SIGNED_IN}: the password cannot be checked"))
        assert status == 503 and out["code"] == "PC_NOT_SIGNED_IN"

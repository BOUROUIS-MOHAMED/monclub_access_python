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

import logging
from types import SimpleNamespace
from typing import List

import pytest

import app.core.db as dbmod
import app.core.erase_wizard as ew
from app.core import device_hold
from app.core.v2 import lease_gate as lg
from tests.test_erase_wizard import (  # noqa: F401 -- fixtures are used by name
    FakePanel, _app, _body, _device, _devices, _mb_body, _mb_setup, _own, _panel, _pw_ok,
    _refill_body, _removed, _setup_c3, _state, _terminal, _wizard, refill_cache, sqlite_db,
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
        assert {c[0] for c in panel.calls} == {"count"}

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
        assert {c[0] for c in panel.calls} == {"count"}, "nothing read beyond step 1, nothing erased"

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
        panel.read_table_strict = _read
        pv = _preview(wiz, 5)
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
        assert any("HELD_BEFORE" in str(s.get("note", "")) for s in run["steps"])
        assert worker.full_sync_requests == []


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

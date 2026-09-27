"""Lane 1b (2026-09-27): the tests the master review found missing (item 10), most dangerous first.

Each gate or claim below was in the code and right, but nothing failed if it went:
* F19 the refusal gates on the erase path -- ADD_ONLY first, at start() and inside a write;
* F15 an MB2000 erase the verify does not confirm -- nothing forgotten;
* F21 the door, the SDK queue and the rescue open keep running while a turnstile is held;
* F22 a hold set during a PullSDK pass stops its batch;
* F24 the MB2000 delete batch of 20, a readable C3 ``template`` table, the fingerprints-only
  path inside the driver timeouts.
(F16 and F9 are in tests/test_v2_last_push.py::TestTrueNeedsTheDoorRights.)
"""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from typing import List
from unittest.mock import MagicMock, patch

import pytest

import app.core.db as dbmod
import app.core.erase_wizard as ew
from app.core import device_hold
from app.core.v2 import lease_gate as lg
from tests.test_erase_wizard import (  # noqa: F401 -- fixtures are used by name
    FakePanel, FakeWorker, WizardTerminal, _Recording, _app, _body, _device, _devices, _mb_body,
    _mb_setup, _own, _panel, _pw_ok, _refill_body, _removed, _setup_c3, _state, _terminal,
    _wizard, erase_switch_on, refill_cache, sqlite_db,
)


def _add_only(did):
    body = {"gymUsesAssignments": True, "role": "DRIVER", "readerOf": [], "release": [],
            "drive": [{"gymDeviceId": did, "generation": 3, "state": "DRIVE",
                       "handoverForced": False}]}
    lg.install(lg.snapshot_from_assignment(body, source="server", add_only=[did]))


def _nothing_happened(wiz, panel, did=5):
    assert not device_hold.is_held(did)
    assert wiz.status()["run"] is None
    # Step 1 counts and reads the user list (lane 1c); no run, so no backup read and no erase.
    assert {c for c in panel.calls if c[0] != "count"} <= {("read", "user")}, panel.calls


# ─────────────────────────── F19: the refusal gates ───────────────────────────

class TestTheRefusalGates:

    def test_add_only_at_start(self, sqlite_db, monkeypatch, tmp_path):
        """A turnstile left add-only by a forced handover: removals of members this PC has not
        read back are not this PC's to make -- an erase is the biggest removal of all."""
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        _add_only(5)
        status, out = wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert status == 409 and out["code"] == "ADD_ONLY"
        _nothing_happened(wiz, panel)

    def test_add_only_mid_run_stops_before_the_next_write(self, sqlite_db, monkeypatch, tmp_path):
        _own(sqlite_db, 5, ["101", "102"])
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        panel.on_erase = lambda table: _add_only(5) if table == "templatev10" else None
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "INCOMPLETE" and "ADD_ONLY" in run["error"]
        assert [c[1] for c in panel.calls if c[0] == "erase"] == ["templatev10"]
        assert set(_state(sqlite_db, 5)) == {"101", "102"} and _removed(sqlite_db, 5) == set()

    def test_a_backup_only_rehearsal_is_allowed_add_only(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        _add_only(5)
        assert wiz.start(5, _body(pv["previewId"], backupOnly=True),
                         verify_password=_pw_ok)[0] == 202

    @pytest.mark.parametrize("snapshot, code", [
        ({"gymUsesAssignments": True, "role": "READER", "drive": [], "release": []}, "NOT_DRIVER"),
        ({"gymUsesAssignments": True, "role": "DRIVER", "drive": [],
          "release": [{"gymDeviceId": 5, "generation": 3, "newDriverPcId": 6}]},
         "HANDOVER_IN_PROGRESS"),
    ])
    def test_the_lease_at_start(self, sqlite_db, monkeypatch, tmp_path, snapshot, code):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        lg.install(lg.snapshot_from_assignment(snapshot, source="server"))
        status, out = wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert status == 409 and out["code"] == code
        _nothing_happened(wiz, panel)

    def test_a_preview_older_than_15_minutes(self, sqlite_db, monkeypatch, tmp_path):
        clock = {"t": 1000.0}
        panel = _panel()
        app = _app({5: FakeWorker(panel)})
        _devices(monkeypatch, _device())
        wiz = ew.EraseWizard(app, backup_root=tmp_path / "b", spawn=lambda fn: fn(),
                             sleep=lambda s: None, mono=lambda: clock["t"])
        _, pv = wiz.preview(5)
        clock["t"] += ew.PREVIEW_TTL_SEC + 1
        status, out = wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert status == 409 and out["code"] == "PREVIEW_EXPIRED"
        _nothing_happened(wiz, panel)

    def test_a_preview_binds_one_run_only(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        assert wiz.start(5, _body(pv["previewId"], backupOnly=True),
                         verify_password=_pw_ok)[0] == 202
        status, out = wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert status == 409 and out["code"] == "PREVIEW_EXPIRED"
        assert not [c for c in panel.calls if c[0] == "erase"]

    @pytest.mark.parametrize("change, status_code, code", [
        (dict(tables=[]), 400, "NO_TABLES"),
        (dict(tables=["user", "user"]), 400, "NO_TABLES"),
        (dict(tables=["nope"]), 400, "UNKNOWN_TABLE"),
        (dict(refill=None), 400, "REFILL_REQUIRED"),
        (dict(refill="later"), 400, "REFILL_REQUIRED"),
        (dict(forget=None), 400, "FORGET_REQUIRED"),
        (dict(forget="yes"), 400, "FORGET_REQUIRED"),
    ])
    def test_a_malformed_request(self, sqlite_db, monkeypatch, tmp_path, change, status_code,
                                 code):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        status, out = wiz.start(5, _body(pv["previewId"], **change), verify_password=_pw_ok)
        assert (status, out["code"]) == (status_code, code)
        _nothing_happened(wiz, panel)

    def test_an_unsupported_sdk_family(self, sqlite_db, monkeypatch, tmp_path):
        panel = _panel()
        wiz = _wizard(_app({5: FakeWorker(panel)}), tmp_path)
        _devices(monkeypatch, _device(proto="ZK_ADMS_PUSH"))
        monkeypatch.setattr(ew, "_protocol_of", lambda device: None)
        status, out = wiz.preview(5)
        assert status == 409 and out["code"] == "UNSUPPORTED_PROTOCOL" and panel.calls == []

    def test_a_turnstile_with_no_name(self, sqlite_db, monkeypatch, tmp_path):
        panel = _panel()
        wiz = _wizard(_app({5: FakeWorker(panel)}), tmp_path)
        _devices(monkeypatch, _device(name="   "))
        _, pv = wiz.preview(5)
        status, out = wiz.start(5, _body(pv["previewId"], typedName=""), verify_password=_pw_ok)
        assert status == 409 and out["code"] == "NO_DEVICE_NAME"
        _nothing_happened(wiz, panel)

    def test_an_unreadable_pin_scheme_at_start(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)

        def _boom(did):
            raise RuntimeError("database is locked")
        monkeypatch.setattr(dbmod, "get_device_pin_scheme", _boom)
        status, out = wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert status == 503 and out["code"] == "PIN_SCHEME_UNREADABLE"
        _nothing_happened(wiz, panel)

    def test_a_pass_that_never_ends_is_busy(self, sqlite_db, monkeypatch, tmp_path):
        clock = {"t": 0.0}
        panel = _panel()
        worker = FakeWorker(panel)
        worker._full_sync_running = True
        app = _app({5: worker})
        _devices(monkeypatch, _device())

        def _sleep(s):
            clock["t"] += s
        wiz = ew.EraseWizard(app, backup_root=tmp_path / "b", spawn=lambda fn: fn(),
                             sleep=_sleep, mono=lambda: clock["t"])
        _, pv = wiz.preview(5)
        panel.calls.clear()                       # step 1's own reads (lane 1c) are not the point
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "BUSY" in run["error"]
        assert clock["t"] > ew.IDLE_WAIT_SEC, "it waited the whole idle budget"
        assert not device_hold.is_held(5) and panel.calls == [], "nothing read, nothing erased"

    def test_a_pass_that_ends_lets_the_run_go_on(self, sqlite_db, monkeypatch, tmp_path):
        clock = {"t": 0.0}
        panel = _panel()
        worker = FakeWorker(panel)
        worker._full_sync_running = True
        app = _app({5: worker})
        _devices(monkeypatch, _device())

        def _sleep(s):
            clock["t"] += s
            if clock["t"] >= 3:
                worker._full_sync_running = False
        wiz = ew.EraseWizard(app, backup_root=tmp_path / "b", spawn=lambda fn: fn(),
                             sleep=_sleep, mono=lambda: clock["t"])
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "DONE"


class TestTheBackupReadBack:

    def test_a_backup_that_reads_back_differently_stops_before_any_erase(self, sqlite_db,
                                                                        monkeypatch, tmp_path):
        """The hash is checked on the bytes READ BACK: a disk that returns other bytes fails the
        run before the first delete (review nit)."""
        from pathlib import Path
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        real = Path.read_bytes

        def _flipped(self):
            data = real(self)
            return data + b" " if self.name == "backup.json" else data
        monkeypatch.setattr(Path, "read_bytes", _flipped)
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "BACKUP_WRITE" in run["error"]
        assert not [c for c in panel.calls if c[0] == "erase"] and not device_hold.is_held(5)


class TestTheMb2000RefusalGates:

    def test_status_unreadable_at_step_1(self, sqlite_db, monkeypatch, tmp_path):
        wiz, worker, drv = _mb_setup(monkeypatch, tmp_path, _terminal())

        class _NoStatus:
            def __getattr__(self, name):
                return getattr(drv, name)

            def read_device_status(self, **k):
                return {"ok": False, "error": "timeout"}
        worker.drv = _NoStatus()
        try:
            status, out = wiz.preview(8)
        finally:
            drv.disconnect()
        assert status == 503 and out["code"] == "STATUS_UNREADABLE"

    def test_a_counter_that_does_not_read_makes_the_backup_unverifiable(self, sqlite_db,
                                                                          monkeypatch, tmp_path):
        class _NoFingerCount(WizardTerminal):
            def GetDeviceStatus(self, machine, idx, box):
                if int(idx) == 3:
                    return False if hasattr(box, "value") else (False, 0)
                return super().GetDeviceStatus(machine, idx, box)
        term = _NoFingerCount()
        for u in (("1", "Admin", "", (0,), 14), ("30001", "Ali", "111", (0, 3), 0)):
            term.add(u[0], u[1], u[2], fingers=u[3], privilege=u[4])
        wiz, _w, drv = _mb_setup(monkeypatch, tmp_path, term)
        try:
            _, pv = wiz.preview(8)
            wiz.start(8, _mb_body(pv["previewId"]), verify_password=_pw_ok)
        finally:
            drv.disconnect()
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "BACKUP_UNVERIFIABLE" in run["error"]
        assert set(term.users) == {"1", "30001"} and not device_hold.is_held(8)

    @pytest.mark.parametrize("bad", ["name", "privilege"])
    def test_an_untrusted_listing(self, sqlite_db, monkeypatch, tmp_path, bad):
        term = _terminal()
        wiz, worker, drv = _mb_setup(monkeypatch, tmp_path, term)
        real = drv.list_device_users

        class _Listing:
            def __getattr__(self, name):
                return getattr(drv, name)

            def list_device_users(self, **k):
                out = real(**k)
                users = [dict(u) for u in out.get("users") or []]
                if bad == "name":
                    users[1]["pin"] = "Ali Ben Salah"           # a wrong out-param order
                else:
                    users[1]["privilege"] = None
                return dict(out, users=users)
        worker.drv = _Listing()
        try:
            _, pv = wiz.preview(8)
            wiz.start(8, _mb_body(pv["previewId"]), verify_password=_pw_ok)
        finally:
            drv.disconnect()
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "BACKUP_UNTRUSTED" in run["error"]
        assert "Ali" not in run["error"], "a listed value never reaches the log (F29)"
        assert len(term.users) == 4


class TestTheRefillRoute:
    """Refill's password is checked by the server, through the local route."""

    def _ctx(self, monkeypatch, tmp_path, validate, body):
        import access.store as store
        import app.api.local_access_api_v2 as la2
        from tests.test_erase_wizard import _Ctx

        worker = FakeWorker(_panel())
        app = _app({5: worker})
        app._erase_wizard = _wizard(app, tmp_path)
        app._api = lambda: SimpleNamespace(validate_statistics_password=validate)
        monkeypatch.setattr(store, "load_auth_token", lambda: SimpleNamespace(token="jwt"))
        _devices(monkeypatch, _device())
        device_hold.hold(5, reason="erase", run_id="r")
        ctx = _Ctx(app, 5, body)
        la2._handle_device_erase_refill(ctx)
        return ctx.sent, worker

    def test_an_empty_password_is_refused(self, sqlite_db, monkeypatch, tmp_path):
        (status, out), _w = self._ctx(monkeypatch, tmp_path, lambda **k: True,
                                      _refill_body(password=""))
        assert status == 400 and out["code"] == "ADMIN_PASSWORD_REQUIRED" and device_hold.is_held(5)

    def test_a_server_failure_is_never_a_wrong_password(self, sqlite_db, monkeypatch, tmp_path):
        """Review round 1, finding 2: only a 401 is a wrong password."""
        from app.api.monclub_api import MonClubApiHttpError

        def _bad_gateway(token, password):
            raise MonClubApiHttpError("validate_statistics_password: HTTP 502", status_code=502)
        (status, out), _w = self._ctx(monkeypatch, tmp_path, _bad_gateway, _refill_body())
        assert status == 502 and out["code"] == "ADMIN_PASSWORD_CHECK_FAILED"
        assert device_hold.is_held(5)

    def test_no_gym_token_cannot_check_and_is_not_a_wrong_password(self, sqlite_db, monkeypatch,
                                                                  tmp_path):
        import access.store as store
        import app.api.local_access_api_v2 as la2
        from tests.test_erase_wizard import _Ctx

        app = _app({5: FakeWorker(_panel())})
        app._erase_wizard = _wizard(app, tmp_path)
        monkeypatch.setattr(store, "load_auth_token", lambda: None)
        _devices(monkeypatch, _device())
        device_hold.hold(5, reason="erase", run_id="r")
        ctx = _Ctx(app, 5, _refill_body())
        la2._handle_device_erase_refill(ctx)
        assert ctx.sent[0] == 503 and ctx.sent[1]["code"] == "PC_NOT_SIGNED_IN"

    def test_a_wrong_password_is_refused_by_the_server(self, sqlite_db, monkeypatch, tmp_path):
        (status, out), _w = self._ctx(monkeypatch, tmp_path, lambda token, password: False,
                                      _refill_body())
        assert status == 401 and device_hold.is_held(5)

    def test_offline_is_unchecked_not_wrong(self, sqlite_db, monkeypatch, tmp_path):
        def _down(token, password):
            raise ConnectionError("offline")
        (status, out), _w = self._ctx(monkeypatch, tmp_path, _down, _refill_body())
        assert status == 503 and out["code"] == "ADMIN_PASSWORD_UNCHECKABLE"
        assert device_hold.is_held(5)

    def test_the_right_password_releases(self, sqlite_db, monkeypatch, tmp_path):
        (status, out), worker = self._ctx(monkeypatch, tmp_path, lambda token, password: True,
                                          _refill_body())
        assert status == 200 and not device_hold.is_held(5)
        assert worker.full_sync_requests == ["erase-refill"]


# ─────────────────────────── F15: an MB2000 erase the verify does not confirm ───────────────────────────

class _KeepsSome(WizardTerminal):
    """Answers True to the whole-user delete and to the slot clear, yet keeps chosen rows."""

    def __init__(self, keep_users=(), keep_fingers=()):
        super().__init__()
        self.keep_users = {str(p) for p in keep_users}
        self.keep_fingers = {(str(p), int(f)) for p, f in keep_fingers}

    def SSR_DeleteEnrollData(self, machine, pin, backup):
        if str(pin) in self.keep_users:
            self._rec("SSR_DeleteEnrollData", machine, pin, backup)
            return True
        return super().SSR_DeleteEnrollData(machine, pin, backup)

    def SSR_DelUserTmpExt(self, machine, pin, finger_id):
        if (str(pin), int(finger_id)) in self.keep_fingers:
            self._rec("SSR_DelUserTmpExt", machine, pin, finger_id)
            return True
        return super().SSR_DelUserTmpExt(machine, pin, finger_id)


def _keeps_some(**kw):
    t = _KeepsSome(**kw)
    t.add("1", "Admin", "", fingers=(0,), privilege=14)
    t.add("30001", "Ali", "111", fingers=(0, 3))
    t.add("30002", "Sonia", "222", fingers=(1,))
    t.add("777", "Old system", "333", fingers=(2,))
    return t


class TestAnUnconfirmedMb2000EraseForgetsNothing:

    def _assert_nothing_forgotten(self, sqlite_db, run):
        assert run["state"] == "INCOMPLETE", run["error"]
        after = [s for s in run["steps"] if s["step"] == "counts_after"][0]
        assert after["ok"] is False and after["verified"] is False
        assert device_hold.is_held(8)
        assert set(sqlite_db.list_confirmed_device_sync_pins(device_id=8)) == {"30001", "30002"}
        assert _removed(sqlite_db, 8) == set(), "no REMOVED fact for a pin still on the terminal"

    def test_a_users_erase_that_answered_ok_but_left_a_member(self, sqlite_db, monkeypatch,
                                                             tmp_path):
        term = _keeps_some(keep_users={"30002"})
        _own(sqlite_db, 8, ["30001", "30002"])
        wiz, _w, drv = _mb_setup(monkeypatch, tmp_path, term)
        try:
            _, pv = wiz.preview(8)
            wiz.start(8, _mb_body(pv["previewId"]), verify_password=_pw_ok)
        finally:
            drv.disconnect()
        run = wiz.status()["run"]
        self._assert_nothing_forgotten(sqlite_db, run)
        assert "NOT_VERIFIED" in run["error"] and "30002" in term.users

    def test_a_fingerprints_erase_that_answered_ok_but_left_a_template(self, sqlite_db,
                                                                      monkeypatch, tmp_path):
        term = _keeps_some(keep_fingers={("30001", 3)})
        _own(sqlite_db, 8, ["30001", "30002"])
        wiz, _w, drv = _mb_setup(monkeypatch, tmp_path, term)
        try:
            _, pv = wiz.preview(8)
            wiz.start(8, _mb_body(pv["previewId"], tables=["fingerprints"], forget=False,
                                  refill="now"), verify_password=_pw_ok)
        finally:
            drv.disconnect()
        run = wiz.status()["run"]
        self._assert_nothing_forgotten(sqlite_db, run)
        assert ("30001", 3) in term.fingers


# ─────────────────────────── F21: the door runs while held ───────────────────────────

class TestTheDoorRunsWhileHeld:

    def _worker(self):
        from tests.test_door_open_deadline import _connected_worker
        return _connected_worker()                            # device 1

    def test_a_desk_door_open_is_executed(self, sqlite_db):
        worker = self._worker()
        device_hold.hold(1, reason="erase", run_id="r")
        box = {}
        t = threading.Thread(target=lambda: box.update(
            worker.request_door_open(door_id=1, pulse_ms=3000, timeout=5.0)))
        t.start()
        deadline = time.monotonic() + 5
        while worker._cmd_queue.empty() and time.monotonic() < deadline:
            time.sleep(0.005)
        worker._drain_commands()
        t.join(5)
        assert box.get("ok") is True
        worker._sdk.open_door.assert_called()

    def test_a_queued_sdk_command_runs(self, sqlite_db):
        worker = self._worker()
        device_hold.hold(1, reason="erase", run_id="r")
        box = {}
        t = threading.Thread(target=lambda: box.update(
            worker.request_run_sdk(lambda sdk: "ran", label="probe", timeout=5.0)))
        t.start()
        deadline = time.monotonic() + 5
        while worker._sdk_cmd_queue.empty() and time.monotonic() < deadline:
            time.sleep(0.005)
        worker._drain_sdk_commands()
        t.join(5)
        assert box.get("ok") is True and box.get("result") == "ran"

    def test_a_rescue_open_goes_straight_to_the_sdk(self, sqlite_db):
        worker = self._worker()
        device_hold.hold(1, reason="erase", run_id="r")
        assert worker._open_door_with_retry(door_id=1) is True
        worker._sdk.open_door.assert_called()

    def test_the_hold_is_read_only_by_the_write_gate(self):
        """The door side never reads the hold: only _v2_writes_blocked does (six write paths)."""
        import ast
        import inspect

        import app.core.ultra_engine as ue
        src = inspect.getsource(ue)
        tree = ast.parse(src)
        readers = set()
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for node in ast.walk(fn):
                    if (isinstance(node, ast.Attribute) and node.attr == "is_held"
                            and isinstance(node.value, ast.Name)
                            and node.value.id == "_device_hold"):
                        readers.add(fn.name)
        assert readers == {"_v2_writes_blocked"}, readers
        door_side = {"run", "_drain_commands", "_drain_sdk_commands", "_poll_with_watchdog",
                     "_process_event", "_open_door_with_retry", "_connect"}
        callers = set()
        for fn in ast.walk(tree):
            if isinstance(fn, ast.FunctionDef) and fn.name in door_side:
                for node in ast.walk(fn):
                    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                            and node.func.id == "_v2_writes_blocked"):
                        callers.add(fn.name)
        assert callers == set(), callers


# ─────────────────────────── F22: a hold set during a PullSDK pass ───────────────────────────

def test_a_hold_set_during_a_pullsdk_pass_stops_its_batch(sqlite_db):
    from tests.test_account_pin_device_sites import _engine, _pullsdk_device, _sdk, _written_pins
    from tests.test_device_hold import _users

    sdk = _sdk()

    def _read(*a, **k):
        device_hold.hold(1, reason="erase", run_id="r")    # lands while the pass reads the panel
        return []
    sdk.get_device_data_rows.side_effect = _read
    sdk.get_all_device_data.side_effect = _read
    engine = _engine()
    with patch("app.core.device_sync.PullSDK", MagicMock(return_value=sdk)):
        engine._sync_one_device(device=_pullsdk_device(), users=_users(*range(101, 109)),
                                local_fp_index={}, default_door_id=1)
    assert device_hold.is_held(1)
    assert _written_pins(sdk) == [], "nothing written after the hold landed"
    assert sqlite_db.list_push_intents(device_id=1) == {}, "no intent: nothing was attempted"


# ─────────────────────────── F24: the smaller claims ───────────────────────────

class TestTheSmallerClaims:

    def test_the_mb2000_users_are_deleted_20_per_command(self, sqlite_db, monkeypatch, tmp_path,
                                                        refill_cache):
        term = WizardTerminal()
        term.add("1", "Admin", "", fingers=(), privilege=14)
        for i in range(45):
            term.add(str(50000 + i), f"M{i}", str(700 + i))
        wiz, worker, drv = _mb_setup(monkeypatch, tmp_path, term)
        chunks: List[list] = []
        real = drv.delete_users

        class _Count:
            def __getattr__(self, name):
                return getattr(drv, name)

            def delete_users(self, pins, **k):
                chunks.append(list(pins))
                return real(pins, **k)
        worker.drv = _Count()
        try:
            _, pv = wiz.preview(8)
            wiz.start(8, _mb_body(pv["previewId"]), verify_password=_pw_ok)
        finally:
            drv.disconnect()
        assert wiz.status()["run"]["state"] == "DONE"
        assert [len(c) for c in chunks] == [20, 20, 5]
        assert set(term.users) == {"1"}

    def test_a_readable_template_table_is_required_with_user_and_erased(self, sqlite_db,
                                                                       monkeypatch, tmp_path):
        tables = dict(_panel().tables, template=[{"Pin": "101", "FingerID": "1"}])
        panel = FakePanel(tables)
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=panel)
        _, pv = wiz.preview(5)
        status, out = wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert status == 400 and out["code"] == "USER_NEEDS_RIGHTS_AND_FINGERS"
        assert out["missing"] == ["template"]
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"], tables=["user", "userauthorize", "templatev10",
                                                    "template"]), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "DONE" and panel.tables["template"] == []

    def test_the_fingerprints_only_path_stays_inside_its_budgets(self, sqlite_db, monkeypatch,
                                                                tmp_path):
        term = _terminal()
        wiz, worker, drv = _mb_setup(monkeypatch, tmp_path, term)
        calls: List[tuple] = []
        budgets: List[tuple] = []
        worker.drv = _Recording(drv, calls)
        real = worker.request_run_sdk

        def _budget(fn, *, label, timeout):
            before = len(calls)
            out = real(fn, label=label, timeout=timeout)
            budgets.extend((c, timeout) for c in calls[before:])
            return out
        worker.request_run_sdk = _budget
        try:
            _, pv = wiz.preview(8)
            wiz.start(8, _mb_body(pv["previewId"], tables=["fingerprints"], forget=False,
                                  refill="now"), verify_password=_pw_ok)
        finally:
            drv.disconnect()
        assert wiz.status()["run"]["state"] == "DONE"
        seen = {name for (name, _t), _b in budgets}
        assert "sweep_finger_slots" in seen
        for (name, t), budget in budgets:
            assert t is not None and 0 < t < budget, (name, t, budget)

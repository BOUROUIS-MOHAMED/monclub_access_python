"""Lane 1 item 3: the Erase-content wizard (owner design 2026-09-27, guide §3.2h).

What must hold, each pinned below against fake SDKs (nothing reaches a device, a real temp
SQLite for the records):
* nothing is erased without the admin password, the typed name and a verified backup;
* the preview binds the run to ONE turnstile: another device, or a changed name/address, refuses;
* door logs are shown, never erasable (the PC cannot prove which panel rows it already sent);
* the turnstile is on hold -- nothing written to it -- from before the backup to the refill;
* an erase that cannot be verified keeps the hold and forgets nothing;
* "forget" retires the records through the removal log and reports the wipe; "keep" invalidates;
* the refill options: now / next sync / hold until Refill (durable across a restart);
* on the MB2000 the administrators, and their fingers, are kept; faces refuse the users erase.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

import app.core.db as dbmod
from app.core import device_hold
from app.core.erase_wizard import EraseWizard
from app.core.v2 import lease_gate as lg
from tests.fake_terminal import TerminalZkem
from tests.test_standalone_incremental_sync import _make_driver

GOOD = (True, 200, "")


def _pw_ok(_p):
    return GOOD


def _pw_bad(_p):
    return (False, 401, "Mot de passe incorrect")


@pytest.fixture
def sqlite_db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "erase.db"), raising=False)
    dbmod.init_db()
    device_hold.reset_for_tests()
    lg.reset_for_tests()
    yield dbmod
    device_hold.reset_for_tests()
    lg.reset_for_tests()
    dbmod._shutdown_db_writer_for_tests()


# ─────────────────────────── fakes ───────────────────────────

class FakePanel:
    """A C3 panel's tables behind the PullSDKDevice strict surface the wizard uses."""

    def __init__(self, tables: Dict[str, List[Dict[str, str]]]):
        self.tables = {k: list(v) for k, v in tables.items()}
        self.calls: List[tuple] = []
        self.short_read: set = set()
        self.refuse_erase: set = set()
        self.on_erase = None

    def count_table_strict(self, *, table):
        self.calls.append(("count", table))
        if table not in self.tables:
            raise RuntimeError(f"GetDeviceDataCount FAILED table={table} rc=-1")
        return len(self.tables[table])

    def read_table_strict(self, *, table, fields="*"):
        self.calls.append(("read", table))
        rows = list(self.tables[table])
        return rows[:-1] if table in self.short_read else rows

    def erase_table(self, *, table):
        self.calls.append(("erase", table))
        if self.on_erase:
            self.on_erase(table)
        if table in self.refuse_erase:
            return 0          # the dll said nothing wrong, the rows stay (verify catches it)
        self.tables[table] = []
        return 0


class FakeWorker:
    def __init__(self, drv):
        self.drv = drv
        self._connected = True
        self._full_sync_running = False
        self.full_sync_requests: List[str] = []
        self.no_answer: set = set()
        self._waiting_pins = 3

    def request_run_sdk(self, fn, *, label, timeout):
        try:
            result = fn(self.drv)
        except Exception as exc:          # what _drain_sdk_commands does with fn's exception
            return {"ok": False, "result": None, "error": str(exc)}
        if label in self.no_answer:
            return {"ok": False, "result": None, "error": "sent, no answer"}
        return {"ok": True, "result": result, "error": ""}

    def request_full_sync(self, reason="manual", **kw):
        self.full_sync_requests.append(reason)
        return True


class FakeSched:
    def __init__(self):
        self.forced: List[int] = []

    def force_resync(self, did):
        self.forced.append(int(did))


def _app(workers):
    return SimpleNamespace(_ultra_engine=SimpleNamespace(running=True, _workers=workers,
                                                         _sync_scheduler=FakeSched()))


def _device(did=5, name="Entrée 1", ip="192.168.0.202", proto="ZK_PULLSDK"):
    return {"id": did, "name": name, "ipAddress": ip, "portNumber": 4370,
            "deviceProtocol": proto, "accessDataMode": "ULTRA"}


def _devices(monkeypatch, *devices):
    by_id = {d["id"]: d for d in devices}
    monkeypatch.setattr(dbmod, "get_sync_device_payload", lambda did: by_id.get(int(did)))
    return by_id


def _wizard(app, tmp_path):
    return EraseWizard(app, backup_root=tmp_path / "backups", spawn=lambda fn: fn(),
                       sleep=lambda s: None)


def _panel():
    return FakePanel({
        "user": [{"Pin": "101", "CardNo": "1001"}, {"Pin": "102", "CardNo": "1002"}],
        "userauthorize": [{"Pin": "101", "AuthorizeDoorId": "15"},
                          {"Pin": "102", "AuthorizeDoorId": "15"}],
        "templatev10": [{"Pin": "101", "FingerID": "0"}],
        "transaction": [{"Pin": "101", "Time_second": "1"}],
        # "template" absent: this panel does not answer for it
    })


def _body(preview_id, **kw):
    body = {"previewId": preview_id, "tables": ["user", "userauthorize", "templatev10"],
            "forget": True, "refill": "hold", "typedName": "Entrée 1", "password": "pw"}
    body.update(kw)
    return body


def _own(db, did, pins):
    for p in pins:
        db.save_device_sync_state(device_id=did, pin=p, desired_hash="h", ok=True, error=None)


def _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=None):
    panel = panel or _panel()
    worker = FakeWorker(panel)
    app = _app({5: worker})
    _devices(monkeypatch, _device())
    return _wizard(app, tmp_path), worker, panel, app


# ─────────────────────────── step 1: the preview ───────────────────────────

class TestPreview:

    def test_counts_every_table_and_door_logs_are_never_erasable(self, sqlite_db, monkeypatch,
                                                                  tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        status, out = wiz.preview(5)
        assert status == 200 and out["ok"]
        rows = {r["key"]: r for r in out["tables"]}
        assert [r["key"] for r in out["tables"]] == ["user", "userauthorize", "templatev10",
                                                     "template", "transaction"]
        assert rows["user"] == {"key": "user", "count": 2, "erasable": True}
        assert rows["template"]["count"] is None and rows["template"]["erasable"] is False
        assert rows["transaction"]["count"] == 1
        assert rows["transaction"]["erasable"] is False
        assert rows["transaction"]["reason"] == "DOOR_LOG_NOT_SUPPORTED"
        assert {c[0] for c in panel.calls} == {"count"}, "step 1 only counts"
        assert not device_hold.is_held(5)

    def test_a_turnstile_this_pc_does_not_drive_is_refused(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        lg.install(lg.snapshot_from_assignment({"gymUsesAssignments": True, "role": "READER",
                                                "drive": [], "release": []}, source="server"))
        status, out = wiz.preview(5)
        assert status == 409 and out["notDriver"] is True and panel.calls == []

    def test_no_running_worker_no_second_session(self, sqlite_db, monkeypatch, tmp_path):
        _devices(monkeypatch, _device())
        wiz = _wizard(_app({}), tmp_path)
        status, out = wiz.preview(5)
        assert status == 409 and out["code"] == "NO_WORKER"


# ─────────────────────────── the three safety gates ───────────────────────────

class TestNothingIsErasedWithout:

    def test_the_admin_password(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        status, out = wiz.start(5, _body(pv["previewId"]), verify_password=_pw_bad)
        assert status == 401 and out["code"] == "ADMIN_PASSWORD"
        assert all(c[0] == "count" for c in panel.calls) and panel.tables["user"]
        assert not device_hold.is_held(5) and wiz.status()["run"] is None

    def test_the_typed_name(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        checked = []
        status, out = wiz.start(5, _body(pv["previewId"], typedName="Entree 1"),
                                verify_password=lambda p: checked.append(p) or GOOD)
        assert status == 400 and out["code"] == "NAME_MISMATCH"
        assert checked == [] and panel.tables["user"] and not device_hold.is_held(5)

    @pytest.mark.parametrize("break_it", ["short_read", "unwritable"])
    def test_a_verified_backup(self, sqlite_db, monkeypatch, tmp_path, break_it):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        if break_it == "short_read":
            panel.short_read = {"user"}
        else:
            blocker = tmp_path / "backups"
            blocker.write_text("a file where the backup folder should be")
        _, pv = wiz.preview(5)
        status, _ = wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert status == 202
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "nothing was erased" in run["error"]
        assert [c for c in panel.calls if c[0] == "erase"] == []
        assert len(panel.tables["user"]) == 2
        assert not device_hold.is_held(5), "nothing was erased: the hold is released"

    def test_the_backup_is_written_and_checked_before_the_first_erase(self, sqlite_db, monkeypatch,
                                                                       tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        seen = []

        def _at_erase(table):
            run = wiz.status()["run"]
            path = Path(run["backup"]["path"])
            data = json.loads(path.read_text(encoding="utf-8"))
            seen.append((table, data["rowCounts"], device_hold.is_held(5)))

        panel.on_erase = _at_erase
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert seen and seen[0][1] == {"user": 2, "userauthorize": 2, "templatev10": 1}
        assert all(held for _t, _c, held in seen), "the turnstile is on hold during the erase"
        run = wiz.status()["run"]
        path = Path(run["backup"]["path"])
        import hashlib
        assert hashlib.sha256(path.read_bytes()).hexdigest() == run["backup"]["sha256"]
        assert (path.parent / "backup.json.sha256").read_text().startswith(run["backup"]["sha256"])
        assert json.loads((path.parent / "run.json").read_text(encoding="utf-8"))["state"] == "DONE"


class TestTheRightDeviceOnly:

    def test_a_preview_of_another_turnstile_is_refused(self, sqlite_db, monkeypatch, tmp_path):
        p5, p6 = _panel(), _panel()
        app = _app({5: FakeWorker(p5), 6: FakeWorker(p6)})
        _devices(monkeypatch, _device(), _device(did=6, name="Sortie", ip="192.168.0.203"))
        wiz = _wizard(app, tmp_path)
        _, pv5 = wiz.preview(5)
        status, out = wiz.start(6, _body(pv5["previewId"], typedName="Sortie"),
                                verify_password=_pw_ok)
        assert status == 409 and out["code"] == "WRONG_DEVICE"
        assert p6.tables["user"] and p5.tables["user"]

    def test_a_turnstile_whose_address_changed_is_refused(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        _devices(monkeypatch, _device(ip="192.168.0.250"))
        status, out = wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert status == 409 and out["code"] == "DEVICE_CHANGED"
        assert panel.tables["user"]

    @pytest.mark.parametrize("table", ["transaction", "template"])
    def test_a_door_log_or_an_unreadable_table_cannot_be_chosen(self, sqlite_db, monkeypatch,
                                                                tmp_path, table):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        status, out = wiz.start(5, _body(pv["previewId"], tables=["user", table]),
                                verify_password=_pw_ok)
        assert status == 400
        assert out["code"] == ("DOOR_LOG_NOT_SUPPORTED" if table == "transaction" else "UNREADABLE")
        assert panel.tables["transaction"]

    def test_forget_needs_the_users_table(self, sqlite_db, monkeypatch, tmp_path):
        """Forgetting pins still on the panel would strand them there (guide §3.2c)."""
        wiz, _w, _panel_, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        status, out = wiz.start(5, _body(pv["previewId"], tables=["templatev10"], forget=True),
                                verify_password=_pw_ok)
        assert status == 400 and out["code"] == "FORGET_NEEDS_USERS"

    def test_one_run_at_a_time(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        wiz._spawn = lambda fn: None          # the first run never ends in this test
        _, pv = wiz.preview(5)
        assert wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)[0] == 202
        _, pv2 = wiz.preview(5)
        status, out = wiz.start(5, _body(pv2["previewId"]), verify_password=_pw_ok)
        assert status == 409 and out["code"] == "RUN_IN_PROGRESS"


# ─────────────────────────── erase, verify, records, refill (C3) ───────────────────────────

class TestC3Run:

    def test_the_chosen_tables_are_erased_rights_and_fingers_first(self, sqlite_db, monkeypatch,
                                                                   tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert [c[1] for c in panel.calls if c[0] == "erase"] == ["templatev10", "userauthorize",
                                                                  "user"]
        assert panel.tables["transaction"], "the door log is never touched"
        run = wiz.status()["run"]
        assert run["state"] == "DONE"
        assert run["countsBefore"]["tables"]["user"] == 2
        assert run["countsAfter"]["tables"]["user"] == 0

    def test_an_erase_that_leaves_rows_keeps_the_hold_and_forgets_nothing(self, sqlite_db,
                                                                        monkeypatch, tmp_path):
        _own(sqlite_db, 5, ["101", "102"])
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        panel.refuse_erase = {"user"}
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "INCOMPLETE" and run["holdKept"] is True
        assert device_hold.is_held(5)
        assert set(sqlite_db.list_confirmed_device_sync_pins(device_id=5)) == {"101", "102"}

    def test_an_unanswered_erase_is_never_read_as_done(self, sqlite_db, monkeypatch, tmp_path):
        _own(sqlite_db, 5, ["101"])
        wiz, worker, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        worker.no_answer = {"erase_erase_user"}
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "INCOMPLETE" and device_hold.is_held(5)
        assert set(sqlite_db.list_confirmed_device_sync_pins(device_id=5)) == {"101"}

    def test_forget_retires_the_records_through_the_removal_log_and_reports_the_wipe(
            self, sqlite_db, monkeypatch, tmp_path):
        _own(sqlite_db, 5, ["101", "102"])
        sqlite_db.record_push_intents(device_id=5, rows=[("103", "N", "1003", "h3")],
                                      protocol="ZK_PULLSDK")
        wiz, _w, _panel_, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"], forget=True), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "DONE"
        assert sqlite_db.list_device_sync_hashes_and_status(device_id=5) == {}
        with sqlite_db.get_conn() as conn:
            removed = {r[0] for r in conn.execute(
                "SELECT pin FROM v2_removal_log WHERE device_id=5").fetchall()}
            intents = conn.execute("SELECT COUNT(*) FROM device_push_intent WHERE device_id=5"
                                   ).fetchone()[0]
        assert removed == {"101", "102", "103"} and intents == 0
        from app.core.v2 import store
        assert store.kv_get("wipe:5"), "the server's ownership record is told the panel was wiped"

    def test_keep_records_invalidates_every_pin_and_keeps_ownership(self, sqlite_db, monkeypatch,
                                                                    tmp_path):
        _own(sqlite_db, 5, ["101", "102"])
        wiz, _w, _panel_, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"], forget=False), verify_password=_pw_ok)
        state = sqlite_db.list_device_sync_hashes_and_status(device_id=5)
        assert state == {"101": ("", False), "102": ("", False)}, "every pin is pushed again"
        assert set(sqlite_db.list_confirmed_device_sync_pins(device_id=5)) == {"101", "102"}

    def test_refill_now(self, sqlite_db, monkeypatch, tmp_path):
        wiz, worker, _p, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"], refill="now"), verify_password=_pw_ok)
        assert not device_hold.is_held(5)
        assert worker.full_sync_requests == ["erase-refill"]
        assert app._ultra_engine._sync_scheduler.forced == [5]

    def test_refill_at_the_next_sync(self, sqlite_db, monkeypatch, tmp_path):
        wiz, worker, _p, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"], refill="auto"), verify_password=_pw_ok)
        assert not device_hold.is_held(5) and worker.full_sync_requests == []
        assert app._ultra_engine._sync_scheduler.forced == [5], (
            "the roster hash did not move: without this the scheduler skips the device")

    def test_hold_until_refill_survives_a_restart_and_refill_needs_the_password(
            self, sqlite_db, monkeypatch, tmp_path):
        wiz, worker, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"], refill="hold"), verify_password=_pw_ok)
        assert device_hold.is_held(5) and worker.full_sync_requests == []
        device_hold.reset_for_tests()                     # a restart ...
        assert device_hold.load() == frozenset({5})       # ... finds the hold in the database
        status, out = wiz.refill(5, {"password": "x"}, verify_password=_pw_bad)
        assert status == 401 and device_hold.is_held(5)
        status, out = wiz.refill(5, {"password": "pw"}, verify_password=_pw_ok)
        assert status == 200 and out["passRequested"] is True
        assert not device_hold.is_held(5) and dbmod.list_device_write_holds() == {}
        assert worker.full_sync_requests == ["erase-refill"]

    def test_the_refill_names_the_scheme_recorded_now(self, sqlite_db, monkeypatch, tmp_path):
        """Cutover: erase with hold, switch to "Par personne", then Refill. The refill pushes
        what the database records by then; the button shows it."""
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"], refill="hold"), verify_password=_pw_ok)
        monkeypatch.setattr(dbmod, "get_device_pin_scheme", lambda did: "ACCOUNT")
        assert wiz.holds() and wiz.holds()[0]["pinScheme"] == "ACCOUNT"
        status, out = wiz.refill(5, {"password": "pw"}, verify_password=_pw_ok)
        assert status == 200 and out["pinScheme"] == "ACCOUNT"

    def test_backup_only_erases_nothing(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"], backupOnly=True), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "DONE" and Path(run["backup"]["path"]).exists()
        assert [c for c in panel.calls if c[0] == "erase"] == [] and not device_hold.is_held(5)

    def test_a_turnstile_already_on_hold_stays_held_when_a_run_fails(self, sqlite_db, monkeypatch,
                                                                     tmp_path):
        device_hold.hold(5, reason="erase", run_id="earlier")
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        panel.short_read = {"user"}
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "FAILED" and device_hold.is_held(5)


# ─────────────────────────── MB2000 ───────────────────────────

class WizardTerminal(TerminalZkem):
    """The fake MB2000 with privileges, live counters and a template read."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.priv: Dict[str, int] = {}
        self.faces = 0
        self.attendance = 70
        self.admin_count_override = None

    def add(self, pin, name, card, fingers=(), privilege=0):
        self.add_user(pin, name, card, fingers)
        self.priv[str(pin)] = privilege

    def ReadAllUserID(self, machine):
        ok = super().ReadAllUserID(machine)
        for u in self.device_users:
            u["privilege"] = self.priv.get(u["pin"], 0)
        return ok

    def SSR_GetAllUserInfo(self, machine, *placeholders):
        if self._enum_idx >= len(self.device_users):
            return (False, "", "", "", 0, 0)
        u = self.device_users[self._enum_idx]
        self._enum_idx += 1
        self._cur_card = str(u.get("card", ""))
        return (True, u["pin"], u["name"], "", u.get("privilege", 0), 1)

    def SSR_GetUserTmpStr(self, machine, pin, fid, *placeholders):
        self._rec("SSR_GetUserTmpStr", pin, fid)
        if (str(pin), int(fid)) in self.fingers:
            return (True, f"TPL{pin}F{fid}", 8)
        return (False, "", 0)

    def GetDeviceStatus(self, machine, idx, box):
        admins = sum(1 for p in self.users if self.priv.get(p, 0) > 0)
        if self.admin_count_override is not None:
            admins = self.admin_count_override
        self.status = {1: admins, 2: len(self.users), 3: len(self.fingers), 4: 0,
                       6: self.attendance, 21: self.faces}
        return super().GetDeviceStatus(machine, idx, box)


def _mb_setup(monkeypatch, tmp_path, term):
    drv = _make_driver(term)
    worker = FakeWorker(drv)
    app = _app({8: worker})
    _devices(monkeypatch, _device(did=8, name="Sortie", ip="192.168.1.247", proto="ZK_STANDALONE"))
    return _wizard(app, tmp_path), worker, drv


def _terminal():
    t = WizardTerminal()
    t.add("1", "Admin", "", fingers=(0,), privilege=14)
    t.add("30001", "Ali", "111", fingers=(0, 3))
    t.add("30002", "Sonia", "222", fingers=(1,))
    t.add("777", "Old system", "333", fingers=(2,))
    return t


def _mb_body(pid, **kw):
    b = {"previewId": pid, "tables": ["users"], "forget": True, "refill": "hold",
         "typedName": "Sortie", "password": "pw"}
    b.update(kw)
    return b


class TestMb2000:

    def test_the_preview_reads_the_terminal_counters(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, drv = _mb_setup(monkeypatch, tmp_path, _terminal())
        try:
            status, out = wiz.preview(8)
        finally:
            drv.disconnect()
        assert status == 200
        rows = {r["key"]: r for r in out["tables"]}
        assert rows["users"]["count"] == 4 and rows["fingerprints"]["count"] == 5
        assert rows["attendance"]["count"] == 70 and rows["attendance"]["erasable"] is False
        assert out["extra"]["admins"] == 1 and out["extra"]["faces"] == 0

    def test_every_non_admin_user_goes_the_admin_stays(self, sqlite_db, monkeypatch, tmp_path):
        term = _terminal()
        _own(sqlite_db, 8, ["30001", "30002"])
        wiz, _w, drv = _mb_setup(monkeypatch, tmp_path, term)
        try:
            _, pv = wiz.preview(8)
            wiz.start(8, _mb_body(pv["previewId"]), verify_password=_pw_ok)
        finally:
            drv.disconnect()
        run = wiz.status()["run"]
        assert run["state"] == "DONE", run["error"]
        assert set(term.users) == {"1"} and term.fingers == {("1", 0)}
        deletes = [c for c in term.calls if c[0] == "SSR_DeleteEnrollData"]
        assert deletes and all(c[3] == 12 for c in deletes), "only the whole-user delete"
        backup = json.loads(Path(run["backup"]["path"]).read_text(encoding="utf-8"))
        assert {u["pin"] for u in backup["users"]} == {"1", "30001", "30002", "777"}
        assert backup["templates"]["30001"] == [
            {"fingerId": 0, "template": "TPL30001F0", "size": 8},
            {"fingerId": 3, "template": "TPL30001F3", "size": 8}]
        assert sqlite_db.list_device_sync_hashes_and_status(device_id=8) == {}

    def test_fingerprints_only_keep_the_users_and_the_admins_fingers(self, sqlite_db, monkeypatch,
                                                                     tmp_path):
        term = _terminal()
        _own(sqlite_db, 8, ["30001"])
        wiz, _w, drv = _mb_setup(monkeypatch, tmp_path, term)
        try:
            _, pv = wiz.preview(8)
            wiz.start(8, _mb_body(pv["previewId"], tables=["fingerprints"], forget=False,
                                  refill="now"), verify_password=_pw_ok)
        finally:
            drv.disconnect()
        run = wiz.status()["run"]
        assert run["state"] == "DONE", run["error"]
        assert set(term.users) == {"1", "30001", "30002", "777"}
        assert term.fingers == {("1", 0)}
        assert [c for c in term.calls if c[0] == "SSR_DeleteEnrollData"] == [], (
            "never the finger-index delete that hangs the MB2000")
        with sqlite_db.get_conn() as conn:
            row = conn.execute("SELECT pushed_finger_ids, finger_slots_swept, ownership_confirmed "
                               "FROM device_sync_state WHERE device_id=8 AND pin='30001'").fetchone()
        assert tuple(row) == ("", 1, 1), "fingers known EMPTY, ownership kept"

    def test_faces_refuse_the_users_erase_unless_their_loss_is_accepted(self, sqlite_db,
                                                                         monkeypatch, tmp_path):
        term = _terminal()
        term.faces = 2
        wiz, _w, drv = _mb_setup(monkeypatch, tmp_path, term)
        try:
            _, pv = wiz.preview(8)
            status, out = wiz.start(8, _mb_body(pv["previewId"]), verify_password=_pw_ok)
            assert status == 409 and out["code"] == "FACES_PRESENT" and len(term.users) == 4
            _, pv = wiz.preview(8)
            status, _ = wiz.start(8, _mb_body(pv["previewId"], acceptFaceLoss=True),
                                  verify_password=_pw_ok)
        finally:
            drv.disconnect()
        assert status == 202 and set(term.users) == {"1"}

    def test_a_listing_whose_admin_count_disagrees_is_not_trusted(self, sqlite_db, monkeypatch,
                                                                   tmp_path):
        term = _terminal()
        term.admin_count_override = 3          # the terminal says 3 admins, the listing 1
        wiz, _w, drv = _mb_setup(monkeypatch, tmp_path, term)
        try:
            _, pv = wiz.preview(8)
            wiz.start(8, _mb_body(pv["previewId"]), verify_password=_pw_ok)
        finally:
            drv.disconnect()
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "BACKUP_UNTRUSTED" in run["error"]
        assert len(term.users) == 4 and not device_hold.is_held(8)

    def test_a_template_count_that_disagrees_stops_before_any_erase(self, sqlite_db, monkeypatch,
                                                                     tmp_path):
        term = _terminal()
        real = term.SSR_GetUserTmpStr
        term.SSR_GetUserTmpStr = lambda m, pin, fid, *a: (
            (False, "", 0) if (pin, fid) == ("30002", 1) else real(m, pin, fid))
        wiz, _w, drv = _mb_setup(monkeypatch, tmp_path, term)
        try:
            _, pv = wiz.preview(8)
            wiz.start(8, _mb_body(pv["previewId"]), verify_password=_pw_ok)
        finally:
            drv.disconnect()
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "4 template(s) read, the terminal counts 5" in run["error"]
        assert len(term.users) == 4


# ─────────────────────────── the local API: the password is checked on the server ───────────

class _Ctx:
    def __init__(self, app, did, body=None):
        self.app = app
        self._did = did
        self._body = dict(body or {})
        self.sent = None

    def param_int(self, name, default=0):
        return self._did

    def body(self):
        return dict(self._body)

    def send_json(self, status, payload):
        self.sent = (status, payload)


class TestLocalApi:

    def _run(self, monkeypatch, tmp_path, validate):
        import access.store as store
        import app.api.local_access_api_v2 as la2

        panel = _panel()
        worker = FakeWorker(panel)
        app = _app({5: worker})
        app._erase_wizard = _wizard(app, tmp_path)
        api = SimpleNamespace(validate_statistics_password=validate)
        app._api = lambda: api
        monkeypatch.setattr(store, "load_auth_token", lambda: SimpleNamespace(token="jwt"))
        _devices(monkeypatch, _device())
        ctx = _Ctx(app, 5)
        la2._handle_device_erase_preview(ctx)
        assert ctx.sent[0] == 200
        ctx2 = _Ctx(app, 5, _body(ctx.sent[1]["previewId"]))
        la2._handle_device_erase_start(ctx2)
        return ctx2.sent, panel

    def test_a_wrong_password_is_refused_by_the_backend_check(self, sqlite_db, monkeypatch,
                                                              tmp_path):
        (status, out), panel = self._run(monkeypatch, tmp_path,
                                         lambda token, password: False)
        assert status == 401 and out["code"] == "ADMIN_PASSWORD" and panel.tables["user"]

    def test_no_backend_answer_means_no_erase(self, sqlite_db, monkeypatch, tmp_path):
        def _down(token, password):
            raise ConnectionError("offline")
        (status, out), panel = self._run(monkeypatch, tmp_path, _down)
        assert status == 503 and panel.tables["user"] and not device_hold.is_held(5)

    def test_the_right_password_starts_the_run(self, sqlite_db, monkeypatch, tmp_path):
        (status, out), panel = self._run(monkeypatch, tmp_path, lambda token, password: True)
        assert status == 202 and out["runId"] and panel.tables["user"] == []

    def test_the_routes_are_registered_and_the_device_ones_lease_gated(self):
        from access.local_api_routes import ACCESS_LOCAL_ROUTE_SPECS, LEASE_GATED_HANDLERS

        specs = set(ACCESS_LOCAL_ROUTE_SPECS)
        assert ("GET", "/api/v2/devices/{deviceId}/erase/preview",
                "_handle_device_erase_preview") in specs
        assert ("POST", "/api/v2/devices/{deviceId}/erase", "_handle_device_erase_start") in specs
        assert ("POST", "/api/v2/devices/{deviceId}/erase/refill",
                "_handle_device_erase_refill") in specs
        assert {"_handle_device_erase_preview", "_handle_device_erase_start"} <= set(
            LEASE_GATED_HANDLERS)

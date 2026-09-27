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
import time
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
    def __init__(self, drv, addr=("192.168.0.202", 4370)):
        self.drv = drv
        self._connected = True
        self._connected_addr = addr          # what the real worker records at connect
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
    # A getSyncData that succeeded just now (lane 1c: the member list's age limit reads the
    # monotonic stamp app.py records with the success).
    return SimpleNamespace(_ultra_engine=SimpleNamespace(running=True, _workers=workers,
                                                         _sync_scheduler=FakeSched()),
                           _last_sync_ok=True, _last_sync_ok_mono=time.monotonic())


# What the refill would write (lane 1b, review C1): the sync cache's members. Membership pins
# 101/102 (the fake C3's users) and 30001/30002 (the fake MB2000's), each with an account number,
# none equal to the MB2000 administrator's pin 1.
_ROSTER = [
    {"userId": 11, "activeMembershipId": 101, "mainAccountId": 9101, "fullName": "A"},
    {"userId": 12, "activeMembershipId": 102, "mainAccountId": 9102, "fullName": "B"},
    {"userId": 13, "activeMembershipId": 30001, "mainAccountId": 9301, "fullName": "Ali"},
    {"userId": 14, "activeMembershipId": 30002, "mainAccountId": 9302, "fullName": "Sonia"},
]


@pytest.fixture(autouse=True)
def erase_switch_on(monkeypatch):
    """The gym's server switch for the wizard (owner decision 2026-09-27) is ON in these tests;
    tests/test_erase_wizard_lane1b.py::TestTheGymsServerSwitch covers it."""
    import app.core.erase_wizard as ew
    calls: List[int] = []
    monkeypatch.setattr(ew, "check_erase_switch", lambda app: calls.append(1) or (True, None, ""))
    return calls


@pytest.fixture(autouse=True)
def refill_cache(monkeypatch):
    """Every wizard test has a member list to refill from; a test changes ``users``."""
    cache = SimpleNamespace(users=[dict(u) for u in _ROSTER], devices=[],
                            updated_at="2026-09-27T10:00:00")
    monkeypatch.setattr(dbmod, "load_sync_cache", lambda: cache)
    return cache


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
            "forget": True, "refill": "hold", "typedName": "Entrée 1", "password": "pw",
            "otherPcsClosed": True}
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
        # Step 1 counts, and reads the user list (lane 1c: who the refill will not put back).
        assert {c for c in panel.calls if c[0] != "count"} == {("read", "user")}, panel.calls
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
        panel.calls.clear()                       # step 1's own reads (lane 1c) are not the point
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
        app = _app({5: FakeWorker(p5), 6: FakeWorker(p6, addr=("192.168.0.203", 4370))})
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
        status, out = wiz.refill(5, {"password": "x", "expectedPinScheme": None},
                                 verify_password=_pw_bad)
        assert status == 401 and device_hold.is_held(5)
        status, out = wiz.refill(5, {"password": "pw", "expectedPinScheme": None},
                                 verify_password=_pw_ok)
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
        status, out = wiz.refill(5, {"password": "pw", "expectedPinScheme": "ACCOUNT"},
                                 verify_password=_pw_ok)
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
    worker = FakeWorker(drv, addr=("192.168.1.247", 4370))
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
    # "Old system" (777) is on the terminal and not in the refill roster: accepted (lane 1c, C0).
    b = {"previewId": pid, "tables": ["users"], "forget": True, "refill": "hold",
         "typedName": "Sortie", "password": "pw", "otherPcsClosed": True,
         "acceptNotRefilled": True}
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


# ─────────────────────────── static: what the wizard may call on a device ───────────────────────────

_DRIVER_ALLOWLIST = {"count_table_strict", "read_table_strict", "erase_table",
                     "read_device_status", "list_device_users", "read_user_templates",
                     "delete_users", "sweep_finger_slots"}


def _wizard_tree():
    import ast
    source = Path(__file__).resolve().parents[1] / "app" / "core" / "erase_wizard.py"
    return ast.parse(source.read_text(encoding="utf-8"))


def _device_commands(tree):
    """Every function the wizard hands to the worker as a device command: the ``fn`` argument
    of ``self._call(worker, fn, ...)`` and ``self._write_call(worker, did, fn, ...)``, resolved
    in the scope of the method that makes the call. [(method, function node)]."""
    import ast
    out = []
    for method in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        local_defs = {n.name: n for n in ast.walk(method)
                      if isinstance(n, ast.FunctionDef) and n is not method}
        for node in ast.walk(method):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("_call", "_write_call")):
                continue
            idx = 1 if node.func.attr == "_call" else 2
            arg = node.args[idx]
            if isinstance(arg, ast.Lambda):
                out.append((method.name, arg))
            elif isinstance(arg, ast.Name) and arg.id in local_defs:
                out.append((method.name, local_defs[arg.id]))
            elif isinstance(arg, ast.Name) and method.name == "_write_call" and arg.id == "fn":
                continue                                # its own parameter: checked at its callers
            else:
                raise AssertionError(f"{method.name}: a device command that is not a lambda or a "
                                     f"local def: {ast.dump(arg)[:80]}")
    return out


def test_the_wizard_calls_only_these_driver_methods():
    """Lane 1b (review F17): an allowlist, not a tripwire. Every function the wizard hands to the
    worker (``_call`` / ``_write_call``) may use its device parameter -- whatever it is named --
    ONLY as ``param.<allowed>(...)``: no alias, no ``getattr``, no nested attribute
    (``drv._sdk._dll.X``), no passing it on (``_guarded`` hands it to the checked ``fn`` only).
    ``request_run_sdk`` is called in ``_call`` alone. The table erase is bounded twice: by
    ``C3_ERASE_ORDER`` here and by ``PullSDKDevice.ERASABLE_TABLES`` in the driver."""
    import ast

    tree = _wizard_tree()
    commands = _device_commands(tree)
    assert len(commands) >= 10, [m for m, _ in commands]
    used = set()
    for method, fn in commands:
        param = fn.args.args[0].arg
        parents = {}
        for node in ast.walk(fn):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Name) and node.id == param):
                continue
            up = parents.get(node)
            if (isinstance(up, ast.Attribute) and isinstance(parents.get(up), ast.Call)
                    and parents[up].func is up):
                assert up.attr in _DRIVER_ALLOWLIST, (method, up.attr)
                used.add(up.attr)
            elif (method == "_write_call" and isinstance(up, ast.Call)
                  and isinstance(up.func, ast.Name) and up.func.id == "fn"):
                continue
            else:
                raise AssertionError(f"{method}: the device parameter {param!r} is used as "
                                     f"{type(up).__name__}, not as {param}.<allowed>(...)")
    assert used == _DRIVER_ALLOWLIST, used
    request_sites = {m.name for m in ast.walk(tree) if isinstance(m, ast.FunctionDef)
                     for n in ast.walk(m) if isinstance(n, ast.Attribute)
                     and n.attr == "request_run_sdk"}
    assert request_sites == {"_call"}, request_sites
    # Every name the CODE uses (docstrings are string constants: they do not count).
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    forbidden = {"clear_device_table", "delete_device_data", "set_device_param",
                 "set_device_data", "delete_all_transaction_rows", "ClearGLog", "ClearData",
                 "SSR_DeleteEnrollData", "SSR_DeleteEnrollDataExt", "DeleteDeviceData",
                 "SetDeviceData", "remove_fingers_by_pin", "push_roster", "partial"}
    assert not (forbidden & names), forbidden & names


def test_the_table_erase_takes_its_table_from_the_erase_order_only():
    """``erase_table(table=...)`` is called once, in a loop over ``C3_ERASE_ORDER``, with the
    loop's own table: a door log or a parameter table cannot be named there (review F17)."""
    import ast

    import app.core.erase_wizard as ew
    from app.sdk.pullsdk import PullSDKDevice

    assert set(ew.C3_ERASE_ORDER) == {"templatev10", "template", "userauthorize", "user"}
    assert set(ew.C3_ERASE_ORDER) == set(PullSDKDevice.ERASABLE_TABLES)
    tree = _wizard_tree()
    loops = [n for n in ast.walk(tree) if isinstance(n, ast.For)
             and any(isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
                     and c.func.attr == "erase_table" for c in ast.walk(n))]
    calls = [c for c in ast.walk(tree) if isinstance(c, ast.Call)
             and isinstance(c.func, ast.Attribute) and c.func.attr == "erase_table"]
    assert len(calls) == 1 and len(loops) == 1
    loop, call = loops[0], calls[0]
    assert isinstance(loop.iter, ast.Name) and loop.iter.id == "C3_ERASE_ORDER"
    lam = [n for n in ast.walk(loop) if isinstance(n, ast.Lambda)
           and any(c is call for c in ast.walk(n))][0]
    (kw,) = call.keywords
    assert kw.arg == "table" and isinstance(kw.value, ast.Name)
    bound = dict(zip([a.arg for a in lam.args.args][-len(lam.args.defaults):], lam.args.defaults))
    assert isinstance(bound[kw.value.id], ast.Name) and bound[kw.value.id].id == loop.target.id


@pytest.mark.parametrize("table", ["transaction", "timezone", "holiday", "firstcard",
                                   "user ", "USER"])
def test_the_driver_refuses_any_other_table_before_connecting(table):
    from app.sdk.pullsdk import PullSDKDevice, PullSDKError

    dev = PullSDKDevice.__new__(PullSDKDevice)          # no connection, no DLL
    with pytest.raises(PullSDKError):
        dev.erase_table(table=table)


# ─────────────────────────── review round 1 (2026-09-27): each finding pinned ───────────────────────────

def _state(db, did):
    return db.list_device_sync_hashes_and_status(device_id=did)


def _removed(db, did):
    with db.get_conn() as conn:
        return {r[0] for r in conn.execute(
            "SELECT pin FROM v2_removal_log WHERE device_id=?", (did,)).fetchall()}


def _refill_body(scheme=None, **kw):
    body = {"password": "pw", "expectedPinScheme": scheme}
    body.update(kw)
    return body


class TestIncompleteRefillsEverything:
    """Finding 1 (BLOCKER): an INCOMPLETE run (or a restart mid-run) left every record "in
    sync", so Refill put back nothing the erase had removed."""

    def test_c3_incomplete_invalidates_every_pin_and_refill_pushes_them(self, sqlite_db,
                                                                       monkeypatch, tmp_path):
        from app.core.device_sync import count_waiting_pins
        _own(sqlite_db, 5, ["101", "102"])
        wiz, _w, panel, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        panel.refuse_erase = {"user"}          # rights and fingers went, the user rows stayed
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "INCOMPLETE" and device_hold.is_held(5)
        assert _state(sqlite_db, 5) == {"101": ("", False), "102": ("", False)}
        assert set(sqlite_db.list_confirmed_device_sync_pins(device_id=5)) == {"101", "102"}, (
            "ownership kept: nothing is forgotten after an unverified erase")
        assert _removed(sqlite_db, 5) == set()
        assert any(s["step"] == "records_invalidated" for s in run["steps"])
        status, _ = wiz.refill(5, _refill_body(), verify_password=_pw_ok)
        assert status == 200 and not device_hold.is_held(5)
        assert count_waiting_pins({"101": "h", "102": "h"}, _state(sqlite_db, 5)) == 2

    def test_mb2000_incomplete_invalidates_and_keeps_the_recorded_finger_sets(
            self, sqlite_db, monkeypatch, tmp_path):
        from app.core.device_sync import count_waiting_pins
        term = _terminal()
        _own(sqlite_db, 8, ["30001", "30002"])
        with sqlite_db.get_conn() as conn:
            conn.execute("UPDATE device_sync_state SET pushed_finger_ids='0,3' WHERE pin='30001'")
            conn.commit()
        wiz, worker, drv = _mb_setup(monkeypatch, tmp_path, term)
        worker.no_answer = {"erase_delete_users"}      # the delete ran, its answer was lost
        try:
            _, pv = wiz.preview(8)
            wiz.start(8, _mb_body(pv["previewId"]), verify_password=_pw_ok)
        finally:
            drv.disconnect()
        assert wiz.status()["run"]["state"] == "INCOMPLETE"
        assert _state(sqlite_db, 8) == {"30001": ("", False), "30002": ("", False)}
        with sqlite_db.get_conn() as conn:
            fingers = conn.execute("SELECT pushed_finger_ids FROM device_sync_state "
                                   "WHERE device_id=8 AND pin='30001'").fetchone()[0]
        assert fingers == "0,3", "an unverified erase never claims the fingers are known empty"
        wiz.refill(8, _refill_body(), verify_password=_pw_ok)
        assert count_waiting_pins({"30001": "h", "30002": "h"}, _state(sqlite_db, 8)) == 2

    def test_a_crash_after_the_erase_started_invalidates_too(self, sqlite_db, monkeypatch,
                                                             tmp_path):
        _own(sqlite_db, 5, ["101"])
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)

        def _boom(*a, **k):
            raise RuntimeError("a bug")

        monkeypatch.setattr(wiz, "_verify", _boom)
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "INCOMPLETE" and "UNEXPECTED" in run["error"]
        assert _state(sqlite_db, 5) == {"101": ("", False)} and device_hold.is_held(5)

    def test_a_hold_left_by_a_restart_mid_run_refills_every_pin(self, sqlite_db, monkeypatch,
                                                               tmp_path):
        from app.core.device_sync import count_waiting_pins
        _own(sqlite_db, 5, ["101", "102"])
        device_hold.hold(5, reason="erase", run_id="crashed-mid-run")
        device_hold.reset_for_tests()
        device_hold.load()                              # Access restarted: no run record
        wiz, worker, _p, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        assert wiz.status()["run"] is None
        status, out = wiz.refill(5, _refill_body(), verify_password=_pw_ok)
        assert status == 200 and not device_hold.is_held(5)
        assert count_waiting_pins({"101": "h", "102": "h"}, _state(sqlite_db, 5)) == 2
        assert app._ultra_engine._sync_scheduler.forced == [5]
        assert worker.full_sync_requests == ["erase-refill"]

    def test_refill_keeps_the_hold_when_the_records_cannot_be_reset(self, sqlite_db, monkeypatch,
                                                                    tmp_path):
        device_hold.hold(5, reason="erase", run_id="r")
        wiz, worker, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)

        def _fail(**k):
            raise RuntimeError("database is locked")

        monkeypatch.setattr(dbmod, "invalidate_device_records", _fail)
        status, out = wiz.refill(5, _refill_body(), verify_password=_pw_ok)
        assert status == 500 and out["code"] == "RECORDS_NOT_RESET"
        assert device_hold.is_held(5) and worker.full_sync_requests == []


class TestTheLeaseIsCheckedAtEveryWrite:
    """Finding 2: the lease and the handover freeze were checked at start() only."""

    def _reader(self):
        lg.install(lg.snapshot_from_assignment(
            {"gymUsesAssignments": True, "role": "READER", "drive": [], "release": []},
            source="server"))

    def test_a_lease_lost_mid_erase_stops_before_the_next_table(self, sqlite_db, monkeypatch,
                                                                tmp_path):
        _own(sqlite_db, 5, ["101", "102"])
        wiz, worker, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        panel.on_erase = lambda table: self._reader() if table == "templatev10" else None
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"], forget=True, refill="now"), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert [c[1] for c in panel.calls if c[0] == "erase"] == ["templatev10"]
        assert len(panel.tables["userauthorize"]) == 2 and len(panel.tables["user"]) == 2
        assert run["state"] == "INCOMPLETE" and "NOT_DRIVER" in run["error"]
        assert _state(sqlite_db, 5) == {"101": ("", False), "102": ("", False)}
        assert _removed(sqlite_db, 5) == set() and worker.full_sync_requests == []
        assert device_hold.is_held(5)

    def test_a_handover_freeze_mid_erase_stops_the_run(self, sqlite_db, monkeypatch, tmp_path):
        _own(sqlite_db, 5, ["101", "102"])
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)

        def _freeze(table):
            monkeypatch.setattr(lg, "writes_frozen", lambda did: int(did) == 5)

        panel.on_erase = _freeze
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"], forget=True, refill="hold"), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "INCOMPLETE" and "HANDOVER_IN_PROGRESS" in run["error"]
        assert [c[1] for c in panel.calls if c[0] == "erase"] == ["templatev10"]
        assert set(_state(sqlite_db, 5)) == {"101", "102"}

    def test_a_lease_lost_after_the_last_erase_forgets_nothing(self, sqlite_db, monkeypatch,
                                                              tmp_path):
        _own(sqlite_db, 5, ["101", "102"])
        wiz, worker, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        panel.on_erase = lambda table: self._reader() if table == "user" else None
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"], forget=True, refill="now"), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert panel.tables["user"] == []
        assert run["state"] == "INCOMPLETE" and "NOT_DRIVER" in run["error"]
        assert set(_state(sqlite_db, 5)) == {"101", "102"} and _removed(sqlite_db, 5) == set()
        assert worker.full_sync_requests == []

    def test_the_guard_runs_on_the_worker_thread_just_before_the_write(self, sqlite_db,
                                                                       monkeypatch, tmp_path):
        """request_run_sdk queues the call: a check made before queuing leaves a gap."""
        wiz, worker, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        real = worker.request_run_sdk

        def _lose_then_run(fn, *, label, timeout):
            if label == "erase_erase_templatev10":
                self._reader()                        # lost while the command sat queued
            return real(fn, label=label, timeout=timeout)

        worker.request_run_sdk = _lose_then_run
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert [c for c in panel.calls if c[0] == "erase"] == []
        run = wiz.status()["run"]
        assert run["state"] == "INCOMPLETE" and "NOT_DRIVER" in run["error"]

    def test_a_handover_release_waits_while_an_erase_runs(self, sqlite_db, monkeypatch, tmp_path):
        from app.core.v2.ownership import OwnershipSync
        wiz, _w, _p, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        app._erase_wizard = wiz
        wiz._spawn = lambda fn: None                  # the run is still going
        own = OwnershipSync(SimpleNamespace(app=app))
        assert own._worker_idle(5) is True
        _, pv = wiz.preview(5)
        assert wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)[0] == 202
        assert wiz.running_device() == 5
        assert own._worker_idle(5) is False and own._worker_idle(6) is True


class TestForgetKeepsWhatStaysOnTheTerminal:
    """Finding 3: forget retired an admin pin the wizard deliberately kept."""

    def test_the_kept_admins_records_are_not_retired(self, sqlite_db, monkeypatch, tmp_path):
        term = _terminal()                       # pin "1" is an admin (privilege 14)
        _own(sqlite_db, 8, ["1", "30001"])
        wiz, _w, drv = _mb_setup(monkeypatch, tmp_path, term)
        try:
            _, pv = wiz.preview(8)
            wiz.start(8, _mb_body(pv["previewId"], forget=True), verify_password=_pw_ok)
        finally:
            drv.disconnect()
        assert wiz.status()["run"]["state"] == "DONE"
        assert "1" in term.users and ("1", 0) in term.fingers
        assert set(_state(sqlite_db, 8)) == {"1"}, "the admin's record stays, untouched"
        assert _state(sqlite_db, 8)["1"] == ("h", True)
        assert _removed(sqlite_db, 8) == {"30001"}

    def test_retire_leaves_every_row_of_a_kept_pin(self, sqlite_db):
        _own(sqlite_db, 3, ["1", "2"])
        sqlite_db.record_push_intents(device_id=3, rows=[("1", "A", "", "h1"), ("2", "B", "", "h2")],
                                      protocol="ZK_STANDALONE")
        out = sqlite_db.retire_device_records(device_id=3, keep_pins=["1"])
        assert out["removals_logged"] == 1
        with sqlite_db.get_conn() as conn:
            left = {t: {r[0] for r in conn.execute(f"SELECT pin FROM {t} WHERE device_id=3")}
                    for t in ("device_sync_state", "device_push_intent")}
        assert left == {"device_sync_state": {"1"}, "device_push_intent": {"1"}}
        assert _removed(sqlite_db, 3) == {"2"}


class TestC3UsersNeedsRightsAndFingers:
    """Finding 4: erasing the C3 ``user`` table alone left the old pins' rights and fingers."""

    @pytest.mark.parametrize("tables,forget", [
        (["user"], True), (["user"], False), (["user", "userauthorize"], True),
        (["user", "templatev10"], False)])
    def test_user_without_every_readable_rights_and_finger_table_is_refused(
            self, sqlite_db, monkeypatch, tmp_path, tables, forget):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        panel.calls.clear()                       # step 1's own reads (lane 1c) are not the point
        status, out = wiz.start(5, _body(pv["previewId"], tables=tables, forget=forget),
                                verify_password=_pw_ok)
        assert status == 400 and out["code"] == "USER_NEEDS_RIGHTS_AND_FINGERS"
        assert set(out["required"]) == {"userauthorize", "templatev10"}
        assert [c for c in panel.calls if c[0] != "count"] == []

    def test_an_unreadable_table_is_not_required(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)   # "template" absent
        _, pv = wiz.preview(5)
        status, _ = wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert status == 202 and wiz.status()["run"]["state"] == "DONE"


class TestUnknownFaces:
    """Finding 5: an unreadable face counter was read as 0."""

    def test_an_unreadable_face_count_needs_the_loss_accepted(self, sqlite_db, monkeypatch,
                                                              tmp_path):
        term = _terminal()
        term.faces = 3
        real = term.GetDeviceStatus
        term.GetDeviceStatus = lambda m, idx, box: False if int(idx) == 21 else real(m, idx, box)
        wiz, _w, drv = _mb_setup(monkeypatch, tmp_path, term)
        try:
            _, pv = wiz.preview(8)
            assert pv["extra"].get("faces") is None
            status, out = wiz.start(8, _mb_body(pv["previewId"]), verify_password=_pw_ok)
            assert status == 409 and out["code"] == "FACES_UNKNOWN" and len(term.users) == 4
            _, pv = wiz.preview(8)
            status, _ = wiz.start(8, _mb_body(pv["previewId"], acceptFaceLoss=True),
                                  verify_password=_pw_ok)
        finally:
            drv.disconnect()
        assert status == 202 and wiz.status()["run"]["acceptFaceLoss"] is True


class TestRefillPinScheme:
    """Finding 6: Refill had no pin-scheme interlock."""

    def _held(self, monkeypatch, tmp_path, sqlite_db):
        wiz, worker, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"], refill="hold"), verify_password=_pw_ok)
        assert device_hold.is_held(5)
        return wiz, worker

    def test_refill_needs_the_scheme_the_page_showed(self, sqlite_db, monkeypatch, tmp_path):
        wiz, worker = self._held(monkeypatch, tmp_path, sqlite_db)
        status, out = wiz.refill(5, {"password": "pw"}, verify_password=_pw_ok)
        assert status == 400 and out["code"] == "PIN_SCHEME_REQUIRED" and device_hold.is_held(5)

    def test_a_scheme_that_moved_since_the_page_read_it_is_refused(self, sqlite_db, monkeypatch,
                                                                   tmp_path):
        wiz, worker = self._held(monkeypatch, tmp_path, sqlite_db)
        monkeypatch.setattr(dbmod, "get_device_pin_scheme", lambda did: "MEMBERSHIP")
        status, out = wiz.refill(5, _refill_body("ACCOUNT"), verify_password=_pw_ok)
        assert status == 409 and out["code"] == "PIN_SCHEME_CHANGED"
        assert out["pinScheme"] == "MEMBERSHIP"
        assert device_hold.is_held(5) and worker.full_sync_requests == []
        status, out = wiz.refill(5, _refill_body("MEMBERSHIP"), verify_password=_pw_ok)
        assert status == 200 and out["pinScheme"] == "MEMBERSHIP"

    def test_an_unreadable_scheme_refuses_the_refill(self, sqlite_db, monkeypatch, tmp_path):
        wiz, worker = self._held(monkeypatch, tmp_path, sqlite_db)

        def _broken(did):
            raise RuntimeError("database is locked")

        monkeypatch.setattr(dbmod, "get_device_pin_scheme", _broken)
        status, out = wiz.refill(5, _refill_body(None), verify_password=_pw_ok)
        assert status == 503 and out["code"] == "PIN_SCHEME_UNREADABLE" and device_hold.is_held(5)

    @pytest.mark.parametrize("refill", ["now", "auto"])
    def test_a_scheme_switched_during_the_run_keeps_the_hold(self, sqlite_db, monkeypatch,
                                                             tmp_path, refill):
        wiz, worker, panel, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        panel.on_erase = lambda table: monkeypatch.setattr(dbmod, "get_device_pin_scheme",
                                                           lambda did: "ACCOUNT")
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"], refill=refill), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "DONE" and run["holdKept"] is True
        assert device_hold.is_held(5) and worker.full_sync_requests == []
        assert any(str(s.get("note", "")).startswith("PIN_SCHEME_CHANGED") for s in run["steps"])


class TestEveryReleaseForcesTheScheduler:
    """Finding 7: a FAILED or backup-only run released the hold without force_resync."""

    def test_a_failed_run(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, panel, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        panel.short_read = {"user"}
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "FAILED" and not device_hold.is_held(5)
        assert app._ultra_engine._sync_scheduler.forced == [5]

    def test_a_backup_only_run(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, _p, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"], backupOnly=True), verify_password=_pw_ok)
        assert app._ultra_engine._sync_scheduler.forced == [5]


class TestDirectWritesRefuseAHeldTurnstile:
    """Finding 8: users/push and users/delete opened a second PullSDK session on a held panel."""

    @pytest.mark.parametrize("handler", ["_handle_device_users_push", "_handle_device_users_delete"])
    @pytest.mark.parametrize("why", ["hold", "frozen"])
    def test_refused_before_any_connect(self, sqlite_db, monkeypatch, handler, why):
        import app.api.local_access_api_v2 as la2
        connects = []
        monkeypatch.setattr(la2, "_connect_device", lambda ctx, did: connects.append(did) or (
            None, "should not connect"))
        monkeypatch.setattr(la2, "_unsupported_for_protocol", lambda *a, **k: False)
        if why == "hold":
            device_hold.hold(5, reason="erase", run_id="r")
        else:
            monkeypatch.setattr(lg, "writes_frozen", lambda did: int(did) == 5)
        ctx = _Ctx(SimpleNamespace(), 5, {"pin": "101"})
        getattr(la2, handler)(ctx)
        assert ctx.sent[0] == 409 and connects == []
        assert ctx.sent[1]["code"] == ("DEVICE_ON_HOLD" if why == "hold" else "HANDOVER_IN_PROGRESS")


class _Recording:
    """Proxy over the real MB2000 driver: records each call's ``timeout_sec``."""

    def __init__(self, drv, log):
        self._drv, self._log = drv, log

    def __getattr__(self, name):
        target = getattr(self._drv, name)
        if not callable(target):
            return target

        def _call(*a, **k):
            self._log.append((name, k.get("timeout_sec")))
            return target(*a, **k)
        return _call


class TestMb2000Commands:
    """Finding 9: driver timeouts left at the 10 s default; a failed delete chunk went on."""

    def test_every_driver_call_has_a_timeout_inside_the_command_budget(self, sqlite_db,
                                                                       monkeypatch, tmp_path):
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
            wiz.start(8, _mb_body(pv["previewId"]), verify_password=_pw_ok)
        finally:
            drv.disconnect()
        assert wiz.status()["run"]["state"] == "DONE"
        seen = {name for (name, _t), _b in budgets}
        assert {"read_device_status", "list_device_users", "read_user_templates",
                "delete_users"} <= seen
        for (name, t), budget in budgets:
            assert t is not None and 0 < t < budget, (name, t, budget)

    def test_a_failed_delete_chunk_stops_the_erase(self, sqlite_db, monkeypatch, tmp_path):
        import app.core.erase_wizard as ew
        monkeypatch.setattr(ew, "MB_DELETE_PINS_PER_CALL", 1)
        term = _terminal()
        wiz, worker, drv = _mb_setup(monkeypatch, tmp_path, term)
        deletes: List[list] = []
        real_drv = drv

        class _Failing:
            def __getattr__(self, name):
                return getattr(real_drv, name)

            def delete_users(self, pins, **k):
                deletes.append(list(pins))
                return {"ok": False, "deleted": 0, "failed": len(pins), "failed_pins": list(pins),
                        "errors": ["timeout"]}

        worker.drv = _Failing()
        try:
            _, pv = wiz.preview(8)
            wiz.start(8, _mb_body(pv["previewId"]), verify_password=_pw_ok)
        finally:
            drv.disconnect()
        run = wiz.status()["run"]
        assert len(deletes) == 1, "the first failed chunk stops the erase"
        assert run["state"] == "INCOMPLETE"
        erase_step = [s for s in run["steps"] if s["step"] == "erase"][0]
        assert erase_step["uncertain"] is True


class TestBackupRedactsPasswords:
    """Finding 12: the C3 backup read the ``user`` table's Password values in plain JSON."""

    def test_c3_password_values_are_not_written(self, sqlite_db, monkeypatch, tmp_path):
        panel = _panel()
        panel.tables["user"] = [{"Pin": "101", "CardNo": "1001", "Password": "1234"},
                                {"Pin": "102", "CardNo": "1002", "password": ""}]
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=panel)
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        raw = Path(run["backup"]["path"]).read_text(encoding="utf-8")
        assert "1234" not in raw
        data = json.loads(raw)
        assert data["rows"]["user"][0]["Password"] == ""
        assert data["redacted"] == {"user.Password": 1}


class TestMb2000UsersEraseForgets:
    """Finding 13: "keep" after an MB2000 users erase was allowed on the server."""

    def test_keep_is_refused(self, sqlite_db, monkeypatch, tmp_path):
        term = _terminal()
        wiz, _w, drv = _mb_setup(monkeypatch, tmp_path, term)
        try:
            _, pv = wiz.preview(8)
            status, out = wiz.start(8, _mb_body(pv["previewId"], forget=False),
                                    verify_password=_pw_ok)
        finally:
            drv.disconnect()
        assert status == 400 and out["code"] == "USERS_ERASE_NEEDS_FORGET" and len(term.users) == 4


class TestRefillWhileTheHoldsAreUnknown:
    """Finding 10 (the wizard side): while the start-up hold load has failed, every turnstile
    reads as held -- Refill must not reset and release one that never was."""

    def test_refill_is_refused(self, sqlite_db, monkeypatch, tmp_path):
        wiz, worker, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)

        def _broken():
            raise RuntimeError("database is locked")

        monkeypatch.setattr(dbmod, "list_device_write_holds", _broken)
        with pytest.raises(RuntimeError):
            device_hold.load()
        assert device_hold.is_held(5)
        status, out = wiz.refill(5, _refill_body(), verify_password=_pw_ok)
        assert status == 503 and out["code"] == "HOLDS_UNKNOWN" and worker.full_sync_requests == []
        assert wiz.holds_state()["loadFailed"] is True


# ─────────────────────────── review round 2 (2026-09-27): each finding pinned ───────────────────────────

class _BlockingWorker(FakeWorker):
    """Blocks the FIRST erase command until ``go`` is set (a run is mid-erase, its hold set)."""

    def __init__(self, drv, **kw):
        super().__init__(drv, **kw)
        self.reached = threading.Event()
        self.go = threading.Event()

    def request_run_sdk(self, fn, *, label, timeout):
        if label.startswith("erase_erase_") and not self.go.is_set():
            self.reached.set()
            self.go.wait(20.0)
        return super().request_run_sdk(fn, label=label, timeout=timeout)


def _threaded_wizard(monkeypatch, tmp_path, worker):
    app = _app({5: worker})
    _devices(monkeypatch, _device())
    threads: List[threading.Thread] = []

    def _spawn(fn):
        t = threading.Thread(target=fn, daemon=True)
        threads.append(t)
        t.start()

    wiz = EraseWizard(app, backup_root=tmp_path / "b", spawn=_spawn, sleep=lambda s: None)
    return wiz, app, threads


class TestRefillAndARunNeverOverlap:
    """R2-1: Refill checked for a running erase before its password round trip only, so a run
    started meanwhile had its hold released and a pass requested under it."""

    def test_no_erase_starts_while_a_refill_checks_its_password(self, sqlite_db, monkeypatch,
                                                                 tmp_path):
        panel = _panel()
        worker = _BlockingWorker(panel)
        worker.go.set()
        wiz, app, threads = _threaded_wizard(monkeypatch, tmp_path, worker)
        _, pv = wiz.preview(5)
        assert wiz.start(5, _body(pv["previewId"], refill="hold"), verify_password=_pw_ok)[0] == 202
        threads[-1].join(10)
        assert wiz.status()["run"]["state"] == "DONE" and device_hold.is_held(5)
        _, pv2 = wiz.preview(5)
        seen = {}

        def _slow_password(_pw):
            seen["start"] = wiz.start(5, _body(pv2["previewId"], refill="hold"),
                                      verify_password=_pw_ok)
            return GOOD

        status, out = wiz.refill(5, _refill_body(), verify_password=_slow_password)
        assert seen["start"][0] == 409 and seen["start"][1]["code"] == "REFILL_IN_PROGRESS"
        assert status == 200 and not device_hold.is_held(5)
        assert wiz.status()["running"] is False
        # The mark is cleared: the next erase may start.
        _, pv3 = wiz.preview(5)
        assert wiz.start(5, _body(pv3["previewId"], refill="hold"), verify_password=_pw_ok)[0] == 202
        threads[-1].join(10)
        assert device_hold.is_held(5)

    def test_a_run_that_began_before_the_mark_is_seen_after_the_password(self, sqlite_db,
                                                                        monkeypatch, tmp_path):
        """A run the mark could not stop (it began first) is caught by the re-check."""
        panel = _panel()
        worker = _BlockingWorker(panel)
        wiz, app, threads = _threaded_wizard(monkeypatch, tmp_path, worker)
        device_hold.hold(5, reason="erase", run_id="earlier")
        _, pv = wiz.preview(5)

        def _password_while_a_run_starts(_pw):
            with wiz._lock:                    # the run slipped in: bypass the mark
                wiz._refilling.discard(5)
            assert wiz.start(5, _body(pv["previewId"], refill="hold"),
                             verify_password=_pw_ok)[0] == 202
            assert worker.reached.wait(10)
            return GOOD

        try:
            status, out = wiz.refill(5, _refill_body(), verify_password=_password_while_a_run_starts)
            assert status == 409 and out["code"] in ("RUN_IN_PROGRESS", "HOLD_CHANGED")
            assert device_hold.is_held(5) and worker.full_sync_requests == []
            assert app._ultra_engine._sync_scheduler.forced == []
        finally:
            worker.go.set()
            for t in threads:
                t.join(10)
        run = wiz.status()["run"]
        assert run["state"] == "DONE" and run["holdKept"] is True and device_hold.is_held(5)

    def test_a_hold_replaced_during_the_password_check_is_not_released(self, sqlite_db,
                                                                      monkeypatch, tmp_path):
        wiz, worker, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        device_hold.hold(5, reason="erase", run_id="first")

        def _password(_pw):
            device_hold.hold(5, reason="erase", run_id="second")
            return GOOD

        status, out = wiz.refill(5, _refill_body(), verify_password=_password)
        assert status == 409 and out["code"] == "HOLD_CHANGED" and device_hold.is_held(5)
        assert worker.full_sync_requests == []


class TestTheResetsClearTheRetryBackoff:
    """R2-2: fail_streak and last_attempt_hash survived every reset of the wizard, so a pin the
    erase removed but that was in retry backoff stayed off the terminal for up to 6 h."""

    def _backoff(self, db, did, pin, attempt_hash):
        from app.core.utils import now_iso
        with db.get_conn() as conn:
            conn.execute("UPDATE device_sync_state SET desired_hash='', last_ok=0, fail_streak=6, "
                         "last_attempt_hash=?, updated_at=? WHERE device_id=? AND pin=?",
                         (attempt_hash, now_iso(), did, pin))
            conn.commit()

    def test_mb2000_incomplete_then_refill_pushes_the_backoff_pin(self, sqlite_db, monkeypatch,
                                                                  tmp_path):
        from app.core.ultra_engine import UltraDeviceWorker
        term = _terminal()
        _own(sqlite_db, 8, ["30001", "30002"])
        self._backoff(sqlite_db, 8, "30001", "H30001")
        wiz, worker, drv = _mb_setup(monkeypatch, tmp_path, term)
        worker.no_answer = {"erase_delete_users"}
        try:
            _, pv = wiz.preview(8)
            wiz.start(8, _mb_body(pv["previewId"]), verify_password=_pw_ok)
        finally:
            drv.disconnect()
        assert wiz.status()["run"]["state"] == "INCOMPLETE"
        assert wiz.refill(8, _refill_body(), verify_password=_pw_ok)[0] == 200
        rs = sqlite_db.list_device_sync_retry_state(device_id=8)["30001"]
        assert rs[2] == 0 and rs[3] is None
        fake = SimpleNamespace(_device_id=8, _prefix="[t]", _tel_wid="t")
        to_push, _ = UltraDeviceWorker._standalone_pins_needing_push(
            fake, [{"pin": "30001"}, {"pin": "30002"}], {"30001": "H30001", "30002": "H30002"})
        assert {u["pin"] for u in to_push} == {"30001", "30002"}

    def test_c3_keep_clears_the_backoff(self, sqlite_db, monkeypatch, tmp_path):
        _own(sqlite_db, 5, ["101", "102"])
        self._backoff(sqlite_db, 5, "101", "H101")
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"], forget=False, refill="now"), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "DONE"
        _h, ok, streak, attempt, _seen = sqlite_db.list_device_sync_retry_state(device_id=5)["101"]
        assert (ok, streak, attempt) == (False, 0, None)


class TestAHeldTurnstileIsNotHandedOver:
    """R2-3: the hold lives on this PC only; releasing a held turnstile to another PC let that
    PC refill it under its own recorded scheme."""

    def test_the_release_waits_for_refill(self, sqlite_db, monkeypatch, tmp_path):
        from app.core.v2.ownership import OwnershipSync
        wiz, _w, _p, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        app._erase_wizard = wiz
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"], refill="hold"), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "DONE" and device_hold.is_held(5)
        own = OwnershipSync(SimpleNamespace(app=app))
        assert own._worker_idle(5) is False and own._worker_idle(6) is True
        assert wiz.refill(5, _refill_body(), verify_password=_pw_ok)[0] == 200
        assert own._worker_idle(5) is True


class TestNoRunWhileTheHoldsAreUnknown:
    """R2-4: a run while the start-up hold load had failed never released the hold it wrote."""

    def test_start_is_refused(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        monkeypatch.setattr(device_hold, "_load_failed", True)
        status, out = wiz.start(5, _body(pv["previewId"], backupOnly=True), verify_password=_pw_ok)
        assert status == 503 and out["code"] == "HOLDS_UNKNOWN"
        assert sqlite_db.list_device_write_holds() == {}


class TestTheWorkerMustBeOnTheRecordedAddress:
    """Round 2: a worker keeps its socket to the OLD address after an IP edit (up to the 30-min
    connection refresh). The wizard's identity was the database's only, so it could erase the
    turnstile at the old address -- another turnstile."""

    def test_preview_and_start_refuse_a_worker_on_another_address(self, sqlite_db, monkeypatch,
                                                                 tmp_path):
        wiz, worker, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        worker._connected_addr = ("192.168.0.203", 4370)      # still on the old socket
        status, out = wiz.preview(5)
        assert status == 409 and out["code"] == "ADDRESS_CHANGED" and panel.calls == []
        worker._connected_addr = ("192.168.0.202", 4370)
        _, pv = wiz.preview(5)
        panel.calls.clear()                       # step 1's own reads (lane 1c) are not the point
        worker._connected_addr = ("192.168.0.203", 4370)
        status, out = wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert status == 409 and out["code"] == "ADDRESS_CHANGED"
        assert [c for c in panel.calls if c[0] != "count"] == []

    def test_an_unknown_address_is_refused(self, sqlite_db, monkeypatch, tmp_path):
        wiz, worker, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        worker._connected_addr = None
        status, out = wiz.preview(5)
        assert status == 409 and out["code"] == "ADDRESS_UNKNOWN"

    def test_a_reconnect_to_another_address_mid_run_stops_before_the_next_write(
            self, sqlite_db, monkeypatch, tmp_path):
        _own(sqlite_db, 5, ["101"])
        wiz, worker, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)

        def _moved(table):
            worker._connected_addr = ("192.168.0.203", 4370)

        panel.on_erase = _moved
        _, pv = wiz.preview(5)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert [c[1] for c in panel.calls if c[0] == "erase"] == ["templatev10"]
        assert run["state"] == "INCOMPLETE" and "ADDRESS_CHANGED" in run["error"]
        assert device_hold.is_held(5)

    def test_the_address_is_checked_before_the_backup(self, sqlite_db, monkeypatch, tmp_path):
        wiz, worker, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _, pv = wiz.preview(5)
        panel.calls.clear()                       # step 1's own reads (lane 1c) are not the point
        real = wiz._wait_idle

        def _idle_then_moved(did):
            w = real(did)
            w._connected_addr = ("192.168.0.203", 4370)
            return w

        monkeypatch.setattr(wiz, "_wait_idle", _idle_then_moved)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "ADDRESS_CHANGED" in run["error"]
        assert [c for c in panel.calls if c[0] in ("read", "erase")] == []
        assert not device_hold.is_held(5)

    def test_the_worker_records_the_address_it_connected_to(self, monkeypatch):
        import queue as _queue
        import app.core.ultra_engine as ue

        class _Drv:
            ip, port = "10.0.0.9", 4370

            def connect(self):
                return True

            def disconnect(self):
                pass

        monkeypatch.setattr(ue, "get_driver", lambda device_payload=None, logger=None: _Drv())
        monkeypatch.setattr(ue._lease_gate, "require_device", lambda did: None)
        w = ue.UltraDeviceWorker(device={"id": 5, "name": "E", "ipAddress": "10.0.0.9"}, settings={},
                                 popup_q=_queue.Queue(), history_q=_queue.Queue(),
                                 stop_event=threading.Event())
        for name in ("_note_user_count_at_connect", "_maybe_discipline_device_clock"):
            monkeypatch.setattr(w, name, lambda: None)
        assert w._connected_addr is None
        w._connect()
        assert w._connected and w._connected_addr == ("10.0.0.9", 4370)
        w._disconnect()
        assert w._connected_addr is None


# ─────────────────────────── review round 3 (2026-09-27) ───────────────────────────

def test_a_run_thread_that_cannot_start_leaves_no_run_behind(sqlite_db, monkeypatch, tmp_path):
    """Round 3: start() set _running and then spawned outside any try -- a spawn that raised
    (the 32-bit build's "can't start new thread") left the wizard RUNNING with no thread: no
    erase, no Refill, and the turnstile's handover waiting, until a restart."""
    wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)

    def _boom(fn):
        raise RuntimeError("can't start new thread")

    wiz._spawn = _boom
    _, pv = wiz.preview(5)
    panel.calls.clear()                           # step 1's own reads (lane 1c) are not the point
    status, out = wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
    assert status == 503 and out["code"] == "RUN_NOT_STARTED"
    assert wiz.status()["running"] is False and wiz.running_device() is None
    assert wiz.status()["run"]["state"] == "FAILED" and not device_hold.is_held(5)
    assert [c for c in panel.calls if c[0] != "count"] == []
    wiz._spawn = lambda fn: fn()
    _, pv2 = wiz.preview(5)
    assert wiz.start(5, _body(pv2["previewId"]), verify_password=_pw_ok)[0] == 202

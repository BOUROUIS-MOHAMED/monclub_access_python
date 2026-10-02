"""The device side of the removal requests (ULTRA merge plan 3, Task 5): D11 erases every
fingerprint, D13 removes only what MonClub wrote. Fake C3 panel, fake MB2000 behind the real
zkemkeeper driver, a real temp SQLite for the records; nothing reaches a device."""
from __future__ import annotations

from typing import Dict, List

import pytest

import app.core.db as dbmod
from app.core import removal_executors as rx
from tests.test_erase_wizard import WizardTerminal
from tests.test_standalone_incremental_sync import _make_driver


@pytest.fixture
def sqlite_db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "removal.db"), raising=False)
    dbmod.init_db()
    yield dbmod
    dbmod._shutdown_db_writer_for_tests()


class FakePanel:
    """A C3 panel's tables behind the PullSDKDevice calls the executors use."""

    def __init__(self, tables: Dict[str, List[Dict[str, str]]]):
        self.tables = {k: list(v) for k, v in tables.items()}
        self.calls: List[tuple] = []
        self.refuse_erase: set = set()
        self.refuse_delete: set = set()
        self.refuse_bulk: set = set()          # tables that refuse a call naming more than one pin

    def count_table_strict(self, *, table):
        self.calls.append(("count", table))
        if table not in self.tables:
            raise RuntimeError(f"GetDeviceDataCount FAILED table={table} rc=-1")
        return len(self.tables[table])

    def erase_table(self, *, table):
        self.calls.append(("erase", table))
        if table not in self.refuse_erase:
            self.tables[table] = []
        return 0

    def delete_table_rows(self, *, table, data="", options=""):
        self.calls.append(("delete", table, data))
        if table in self.refuse_delete or table not in self.tables:
            return -1
        if table in self.refuse_bulk and data.count("Pin=") > 1:
            return -1
        pins = {line[4:] for line in data.split("\r\n") if line.startswith("Pin=")}
        self.tables[table] = [r for r in self.tables[table] if r.get("Pin") not in pins]
        return 0

    def read_table_strict(self, *, table, fields="*"):
        self.calls.append(("read", table))
        return list(self.tables[table])


class FakeWorker:
    def __init__(self, drv):
        self.drv = drv

    def request_run_sdk(self, fn, *, label, timeout):
        try:
            return {"ok": True, "result": fn(self.drv), "error": ""}
        except Exception as exc:
            return {"ok": False, "result": None, "error": str(exc)}


def _run(drv, guard=lambda: None):
    return rx.Runway(FakeWorker(drv), guard)


def _panel():
    return FakePanel({
        "user": [{"Pin": "101", "CardNo": "1001"}, {"Pin": "102", "CardNo": "1002"},
                 {"Pin": "777", "CardNo": "7777"}],
        "userauthorize": [{"Pin": "101"}, {"Pin": "102"}, {"Pin": "777"}],
        "templatev10": [{"Pin": "101", "FingerID": "0"}, {"Pin": "777", "FingerID": "1"}],
        "template": [{"Pin": "102", "FingerID": "2"}],
    })


def _own(db, did, pins):
    for p in pins:
        db.save_device_sync_state(device_id=did, pin=p, desired_hash="h", ok=True, error=None)


def _rows(db, did):
    with db.get_conn() as conn:
        return {str(r[0]): (r[1], int(r[2])) for r in conn.execute(
            "SELECT pin, desired_hash, last_ok FROM device_sync_state WHERE device_id=?", (did,))}


# ------------------------------------------------------------------ D11 on a C3
def test_d11_erases_both_template_tables_and_nothing_else():
    panel = _panel()
    code, detail = rx.erase_fingerprints(_run(panel), rx.PROTO_PULLSDK, device_id=5)
    assert (code, detail) == ("ERASED", "templatev10=2 template=1")
    assert panel.tables["templatev10"] == [] and panel.tables["template"] == []
    assert len(panel.tables["user"]) == 3 and len(panel.tables["userauthorize"]) == 3


def test_d11_reads_a_missing_v9_table_as_absent():
    panel = _panel()
    del panel.tables["template"]
    assert rx.erase_fingerprints(_run(panel), rx.PROTO_PULLSDK, device_id=5) == \
        ("ERASED", "templatev10=2 template=absent")
    assert ("erase", "template") not in panel.calls


def test_d11_stops_when_templatev10_does_not_answer():
    panel = _panel()
    del panel.tables["templatev10"]
    with pytest.raises(rx.StepFailed) as exc:
        rx.erase_fingerprints(_run(panel), rx.PROTO_PULLSDK, device_id=5)
    assert exc.value.code == "UNREADABLE"
    assert not [c for c in panel.calls if c[0] == "erase"]


def test_d11_an_erase_that_leaves_rows_is_not_done():
    panel = _panel()
    panel.refuse_erase.add("templatev10")
    with pytest.raises(rx.StepFailed) as exc:
        rx.erase_fingerprints(_run(panel), rx.PROTO_PULLSDK, device_id=5)
    assert exc.value.code == "NOT_ERASED"


def test_a_guard_that_refuses_on_the_worker_thread_stops_before_the_write():
    panel = _panel()
    answers = iter([None, ("CANCELLED", "the request left the device payload")])
    run = _run(panel, guard=lambda: next(answers))
    with pytest.raises(rx.StepFailed) as exc:
        rx.erase_fingerprints(run, rx.PROTO_PULLSDK, device_id=5)
    assert exc.value.code == "CANCELLED"
    assert panel.tables["templatev10"] != []
    assert run.wrote is True           # queued: the runner treats the turnstile as possibly changed


def test_a_run_that_only_read_wrote_nothing():
    panel = _panel()
    del panel.tables["templatev10"]
    run = _run(panel)
    with pytest.raises(rx.StepFailed):
        rx.erase_fingerprints(run, rx.PROTO_PULLSDK, device_id=5)
    assert run.wrote is False


# ------------------------------------------------------------------ D11 on an MB2000
def _terminal():
    t = WizardTerminal()
    t.add("1", "Admin", "", fingers=(0,), privilege=14)
    t.add("30001", "Ali", "111", fingers=(0, 3))
    t.add("777", "Hand enrolled", "333", fingers=(2,))
    return t


def test_d11_on_an_mb2000_sweeps_every_member_and_keeps_the_admin(sqlite_db):
    term = _terminal()
    _own(sqlite_db, 8, ["1", "30001"])
    drv = _make_driver(term)
    try:
        code, detail = rx.erase_fingerprints(_run(drv), rx.PROTO_STANDALONE, device_id=8)
    finally:
        drv.disconnect()
    assert code == "ERASED" and detail == "fingerprints=3 swept=2 admins_kept=1"
    assert term.fingers == {("1", 0)}
    with sqlite_db.get_conn() as conn:
        rows = dict(conn.execute(
            "SELECT pin, pushed_finger_ids FROM device_sync_state WHERE device_id=8").fetchall())
    assert rows == {"1": None, "30001": ""}


def test_d11_on_an_mb2000_with_only_admin_fingers_sweeps_nothing(sqlite_db):
    term = WizardTerminal()
    term.add("1", "Admin", "", fingers=(0,), privilege=14)
    term.add("30001", "Ali", "111")
    drv = _make_driver(term)
    try:
        assert rx.erase_fingerprints(_run(drv), rx.PROTO_STANDALONE, device_id=8)[1] == \
            "fingerprints=0 swept=0 admins_kept=1"
    finally:
        drv.disconnect()
    assert not [c for c in term.calls if c[0] == "SSR_DelUserTmpExt"]


# ------------------------------------------------------------------ D13 on a C3
def test_d13_removes_only_the_pins_monclub_wrote(sqlite_db):
    panel = _panel()
    _own(sqlite_db, 5, ["101", "102"])
    code, detail = rx.remove_cards(_run(panel), rx.PROTO_PULLSDK, device_id=5)
    assert (code, detail) == ("REMOVED", "users=2 records=2")
    assert [r["Pin"] for r in panel.tables["user"]] == ["777"]
    assert [r["Pin"] for r in panel.tables["templatev10"]] == ["777"]
    assert _rows(sqlite_db, 5) == {}
    with sqlite_db.get_conn() as conn:
        logged = {r[0] for r in conn.execute("SELECT pin FROM v2_removal_log WHERE device_id=5")}
    assert logged == {"101", "102"}


def test_d13_keeps_the_row_of_a_pin_a_pass_rewrote_during_the_run(sqlite_db):
    panel = _panel()
    _own(sqlite_db, 5, ["101", "102"])
    real_read = panel.read_table_strict

    def read_after_a_pass(*, table, fields="*"):
        with sqlite_db.get_conn() as conn:     # a pass rewrote 102 after the delete (new stamp)
            conn.execute("UPDATE device_sync_state SET updated_at='2099-01-01 00:00:00' "
                         "WHERE device_id=5 AND pin='102'")
            conn.commit()
        return real_read(table=table, fields=fields)

    panel.read_table_strict = read_after_a_pass
    assert rx.remove_cards(_run(panel), rx.PROTO_PULLSDK, device_id=5) == ("REMOVED", "users=2 records=1")
    assert _rows(sqlite_db, 5) == {"102": ("h", 1)}      # kept: the runner then clears every hash


def test_d13_falls_back_to_one_pin_at_a_time_when_a_chunk_is_refused(sqlite_db):
    panel = _panel()
    panel.refuse_bulk.add("user")
    _own(sqlite_db, 5, ["101", "102"])
    assert rx.remove_cards(_run(panel), rx.PROTO_PULLSDK, device_id=5) == ("REMOVED", "users=2 records=2")
    assert [r["Pin"] for r in panel.tables["user"]] == ["777"]
    assert [c[2] for c in panel.calls if c[:2] == ("delete", "user")] == \
        ["Pin=101\r\nPin=102\r\n", "Pin=101\r\n", "Pin=102\r\n"]


def test_invalidate_hashes_keeps_ownership_and_resets_the_backoff(sqlite_db):
    _own(sqlite_db, 5, ["101", "102"])
    sqlite_db.save_device_sync_state(device_id=5, pin="102", desired_hash="h2", ok=False, error="x")
    before = rx.owned_rows(5)
    assert rx.invalidate_hashes(5) == 2
    assert _rows(sqlite_db, 5) == {"101": (None, 0), "102": (None, 0)}
    assert rx.owned_rows(5) == before                    # ownership and updated_at untouched
    with sqlite_db.get_conn() as conn:
        streaks = {r[0]: r[1] for r in conn.execute(
            "SELECT pin, fail_streak FROM device_sync_state WHERE device_id=5")}
    assert streaks == {"101": 0, "102": 0}


def test_d13_a_pin_still_on_the_panel_fails_and_forgets_nothing(sqlite_db):
    panel = _panel()
    panel.refuse_delete.add("user")
    _own(sqlite_db, 5, ["101"])
    with pytest.raises(rx.StepFailed) as exc:
        rx.remove_cards(_run(panel), rx.PROTO_PULLSDK, device_id=5)
    assert exc.value.code == "DELETE_FAILED"
    assert set(_rows(sqlite_db, 5)) == {"101"}


def test_d13_with_nothing_owned_touches_nothing(sqlite_db):
    panel = _panel()
    assert rx.remove_cards(_run(panel), rx.PROTO_PULLSDK, device_id=5) == ("REMOVED", "users=0 records=0")
    assert panel.calls == []


# ------------------------------------------------------------------ D13 on an MB2000
def test_d13_on_an_mb2000_never_deletes_an_admin_or_a_hand_added_user(sqlite_db):
    term = _terminal()
    _own(sqlite_db, 8, ["1", "30001", "40404"])          # 40404: owned, already gone
    drv = _make_driver(term)
    try:
        code, detail = rx.remove_cards(_run(drv), rx.PROTO_STANDALONE, device_id=8)
    finally:
        drv.disconnect()
    assert (code, detail) == ("REMOVED", "users=1 records=2")
    assert set(term.users) == {"1", "777"}
    assert set(_rows(sqlite_db, 8)) == {"1"}

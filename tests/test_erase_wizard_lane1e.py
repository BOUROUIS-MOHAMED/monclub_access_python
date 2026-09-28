"""Lane 1e (2026-09-28): the master review of lanes 1d and 2c -- the Erase wizard's last code points.

Guide §3.2h. Against the same fakes as tests/test_erase_wizard.py -- nothing reaches a device:
* C0  a hold kept because the pin scheme moved before any delete (``erase-scheme-moved``) records
      the scheme the terminal's pins were written under (``device_write_hold.pin_scheme``), and
      « Remplir » refuses it until the scheme recorded now is that one again -- after a restart too,
      when the run's own finish note is gone; the page reads the warning from the hold row;
* C0  the start-up release keeps (as ``erase-scheme-moved``) a hold still at ``erase-prep`` whose
      turnstile's scheme moved since the run began -- a power cut before the run saw the move;
* F7  a scheme-moved stop on a turnstile already held at ``erase-prep`` is made durable too;
* F8  the keep mark is written after the erase record, so a run cut before it keeps no mark;
* F5  a gym login the server refuses (its filter's 401 ``UNAUTHORIZED``) no longer reads as a
      wrong administrator password;
* nits: a TLS drop (SSLEOFError) reads as no internet, a certificate not yet valid or expired as
      "check this PC's date and time"; the lock screen's TLS refusal is French; a turnstile deleted
      during a run gets its own finish note.
"""
from __future__ import annotations

import json
import logging
import re
import sqlite3
import ssl
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests
import urllib3

import app.core.db as dbmod
import app.core.erase_wizard as ew
from app.core import device_hold
from tests.test_erase_wizard import (  # noqa: F401 -- fixtures are used by name
    _body, _device, _devices, _pw_ok, _setup_c3, erase_switch_on, refill_cache, sqlite_db,
)
from tests.test_erase_wizard_lane1b import _Resp, _real_api
from tests.test_erase_wizard_lane1c import _account, _preview, _run_dir, _staff_panel

# Before the autouse fixture replaces it (tests/test_erase_wizard.py::erase_switch_on).
_real_check_erase_switch = ew.check_erase_switch

REPO = Path(__file__).resolve().parents[1]


def _restart():
    """A restart of Access: the in-memory gate is gone, and the start-up load (app.py) releases
    the holds of runs that stopped before any delete."""
    device_hold.reset_for_tests()
    device_hold.load(release_unstarted=True)


def _hold_row(db, did):
    return (db.list_device_write_holds() or {}).get(did)


def _note(wiz):
    return [s for s in wiz.status()["run"]["steps"] if s["step"] == "finish"][0]["note"]


def _scheme(monkeypatch, value):
    monkeypatch.setattr(dbmod, "get_device_pin_scheme", lambda d: value)


def _signed_in(db, *listed):
    """This PC signed in to MonClub (a gym token) with the turnstiles ``listed`` in its list,
    written whole by a sync (lane 1g: the marker only a full device replace writes): only then
    does a missing device row mean "deleted in MonClub" (lane 1f, review C1)."""
    db.save_auth_token(email="gym@example.test", token="tok-lane1f")
    db._run_db_write_sync("test_device_list_whole",
                          lambda conn, profile: db._mark_device_list_replaced(conn))
    for did in listed:
        _device_row(db, did, "MEMBERSHIP")


def _device_row(db, did, scheme):
    """A ``sync_devices`` row, as the sync writes one (the start-up release reads this table)."""
    def _write(conn, profile):
        conn.execute("DELETE FROM sync_devices WHERE id=?", (int(did),))
        conn.execute("INSERT INTO sync_devices (id, name, pin_scheme) VALUES (?, ?, ?)",
                     (int(did), f"Door {did}", scheme))
    db._run_db_write_sync("test_device_row", _write)


def _moved_during_backup(monkeypatch, panel):
    """The cutover's switch to « Par personne » lands while the run reads its backup."""
    real = panel.read_table_strict

    def _read(*, table, fields="*"):
        _account(monkeypatch, 5, _device())
        return real(table=table, fields=fields)
    _read.real = real                                    # the panel's own read, to put back
    panel.read_table_strict = _read


def _held_scheme_moved(monkeypatch, tmp_path, db, panel=None):
    """Panel 5 on « Par abonnement », its erase stopped before any delete by a switch to
    « Par personne » during the backup: FAILED, the hold kept."""
    wiz, worker, panel, app = _setup_c3(monkeypatch, tmp_path, db, panel=panel)
    _scheme(monkeypatch, "MEMBERSHIP")
    pv = _preview(wiz, 5)
    _moved_during_backup(monkeypatch, panel)
    wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
    return wiz, worker, panel


def _refill(wiz, scheme):
    return wiz.refill(5, {"password": "pw", "expectedPinScheme": scheme}, verify_password=_pw_ok)


# ─────────────────────── C0: « Remplir » on a hold kept after a scheme move ───────────────────────

class TestRemplirOnASchemeMovedHold:

    def test_the_hold_row_records_the_scheme_the_terminal_holds(self, sqlite_db, monkeypatch,
                                                                tmp_path):
        wiz, _w, panel = _held_scheme_moved(monkeypatch, tmp_path, sqlite_db)
        assert wiz.status()["run"]["state"] == "FAILED"
        assert _note(wiz).startswith("HELD_SCHEME_MOVED:")
        assert not [c for c in panel.calls if c[0] == "erase"]
        row = _hold_row(sqlite_db, 5)
        assert row["reason"] == sqlite_db.HOLD_REASON_SCHEME_MOVED
        assert row["terminalScheme"] == "MEMBERSHIP", row

    def test_after_a_restart_remplir_is_refused_while_the_scheme_moved(self, sqlite_db,
                                                                       monkeypatch, tmp_path):
        """The finish note lived only in memory: after a restart the page offered « Remplir »
        and the route accepted it -- a full pass would write « Par personne » pins beside every
        « Par abonnement » pin still on the panel (master review of lane 1d, C0)."""
        wiz, worker, _p = _held_scheme_moved(monkeypatch, tmp_path, sqlite_db)
        _restart()
        requests_before = list(worker.full_sync_requests)
        status, out = _refill(wiz, "ACCOUNT")
        assert (status, out["code"]) == (409, "HELD_SCHEME_MOVED"), out
        assert out["terminalScheme"] == "MEMBERSHIP" and out["pinScheme"] == "ACCOUNT"
        assert "MEMBERSHIP" in out["error"] and "erase" in out["error"]
        assert device_hold.is_held(5)
        assert _hold_row(sqlite_db, 5)["reason"] == sqlite_db.HOLD_REASON_SCHEME_MOVED
        assert worker.full_sync_requests == requests_before, "no pass may be asked"

    def test_the_holds_list_carries_the_reason_and_both_schemes(self, sqlite_db, monkeypatch,
                                                                tmp_path):
        """What the page derives its warning from, after a restart (no run record then)."""
        wiz, _w, _p = _held_scheme_moved(monkeypatch, tmp_path, sqlite_db)
        _restart()
        wiz2 = ew.EraseWizard(wiz.app, backup_root=wiz.backup_root(), spawn=lambda fn: fn(),
                              sleep=lambda s: None)
        assert wiz2.status()["run"] is None
        item = [h for h in wiz2.holds() if h["deviceId"] == 5][0]
        assert item["reason"] == "erase-scheme-moved"
        assert item["pinScheme"] == "ACCOUNT" and item["terminalScheme"] == "MEMBERSHIP", item

    def test_with_the_scheme_set_back_remplir_releases_it(self, sqlite_db, monkeypatch, tmp_path):
        wiz, worker, _p = _held_scheme_moved(monkeypatch, tmp_path, sqlite_db)
        _restart()
        _devices(monkeypatch, _device())
        _scheme(monkeypatch, "MEMBERSHIP")                      # the owner set it back
        status, out = _refill(wiz, "MEMBERSHIP")
        assert status == 200, out
        assert not device_hold.is_held(5) and _hold_row(sqlite_db, 5) is None

    def test_a_second_run_cut_before_its_erase_record_does_not_hide_the_old_scheme(
            self, sqlite_db, monkeypatch, tmp_path):
        """The re-erase with « Attendre… » takes the row's run id over (its erase record needs
        it). Cut before that record, the terminal still holds every « Par abonnement » pin, while
        that second run started under « Par personne »: the row keeps the terminal's scheme."""
        wiz, _w, panel = _held_scheme_moved(monkeypatch, tmp_path, sqlite_db)
        first = _hold_row(sqlite_db, 5)["runId"]

        class _Killed(BaseException):
            pass

        def _killed(*a, **k):
            raise _Killed()
        monkeypatch.setattr(ew, "_begin_erase", _killed)
        pv = _preview(wiz, 5)
        assert pv["notRefilled"]["count"] == 2        # every old pin: not in the ACCOUNT roster
        with pytest.raises(_Killed):
            wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        _restart()
        row = _hold_row(sqlite_db, 5)
        assert row["runId"] != first and row["reason"] == sqlite_db.HOLD_REASON_SCHEME_MOVED
        assert row["terminalScheme"] == "MEMBERSHIP", row
        assert not [c for c in panel.calls if c[0] == "erase"]
        status, out = _refill(wiz, "ACCOUNT")
        assert (status, out["code"]) == (409, "HELD_SCHEME_MOVED"), out

    def test_a_second_run_that_erases_turns_it_into_a_normal_hold(self, sqlite_db, monkeypatch,
                                                                   tmp_path):
        """The recovery the page names: erase again with « Attendre… » -- its erase record moves
        the row to ``erase``, and « Remplir » under « Par personne » is then the normal one."""
        wiz, _w, panel = _held_scheme_moved(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "DONE", wiz.status()["run"]
        assert _hold_row(sqlite_db, 5)["reason"] == sqlite_db.HOLD_REASON_ERASE
        _restart()
        status, out = _refill(wiz, "ACCOUNT")
        assert status == 200, out

    def test_a_row_that_records_no_scheme_is_refused(self, sqlite_db, monkeypatch, tmp_path):
        """A row written before lane 1e has no terminal scheme: which pins the terminal holds
        cannot be told -- only an erase clears it."""
        db = sqlite_db
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, db)
        db.set_device_write_hold(device_id=5, reason=db.HOLD_REASON_ERASE_PREP, run_id="r0")
        db.keep_erase_hold_after_scheme_move(device_id=5, run_id="r0")
        device_hold.load()
        _scheme(monkeypatch, "MEMBERSHIP")
        status, out = _refill(wiz, "MEMBERSHIP")
        assert (status, out["code"]) == (409, "HELD_SCHEME_MOVED"), out
        assert out["terminalScheme"] is None
        assert device_hold.is_held(5)

    def test_the_cutover_hold_is_not_affected(self, sqlite_db, monkeypatch, tmp_path):
        """The night's own order: erased under « Par abonnement » with « Attendre… », switched to
        « Par personne », restarted, « Remplir » -- a row at ``erase`` whatever scheme it records."""
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _scheme(monkeypatch, "MEMBERSHIP")
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "DONE"
        row = _hold_row(sqlite_db, 5)
        assert row["reason"] == sqlite_db.HOLD_REASON_ERASE and row["terminalScheme"] == "MEMBERSHIP"
        _account(monkeypatch, 5, _device())
        _restart()
        status, out = _refill(wiz, "ACCOUNT")
        assert status == 200, out

    def test_a_later_hold_never_overwrites_the_recorded_scheme(self, sqlite_db):
        db = sqlite_db
        db.set_device_write_hold(device_id=5, reason=db.HOLD_REASON_ERASE_PREP, run_id="r1",
                                 pin_scheme="MEMBERSHIP")
        db.set_device_write_hold(device_id=5, reason=db.HOLD_REASON_ERASE_PREP, run_id="r2",
                                 pin_scheme="ACCOUNT")
        assert _hold_row(db, 5)["terminalScheme"] == "MEMBERSHIP"
        db.set_device_write_hold(device_id=6, reason=db.HOLD_REASON_ERASE_PREP, run_id="r3")
        db.set_device_write_hold(device_id=6, reason=db.HOLD_REASON_ERASE_PREP, run_id="r4",
                                 pin_scheme="ACCOUNT")
        assert _hold_row(db, 6)["terminalScheme"] is None, "even NULL is kept"


class TestTheHoldColumnMigration:

    def test_a_database_with_the_old_hold_table_gets_the_column(self, tmp_path, monkeypatch):
        """Upgrade path: the table created by lanes 1-1d (no ``pin_scheme``), a held row in it."""
        path = tmp_path / "old.db"
        con = sqlite3.connect(str(path))
        con.execute("CREATE TABLE device_write_hold (device_id INTEGER PRIMARY KEY, reason TEXT "
                    "NOT NULL, run_id TEXT, created_at TEXT NOT NULL)")
        con.execute("INSERT INTO device_write_hold VALUES (5, 'erase', 'r0', '2026-09-28 01:00:00')")
        con.commit()
        con.close()
        monkeypatch.setattr(dbmod, "_DB_PATH", str(path), raising=False)
        dbmod._close_thread_local_conn()
        device_hold.reset_for_tests()
        try:
            dbmod.init_db()
            with dbmod.get_conn() as conn:
                assert "pin_scheme" in dbmod._table_columns(conn, "device_write_hold")
            held = dbmod.list_device_write_holds()
            assert held[5]["reason"] == "erase" and held[5]["terminalScheme"] is None
            dbmod.set_device_write_hold(device_id=6, reason="erase-prep", run_id="r1",
                                        pin_scheme="ACCOUNT")
            assert dbmod.list_device_write_holds()[6]["terminalScheme"] == "ACCOUNT"
            _device_row(dbmod, 6, "ACCOUNT")                   # unchanged: released (lane 1f)
            assert device_hold.load(release_unstarted=True) == frozenset({5})
        finally:
            device_hold.reset_for_tests()
            dbmod._shutdown_db_writer_for_tests()


class TestTheStartUpKeepsAHoldWhoseSchemeMoved:
    """A run cut (a power cut, a kill) before it saw the scheme move: its row is still
    ``erase-prep``. Released at the start, the first pass would write the new scheme's pins beside
    every old one (the review's UNVERIFIED residual of lane 1d)."""

    def test_an_unstarted_hold_on_a_moved_scheme_is_kept(self, sqlite_db):
        db = sqlite_db
        _device_row(db, 5, "ACCOUNT")
        db.set_device_write_hold(device_id=5, reason=db.HOLD_REASON_ERASE_PREP, run_id="r-cut",
                                 pin_scheme="MEMBERSHIP")
        _restart()
        assert device_hold.is_held(5)
        assert _hold_row(db, 5)["reason"] == db.HOLD_REASON_SCHEME_MOVED

    @pytest.mark.parametrize("device_scheme, held_scheme", [
        ("MEMBERSHIP", "MEMBERSHIP"),     # unchanged: released, as lane 1b
        (None, "MEMBERSHIP"),             # a NULL column reads MEMBERSHIP (normalize_pin_scheme)
        ("ACCOUNT", None),                # a row that records no scheme: released, as before
    ])
    def test_the_other_unstarted_holds_are_released(self, sqlite_db, device_scheme, held_scheme):
        db = sqlite_db
        _device_row(db, 5, device_scheme)
        db.set_device_write_hold(device_id=5, reason=db.HOLD_REASON_ERASE_PREP, run_id="r-cut",
                                 pin_scheme=held_scheme)
        _restart()
        assert not device_hold.is_held(5) and _hold_row(db, 5) is None

    def test_a_turnstile_no_longer_in_monclub_is_released(self, sqlite_db):
        """Signed in, with a list that no longer has it (lane 1f: only such a list says so)."""
        db = sqlite_db
        _signed_in(db, 5)
        db.set_device_write_hold(device_id=7, reason=db.HOLD_REASON_ERASE_PREP, run_id="r-cut",
                                 pin_scheme="MEMBERSHIP")
        _restart()
        assert not device_hold.is_held(7)

    def test_a_scheme_that_cannot_be_read_releases_nothing(self, sqlite_db):
        db = sqlite_db
        db.set_device_write_hold(device_id=5, reason=db.HOLD_REASON_ERASE_PREP, run_id="r-cut",
                                 pin_scheme="MEMBERSHIP")

        def _drop(conn, profile):
            conn.execute("DROP TABLE sync_devices")
        db._run_db_write_sync("test_drop", _drop)
        _restart()
        assert device_hold.is_held(5)
        assert _hold_row(db, 5)["reason"] == db.HOLD_REASON_ERASE_PREP, "fail closed, retried"

    def test_a_power_cut_after_the_switch_landed_mid_run(self, sqlite_db, monkeypatch, tmp_path):
        """The whole path: the run holds under « Par abonnement », the switch reaches the database
        during the backup, and the power goes before the run looks at the scheme again."""
        db = sqlite_db
        _device_row(db, 5, "MEMBERSHIP")
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, db)
        pv = _preview(wiz, 5)

        class _Killed(BaseException):
            pass
        real = panel.read_table_strict

        def _read(*, table, fields="*"):
            _device_row(db, 5, "ACCOUNT")
            raise _Killed()
        panel.read_table_strict = _read
        with pytest.raises(_Killed):
            wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        panel.read_table_strict = real
        assert _hold_row(db, 5)["reason"] == db.HOLD_REASON_ERASE_PREP
        assert _hold_row(db, 5)["terminalScheme"] == "MEMBERSHIP"
        _restart()
        assert device_hold.is_held(5)
        assert _hold_row(db, 5)["reason"] == db.HOLD_REASON_SCHEME_MOVED

    def test_a_kept_run_loses_its_keep_mark_too(self, sqlite_db, tmp_path, monkeypatch):
        """It erased nobody (its row never left ``erase-prep``): a mark it left goes, as for a
        released one (lane 1d, F3)."""
        db = sqlite_db
        root = tmp_path / "b"
        monkeypatch.setattr(ew, "_default_backup_root", lambda: root)
        folder = root / "20260928-100000-abcdef_device5"
        folder.mkdir(parents=True)
        (folder / ew.KEEP_MARK).write_text("{}", encoding="utf-8")
        _device_row(db, 5, "ACCOUNT")
        db.set_device_write_hold(device_id=5, reason=db.HOLD_REASON_ERASE_PREP,
                                 run_id="20260928-100000-abcdef", pin_scheme="MEMBERSHIP")
        _restart()
        assert device_hold.is_held(5)
        assert not (folder / ew.KEEP_MARK).exists()


# ─────────────────────── F7: a turnstile already held at erase-prep ───────────────────────

class TestASchemeMovedStopOnATurnstileHeldBefore:

    def test_it_is_made_durable_at_once(self, sqlite_db, monkeypatch, tmp_path):
        """An earlier run left a session-only hold (row ``erase-prep``). A second run on it
        stops because the scheme moved: before lane 1e only a run that was not held before made
        its hold durable, so the row stayed ``erase-prep`` while the page said the hold outlives
        a restart (master review F7). Asserted before any restart: the start-up rule above would
        also keep it, and would hide the missing write."""
        db = sqlite_db
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, db)
        _scheme(monkeypatch, "MEMBERSHIP")
        device_hold.hold(5, reason=device_hold.REASON_ERASE_PREP, run_id="r-earlier",
                         pin_scheme="MEMBERSHIP")
        pv = _preview(wiz, 5)
        _moved_during_backup(monkeypatch, panel)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        note = _note(wiz)
        assert run["state"] == "FAILED" and note.startswith("HELD_SCHEME_MOVED:"), note
        row = _hold_row(db, 5)
        assert row["reason"] == db.HOLD_REASON_SCHEME_MOVED and row["runId"] == run["runId"], row

    def test_a_row_already_at_erase_keeps_its_reason_and_says_press_refill(self, sqlite_db,
                                                                            monkeypatch, tmp_path):
        """An earlier run may have deleted (row ``erase``): « Remplir » is not refused there, so the
        note must not say it is -- but the scheme moved during this run, so neither a plain "press
        Refill": its own code (lane 1g, review C2 of lane 1f: HELD_BEFORE_SCHEME_MOVED)."""
        db = sqlite_db
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, db)
        _scheme(monkeypatch, "MEMBERSHIP")
        device_hold.hold(5, reason=device_hold.REASON_ERASE, run_id="r-erased",
                         pin_scheme="MEMBERSHIP")
        pv = _preview(wiz, 5)
        _moved_during_backup(monkeypatch, panel)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert _note(wiz).startswith("HELD_BEFORE_SCHEME_MOVED:"), _note(wiz)
        assert _hold_row(db, 5)["reason"] == db.HOLD_REASON_ERASE
        _restart()
        assert _refill(wiz, "ACCOUNT")[0] == 200

    def test_a_row_already_scheme_moved_keeps_the_plain_note(self, sqlite_db, monkeypatch,
                                                             tmp_path):
        db = sqlite_db
        wiz, _w, panel = _held_scheme_moved(monkeypatch, tmp_path, db)
        first = wiz.status()["run"]["runId"]
        panel.read_table_strict = panel.read_table_strict.real
        _devices(monkeypatch, _device())
        _scheme(monkeypatch, "MEMBERSHIP")                   # set back, then it moves once more
        pv = _preview(wiz, 5)
        _moved_during_backup(monkeypatch, panel)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert wiz.status()["run"]["runId"] != first, "a second run must have started"
        assert _note(wiz).startswith("HELD_SCHEME_MOVED:"), _note(wiz)
        assert _hold_row(db, 5)["reason"] == db.HOLD_REASON_SCHEME_MOVED


# ─────────────────────── F8: the keep mark after the erase record ───────────────────────

class _Killed(BaseException):
    pass


def _mark_fails(monkeypatch, then=None):
    """The run folder's KEEP_MARK cannot be written (a full disk, an antivirus lock); ``then`` runs
    first -- something landing between the erase record and the mark."""
    real = ew._write_file_durably

    def _write(path, data):
        if Path(path).name == ew.KEEP_MARK:
            if then is not None:
                then()
            raise OSError("disk full")
        return real(path, data)
    monkeypatch.setattr(ew, "_write_file_durably", _write)


class TestTheKeepMarkComesAfterTheEraseRecord:

    def test_a_run_cut_before_its_erase_record_leaves_no_mark(self, sqlite_db, monkeypatch,
                                                              tmp_path):
        def _killed(*a, **k):
            raise _Killed()
        monkeypatch.setattr(ew, "_begin_erase", _killed)
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        pv = _preview(wiz, 5)
        with pytest.raises(_Killed):
            wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        assert not (_run_dir(wiz) / ew.KEEP_MARK).exists()

    def test_a_re_erase_of_a_held_turnstile_cut_before_its_record_keeps_nothing_forever(
            self, sqlite_db, monkeypatch, tmp_path):
        """The case lane 1d's start-up drop could not see (master review F8): the row is at
        ``erase`` from an earlier run, so the start never releases it. The second run erased
        nobody: its backup must be prunable once « Remplir » is pressed."""
        db = sqlite_db
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, db, panel=_staff_panel())
        device_hold.hold(5, reason=device_hold.REASON_ERASE, run_id="r-earlier")

        def _killed(*a, **k):
            raise _Killed()
        monkeypatch.setattr(ew, "_begin_erase", _killed)
        pv = _preview(wiz, 5)
        with pytest.raises(_Killed):
            wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        folder = _run_dir(wiz)
        _restart()
        assert device_hold.is_held(5)
        assert not (folder / ew.KEEP_MARK).exists()
        assert _refill(wiz, None)[0] == 200
        monkeypatch.setattr(ew, "_NO_RUN_BEFORE", "20000101")
        run_id = folder.name.split("_device")[0]
        assert run_id in ew.prune_erase_backups(folder.parent, now=time.time() + 31 * 86400)

    def test_the_mark_exists_before_the_first_delete(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        seen = []
        panel.on_erase = lambda table: seen.append((table, (_run_dir(wiz) / ew.KEEP_MARK).exists(),
                                                    _hold_row(sqlite_db, 5)["reason"]))
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "DONE"
        assert seen and seen[0][1] is True and seen[0][2] == sqlite_db.HOLD_REASON_ERASE, seen
        assert (_run_dir(wiz) / ew.KEEP_MARK).exists()

    def test_a_mark_that_cannot_be_written_puts_the_erase_record_back(
            self, sqlite_db, monkeypatch, tmp_path):
        """Lane 1f (review of lane 1e, C2): no delete was issued, so the erase record is undone and
        the run ends as any stop before a delete -- FAILED, released (the scheme did not move, the
        turnstile was not held before). Lane 1e left it INCOMPLETE and held at ``erase``, where
        « Remplir » has no scheme guard."""
        _mark_fails(monkeypatch)
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "FAILED", run
        assert run["error"].startswith("KEEP_MARK_NOT_WRITTEN:") and "undone" in run["error"]
        assert not run.get("erased"), "erased=True only once the mark is written"
        undone = [s for s in run["steps"] if s["step"] == "erase_record_undone"]
        assert undone and undone[0]["ok"] is True and undone[0]["reason"] == "erase-prep", undone
        assert not [c for c in panel.calls if c[0] == "erase"]
        assert not device_hold.is_held(5) and _hold_row(sqlite_db, 5) is None
        assert not (_run_dir(wiz) / ew.KEEP_MARK).exists()

    def test_a_scheme_move_then_a_mark_failure_keeps_the_scheme_guard(
            self, sqlite_db, monkeypatch, tmp_path):
        """The review's case: the switch lands just before the mark, whose write then fails. The
        record put back to ``erase-prep``, the stop keeps the hold as ``erase-scheme-moved`` --
        « Remplir » is refused under the new scheme, after a restart too."""
        _mark_fails(monkeypatch, then=lambda: _account(monkeypatch, 5, _device()))
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        _scheme(monkeypatch, "MEMBERSHIP")
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and _note(wiz).startswith("HELD_SCHEME_MOVED:"), run
        assert run["error"].startswith("KEEP_MARK_NOT_WRITTEN:"), run["error"]
        assert [s["ok"] for s in run["steps"] if s["step"] == "erase_record_undone"] == [True]
        assert not [c for c in panel.calls if c[0] == "erase"]
        assert _hold_row(sqlite_db, 5)["reason"] == sqlite_db.HOLD_REASON_SCHEME_MOVED
        _restart()
        status, out = _refill(wiz, "ACCOUNT")
        assert (status, out["code"]) == (409, "HELD_SCHEME_MOVED"), out

    def test_a_scheme_moved_row_taken_over_is_put_back_as_it_was(
            self, sqlite_db, monkeypatch, tmp_path):
        """The redo of C6 (the scheme set back, erase again with « Attendre… »): its erase record
        moved the ``erase-scheme-moved`` row to ``erase``; a mark failure puts it back there."""
        wiz, _w, panel = _held_scheme_moved(monkeypatch, tmp_path, sqlite_db)
        panel.read_table_strict = panel.read_table_strict.real
        staff = _staff_panel()                                   # a cleaner: the redo writes a mark
        panel.tables["user"] = staff.tables["user"]
        panel.tables["userauthorize"] = staff.tables["userauthorize"]
        _devices(monkeypatch, _device())
        _scheme(monkeypatch, "MEMBERSHIP")                      # the owner set it back
        _mark_fails(monkeypatch)
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and run["error"].startswith("KEEP_MARK_NOT_WRITTEN:"), run
        assert not [c for c in panel.calls if c[0] == "erase"]
        assert device_hold.is_held(5), "held before: the hold stays"
        assert _hold_row(sqlite_db, 5)["reason"] == sqlite_db.HOLD_REASON_SCHEME_MOVED
        _scheme(monkeypatch, "ACCOUNT")
        _account(monkeypatch, 5, _device())
        status, out = _refill(wiz, "ACCOUNT")
        assert (status, out["code"]) == (409, "HELD_SCHEME_MOVED"), out

    def test_a_row_already_at_erase_is_never_put_back(self, sqlite_db, monkeypatch, tmp_path):
        """Held at ``erase`` by an earlier run that may have deleted (« Incomplet », run again):
        nothing to put back -- INCOMPLETE and held, under the code that says « Remplir » only under
        the scheme of the erase's start."""
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        device_hold.hold(5, reason=device_hold.REASON_ERASE, run_id="r-incomplete",
                         pin_scheme="MEMBERSHIP")
        _mark_fails(monkeypatch)
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "INCOMPLETE", run
        assert run["error"].startswith("KEEP_MARK_NOT_WRITTEN_HELD:"), run["error"]
        assert "nothing was erased" in run["error"]
        assert not [s for s in run["steps"] if s["step"] == "erase_record_undone"]
        assert not [c for c in panel.calls if c[0] == "erase"]
        assert _hold_row(sqlite_db, 5)["reason"] == sqlite_db.HOLD_REASON_ERASE

    def test_an_undo_that_cannot_be_written_stays_incomplete_and_held(
            self, sqlite_db, monkeypatch, tmp_path):
        """Fail closed: the record stays at ``erase`` when putting it back fails."""
        def _undo_fails(**kw):
            raise sqlite3.OperationalError("disk I/O error")
        monkeypatch.setattr(dbmod, "undo_device_erase_record", _undo_fails)
        _mark_fails(monkeypatch)
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "INCOMPLETE", run
        assert run["error"].startswith("KEEP_MARK_NOT_WRITTEN_HELD:"), run["error"]
        undone = [s for s in run["steps"] if s["step"] == "erase_record_undone"]
        assert undone and undone[0]["ok"] is False, undone
        assert not [c for c in panel.calls if c[0] == "erase"]
        assert device_hold.is_held(5)
        assert _hold_row(sqlite_db, 5)["reason"] == sqlite_db.HOLD_REASON_ERASE

    def test_the_undo_touches_only_that_runs_row_at_erase(self, sqlite_db):
        db = sqlite_db
        db.set_device_write_hold(device_id=5, reason=db.HOLD_REASON_ERASE_PREP, run_id="r1",
                                 pin_scheme="MEMBERSHIP")
        assert db.undo_device_erase_record(device_id=5, run_id="r1",
                                           reason=db.HOLD_REASON_ERASE_PREP) is False
        db.begin_device_erase(device_id=5, run_id="r1")
        assert db.undo_device_erase_record(device_id=5, run_id="r-other",
                                           reason=db.HOLD_REASON_ERASE_PREP) is False
        assert _hold_row(db, 5)["reason"] == db.HOLD_REASON_ERASE
        assert db.undo_device_erase_record(device_id=5, run_id="r1",
                                           reason=db.HOLD_REASON_ERASE_PREP) is True
        row = _hold_row(db, 5)
        assert row["reason"] == db.HOLD_REASON_ERASE_PREP and row["terminalScheme"] == "MEMBERSHIP"
        with pytest.raises(ValueError):
            db.undo_device_erase_record(device_id=5, run_id="r1", reason=db.HOLD_REASON_ERASE)

    def test_a_written_mark_still_sets_erased(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "DONE" and run["erased"] is True, run


# ─────────────────────── a turnstile deleted during the run ───────────────────────

class TestATurnstileRemovedDuringTheRun:

    def test_its_note_says_nothing_needs_doing(self, sqlite_db, monkeypatch, tmp_path):
        """Master review nit: the session-only note told the operator to erase again or press
        « Remplir » -- impossible for a turnstile MonClub no longer has."""
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _signed_in(sqlite_db, 6)                               # the list still has panel 6
        _scheme(monkeypatch, "MEMBERSHIP")
        pv = _preview(wiz, 5)
        real = panel.read_table_strict

        def _read(*, table, fields="*"):
            _devices(monkeypatch)                              # the turnstile deleted in MonClub
            _scheme(monkeypatch, None)
            return real(table=table, fields=fields)
        panel.read_table_strict = _read
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        note = _note(wiz)
        assert note.startswith("HELD_DEVICE_GONE:"), note
        assert _hold_row(sqlite_db, 5)["reason"] == sqlite_db.HOLD_REASON_ERASE_PREP
        _restart()
        assert not device_hold.is_held(5)


# ─────────────────────── F5: a refused gym login is not a wrong password ───────────────────────

class _Post:
    def __init__(self, status, text):
        self.status_code, self.text = status, text

    def json(self):
        return json.loads(self.text)


class _PostSession:
    def __init__(self, answer):
        self.answer = answer

    def post(self, url, json=None, headers=None, timeout=None):
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


def _stats_api(answer):
    from app.api.monclub_api import ApiEndpoints, MonClubApi
    api = MonClubApi(ApiEndpoints(login_url="https://api.example.test/api/v1/public/access/v1/gym/login",
                                  sync_url="", create_user_fingerprint_url="", latest_release_url=""),
                     logging.getLogger("t"))
    api._session = _PostSession(answer)
    return api


# The backend's JWT filter refusal (JwtAuthenticationFilter.write401 -> ApiError.of(msg,
# "UNAUTHORIZED")) and its wrong-password answer (AccountAuthenticationService.
# validateStatisticsPassword: 401 "Wrong password") -- backend main f1482fd1.
_FILTER_401 = '{"status":false,"errorMsg":"Invalid JWT token","code":"UNAUTHORIZED"}'


class TestARefusedGymLogin:

    @pytest.mark.parametrize("text", ["Wrong password", '"Wrong password"', ""])
    def test_the_wrong_password_answer_is_still_false(self, text):
        assert _stats_api(_Post(401, text)).validate_statistics_password(token="t", password="p") is False

    @pytest.mark.parametrize("text", [_FILTER_401,
                                      '{"status":false,"errorMsg":"Token expired","code":"UNAUTHORIZED"}',
                                      '{"status":false,"errorMsg":"Gym not found","code":"UNAUTHORIZED"}'])
    def test_the_filters_refusal_raises(self, text):
        from app.api.monclub_api import MonClubTokenRejectedError
        with pytest.raises(MonClubTokenRejectedError):
            _stats_api(_Post(401, text)).validate_statistics_password(token="t", password="p")

    def test_the_wizard_reads_it_as_not_signed_in(self, monkeypatch):
        from app.api import local_access_api_v2 as api_mod
        api = _stats_api(_Post(401, _FILTER_401))
        monkeypatch.setattr("access.store.load_auth_token", lambda: SimpleNamespace(token="t"))
        ctx = SimpleNamespace(app=SimpleNamespace(_api=lambda: api))
        ok, status, error = api_mod._erase_password_verifier(ctx)("pw")
        assert ok is False
        assert ew._password_refusal(status, error)[1]["code"] == "PC_NOT_SIGNED_IN", error

    def test_the_lock_screen_reads_it_as_not_signed_in(self, monkeypatch):
        from app.api import local_access_api_v2 as api_mod
        api = _stats_api(_Post(401, _FILTER_401))
        monkeypatch.setattr("access.store.load_auth_token", lambda: SimpleNamespace(token="t"))
        sent = {}
        ctx = SimpleNamespace(body=lambda: {"password": "pw"},
                              app=SimpleNamespace(_api=lambda: api, logger=logging.getLogger("t")),
                              send_json=lambda s, p: sent.update(status=s, payload=p))
        api_mod._handle_auth_verify_admin_password(ctx)
        assert sent["payload"]["code"] == "PC_NOT_SIGNED_IN", sent
        assert "MonClub" in sent["payload"]["error"] and "Mot de passe incorrect" not in sent["payload"]["error"]

    def test_a_wrong_password_still_reads_as_one(self, monkeypatch):
        from app.api import local_access_api_v2 as api_mod
        api = _stats_api(_Post(401, "Wrong password"))
        monkeypatch.setattr("access.store.load_auth_token", lambda: SimpleNamespace(token="t"))
        ctx = SimpleNamespace(app=SimpleNamespace(_api=lambda: api))
        ok, status, error = api_mod._erase_password_verifier(ctx)("pw")
        assert ew._password_refusal(status, error)[1]["code"] == "ADMIN_PASSWORD"


# ─────────────────────── TLS: a dropped connection, a wrong clock ───────────────────────

def _as_requests_raises_it(ssl_exc):
    """What ``requests`` raises for an SSL failure: its SSLError wrapping urllib3's
    MaxRetryError, whose reason is urllib3's SSLError wrapping the ``ssl`` exception."""
    inner = urllib3.exceptions.SSLError(ssl_exc)
    retry = urllib3.exceptions.MaxRetryError(None, "https://api.example.test/x", reason=inner)
    out = requests.exceptions.SSLError(retry)
    out.__context__ = retry
    return out


def _cert_error(code, message):
    exc = ssl.SSLCertVerificationError(1, f"[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify "
                                          f"failed: {message} (_ssl.c:1006)")
    exc.verify_code, exc.verify_message = code, message
    return exc


_NOT_YET_VALID = _cert_error(9, "certificate is not yet valid")
_EXPIRED = _cert_error(10, "certificate has expired")
_SELF_SIGNED = _cert_error(18, "self-signed certificate")
_EOF = ssl.SSLEOFError(8, "EOF occurred in violation of protocol (_ssl.c:2426)")
# The verify code decides, not the text (an OpenSSL build or a wrapper may word it otherwise): only
# a walk down to the ``ssl`` exception itself can read it.
_CODE_ONLY = _cert_error(9, "certificate date check failed")


class TestTheTlsFailures:

    @pytest.mark.parametrize("ssl_exc, kind", [
        (_NOT_YET_VALID, "clock"), (_EXPIRED, "clock"), (_SELF_SIGNED, "other"), (_EOF, "eof"),
        (_CODE_ONLY, "clock"),
    ])
    def test_the_kind_is_read_through_the_whole_chain(self, ssl_exc, kind):
        from app.api.monclub_api import MonClubApiError
        wrapped = MonClubApiError("request failed")
        wrapped.__cause__ = _as_requests_raises_it(ssl_exc)
        assert ew.tls_kind(wrapped) == kind
        assert ew.tls_kind(RuntimeError("nothing to do with TLS")) is None

    @pytest.mark.parametrize("ssl_exc, code", [
        (_NOT_YET_VALID, "TLS_CLOCK"), (_EXPIRED, "TLS_CLOCK"),
        (_EOF, "ERASE_SWITCH_UNREACHABLE"), (_SELF_SIGNED, "ERASE_SWITCH_UNCHECKED"),
    ])
    def test_the_switch_check(self, monkeypatch, ssl_exc, code):
        monkeypatch.setattr("access.store.load_auth_token", lambda: SimpleNamespace(token="jwt"))
        api = _real_api(_as_requests_raises_it(ssl_exc))
        ok, got, why = _real_check_erase_switch(SimpleNamespace(_api=lambda: api))
        assert (ok, got) == (False, code), why

    @pytest.mark.parametrize("ssl_exc, code", [
        (_NOT_YET_VALID, "TLS_CLOCK"), (_EOF, "ADMIN_PASSWORD_UNCHECKABLE"),
        (_SELF_SIGNED, "ADMIN_PASSWORD_CHECK_FAILED"),
    ])
    def test_the_password_check_of_an_erase_and_of_remplir(self, monkeypatch, ssl_exc, code):
        from app.api import local_access_api_v2 as api_mod
        api = _stats_api(_as_requests_raises_it(ssl_exc))
        monkeypatch.setattr("access.store.load_auth_token", lambda: SimpleNamespace(token="t"))
        ok, status, error = api_mod._erase_password_verifier(SimpleNamespace(
            app=SimpleNamespace(_api=lambda: api)))("pw")
        assert ok is False and ew._password_refusal(status, error)[1]["code"] == code, error

    @pytest.mark.parametrize("ssl_exc, status, code", [
        (_NOT_YET_VALID, 502, "TLS_CLOCK"), (_EOF, 503, "ADMIN_PASSWORD_UNCHECKABLE"),
        (_SELF_SIGNED, 502, "ADMIN_PASSWORD_CHECK_FAILED"),
    ])
    def test_the_lock_screen_answers_in_french(self, monkeypatch, ssl_exc, status, code):
        """The Local DB page shows the route's ``error`` text as it is: French, as before lane
        1d's TLS branch (master review nit)."""
        from app.api import local_access_api_v2 as api_mod
        api = _stats_api(_as_requests_raises_it(ssl_exc))
        monkeypatch.setattr("access.store.load_auth_token", lambda: SimpleNamespace(token="t"))
        sent = {}
        ctx = SimpleNamespace(body=lambda: {"password": "pw"},
                              app=SimpleNamespace(_api=lambda: api, logger=logging.getLogger("t")),
                              send_json=lambda s, p: sent.update(status=s, payload=p))
        api_mod._handle_auth_verify_admin_password(ctx)
        assert (sent["status"], sent["payload"]["code"]) == (status, code), sent
        error = sent["payload"]["error"]
        assert "serveur MonClub" in error or "Internet" in error, error
        assert "(TLS)" not in error and "could not be checked" not in error


# ─────────────────────── the page reads the warning from the hold row ───────────────────────

def _ts(rel):
    return (REPO / "tauri-ui" / "src" / rel).read_text(encoding="utf-8")


class TestThePage:

    def test_both_languages_have_the_new_texts(self):
        text = _ts("lib/eraseWizardText.ts")
        # HELD_SCHEME_MOVED: the finish note and the refusal code, in both languages.
        for key, n in (("HELD_SCHEME_MOVED", 4), ("TLS_CLOCK", 2)):
            assert len(re.findall(r"\b" + key + r":\s*\n?\s*\"", text)) == n, key
        assert len(re.findall(r"\bHELD_DEVICE_GONE:", text)) == 2
        assert len(re.findall(r"schemeMovedHold: \(terminal: string \| null, now: string\)", text)) == 2

    def test_the_dialog_derives_the_warning_and_the_refusal_from_the_row(self):
        dialog = _ts("components/EraseWizardDialog.tsx")
        assert '"erase-scheme-moved"' in dialog
        assert re.search(r"schemeMovedBlocked", dialog)
        # The button is disabled while the scheme recorded now is not the terminal's.
        assert re.search(r"disabled=\{[^}]*schemeMovedBlocked", dialog)
        assert "terminalScheme" in _ts("api/erase.ts")

    def test_the_devices_page_no_longer_says_erased_for_it(self):
        page = _ts("pages/DevicesPage.tsx")
        assert "erase-scheme-moved" in page
        assert re.search(r"rien n'a été effacé", page)


# ─────────────────────── review round 1 of lane 1e ───────────────────────

class TestReviewRound1:

    def test_a_leftover_erase_prep_row_whose_scheme_moved_is_refused_too(self, sqlite_db,
                                                                         monkeypatch, tmp_path):
        """Finding 1: the durable write failed, the row stays ``erase-prep`` (recording the
        terminal's scheme) and the session keeps the hold -- Refill must refuse it until the
        scheme is back, before any restart, as for ``erase-scheme-moved``."""
        def _fails(*a, **k):
            raise RuntimeError("disk I/O error")
        monkeypatch.setattr(dbmod, "keep_erase_hold_after_scheme_move", _fails)
        wiz, _w, _p = _held_scheme_moved(monkeypatch, tmp_path, sqlite_db)
        assert _note(wiz).startswith("HELD_SCHEME_MOVED_SESSION:")
        assert "or press Refill" not in _note(wiz)
        row = _hold_row(sqlite_db, 5)
        assert row["reason"] == sqlite_db.HOLD_REASON_ERASE_PREP and row["terminalScheme"] == "MEMBERSHIP"
        status, out = _refill(wiz, "ACCOUNT")
        assert (status, out["code"]) == (409, "HELD_SCHEME_MOVED"), out
        assert device_hold.is_held(5)
        _devices(monkeypatch, _device())
        _scheme(monkeypatch, "MEMBERSHIP")
        assert _refill(wiz, "MEMBERSHIP")[0] == 200

    def test_a_leftover_erase_prep_row_with_no_scheme_or_the_same_scheme_refills(self, sqlite_db,
                                                                                 monkeypatch, tmp_path):
        db = sqlite_db
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, db)
        _scheme(monkeypatch, "ACCOUNT")
        device_hold.hold(5, reason=device_hold.REASON_ERASE_PREP, run_id="r0")
        assert _refill(wiz, "ACCOUNT")[0] == 200
        device_hold.hold(5, reason=device_hold.REASON_ERASE_PREP, run_id="r1", pin_scheme="ACCOUNT")
        assert _refill(wiz, "ACCOUNT")[0] == 200

    def test_the_note_names_the_scheme_the_row_records(self, sqlite_db, monkeypatch, tmp_path):
        """Finding 2: a second run started under « Par personne » on a row that records
        « Par abonnement », the owner switches back mid-run: the note must name the terminal's
        scheme (the row's), which Refill then accepts -- not the second run's start scheme."""
        wiz, _w, panel = _held_scheme_moved(monkeypatch, tmp_path, sqlite_db)
        panel.read_table_strict = panel.read_table_strict.real
        pv = _preview(wiz, 5)                                   # under ACCOUNT
        real = panel.read_table_strict

        def _back(*, table, fields="*"):
            _devices(monkeypatch, _device())
            _scheme(monkeypatch, "MEMBERSHIP")
            return real(table=table, fields=fields)
        panel.read_table_strict = _back
        wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        note = _note(wiz)
        assert note.startswith("HELD_SCHEME_MOVED:"), note
        assert "holds the MEMBERSHIP scheme's pins" in note and "accepted only under MEMBERSHIP" in note, note
        panel.read_table_strict = real
        assert _refill(wiz, "MEMBERSHIP")[0] == 200

    def test_a_deleted_turnstile_held_at_erase_is_not_told_nothing_was_erased(self, sqlite_db,
                                                                              monkeypatch, tmp_path):
        """Finding 6: HELD_DEVICE_GONE only for a row this run held at ``erase-prep``."""
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _scheme(monkeypatch, "MEMBERSHIP")
        device_hold.hold(5, reason=device_hold.REASON_ERASE, run_id="r-erased", pin_scheme="MEMBERSHIP")
        pv = _preview(wiz, 5)
        real = panel.read_table_strict

        def _read(*, table, fields="*"):
            _devices(monkeypatch)
            _scheme(monkeypatch, None)
            return real(table=table, fields=fields)
        panel.read_table_strict = _read
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert not _note(wiz).startswith("HELD_DEVICE_GONE:"), _note(wiz)

    def test_the_page_blocks_a_leftover_erase_prep_row_too(self):
        dialog = _ts("components/EraseWizardDialog.tsx")
        assert '"erase-prep"' in dialog and "holdTerminal !== holdScheme" in dialog


class TestReviewRound2:

    def test_a_row_that_records_no_scheme_gets_a_note_that_matches_the_refusal(self, sqlite_db,
                                                                               monkeypatch, tmp_path):
        db = sqlite_db
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, db)
        db.set_device_write_hold(device_id=5, reason=db.HOLD_REASON_ERASE_PREP, run_id="r0")
        db.keep_erase_hold_after_scheme_move(device_id=5, run_id="r0")      # an earlier build's row
        device_hold.load()
        _scheme(monkeypatch, "MEMBERSHIP")
        pv = _preview(wiz, 5)
        _moved_during_backup(monkeypatch, panel)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        note = _note(wiz)
        assert note.startswith("HELD_SCHEME_MOVED:") and "Refill is refused" in note, note
        assert "accepted only under" not in note

    def test_the_devices_page_tooltip_covers_a_leftover_erase_prep_row(self):
        page = _ts("pages/DevicesPage.tsx")
        assert 'h.reason === "erase-prep" && h.terminalScheme != null' in page

"""Lane 1d (2026-09-28): the master session's review of lane 1c -- three code points and nits.

Guide §3.2h. Against the same fakes as tests/test_erase_wizard.py -- nothing reaches a device:
* F0  a hold a run keeps because the pin scheme moved (or did not read) before its first delete
      survives a restart: its row moves off ``erase-prep``, which a start releases;
* F1  the start-up prune goes through the same clock guard as the prune after a run: it waits, a
      bounded time, for this process to measure the server's clock before it prunes;
* F3  a run stopped (a power cut, a kill) between its keep mark and its erase record erased nobody:
      the start-up release of its hold drops the mark, so its backup is prunable as usual.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

import pytest

import app.core.erase_wizard as ew
from app.core import device_hold
from tests.test_erase_wizard import (  # noqa: F401 -- fixtures are used by name
    _body, _pw_ok, _setup_c3, erase_switch_on, refill_cache, sqlite_db,
)
from tests.test_erase_wizard_lane1c import _Clock, _account, _preview, _run_dir, _staff_panel
from tests.test_erase_wizard_lane1b import _real_api

# Before the autouse fixture replaces it (tests/test_erase_wizard.py::erase_switch_on).
_real_check_erase_switch = ew.check_erase_switch

REPO = Path(__file__).resolve().parents[1]


def _restart():
    """What a restart of Access does to the holds: the in-memory gate is gone, and the start-up
    load (app.py) releases the holds of runs that stopped before any delete."""
    device_hold.reset_for_tests()
    device_hold.load(release_unstarted=True)


def _hold_row(db, did):
    return (db.list_device_write_holds() or {}).get(did)


# ─────────────────────────── F0: a kept hold survives a restart ───────────────────────────

class TestAHoldKeptAfterASchemeMoveSurvivesARestart:

    def _moved_during_backup(self, monkeypatch, panel):
        from tests.test_erase_wizard import _device
        real = panel.read_table_strict

        def _read(*, table, fields="*"):
            _account(monkeypatch, 5, _device())          # the switch lands during the backup
            return real(table=table, fields=fields)
        panel.read_table_strict = _read

    def test_held_scheme_moved_is_still_held_after_a_restart(self, sqlite_db, monkeypatch,
                                                             tmp_path):
        wiz, worker, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        self._moved_during_backup(monkeypatch, panel)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        note = [s for s in run["steps"] if s["step"] == "finish"][0]["note"]
        assert run["state"] == "FAILED" and note.startswith("HELD_SCHEME_MOVED:"), note
        assert not [c for c in panel.calls if c[0] == "erase"]
        row = _hold_row(sqlite_db, 5)
        assert row is not None and row["reason"] == sqlite_db.HOLD_REASON_SCHEME_MOVED, row
        assert row["runId"] == run["runId"]
        _restart()
        assert device_hold.is_held(5), "the start-up load must not release it"
        assert _hold_row(sqlite_db, 5)["reason"] == sqlite_db.HOLD_REASON_SCHEME_MOVED
        assert "NOT kept across a restart" not in note

    def test_held_scheme_unreadable_is_still_held_after_a_restart(self, sqlite_db, monkeypatch,
                                                                  tmp_path, refill_cache):
        import app.core.db as dbmod
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        real = panel.read_table_strict

        def _broken(did):
            raise RuntimeError("database is locked")

        def _read(*, table, fields="*"):
            refill_cache.users = []                               # the run will stop EMPTY
            monkeypatch.setattr(dbmod, "get_device_pin_scheme", _broken)
            return real(table=table, fields=fields)
        panel.read_table_strict = _read
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        note = [s for s in wiz.status()["run"]["steps"] if s["step"] == "finish"][0]["note"]
        assert note.startswith("HELD_SCHEME_UNREADABLE:"), note
        _restart()
        assert device_hold.is_held(5)

    def test_an_unchanged_scheme_failure_still_leaves_nothing_held(self, sqlite_db, monkeypatch,
                                                                   tmp_path, refill_cache):
        """The control: with the scheme unchanged a FAILED run releases at once (lane 1b), and a
        run cut before any delete by a restart is released by the start (lane 1b, F1)."""
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        real = panel.read_table_strict

        def _read(*, table, fields="*"):
            refill_cache.users = []
            return real(table=table, fields=fields)
        panel.read_table_strict = _read
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "FAILED"
        assert not device_hold.is_held(5) and _hold_row(sqlite_db, 5) is None
        device_hold.hold(5, reason=device_hold.REASON_ERASE_PREP, run_id="r-cut")
        _restart()
        assert not device_hold.is_held(5)

    def test_the_row_moves_only_from_its_own_erase_prep(self, sqlite_db):
        """Never an ERASE row (a delete may have run) and never another run's row."""
        db = sqlite_db
        db.set_device_write_hold(device_id=5, reason=db.HOLD_REASON_ERASE, run_id="r1")
        assert db.keep_erase_hold_after_scheme_move(device_id=5, run_id="r1") == db.HOLD_REASON_ERASE
        assert _hold_row(db, 5)["reason"] == db.HOLD_REASON_ERASE
        db.set_device_write_hold(device_id=6, reason=db.HOLD_REASON_ERASE_PREP, run_id="r2")
        assert db.keep_erase_hold_after_scheme_move(device_id=6, run_id="other") == (
            db.HOLD_REASON_ERASE_PREP)
        assert _hold_row(db, 6)["reason"] == db.HOLD_REASON_ERASE_PREP
        assert db.keep_erase_hold_after_scheme_move(device_id=6, run_id="r2") == (
            db.HOLD_REASON_SCHEME_MOVED)
        assert db.keep_erase_hold_after_scheme_move(device_id=7, run_id="r3") is None

    def test_a_later_run_neither_downgrades_nor_releases_it(self, sqlite_db):
        """A second run holds with erase-prep: the upsert keeps the durable reason (it was held
        before), and its erase record moves it on to ERASE."""
        db = sqlite_db
        db.set_device_write_hold(device_id=5, reason=db.HOLD_REASON_ERASE_PREP, run_id="r1")
        db.keep_erase_hold_after_scheme_move(device_id=5, run_id="r1")
        db.set_device_write_hold(device_id=5, reason=db.HOLD_REASON_ERASE_PREP, run_id="r2")
        assert _hold_row(db, 5) == dict(_hold_row(db, 5), reason=db.HOLD_REASON_SCHEME_MOVED,
                                        runId="r2")
        _restart()
        assert device_hold.is_held(5)
        db.begin_device_erase(device_id=5, run_id="r2")
        assert _hold_row(db, 5)["reason"] == db.HOLD_REASON_ERASE

    def test_refill_waits_for_the_terminals_scheme(self, sqlite_db, monkeypatch, tmp_path):
        """Lane 1d released it here, under the new scheme -- the master review of lane 1d (C0):
        nothing was erased, and that pass would write « Par personne » pins beside every old one.
        Since lane 1e Refill is refused until the scheme is the terminal's again
        (tests/test_erase_wizard_lane1e.py::TestRemplirOnASchemeMovedHold, which also sets it
        back); this run started with no scheme recorded, so only an erase clears it."""
        wiz, worker, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        self._moved_during_backup(monkeypatch, panel)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        _restart()
        status, out = wiz.refill(5, {"password": "pw", "expectedPinScheme": "ACCOUNT"},
                                 verify_password=_pw_ok)
        assert (status, out["code"]) == (409, "HELD_SCHEME_MOVED"), out
        assert device_hold.is_held(5) and _hold_row(sqlite_db, 5) is not None

    def test_a_row_that_cannot_be_kept_says_so(self, sqlite_db, monkeypatch, tmp_path):
        """The durable write fails: the hold is kept for this session (as before lane 1d), and
        the note says a restart would release it."""
        def _fails(*a, **k):
            raise RuntimeError("disk I/O error")
        import app.core.db as dbmod
        monkeypatch.setattr(dbmod, "keep_erase_hold_after_scheme_move", _fails)
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        self._moved_during_backup(monkeypatch, panel)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        note = [s for s in run["steps"] if s["step"] == "finish"][0]["note"]
        # Its own code (review round 1 of lane 1d): the page's translated line for
        # HELD_SCHEME_MOVED promises the hold outlives a restart -- this one says it may not
        # ("may": since lane 1e the next start still keeps the row while the scheme differs).
        assert note.startswith("HELD_SCHEME_MOVED_SESSION:"), note
        assert "may NOT last through a restart" in note, note
        assert device_hold.is_held(5) and run["holdKept"] is True

    def test_a_turnstile_removed_during_the_run_keeps_no_durable_hold(self, sqlite_db,
                                                                      monkeypatch, tmp_path):
        """Review round 1 of lane 1d: the device row gone (its scheme reads None) is not a scheme
        move to protect -- no hold for a turnstile MonClub no longer has, kept until a Refill
        nobody could press. Held for the session, as before lane 1d, with the session note."""
        import app.core.db as dbmod
        from tests.test_erase_wizard import _devices
        from tests.test_erase_wizard_lane1e import _signed_in
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        # Lane 1f (review C1): only a list that can say so -- signed in, not empty -- makes a
        # missing row "deleted in MonClub".
        _signed_in(sqlite_db, 6)
        monkeypatch.setattr(dbmod, "get_device_pin_scheme", lambda d: "MEMBERSHIP")
        pv = _preview(wiz, 5)
        real = panel.read_table_strict

        def _read(*, table, fields="*"):
            _devices(monkeypatch)                              # the turnstile deleted in MonClub
            monkeypatch.setattr(dbmod, "get_device_pin_scheme", lambda d: None)
            return real(table=table, fields=fields)
        panel.read_table_strict = _read
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        note = [s for s in wiz.status()["run"]["steps"] if s["step"] == "finish"][0]["note"]
        # Its own note since lane 1e (master review nit): nothing to do for a deleted turnstile.
        assert note.startswith("HELD_DEVICE_GONE:"), note
        assert _hold_row(sqlite_db, 5)["reason"] == sqlite_db.HOLD_REASON_ERASE_PREP
        _restart()
        assert not device_hold.is_held(5)

    def test_the_page_says_it_stays_held_after_a_restart(self):
        text = (REPO / "tauri-ui" / "src" / "lib" / "eraseWizardText.ts").read_text(encoding="utf-8")
        for code in ("HELD_SCHEME_MOVED", "HELD_SCHEME_UNREADABLE", "HELD_SCHEME_MOVED_SESSION",
                     "HELD_SCHEME_UNREADABLE_SESSION"):
            said = re.findall(r"\b" + code + r':\s*\n?\s*"([^"]+)"', text)
            # The finish notes, French and English (since lane 1e HELD_SCHEME_MOVED is also a
            # refusal code of « Remplir », whose texts do not speak of a restart).
            fr = [s for s in said if "redémarrage" in s]
            en = [s for s in said if "restart" in s]
            assert len(fr) == 1 and len(en) == 1, (code, said)
            if code.endswith("_SESSION"):
                assert "PAS" in fr[0] and "NOT" in en[0], said


# ─────────────────────────── F1: the start-up prune and the server clock ───────────────────────────

class _Mono:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _old_folder(root, did=5, days=45):
    run_id = time.strftime("%Y%m%d-%H%M%S", time.localtime(time.time() - days * 86400)) + "-abcdef"
    folder = root / f"{run_id}_device{did}"
    folder.mkdir(parents=True)
    (folder / "backup.json").write_text("{}", encoding="utf-8")
    at = time.time() - days * 86400
    (folder / "run.json").write_text(json.dumps(
        {"state": "DONE", "startedAtEpoch": at, "writtenAtEpoch": at}), encoding="utf-8")
    return folder


class TestTheStartUpPruneWaitsForTheServerClock:

    @pytest.fixture(autouse=True)
    def _no_clock(self, monkeypatch):
        from app.core.v2 import server_clock
        monkeypatch.setattr(server_clock, "_default", None)
        monkeypatch.setattr(ew, "_NO_RUN_BEFORE", "20000101")

    def test_a_clock_measured_after_the_start_guards_the_start_up_prune(self, sqlite_db,
                                                                        monkeypatch, tmp_path):
        """The v2 runtime installs its clock ~12 s after launch and measures the server at its
        first answer. The start-up prune waits for it: a PC clock a year ahead then deletes
        nothing -- the guard the prune after a run already has."""
        from app.core.v2 import server_clock
        root = tmp_path / "b"
        folder = _old_folder(root)
        mono, sleeps = _Mono(), []

        def _sleep(s):
            sleeps.append(s)
            mono.t += s
            if len(sleeps) == 3:                                # the runtime measured the server
                monkeypatch.setattr(server_clock, "_default", _Clock(offset=-365 * 86400))
        deleted = ew.prune_erase_backups_at_startup(root, sleep=_sleep, mono=mono)
        assert deleted == [] and folder.exists()
        assert len(sleeps) == 3

    def test_no_server_time_prunes_on_the_pc_clock_after_the_wait(self, sqlite_db, tmp_path):
        """v2 off (every gym today): no sample ever comes. After the bounded wait the prune runs
        as the prune after a run does -- the PC clock alone -- so the owner's 30 days still hold."""
        root = tmp_path / "b"
        folder = _old_folder(root)
        mono, sleeps = _Mono(), []

        def _sleep(s):
            sleeps.append(s)
            mono.t += s
        deleted = ew.prune_erase_backups_at_startup(root, sleep=_sleep, mono=mono)
        assert deleted == [folder.name.split("_device")[0]] and not folder.exists()
        waited = sum(sleeps)
        assert ew.STARTUP_PRUNE_CLOCK_WAIT_SEC <= waited <= (
            ew.STARTUP_PRUNE_CLOCK_WAIT_SEC + ew.STARTUP_PRUNE_POLL_SEC)

    def test_a_clock_already_measured_does_not_wait(self, sqlite_db, monkeypatch, tmp_path):
        from app.core.v2 import server_clock
        root = tmp_path / "b"
        folder = _old_folder(root)
        monkeypatch.setattr(server_clock, "_default", _Clock(offset=0))

        def _sleep(s):
            raise AssertionError("no wait when the clock is measured")
        assert ew.prune_erase_backups_at_startup(root, sleep=_sleep, mono=_Mono()) == [
            folder.name.split("_device")[0]]

    def test_app_starts_the_waiting_prune_on_its_own_thread(self):
        src = (REPO / "app" / "ui" / "app.py").read_text(encoding="utf-8")
        assert re.search(r"threading\.Thread\(target=prune_erase_backups_at_startup\b", src), (
            "the start-up prune must be the one that waits for the server clock")
        assert not re.search(r"threading\.Thread\(target=prune_erase_backups\b", src)


# ─────────────────────────── F3: a keep mark of a run that erased nobody ───────────────────────────

class TestAKeepMarkOfARunThatNeverErasedIsDroppedAtStartUp:

    def test_a_kill_between_the_mark_and_the_erase_record(self, sqlite_db, monkeypatch, tmp_path):
        """The power goes off after the keep mark is written and before the erase is recorded:
        the hold row is still erase-prep, so the start releases it -- and drops the mark.
        Since lane 1e (master review F8) the mark comes after the erase record, so this build
        leaves none there: the mark below is one an earlier build (lanes 1c-1d) wrote."""
        class _Killed(BaseException):
            pass

        def _killed(*a, **k):
            raise _Killed()
        monkeypatch.setattr(ew, "_begin_erase", _killed)
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        monkeypatch.setattr(ew, "_default_backup_root", lambda: Path(wiz.backup_root()))
        pv = _preview(wiz, 5)
        with pytest.raises(_Killed):
            wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        folder = _run_dir(wiz)
        assert not (folder / ew.KEEP_MARK).exists(), "this build writes no mark before the record"
        (folder / ew.KEEP_MARK).write_text("{}", encoding="utf-8")        # an earlier build's
        assert not [c for c in panel.calls if c[0] == "erase"]
        _restart()
        assert not device_hold.is_held(5)
        assert not (folder / ew.KEEP_MARK).exists()
        assert (folder / "backup.json").exists(), "only the mark goes; the prune decides later"
        run_id = folder.name.split("_device")[0]
        monkeypatch.setattr(ew, "_NO_RUN_BEFORE", "20000101")
        assert ew.prune_erase_backups(folder.parent, now=time.time() + 31 * 86400) == [run_id]

    def test_a_run_whose_erase_was_recorded_keeps_its_mark(self, sqlite_db, monkeypatch,
                                                            tmp_path):
        """Killed at its first delete command: a delete may have run -- the hold (erase) stays,
        and so does the mark (written after the erase record since lane 1e, before that command)."""
        class _Killed(BaseException):
            pass

        def _killed_at_the_first_delete(table):
            raise _Killed()
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        _p.on_erase = _killed_at_the_first_delete
        monkeypatch.setattr(ew, "_default_backup_root", lambda: Path(wiz.backup_root()))
        pv = _preview(wiz, 5)
        with pytest.raises(_Killed):
            wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        _restart()
        assert device_hold.is_held(5)
        assert (_run_dir(wiz) / ew.KEEP_MARK).exists()

    def test_the_drop_touches_only_the_released_runs(self, tmp_path):
        root = tmp_path / "b"
        released = root / "20260928-100000-abcdef_device5"
        other = root / "20260928-110000-abcdef_device6"
        for folder in (released, other):
            folder.mkdir(parents=True)
            (folder / ew.KEEP_MARK).write_text("{}", encoding="utf-8")
        dropped = ew.drop_keep_marks_of_unstarted_runs(
            {5: "20260928-100000-abcdef", 7: None, 8: "20260928-120000-abcdef"}, root=root)
        assert dropped == ["20260928-100000-abcdef"]
        assert not (released / ew.KEEP_MARK).exists() and (other / ew.KEEP_MARK).exists()


# ─────────────────────────── the review's nits ───────────────────────────

class TestTheNits:

    @pytest.mark.parametrize("exc, code", [
        # A TLS failure got an answer of sorts (a certificate that does not check out): not
        # "no internet" -- the developer reads the detail line.
        (__import__("requests").exceptions.SSLError("certificate verify failed"),
         "ERASE_SWITCH_UNCHECKED"),
        (__import__("ssl").SSLError("certificate verify failed"), "ERASE_SWITCH_UNCHECKED"),
        # A proxy that does not answer is still no answer from the server.
        (__import__("requests").exceptions.ProxyError("proxy refused"),
         "ERASE_SWITCH_UNREACHABLE"),
        (__import__("requests").exceptions.ConnectionError("no route"),
         "ERASE_SWITCH_UNREACHABLE"),
    ])
    def test_an_ssl_failure_is_not_read_as_no_internet(self, monkeypatch, exc, code):
        from types import SimpleNamespace
        monkeypatch.setattr("access.store.load_auth_token", lambda: SimpleNamespace(token="jwt"))
        api = _real_api(exc)
        ok, got, why = _real_check_erase_switch(SimpleNamespace(_api=lambda: api))
        assert (ok, got) == (False, code), why

    def test_a_worker_that_vanishes_during_step_1_gives_no_raw_error(self, sqlite_db,
                                                                     monkeypatch, tmp_path):
        """The worker is looked up once: one that leaves the engine after the first check is
        not dereferenced as None (a raw 500 before)."""
        wiz, worker, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        seen = []

        def _once(did):
            seen.append(did)
            return worker if len(seen) <= 2 else None     # gone after the address check
        monkeypatch.setattr(wiz, "_worker", _once)
        status, out = wiz.preview(5)
        assert status == 200, out

    def test_a_user_list_that_raises_reads_as_unread(self, sqlite_db, monkeypatch, tmp_path):
        """Any failure of step 1's user-list read -- not only a device error -- is "unread":
        the preview answers, and a start is refused NOT_REFILLED_UNKNOWN."""
        wiz, worker, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        real = worker.request_run_sdk

        def _raises(fn, *, label, timeout):
            if label == "erase_read_user_list":
                raise RuntimeError("worker gone")
            return real(fn, label=label, timeout=timeout)
        monkeypatch.setattr(worker, "request_run_sdk", _raises)
        status, pv = wiz.preview(5)
        assert status == 200 and pv["notRefilled"] is None, pv
        status, out = wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert (status, out["code"]) == (409, "NOT_REFILLED_UNKNOWN")

    @pytest.mark.parametrize("cause, status, code", [
        (__import__("requests").exceptions.SSLError("certificate verify failed"), 502,
         "ADMIN_PASSWORD_CHECK_FAILED"),
        (__import__("requests").exceptions.ConnectionError("no route"), 503,
         "ADMIN_PASSWORD_UNCHECKABLE"),
    ])
    def test_a_tls_failure_of_the_password_check_is_not_no_internet(self, monkeypatch, cause,
                                                                    status, code):
        """Review round 1 of lane 1d: the erase and Refill password check read every exception as
        offline (« Pas d'Internet »). A TLS failure got an answer: the server check failed."""
        from types import SimpleNamespace
        from app.api import local_access_api_v2 as api_mod
        from app.api.monclub_api import MonClubApiError

        class _Api:
            def validate_statistics_password(self, **k):
                raise MonClubApiError(f"validate_statistics_password failed: {cause}") from cause
        monkeypatch.setattr("access.store.load_auth_token", lambda: SimpleNamespace(token="t"))
        ctx = SimpleNamespace(app=SimpleNamespace(_api=lambda: _Api()))
        ok, got_status, error = api_mod._erase_password_verifier(ctx)("pw")
        assert (ok, got_status) == (False, status), error
        assert ew._password_refusal(got_status, error)[1]["code"] == code

    @pytest.mark.parametrize("cause, status, code", [
        (__import__("requests").exceptions.SSLError("certificate verify failed"), 502,
         "ADMIN_PASSWORD_CHECK_FAILED"),
        (__import__("requests").exceptions.ConnectionError("no route"), 503,
         "ADMIN_PASSWORD_UNCHECKABLE"),
    ])
    def test_the_lock_screen_does_not_read_a_tls_failure_as_no_internet(self, monkeypatch, cause,
                                                                        status, code):
        """Review round 2 of lane 1d: the wizard's lock screen (/auth/verify-admin-password) is
        the first call of an erase and of « Remplir » -- a TLS failure must not read « Pas
        d'Internet » there either."""
        import logging
        from types import SimpleNamespace
        from app.api import local_access_api_v2 as api_mod
        from app.api.monclub_api import MonClubApiError

        class _Api:
            def validate_statistics_password(self, **k):
                raise MonClubApiError(f"validate_statistics_password failed: {cause}") from cause
        monkeypatch.setattr("access.store.load_auth_token", lambda: SimpleNamespace(token="t"))
        sent = {}
        ctx = SimpleNamespace(body=lambda: {"password": "pw"},
                              app=SimpleNamespace(_api=lambda: _Api(), logger=logging.getLogger("t")),
                              send_json=lambda s, p: sent.update(status=s, payload=p))
        api_mod._handle_auth_verify_admin_password(ctx)
        assert (sent["status"], sent["payload"]["code"]) == (status, code), sent

    def test_the_lock_screens_generic_500_carries_a_code(self, monkeypatch):
        import logging
        from types import SimpleNamespace
        from app.api import local_access_api_v2 as api_mod

        class _Api:
            def validate_statistics_password(self, **k):
                raise KeyError("a bug")
        monkeypatch.setattr("access.store.load_auth_token", lambda: SimpleNamespace(token="t"))
        sent = {}
        ctx = SimpleNamespace(body=lambda: {"password": "pw"},
                              app=SimpleNamespace(_api=lambda: _Api(), logger=logging.getLogger("t")),
                              send_json=lambda s, p: sent.update(status=s, payload=p))
        api_mod._handle_auth_verify_admin_password(ctx)
        assert sent["status"] == 500
        assert sent["payload"]["code"] == "ADMIN_PASSWORD_CHECK_FAILED" and sent["payload"]["error"]

    def test_the_not_put_back_title_follows_the_chosen_tables(self):
        """A fingerprints-only or a rights-only erase takes less than the user: the title says
        what the refill does not give back, per the tables chosen (FR and EN)."""
        text = (REPO / "tauri-ui" / "src" / "lib" / "eraseWizardText.ts").read_text(encoding="utf-8")
        assert len(re.findall(r"notRefilledTitle: \(n: number, s: string, what: NotRefilledWhat\)",
                              text)) == 2
        dialog = (REPO / "tauri-ui" / "src" / "components" / "EraseWizardDialog.tsx").read_text(
            encoding="utf-8")
        assert re.search(r"t\.notRefilledTitle\(leftOutCount, schemeName\(leftOut\?\.scheme\), "
                         r"leftOutWhat\)", dialog)

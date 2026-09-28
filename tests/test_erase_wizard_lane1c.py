"""Lane 1c (2026-09-27): the Erase-content wizard's last fixes after the master review of lane 1b.

Guide §3.2h, §3.10. Against the same fakes as tests/test_erase_wizard.py -- nothing reaches a device:
* AGE  the owner's age limit: the member list is stale when the last SUCCESSFUL getSyncData is
       older than max(3 x the effective sync interval, 10 min), on the monotonic clock;
* C0   the people an erase removes and the refill will NOT put back (not in its roster: staff,
       cleaners, another system's users) are counted and named at step 1, need their own tick,
       are bound to the backup before the first delete, and their backup is never pruned;
* C1   the "other PCs closed" tick names what relaunches a quit Access: the watchdog task and
       the start with Windows (runbook C1 / D1);
* F1   Refill checks again, under the scheme it will push, before it releases: withheld rows and a
       stale or missing list are reported (never refused -- refusing leaves the turnstile empty),
       and a kept MB2000 administrator the refill would overwrite is refused until confirmed;
* F2   the 30-day prune does not trust the PC clock blindly: a server offset over a day skips it,
       a run dated more than a day in the future is kept, and runs are dated on the
       server-corrected clock where the PC has a measurement;
* F5   the erase's reset reaches pins known only from a result row or only from an intent row;
* F7   the live v1 heartbeat still builds when the held-count code raises.
"""
from __future__ import annotations

import json
import logging
import re
import time
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.core.erase_wizard as ew
from app.core import device_hold
from tests.test_erase_wizard import (  # noqa: F401 -- fixtures are used by name
    _body, _mb_body, _mb_setup, _pw_ok, _setup_c3, _terminal, erase_switch_on, refill_cache,
    sqlite_db,
)

REPO = Path(__file__).resolve().parents[1]


def _step1_only(panel):
    """Step 1 counts every table and reads the ``user`` list (lane 1c) -- nothing else."""
    return {c for c in panel.calls if c[0] != "count"} <= {("read", "user")}


def _preview(wiz, did):
    status, pv = wiz.preview(did)
    assert status == 200, pv
    return pv


def _synced(app, *, ago_sec, interval_sec=None):
    """The app's last successful getSyncData ``ago_sec`` ago (monotonic), no failure since."""
    app._last_sync_ok = True
    app._last_sync_ok_mono = time.monotonic() - float(ago_sec)
    if interval_sec is not None:
        app._sync_base_interval_sec = lambda: int(interval_sec)


# ─────────────────────────── AGE: the owner's age limit ───────────────────────────

class TestTheMemberListMustBeRecent:

    def test_a_fresh_list_is_not_stale(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, _p, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _synced(app, ago_sec=30, interval_sec=60)
        refill = _preview(wiz, 5)["refill"]
        assert refill["problem"] is None and refill["staleWhy"] is None
        assert refill["syncMaxAgeSec"] == 600, "max(3 x 60 s, 10 min)"
        assert 25 <= refill["lastSyncAgeSec"] <= 60
        assert wiz.start(5, _body(_preview(wiz, 5)["previewId"]), verify_password=_pw_ok)[0] == 202

    def test_an_old_success_is_stale(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, panel, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _synced(app, ago_sec=3600, interval_sec=60)
        pv = _preview(wiz, 5)
        assert pv["refill"]["problem"] == "REFILL_SOURCE_STALE"
        assert pv["refill"]["staleWhy"] == "TOO_OLD"
        assert pv["refill"]["lastSyncOk"] is True, "the heartbeat's flag is not what changed"
        status, out = wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert status == 409 and out["code"] == "REFILL_SOURCE_STALE"
        assert out["staleWhy"] == "TOO_OLD" and out["syncMaxAgeSec"] == 600
        assert out["lastSyncAgeSec"] >= 3600
        assert not device_hold.is_held(5) and wiz.status()["run"] is None
        assert not [c for c in panel.calls if c[0] == "erase"]

    def test_a_hung_sync_is_stale(self, sqlite_db, monkeypatch, tmp_path):
        """A getSyncData that never returns records no failure: ``_last_sync_ok`` stays True.
        Only the age of the last success tells it."""
        wiz, _w, _p, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _synced(app, ago_sec=11 * 60, interval_sec=60)
        app._sync_work_running = True
        pv = _preview(wiz, 5)
        assert pv["refill"]["problem"] == "REFILL_SOURCE_STALE"
        assert pv["refill"]["staleWhy"] == "TOO_OLD"
        assert wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)[1]["code"] == (
            "REFILL_SOURCE_STALE")

    @pytest.mark.parametrize("interval, ago, stale", [
        (300, 14 * 60, False),        # 5 min -> the limit is 15 min
        (300, 16 * 60, True),
        (60, 9 * 60, False),          # 1 min -> 3 min, raised to the 10-min floor
        (60, 11 * 60, True),
        (1800, 80 * 60, False),       # 30 min -> 90 min
        (1800, 95 * 60, True),
    ])
    def test_the_limit_is_three_intervals_never_under_ten_minutes(self, sqlite_db, monkeypatch,
                                                                   tmp_path, interval, ago, stale):
        wiz, _w, _p, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _synced(app, ago_sec=ago, interval_sec=interval)
        refill = _preview(wiz, 5)["refill"]
        assert refill["syncMaxAgeSec"] == max(3 * interval, 600)
        assert (refill["problem"] == "REFILL_SOURCE_STALE") is stale, refill

    def test_an_unreadable_interval_gives_the_ten_minute_floor(self, sqlite_db, monkeypatch,
                                                               tmp_path):
        wiz, _w, _p, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _synced(app, ago_sec=30)

        def _boom():
            raise RuntimeError("settings unreadable")
        app._sync_base_interval_sec = _boom
        assert _preview(wiz, 5)["refill"]["syncMaxAgeSec"] == 600

    @pytest.mark.parametrize("backend_min, cfg_sec, expected", [
        (5, 30, 900),                 # the server's agentSyncBackendRefreshMin wins: 5 min x 3
        (None, 60, 600),              # else cfg.sync_interval_sec: 3 min, raised to the floor
        (None, 400, 1200),
    ])
    def test_the_interval_is_the_one_the_app_schedules_with(self, sqlite_db, monkeypatch,
                                                            tmp_path, backend_min, cfg_sec,
                                                            expected):
        """The wizard asks the app's own ``_sync_base_interval_sec`` (app.py), the one the sync
        timer uses: the server-provided value if any, else ``cfg.sync_interval_sec``."""
        from app.ui.app import MainApp
        import app.core.settings_reader as sr
        wiz, _w, _p, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _synced(app, ago_sec=30)
        app.cfg = SimpleNamespace(sync_interval_sec=cfg_sec)
        app._sync_base_interval_sec = types.MethodType(MainApp._sync_base_interval_sec, app)
        monkeypatch.setattr(sr, "get_backend_global_settings",
                            lambda: {"agent_sync_backend_refresh_min": backend_min})
        assert _preview(wiz, 5)["refill"]["syncMaxAgeSec"] == expected

    @pytest.mark.parametrize("case, why", [
        ("never", "NO_SYNC_YET"),
        ("failed", "LAST_SYNC_FAILED"),
        ("no_stamp", "NO_SYNC_YET"),
    ])
    def test_the_other_stale_cases_say_why(self, sqlite_db, monkeypatch, tmp_path, case, why):
        wiz, _w, _p, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        if case == "never":
            app._last_sync_ok, app._last_sync_ok_mono, app._last_sync_at = False, None, None
        elif case == "failed":
            _synced(app, ago_sec=30)
            app._last_sync_ok, app._last_sync_at = False, "2026-09-27T21:00:00Z"
        else:
            app._last_sync_ok = True
            del app._last_sync_ok_mono
        refill = _preview(wiz, 5)["refill"]
        assert refill["problem"] == "REFILL_SOURCE_STALE" and refill["staleWhy"] == why

    def test_the_limit_reached_during_a_long_backup_does_not_stop_the_run(self, sqlite_db,
                                                                         monkeypatch, tmp_path):
        """The mid-run exception (owner decision): the check before the first delete looks at the
        member counts, never at the list's age -- one MB2000 backup can outlast the limit."""
        wiz, _w, panel, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        real = panel.read_table_strict

        def _read(*, table, fields="*"):
            app._last_sync_ok_mono = time.monotonic() - 7200     # the backup took two hours
            return real(table=table, fields=fields)
        panel.read_table_strict = _read
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "DONE"

    def test_the_app_stamps_the_success_on_the_monotonic_clock(self):
        """app.py: the success of a getSyncData records ``_last_sync_ok_mono`` next to
        ``_last_sync_ok = True`` -- a PC clock change cannot fake the age. Structural: the sync
        work is a closure inside ``_sync_tick`` that no test drives end to end."""
        src = (REPO / "app" / "ui" / "app.py").read_text(encoding="utf-8")
        oks = [m.start() for m in re.finditer(r"self\._last_sync_ok = True\n", src)]
        assert len(oks) == 1, "one success point"
        after = src[oks[0]:oks[0] + 200]
        assert re.search(r"self\._last_sync_ok = True\n\s+self\._last_sync_ok_mono = "
                         r"time\.monotonic\(\)\n", after), after
        assert "self._last_sync_ok_mono: Optional[float] = None" in src, "None until a success"
        # A failure leaves the stamp alone: the age of the last SUCCESS keeps growing.
        fails = [m.start() for m in re.finditer(r"self\._last_sync_ok = False\n", src)]
        assert fails and all("_last_sync_ok_mono" not in src[f:f + 120] for f in fails)


# ─────────────────────────── C1: the watchdog relaunches a quit Access ───────────────────────────

class TestTheOtherPcsTickNamesTheWatchdog:
    """``packaging/watchdog/register_watchdog.ps1`` registers 'MonClub Access Watchdog' at logon
    and every 2 min; ``monclub_access_watchdog.ps1`` starts Access again after two misses at least
    90 s apart. A quit Access on another PC comes back within minutes unless the task is
    disabled -- and the start with Windows brings it back at the next logon."""

    TASK = "Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'"

    def test_the_refusal_says_it(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        body = _body(_preview(wiz, 5)["previewId"])
        del body["otherPcsClosed"]
        status, out = wiz.start(5, body, verify_password=_pw_ok)
        assert status == 400 and out["code"] == "OTHER_PCS_NOT_CONFIRMED"
        assert self.TASK in out["error"] and "Windows" in out["error"]

    def test_the_page_says_it_in_both_languages(self):
        src = (REPO / "tauri-ui" / "src" / "lib" / "eraseWizardText.ts").read_text(encoding="utf-8")
        ticks = re.findall(r"otherPcsTick:\s*\n?\s*\"([^\"]+)\"", src)
        assert len(ticks) == 2, ticks                      # FR, then EN
        for text in ticks:
            assert self.TASK in text, text
            assert "Ouvrir MonClub Access avec Windows" in text, text
        assert "watchdog" in ticks[0] and "watchdog" in ticks[1]
        # The script names the task the tick tells the operator to disable.
        reg = (REPO / "packaging" / "watchdog" / "register_watchdog.ps1").read_text(encoding="utf-8")
        assert "[string] $TaskName = 'MonClub Access Watchdog'" in reg


# ─────────────────────────── F1: Refill checks again ───────────────────────────

def _account(monkeypatch, did, device):
    """The cutover's switch recorded: the device row and the scheme read both say ACCOUNT."""
    from tests.test_erase_wizard import _devices
    import app.core.db as dbmod
    _devices(monkeypatch, dict(device, pinScheme="ACCOUNT"))
    monkeypatch.setattr(dbmod, "get_device_pin_scheme", lambda d: "ACCOUNT")


def _refill(wiz, did, scheme, **kw):
    body = {"password": "pw", "expectedPinScheme": scheme}
    body.update(kw)
    return wiz.refill(did, body, verify_password=_pw_ok)


class TestRefillChecksAgain:

    def _c3_held(self, monkeypatch, tmp_path, sqlite_db):
        wiz, worker, panel, app = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        wiz.start(5, _body(_preview(wiz, 5)["previewId"], refill="hold"), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "DONE" and device_hold.is_held(5)
        return wiz, worker

    def test_it_reports_what_it_will_write(self, sqlite_db, monkeypatch, tmp_path):
        from tests.test_erase_wizard import _device
        wiz, _w = self._c3_held(monkeypatch, tmp_path, sqlite_db)
        _account(monkeypatch, 5, _device())
        status, out = _refill(wiz, 5, "ACCOUNT")
        assert status == 200 and not device_hold.is_held(5)
        refill = out["refill"]
        assert refill["scheme"] == "ACCOUNT" and refill["members"] == 4
        assert refill["withheld"] == 0 and refill["problem"] is None
        assert out["adminCheck"] == "NOT_APPLICABLE" and out["adminPins"] == []

    def test_withheld_rows_after_the_switch_are_reported_not_refused(self, sqlite_db, monkeypatch,
                                                                    tmp_path, refill_cache):
        """F1's scenario: the erase passed its ACCOUNT check; the switch's own sync then brought
        rows with no mainAccountId. Refill releases anyway (refusing leaves the turnstile empty)
        and says how many are withheld -- the heartbeat's count cannot name them."""
        from tests.test_erase_wizard import _device
        wiz, worker = self._c3_held(monkeypatch, tmp_path, sqlite_db)
        _account(monkeypatch, 5, _device())
        refill_cache.users.append({"userId": 15, "activeMembershipId": 103, "fullName": "No acct"})
        status, out = _refill(wiz, 5, "ACCOUNT")
        assert status == 200 and not device_hold.is_held(5)
        assert out["refill"]["withheld"] == 1 and out["refill"]["problem"] == "REFILL_WITHHELD"
        assert worker.full_sync_requests == ["erase-refill"]

    @pytest.mark.parametrize("case, problem", [
        ("stale", "REFILL_SOURCE_STALE"), ("missing", "REFILL_SOURCE_MISSING"),
        ("empty", "REFILL_SOURCE_EMPTY")])
    def test_a_list_it_cannot_trust_is_reported_not_refused(self, sqlite_db, monkeypatch, tmp_path,
                                                            refill_cache, case, problem):
        import app.core.db as dbmod
        wiz, _w = self._c3_held(monkeypatch, tmp_path, sqlite_db)
        if case == "stale":
            wiz.app._last_sync_ok_mono = time.monotonic() - 7200
        elif case == "missing":
            monkeypatch.setattr(dbmod, "load_sync_cache", lambda: None)
        else:
            refill_cache.users = []
        status, out = _refill(wiz, 5, None)          # no scheme row in these fakes: None
        assert status == 200 and not device_hold.is_held(5)
        assert out["refill"]["problem"] == problem

    def _mb_held(self, monkeypatch, tmp_path, sqlite_db):
        term = _terminal()
        wiz, worker, drv = _mb_setup(monkeypatch, tmp_path, term)
        try:
            wiz.start(8, _mb_body(_preview(wiz, 8)["previewId"]), verify_password=_pw_ok)
        finally:
            drv.disconnect()
        assert wiz.status()["run"]["state"] == "DONE" and device_hold.is_held(8)
        return wiz, worker

    def test_an_admin_the_refill_would_overwrite_is_refused_until_confirmed(self, sqlite_db,
                                                                         monkeypatch, tmp_path,
                                                                         refill_cache):
        """C4 at Refill: the terminal kept administrator 1; after the switch a member's account
        number is 1, so the refill would write that member over the admin, privilege 0."""
        import app.core.db as dbmod
        from tests.test_erase_wizard import _device
        wiz, worker = self._mb_held(monkeypatch, tmp_path, sqlite_db)
        _account(monkeypatch, 8, _device(did=8, name="Sortie", ip="192.168.1.247",
                                         proto="ZK_STANDALONE"))
        refill_cache.users.append({"userId": 16, "activeMembershipId": 30003, "mainAccountId": 1,
                                   "fullName": "Member one"})
        reset = []
        real = dbmod.invalidate_device_records
        monkeypatch.setattr(dbmod, "invalidate_device_records",
                            lambda **kw: reset.append(kw) or real(**kw))
        for confirm in (None, [], ["2"]):
            kw = {} if confirm is None else {"confirmAdminPins": confirm}
            status, out = _refill(wiz, 8, "ACCOUNT", **kw)
            assert status == 409 and out["code"] == "ADMIN_PIN_IN_ROSTER", (confirm, out)
            assert out["adminPins"] == ["1"] and out["pinScheme"] == "ACCOUNT"
        assert device_hold.is_held(8) and reset == [] and worker.full_sync_requests == []
        status, out = _refill(wiz, 8, "ACCOUNT", confirmAdminPins=["1"])
        assert status == 200 and not device_hold.is_held(8)
        assert out["adminPins"] == ["1"] and out["adminCheck"] == "CHECKED"

    def test_no_clash_no_question(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w = self._mb_held(monkeypatch, tmp_path, sqlite_db)
        status, out = _refill(wiz, 8, None)          # no scheme row in these fakes: None
        assert status == 200 and out["adminPins"] == [] and out["adminCheck"] == "CHECKED"

    def test_a_c3_without_its_device_row_is_not_an_admin_warning(self, sqlite_db, monkeypatch,
                                                                 tmp_path):
        """Review round 1 (lane 1c): with the device row gone the protocol is read from the hold's
        backup -- a C3 has no administrators, so no « could not be checked » warning."""
        from tests.test_erase_wizard import _devices
        wiz, _w = self._c3_held(monkeypatch, tmp_path, sqlite_db)
        _devices(monkeypatch)                       # no device row any more
        status, out = _refill(wiz, 5, None)
        assert status == 200 and out["adminCheck"] == "NOT_APPLICABLE"
        assert out["refill"]["problem"] == "REFILL_SOURCE_MISSING"

    def test_an_unreadable_backup_is_a_warning(self, sqlite_db, monkeypatch, tmp_path):
        """A held turnstile's backup is never pruned; if it still cannot be read, the admins
        cannot be checked -- said, not refused (the turnstile would stay empty)."""
        import shutil
        wiz, _w = self._mb_held(monkeypatch, tmp_path, sqlite_db)
        shutil.rmtree(_run_dir(wiz))
        status, out = _refill(wiz, 8, None)          # no scheme row in these fakes: None
        assert status == 200 and not device_hold.is_held(8)
        assert out["adminCheck"] == "UNREADABLE" and out["adminPins"] == []

    def test_a_scheme_switched_mid_run_is_checked_under_the_new_scheme(self, sqlite_db,
                                                                       monkeypatch, tmp_path,
                                                                       refill_cache):
        """F1's now/auto case: the switch lands during the run, the run keeps the hold
        (PIN_SCHEME_CHANGED) -- it was only ever checked under MEMBERSHIP. Refill checks the
        new scheme."""
        from tests.test_erase_wizard import _device
        import app.core.db as dbmod
        wiz, worker, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)

        def _switch(table):                          # once per erased table: idempotent
            _account(monkeypatch, 5, _device())
            if not any(u["userId"] == 15 for u in refill_cache.users):
                refill_cache.users.append({"userId": 15, "activeMembershipId": 103})
        panel.on_erase = _switch
        wiz.start(5, _body(pv["previewId"], refill="now"), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "DONE" and run["holdKept"] is True
        assert dbmod.get_device_pin_scheme(5) == "ACCOUNT"
        status, out = _refill(wiz, 5, "ACCOUNT")
        assert status == 200 and out["refill"]["withheld"] == 1


# ─────────────────────────── F2: the prune and the clock ───────────────────────────

class _Clock:
    """A server clock the PC measured: ``offset`` (server - PC), ``now`` the corrected time."""

    def __init__(self, offset, now=None):
        self._offset, self._now = float(offset), now

    def has_sample(self):
        return True

    def offset(self):
        return self._offset

    def now(self):
        return (time.time() + self._offset) if self._now is None else float(self._now)


def _folder(root, run_id, did=5, *, recorded=None, mtime=None, state="DONE"):
    """A run folder. ``recorded``: the lane-1c epochs in run.json (startedAtEpoch,
    writtenAtEpoch); ``mtime``: every file's modification time."""
    import os
    folder = root / f"{run_id}_device{did}"
    folder.mkdir(parents=True)
    (folder / "backup.json").write_text("{}", encoding="utf-8")
    rec = {"state": state}
    if recorded is not None:
        rec.update(startedAtEpoch=recorded, writtenAtEpoch=recorded, clockCorrected=True)
    (folder / "run.json").write_text(json.dumps(rec), encoding="utf-8")
    if mtime is not None:
        for f in folder.iterdir():
            os.utime(f, (mtime, mtime))
    return folder


class TestThePruneAndTheClock:

    @pytest.fixture(autouse=True)
    def _no_clock(self, monkeypatch):
        from app.core.v2 import server_clock
        monkeypatch.setattr(server_clock, "_default", None)
        monkeypatch.setattr(ew, "_NO_RUN_BEFORE", "20000101")

    @staticmethod
    def _run_id(days_ago):
        return time.strftime("%Y%m%d-%H%M%S", time.localtime(time.time() - days_ago * 86400)) + "-abcdef"

    def test_a_pc_clock_a_year_ahead_the_server_knows_about_deletes_nothing(self, sqlite_db,
                                                                         monkeypatch, tmp_path,
                                                                         caplog):
        """Scenario (a): the PC clock set a year forward. With a server measurement the offset
        says so, and nothing is pruned -- not even a folder that looks 400 days old."""
        from app.core.v2 import server_clock
        root = tmp_path / "b"
        folder = _folder(root, self._run_id(45), mtime=time.time() - 45 * 86400)
        monkeypatch.setattr(server_clock, "_default", _Clock(offset=-365 * 86400))
        with caplog.at_level(logging.WARNING):
            assert ew.prune_erase_backups(root) == []
        assert folder.exists() and "off the server" in caplog.text

    @pytest.mark.parametrize("offset_h, pruned", [(23, True), (25, False)])
    def test_the_limit_is_one_day(self, sqlite_db, monkeypatch, tmp_path, offset_h, pruned):
        from app.core.v2 import server_clock
        root = tmp_path / "b"
        folder = _folder(root, self._run_id(45), mtime=time.time() - 45 * 86400)
        monkeypatch.setattr(server_clock, "_default", _Clock(offset=-offset_h * 3600))
        assert (ew.prune_erase_backups(root) != []) is pruned
        assert folder.exists() is not pruned

    def test_now_is_the_server_corrected_time(self, sqlite_db, monkeypatch, tmp_path):
        """The PC clock 20 h behind (under the limit): a folder the PC dates 29.5 days old is
        30.3 days old on the server's clock -- it goes."""
        from app.core.v2 import server_clock
        root = tmp_path / "b"
        folder = _folder(root, self._run_id(29.5), mtime=time.time() - 29.5 * 86400)
        monkeypatch.setattr(server_clock, "_default", _Clock(offset=20 * 3600))
        assert ew.prune_erase_backups(root) == [folder.name.split("_device")[0]]

    def test_a_run_dated_more_than_a_day_ahead_is_kept(self, sqlite_db, tmp_path, caplog):
        """A folder dated in the future was written by a clock ahead of this one: its age cannot
        be told -- kept, and the others are pruned as usual."""
        root = tmp_path / "b"
        ahead = _folder(root, self._run_id(45), recorded=time.time() + 3 * 86400)
        old = _folder(root, self._run_id(46), recorded=time.time() - 46 * 86400)
        with caplog.at_level(logging.WARNING):
            deleted = ew.prune_erase_backups(root)
        assert ahead.exists() and not old.exists() and len(deleted) == 1
        assert "in the future" in caplog.text

    def test_the_recorded_times_win_over_the_file_times(self, sqlite_db, tmp_path):
        """Scenario (b): the PC clock was behind when the files were written (their mtimes look
        45 days old), but the run was dated on the corrected clock 5 days ago: kept."""
        root = tmp_path / "b"
        folder = _folder(root, self._run_id(45), recorded=time.time() - 5 * 86400,
                         mtime=time.time() - 45 * 86400)
        assert ew.prune_erase_backups(root) == [] and folder.exists()

    def test_a_run_and_a_refill_record_the_corrected_time(self, sqlite_db, monkeypatch, tmp_path):
        from app.core.v2 import server_clock
        monkeypatch.setattr(server_clock, "_default", _Clock(offset=0, now=1_900_000_000.0))
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        wiz.start(5, _body(_preview(wiz, 5)["previewId"], refill="hold"), verify_password=_pw_ok)
        rec = json.loads((_run_dir(wiz) / "run.json").read_text(encoding="utf-8"))
        assert rec["startedAtEpoch"] == 1_900_000_000.0 and rec["clockCorrected"] is True
        assert rec["writtenAtEpoch"] == 1_900_000_000.0
        status, _ = wiz.refill(5, {"password": "pw", "expectedPinScheme": None},
                               verify_password=_pw_ok)
        assert status == 200
        mark = json.loads((_run_dir(wiz) / ew.REFILLED_MARK).read_text(encoding="utf-8"))
        assert mark["at"] == 1_900_000_000.0 and mark["corrected"] is True

    def test_a_lane_1b_mark_still_counts_by_its_file_time(self, sqlite_db, tmp_path):
        """Folders written before lane 1c keep the old rule: the run id and every file's time."""
        import os
        root = tmp_path / "b"
        folder = _folder(root, self._run_id(45), mtime=time.time() - 45 * 86400)
        (folder / ew.REFILLED_MARK).write_text("2026-09-27 21:00:00", encoding="utf-8")
        recent = time.time() - 2 * 86400
        os.utime(folder / ew.REFILLED_MARK, (recent, recent))
        assert ew.prune_erase_backups(root) == [] and folder.exists()


# ─────────────────────────── F5 / F7 / a review nit: regression tests ───────────────────────────

def _results(db, did):
    return {p: (r[0], r[3]) for p, r in db.list_push_results(device_id=did).items()}


class TestRegressionGuards:

    def test_the_erase_resets_pins_known_only_from_a_result_or_an_intent_row(self, sqlite_db,
                                                                            monkeypatch, tmp_path):
        """F5: every earlier test seeded its pins through a sync-state row, so narrowing
        ``begin_device_erase``'s pin query to that table passed them all. 999 has only a result
        row (its state and intent rows gone, as ``delete_device_sync_state`` leaves it); 888 only
        an intent row (one written before lane 1 had no result row)."""
        sqlite_db.record_push_results(device_id=5, rows=[("999", True, None)])
        sqlite_db.record_push_intents(device_id=5, rows=[("888", "Name", "8880", "h")],
                                      protocol="ZK_PULLSDK")
        sqlite_db._run_db_write_sync("test_drop_result", lambda conn, profile: conn.execute(
            "DELETE FROM device_push_result WHERE device_id=5 AND pin='888'").rowcount)
        assert _results(sqlite_db, 5) == {"999": (True, None)}
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        panel.refuse_erase = {"user"}
        wiz.start(5, _body(_preview(wiz, 5)["previewId"], forget=False), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "INCOMPLETE"
        got = sqlite_db.list_push_results(device_id=5)
        for pin in ("999", "888"):
            ok, at, _corrected, err = got[pin]
            assert ok is None and err is None and at is not None, (pin, got.get(pin))

    @pytest.mark.parametrize("breaks", ["refill_roster", "is_held", "peek_sync_cache",
                                        "report_held"])
    def test_the_heartbeat_builds_when_the_held_count_raises(self, sqlite_db, monkeypatch,
                                                            refill_cache, breaks):
        """F7: the v1 heartbeat is live for every gym; a PC whose payload raises sends nothing
        and looks silent. Whatever the held-turnstile code raises, every line still goes."""
        import access.pc_identity as pci
        import app.core.db as dbmod
        from tests.test_erase_wizard import _device
        refill_cache.devices = [_device(did=5), _device(did=6, name="B")]
        monkeypatch.setattr(dbmod, "peek_sync_cache", lambda: refill_cache)
        snap = {5: {"connected": True, "failed_pins": 2}, 6: {"connected": True, "failed_pins": 0}}
        app = SimpleNamespace(
            _update_manager=SimpleNamespace(get_current_version=lambda: "9.9.9"),
            _agent_engine=SimpleNamespace(get_status_snapshot=lambda: {}),
            _ultra_engine=SimpleNamespace(get_status=lambda: {"devices": snap}),
            _last_sync_at=None, _last_sync_ok=True)
        device_hold.hold(5, reason="erase", run_id="r")

        def _boom(*a, **k):
            raise RuntimeError(f"{breaks} failed")
        if breaks == "refill_roster":
            monkeypatch.setattr(ew, "refill_roster", _boom)
        elif breaks == "is_held":
            monkeypatch.setattr(device_hold, "is_held", _boom)
        elif breaks == "peek_sync_cache":
            monkeypatch.setattr(dbmod, "peek_sync_cache", _boom)
        else:
            monkeypatch.setattr(pci, "_report_held_turnstiles", _boom)
        payload = pci.build_heartbeat_payload(app)
        lines = {t["gymDeviceId"]: t for t in payload["turnstiles"]}
        assert set(lines) == {5, 6}, payload
        assert lines[6]["failedPins"] == 0 and "held" not in lines[6]
        if breaks in ("refill_roster", "peek_sync_cache"):
            assert lines[5]["held"] is True and lines[5]["failedPins"] == 2, "the worker's figure"

    @pytest.mark.parametrize("case, status, code", [
        ("no_password", 400, "ADMIN_PASSWORD_REQUIRED"),
        ("no_token", 401, "PC_NOT_SIGNED_IN"),
        ("wrong", 401, "ADMIN_PASSWORD"),
        ("http_502", 502, "ADMIN_PASSWORD_CHECK_FAILED"),
    ])
    def test_the_lock_screens_route_answers_with_a_code(self, monkeypatch, case, status, code):
        """Review F6: the wizard's lock screen calls /auth/verify-admin-password, whose answers
        had no code but offline -- the page showed the server's French text on the English page.
        The statuses and texts stay (the Local DB page reads them); each answer gains a code."""
        from app.api import local_access_api_v2 as api_mod
        from app.api.monclub_api import MonClubApiHttpError

        class _Api:
            def validate_statistics_password(self, **k):
                if case == "http_502":
                    raise MonClubApiHttpError("validate_statistics_password: HTTP 502",
                                              status_code=502)
                return False

        monkeypatch.setattr("access.store.load_auth_token",
                            lambda: None if case == "no_token" else SimpleNamespace(token="t"))
        sent = {}
        ctx = SimpleNamespace(body=lambda: {"password": "" if case == "no_password" else "pw"},
                              app=SimpleNamespace(_api=lambda: _Api(), logger=logging.getLogger("t")),
                              send_json=lambda s, p: sent.update(status=s, payload=p))
        api_mod._handle_auth_verify_admin_password(ctx)
        assert sent["status"] == status and sent["payload"]["code"] == code
        assert sent["payload"]["ok"] is False and sent["payload"]["error"]

    def test_a_member_list_gone_before_the_first_delete_stops_the_run(self, sqlite_db,
                                                                      monkeypatch, tmp_path):
        """Review nit: the re-check's REFILL_SOURCE_MISSING branch had no test."""
        import app.core.db as dbmod
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        real = panel.read_table_strict

        def _read(*, table, fields="*"):
            monkeypatch.setattr(dbmod, "load_sync_cache", lambda: None)
            return real(table=table, fields=fields)
        panel.read_table_strict = _read
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "REFILL_SOURCE_MISSING" in run["error"]
        assert not [c for c in panel.calls if c[0] == "erase"] and not device_hold.is_held(5)


# ─────────────────────────── C0: the people the refill will not put back ───────────────────────────

def _staff_panel():
    """The default C3 (members 101 and 102, both in the refill roster) plus a cleaner enrolled
    directly on the panel -- a pin MonClub never wrote and will never write back."""
    from tests.test_erase_wizard import _panel
    panel = _panel()
    panel.tables["user"].append({"Pin": "555", "CardNo": "5550", "Name": "Cleaner Zied"})
    panel.tables["userauthorize"].append({"Pin": "555", "AuthorizeDoorId": "15"})
    return panel


def _run_dir(wiz):
    run = wiz.status()["run"]
    return Path(wiz.backup_root()) / f"{run['runId']}_device{run['deviceId']}"


class TestPeopleTheRefillWillNotPutBack:

    def test_step_1_names_who_will_not_be_put_back_on_a_c3(self, sqlite_db, monkeypatch,
                                                           tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        pv = _preview(wiz, 5)
        assert pv["notRefilled"] == {"count": 1, "scheme": "MEMBERSHIP",
                                     "people": [{"pin": "555", "name": "Cleaner Zied"}]}
        assert ("read", "user") in panel.calls and _step1_only(panel), panel.calls
        assert not device_hold.is_held(5)

    def test_nobody_left_out_is_a_zero_and_needs_no_tick(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        assert pv["notRefilled"] == {"count": 0, "scheme": "MEMBERSHIP", "people": []}
        assert wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)[0] == 202
        run = wiz.status()["run"]
        assert run["state"] == "DONE" and run["notRefilled"] == {"count": 0, "pins": []}
        assert not (_run_dir(wiz) / ew.KEEP_MARK).exists()

    def test_the_mb2000_admins_are_not_counted(self, sqlite_db, monkeypatch, tmp_path):
        """The fake MB2000: admin 1 (kept by the erase), members 30001/30002 (in the roster) and
        777, "Old system" -- another system's user, removed by a users erase, never refilled."""
        wiz, _w, drv = _mb_setup(monkeypatch, tmp_path, _terminal())
        try:
            pv = _preview(wiz, 8)
        finally:
            drv.disconnect()
        assert pv["notRefilled"] == {"count": 1, "scheme": "MEMBERSHIP",
                                     "people": [{"pin": "777", "name": "Old system"}]}

    def test_an_erase_needs_the_tick_when_someone_will_not_come_back(self, sqlite_db,
                                                                    monkeypatch, tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        pv = _preview(wiz, 5)
        for tick in (None, False, "yes"):
            body = _body(pv["previewId"])
            if tick is not None:
                body["acceptNotRefilled"] = tick
            status, out = wiz.start(5, body, verify_password=_pw_ok)
            assert status == 409 and out["code"] == "NOT_REFILLED_UNCONFIRMED", (tick, out)
            assert out["count"] == 1
        assert not device_hold.is_held(5) and _step1_only(panel)
        status, _ = wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True),
                              verify_password=_pw_ok)
        assert status == 202
        run = wiz.status()["run"]
        assert run["state"] == "DONE" and run["notRefilled"] == {"count": 1, "pins": ["555"]}
        assert panel.tables["user"] == [], "erased, as the operator accepted"

    def test_a_backup_holding_people_left_out_is_kept_and_named_nowhere(self, sqlite_db,
                                                                        monkeypatch, tmp_path,
                                                                        caplog):
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        pv = _preview(wiz, 5)
        with caplog.at_level(logging.DEBUG):
            wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        folder = _run_dir(wiz)
        mark = folder / ew.KEEP_MARK
        assert mark.exists() and "555" in mark.read_text(encoding="utf-8")
        assert "Cleaner" not in mark.read_text(encoding="utf-8")
        assert "Cleaner" not in (folder / "run.json").read_text(encoding="utf-8")
        assert "Cleaner" not in caplog.text, "names reach the page only (review F29)"
        assert "Cleaner Zied" in (folder / "backup.json").read_text(encoding="utf-8")

    def test_the_mark_is_on_disk_before_the_first_delete(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        seen = []
        panel.on_erase = lambda table: seen.append((_run_dir(wiz) / ew.KEEP_MARK).exists())
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        assert seen and all(seen), seen

    def test_a_mark_that_cannot_be_written_erases_nothing(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        real = ew._write_file_durably

        def _write(path, data):
            if Path(path).name == ew.KEEP_MARK:
                raise OSError("disk full")
            return real(path, data)
        monkeypatch.setattr(ew, "_write_file_durably", _write)
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        run = wiz.status()["run"]
        # Lane 1e (master review F8): the mark now comes AFTER the erase record. Lane 1f (review
        # C2): its failure puts that record back, so the run ends FAILED and released again, as
        # lane 1c's order did -- nothing erased (lane 1e ended it INCOMPLETE and held).
        assert run["state"] == "FAILED" and run["error"].startswith("KEEP_MARK_NOT_WRITTEN:")
        assert not [c for c in panel.calls if c[0] == "erase"] and not device_hold.is_held(5)

    def test_someone_new_outside_the_roster_at_the_backup_stops_the_run(self, sqlite_db,
                                                                       monkeypatch, tmp_path):
        """Bound to the backup: a person the operator was not shown -- enrolled on the panel after
        step 1 -- is never erased unseen."""
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        pv = _preview(wiz, 5)
        panel.tables["user"].append({"Pin": "556", "CardNo": "5560", "Name": "Guard Amine"})
        wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "NOT_REFILLED_CHANGED" in run["error"], run["error"]
        assert "Guard" not in run["error"]
        assert not [c for c in panel.calls if c[0] == "erase"] and not device_hold.is_held(5)
        assert not (_run_dir(wiz) / ew.KEEP_MARK).exists(), "nothing erased: prunable as usual"

    def test_a_member_who_left_the_roster_since_step_1_does_not_stop_it(self, sqlite_db,
                                                                         monkeypatch, tmp_path,
                                                                         refill_cache):
        """Review round 1 (lane 1c): a member whose right ended since step 1 -- the midnight date
        flip during a long MB2000 backup -- left MonClub's roster; a normal pass would remove them
        too. They were not "someone MonClub cannot put back", so the run goes on; they still count
        as not put back, and their backup is kept."""
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        assert pv["notRefilled"]["count"] == 0
        refill_cache.users = [u for u in refill_cache.users if u["activeMembershipId"] != 102]
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "DONE", run.get("error")
        assert run["notRefilled"] == {"count": 1, "pins": ["102"]}
        assert (_run_dir(wiz) / ew.KEEP_MARK).exists()

    def test_a_scheme_switched_since_step_1_stops_the_run_before_any_delete(self, sqlite_db,
                                                                            monkeypatch, tmp_path):
        """Review round 2 (lane 1c): the step-1 roster excuses its own pins only under the scheme
        it was read with. A « Par personne » switch saved during the backup makes every old pin
        look outside the roster -- counting them all "not put back" (and keeping the backup for
        good) would be wrong: the run stops before any delete instead."""
        from tests.test_erase_wizard import _device
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        real = panel.read_table_strict

        def _read(*, table, fields="*"):
            _account(monkeypatch, 5, _device())          # the switch lands during the backup
            return real(table=table, fields=fields)
        panel.read_table_strict = _read
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "PIN_SCHEME_CHANGED" in run["error"], run["error"]
        assert not [c for c in panel.calls if c[0] == "erase"]
        assert run["notRefilled"] is None
        assert not (_run_dir(wiz) / ew.KEEP_MARK).exists()
        # Review round 3: nothing erased, but the terminal still holds every OLD pin -- releasing
        # would push the new scheme onto it at once. Kept on hold, no pass asked: « Remplir ».
        assert device_hold.is_held(5) and run["holdKept"] is True
        assert "erase-released" not in _w.full_sync_requests
        note = [s for s in run["steps"] if s["step"] == "finish"][0]["note"]
        assert note.startswith("HELD_SCHEME_MOVED:"), "its own note: not 'press Refill'"

    def test_any_failure_before_the_first_delete_after_a_switch_keeps_the_hold(
            self, sqlite_db, monkeypatch, tmp_path, refill_cache):
        """Review round 3: the same for every stop before the first delete once the scheme moved
        since the run's start -- here a now/auto run whose re-check finds withheld rows under the
        new scheme. The run's own rule at its end (_refill: PIN_SCHEME_CHANGED keeps the hold)."""
        from tests.test_erase_wizard import _device
        wiz, worker, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        real = panel.read_table_strict

        def _read(*, table, fields="*"):
            _account(monkeypatch, 5, _device())
            if not any(u["userId"] == 15 for u in refill_cache.users):
                refill_cache.users.append({"userId": 15, "activeMembershipId": 103})
            return real(table=table, fields=fields)
        panel.read_table_strict = _read
        wiz.start(5, _body(pv["previewId"], refill="now"), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "REFILL_WITHHELD" in run["error"], run["error"]
        assert not [c for c in panel.calls if c[0] == "erase"]
        assert device_hold.is_held(5) and "erase-released" not in worker.full_sync_requests

    def test_a_switch_between_step_1_and_start_is_refused_at_start(self, sqlite_db, monkeypatch,
                                                                    tmp_path):
        """Review round 4: a switch saved while the operator is on steps 2-4 makes the run's own
        start scheme the new one, so the in-run rule could not see it. START refuses it, nothing
        held, no pass asked -- step 1 is read again."""
        from tests.test_erase_wizard import _device
        wiz, worker, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        panel.calls.clear()
        _account(monkeypatch, 5, _device())
        status, out = wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert status == 409 and out["code"] == "PIN_SCHEME_CHANGED", out
        assert out["pinScheme"] == "ACCOUNT" and out["previewScheme"] == "MEMBERSHIP"
        assert not device_hold.is_held(5) and wiz.status()["run"] is None
        assert panel.calls == [] and worker.full_sync_requests == []
        # A rehearsal erases nothing: not refused.
        status, _ = wiz.start(5, _body(pv["previewId"], backupOnly=True), verify_password=_pw_ok)
        assert status == 202

    def test_a_switch_landing_between_starts_two_reads_is_refused_too(self, sqlite_db,
                                                                       monkeypatch, tmp_path):
        """Review round 5 nit: start() read the device row, then the strict scheme; a switch saved
        between the two would pass the step-1 comparison (old row) and make the run's start
        scheme the new one. The refill check re-reads the row after the scheme read."""
        from tests.test_erase_wizard import _device
        wiz, worker, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        real = wiz._pin_scheme_strict

        def _switch_then_read(did):
            _account(monkeypatch, 5, _device())          # the switch lands between the reads
            return real(did)
        monkeypatch.setattr(wiz, "_pin_scheme_strict", _switch_then_read)
        status, out = wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert status == 409 and out["code"] == "PIN_SCHEME_CHANGED", out
        assert not device_hold.is_held(5) and worker.full_sync_requests == []

    def test_a_scheme_that_does_not_read_after_a_stop_keeps_the_hold_with_its_own_note(
            self, sqlite_db, monkeypatch, tmp_path, refill_cache):
        """Review round 4 nit: an unreadable scheme is not "moved" -- its own note."""
        import app.core.db as dbmod
        wiz, worker, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
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
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "REFILL_SOURCE_EMPTY" in run["error"]
        assert device_hold.is_held(5) and "erase-released" not in worker.full_sync_requests
        note = [s for s in run["steps"] if s["step"] == "finish"][0]["note"]
        assert note.startswith("HELD_SCHEME_UNREADABLE:"), note

    def test_a_failure_with_the_scheme_unchanged_still_releases(self, sqlite_db, monkeypatch,
                                                                tmp_path, refill_cache):
        wiz, worker, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        real = panel.read_table_strict

        def _read(*, table, fields="*"):
            refill_cache.users = []
            return real(table=table, fields=fields)
        panel.read_table_strict = _read
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "REFILL_SOURCE_EMPTY" in run["error"]
        assert not device_hold.is_held(5) and worker.full_sync_requests == ["erase-released"]

    def test_a_member_of_step_1_does_not_cover_a_new_stranger(self, sqlite_db, monkeypatch,
                                                              tmp_path, refill_cache):
        """The step-1 roster excuses only its own pins: a person enrolled on the panel since step
        1 still stops the run, even while members leave the roster."""
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        pv = _preview(wiz, 5)
        refill_cache.users = [u for u in refill_cache.users if u["activeMembershipId"] != 102]
        panel.tables["user"].append({"Pin": "556", "CardNo": "5560", "Name": "Guard Amine"})
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "NOT_REFILLED_CHANGED" in run["error"]
        assert "556" in run["error"] and "102" not in run["error"]
        assert not [c for c in panel.calls if c[0] == "erase"]

    def test_someone_who_left_the_panel_meanwhile_does_not_stop_it(self, sqlite_db, monkeypatch,
                                                                    tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        pv = _preview(wiz, 5)
        panel.tables["user"] = [r for r in panel.tables["user"] if r["Pin"] != "555"]
        wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "DONE" and run["notRefilled"] == {"count": 0, "pins": []}

    def test_a_c3_rights_only_erase_reads_the_user_list_again(self, sqlite_db, monkeypatch,
                                                              tmp_path):
        """Without the ``user`` table the backup holds no user rows: the list is read again
        before the first delete (the cleaner keeps a user row but loses the door rights)."""
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        pv = _preview(wiz, 5)
        panel.calls.clear()
        wiz.start(5, _body(pv["previewId"], tables=["userauthorize"], forget=False, refill="now",
                           acceptNotRefilled=True), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "DONE" and run["notRefilled"] == {"count": 1, "pins": ["555"]}
        reads = [c for c in panel.calls if c[0] == "read"]
        assert reads == [("read", "userauthorize"), ("read", "user")], reads

    def test_an_unreadable_list_refuses_the_erase_not_the_rehearsal(self, sqlite_db, monkeypatch,
                                                                    tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        real = panel.read_table_strict

        def _read(*, table, fields="*"):
            if table == "user" and not wiz.status()["running"]:
                raise RuntimeError("GetDeviceData FAILED rc=-2")
            return real(table=table, fields=fields)
        panel.read_table_strict = _read
        pv = _preview(wiz, 5)
        assert pv["notRefilled"] is None
        status, out = wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True),
                                verify_password=_pw_ok)
        assert status == 409 and out["code"] == "NOT_REFILLED_UNKNOWN"
        assert not device_hold.is_held(5)
        panel.read_table_strict = real
        status, _ = wiz.start(5, _body(pv["previewId"], backupOnly=True), verify_password=_pw_ok)
        assert status == 202 and wiz.status()["run"]["state"] == "DONE"

    def test_a_rehearsal_needs_no_tick(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        pv = _preview(wiz, 5)
        assert wiz.start(5, _body(pv["previewId"], backupOnly=True),
                         verify_password=_pw_ok)[0] == 202
        assert not (_run_dir(wiz) / ew.KEEP_MARK).exists(), "nothing erased"

    def test_the_mb2000_users_erase_is_bound_too(self, sqlite_db, monkeypatch, tmp_path):
        term = _terminal()
        wiz, _w, drv = _mb_setup(monkeypatch, tmp_path, term)
        try:
            pv = _preview(wiz, 8)
            body = _mb_body(pv["previewId"])
            body.pop("acceptNotRefilled", None)
            status, out = wiz.start(8, body, verify_password=_pw_ok)
            assert status == 409 and out["code"] == "NOT_REFILLED_UNCONFIRMED"
            status, _ = wiz.start(8, _mb_body(pv["previewId"], acceptNotRefilled=True),
                                  verify_password=_pw_ok)
        finally:
            drv.disconnect()
        run = wiz.status()["run"]
        assert status == 202 and run["state"] == "DONE", run.get("error")
        assert run["notRefilled"] == {"count": 1, "pins": ["777"]}
        assert (_run_dir(wiz) / ew.KEEP_MARK).exists()


class TestTheirBackupIsNeverPruned:

    @staticmethod
    def _old_run(root, run_id="20260902-100000-abcdef", did=5, *, mark=True, run_json=True):
        import os
        folder = root / f"{run_id}_device{did}"
        folder.mkdir(parents=True)
        (folder / "backup.json").write_text("{}", encoding="utf-8")
        (folder / "run.json").write_text(json.dumps({"state": "DONE"}) if run_json else "{not json",
                                         encoding="utf-8")
        if mark:
            (folder / ew.KEEP_MARK).write_text('{"count": 1, "pins": ["555"]}', encoding="utf-8")
        old = time.time() - 90 * 86400
        for f in folder.iterdir():
            os.utime(f, (old, old))
        return folder

    @pytest.mark.parametrize("run_json", [True, False])
    def test_a_marked_folder_is_never_deleted(self, sqlite_db, tmp_path, run_json):
        root = tmp_path / "b"
        kept = self._old_run(root, run_json=run_json)
        gone = self._old_run(root, run_id="20260902-110000-abcdef", mark=False)
        deleted = ew.prune_erase_backups(root, now=time.time() + 60 * 86400)
        assert kept.exists() and not gone.exists(), deleted
        assert deleted == ["20260902-110000-abcdef"]

    def test_a_failed_run_drops_its_mark(self, sqlite_db, monkeypatch, tmp_path):
        """The mark goes on disk before the erase is recorded; a run that then fails before any
        delete erased nobody, so its backup is prunable as usual."""
        def _fails(*a, **k):
            raise RuntimeError("disk I/O error")
        monkeypatch.setattr(ew, "_begin_erase", _fails)
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        run = wiz.status()["run"]
        assert run["state"] == "FAILED" and "RESULTS_NOT_RESET" in run["error"]
        assert not (_run_dir(wiz) / ew.KEEP_MARK).exists()
        assert not [c for c in panel.calls if c[0] == "erase"]

    def test_an_incomplete_run_keeps_its_mark(self, sqlite_db, monkeypatch, tmp_path):
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db, panel=_staff_panel())
        panel.refuse_erase = {"user"}
        pv = _preview(wiz, 5)
        wiz.start(5, _body(pv["previewId"], acceptNotRefilled=True), verify_password=_pw_ok)
        assert wiz.status()["run"]["state"] == "INCOMPLETE"
        assert (_run_dir(wiz) / ew.KEEP_MARK).exists()

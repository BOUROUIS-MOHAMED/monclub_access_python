"""Lane 1c (2026-09-27): the Erase-content wizard's last fixes after the master review of lane 1b.

Guide §3.2h, §3.10. Against the same fakes as tests/test_erase_wizard.py -- nothing reaches a device:
* AGE  the owner's age limit: the member list is stale when the last SUCCESSFUL getSyncData is
       older than max(3 x the effective sync interval, 10 min), on the monotonic clock;
"""
from __future__ import annotations

import re
import time
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.core.erase_wizard as ew
from app.core import device_hold
from tests.test_erase_wizard import (  # noqa: F401 -- fixtures are used by name
    _body, _pw_ok, _setup_c3, erase_switch_on, refill_cache, sqlite_db,
)

REPO = Path(__file__).resolve().parents[1]


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

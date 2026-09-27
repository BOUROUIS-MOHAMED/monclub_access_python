"""P3b-1 part C: the app wiring of the local date flips (plan docs/plans/2026-09-19_p3b1_power_on_dates.md
§2, §4, §5).

What is pinned here, and only here:

* ``MonClubApi.get_sync_data`` asks for protocol 2 on every request and stamps the PC time the
  answer arrived (``_clientReceivedAtEpoch``, the save measures the clock skew from it);
* ``MainApp._apply_date_flips`` -- what the app does around ``db.apply_local_date_flips``: the
  telemetry (DATE_FLIP / CLOCK_SUSPECT / CLOCK_OK / DATE_FLIP_FAILED), the cache resets, the ULTRA
  full pass (not in manual-sync mode), the one 00:17 first-day sync, and the lock;
* the triggers: ``MainApp.__init__`` (before the first sync tick, i.e. before any device worker),
  the 60 s tick, the 00:00:05 one-shot, ``_sync_tick``'s ``work()`` (before the fetch, after both
  saves), the fast patch, the enrolment fallback sync and the heartbeat;
* the member-cache self-heal counts held rows (``db.count_member_cache_rows``);
* one end-to-end pass through the real temp database: a v2 answer saved by ``work()``, then a
  power-on the next morning holds the expired member, promotes the starter and asks ULTRA.

Every database is a temp file (``app.core.db._DB_PATH``); nothing here reaches the network.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

import app.core.db as dbmod
import app.ui.app as app_module
from app.api.monclub_api import ApiEndpoints, MonClubApi
from app.core import access_dates
from app.ui.app import MainApp
from tests.test_sync_retry_and_rerun import _CapturedThread, _Harness

OFFSET = 3600  # Africa/Tunis, as syncMeta.serverTime carries it


def _epoch(iso: str) -> float:
    return datetime.fromisoformat(iso).timestamp()


SERVER_EPOCH = _epoch("2026-09-19T10:00:00+01:00")


# ================================================================== helpers
def _result(**over: Any) -> Dict[str, Any]:
    """The shape db.apply_local_date_flips returns (its docstring's keys)."""
    out: Dict[str, Any] = {
        "gym_date": "2026-09-20", "pc_date": "2026-09-20", "applied_before": "2026-09-19",
        "held": 0, "restored": 0, "promoted": 0, "moved": 0, "hold_reasons": {}, "starters": [],
        "clock_suspect": False, "clock_reason": "", "clock_changed": False,
        "trusted": True, "skipped": None,
    }
    out.update(over)
    return out


def _tel_calls(fake_tel: MagicMock, kind: str, name: str) -> List[Dict[str, Any]]:
    """kwargs of every _tel.<kind>(name, ...) call."""
    return [c.kwargs for c in getattr(fake_tel, kind).call_args_list if c.args and c.args[0] == name]


def _scheduled(app: MainApp, callback: Any) -> List[float]:
    """Delays (s) of the scheduler entries whose callback is ``callback``."""
    now = time.monotonic()
    with app._sched_lock:
        return [t - now for t, _sid, cb in app._scheduled if cb == callback]


class _Spawned:
    """Stands in for threading.Thread: records the thread, runs it only when asked."""

    started: List["_Spawned"] = []

    def __init__(self, target=None, args=(), kwargs=None, daemon=None, name=None, **_kw: Any) -> None:
        self.target = target
        self.args = tuple(args or ())
        self.kwargs = dict(kwargs or {})
        self.daemon = daemon
        self.name = name
        self._alive = False

    def start(self) -> None:
        _Spawned.started.append(self)
        self._alive = True

    def is_alive(self) -> bool:
        return self._alive

    def run_now(self) -> None:
        try:
            self.target(*self.args, **self.kwargs)
        finally:
            self._alive = False


@pytest.fixture
def fake_tel(monkeypatch):
    fake = MagicMock()
    monkeypatch.setattr(app_module, "_tel", fake)
    return fake


@pytest.fixture
def flip_app(tmp_path, monkeypatch, fake_tel):
    """A MainApp without __init__: scheduler, engines as mocks, clock pinned, db side stubbed.

    _DB_PATH points at a temp file anyway, so a path this test forgot to stub cannot reach the
    installed database.
    """
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "flip_app.db"), raising=False)
    settings: Dict[str, Any] = {}
    monkeypatch.setattr("app.core.settings_reader.get_backend_global_settings", lambda: dict(settings))
    invalidate = MagicMock()
    refresh = MagicMock()
    monkeypatch.setattr("app.core.db.invalidate_sync_cache", invalidate)
    monkeypatch.setattr("app.core.db.refresh_sync_cache_async", refresh)
    monkeypatch.setattr("app.core.db.get_access_v2_state", lambda: {"utc_offset_sec": OFFSET})
    flips: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []

    def fake_flip(**kw: Any) -> Dict[str, Any]:
        flips.append(kw)
        return dict(results.pop(0)) if results else _result()

    monkeypatch.setattr("app.core.db.apply_local_date_flips", fake_flip)

    app = object.__new__(MainApp)
    app.logger = MagicMock()
    app.cfg = SimpleNamespace(offline_revoke_grace_days=0, sync_interval_sec=60, device_sync_enabled=False)
    app._stop_event = threading.Event()
    MainApp._init_scheduler(app)
    MainApp._init_date_flip_state(app)
    app._ultra_lock = threading.Lock()
    app._ultra_engine = MagicMock(running=True)
    app._agent_engine = MagicMock()
    app.request_sync_now = MagicMock()
    now = {"t": _epoch("2026-09-20T07:30:00+01:00")}
    app._date_flip_now = lambda: now["t"]
    app.t = SimpleNamespace(settings=settings, invalidate=invalidate, refresh=refresh, flips=flips,
                            results=results, now=now)
    return app


# ================================================================== 1. the request
class _Resp:
    status_code = 200
    text = "{}"
    headers: Dict[str, str] = {}

    def __init__(self, body: Dict[str, Any]) -> None:
        self._body = body

    def json(self) -> Dict[str, Any]:
        return dict(self._body)


def _api_capturing(body: Dict[str, Any]):
    sent: Dict[str, Any] = {}
    api = MonClubApi(
        endpoints=ApiEndpoints(
            login_url="https://example.test/api/v1/login",
            sync_url="https://example.test/api/v1/sync",
            create_user_fingerprint_url="",
            latest_release_url="",
        ),
        logger=MagicMock(),
    )

    def get(url, params=None, headers=None, timeout=None):
        sent.update(dict(params or {}))
        sent["_answered_at"] = time.time()
        return _Resp(body)

    api._session = SimpleNamespace(get=get)
    return api, sent


def test_get_sync_data_always_asks_for_protocol_2() -> None:
    api, sent = _api_capturing({})
    api.get_sync_data(token="t")
    assert sent["protocol"] == "2"
    assert "lastCheckTimeStamp" in sent


def test_get_sync_data_sends_protocol_2_with_the_stored_tokens_and_the_windows_version() -> None:
    api, sent = _api_capturing({})
    api.get_sync_data(token="t", version_tokens={"membersVersion": "5:x", "windowsVersion": "p2.7.a.b"})
    assert sent["protocol"] == "2"
    assert sent["membersVersion"] == "5:x"
    assert sent["windowsVersion"] == "p2.7.a.b"


def test_a_stored_token_cannot_replace_the_protocol() -> None:
    api, sent = _api_capturing({})
    api.get_sync_data(token="t", version_tokens={"protocol": "1"})
    assert sent["protocol"] == "2"


def test_get_sync_data_stamps_the_pc_time_the_answer_arrived() -> None:
    api, sent = _api_capturing({"refreshMembers": False, "users": []})
    data = api.get_sync_data(token="t")
    after = time.time()
    stamp = data.pop("_clientReceivedAtEpoch")
    assert isinstance(stamp, float)
    assert sent["_answered_at"] <= stamp <= after
    assert data == {"refreshMembers": False, "users": []}      # the answer itself untouched


# ================================================================== 2. _apply_date_flips
def test_the_flip_reads_the_pc_clock_and_the_grace_setting(flip_app) -> None:
    flip_app.cfg.offline_revoke_grace_days = 3
    flip_app._apply_date_flips("save")
    assert flip_app.t.flips == [{"pc_now_epoch": flip_app.t.now["t"], "grace_days": 3, "source": "save"}]


def test_an_explicit_pc_now_wins(flip_app) -> None:
    flip_app._apply_date_flips("startup", pc_now=_epoch("2026-09-21T08:00:00+01:00"))
    assert flip_app.t.flips[0]["pc_now_epoch"] == _epoch("2026-09-21T08:00:00+01:00")


def test_a_flip_that_moved_rows_resets_the_caches_and_asks_ultra_for_a_full_pass(flip_app, fake_tel) -> None:
    flip_app.t.results.append(_result(held=1, promoted=1, moved=2))

    out = flip_app._apply_date_flips("midnight")

    assert out["moved"] == 2
    flip_app.t.invalidate.assert_called()
    flip_app.t.refresh.assert_called_once_with()
    flip_app._agent_engine.reset_fast_patch_caches.assert_called_once_with()
    flip_app._ultra_engine.reset_fast_patch_caches.assert_called_once_with()
    flip_app._ultra_engine.request_sync_now.assert_called_once_with(changed_ids=None, reason="date-flip")
    [ev] = _tel_calls(fake_tel, "event", "DATE_FLIP")
    assert ev["source"] == "midnight" and ev["gym_date"] == "2026-09-20"
    assert (ev["held"], ev["restored"], ev["promoted"], ev["moved"]) == (1, 0, 1, 2)
    assert isinstance(ev["dur_ms"], int)


def test_manual_sync_mode_updates_the_pc_but_does_not_ask_ultra(flip_app) -> None:
    flip_app.t.settings["manual_sync_mode"] = True
    flip_app.t.results.append(_result(held=1, moved=1))

    flip_app._apply_date_flips("midnight")

    flip_app._ultra_engine.request_sync_now.assert_not_called()
    flip_app._ultra_engine.reset_fast_patch_caches.assert_called_once_with()   # the PC's own view moves
    flip_app.t.refresh.assert_called_once_with()


def test_no_ultra_request_when_the_engine_is_not_running(flip_app) -> None:
    flip_app._ultra_engine.running = False
    flip_app.t.results.append(_result(held=1, moved=1))

    flip_app._apply_date_flips("tick")

    flip_app._ultra_engine.request_sync_now.assert_not_called()


def test_nothing_moved_means_no_cache_work_no_ultra_request_and_no_flip_line(flip_app, fake_tel) -> None:
    flip_app._apply_date_flips("save")

    flip_app.t.refresh.assert_not_called()
    flip_app._ultra_engine.reset_fast_patch_caches.assert_not_called()
    flip_app._ultra_engine.request_sync_now.assert_not_called()
    assert _tel_calls(fake_tel, "event", "DATE_FLIP") == []


def test_the_startup_flip_always_says_which_date_it_applied(flip_app, fake_tel) -> None:
    flip_app.t.results.append(_result(gym_date="2026-09-20", moved=0))
    flip_app._apply_date_flips("startup")
    [ev] = _tel_calls(fake_tel, "event", "DATE_FLIP")
    assert ev["source"] == "startup" and ev["gym_date"] == "2026-09-20" and ev["moved"] == 0


def test_the_startup_line_says_why_nothing_was_applied(flip_app, fake_tel) -> None:
    flip_app.t.results.append(_result(gym_date=None, trusted=False, skipped="no_state"))
    flip_app._apply_date_flips("startup")
    [ev] = _tel_calls(fake_tel, "event", "DATE_FLIP")
    assert ev["skipped"] == "no_state"


def test_a_failed_flip_is_logged_and_never_raises(flip_app, fake_tel, monkeypatch) -> None:
    def boom(**_kw):
        raise RuntimeError("database is locked")

    monkeypatch.setattr("app.core.db.apply_local_date_flips", boom)

    assert flip_app._apply_date_flips("startup") is None
    [w] = _tel_calls(fake_tel, "warn", "DATE_FLIP_FAILED")
    assert w["source"] == "startup" and "database is locked" in w["err"]
    flip_app._ultra_engine.request_sync_now.assert_not_called()


def test_entering_a_suspect_clock_warns(flip_app, fake_tel) -> None:
    flip_app.t.results.append(_result(clock_changed=True, clock_suspect=True, clock_reason="behind",
                                      gym_date="2026-09-19", pc_date="2000-01-01"))
    flip_app._apply_date_flips("tick")
    [w] = _tel_calls(fake_tel, "warn", "CLOCK_SUSPECT")
    assert w == {"reason": "behind", "gym_date": "2026-09-19", "pc_date": "2000-01-01"}
    assert _tel_calls(fake_tel, "event", "CLOCK_OK") == []


def test_leaving_a_suspect_clock_says_ok(flip_app, fake_tel) -> None:
    flip_app.t.results.append(_result(clock_changed=True, clock_suspect=False, gym_date="2026-09-20"))
    flip_app._apply_date_flips("tick")
    assert _tel_calls(fake_tel, "event", "CLOCK_OK") == [{"gym_date": "2026-09-20"}]
    assert _tel_calls(fake_tel, "warn", "CLOCK_SUSPECT") == []


def test_an_unchanged_clock_verdict_says_nothing(flip_app, fake_tel) -> None:
    flip_app.t.results.append(_result(clock_changed=False, clock_suspect=True, clock_reason="behind"))
    flip_app._apply_date_flips("tick")
    assert _tel_calls(fake_tel, "warn", "CLOCK_SUSPECT") == []
    assert _tel_calls(fake_tel, "event", "CLOCK_OK") == []


def test_date_flips_are_serialised(flip_app, monkeypatch) -> None:
    inside = threading.Event()
    release = threading.Event()
    guard = threading.Lock()
    active = [0]
    peak = [0]

    def slow_flip(**_kw):
        with guard:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        inside.set()
        release.wait(5)
        with guard:
            active[0] -= 1
        return _result()

    monkeypatch.setattr("app.core.db.apply_local_date_flips", slow_flip)
    t1 = threading.Thread(target=flip_app._apply_date_flips, args=("tick",), daemon=True)
    t2 = threading.Thread(target=flip_app._apply_date_flips, args=("heartbeat",), daemon=True)
    t1.start()
    assert inside.wait(5)
    inside.clear()
    t2.start()
    assert not inside.wait(0.3)          # the second flip waits for the first
    release.set()
    t1.join(5)
    t2.join(5)
    assert inside.is_set()
    assert peak[0] == 1


# ------------------------------------------------------------------ 00:17 (F8)
def test_a_starter_before_0017_arms_one_first_day_sync_at_0017(flip_app) -> None:
    flip_app.t.now["t"] = _epoch("2026-09-20T00:00:05+01:00")
    flip_app.t.results.append(_result(starters=[3], promoted=1, moved=1))

    flip_app._apply_date_flips("midnight")

    [delay] = _scheduled(flip_app, flip_app._run_first_day_credentials_sync)
    assert delay == pytest.approx(16 * 60 + 55, abs=1)
    flip_app._run_first_day_credentials_sync()
    flip_app.request_sync_now.assert_called_once_with(
        trigger_source="DATE_FLIP", run_type="TRIGGERED", trigger_hint={"reason": "first-day-credentials"},
    )


def test_a_second_flip_with_starters_replaces_the_armed_sync_never_two(flip_app) -> None:
    flip_app.t.now["t"] = _epoch("2026-09-20T00:00:05+01:00")
    flip_app.t.results.extend([_result(starters=[3]), _result(starters=[3])])

    flip_app._apply_date_flips("midnight")
    flip_app.t.now["t"] = _epoch("2026-09-20T00:05:00+01:00")
    flip_app._apply_date_flips("save")

    [delay] = _scheduled(flip_app, flip_app._run_first_day_credentials_sync)
    assert delay == pytest.approx(12 * 60, abs=1)


@pytest.mark.parametrize("clock", ["2026-09-20T00:17:00+01:00", "2026-09-20T07:30:00+01:00"])
def test_no_first_day_sync_from_0017_on(flip_app, clock) -> None:
    flip_app.t.now["t"] = _epoch(clock)
    flip_app.t.results.append(_result(starters=[3]))
    flip_app._apply_date_flips("save")
    assert _scheduled(flip_app, flip_app._run_first_day_credentials_sync) == []


def test_no_first_day_sync_without_a_starter(flip_app) -> None:
    flip_app.t.now["t"] = _epoch("2026-09-20T00:00:05+01:00")
    flip_app.t.results.append(_result(starters=[]))
    flip_app._apply_date_flips("midnight")
    assert _scheduled(flip_app, flip_app._run_first_day_credentials_sync) == []


def test_no_first_day_sync_without_a_known_offset(flip_app, monkeypatch) -> None:
    monkeypatch.setattr("app.core.db.get_access_v2_state", lambda: {})
    flip_app.t.now["t"] = _epoch("2026-09-20T00:00:05+01:00")
    flip_app.t.results.append(_result(starters=[3]))
    flip_app._apply_date_flips("midnight")
    assert _scheduled(flip_app, flip_app._run_first_day_credentials_sync) == []


# ------------------------------------------------------------------ _maybe_apply_date_flips
def test_maybe_flips_only_when_the_precheck_says_so(flip_app, monkeypatch) -> None:
    status = {"needs_flip": False}
    seen: List[float] = []

    def fake_status(*, pc_now_epoch):
        seen.append(pc_now_epoch)
        return dict(status)

    monkeypatch.setattr("app.core.db.gym_date_status", fake_status)
    flip_app._apply_date_flips = MagicMock(return_value={"moved": 0})

    assert flip_app._maybe_apply_date_flips("heartbeat") is None
    flip_app._apply_date_flips.assert_not_called()
    status["needs_flip"] = True
    flip_app._maybe_apply_date_flips("heartbeat")
    flip_app._apply_date_flips.assert_called_once_with("heartbeat")
    assert seen == [flip_app.t.now["t"]] * 2


def test_maybe_never_raises(flip_app, monkeypatch) -> None:
    def boom(**_kw):
        raise RuntimeError("no such table: access_v2_state")

    monkeypatch.setattr("app.core.db.gym_date_status", boom)
    flip_app._apply_date_flips = MagicMock()
    assert flip_app._maybe_apply_date_flips("sync-tick") is None
    flip_app._apply_date_flips.assert_not_called()


# ------------------------------------------------------------------ the 60 s tick and 00:00:05
@pytest.fixture
def spawned(monkeypatch):
    _Spawned.started = []
    monkeypatch.setattr(app_module.threading, "Thread", _Spawned)
    return _Spawned


def test_the_tick_does_nothing_when_no_flip_is_needed_and_rearms(flip_app, spawned, monkeypatch) -> None:
    monkeypatch.setattr("app.core.db.gym_date_status", lambda *, pc_now_epoch: {"needs_flip": False})
    flip_app._date_flip_tick()
    assert spawned.started == []
    assert _scheduled(flip_app, flip_app._date_flip_tick) == [pytest.approx(60, abs=1)]


def test_the_tick_flips_on_a_daemon_thread_when_needed(flip_app, spawned, monkeypatch) -> None:
    monkeypatch.setattr("app.core.db.gym_date_status", lambda *, pc_now_epoch: {"needs_flip": True})
    flip_app._apply_date_flips = MagicMock()

    flip_app._date_flip_tick()

    flip_app._apply_date_flips.assert_not_called()      # not on the loop thread
    [thread] = spawned.started
    assert thread.daemon is True
    thread.run_now()
    flip_app._apply_date_flips.assert_called_once_with("tick")
    assert _scheduled(flip_app, flip_app._date_flip_tick) == [pytest.approx(60, abs=1)]


def test_the_tick_never_piles_up_flip_threads(flip_app, spawned, monkeypatch) -> None:
    monkeypatch.setattr("app.core.db.gym_date_status", lambda *, pc_now_epoch: {"needs_flip": True})
    flip_app._apply_date_flips = MagicMock()
    flip_app._date_flip_tick()
    flip_app._date_flip_tick()                          # the first flip is still running
    assert len(spawned.started) == 1


def test_the_tick_survives_a_failed_precheck(flip_app, spawned, monkeypatch) -> None:
    def boom(**_kw):
        raise RuntimeError("disk I/O error")

    monkeypatch.setattr("app.core.db.gym_date_status", boom)
    flip_app._date_flip_tick()
    assert spawned.started == []
    assert _scheduled(flip_app, flip_app._date_flip_tick) == [pytest.approx(60, abs=1)]


def test_the_tick_arms_the_midnight_one_shot_once_the_offset_is_known(flip_app, spawned, monkeypatch) -> None:
    monkeypatch.setattr("app.core.db.gym_date_status", lambda *, pc_now_epoch: {"needs_flip": False})
    monkeypatch.setattr("app.core.db.get_access_v2_state", lambda: {})
    flip_app._date_flip_tick()
    assert _scheduled(flip_app, flip_app._midnight_date_flip) == []

    monkeypatch.setattr("app.core.db.get_access_v2_state", lambda: {"utc_offset_sec": OFFSET})
    flip_app.t.now["t"] = _epoch("2026-09-19T23:00:00+01:00")
    flip_app._date_flip_tick()
    flip_app._date_flip_tick()
    assert _scheduled(flip_app, flip_app._midnight_date_flip) == [pytest.approx(3605, abs=1)]


def test_the_midnight_one_shot_is_at_000005_gym_time(flip_app) -> None:
    flip_app.t.now["t"] = _epoch("2026-09-19T23:00:00+01:00")
    assert flip_app._arm_midnight_date_flip() is True
    assert _scheduled(flip_app, flip_app._midnight_date_flip) == [
        pytest.approx(access_dates.seconds_until_gym_time(flip_app.t.now["t"], OFFSET, 0, 0, 5), abs=1)
    ]
    assert _scheduled(flip_app, flip_app._midnight_date_flip) == [pytest.approx(3605, abs=1)]


def test_the_midnight_one_shot_checks_on_a_thread_and_rearms_for_the_next_day(flip_app, spawned) -> None:
    flip_app.t.now["t"] = _epoch("2026-09-19T23:00:00+01:00")
    flip_app._arm_midnight_date_flip()
    flip_app._maybe_apply_date_flips = MagicMock()
    flip_app.t.now["t"] = _epoch("2026-09-20T00:00:04.990+01:00")     # a timer may fire a hair early

    flip_app._midnight_date_flip()

    [thread] = spawned.started
    assert thread.daemon is True
    thread.run_now()
    flip_app._maybe_apply_date_flips.assert_called_once_with("midnight")
    [delay] = _scheduled(flip_app, flip_app._midnight_date_flip)
    assert delay == pytest.approx(86400, abs=1)


# ================================================================== 3. MainApp.__init__
def _stub_heavy_init(monkeypatch) -> None:
    """The stubs tests/test_sync_observability.py::test_main_app_initializes_scheduler_before_first_after
    uses: no DLL, no logging setup, no engines."""
    cfg = SimpleNamespace(plcomm_dll_path="C:/sdk/plcommpro.dll", zkfp_dll_path="C:/sdk/libzkfp.dll",
                          log_level="INFO", log_presign_url="")
    monkeypatch.setattr(app_module, "add_windows_dll_search_paths", lambda: None)
    monkeypatch.setattr(app_module, "ensure_dirs", lambda: None)
    monkeypatch.setattr(app_module, "init_db", lambda: None)
    monkeypatch.setattr(app_module, "load_access_app_config", lambda: cfg)
    monkeypatch.setattr(app_module.MainApp, "_resolve_sdk_dll", lambda self, path: path)
    monkeypatch.setattr(app_module, "require_32bit_python_for_32bit_dll", lambda path: None)
    monkeypatch.setattr(app_module, "setup_logging", lambda *args, **kwargs: MagicMock())
    monkeypatch.setattr(app_module, "get_access_config_status", lambda: {})
    monkeypatch.setattr(app_module, "get_access_storage_status", lambda: {})
    monkeypatch.setattr(app_module, "check_zkemkeeper_registration", lambda: {"ok": True})
    monkeypatch.setattr(app_module, "UpdateManager", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(app_module, "DeviceSyncEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(app_module, "DeviceAttendanceMaintenanceEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(app_module, "AgentRealtimeEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(app_module, "UltraEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(app_module.MainApp, "_sync_startup_registration", lambda self: None)


def test_init_applies_the_startup_flip_before_the_first_sync_tick(tmp_path, monkeypatch) -> None:
    """F6: the first ULTRA/AGENT worker starts from the first sync tick's work(); the flip in
    __init__ runs synchronously before that tick is even scheduled."""
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "init.db"), raising=False)
    _stub_heavy_init(monkeypatch)

    class StopInit(Exception):
        pass

    calls: List[Any] = []
    monkeypatch.setattr(MainApp, "_apply_date_flips",
                        lambda self, source, **_kw: calls.append(("flip", source)))
    monkeypatch.setattr(MainApp, "_date_flip_now", staticmethod(lambda: _epoch("2026-09-19T23:00:00+01:00")))
    monkeypatch.setattr("app.core.db.get_access_v2_state", lambda: {"utc_offset_sec": OFFSET})

    def recording_after(self, delay_ms, callback):
        name = getattr(callback, "__name__", repr(callback))
        calls.append(("after", int(delay_ms), name))
        if name == "_sync_tick":
            raise StopInit
        return len(calls)

    monkeypatch.setattr(MainApp, "after", recording_after)

    with pytest.raises(StopInit):
        MainApp()

    assert calls[0] == ("flip", "startup")
    assert calls[-1] == ("after", 250, "_sync_tick")
    assert ("after", 60_000, "_date_flip_tick") in calls
    assert ("after", 3_605_000, "_midnight_date_flip") in calls
    assert [c for c in calls if c[0] == "flip"] == [("flip", "startup")]


# ================================================================== 4. _sync_tick's work()
class _Api:
    def __init__(self, answers: List[Dict[str, Any]], events: List[Any]) -> None:
        self.answers = list(answers)
        self.events = events
        self.version_tokens: List[Any] = []

    def do_proactive_refresh(self, **_kw: Any) -> bool:
        return False

    def get_sync_data(self, *, token, version_tokens=None, timeout=None):
        self.events.append(("fetch",))
        self.version_tokens.append(version_tokens)
        return dict(self.answers.pop(0))


@pytest.fixture
def wired(tmp_path, monkeypatch, fake_tel):
    """tests/test_sync_retry_and_rerun.py's _Harness with a succeeding API.

    The harness replaces threading.Thread (to capture the sync worker), so the database writer
    thread is started first, on the very path the harness then sets.
    """
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "sync_retry.db"), raising=False)
    dbmod._shutdown_db_writer_for_tests()
    dbmod.init_db()
    dbmod._ensure_db_writer()
    h = _Harness(monkeypatch, tmp_path)
    MainApp._init_date_flip_state(h.app)
    h.app._date_flip_now = lambda: SERVER_EPOCH + 5
    h.app._maybe_emit_sync_success_feedback = MagicMock()
    h.app.get_access_mode_summary = lambda: {"DEVICE": 0, "AGENT": 0, "ULTRA": 0, "UNKNOWN": 0}
    monkeypatch.setattr("app.core.db.refresh_sync_cache_async", MagicMock())
    h.events = []
    yield h
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


def _run_worker(h) -> None:
    h.tick()
    worker = _CapturedThread.started.pop(0)
    worker.target()


_NOTHING = {"refreshMembers": False, "refreshDevices": False, "refreshCredentials": False,
            "refreshSettings": False}


def test_work_checks_the_date_before_the_fetch_and_flips_after_the_save(wired, monkeypatch) -> None:
    ev = wired.events
    wired.app._api = lambda: _Api([_NOTHING], ev)
    wired.app._maybe_apply_date_flips = lambda source: ev.append(("maybe", source))
    wired.app._apply_date_flips = lambda source, **_kw: ev.append(("flip", source))
    monkeypatch.setattr(app_module, "save_sync_cache_delta", lambda data, refresh: ev.append(("save",)) or {})

    _run_worker(wired)

    assert ev == [("maybe", "sync-tick"), ("fetch",), ("save",), ("flip", "save")]
    assert wired.app._sync_fail_count == 0


def test_work_flips_after_the_forced_follow_up_save_too(wired, monkeypatch) -> None:
    ev = wired.events
    devices_changed = dict(_NOTHING, refreshDevices=True, devices=[])
    wired.app._api = lambda: _Api([devices_changed, _NOTHING], ev)
    wired.app._maybe_apply_date_flips = lambda source: ev.append(("maybe", source))
    wired.app._apply_date_flips = lambda source, **_kw: ev.append(("flip", source))
    monkeypatch.setattr(app_module, "save_sync_cache_delta", lambda data, refresh: ev.append(("save",)) or {})
    monkeypatch.setattr(app_module, "device_membership_scope_changed", lambda *_a: True)

    _run_worker(wired)

    assert ev == [("maybe", "sync-tick"), ("fetch",), ("save",), ("flip", "save"),
                  ("fetch",), ("save",), ("flip", "save")]


def test_an_offline_tick_still_checks_the_date(wired) -> None:
    ev = wired.events
    wired.app._maybe_apply_date_flips = lambda source: ev.append(("maybe", source))
    wired.app._apply_date_flips = lambda source, **_kw: ev.append(("flip", source))
    # the harness API raises ConnectionError

    _run_worker(wired)

    assert ev == [("maybe", "sync-tick")]
    assert wired.app._sync_fail_count == 1


@pytest.mark.parametrize(("cached_rows", "stripped"), [(100, False), (10, True)])
def test_the_member_cache_self_heal_counts_held_rows(wired, monkeypatch, cached_rows, stripped) -> None:
    """A long closure holds most members: they are still in the server's count, so the self-heal
    must count them, or it forces a FULL member refresh on every tick."""
    dbmod.save_version_tokens({"membersVersion": "100:abc", "membersUpdatedAfter": "2026-09-19T00:00:00"})
    api = _Api([_NOTHING], wired.events)
    wired.app._api = lambda: api
    monkeypatch.setattr("app.core.db.count_sync_users", lambda: 10)        # most rows are held
    monkeypatch.setattr("app.core.db.count_member_cache_rows", lambda: cached_rows)
    monkeypatch.setattr(app_module, "save_sync_cache_delta", lambda data, refresh: {})

    _run_worker(wired)

    [sent] = api.version_tokens
    assert ("membersVersion" not in (sent or {})) is stripped


# ================================================================== 5. the fast patch
def _fast_patch_app(order: List[Any]) -> SimpleNamespace:
    return SimpleNamespace(
        logger=MagicMock(),
        reset_runtime_fast_patch_caches=MagicMock(),
        _request_running_ultra_sync=MagicMock(side_effect=lambda **_kw: order.append("dispatch") or True),
        _defer_ultra_reconnects=MagicMock(),
        request_sync_now=MagicMock(),
        _apply_date_flips=MagicMock(side_effect=lambda source, **_kw: order.append(("flip", source))),
    )


_BUNDLE = {
    "bundleId": "bundle-p3b1",
    "items": [{
        "kind": "ENTITY_UPSERT", "entityType": "ACTIVE_MEMBERSHIP", "entityId": 9,
        "revision": "2026-09-19T10:00:00Z",
        "impact": {"affectedMemberIds": [9], "affectedDeviceIds": []},
    }],
}


def test_a_fast_patch_is_followed_by_a_date_flip_before_the_dispatch(tmp_path, monkeypatch) -> None:
    """A fast-patch upsert can put a held membership back on sync_users (e.g. on its freeze
    day); the flip re-holds it before anything is dispatched."""
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "fp.db"), raising=False)
    order: List[Any] = []
    monkeypatch.setattr("app.core.settings_reader.get_backend_global_settings", lambda: {})
    monkeypatch.setattr("app.core.db.apply_fast_patch_bundle",
                        lambda bundle: order.append("db-apply") or {"applied": 1, "skipped": 0, "ignored": None})
    monkeypatch.setattr("app.core.db.invalidate_sync_cache", lambda *a, **k: None)
    monkeypatch.setattr("app.core.db.refresh_sync_cache_async", lambda: None)
    app = _fast_patch_app(order)

    MainApp.apply_fast_patch_bundle(app, _BUNDLE)

    assert order == ["db-apply", ("flip", "fast-patch"), "dispatch"]


def test_a_duplicate_fast_patch_does_not_flip(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "fp.db"), raising=False)
    order: List[Any] = []
    monkeypatch.setattr("app.core.settings_reader.get_backend_global_settings", lambda: {})
    monkeypatch.setattr("app.core.db.apply_fast_patch_bundle", lambda bundle: {"ignored": "duplicate_bundle"})
    app = _fast_patch_app(order)

    MainApp.apply_fast_patch_bundle(app, _BUNDLE)

    app._apply_date_flips.assert_not_called()


# ================================================================== 6. the enrolment fallback sync
def test_the_enrolment_fallback_sync_flips_after_its_full_save(tmp_path, monkeypatch, fake_tel) -> None:
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "enrol.db"), raising=False)
    order: List[Any] = []
    monkeypatch.setattr(app_module, "load_auth_token",
                        lambda: SimpleNamespace(token="tok", email="op@example.invalid"))
    monkeypatch.setattr(app_module, "save_sync_cache", lambda data: order.append(("save", data.get("marker"))))
    api = MagicMock()
    api.get_sync_data.side_effect = lambda **_kw: order.append("fetch") or {"marker": "v2"}
    self_obj = SimpleNamespace(
        logger=MagicMock(),
        cfg=SimpleNamespace(zkfp_dll_path="libzkfp.dll", template_version=10,
                            template_encoding="base64", login_email="op@example.invalid"),
        _enroll_state_lock=threading.Lock(),
        _enroll_cancel_event=threading.Event(),
        _enroll_running=True,
        _restriction_reasons=lambda: [],
        _api=lambda: api,
        _find_user_membership=lambda _uid: (None, None),
        _request_running_ultra_sync=lambda **_kw: None,
        _apply_date_flips=lambda source, **_kw: order.append(("flip", source)),
        # lane B (review R2-3): the full save writes device rows too; the workers follow first
        _refresh_running_ultra_devices=lambda **kw: order.append(("refresh", kw.get("reason"))) or True,
    )

    MainApp._remote_enroll_worker(self_obj, 35, 1, "", "zk9500", None, "e-p3b1")

    assert order == ["fetch", ("save", "v2"), ("refresh", "enroll-save"), ("flip", "save")]


# ================================================================== 7. the heartbeat
def _identity_service(monkeypatch, app, order: List[Any]):
    import access.pc_identity as pci

    monkeypatch.setattr(pci, "PcCredentialStore", lambda *a, **k: SimpleNamespace(load=lambda: None))
    monkeypatch.setattr(pci, "PcIdentityApiClient", lambda *a, **k: SimpleNamespace())
    monkeypatch.setattr(pci, "build_heartbeat_payload", lambda a: order.append("payload") or {"ok": True})
    return pci.get_pc_identity_service(app)


def test_every_heartbeat_first_checks_the_gym_date(monkeypatch) -> None:
    order: List[Any] = []
    app = SimpleNamespace(logger=MagicMock(), _maybe_apply_date_flips=lambda source: order.append(("date", source)))
    service = _identity_service(monkeypatch, app, order)

    assert service._heartbeat_payload_provider() == {"ok": True}
    assert order == [("date", "heartbeat"), "payload"]


def test_the_heartbeat_payload_survives_a_failing_date_check(monkeypatch) -> None:
    order: List[Any] = []

    def boom(_source):
        raise RuntimeError("database is locked")

    app = SimpleNamespace(logger=MagicMock(), _maybe_apply_date_flips=boom)
    service = _identity_service(monkeypatch, app, order)
    assert service._heartbeat_payload_provider() == {"ok": True}


def test_the_heartbeat_payload_needs_no_date_check(monkeypatch) -> None:
    order: List[Any] = []
    app = SimpleNamespace(logger=MagicMock())
    service = _identity_service(monkeypatch, app, order)
    assert service._heartbeat_payload_provider() == {"ok": True}
    assert order == ["payload"]


# ================================================================== 8. end to end (real temp db)
def _meta() -> Dict[str, Any]:
    return {"protocol": 2, "today": "2026-09-19", "horizonDays": 7, "horizonEnd": "2026-09-26",
            "serverTime": "2026-09-19T10:00:00.000+01:00", "snapshotAt": "2026-09-19T09:59:59.500+01:00",
            "reconcileSec": 600, "capabilities": ["accessWindows", "upcoming", "upcomingCredentials"]}


def _row(am: int, frm: str = "2026-09-01", until: str = "2026-09-30", **extra: Any) -> Dict[str, Any]:
    row = {"activeMembershipId": am, "userId": 7000 + am, "membershipId": 3, "fullName": f"M{am}",
           "firstCardId": str(1000 + am), "mainAccountId": 9000 + am,
           "accessFrom": frm, "accessUntil": until, "offDays": []}
    row.update(extra)
    return row


def _ids(table: str) -> set:
    with dbmod.get_conn() as conn:
        return {int(r[0]) for r in conn.execute(f"SELECT active_membership_id FROM {table}").fetchall()}


def test_end_to_end_a_saved_v2_answer_then_a_power_on_the_next_morning(wired, fake_tel) -> None:
    answer = {
        "syncMeta": _meta(), "currentWindowsVersion": "p2.7.a.b",
        "refreshMembers": True, "refreshDevices": False, "refreshCredentials": False,
        "refreshSettings": False, "membersDeltaMode": False,
        # 1 ends today; 5 runs all month; 3 (another plan of person 7001's gym) starts tomorrow
        "users": [_row(1, until="2026-09-19"), _row(5)],
        "memberWindows": [],
        "upcoming": [_row(3, frm="2026-09-20", qrAccountId=55)],
        "upcomingIds": [3],
        "upcomingCredentials": [],
        "currentMembersVersion": "2:abc",
        "_clientReceivedAtEpoch": SERVER_EPOCH + 2,
    }
    wired.app._api = lambda: _Api([answer], wired.events)

    _run_worker(wired)

    assert wired.app._sync_fail_count == 0
    assert _ids("sync_users") == {1, 5}                       # today: nothing to move
    assert _ids("sync_users_held") == set()
    assert dbmod.get_access_v2_state()["applied_date"] == "2026-09-19"
    assert dbmod.load_version_tokens().get("windowsVersion") == "p2.7.a.b"

    # The PC is switched off overnight, and on again at 07:30 with no network: the ULTRA engine
    # is up by the time the flip asks it (the order at a real start-up is the flip first, then
    # the engine from the first sync tick -- this pins the request itself).
    wired.app._ultra_engine = MagicMock(running=True)
    out = wired.app._apply_date_flips("startup", pc_now=_epoch("2026-09-20T07:30:00+01:00"))

    assert out["gym_date"] == "2026-09-20"
    assert (out["held"], out["promoted"]) == (1, 1)
    assert _ids("sync_users") == {3, 5}
    assert _ids("sync_users_held") == {1}
    wired.app._ultra_engine.request_sync_now.assert_called_once_with(changed_ids=None, reason="date-flip")
    [ev] = _tel_calls(fake_tel, "event", "DATE_FLIP")
    assert (ev["source"], ev["gym_date"], ev["held"], ev["promoted"], ev["moved"]) == (
        "startup", "2026-09-20", 1, 1, 2)
    # 07:30 is past 00:17: the server already enabled the new member's QR, nothing to arm
    assert _scheduled(wired.app, wired.app._run_first_day_credentials_sync) == []

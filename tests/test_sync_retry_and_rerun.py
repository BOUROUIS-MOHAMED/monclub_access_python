"""The periodic backend sync: failure-retry schedule, Retry-After, and the coalesced re-run.

Before this change:

* the sync timer was re-armed only at the *start* of each tick, from the failure count of the
  *previous* tick, so the first retry after a failure waited a full healthy interval (1800 s
  with ``agentSyncBackendRefreshMin=30``), and every later one a flat ~600 s;
* ``getSyncData`` threw away the HTTP status and ``Retry-After``;
* a sync requested while one was running was skipped and waited for the next timer tick.

These tests build a MainApp without ``__init__`` (no database, devices or network), run the
real ``_sync_tick`` / ``reschedule_sync_timer`` / ``request_sync_now``, capture the worker
thread instead of starting it, and run due scheduler callbacks by hand. Every database call
the worker reaches is patched or redirected to a temp database (``_DB_PATH``).
"""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from typing import Any, Callable, List, Optional, Tuple
from unittest.mock import MagicMock

import pytest

import app.ui.app as app_module
from app.api.monclub_api import ApiEndpoints, MonClubApi, MonClubApiError, MonClubApiHttpError
from app.core.sync_retry import (
    SYNC_RETRY_CAP_SEC,
    SYNC_RETRY_STEPS_SEC,
    parse_retry_after_sec,
    sync_retry_delay_sec,
)
from app.ui.app import MainApp

HEALTHY_30_MIN = 30 * 60


# ── Harness ─────────────────────────────────────────────────────────────────────────


class _CapturedThread:
    """Stands in for threading.Thread inside app.ui.app: records the worker, never runs it."""

    started: List["_CapturedThread"] = []
    fail_start = False

    def __init__(self, target: Callable[[], None], daemon: bool = False, **_kw: Any) -> None:
        self.target = target

    def start(self) -> None:
        if _CapturedThread.fail_start:
            raise RuntimeError("can't start new thread")
        _CapturedThread.started.append(self)


class _Harness:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp_path, *, refresh_min: Optional[int] = 30,
                 sync_interval_sec: int = 60) -> None:
        # The worker body reaches a few real db reads after the patched calls; the documented
        # _DB_PATH override keeps every one of them in a temp database.
        import app.core.db as db_module

        monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "sync_retry.db"), raising=False)
        db_module.init_db()
        _CapturedThread.started = []
        _CapturedThread.fail_start = False
        monkeypatch.setattr(app_module.threading, "Thread", _CapturedThread)
        monkeypatch.setattr(
            app_module, "load_auth_token", lambda: SimpleNamespace(token="jwt", email="gym@example.test"),
        )
        settings = {} if refresh_min is None else {"agent_sync_backend_refresh_min": refresh_min}
        monkeypatch.setattr("app.core.settings_reader.get_backend_global_settings", lambda: dict(settings))
        monkeypatch.setattr("app.core.db.insert_sync_run", lambda **_kw: None)

        self.resolved: List[Any] = []
        real_resolve = app_module.resolve_sync_context

        def recording_resolve(**kw: Any):
            out = real_resolve(**kw)
            self.resolved.append(out[0])
            return out

        monkeypatch.setattr(app_module, "resolve_sync_context", recording_resolve)

        app = object.__new__(MainApp)
        app.logger = MagicMock()
        app.cfg = SimpleNamespace(sync_interval_sec=sync_interval_sec, device_sync_enabled=False)
        app._stop_event = threading.Event()
        MainApp._init_scheduler(app)
        app._sync_after_id = None
        app._sync_work_running = False
        app._pending_sync_context = None
        app._startup_sync_pending = False
        app._sync_fail_count = 0
        app._sync_retry_after_sec = None
        app._sync_rerun_requested = False
        app._last_tick_device_reconcile_mono = None
        app._last_sync_at = None
        app._last_sync_ok = False
        app._last_sync_error = None
        app.evaluate_access_and_redirect = MagicMock()
        app.maybe_run_offline_retry = MagicMock()
        app._device_attendance_engine = MagicMock()
        app._ultra_lock = threading.Lock()
        app._ultra_engine = MagicMock(running=False)
        app._ultra_history_consumer = None
        app._agent_engine = MagicMock()
        self.api_error: BaseException = ConnectionError("backend unreachable")
        app._api = self._api
        self.app = app

    def _api(self):
        raise self.api_error

    # -- scheduler inspection ------------------------------------------------------------

    def armed_sync_timer_sec(self) -> float:
        """Delay (s) of the one armed periodic sync timer."""
        with self.app._sched_lock:
            entries = [(t, sid) for t, sid, cb in self.app._scheduled if sid == self.app._sync_after_id]
        assert len(entries) == 1
        return entries[0][0] - time.monotonic()

    def pending_callbacks(self) -> List[Tuple[float, Any]]:
        now = time.monotonic()
        with self.app._sched_lock:
            return [(t - now, cb) for t, _sid, cb in self.app._scheduled]

    def run_due(self) -> List[Any]:
        """Run every callback due now (delay <= 0.1 s), like one mainloop pass."""
        now = time.monotonic() + 0.1
        with self.app._sched_lock:
            due = [cb for t, _sid, cb in self.app._scheduled if t <= now]
            self.app._scheduled = [e for e in self.app._scheduled if e[0] > now]
        for cb in due:
            cb()
        return due

    # -- lifecycle -----------------------------------------------------------------------

    def tick(self) -> None:
        MainApp._sync_tick(self.app)

    def finish_worker(self, *, fail: bool) -> None:
        """Run the captured worker body to completion on this thread, failing getSyncData.

        A successful getSyncData needs most of the app, so successes are simulated by
        ``_succeed`` below: the fail-count reset the worker's success branch records, then the
        same completion call the worker posts.
        """
        assert fail
        worker = _CapturedThread.started.pop(0)
        worker.target()


@pytest.fixture
def harness(monkeypatch, tmp_path):
    return _Harness(monkeypatch, tmp_path)


def _is_sync_tick(cb: Any, app: MainApp) -> bool:
    return getattr(cb, "__func__", None) is MainApp._sync_tick and getattr(cb, "__self__", None) is app


# ── The pure schedule ───────────────────────────────────────────────────────────────


def test_schedule_steps_without_jitter() -> None:
    delays = [sync_retry_delay_sec(n, HEALTHY_30_MIN, uniform=lambda a, b: 0.0) for n in range(1, 9)]
    assert delays == [15, 30, 60, 120, 300, 300, 300, 300]
    assert SYNC_RETRY_STEPS_SEC == (15, 30, 60, 120, 300)
    assert SYNC_RETRY_CAP_SEC == 300


@pytest.mark.parametrize("fails", range(1, 8))
def test_jitter_is_plus_minus_20_percent_and_never_above_the_cap(fails: int) -> None:
    step = SYNC_RETRY_STEPS_SEC[min(fails, len(SYNC_RETRY_STEPS_SEC)) - 1]
    low = sync_retry_delay_sec(fails, HEALTHY_30_MIN, uniform=lambda a, b: a)
    high = sync_retry_delay_sec(fails, HEALTHY_30_MIN, uniform=lambda a, b: b)
    assert low == pytest.approx(step * 0.8)
    assert high == pytest.approx(min(step * 1.2, SYNC_RETRY_CAP_SEC))


def test_retry_is_never_longer_than_the_healthy_interval() -> None:
    assert sync_retry_delay_sec(4, 60, uniform=lambda a, b: 0.0) == 60
    assert sync_retry_delay_sec(1, 10, uniform=lambda a, b: b) == 10


def test_retry_after_is_honoured_up_to_the_healthy_interval() -> None:
    assert sync_retry_delay_sec(1, HEALTHY_30_MIN, retry_after_sec=90, uniform=lambda a, b: 0.0) == 90
    assert sync_retry_delay_sec(1, HEALTHY_30_MIN, retry_after_sec=5000, uniform=lambda a, b: 0.0) == HEALTHY_30_MIN
    # A Retry-After shorter than our own step does not make us retry sooner.
    assert sync_retry_delay_sec(3, HEALTHY_30_MIN, retry_after_sec=2, uniform=lambda a, b: 0.0) == 60


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("42", 42.0), (" 7 ", 7.0), ("0", 0.0), (None, None), ("", None), ("-3", None), ("soon", None),
     ("Wed, 21 Oct 2015 07:28:00 GMT", None)],
)
def test_parse_retry_after(raw: Optional[str], expected: Optional[float]) -> None:
    assert parse_retry_after_sec(raw) == expected


# ── getSyncData exposes 429 / Retry-After ───────────────────────────────────────────


def _api_returning(status: int, headers: dict, text: str = "busy") -> MonClubApi:
    api = MonClubApi(
        endpoints=ApiEndpoints(
            login_url="https://example.test/api/v1/login",
            sync_url="https://example.test/api/v1/sync",
            create_user_fingerprint_url="",
            latest_release_url="",
        ),
        logger=MagicMock(),
    )
    api._session = SimpleNamespace(
        get=lambda *a, **k: SimpleNamespace(status_code=status, headers=headers, text=text),
    )
    return api


def test_get_sync_data_429_carries_status_and_retry_after() -> None:
    with pytest.raises(MonClubApiHttpError) as info:
        _api_returning(429, {"Retry-After": "90"}).get_sync_data(token="t")

    assert info.value.status_code == 429
    assert info.value.retry_after_sec == 90.0
    assert isinstance(info.value, MonClubApiError)  # existing handlers still catch it
    assert str(info.value).startswith("getSyncData failed: HTTP 429 -> busy")


def test_get_sync_data_500_has_no_retry_after() -> None:
    with pytest.raises(MonClubApiHttpError) as info:
        _api_returning(500, {"Retry-After": "90"}).get_sync_data(token="t")

    assert info.value.status_code == 500
    assert info.value.retry_after_sec is None


# ── Retry timeline through the real tick / worker / completion path ─────────────────


def test_first_retry_after_a_failure_is_about_15s_not_a_full_interval(harness) -> None:
    harness.tick()
    assert harness.armed_sync_timer_sec() == pytest.approx(HEALTHY_30_MIN, abs=1)

    harness.finish_worker(fail=True)
    harness.run_due()  # the completion callback, posted by the worker onto the loop

    assert harness.app._sync_fail_count == 1
    assert 12 - 0.5 <= harness.armed_sync_timer_sec() <= 18


def test_retry_timeline_over_consecutive_failures(harness) -> None:
    observed = []
    for _ in range(7):
        harness.tick()
        harness.finish_worker(fail=True)
        harness.run_due()
        observed.append(harness.armed_sync_timer_sec())

    bounds = [(12, 18), (24, 36), (48, 72), (96, 144), (240, 300), (240, 300), (240, 300)]
    for got, (lo, hi) in zip(observed, bounds):
        assert lo - 0.5 <= got <= hi, observed


def test_success_after_failures_returns_to_the_healthy_interval(harness) -> None:
    harness.tick()
    harness.finish_worker(fail=True)
    harness.run_due()

    harness.tick()  # the retry fires; the tick re-arms the healthy backstop
    worker = _CapturedThread.started.pop(0)
    harness.app._sync_fail_count = 0  # what the worker's success branch records
    harness.app._sync_work_running = False
    MainApp._on_sync_work_finished(harness.app)

    assert harness.armed_sync_timer_sec() == pytest.approx(HEALTHY_30_MIN, abs=1)
    assert worker is not None


def test_without_the_backend_setting_the_base_is_sync_interval_sec(monkeypatch, tmp_path) -> None:
    h = _Harness(monkeypatch, tmp_path, refresh_min=None, sync_interval_sec=60)
    observed = []
    for _ in range(5):
        h.tick()
        assert h.armed_sync_timer_sec() == pytest.approx(60, abs=1)  # healthy backstop
        h.finish_worker(fail=True)
        h.run_due()
        observed.append(h.armed_sync_timer_sec())

    # 15, 30 then capped by the 60 s healthy interval.
    for got, (lo, hi) in zip(observed, [(12, 18), (24, 36), (48, 60), (48, 60), (48, 60)]):
        assert lo - 0.5 <= got <= hi, observed


def test_a_429_retry_after_stretches_the_retry(harness) -> None:
    err = MonClubApiHttpError("getSyncData failed: HTTP 429 -> busy", status_code=429)
    err.retry_after_sec = 90.0
    harness.tick()
    harness.api_error = err
    worker = _CapturedThread.started.pop(0)
    worker.target()
    harness.run_due()

    assert harness.armed_sync_timer_sec() == pytest.approx(90, abs=1)


def test_the_worker_posts_completion_to_the_loop_not_inline(harness) -> None:
    harness.tick()
    harness.finish_worker(fail=True)

    assert harness.app._sync_work_running is False
    # Nothing re-armed yet: the worker thread only posts; the loop thread re-arms.
    assert harness.armed_sync_timer_sec() == pytest.approx(HEALTHY_30_MIN, abs=1)
    due = [cb for delay, cb in harness.pending_callbacks() if delay <= 0.1]
    assert any(getattr(cb, "__func__", None) is MainApp._on_sync_work_finished for cb in due)


# ── A sync requested while one is running re-runs once ──────────────────────────────


def _succeed(harness: _Harness) -> None:
    worker = _CapturedThread.started.pop(0)
    assert worker is not None
    harness.app._sync_fail_count = 0
    harness.app._sync_work_running = False
    MainApp._on_sync_work_finished(harness.app)


def test_a_request_during_a_running_sync_reruns_when_it_finishes(harness) -> None:
    harness.tick()
    assert harness.app._sync_work_running is True

    MainApp.request_sync_now(harness.app, trigger_source="CHANGE_DETECTOR", run_type="TRIGGERED")
    harness.run_due()  # request_sync_now's after(50, _sync_tick) -- nearly due
    time.sleep(0.06)
    harness.run_due()

    assert harness.app._sync_rerun_requested is True
    assert harness.app._pending_sync_context.trigger_source == "CHANGE_DETECTOR"
    assert _CapturedThread.started and len(_CapturedThread.started) == 1  # never two workers

    _succeed(harness)
    due = harness.run_due()
    assert any(_is_sync_tick(cb, harness.app) for cb in due)
    assert len(_CapturedThread.started) == 1  # the re-run started
    assert harness.resolved[-1].trigger_source == "CHANGE_DETECTOR"
    assert harness.app._pending_sync_context is None
    assert harness.app._sync_rerun_requested is False


def test_many_rapid_requests_coalesce_into_one_rerun(harness) -> None:
    harness.tick()
    for i in range(25):
        MainApp.request_sync_now(harness.app, trigger_source="SYNC_NOW_API", trigger_hint={"n": i})
    time.sleep(0.06)
    harness.run_due()
    assert len(_CapturedThread.started) == 1

    _succeed(harness)
    harness.run_due()
    assert len(_CapturedThread.started) == 1  # exactly one re-run
    assert harness.resolved[-1].trigger_hint == {"n": 24}  # the latest request wins, as before

    _succeed(harness)
    harness.run_due()
    assert _CapturedThread.started == []  # and it does not loop


def test_a_plain_timer_tick_during_a_sync_does_not_queue_a_rerun(harness) -> None:
    harness.tick()
    harness.tick()  # backstop timer firing while the worker still runs; no request pending

    assert harness.app._sync_rerun_requested is False
    _succeed(harness)
    harness.run_due()
    assert _CapturedThread.started == []


def test_a_rerun_after_a_failed_sync_waits_for_the_retry(harness) -> None:
    harness.tick()
    MainApp.request_sync_now(harness.app, trigger_source="SYNC_NOW_API", trigger_hint={"reason": "user-sync"})
    time.sleep(0.06)
    harness.run_due()

    harness.finish_worker(fail=True)
    due = harness.run_due()

    assert not any(_is_sync_tick(cb, harness.app) for cb in due)
    assert _CapturedThread.started == []
    assert 12 - 0.5 <= harness.armed_sync_timer_sec() <= 18
    # The request is still pending for the retry tick to carry.
    assert harness.app._pending_sync_context.trigger_hint == {"reason": "user-sync"}


def test_completion_after_a_newer_sync_started_leaves_it_alone(harness) -> None:
    harness.tick()
    harness.finish_worker(fail=True)  # posts completion; not yet run by the loop
    harness.tick()  # a newer sync starts before the loop runs the completion
    assert harness.app._sync_work_running is True
    armed_before = harness.app._sync_after_id

    harness.run_due()

    assert harness.app._sync_after_id == armed_before  # the newer tick's timer is kept
    assert len(_CapturedThread.started) == 1


# ── The worker thread failing to start ──────────────────────────────────────────────


def test_a_worker_that_cannot_start_does_not_wedge_the_sync(harness) -> None:
    MainApp.request_sync_now(harness.app, trigger_source="SYNC_NOW_API", trigger_hint={"reason": "user-sync"})
    _CapturedThread.fail_start = True
    time.sleep(0.06)
    harness.run_due()

    assert harness.app._sync_work_running is False
    assert 12 - 0.5 <= harness.armed_sync_timer_sec() <= 18
    assert harness.app._pending_sync_context.trigger_hint == {"reason": "user-sync"}


# ── Fast retries must not multiply device reconciles ────────────────────────────────
#
# A tick whose getSyncData fails still reconciles DEVICE-mode panels from the cached roster
# (PullSDK connect, full Pin read, SetDeviceParam; a FULL_REPLACE panel is wiped and re-pushed).
# Only the backend fetch retries fast: a failed-fetch tick dispatches that reconcile only when
# the last one from a sync tick is at least one healthy interval old.


def _with_device_mode_panel(monkeypatch, h: _Harness) -> MagicMock:
    engine = MagicMock()
    engine.run_blocking.return_value = True
    engine.get_progress_snapshot.return_value = ({"total": 1}, None)
    h.app._device_sync_engine = engine
    h.app.cfg.device_sync_enabled = True
    h.app._restriction_reasons = lambda: []
    h.app.get_access_mode_summary = lambda: {"DEVICE": 1, "AGENT": 0, "ULTRA": 0, "UNKNOWN": 0}
    monkeypatch.setattr(app_module, "load_sync_cache", lambda: SimpleNamespace(devices=[{"id": 1}], users=[]))
    return engine


def test_retry_ticks_during_an_outage_do_not_repeat_the_device_reconcile(monkeypatch, harness) -> None:
    engine = _with_device_mode_panel(monkeypatch, harness)

    for _ in range(6):  # the first failed tick, then five fast retries
        harness.tick()
        harness.finish_worker(fail=True)
        harness.run_due()

    assert engine.run_blocking.call_count == 1


def test_a_failed_tick_reconciles_again_once_a_healthy_interval_has_passed(monkeypatch, harness) -> None:
    engine = _with_device_mode_panel(monkeypatch, harness)
    harness.tick()
    harness.finish_worker(fail=True)
    harness.run_due()
    assert engine.run_blocking.call_count == 1

    harness.app._last_tick_device_reconcile_mono -= HEALTHY_30_MIN + 1
    harness.tick()
    harness.finish_worker(fail=True)

    assert engine.run_blocking.call_count == 2


def test_the_first_failed_tick_after_start_still_reconciles(monkeypatch, harness) -> None:
    engine = _with_device_mode_panel(monkeypatch, harness)
    harness.tick()
    harness.finish_worker(fail=True)

    engine.run_blocking.assert_called_once()


def test_the_first_failed_healthy_tick_after_a_reconcile_still_reconciles(monkeypatch, harness) -> None:
    """Healthy timer ticks start one interval apart; the gate compares tick starts, so a
    failure on the very next healthy tick reconciles exactly as it did before this change."""
    engine = _with_device_mode_panel(monkeypatch, harness)
    harness.app._last_tick_device_reconcile_mono = time.monotonic() - HEALTHY_30_MIN

    before = time.monotonic()
    harness.tick()
    after_tick = time.monotonic()
    time.sleep(0.02)  # the worker (fetch, then dispatch) runs later than the tick itself
    harness.finish_worker(fail=True)

    engine.run_blocking.assert_called_once()
    # Stamped with this tick's start, not the (later) dispatch time.
    assert before <= harness.app._last_tick_device_reconcile_mono <= after_tick


@pytest.mark.parametrize(
    ("run_type", "hint"),
    [("TRIGGERED", {"reason": "user-sync"}), ("HARD_RESET", {"hardReset": True}),
     ("TRIGGERED", {"reason": "daily-auto-sync"})],
)
def test_an_explicit_sync_still_reconciles_while_the_backend_is_down(monkeypatch, harness, run_type, hint) -> None:
    engine = _with_device_mode_panel(monkeypatch, harness)
    harness.tick()
    harness.finish_worker(fail=True)  # automatic tick: reconciles, stamps the gate
    assert engine.run_blocking.call_count == 1

    MainApp.request_sync_now(harness.app, trigger_source="SYNC_NOW_API", run_type=run_type, trigger_hint=hint)
    time.sleep(0.06)
    harness.run_due()
    harness.finish_worker(fail=True)

    assert engine.run_blocking.call_count == 2

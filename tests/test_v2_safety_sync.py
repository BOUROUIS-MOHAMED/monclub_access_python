"""The promised safety sync (lane B, 2026-09-26, guide §3.6 / §3.9).

Before: ``syncMeta.reconcileSec`` (600 s, the server's "how often an idle v2 PC should compare its
list with mine") was stored in ``access_v2_state`` and read nowhere. The data sync ran on the healthy
interval (``agentSyncBackendRefreshMin``, 30 min); only pending COMMANDS were polled every 120 s while
the notice socket was down. The server relies on the PC's safety poll for the changes it does not
notify (backend plan P2b, "the PC's safety poll covers it").

Now, on a PC that is v2-on AND trusted -- the v2 runtime answers ``availability == ON`` (the commands
switch), the protocol-2 windows are trusted (the dates switch, a members section applied) and a
positive ``reconcileSec`` was stored -- the healthy timer runs a data sync at least every
``reconcileSec`` while the socket is connected and every 120 s while it is down. Anything else --
an old server, a switch off, no runtime, an unreadable state -- is today's cadence exactly. The
failure-retry schedule and the ``Retry-After`` clamp keep using the old healthy interval.
"""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from typing import Any, Dict, Optional
from unittest.mock import MagicMock

import pytest

from app.core import sync_cadence
from app.core.sync_cadence import (
    SAFETY_MIN_SEC,
    SAFETY_SOCKET_DOWN_SEC,
    healthy_sync_delay_sec,
)

BASE = 30 * 60
UP = {"reconcile_sec": 600, "socket_connected": True}
DOWN = {"reconcile_sec": 600, "socket_connected": False}


# ── the pure cadence ────────────────────────────────────────────────────────────────


def test_no_safety_mode_is_the_healthy_interval_exactly() -> None:
    assert healthy_sync_delay_sec(BASE, None) == BASE
    assert healthy_sync_delay_sec(60, None) == 60


def test_socket_up_syncs_at_least_every_reconcile_sec() -> None:
    assert healthy_sync_delay_sec(BASE, UP, uniform=lambda a, b: b) == 600
    assert healthy_sync_delay_sec(BASE, UP, uniform=lambda a, b: a) == pytest.approx(480)


def test_socket_down_syncs_every_two_minutes() -> None:
    assert SAFETY_SOCKET_DOWN_SEC == 120
    assert healthy_sync_delay_sec(BASE, DOWN, uniform=lambda a, b: b) == 120
    assert healthy_sync_delay_sec(BASE, DOWN, uniform=lambda a, b: a) == pytest.approx(96)


def test_the_spread_only_ever_shortens() -> None:
    """Jitter spreads the PCs of a gym (a server restart drops every socket at once); it may
    only bring a sync forward -- "at least every reconcileSec" -- never push it back."""
    for _ in range(200):
        assert 96 <= healthy_sync_delay_sec(BASE, DOWN) <= 120
        assert 480 <= healthy_sync_delay_sec(BASE, UP) <= 600


def test_never_longer_than_the_healthy_interval_and_no_spread_when_it_is_shorter() -> None:
    assert healthy_sync_delay_sec(60, UP, uniform=lambda a, b: a) == 60
    assert healthy_sync_delay_sec(60, DOWN, uniform=lambda a, b: a) == 60


def test_a_tiny_reconcile_sec_is_floored() -> None:
    tiny = {"reconcile_sec": 5, "socket_connected": True}
    assert SAFETY_MIN_SEC == 60
    assert healthy_sync_delay_sec(BASE, tiny, uniform=lambda a, b: b) == 60


# ── the predicate: v2 on AND trusted ────────────────────────────────────────────────


def _app_with(monkeypatch, *, availability: Optional[str] = "ON", connected: bool = True,
              state: Optional[Dict[str, Any]] = None, state_raises: bool = False):
    import app.ui.app as app_module

    app = object.__new__(app_module.MainApp)
    app.logger = MagicMock()
    if availability is not None:
        app._v2_runtime = SimpleNamespace(availability=availability,
                                          notice=SimpleNamespace(connected=connected))
    st = {"trusted": True, "reconcile_sec": 600} if state is None else state

    def _get_state():
        if state_raises:
            raise RuntimeError("database is locked")
        return dict(st)

    monkeypatch.setattr("app.core.db.get_access_v2_state", _get_state)
    return app


def test_on_and_trusted_is_safety_mode(monkeypatch) -> None:
    app = _app_with(monkeypatch)
    assert app._v2_safety_sync() == {"reconcile_sec": 600, "socket_connected": True}
    app = _app_with(monkeypatch, connected=False)
    assert app._v2_safety_sync() == {"reconcile_sec": 600, "socket_connected": False}


@pytest.mark.parametrize("availability", [None, "UNKNOWN", "OFF"])
def test_no_runtime_or_a_server_without_v2_is_not_safety_mode(monkeypatch, availability) -> None:
    assert _app_with(monkeypatch, availability=availability)._v2_safety_sync() is None


@pytest.mark.parametrize("state", [
    {},                                              # no protocol-2 answer ever
    {"trusted": False, "reconcile_sec": 600},        # a v1 answer / refused members section
    {"trusted": True, "reconcile_sec": None},        # no reconcileSec from the server
    {"trusted": True, "reconcile_sec": 0},
    {"trusted": True, "reconcile_sec": -5},
    {"trusted": True, "reconcile_sec": True},        # a bool is not a number of seconds
    {"trusted": True, "reconcile_sec": "600"},
])
def test_untrusted_or_no_reconcile_sec_is_not_safety_mode(monkeypatch, state) -> None:
    assert _app_with(monkeypatch, state=state)._v2_safety_sync() is None


def test_an_unreadable_state_is_not_safety_mode(monkeypatch) -> None:
    assert _app_with(monkeypatch, state_raises=True)._v2_safety_sync() is None


# ── the timer ───────────────────────────────────────────────────────────────────────
from tests.test_sync_retry_and_rerun import _CapturedThread, _Harness  # noqa: E402


@pytest.fixture
def h(monkeypatch, tmp_path):
    harness = _Harness(monkeypatch, tmp_path)
    harness.safety: Optional[Dict[str, Any]] = None
    harness.app._v2_safety_sync = lambda: harness.safety
    monkeypatch.setattr(sync_cadence, "_uniform", lambda a, b: b)
    return harness


def test_without_v2_the_timer_is_the_healthy_interval(h) -> None:
    h.tick()
    assert h.armed_sync_timer_sec() == pytest.approx(BASE, abs=0.05)


def test_with_v2_and_the_socket_up_the_timer_is_reconcile_sec(h) -> None:
    h.safety = dict(UP)
    h.tick()
    assert h.armed_sync_timer_sec() == pytest.approx(600, abs=0.05)


def test_with_v2_and_the_socket_down_the_timer_is_two_minutes(h) -> None:
    h.safety = dict(DOWN)
    h.tick()
    assert h.armed_sync_timer_sec() == pytest.approx(120, abs=0.05)


def test_the_failure_retry_schedule_is_unchanged_in_safety_mode(h) -> None:
    """The retry steps and the Retry-After clamp keep the OLD healthy interval as their cap:
    a 2-min cadence must not become the ceiling of an outage's back-off (or of a 429)."""
    h.safety = dict(DOWN)
    for fails, step in [(1, 15), (2, 30), (3, 60), (4, 120), (5, 300), (6, 300)]:
        h.tick()
        h.finish_worker(fail=True)
        h.run_due()
        assert h.app._sync_fail_count == fails
        assert h.armed_sync_timer_sec() == pytest.approx(step, rel=0.21), (fails, step)


def test_a_429_retry_after_is_not_clamped_to_the_safety_cadence(h) -> None:
    from app.api.monclub_api import MonClubApiHttpError

    h.safety = dict(DOWN)
    err = MonClubApiHttpError("getSyncData failed: HTTP 429 -> busy", status_code=429)
    err.retry_after_sec = 900.0
    h.api_error = err
    h.tick()
    h.finish_worker(fail=True)
    h.run_due()
    assert h.armed_sync_timer_sec() == pytest.approx(900, abs=0.05)


# ── tightening: a socket that drops, the switch that comes on ──────────────────────


def test_a_dropped_socket_brings_the_next_sync_forward_to_two_minutes(h) -> None:
    h.safety = dict(UP)
    h.tick()
    assert h.armed_sync_timer_sec() == pytest.approx(600, abs=0.05)
    h.safety = dict(DOWN)

    h.app._tighten_sync_timer("socket-down")

    assert h.armed_sync_timer_sec() == pytest.approx(120, abs=0.05)


def test_tightening_never_pushes_a_sync_back(h) -> None:
    h.safety = dict(DOWN)
    h.tick()
    h.safety = dict(UP)                      # the socket came back: the next tick decides
    h.app._tighten_sync_timer("socket-up")
    assert h.armed_sync_timer_sec() == pytest.approx(120, abs=0.05)


def test_tightening_leaves_a_failure_retry_alone(h) -> None:
    h.safety = dict(DOWN)
    h.tick()
    h.finish_worker(fail=True)
    h.run_due()
    for _ in range(4):
        h.tick()
        h.finish_worker(fail=True)
        h.run_due()
    armed = h.armed_sync_timer_sec()           # the 300 s outage step
    h.app._tighten_sync_timer("socket-down")
    assert h.armed_sync_timer_sec() == pytest.approx(armed, abs=0.05)


def test_tightening_does_nothing_on_an_old_server(h) -> None:
    h.tick()
    h.app._tighten_sync_timer("availability")
    assert h.armed_sync_timer_sec() == pytest.approx(BASE, abs=0.05)


# ── the runtime asks the app to re-check its cadence ───────────────────────────────
from tests.test_v2_runtime import FakeApp, _isolate, _runtime  # noqa: E402,F401  (autouse fixture)


class _CadenceApp(FakeApp):
    def __init__(self):
        super().__init__()
        self.tightened = []

    def _tighten_sync_timer(self, reason):
        self.tightened.append(reason)


def _cadence_runtime():
    from app.core.v2 import runtime as rtmod

    app = _CadenceApp()
    rt, _app, _calls = _runtime()
    rt.app = app
    return rt, app


def test_v2_coming_on_asks_the_app_to_tighten_its_timer() -> None:
    rt, app = _cadence_runtime()
    rt.refresh_assignment()
    assert rt.availability == "ON"
    assert app.tightened == ["v2-on"]
    rt.refresh_assignment()                              # still ON: nothing new
    assert app.tightened == ["v2-on"]


def test_a_dropped_socket_asks_the_app_to_tighten_its_timer() -> None:
    rt, app = _cadence_runtime()
    rt.on_disconnected("half-open (no frame from the server)")
    assert app.tightened == ["socket-down"]


def test_an_app_without_the_hook_is_left_alone() -> None:
    rt, app = _runtime()[:2]
    rt.on_disconnected("ended")                          # FakeApp has no _tighten_sync_timer
    rt._set_availability("OFF")
    rt._set_availability("ON")


# ── DEVICE-mode panels keep their healthy-interval reconcile ──────────────────────
from tests.test_p3b1_app_wiring import _Api, _NOTHING, _run_worker, fake_tel, wired  # noqa: E402,F401


def _two_timer_ticks(wired, monkeypatch, safety):
    import app.ui.app as app_module

    ev = wired.events
    wired.app._api = lambda: _Api([_NOTHING, _NOTHING], ev)
    wired.app._maybe_apply_date_flips = lambda source: None
    wired.app._apply_date_flips = lambda source, **_kw: None
    wired.app._v2_safety_sync = lambda: safety
    wired.app.get_access_mode_summary = lambda: {"DEVICE": 1, "AGENT": 0, "ULTRA": 0, "UNKNOWN": 0}
    wired.app._restriction_reasons = lambda: []
    wired.app.cfg.device_sync_enabled = True
    wired.app._device_sync_engine = MagicMock()
    wired.app._device_sync_engine.run_blocking.side_effect = (
        lambda **kw: ev.append(("reconcile", kw.get("changed_ids"))) or False)
    monkeypatch.setattr(app_module, "save_sync_cache_delta", lambda data, refresh: {})
    monkeypatch.setattr(app_module, "load_sync_cache", lambda: SimpleNamespace(users=[], devices=[]))
    _run_worker(wired)
    MainApp._on_sync_work_finished(wired.app)
    _run_worker(wired)
    return [e for e in ev if e[0] == "reconcile"]


from app.ui.app import MainApp  # noqa: E402


def test_without_v2_every_timer_tick_still_reconciles_the_panels(wired, monkeypatch) -> None:
    assert _two_timer_ticks(wired, monkeypatch, None) == [("reconcile", None), ("reconcile", None)]


def test_a_second_safety_tick_within_the_healthy_interval_leaves_the_panels_alone(wired, monkeypatch) -> None:
    assert _two_timer_ticks(wired, monkeypatch, dict(UP)) == [("reconcile", None)]


# ================================================================== step 3: probe gating
# The 45 s members-version probe and the in-memory 22:00 job are off while -- and only while --
# the safety sync runs: same predicate, so the probe can never be off while the cadence is 30 min.


class _ProbeApp:
    def __init__(self, gated):
        self._gated = gated
        self._pending_sync_context = None
        self.after_calls = []

    def change_detection_gated(self):
        return self._gated

    def after(self, ms, fn):
        self.after_calls.append(ms)

    def request_sync_now(self):
        pass


def _detector(app, monkeypatch, calls):
    import app.core.change_detector as cd

    class _Resp:
        status_code = 200

        @staticmethod
        def json():
            calls.append("json")
            return {"lastModifiedAt": "2026-09-26T10:00:0%d" % len(calls)}

    monkeypatch.setattr(cd._requests, "get",
                        lambda url, headers=None, timeout=None: calls.append("get") or _Resp())
    det = cd.ChangeDetectorService(app=app, backend_base_url="https://example.test",
                                   get_token_fn=lambda: "jwt", re_login_fn=lambda: None, gym_id=45,
                                   logger=MagicMock())
    return det


def test_the_probe_makes_no_request_while_the_safety_sync_runs(monkeypatch) -> None:
    calls = []
    det = _detector(_ProbeApp(gated=True), monkeypatch, calls)
    det._poll_once()
    det._poll_once()
    assert calls == []


def test_the_probe_is_unchanged_without_it(monkeypatch) -> None:
    calls = []
    app = _ProbeApp(gated=False)
    det = _detector(app, monkeypatch, calls)
    det._poll_once()                       # baseline
    det._poll_once()                       # a newer lastModifiedAt -> a sync request
    assert calls.count("get") == 2
    assert app._pending_sync_context is not None
    assert app._pending_sync_context.trigger_source == "CHANGE_DETECTOR"


def test_a_probe_gate_that_raises_keeps_the_probe_running(monkeypatch) -> None:
    calls = []
    app = _ProbeApp(gated=False)
    app.change_detection_gated = lambda: 1 / 0
    det = _detector(app, monkeypatch, calls)
    det._poll_once()
    assert calls.count("get") == 1


def test_the_app_gate_is_the_safety_predicate(monkeypatch) -> None:
    app = _app_with(monkeypatch)
    assert app.change_detection_gated() is True
    app = _app_with(monkeypatch, availability="OFF")
    assert app.change_detection_gated() is False
    app = _app_with(monkeypatch, state={"trusted": False, "reconcile_sec": 600})
    assert app.change_detection_gated() is False


# -- the 22:00 job --


def _daily_app(monkeypatch, *, safety, manual=False):
    import app.ui.app as app_module

    app = object.__new__(app_module.MainApp)
    app.logger = MagicMock()
    app._daily_sync_hour = 0                     # "now" is always past the hour
    app._daily_sync_last_run_date = None
    app._daily_sync_after_id = None
    app.after = lambda ms, fn: "id"
    app.request_sync_now = MagicMock()
    app._v2_safety_sync = lambda: safety
    monkeypatch.setattr("app.core.settings_reader.get_backend_global_settings",
                        lambda: {"manual_sync_mode": manual})
    return app


def test_the_daily_job_fires_without_the_safety_sync(monkeypatch) -> None:
    app = _daily_app(monkeypatch, safety=None)
    app._daily_sync_check()
    app.request_sync_now.assert_called_once()
    assert app.request_sync_now.call_args.kwargs["trigger_hint"] == {"reason": "daily-auto-sync"}


def test_the_daily_job_is_off_while_the_safety_sync_runs(monkeypatch) -> None:
    app = _daily_app(monkeypatch, safety=dict(UP))
    app._daily_sync_check()
    app._daily_sync_check()
    app.request_sync_now.assert_not_called()
    assert app._daily_sync_last_run_date is None, "not marked: it fires later today if the gate lifts"


def test_the_daily_job_fires_later_the_same_day_if_the_safety_sync_stops(monkeypatch) -> None:
    app = _daily_app(monkeypatch, safety=dict(UP))
    app._daily_sync_check()
    app._v2_safety_sync = lambda: None          # e.g. a v1 answer dropped trust at 22:40
    app._daily_sync_check()
    app.request_sync_now.assert_called_once()


def test_a_manual_sync_gym_keeps_its_daily_push_in_safety_mode(monkeypatch) -> None:
    """In manual sync mode the 22:00 job is the only automatic push of the day (the safety
    sync is a TIMER sync, which manual mode never pushes): it stays."""
    app = _daily_app(monkeypatch, safety=dict(UP), manual=True)
    app._daily_sync_check()
    app.request_sync_now.assert_called_once()


# ================================================================== review round 1
from app.core.sync_observability import SyncTriggerContext  # noqa: E402


def _feedback_app(safety):
    import app.ui.app as app_module

    app = object.__new__(app_module.MainApp)
    app.logger = MagicMock()
    app.publish_feedback_event = MagicMock()
    app._v2_safety_sync = lambda: safety
    return app


@pytest.mark.parametrize(("safety", "source", "changes", "played"), [
    (None, "TIMER", False, True),                 # today: the 30-min timer sync plays it
    (dict(DOWN), "TIMER", False, False),          # a safety tick that brought nothing: silent
    (dict(UP), "TIMER", False, False),
    (dict(DOWN), "TIMER", True, True),            # one that brought a change plays it (R2-5)
    (dict(UP), "SYNC_NOW_API", False, True),      # a sync someone asked for still does
    (dict(UP), "REALTIME_NOTICE", False, True),   # P3b-2's notice syncs: unchanged
])
def test_r1_the_success_sound_is_not_played_on_every_safety_tick(safety, source, changes, played) -> None:
    app = _feedback_app(safety)
    app._maybe_emit_sync_success_feedback(
        sync_run_id=7, final_status="SUCCESS",
        trigger_context=SyncTriggerContext(run_type="PERIODIC", trigger_source=source),
        brought_changes=changes)
    assert app.publish_feedback_event.called is played

"""The update check runs every 3 hours, not every 60 s (field log 2026-09-30, gym PC "Accueil").

The dataclass default was a leftover ``30`` -- the original line
``# update_check_interval_sec: int = 3 * 60 * 60  # 3 hours`` sat commented out right above it
(commit 0548a1d) -- and ``from_dict`` clamped it to 60, so 1.4.35 asked the server for the latest
release 60 times an hour. Every install has that 30 persisted in its config.json
(``ACCESS_CONFIG_FIELDS`` saves the field), so the fix must also hold for a file that says 30.
"""
from __future__ import annotations

import json

import pytest

from app.core.config import DEFAULT_UPDATE_CHECK_INTERVAL_SEC, AppConfig

THREE_HOURS = 3 * 60 * 60


def test_the_default_is_three_hours():
    assert DEFAULT_UPDATE_CHECK_INTERVAL_SEC == THREE_HOURS
    assert AppConfig().update_check_interval_sec == THREE_HOURS
    assert AppConfig.from_dict({}).update_check_interval_sec == THREE_HOURS


@pytest.mark.parametrize("stored", [30, 0, 59, -5, "junk", None])
def test_a_value_below_the_floor_or_unreadable_falls_back_to_the_default(stored):
    # Below 60 s was never honoured (always clamped to 60); the only writer of such a value
    # was the leftover default itself.
    assert AppConfig.from_dict({"update_check_interval_sec": stored}).update_check_interval_sec == THREE_HOURS


@pytest.mark.parametrize("stored", [60, 600, 3600, THREE_HOURS, 86400])
def test_an_explicit_value_at_or_above_the_floor_is_kept(stored):
    assert AppConfig.from_dict({"update_check_interval_sec": stored}).update_check_interval_sec == stored


def test_an_installed_config_json_holding_the_old_30_loads_as_three_hours(tmp_path, monkeypatch):
    import shared.config as shared_config

    path = tmp_path / "config.json"
    path.write_text(json.dumps({"update_check_interval_sec": 30}), encoding="utf-8")
    monkeypatch.setattr(shared_config, "_component_config_path", lambda component: path)
    monkeypatch.setattr(shared_config, "migrate_split_config_if_needed", lambda: None)

    cfg = shared_config.load_component_app_config("access")

    assert cfg.update_check_interval_sec == THREE_HOURS
    assert shared_config._build_access_section_from_cfg(cfg).update_check_interval_sec == THREE_HOURS


def test_the_update_manager_schedules_the_configured_interval():
    from types import SimpleNamespace

    from shared.update_runtime import ComponentUpdateManager

    mgr = ComponentUpdateManager.__new__(ComponentUpdateManager)
    mgr.cfg = AppConfig.from_dict({"update_check_interval_sec": 30})
    assert mgr._interval_ms() == THREE_HOURS * 1000
    mgr.cfg = SimpleNamespace(update_check_interval_sec=0)
    assert mgr._interval_ms() == THREE_HOURS * 1000


# ---- A failed check is retried soon, not after 3 hours (review, 2026-09-30) ----
class _FakeApp:
    """Tk's after/after_cancel, run by hand: the scheduled delays are what is under test."""

    def __init__(self):
        self.scheduled: list[tuple[str, int, object]] = []
        self._n = 0

    def after(self, delay_ms, fn):
        self._n += 1
        aid = f"after#{self._n}"
        self.scheduled.append((aid, int(delay_ms), fn))
        return aid

    def after_cancel(self, aid):
        self.scheduled = [s for s in self.scheduled if s[0] != aid]

    def on_update_error(self, msg):
        pass

    def on_update_status_changed(self, st):
        pass


class _Api:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)

    def get_latest_software_release(self, **kwargs):
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _manager(outcomes, install_root):
    import logging

    from shared.component_identity import get_component_identity
    from shared.update_runtime import ComponentUpdateManager

    app = _FakeApp()
    api = _Api(outcomes)
    mgr = ComponentUpdateManager(
        component=get_component_identity("access"),
        app=app,
        cfg=AppConfig(),
        logger=logging.getLogger("test.update"),
        api_factory=lambda: api,
        install_root=install_root,
        keys_provider=lambda: {},
        auto_install_allowed=False,
        setup_running=lambda: False,
    )
    mgr._running = True
    mgr._token = "tok"
    mgr.get_current_version = lambda: "1.4.35"
    mgr.get_current_release_id = lambda: "rid"
    mgr.get_current_codename = lambda: ""
    app.scheduled.clear()
    return mgr, app


def _run_tick(mgr, app, monkeypatch):
    """One _tick with the worker thread run inline; returns the delay now scheduled."""
    import shared.update_runtime as ur

    class _Inline:
        def __init__(self, target, **kwargs):
            self._t = target

        def start(self):
            self._t()

    monkeypatch.setattr(ur.threading, "Thread", _Inline)
    mgr._tick()
    # Retries are handed back to the Tk thread through after(0, ...): run those.
    while any(d == 0 for _, d, _ in app.scheduled):
        aid, _, fn = next(s for s in app.scheduled if s[1] == 0)
        app.scheduled = [s for s in app.scheduled if s[0] != aid]
        fn()
    assert len(app.scheduled) == 1, app.scheduled
    return app.scheduled[0][1]


def test_a_failed_check_is_retried_after_60s_then_5min_then_15min_then_the_interval(monkeypatch, tmp_path):
    boom = RuntimeError("network down")
    mgr, app = _manager([boom, boom, boom, boom, {"version": "1.4.35"}, boom], tmp_path)
    assert _run_tick(mgr, app, monkeypatch) == 60 * 1000
    assert _run_tick(mgr, app, monkeypatch) == 5 * 60 * 1000
    assert _run_tick(mgr, app, monkeypatch) == 15 * 60 * 1000
    assert _run_tick(mgr, app, monkeypatch) == 15 * 60 * 1000  # capped
    assert _run_tick(mgr, app, monkeypatch) == THREE_HOURS * 1000  # success: back to normal
    assert _run_tick(mgr, app, monkeypatch) == 60 * 1000  # a new failure starts over


def test_a_successful_check_keeps_the_normal_interval(monkeypatch, tmp_path):
    mgr, app = _manager([{"version": "1.4.35"}], tmp_path)
    assert _run_tick(mgr, app, monkeypatch) == THREE_HOURS * 1000

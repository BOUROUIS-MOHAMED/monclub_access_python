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

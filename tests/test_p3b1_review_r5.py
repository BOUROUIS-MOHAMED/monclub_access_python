"""P3b-1 adversarial review, round 5: regressions for the confirmed findings.

Real temp SQLite through the ``app.core.db._DB_PATH`` override; no network.
"""
from __future__ import annotations

import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import app.core.db as dbmod
import app.ui.app as app_module
from app.ui.app import MainApp
from tests.test_protocol2_save_and_flip import NOTHING, _flip, _ids, _seed_full_v2


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "r5.db"), raising=False)
    dbmod._shutdown_db_writer_for_tests()
    dbmod.init_db()
    yield dbmod
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


# ================================================================== 1. held rows when trust drops
def test_a_trust_drop_puts_the_held_rows_back_like_a_v1_pc(db):
    # Review R5: 2 was held for its freeze day; a v1 answer with the members section skipped
    # dropped trust, and every later flip returned 'untrusted' before it could restore 2, so a
    # paying member stayed off the roster offline. Untrusted = base behaviour: the server's list.
    _seed_full_v2(db)
    r = _flip(db, "2026-09-20T07:30:00+01:00")
    assert 2 in _ids("sync_users_held") and 1 in _ids("sync_users_held")
    out = db.save_sync_cache_delta({"refreshMembers": False, "users": []}, NOTHING) or {}
    assert (out.get("protocol2") or {}).get("trusted") is False
    r = _flip(db, "2026-09-20T09:00:00+01:00")
    assert r["skipped"] == "untrusted" and r["restored"] == 2 and r["moved"] == 2
    assert {1, 2, 5} <= _ids("sync_users") and _ids("sync_users_held") == set()
    r = _flip(db, "2026-09-21T07:30:00+01:00")
    assert r["skipped"] == "untrusted" and r["moved"] == 0


def test_a_trust_drop_keeps_a_fresher_row_a_fast_patch_put_back(db):
    _seed_full_v2(db)
    _flip(db, "2026-09-20T07:30:00+01:00")
    from tests.test_protocol2_save_and_flip import _row, _user_row
    db.save_sync_cache_delta({"refreshMembers": False, "users": []}, NOTHING)
    db.upsert_delta_users([_row(2, fullName="FRESH")])       # back on sync_users meanwhile
    _flip(db, "2026-09-20T09:00:00+01:00")
    assert _user_row(2)["full_name"] == "FRESH"


# ================================================================== 2. a flip that outlived its wait
@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "r5_app.db"), raising=False)
    monkeypatch.setattr(app_module, "_tel", MagicMock())
    monkeypatch.setattr("app.core.settings_reader.get_backend_global_settings", lambda: {})
    monkeypatch.setattr("app.core.db.invalidate_sync_cache", MagicMock())
    monkeypatch.setattr("app.core.db.refresh_sync_cache_async", MagicMock())
    monkeypatch.setattr("app.core.db.get_access_v2_state", lambda: {"utc_offset_sec": 3600})
    bumps = MagicMock()
    monkeypatch.setattr("app.core.db.bump_local_state_generation", bumps)
    a = object.__new__(MainApp)
    a.logger = MagicMock()
    a.cfg = SimpleNamespace(offline_revoke_grace_days=0)
    a._stop_event = threading.Event()
    MainApp._init_scheduler(a)
    MainApp._init_date_flip_state(a)
    a._ultra_lock = threading.Lock()
    a._ultra_engine = MagicMock(running=True)
    a._agent_engine = MagicMock()
    a.request_sync_now = MagicMock()
    a._date_flip_now = lambda: 1_790_000_000.0
    a.bumps = bumps
    return a


def _result(**over):
    out = {"gym_date": "2026-09-20", "pc_date": "2026-09-20", "applied_before": "2026-09-20",
           "held": 0, "restored": 0, "promoted": 0, "moved": 0, "hold_reasons": {}, "starters": [],
           "clock_suspect": False, "clock_reason": "", "clock_changed": False, "trusted": True,
           "skipped": None}
    out.update(over)
    return out


def test_a_flip_that_timed_out_is_announced_by_the_next_run(app, monkeypatch):
    # Review R5: _run_db_write_sync gave up after 60 s but the job committed later; the app logged
    # DATE_FLIP_FAILED, never woke the caches or ULTRA, and the precheck then saw nothing to do.
    calls = []

    def flip(**kw):
        calls.append(kw)
        if len(calls) == 1:
            raise TimeoutError("Timed out waiting for DB writer job 'apply_local_date_flips'")
        return _result()                                   # the late commit already moved the rows

    monkeypatch.setattr("app.core.db.apply_local_date_flips", flip)
    assert app._apply_date_flips("midnight") is None
    assert app._date_flip_needed({"needs_flip": False, "grace_days": 0}) is True
    app._apply_date_flips("tick")
    app._ultra_engine.request_sync_now.assert_called_once_with(changed_ids=None, reason="date-flip")
    app.bumps.assert_called()
    assert app._date_flip_needed({"needs_flip": False, "grace_days": 0}) is False


def test_an_ordinary_flip_that_moves_nothing_wakes_nobody(app, monkeypatch):
    monkeypatch.setattr("app.core.db.apply_local_date_flips", lambda **kw: _result())
    app._apply_date_flips("tick")
    app._ultra_engine.request_sync_now.assert_not_called()

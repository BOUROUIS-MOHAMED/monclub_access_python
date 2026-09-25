"""P3b-1 adversarial review, round 3: regressions for the confirmed findings.

Real temp SQLite through the ``app.core.db._DB_PATH`` override; no network.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import app.core.db as dbmod
from app.ui.app import MainApp
from tests.test_protocol2_save_and_flip import (
    MEMBERS_ONLY, _epoch, _flip, _ids, _meta, _row, _seed_full_v2, _v2, _window,
)


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "r3.db"), raising=False)
    dbmod._shutdown_db_writer_for_tests()
    dbmod.init_db()
    yield dbmod
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


# ================================================================== 1. a promoted row the server drops
def _shadow_sync(data, outcome):
    """The app's revocation source for a sync (MainApp._apply_member_shadow_sync), as work() calls it."""
    app = SimpleNamespace(logger=MagicMock())
    return MainApp._apply_member_shadow_sync(
        app, data=data, refresh=MEMBERS_ONLY, delta_changed_ids=None,
        cache_members_delete_refused=bool(outcome.get("members_delete_refused")),
        authoritative_member_ids=outcome.get("authoritative_member_ids"),
        authoritative_member_ids_valid=bool(outcome.get("authoritative_member_ids_valid", True)),
        accepted_member_user_indexes=outcome.get("accepted_member_user_indexes"),
        accepted_member_ids=outcome.get("accepted_member_ids"),
    )


def test_a_promoted_pre_sale_the_next_sync_drops_is_revoked(db):
    # Review R3: 3 (a pre-sale starting on the 20th) reached sync_users only through the flip, so
    # it was not in member_shadow; the sync that no longer lists it (cancelled offline) produced no
    # revocation and the turnstile kept its pin.
    seed = _v2([_row(1, until="2026-09-19"), _row(2, off=["2026-09-20"]), _row(5)],
               upcoming=[_row(3, frm="2026-09-20", qrAccountId=55)])
    _shadow_sync(seed, db.save_sync_cache_delta(seed, MEMBERS_ONLY) or {})
    r = _flip(db, "2026-09-20T07:30:00+01:00")
    assert r["promoted"] == 1 and 3 in _ids("sync_users")

    morning = _v2([], delta=True, valid=[5], member_windows=[_window(5)], upcoming=[],
                  meta=_meta(today="2026-09-20", horizon_end="2026-09-27",
                             server_time="2026-09-20T09:00:00.000+01:00"),
                  received=_epoch("2026-09-20T09:00:02+01:00"), windows_version="p2.7.c.d")
    out = db.save_sync_cache_delta(morning, MEMBERS_ONLY) or {}
    _changed, revoked = _shadow_sync(morning, out)
    assert 3 not in _ids("sync_users")
    assert 3 in revoked


def test_a_promoted_row_the_next_sync_lists_is_not_revoked(db):
    seed = _v2([_row(1, until="2026-09-19"), _row(5)],
               upcoming=[_row(3, frm="2026-09-20", qrAccountId=55)])
    _shadow_sync(seed, db.save_sync_cache_delta(seed, MEMBERS_ONLY) or {})
    _flip(db, "2026-09-20T07:30:00+01:00")
    morning = _v2([_row(3, frm="2026-09-20")], delta=True, valid=[3, 5],
                  member_windows=[_window(5)], upcoming=[],
                  meta=_meta(today="2026-09-20", horizon_end="2026-09-27",
                             server_time="2026-09-20T09:00:00.000+01:00"),
                  received=_epoch("2026-09-20T09:00:02+01:00"), windows_version="p2.7.c.d")
    _changed, revoked = _shadow_sync(morning, db.save_sync_cache_delta(morning, MEMBERS_ONLY) or {})
    assert 3 not in revoked and 3 in _ids("sync_users")

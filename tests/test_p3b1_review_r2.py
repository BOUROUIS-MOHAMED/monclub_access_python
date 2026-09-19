"""P3b-1 adversarial review, round 2: regressions for the confirmed findings.

Real temp SQLite through the ``app.core.db._DB_PATH`` override; no network.
"""
from __future__ import annotations

from datetime import date

import pytest

import app.core.db as dbmod
from app.core import access_dates as ad
from tests.test_protocol2_save_and_flip import _flip, _ids, _seed_full_v2


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "r2.db"), raising=False)
    dbmod._shutdown_db_writer_for_tests()
    dbmod.init_db()
    yield dbmod
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


# ================================================================== 1. a huge offline grace
@pytest.mark.parametrize("grace", [9_999_999, 10 ** 12])
def test_a_huge_grace_is_a_grace_not_an_overflow(grace):
    w = ad.AccessWindow(date(2026, 9, 1), date(2026, 9, 19), frozenset())
    assert ad.window_status(w, date(2026, 9, 20), horizon_end=date(2026, 9, 26),
                            server_today=date(2026, 9, 19), grace_days=grace) == "grace"


def test_the_grace_boundary_is_unchanged():
    w = ad.AccessWindow(date(2026, 9, 1), date(2026, 9, 19), frozenset())
    kw = dict(horizon_end=date(2026, 9, 26), server_today=date(2026, 9, 19), grace_days=2)
    assert ad.window_status(w, date(2026, 9, 21), **kw) == "grace"
    assert ad.window_status(w, date(2026, 9, 22), **kw) == "expired"


def test_an_offline_flip_with_a_huge_grace_still_moves_the_other_rows(db):
    # 1 ends on the 19th (kept by the grace); 2 is frozen on the 20th (held); 3 starts (promoted).
    _seed_full_v2(db)
    r = _flip(db, "2026-09-20T07:30:00+01:00", grace=9_999_999)
    assert r["held"] == 1 and r["promoted"] == 1
    assert 1 in _ids("sync_users") and 2 in _ids("sync_users_held") and 3 in _ids("sync_users")

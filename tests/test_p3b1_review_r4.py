"""P3b-1 adversarial review, round 4: regressions for the confirmed findings.

Real temp SQLite through the ``app.core.db._DB_PATH`` override; no network.
"""
from __future__ import annotations

import pytest

import app.core.db as dbmod
from tests.test_p3b1_review_r3 import _shadow_sync
from tests.test_protocol2_save_and_flip import (
    MEMBERS_ONLY, _epoch, _flip, _ids, _meta, _row, _v2, _window,
)


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "r4.db"), raising=False)
    dbmod._shutdown_db_writer_for_tests()
    dbmod.init_db()
    yield dbmod
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


def _shadow_has(am):
    with dbmod.get_conn() as c:
        return am in {int(r[0]) for r in c.execute("SELECT active_membership_id FROM member_shadow")}


# ================================================================== 1. an answer of the previous day
def _midnight_then_stale_answer(db, *, delta):
    # D = 2026-09-19: 1 ends on D, 5 ongoing, 3 is a pre-sale starting D+1.
    seed = _v2([_row(1, until="2026-09-19"), _row(5)],
               upcoming=[_row(3, frm="2026-09-20", qrAccountId=55)])
    _shadow_sync(seed, db.save_sync_cache_delta(seed, MEMBERS_ONLY) or {})
    r = _flip(db, "2026-09-20T00:00:05+01:00")               # midnight: 3 promoted, 1 held
    assert r["promoted"] == 1 and 3 in _ids("sync_users")
    # Answered at 23:59:58 on D (today = D), saved just after midnight, then work()'s order:
    # save -> flip("save") -> shadow sync.
    stale = _v2([_row(5)] if not delta else [], delta=delta,
                valid=[1, 5] if delta else None,
                member_windows=([_window(1, until="2026-09-19"), _window(5)] if delta else []),
                upcoming=[_row(3, frm="2026-09-20", qrAccountId=55)],
                meta=_meta(today="2026-09-19", horizon_end="2026-09-26",
                           server_time="2026-09-19T23:59:58.000+01:00"),
                received=_epoch("2026-09-20T00:00:01+01:00"), windows_version="p2.7.x.y")
    if not delta:
        stale["users"] = [_row(1, until="2026-09-19"), _row(5)]
    out = db.save_sync_cache_delta(stale, MEMBERS_ONLY) or {}
    _flip(db, "2026-09-20T00:00:06+01:00")
    return _shadow_sync(stale, out)


@pytest.mark.parametrize("delta", [True, False])
def test_a_previous_day_answer_after_midnight_does_not_revoke_the_promoted_starter(db, delta):
    # Review R4: the flip after the save put 3 back (it is still upcoming on day D) and wrote its
    # shadow row; the shadow sync then deleted that row and returned 3 as revoked -- ULTRA removed
    # the pin of a member the PC admits today.
    _changed, revoked = _midnight_then_stale_answer(db, delta=delta)
    assert 3 in _ids("sync_users")
    assert 3 not in revoked
    assert _shadow_has(3)


def test_a_membership_the_server_really_dropped_is_still_revoked(db):
    seed = _v2([_row(1), _row(5)])
    _shadow_sync(seed, db.save_sync_cache_delta(seed, MEMBERS_ONLY) or {})
    gone = _v2([], delta=True, valid=[5], member_windows=[_window(5)])
    _changed, revoked = _shadow_sync(gone, db.save_sync_cache_delta(gone, MEMBERS_ONLY) or {})
    assert 1 in revoked and not _shadow_has(1)


def test_the_shadow_batch_write_is_timed_again():
    # Review R4: a266f20 left @_tel.timed("SHADOW_DIFF") on the per-row helper.
    assert hasattr(dbmod.upsert_member_shadow, "__wrapped__")
    assert not hasattr(dbmod._upsert_member_shadow_row, "__wrapped__")

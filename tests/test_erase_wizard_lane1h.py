"""Lane 1h (2026-09-28): the independent review of lane 1g -- the Erase wizard's code points.

Guide §3.2h. Against the same fakes as tests/test_erase_wizard.py -- nothing reaches a device:
* C1  a sync answer that carries no device list empties ``sync_devices`` AND deletes the whole-list
      marker, in the same transaction, in both writers (``_save_sync_cache``,
      ``save_sync_cache_delta``) -- a stale marker would make a later fast patch's single row read
      as the whole list, and a cut run's hold would be released at start-up;
* C3  the upgrade path: an existing database gets the marker table empty, and fails closed until
      its first device refresh AND the start after it.
"""
from __future__ import annotations

import sqlite3

import app.core.db as dbmod
from app.core import device_hold
from tests.test_erase_wizard import sqlite_db  # noqa: F401 -- the fixture is used by name
from tests.test_erase_wizard_lane1e import _hold_row, _restart, _signed_in
from tests.test_erase_wizard_lane1g import (
    _cut_run_row, _device_bundle, _device_ids, _device_payload, _marker,
)

_DEVICES_ONLY = {"members": False, "devices": True, "credentials": False, "settings": False}


def _listless_full(db):
    """A 2xx answer with no ``devices`` key, through the full save."""
    db.save_sync_cache({"users": []})


def _listless_delta(db):
    """The same through the delta writer: ``get_sync_data`` always adds ``_clientReceivedAtEpoch``
    (so the payload is never empty -- ``{}`` returns before any write), and app.py defaults
    ``refreshDevices`` to True."""
    db.save_sync_cache_delta({"_clientReceivedAtEpoch": 1790000000}, dict(_DEVICES_ONLY))


# ─────────────────────── C1: a list-less answer deletes the marker ───────────────────────

class TestAListLessAnswerDeletesTheMarker:

    def test_the_full_save(self, sqlite_db):
        db = sqlite_db
        db.save_sync_cache({"users": [], "devices": [_device_payload(5), _device_payload(6)]})
        assert _marker(db) and _device_ids(db) == [5, 6]
        _listless_full(db)
        assert _device_ids(db) == [], "the table is emptied, as before"
        assert not _marker(db), "and its marker goes with it"

    def test_the_delta(self, sqlite_db):
        db = sqlite_db
        db.save_sync_cache_delta({"devices": [_device_payload(5), _device_payload(6)]},
                                 dict(_DEVICES_ONLY))
        assert _marker(db) and _device_ids(db) == [5, 6]
        _listless_delta(db)
        assert _device_ids(db) == []
        assert not _marker(db)

    def test_a_delta_without_its_devices_section_keeps_both(self, sqlite_db):
        """Control: ``refresh.devices`` False touches neither the list nor its marker."""
        db = sqlite_db
        db.save_sync_cache({"users": [], "devices": [_device_payload(5)]})
        db.save_sync_cache_delta({"_clientReceivedAtEpoch": 1790000000},
                                 dict(_DEVICES_ONLY, devices=False))
        assert _marker(db) and _device_ids(db) == [5]

    def test_an_empty_list_is_still_a_whole_list(self, sqlite_db):
        """Control: ``devices: []`` is a list -- the marker is written (the authority read then
        still needs a row, lane 1f)."""
        db = sqlite_db
        db.save_sync_cache({"users": [], "devices": []})
        assert _marker(db)
        db.save_sync_cache_delta({"devices": []}, dict(_DEVICES_ONLY))
        assert _marker(db)


class TestTheReviewChain:
    """Signed in with 5 and 6, a cut run's row on 5 that records MEMBERSHIP; a list-less answer;
    a fast patch for 6; a restart before the next real device refresh. Lane 1g released 5 as
    "deleted in MonClub" (the stale marker, the token and the patched row)."""

    def _chain(self, db, listless):
        _signed_in(db, 5, 6)
        _cut_run_row(db)
        listless(db)
        out = db.apply_fast_patch_bundle(_device_bundle(6))
        assert out["applied"] == 1, out
        assert _device_ids(db) == [6]
        _restart()
        assert device_hold.is_held(5), "released as 'deleted in MonClub' on a stale marker"
        assert _hold_row(db, 5)["reason"] == db.HOLD_REASON_ERASE_PREP, "left as it is"
        assert db.device_list_is_authoritative() is False

    def test_through_the_full_save(self, sqlite_db):
        self._chain(sqlite_db, _listless_full)

    def test_through_the_delta(self, sqlite_db):
        self._chain(sqlite_db, _listless_delta)

    def test_the_next_real_refresh_then_decides(self, sqlite_db):
        """Control: the next answer that carries the list writes the marker; 5 not in it reads as
        deleted in MonClub and is released at the start after it."""
        db = sqlite_db
        self._chain(db, _listless_delta)
        db.save_sync_cache_delta({"devices": [_device_payload(6)]}, dict(_DEVICES_ONLY))
        assert device_hold.is_held(5), "nothing releases it before a start"
        _restart()
        assert not device_hold.is_held(5) and _hold_row(db, 5) is None


# ─────────────────────── C3: the upgrade path ───────────────────────

def _table_exists(db, name):
    with db.get_conn() as conn:
        return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                            (name,)).fetchone() is not None


class TestTheUpgradePath:

    def test_an_existing_database_fails_closed_until_a_refresh_and_a_start(self, sqlite_db):
        """A database written before lane 1g: signed in, a device list (6 only) and its
        ``devicesVersion`` token, and no marker table. ``init_db`` creates the table EMPTY -- no
        marker is seeded from the rows or the token already there -- so a cut row on a turnstile
        missing from that list stays held across a start, until a device refresh writes the
        marker and the start after it reads the list as whole."""
        db = sqlite_db
        db.save_sync_cache({"users": [], "devices": [_device_payload(6)]})
        db.save_auth_token(email="gym@example.test", token="tok-lane1h")
        db.save_version_tokens({"devicesVersion": "dv-1"})
        with db.get_conn() as conn:
            conn.execute("DROP TABLE sync_device_list_state")
            conn.commit()
        assert not _table_exists(db, "sync_device_list_state")

        db.init_db()                                                  # the upgraded start
        assert _table_exists(db, "sync_device_list_state")
        assert not _marker(db), "no marker seeded on an existing database"
        assert _device_ids(db) == [6]
        assert db.device_list_is_authoritative() is False

        _cut_run_row(db, 5)
        _restart()
        assert device_hold.is_held(5)
        assert _hold_row(db, 5)["reason"] == db.HOLD_REASON_ERASE_PREP, "undecided: held"

        db.save_sync_cache_delta({"devices": [_device_payload(6)]}, dict(_DEVICES_ONLY))
        assert _marker(db) and db.device_list_is_authoritative() is True
        assert device_hold.is_held(5), "the refresh alone releases nothing"
        _restart()
        assert not device_hold.is_held(5) and _hold_row(db, 5) is None


def test_the_marker_table_is_created_by_init_db_on_a_database_without_it(tmp_path, monkeypatch):
    """The DDL itself, on a bare database file that already has the older tables: not under a
    swallowed try (a missing table would make every authority read raise -- fail closed, but every
    cut row would then stay held)."""
    path = tmp_path / "old.db"
    monkeypatch.setattr(dbmod, "_DB_PATH", str(path), raising=False)
    dbmod.init_db()
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("DROP TABLE sync_device_list_state")
        conn.commit()
    finally:
        conn.close()
    dbmod.init_db()
    conn = sqlite3.connect(str(path))
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(sync_device_list_state)").fetchall()]
        rows = conn.execute("SELECT COUNT(*) FROM sync_device_list_state").fetchone()[0]
    finally:
        conn.close()
    assert cols == ["id", "replaced_at"] and rows == 0

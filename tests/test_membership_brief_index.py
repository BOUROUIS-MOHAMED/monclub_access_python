"""Tests for db.get_membership_brief_index() — the cached scan-popup badge lookup
that replaced the per-scan get_sync_membership_brief() DB read on the ULTRA worker
loop (NOTIF_ENQUEUE_SLOW). Mirrors the proven get_staff_membership_ids cache:
generation-gated + 60s TTL, cosmetic-only (never gates a door decision).
"""

from __future__ import annotations

import importlib

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    importlib.reload(db_module)
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "mbrief.db"), raising=False)
    db_module.init_db()
    return db_module


def _insert(db_module, rows):
    with db_module.get_conn() as conn:
        conn.executemany(
            "INSERT INTO sync_memberships (id, title, description, price, duration_in_days, members_type) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()


def test_index_maps_plan_id_to_title_and_type(db):
    _insert(db, [
        (1, "Monthly", "", "50", 30, "NORMAL"),
        (2, "Staff Pass", "", "0", 365, "STAFF"),
    ])
    idx = db.get_membership_brief_index()
    assert idx[1]["title"] == "Monthly"
    assert idx[1]["membersType"] == "NORMAL"
    assert idx[2]["title"] == "Staff Pass"
    assert idx[2]["membersType"] == "STAFF"


def test_null_members_type_defaults_normal(db):
    _insert(db, [(3, "Legacy", "", "10", 30, None)])
    idx = db.get_membership_brief_index()
    assert idx[3]["membersType"] == "NORMAL"


def test_empty_when_no_memberships(db):
    assert db.get_membership_brief_index() == {}


def test_cached_until_generation_moves(db):
    _insert(db, [(1, "Monthly", "", "50", 30, "NORMAL")])
    first = db.get_membership_brief_index()
    assert 1 in first
    # A new plan inserted WITHOUT bumping the local-state generation is not seen
    # until the 60s TTL — the cache returns the same (stale) map. This proves the
    # per-scan DB read is actually avoided.
    _insert(db, [(9, "Later", "", "10", 30, "NORMAL")])
    second = db.get_membership_brief_index()
    assert 9 not in second  # served from cache, no re-query

    # Bumping the generation (a real members/creds refresh) forces a rebuild.
    db.bump_local_state_generation()
    third = db.get_membership_brief_index()
    assert 9 in third


# --- Non-blocking peeks used on the ULTRA hot path (must NEVER touch SQLite) ---

def _no_db(db, monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("hot-path peek must not open a DB connection")
    monkeypatch.setattr(db, "get_conn", _boom)


def test_brief_index_cached_never_queries_db(db, monkeypatch):
    _insert(db, [(1, "Monthly", "", "50", 30, "NORMAL")])
    db.get_membership_brief_index()  # warm on the (allowed) bg path
    _no_db(db, monkeypatch)          # now forbid any DB access
    idx = db.get_membership_brief_index_cached()
    assert idx[1]["title"] == "Monthly"  # served from cache, zero SELECTs


def test_brief_index_cached_empty_before_warm(db, monkeypatch):
    _no_db(db, monkeypatch)
    assert db.get_membership_brief_index_cached() == {}  # cold => empty, no DB


def test_staff_ids_cached_never_queries_db(db, monkeypatch):
    _insert(db, [(2, "Staff", "", "0", 365, "STAFF")])
    db.get_staff_membership_ids()  # warm on the (allowed) bg path
    _no_db(db, monkeypatch)
    assert 2 in db.get_staff_membership_ids_cached()  # served from cache


def test_staff_ids_cached_empty_before_warm(db, monkeypatch):
    _no_db(db, monkeypatch)
    assert db.get_staff_membership_ids_cached() == frozenset()  # cold => empty, no DB

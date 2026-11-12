import sqlite3

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    from app.core import db
    monkeypatch.setattr(db, "_DB_PATH", str(tmp_path / "successor.db"))
    db.init_db()
    return db


def plans():
    return [
        {"id": 1, "title": "Ancienne", "price": "90", "successorPlanId": 2, "futureField": True},
        {"id": 2, "title": "Actuelle", "price": "100"},
    ]


def assert_successor(db):
    rows = {r["id"]: r for r in db.list_sync_memberships()}
    assert rows[1]["successor_plan_id"] == 2
    assert rows[2]["successor_plan_id"] is None


def test_full_sync_keeps_successor_and_ignores_unknown_fields(db):
    db.save_sync_cache({"membership": plans(), "users": []})
    assert_successor(db)
    db.save_sync_cache_delta({"membership": [{"id": 1, "title": "Old server"}]}, {"settings": False,
                             "members": False, "devices": False, "credentials": False})
    assert_successor(db)
    db.save_sync_cache_delta({"membership": [{"id": 1, "successorPlanId": None}]}, {"settings": False,
                             "members": False, "devices": False, "credentials": False})
    assert db.list_sync_memberships()[0]["successor_plan_id"] is None


def test_delta_and_patch_replacements_keep_successor(db):
    db.save_sync_cache_delta({"membership": plans()}, {"members": False, "devices": False,
                             "credentials": False, "settings": False})
    assert_successor(db)
    db.apply_fast_patch_bundle({"schemaVersion": 1, "bundleId": "successor", "gymId": 1,
        "items": [{"kind": "SECTION_REPLACE", "entityType": "MEMBERSHIP_TYPE", "revision": "1",
                   "payload": {"membership": plans()}}]})
    assert_successor(db)
    db.save_sync_cache_delta({"membership": [{"id": 1, "title": "Old payload"}]}, {})
    assert db.list_sync_memberships()[0]["successor_plan_id"] is None


def test_existing_database_gains_nullable_column_without_losing_plans(tmp_path, monkeypatch):
    from app.core import db
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE sync_memberships (id INTEGER PRIMARY KEY, title TEXT, description TEXT, "
                     "price TEXT, duration_in_days INTEGER, members_type TEXT)")
        conn.execute("INSERT INTO sync_memberships (id, title) VALUES (7, 'Existing')")
    monkeypatch.setattr(db, "_DB_PATH", str(path))
    db.init_db()
    db.init_db()
    assert db.list_sync_memberships() == [{"id": 7, "title": "Existing", "description": None,
        "price": None, "duration_in_days": None, "members_type": None, "successor_plan_id": None}]

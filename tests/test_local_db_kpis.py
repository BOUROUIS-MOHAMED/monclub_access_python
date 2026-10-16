"""Card H item 11: Base locale tiles (GET /api/v2/db/kpis -> db.local_db_kpis).

Cards are counted per PERSON: one person has one sync_users row per membership with the same
cards, so a per-row count reports false duplicates. Door history to send uses the uploader's own
states and blank-row filter.
"""
from __future__ import annotations

import importlib

import pytest


@pytest.fixture()
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    importlib.reload(db_module)
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()
    return db_module


def _member(conn, *, amid, uid, mid=None, name="", c1="", c2=""):
    conn.execute(
        "INSERT INTO sync_users (user_id, active_membership_id, full_name, first_card_id, second_card_id,"
        " main_account_id) VALUES (?, ?, ?, ?, ?, ?)",
        (uid, amid, name, c1, c2, mid),
    )


def _history(conn, event_id, state, *, card="123", event_time="2026-10-16 10:00:00", created="2026-10-16T09:00:00"):
    conn.execute(
        "INSERT INTO access_history (created_at, event_id, card_no, event_time, backend_sync_state)"
        " VALUES (?, ?, ?, ?, ?)",
        (created, event_id, card, event_time, state),
    )


def test_one_person_with_several_memberships_is_not_a_duplicate(db):
    with db.get_conn() as conn:
        _member(conn, amid=1, uid=10, name="Ali", c1="555")
        _member(conn, amid=2, uid=10, name="Ali", c1="555")            # same person, 2nd membership
        _member(conn, amid=3, uid=11, mid=900, name="Sami", c1="777", c2="777")  # both columns, one person
        _member(conn, amid=4, uid=12, name="Sans carte", c1="", c2="  ")
        conn.commit()

    k = db.local_db_kpis()

    assert (k["memberships"], k["people"]) == (4, 3)
    assert k["cards"] == {"distinct": 2, "duplicated": 0, "peopleInvolved": 0, "duplicates": []}


def test_a_card_held_by_two_persons_across_columns_is_one_duplicate(db):
    with db.get_conn() as conn:
        _member(conn, amid=1, uid=10, name="Ali", c1=" 555 ")
        _member(conn, amid=2, uid=20, name="Nour", c2="555")
        _member(conn, amid=3, uid=20, name="Nour", c2="555")
        conn.commit()

    cards = db.local_db_kpis()["cards"]

    assert (cards["duplicated"], cards["peopleInvolved"]) == (1, 2)
    assert cards["duplicates"][0]["card"] == "555"
    assert sorted(p["fullName"] for p in cards["duplicates"][0]["people"]) == ["Ali", "Nour"]


def test_main_account_groups_users_and_a_row_without_it_borrows_it_from_its_user(db):
    with db.get_conn() as conn:
        # Two user ids of one account holding one card: one person, no duplicate.
        _member(conn, amid=1, uid=10, mid=500, c1="888")
        _member(conn, amid=2, uid=11, mid=500, c1="888")
        # Same user, one row with the account and one without: still one person.
        _member(conn, amid=3, uid=30, mid=600, c1="999")
        _member(conn, amid=4, uid=30, mid=None, c1="999")
        conn.commit()

    k = db.local_db_kpis()

    assert k["people"] == 2
    assert k["cards"]["duplicated"] == 0


def test_history_to_send_uses_the_uploader_states_and_skips_blank_rows(db):
    with db.get_conn() as conn:
        _history(conn, "a", "PENDING", created="2026-10-16T08:00:00")
        _history(conn, "b", "PENDING")
        _history(conn, "c", "FAILED_RETRYABLE", created="2026-10-15T07:00:00")
        _history(conn, "d", "SYNCED")
        _history(conn, "e", "FAILED_TERMINAL")
        # A stored blank MB2000 row: never sent, never counted.
        _history(conn, "2000-00-00 00:00:00||1||zkem|x", "PENDING", card="", event_time="2000-00-00 00:00:00")
        conn.commit()

    h = db.local_db_kpis()["historyToSend"]

    assert h == {"total": 3, "pending": 2, "retrying": 1, "oldestCreatedAt": "2026-10-15T07:00:00"}


def test_empty_database(db):
    k = db.local_db_kpis()
    assert k["memberships"] == 0 and k["cards"]["distinct"] == 0
    assert k["historyToSend"] == {"total": 0, "pending": 0, "retrying": 0, "oldestCreatedAt": None}


def test_handler_and_route(db):
    from access.local_api_routes import ACCESS_LOCAL_ROUTE_SPECS
    from app.api import local_access_api_v2 as api

    sent = {}

    class _Ctx:
        def send_json(self, status, payload):
            sent.update(status=status, payload=payload)

    api._handle_db_kpis(_Ctx())
    assert sent["status"] == 200 and sent["payload"]["ok"] is True
    assert ("GET", "/api/v2/db/kpis", "_handle_db_kpis") in ACCESS_LOCAL_ROUTE_SPECS


def test_rows_that_name_no_person_are_never_merged(db):
    with db.get_conn() as conn:
        _member(conn, amid=None, uid=None, name="A", c1="444")
        _member(conn, amid=None, uid=None, name="B", c1="444")
        conn.commit()

    k = db.local_db_kpis()

    assert k["people"] == 2
    assert k["cards"]["duplicated"] == 1

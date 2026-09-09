"""After a FULL member refresh, only the diffed members are written back to member_shadow.

WHY THIS FILE EXISTS
--------------------
`MainApp._apply_member_shadow_sync` (app/ui/app.py) computes `diff_member_shadow(...)`
and narrows the device push to `new + modified`, but then called
`upsert_member_shadow(users=<every incoming user>)`: one INSERT ... ON CONFLICT per row,
934 rows = 1535 ms on the OXYGENE_FIT PC (2026-08-30 log) for rows that already held
exactly those values.

`diff_member_shadow` compares only the access-affecting fields (cards, name, fp hash,
validity dates). It does NOT compare membership_id, so writing back only `new + modified`
would leave `member_shadow.membership_id` stale after a plan-only change. The diff now
reports those rows under a separate key, `membership_changed`, which the app writes but
does NOT add to the push set (a plan change never reaches a device).

Every test patches ``app.core.db._DB_PATH`` to a temp file.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "test.db"), raising=False)
    db_module.init_db()
    yield db_module
    if hasattr(db_module, "_shutdown_db_writer_for_tests"):
        db_module._shutdown_db_writer_for_tests()


_OLD_STAMP = "2000-01-01T00:00:00Z"


def _user(am_id, user_id, *, card="1000", name="Someone", membership_id=50, fps=None):
    return {
        "activeMembershipId": am_id,
        "userId": user_id,
        "membershipId": membership_id,
        "fullName": name,
        "validFrom": "2026-01-01",
        "validTo": "2026-12-31",
        "firstCardId": card,
        "secondCardId": None,
        "fingerprints": fps or [],
    }


def _shadow_rows(db) -> dict:
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT active_membership_id, card_id, membership_id, updated_at FROM member_shadow"
        ).fetchall()
    return {int(r[0]): {"card_id": r[1], "membership_id": r[2], "updated_at": r[3]} for r in rows}


def _seed_shadow(db, users):
    db.upsert_member_shadow(users=users)
    with db.get_conn() as conn:
        conn.execute("UPDATE member_shadow SET updated_at=?", (_OLD_STAMP,))
        conn.commit()


def _recording_upsert(db, monkeypatch):
    """Wrap the real upsert so the test sees exactly which rows the app hands it."""
    real = db.upsert_member_shadow
    calls: list = []

    def _rec(*, users):
        calls.append([u.get("activeMembershipId") for u in users])
        return real(users=users)

    monkeypatch.setattr("app.core.db.upsert_member_shadow", _rec)
    return calls


def _run_full_sync(incoming, valid_ids, delta_changed_ids=None):
    import app.ui.app as app_module

    app = SimpleNamespace(logger=MagicMock())
    changed_ids, _revoked_ids = app_module.MainApp._apply_member_shadow_sync(
        app,
        data={"membersDeltaMode": False, "users": incoming, "validMemberIds": valid_ids},
        refresh={"members": True},
        delta_changed_ids=delta_changed_ids,
    )
    return changed_ids


# --------------------------------------------------------------------------- diff

def test_diff_reports_a_plan_only_change_separately_from_modified(db):
    _seed_shadow(db, [_user(1, 100, card="1001"), _user(2, 200, card="1002")])

    diff = db.diff_member_shadow(
        incoming_users=[_user(1, 100, card="1001", membership_id=51), _user(2, 200, card="1002")],
        valid_member_ids=[1, 2],
    )

    assert diff["new"] == []
    assert diff["modified"] == []
    assert diff["deleted"] == []
    assert diff["membership_changed"] == [1]


def test_diff_does_not_double_list_a_member_whose_plan_and_card_both_changed(db):
    _seed_shadow(db, [_user(1, 100, card="1001")])

    diff = db.diff_member_shadow(
        incoming_users=[_user(1, 100, card="9999", membership_id=51)],
        valid_member_ids=[1],
    )

    assert diff["modified"] == [1]
    assert diff["membership_changed"] == []


def test_diff_compares_membership_id_numerically(db):
    """The shadow column is INTEGER; a backend payload may carry the id as a string."""
    _seed_shadow(db, [_user(1, 100, membership_id=50)])

    diff = db.diff_member_shadow(incoming_users=[_user(1, 100, membership_id="50")], valid_member_ids=[1])

    assert diff["membership_changed"] == []
    assert diff["modified"] == []


# --------------------------------------------------------------------------- app write set

def test_full_sync_writes_only_new_modified_and_plan_changed_rows(db, monkeypatch):
    _seed_shadow(db, [
        _user(1, 100, card="1001"),
        _user(2, 200, card="1002"),
        _user(3, 300, card="1003"),
        _user(4, 400, card="1004"),
    ])
    calls = _recording_upsert(db, monkeypatch)

    incoming = [
        _user(1, 100, card="1001-NEW"),               # modified (card)
        _user(2, 200, card="1002"),                   # unchanged
        _user(3, 300, card="1003", membership_id=51),  # plan-only change
        _user(5, 500, card="1005"),                   # new
    ]
    changed = _run_full_sync(incoming, valid_ids=[1, 2, 3, 5])

    # Push narrowing = new + modified only; the plan-only change never reaches a device.
    assert changed == {1, 5}
    assert calls == [[1, 3, 5]]

    rows = _shadow_rows(db)
    assert set(rows) == {1, 2, 3, 5}, "member 4 (absent from validMemberIds) is deleted"
    assert rows[1]["card_id"] == "1001-NEW" and rows[1]["updated_at"] != _OLD_STAMP
    assert rows[2] == {"card_id": "1002", "membership_id": 50, "updated_at": _OLD_STAMP}, "untouched"
    assert rows[3]["membership_id"] == 51 and rows[3]["updated_at"] != _OLD_STAMP
    assert rows[5]["card_id"] == "1005"


def test_full_sync_with_no_changes_writes_nothing(db, monkeypatch):
    seed = [_user(1, 100, card="1001"), _user(2, 200, card="1002")]
    _seed_shadow(db, seed)
    calls = _recording_upsert(db, monkeypatch)

    changed = _run_full_sync(seed, valid_ids=[1, 2], delta_changed_ids={1, 2})

    assert changed == set(), "no member changes => the pin push is skipped entirely"
    assert calls == [[]]
    assert all(r["updated_at"] == _OLD_STAMP for r in _shadow_rows(db).values())


def test_empty_shadow_writes_every_incoming_row(db, monkeypatch):
    calls = _recording_upsert(db, monkeypatch)
    incoming = [_user(1, 100), _user(2, 200), _user(3, 300)]

    changed = _run_full_sync(incoming, valid_ids=[1, 2, 3])

    assert changed == {1, 2, 3}
    assert calls == [[1, 2, 3]]
    assert set(_shadow_rows(db)) == {1, 2, 3}


def test_app_tolerates_a_diff_without_the_membership_changed_key(db, monkeypatch):
    """tests/test_sync_hot_path_optimizations.py fakes diff_member_shadow with the three
    historical keys only; the write-set code must not depend on the new key."""
    monkeypatch.setattr(
        "app.core.db.diff_member_shadow",
        lambda **kwargs: {"new": [1], "modified": [], "deleted": []},
    )
    calls = _recording_upsert(db, monkeypatch)

    changed = _run_full_sync([_user(1, 100), _user(2, 200)], valid_ids=[1, 2])

    assert changed == {1}
    assert calls == [[1]]


def test_rows_with_unparseable_membership_ids_are_never_written(db, monkeypatch):
    """upsert_member_shadow skips them anyway; the write-set filter must agree so the
    counts logged match what lands in the table."""
    calls = _recording_upsert(db, monkeypatch)

    _run_full_sync([_user("abc", 100), _user(None, 200), _user(3, 300)], valid_ids=[3])

    assert calls == [[3]]
    assert set(_shadow_rows(db)) == {3}

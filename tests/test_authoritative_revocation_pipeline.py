from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    db_path = str(tmp_path / "authoritative-revocations.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()
    yield db_module
    if hasattr(db_module, "_shutdown_db_writer_for_tests"):
        db_module._shutdown_db_writer_for_tests()


def _make_user(active_membership_id: int) -> dict:
    return {
        "activeMembershipId": active_membership_id,
        "userId": active_membership_id + 100,
        "membershipId": 50,
        "firstName": f"Member{active_membership_id}",
        "lastName": "Example",
        "fullName": f"Member{active_membership_id} Example",
        "phone": "0600000000",
        "email": f"member{active_membership_id}@example.com",
        "firstCardId": f"CARD-{active_membership_id}",
        "secondCardId": None,
        "validFrom": "2026-01-01",
        "validTo": "2026-12-31",
        "status": "ACTIVE",
        "contractStatus": "ACTIVE",
        "fingerprints": [],
        "faceId": None,
        "accountUsernameId": None,
        "qrCodePayload": None,
        "birthday": None,
        "image": None,
        "imageSource": None,
        "userImageStatus": None,
    }


def _app():
    return SimpleNamespace(logger=MagicMock())


def _shadow_ids(db) -> set[int]:
    with db.get_conn() as conn:
        return {
            int(row["active_membership_id"])
            for row in conn.execute(
                "SELECT active_membership_id FROM member_shadow"
            ).fetchall()
        }


def test_delta_authoritative_deletion_is_returned_only_as_revocation(db):
    from app.ui.app import MainApp

    db.upsert_member_shadow(users=[_make_user(1), _make_user(2)])

    changed, revoked = MainApp._apply_member_shadow_sync(
        _app(),
        data={
            "membersDeltaMode": True,
            "users": [_make_user(1)],
            "validMemberIds": [1],
        },
        refresh={"members": True},
        delta_changed_ids={1},
    )

    assert changed == {1}
    assert revoked == {2}
    assert _shadow_ids(db) == {1}


def test_full_authoritative_deletion_is_returned_only_as_revocation(db):
    from app.ui.app import MainApp

    db.upsert_member_shadow(users=[_make_user(1), _make_user(2)])

    changed, revoked = MainApp._apply_member_shadow_sync(
        _app(),
        data={
            "membersDeltaMode": False,
            "users": [_make_user(1)],
            "validMemberIds": [1],
        },
        refresh={"members": True},
        delta_changed_ids=None,
    )

    assert changed is None
    assert revoked == {2}
    assert _shadow_ids(db) == {1}


def test_h006_refusal_emits_no_revocations_and_preserves_shadow(db):
    from app.ui.app import MainApp

    db.upsert_member_shadow(users=[_make_user(member_id) for member_id in range(1, 12)])

    changed, revoked = MainApp._apply_member_shadow_sync(
        _app(),
        data={
            "membersDeltaMode": True,
            "users": [],
            "validMemberIds": [],
        },
        refresh={"members": True},
        delta_changed_ids=set(),
    )

    assert changed == set()
    assert revoked == set()
    assert _shadow_ids(db) == set(range(1, 12))


def test_shadow_error_emits_no_revocations_and_preserves_changed_ids(db, monkeypatch):
    from app.ui.app import MainApp

    db.upsert_member_shadow(users=[_make_user(1), _make_user(2)])
    monkeypatch.setattr(
        db,
        "diff_member_shadow",
        MagicMock(side_effect=RuntimeError("shadow unavailable")),
    )

    changed, revoked = MainApp._apply_member_shadow_sync(
        _app(),
        data={
            "membersDeltaMode": False,
            "users": [_make_user(1)],
            "validMemberIds": [1],
        },
        refresh={"members": True},
        delta_changed_ids={1},
    )

    assert changed == {1}
    assert revoked == set()
    assert _shadow_ids(db) == {1, 2}


def test_revocation_takes_precedence_over_incoming_changed_id(db):
    from app.ui.app import MainApp

    db.upsert_member_shadow(users=[_make_user(1), _make_user(2)])

    changed, revoked = MainApp._apply_member_shadow_sync(
        _app(),
        data={
            "membersDeltaMode": True,
            "users": [_make_user(1)],
            "validMemberIds": [1],
        },
        refresh={"members": True},
        delta_changed_ids={1, 2},
    )

    assert changed == {1}
    assert revoked == {2}


def test_main_sync_routing_keeps_ultra_sets_separate_and_unions_device_ids():
    from app.ui.app import MainApp

    ultra_changed, ultra_revoked, device_changed = MainApp._member_sync_dispatch_ids(
        changed_ids={1},
        revoked_ids={2},
    )

    assert ultra_changed == {1}
    assert ultra_revoked == {2}
    assert device_changed == {1, 2}


def test_main_sync_routing_preserves_device_full_semantics():
    from app.ui.app import MainApp

    ultra_changed, ultra_revoked, device_changed = MainApp._member_sync_dispatch_ids(
        changed_ids=None,
        revoked_ids={2},
    )

    assert ultra_changed is None
    assert ultra_revoked == {2}
    assert device_changed is None


@pytest.mark.parametrize(
    "invalid_id",
    [True, 2.5, "2.5", "02", 0, -1],
)
def test_shadow_sync_never_truncates_or_accepts_noncanonical_valid_ids(
    db, invalid_id
):
    from app.ui.app import MainApp

    db.upsert_member_shadow(users=[_make_user(2)])

    changed, revoked = MainApp._apply_member_shadow_sync(
        _app(),
        data={
            "membersDeltaMode": True,
            "users": [],
            "validMemberIds": [invalid_id],
        },
        refresh={"members": True},
        delta_changed_ids=set(),
    )

    assert changed == set()
    assert revoked == {2}
    assert _shadow_ids(db) == set()

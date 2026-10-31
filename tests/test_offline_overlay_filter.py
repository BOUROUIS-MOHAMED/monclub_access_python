from types import SimpleNamespace

import pytest

from app.core import db
from app.core.device_sync import DeviceSyncEngine


@pytest.fixture
def overlay_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "_DB_PATH", str(tmp_path / "overlay.db"))
    db.init_db()
    db.bump_local_state_generation()
    yield db
    db._shutdown_db_writer_for_tests()


def entry(local_id="temp", kind="TEMP_MEMBER", **values):
    return {"local_id": local_id, "kind": kind, "state": "ACTIVE", "device_ids": [1],
            "temp_pin": "900100001" if kind == "TEMP_MEMBER" else None,
            "full_name": "Ali", "membership_id": 3, "created_at": "2026-10-31T12:00:00",
            "local_day": "2026-10-31", "expires_at_epoch": 1793487600, **values}


def filtered(users=(), **device):
    return DeviceSyncEngine(cfg=SimpleNamespace(), logger=None)._filter_users_for_device(
        users=list(users), device={"id": 1, **device}, default_door_id=1)


def test_empty_overlay_filter_identical(overlay_db):
    user = {"activeMembershipId": 10, "mainAccountId": 20, "fingerprints": []}
    assert filtered([user])["10"] is user
    assert filtered([user], pinScheme="ACCOUNT")["20"] is user


@pytest.mark.parametrize("scheme", ["MEMBERSHIP", "ACCOUNT"])
def test_temp_member_row_under_both_schemes(overlay_db, scheme):
    db.insert_offline_overlay(entry(card="1234"))
    row = filtered(pinScheme=scheme)["900100001"]
    assert row["fullName"] == "Ali" and row["firstCardId"] == "1234"
    assert not row.get("userId") and not row.get("offlinePending")
    assert not filtered(id=2, pinScheme=scheme)


def test_door_event_on_temp_pin_never_uploaded_as_person_id(overlay_db):
    db.insert_offline_overlay(entry())
    from app.core.offline_overlay import snapshot
    user = snapshot().user_for_pin("900100001", {"id": 1})
    assert user["offlineLocalId"] == "temp"
    assert user.get("userId") is None and user.get("mainAccountId") is None


def test_finger_add_patch_on_copy_not_cache(overlay_db):
    user = {"activeMembershipId": 10, "fingerprints": [{"fingerId": 1, "templateData": "old"}]}
    db.insert_offline_overlay(entry("finger", "FINGER_ADD", target_active_membership_id=10,
        finger_id=1, template_data="AQIDBA==", template_version=10, template_encoding="BASE64"))
    result = filtered([user])["10"]
    assert result is not user and user["fingerprints"][0]["templateData"] == "old"
    assert result["fingerprints"][0]["templateData"] == "AQIDBA=="
    assert "templateSize" not in result["fingerprints"][0]
    with db.get_conn() as conn:
        assert "AQIDBA==" not in conn.execute("SELECT template_data FROM offline_turnstile_overlay").fetchone()[0]


def test_finger_disable_patch(overlay_db):
    db.insert_offline_overlay(entry("disable", "FINGER_DISABLE", target_active_membership_id=10, fingerprint_id=55))
    user = {"activeMembershipId": 10, "fingerprints": [{"id": 55, "fingerId": 1}, {"id": 56, "fingerId": 2}]}
    assert filtered([user])["10"]["fingerprints"] == [{"id": 56, "fingerId": 2}]


def test_card_patch(overlay_db):
    db.insert_offline_overlay(entry("card", "CARD_SET", target_active_membership_id=10, card="0012"))
    user = {"activeMembershipId": 10, "firstCardId": "1111"}
    assert filtered([user])["10"]["firstCardId"] == "0012"
    assert user["firstCardId"] == "1111"
    assert not filtered([])


def test_plan_filter_applies_to_temp_row(overlay_db):
    db.insert_offline_overlay(entry())
    assert not filtered(allowedMemberships=[4])


def test_empty_snapshot_reads_once_per_generation_and_keeps_cache_rows(overlay_db, monkeypatch):
    from app.core.offline_overlay import snapshot
    snapshot()
    def unexpected_read(*args, **kwargs):
        raise AssertionError("new DB read on the hot path")
    monkeypatch.setattr(db, "list_offline_overlay", unexpected_read)
    for _ in range(5):
        user = {"activeMembershipId": 10, "mainAccountId": 20}
        assert filtered([user])["10"] is user

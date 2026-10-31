import pytest

from app.core import db, offline_overlay
from app.core.v2.store import kv_put
from tests.test_offline_overlay_filter import overlay_db, entry, filtered
from tests.test_account_pin_device_sites import _cache, _ali_gym, _pullsdk_device
from tests.test_offline_overlay_expiry import NOW


def decision(local_id="temp", status="APPLIED", **values):
    return {"localId": local_id, "status": status, "activeMembershipId": 31000,
            "userId": 900, "mainAccountId": 5, "decidedAt": "2026-10-31T13:00:00", **values}


def test_refused_drops_and_removes(overlay_db, monkeypatch):
    from tests.test_standalone_incremental_sync import _worker
    from tests.test_standalone_revoked_pin_removal import RevokeDriver
    db.insert_offline_overlay(entry())
    db.save_device_sync_state(device_id=1, pin="900100001", desired_hash="h", ok=True, error=None)
    offline_overlay.reconcile_decisions([decision(status="REFUSED")], now=NOW)
    drv = RevokeDriver()
    worker, _ = _worker(monkeypatch, driver=drv)
    worker._device["id"] = worker._device_id = 1
    worker._drain_member_sync_commands()
    assert drv.delete_calls == [["900100001"]]


def test_applied_finger_dropped_only_when_server_has_it(overlay_db):
    user = _ali_gym()
    user["fingerprints"] = []
    _cache(db, [user])
    db.insert_offline_overlay(entry("finger", "FINGER_ADD", target_active_membership_id=31000,
        finger_id=2, template_data="AQIDBA==", template_version=10, template_encoding="BASE64"))
    offline_overlay.reconcile_decisions([decision("finger")], now=NOW)
    assert db.list_offline_overlay()[0]["state"] == "ACTIVE"
    user["fingerprints"] = [{"fingerId": 2, "enabled": True}]
    _cache(db, [user])
    offline_overlay.reconcile_decisions([decision("finger")], now=NOW)
    assert db.list_offline_overlay()[0]["state"] == "DROPPED"


@pytest.mark.parametrize("protocol", ["ZK_PULLSDK", "ZK_STANDALONE"])
def test_approval_keeps_temp_until_real_pin_pushed(overlay_db, protocol, monkeypatch):
    device = _pullsdk_device(deviceProtocol=protocol, fingerprintEnabled=True)
    with db.get_conn() as conn:
        db._insert_device_row(conn.cursor(), device)
        conn.commit()
    db.insert_offline_overlay(entry())
    _cache(db, [_ali_gym()])
    offline_overlay.reconcile_decisions([decision()], now=NOW)
    assert db.list_offline_overlay()[0]["state"] == "AWAITING_REAL_PIN"
    assert "900100001" in filtered(db.list_sync_users())
    pin, desired_hash = offline_overlay.real_pin_hash(device, db.list_sync_users(), 31000)
    db.save_device_sync_state(device_id=1, pin=pin, desired_hash=desired_hash, ok=False, error="failed")
    offline_overlay.reconcile_decisions([decision()], now=NOW)
    assert db.list_offline_overlay()[0]["state"] == "AWAITING_REAL_PIN"
    if protocol == "ZK_STANDALONE":
        from tests.test_standalone_incremental_sync import _worker
        from tests.test_standalone_finger_removal_state import RecordingDriver
        worker, _ = _worker(monkeypatch, driver=RecordingDriver(), users=db.list_sync_users())
        worker._device, worker._device_id = device, 1
        worker._run_standalone_member_sync(31000)
    else:
        from tests.test_account_pin_device_sites import _engine, _sdk
        engine = _engine()
        monkeypatch.setattr(engine, "_push_templates", lambda sdk, **kw: (len(kw["templates"]), []))
        engine.sync_member_on_connected_sdk(sdk=_sdk(), device=device, member_id=31000)
    assert db.get_pin_sync_status(device_id=1, pin=pin) == (desired_hash, True)
    offline_overlay.reconcile_decisions([decision()], now=NOW)
    assert db.list_offline_overlay()[0]["state"] == "DROPPED"
    assert "900100001" in offline_overlay.planned_pins_for_device(device)


def test_card_stripped_from_temp_once_real_member_cached(overlay_db):
    db.insert_offline_overlay(entry(card="1234"))
    offline_overlay.reconcile_decisions([decision()], now=NOW)
    assert filtered()["900100001"]["firstCardId"] == "1234"
    _cache(db, [_ali_gym()])
    assert not filtered()["900100001"].get("firstCardId")


def test_unknown_timeout_starts_after_successful_upload_and_first_poll(overlay_db):
    db.insert_offline_overlay(entry(created_at="2026-01-01T00:00:00"))
    offline_overlay.reconcile_decisions([decision(status="UNKNOWN")], now=NOW)
    assert db.list_offline_overlay()[0]["state"] == "ACTIVE"
    kv_put("offline_action_receipts", {"temp": {"local_id": "temp"}})
    offline_overlay.reconcile_decisions([decision(status="UNKNOWN")], now=NOW)
    offline_overlay.reconcile_decisions([decision(status="UNKNOWN")], now=NOW + 86400)
    assert db.list_offline_overlay()[0]["state"] == "ACTIVE"
    offline_overlay.reconcile_decisions([decision(status="UNKNOWN")], now=NOW + 86401)
    assert db.list_offline_overlay()[0]["dropped_reason"] == "UNKNOWN"


def test_post_decision_roster_refresh_wins_even_when_values_differ(overlay_db):
    db.insert_offline_overlay(entry("card", "CARD_SET", target_active_membership_id=31000, card="1234"))
    kv_put("offline_overlay_roster_completed", NOW)
    _cache(db, [_ali_gym()])
    offline_overlay.reconcile_decisions([decision("card")], now=NOW)
    assert db.list_offline_overlay()[0]["state"] == "DROPPED"


def test_unknown_must_be_continuous(overlay_db):
    db.insert_offline_overlay(entry())
    kv_put("offline_action_receipts", {"temp": {"local_id": "temp"}})
    offline_overlay.reconcile_decisions([decision(status="UNKNOWN")], now=NOW)
    offline_overlay.reconcile_decisions([decision(status="PENDING")], now=NOW + 80000)
    offline_overlay.reconcile_decisions([decision(status="UNKNOWN")], now=NOW + 86401)
    assert db.list_offline_overlay()[0]["state"] == "ACTIVE"


def test_unknown_upload_proof_outlives_display_receipt(overlay_db):
    db.insert_offline_overlay(entry())
    db.insert_offline_pending_action({"local_id": "temp", "kind": "CREATE", "category": "MONEY", "payload": {},
        "created_at": "2026-10-31T12:00:00", "local_day": "2026-10-31"}, daily_limit=10)
    db.finish_offline_pending_upload(["temp"], {}, receipts={"temp": {"local_id": "temp"}})
    db.retire_offline_action_receipts(["temp"])
    offline_overlay.reconcile_decisions([decision(status="UNKNOWN")], now=NOW)
    offline_overlay.reconcile_decisions([decision(status="UNKNOWN")], now=NOW + 86401)
    assert db.list_offline_overlay()[0]["state"] == "DROPPED"


def test_applied_member_with_no_account_id_never_expires(overlay_db):
    db.insert_offline_overlay(entry())
    offline_overlay.reconcile_decisions([decision(mainAccountId=None)], now=NOW)
    offline_overlay.expire_overlay(NOW + 86400)
    assert db.list_offline_overlay()[0]["state"] == "AWAITING_REAL_PIN"


def test_child_finger_is_on_real_pin_before_swap_and_rekeyed_at_swap(overlay_db):
    device = _pullsdk_device(deviceProtocol="ZK_STANDALONE", fingerprintEnabled=True)
    with db.get_conn() as conn:
        db._insert_device_row(conn.cursor(), device)
        conn.commit()
    db.insert_offline_overlay(entry())
    negative = db._synthetic_negative_id("temp", "offline_approval")
    db.insert_offline_overlay(entry("child", "FINGER_ADD", target_active_membership_id=negative,
        finger_id=8, template_version=10, template_encoding="BASE64", template_data="AQIDBA=="))
    _cache(db, [_ali_gym()])
    offline_overlay.reconcile_decisions([decision()], now=NOW)
    assert any(f["fingerId"] == 8 for f in filtered(db.list_sync_users())["31000"]["fingerprints"])
    pin, desired = offline_overlay.real_pin_hash(device, db.list_sync_users(), 31000)
    db.save_device_sync_state(device_id=1, pin=pin, desired_hash=desired, ok=True, error=None)
    offline_overlay.reconcile_decisions([decision()], now=NOW)
    child = next(r for r in db.list_offline_overlay() if r["local_id"] == "child")
    assert child["target_active_membership_id"] == 31000 and child["state"] == "ACTIVE"
    assert any(f["fingerId"] == 8 for f in filtered(db.list_sync_users())["31000"]["fingerprints"])

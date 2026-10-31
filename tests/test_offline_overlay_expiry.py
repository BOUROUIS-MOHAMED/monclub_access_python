import ast
from datetime import datetime
from pathlib import Path

import pytest

from app.core import db, offline_overlay
from tests.test_offline_overlay_filter import overlay_db, entry
from tests.test_off_hours_removal_bound import warns
from tests.test_removal_ceiling_pullsdk import _run, _users, _gym58_device, _removed_pins
from tests.test_standalone_incremental_sync import _worker
from tests.test_standalone_revoked_pin_removal import RevokeDriver


NOW = datetime(2026, 11, 1, 0, 1).timestamp()


def test_boot_expires_temp_pass_before_sync(overlay_db):
    tree = ast.parse(Path("app/ui/app.py").read_text(encoding="utf-8"))
    init = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "__init__" and
                any(isinstance(x, ast.Attribute) and x.attr == "_apply_date_flips" for x in ast.walk(n)))
    calls = [n for n in ast.walk(init) if isinstance(n, ast.Call)]
    date = next(n for n in calls if isinstance(n.func, ast.Attribute) and n.func.attr == "_apply_date_flips")
    expiry = next(n for n in calls if isinstance(n.func, ast.Name) and n.func.id == "expire_overlay")
    assert 0 < expiry.lineno - date.lineno <= 4  # right after the date flip (inside its own try)
    db.insert_offline_overlay(entry())
    offline_overlay.expire_overlay(NOW)
    assert db.list_offline_overlay()[0]["dropped_reason"] == "EXPIRED"


def test_manual_sync_mode_expiry_targets_revocation(overlay_db, monkeypatch):
    db.insert_offline_overlay(entry())
    db.save_device_sync_state(device_id=1, pin="900100001", desired_hash="h", ok=True, error=None)
    offline_overlay.expire_overlay(NOW)  # No workers exist at boot.
    drv = RevokeDriver()
    worker, _ = _worker(monkeypatch, driver=drv)
    worker._device["id"] = worker._device_id = 1
    worker._settings["manual_sync_mode"] = True
    worker._drain_member_sync_commands()
    assert drv.delete_calls == [["900100001"]]
    assert db.get_pin_sync_status(device_id=1, pin="900100001") is None


def test_awaiting_real_pin_not_expired(overlay_db):
    db.insert_offline_overlay(entry(state="AWAITING_REAL_PIN"))
    offline_overlay.expire_overlay(NOW)
    assert db.list_offline_overlay()[0]["state"] == "AWAITING_REAL_PIN"


@pytest.mark.parametrize("driver", ["pullsdk", "standalone"])
def test_expired_temp_pins_bypass_removal_ceiling(overlay_db, monkeypatch, warns, driver):
    pins = {str(900100001 + i) for i in range(15)}
    for pin in pins:
        db.insert_offline_overlay(entry(pin, temp_pin=pin, device_ids=[1, 9]))
    offline_overlay.expire_overlay(NOW)
    if driver == "pullsdk":
        for pin in pins:
            db.save_device_sync_state(device_id=1, pin=pin, desired_hash="h", ok=True, error=None)
        sdk = _run(_users(*range(101, 121)), _gym58_device(), device_pins=sorted(pins))
        assert _removed_pins(sdk) == pins
    else:
        drv = RevokeDriver()
        worker, _ = _worker(monkeypatch, driver=drv)
        for pin in pins:
            db.save_device_sync_state(device_id=9, pin=pin, desired_hash="h", ok=True, error=None)
        assert worker._neutralise_revoked_pins(desired_pins={str(i) for i in range(20)}, roster_count=20)
        assert {p for call in drv.delete_calls for p in call} == pins
    assert not any(name == "REVOKE_ABORTED" for name, _ in warns)


def test_suspect_clock_expires(overlay_db, monkeypatch):
    db.insert_offline_overlay(entry(local_day="2026-11-01", expires_at_epoch=NOW + 86400))
    monkeypatch.setattr(db, "gym_date_status", lambda **kw: {"suspect": True, "gym_date": "2026-11-01"})
    offline_overlay.expire_overlay(NOW)
    assert db.list_offline_overlay()[0]["state"] == "DROPPED"


def test_dropped_finger_does_not_exempt_a_later_member_departure(overlay_db):
    db.insert_offline_overlay(entry("finger", "FINGER_ADD", state="DROPPED", target_active_membership_id=10))
    assert "10" not in offline_overlay.planned_pins_for_device({"id": 1})


def test_add_only_expiry_stays_durable_and_visible(overlay_db, monkeypatch):
    from app.core.v2 import lease_gate
    db.insert_offline_overlay(entry())
    db.save_device_sync_state(device_id=1, pin="900100001", desired_hash="h", ok=True, error=None)
    offline_overlay.expire_overlay(NOW)
    drv = RevokeDriver()
    worker, _ = _worker(monkeypatch, driver=drv)
    worker._device["id"] = worker._device_id = 1
    monkeypatch.setattr(lease_gate, "removals_blocked", lambda did: "add_only")
    worker._drain_member_sync_commands()
    assert not drv.delete_calls and offline_overlay.expiry_pending()
    monkeypatch.setattr(lease_gate, "removals_blocked", lambda did: None)
    worker._offline_overlay_due = 0
    worker._drain_member_sync_commands()
    assert drv.delete_calls == [["900100001"]]
    assert not offline_overlay.expiry_pending()


def test_manual_mode_pullsdk_expiry_uses_only_the_held_connection(overlay_db, monkeypatch):
    from types import SimpleNamespace
    from app.core import device_sync
    from tests.test_account_pin_device_sites import _sdk
    db.insert_offline_overlay(entry())
    db.save_device_sync_state(device_id=1, pin="900100001", desired_hash="h", ok=True, error=None)
    offline_overlay.expire_overlay(NOW)
    sdk = _sdk()
    sdk.delete_device_data_batch.return_value = (1, [])
    worker, _ = _worker(monkeypatch)
    worker._device["id"] = worker._device_id = 1
    worker._sdk = SimpleNamespace(owns_event_source=False, _sdk=sdk)
    def forbidden(*args, **kwargs):
        raise AssertionError("second connection")
    monkeypatch.setattr(device_sync, "PullSDK", forbidden)
    worker._drain_member_sync_commands()
    assert sdk.delete_device_data_batch.called
    assert db.get_pin_sync_status(device_id=1, pin="900100001") is None


@pytest.mark.parametrize("protocol", ["ZK_STANDALONE", "ZK_PULLSDK"])
@pytest.mark.parametrize("matches", [True, False])
def test_expiry_proves_an_interrupted_first_write_before_removing(overlay_db, monkeypatch, protocol, matches):
    from types import SimpleNamespace
    from tests.test_account_pin_device_sites import _sdk
    db.insert_offline_overlay(entry())
    db.record_push_intents(device_id=1, rows=[("900100001", "Ali", "1234", "hash")], protocol=protocol)
    offline_overlay.expire_overlay(NOW)
    drv = RevokeDriver()
    drv.list_device_users = lambda: {"ok": True, "users": [{"pin": "900100001", "name": "Ali",
                                                         "card": "1234" if matches else "9999"}]}
    sdk = _sdk()
    sdk.get_device_data_rows.return_value = [{"Pin": "900100001", "CardNo": "1234" if matches else "9999"}]
    sdk.delete_device_data_batch.return_value = (1, [])
    worker, _ = _worker(monkeypatch, driver=drv)
    worker._device["id"] = worker._device_id = 1
    if protocol == "ZK_PULLSDK":
        worker._sdk = SimpleNamespace(owns_event_source=False, _sdk=sdk)
    worker._drain_member_sync_commands()
    removed = bool(drv.delete_calls) if protocol == "ZK_STANDALONE" else sdk.delete_device_data_batch.called
    assert removed is matches
    if matches:
        assert db.get_push_intent(device_id=1, pin="900100001") is None


def test_unproven_temp_pin_not_deleted_by_full_pullsdk_pass(overlay_db):
    db.insert_offline_overlay(entry())
    db.save_device_sync_state(device_id=1, pin="900100001", desired_hash="h", ok=False, error="user write failed")
    offline_overlay.expire_overlay(NOW)
    sdk = _run(_users(*range(101, 121)), _gym58_device(), device_pins=["900100001"])
    assert not _removed_pins(sdk)


def test_finished_entries_purged_after_a_week_only_when_nothing_needs_them(overlay_db):
    db.insert_offline_overlay(entry(local_id="gone", temp_pin="900100002", state="DROPPED", dropped_reason="EXPIRED"))
    db.insert_offline_overlay(entry(local_id="held", temp_pin="900100003", state="DROPPED", dropped_reason="EXPIRED"))
    db.save_device_sync_state(device_id=1, pin="900100003", desired_hash="h", ok=True, error=None)
    offline_overlay.expire_overlay(datetime.now().timestamp())  # Dropped just now: kept.
    assert {r["local_id"] for r in db.list_offline_overlay()} == {"gone", "held"}
    offline_overlay.expire_overlay(datetime.now().timestamp() + 8 * 86400)
    assert {r["local_id"] for r in db.list_offline_overlay()} == {"held"}  # Pin still on the device.


def test_active_entries_replayed_once_per_worker(overlay_db):
    db.insert_offline_overlay(entry())
    calls = []

    class Worker:
        _connected, _sdk, _device_id, _settings, _cfg = True, object(), 1, {}, None
        def request_full_sync(self, reason): calls.append(reason)
        def request_member_sync(self, target): calls.append(target)

    worker = Worker()
    offline_overlay.drain_worker(worker)
    worker._offline_overlay_due = 0  # The minute throttle has passed.
    offline_overlay.drain_worker(worker)
    assert calls == ["offline_overlay"]

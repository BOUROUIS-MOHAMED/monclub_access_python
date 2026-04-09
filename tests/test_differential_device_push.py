"""Tests for differential device push (changed_ids filtering in _sync_one_device)."""
import logging
from unittest.mock import MagicMock, patch


def make_engine(tmp_path, monkeypatch):
    import app.core.db as db_module
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()

    from app.core.device_sync import DeviceSyncEngine
    logger = logging.getLogger("test")
    svc = DeviceSyncEngine(cfg=MagicMock(), logger=logger)
    return svc, db_module


def make_device(dev_id=1, ip="10.0.0.1"):
    return {
        "id": dev_id, "name": "TestDevice", "ipAddress": ip, "portNumber": 4370,
        "password": "", "active": True, "accessDevice": True,
        "accessDataMode": "DEVICE", "fingerprintEnabled": False,
        "authorizeTimezoneId": 1, "doorIds": [15], "doorPresets": [],
        "pushingToDevicePolicy": "ALL",
    }


def make_user(am_id, user_id=None):
    return {
        "activeMembershipId": am_id, "userId": user_id or (am_id + 1000),
        "membershipId": am_id, "fullName": f"User {am_id}",
        "phone": "0600000000", "email": f"u{am_id}@example.com",
        "validFrom": "2026-01-01", "validTo": "2026-12-31",
        "firstCardId": str(am_id * 100), "secondCardId": None,
        "image": None, "fingerprints": [], "faceId": None,
        "accountUsernameId": None, "qrCodePayload": None,
        "birthday": None, "imageSource": None, "userImageStatus": None,
    }


def _patch_sdk(monkeypatch, device_pins=None):
    """Return a mock SDK that reports given device pins (default empty)."""
    sdk_cls = MagicMock()
    sdk_instance = MagicMock()
    sdk_cls.return_value = sdk_instance
    device_pins = device_pins or []
    sdk_instance.get_all_device_data.return_value = [
        {"Pin": p} for p in device_pins
    ]
    sdk_instance.set_device_data.return_value = None
    sdk_instance.delete_device_data.return_value = None
    sdk_instance.__enter__ = lambda s: s
    sdk_instance.__exit__ = MagicMock(return_value=False)
    return sdk_cls, sdk_instance


# Each user pushed to device generates 2 set_device_data calls:
# 1 for the "user" table (name/card) and 1 for "userauthorize".
_CALLS_PER_USER = 2


def test_changed_ids_none_pushes_all_new_users(tmp_path, monkeypatch):
    """When changed_ids is None (full sync), all users with no stored hash are pushed."""
    svc, db_module = make_engine(tmp_path, monkeypatch)
    sdk_cls, sdk_inst = _patch_sdk(monkeypatch)

    with patch("app.core.device_sync.PullSDK", sdk_cls):
        svc._sync_one_device(
            device=make_device(),
            users=[make_user(1), make_user(2), make_user(3)],
            local_fp_index={},
            default_door_id=15,
            changed_ids=None,  # full sync
        )

    # All 3 users have no stored hash → all should be pushed
    assert sdk_inst.set_device_data.call_count == 3 * _CALLS_PER_USER


def test_changed_ids_filters_to_only_changed_users(tmp_path, monkeypatch):
    """When changed_ids={2}, only user 2 is pushed; users 1 and 3 are skipped."""
    svc, db_module = make_engine(tmp_path, monkeypatch)

    # Pre-store a "good" hash for users 1 and 3 so delta filter can skip them
    from app.core.db import save_device_sync_state
    save_device_sync_state(device_id=1, pin="1", desired_hash="old_hash_1", ok=True, error=None)
    save_device_sync_state(device_id=1, pin="3", desired_hash="old_hash_3", ok=True, error=None)

    sdk_cls, sdk_inst = _patch_sdk(monkeypatch, device_pins=["1", "3"])

    with patch("app.core.device_sync.PullSDK", sdk_cls):
        svc._sync_one_device(
            device=make_device(),
            users=[make_user(1), make_user(2), make_user(3)],
            local_fp_index={},
            default_door_id=15,
            changed_ids={2},  # only user 2 changed
        )

    # Only user 2 (pin="2") should be pushed, not 1 or 3
    assert sdk_inst.set_device_data.call_count == 1 * _CALLS_PER_USER


def test_changed_ids_still_retries_failed_users(tmp_path, monkeypatch):
    """Even when changed_ids is provided, users whose prev sync failed are retried."""
    svc, db_module = make_engine(tmp_path, monkeypatch)

    from app.core.db import save_device_sync_state
    # User 1: good previous sync, not in changed_ids → skip
    save_device_sync_state(device_id=1, pin="1", desired_hash="hash_1", ok=True, error=None)
    # User 3: FAILED previous sync, not in changed_ids → still retry
    save_device_sync_state(device_id=1, pin="3", desired_hash="hash_3", ok=False, error=None)

    sdk_cls, sdk_inst = _patch_sdk(monkeypatch, device_pins=["1", "3"])

    with patch("app.core.device_sync.PullSDK", sdk_cls):
        svc._sync_one_device(
            device=make_device(),
            users=[make_user(1), make_user(2), make_user(3)],
            local_fp_index={},
            default_door_id=15,
            changed_ids={2},  # only user 2 changed per backend delta
        )

    # Users 2 (changed) and 3 (failed prev) should be pushed; user 1 skipped
    assert sdk_inst.set_device_data.call_count == 2 * _CALLS_PER_USER

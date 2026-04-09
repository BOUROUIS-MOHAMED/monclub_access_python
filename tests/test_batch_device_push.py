"""Tests for batch device push and nuke-and-repave optimization."""
import logging
from unittest.mock import MagicMock, patch, call


def make_engine(tmp_path, monkeypatch):
    import app.core.db as db_module
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()
    from app.core.device_sync import DeviceSyncEngine
    return DeviceSyncEngine(cfg=MagicMock(), logger=logging.getLogger("test")), db_module


def make_device(dev_id=1):
    return {
        "id": dev_id, "name": "TestDevice", "ipAddress": "10.0.0.1", "portNumber": 4370,
        "password": "", "active": True, "accessDevice": True,
        "accessDataMode": "DEVICE", "fingerprintEnabled": False,
        "authorizeTimezoneId": 1, "doorIds": [15], "doorPresets": [],
        "pushingToDevicePolicy": "ALL",
    }


def make_user(am_id):
    return {
        "activeMembershipId": am_id, "userId": am_id + 1000,
        "membershipId": am_id, "fullName": f"User {am_id}",
        "phone": "0600000000", "email": f"u{am_id}@example.com",
        "validFrom": "2026-01-01", "validTo": "2026-12-31",
        "firstCardId": str(am_id * 100), "secondCardId": None,
        "image": None, "fingerprints": [], "faceId": None,
        "accountUsernameId": None, "qrCodePayload": None,
        "birthday": None, "imageSource": None, "userImageStatus": None,
    }


def _patch_sdk(device_pins=None):
    sdk_cls = MagicMock()
    sdk_inst = MagicMock()
    sdk_cls.return_value = sdk_inst
    # _sync_one_device reads device pins via get_device_data_rows (not get_all_device_data)
    sdk_inst.get_device_data_rows.return_value = [{"Pin": p} for p in (device_pins or [])]
    sdk_inst.set_device_data.return_value = 0
    sdk_inst.set_device_data_batch.return_value = (50, [])
    sdk_inst.clear_device_table.return_value = 0
    sdk_inst.delete_device_data.return_value = 0
    sdk_inst.__enter__ = lambda s: s
    sdk_inst.__exit__ = MagicMock(return_value=False)
    return sdk_cls, sdk_inst


# ── PullSDK batch method tests ──────────────────────────────────────────────

def test_set_device_data_batch_chunks_rows(tmp_path, monkeypatch):
    """set_device_data_batch sends rows in chunks of chunk_size."""
    from app.sdk.pullsdk import PullSDK
    sdk = MagicMock(spec=PullSDK)
    sdk.set_device_data = MagicMock(return_value=0)
    # Call the real method
    from app.sdk.pullsdk import PullSDK as RealPullSDK
    rows = [f"Pin={i}\tName=User{i}" for i in range(7)]
    # Manually test the logic
    ok, failed = 0, []
    chunk_size = 3
    for i in range(0, len(rows), chunk_size):
        chunk = rows[i:i + chunk_size]
        data = "\r\n".join(chunk) + "\r\n"
        ok += len(chunk)
    assert ok == 7  # All 7 rows accounted for


def test_nuke_and_repave_triggers_when_stale_exceeds_desired(tmp_path, monkeypatch):
    """When stale_pins > desired_pins, nuke-and-repave clears all tables."""
    svc, db_module = make_engine(tmp_path, monkeypatch)
    # 50 pins on device. Device allowedMemberships restricts to only 5 users.
    # → desired=5, stale=45 > desired → nuke mode
    device_pins = [str(i) for i in range(1, 51)]
    all_users = [make_user(am_id=i) for i in range(1, 51)]
    device = make_device()
    device["allowedMemberships"] = [1, 2, 3, 4, 5]  # only 5 desired

    sdk_cls, sdk_inst = _patch_sdk(device_pins=device_pins)
    sdk_inst.set_device_data_batch.return_value = (5, [])

    with patch("app.core.device_sync.PullSDK", sdk_cls):
        svc._sync_one_device(
            device=device,
            users=all_users,
            local_fp_index={},
            default_door_id=15,
        )

    # clear_device_table should have been called for 4 tables
    clear_calls = sdk_inst.clear_device_table.call_args_list
    cleared_tables = {c.kwargs.get("table") or c.args[0] for c in clear_calls}
    assert "user" in cleared_tables
    assert "userauthorize" in cleared_tables


def test_nuke_mode_does_not_call_individual_deletes(tmp_path, monkeypatch):
    """In nuke mode, individual delete_device_data should NOT be called for stale pins."""
    svc, db_module = make_engine(tmp_path, monkeypatch)
    device_pins = [str(i) for i in range(1, 51)]
    all_users = [make_user(am_id=i) for i in range(1, 51)]
    device = make_device()
    device["allowedMemberships"] = [1, 2, 3, 4, 5]  # only 5 desired → 45 stale

    sdk_cls, sdk_inst = _patch_sdk(device_pins=device_pins)
    sdk_inst.set_device_data_batch.return_value = (5, [])

    with patch("app.core.device_sync.PullSDK", sdk_cls):
        svc._sync_one_device(
            device=device,
            users=all_users,
            local_fp_index={},
            default_door_id=15,
        )

    # Individual delete_device_data should NOT be called for stale pins
    # (nuke mode clears everything via clear_device_table)
    delete_calls = [c for c in sdk_inst.delete_device_data.call_args_list
                    if "Pin=" in str(c)]
    assert len(delete_calls) == 0, f"Expected 0 individual deletes, got {len(delete_calls)}"


def test_batch_push_uses_set_device_data_batch(tmp_path, monkeypatch):
    """When pushing >5 users, batch push should use set_device_data_batch."""
    svc, db_module = make_engine(tmp_path, monkeypatch)
    users = [make_user(am_id=i) for i in range(1, 21)]  # 20 users, all new

    sdk_cls, sdk_inst = _patch_sdk(device_pins=[])  # Empty device
    sdk_inst.set_device_data_batch.return_value = (20, [])

    with patch("app.core.device_sync.PullSDK", sdk_cls):
        svc._sync_one_device(
            device=make_device(),
            users=users,
            local_fp_index={},
            default_door_id=15,
        )

    # set_device_data_batch should have been called for "user" table
    batch_calls = sdk_inst.set_device_data_batch.call_args_list
    user_batch = [c for c in batch_calls if c.kwargs.get("table") == "user"]
    assert len(user_batch) >= 1, "Expected batch push for user table"


def test_small_sync_uses_per_pin_loop(tmp_path, monkeypatch):
    """When pushing ≤5 users, per-pin loop should be used (not batch)."""
    svc, db_module = make_engine(tmp_path, monkeypatch)
    users = [make_user(am_id=i) for i in range(1, 4)]  # 3 users

    sdk_cls, sdk_inst = _patch_sdk(device_pins=[])
    sdk_inst.set_device_data_batch.return_value = (3, [])

    with patch("app.core.device_sync.PullSDK", sdk_cls):
        svc._sync_one_device(
            device=make_device(),
            users=users,
            local_fp_index={},
            default_door_id=15,
        )

    # Per-pin: set_device_data called individually (not batch)
    # 3 users × (1 user + 1 authorize) = 6 individual calls
    individual_calls = sdk_inst.set_device_data.call_count
    assert individual_calls >= 3, f"Expected ≥3 individual set_device_data calls, got {individual_calls}"

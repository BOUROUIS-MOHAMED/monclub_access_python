"""Regression tests for live batch sync progress reporting."""

import logging
from unittest.mock import MagicMock, patch


def make_engine(tmp_path, monkeypatch):
    import app.core.db as db_module

    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()

    from app.core.device_sync import DeviceSyncEngine

    return DeviceSyncEngine(cfg=MagicMock(), logger=logging.getLogger("test"))


def make_device(dev_id=1):
    return {
        "id": dev_id,
        "name": "TestDevice",
        "ipAddress": "10.0.0.1",
        "portNumber": 4370,
        "password": "",
        "active": True,
        "accessDevice": True,
        "accessDataMode": "DEVICE",
        "fingerprintEnabled": False,
        "authorizeTimezoneId": 1,
        "doorIds": [15],
        "doorPresets": [],
        "pushingToDevicePolicy": "ALL",
    }


def make_user(am_id):
    return {
        "activeMembershipId": am_id,
        "userId": am_id + 1000,
        "membershipId": am_id,
        "fullName": f"User {am_id}",
        "phone": "0600000000",
        "email": f"u{am_id}@example.com",
        "validFrom": "2026-01-01",
        "validTo": "2026-12-31",
        "firstCardId": str(am_id * 100),
        "secondCardId": None,
        "image": None,
        "fingerprints": [],
        "faceId": None,
        "accountUsernameId": None,
        "qrCodePayload": None,
        "birthday": None,
        "imageSource": None,
        "userImageStatus": None,
    }


def test_batch_push_reports_final_progress(tmp_path, monkeypatch):
    """
    Batch sync exposes final progress = total on completion.

    P0-bulk: per-pin pre-delete is skipped under the default "upsert" strategy,
    so intermediate progress ticks during pre-delete no longer exist. The
    observable contract is that the terminal snapshot reports current == total.
    """
    svc = make_engine(tmp_path, monkeypatch)
    users = [make_user(am_id=i) for i in range(1, 21)]

    sdk_cls = MagicMock()
    sdk_inst = MagicMock()
    sdk_cls.return_value = sdk_inst
    sdk_inst.get_device_data_rows.return_value = []
    sdk_inst.set_device_data.return_value = 0
    sdk_inst.set_device_data_batch.return_value = (20, [])
    sdk_inst.clear_device_table.return_value = 0
    sdk_inst.delete_device_data.return_value = 0
    sdk_inst.__enter__ = lambda s: s
    sdk_inst.__exit__ = MagicMock(return_value=False)

    progress_updates = []
    orig_set_progress = svc._set_progress

    def record_progress(**changes):
        orig_set_progress(**changes)
        progress_updates.append(svc.get_progress_snapshot()[0])

    monkeypatch.setattr(svc, "_set_progress", record_progress)

    with patch("app.core.device_sync.PullSDK", sdk_cls):
        svc._sync_one_device(
            device=make_device(),
            users=users,
            local_fp_index={},
            default_door_id=15,
        )

    assert progress_updates, "Expected at least one progress snapshot"
    assert progress_updates[-1]["current"] == len(users)
    assert progress_updates[-1]["total"] == len(users)


def test_batch_push_predelete_skipped_under_upsert_strategy(tmp_path, monkeypatch):
    """
    P0-bulk: under default "upsert" insert_strategy, no per-pin DeleteDeviceData
    calls should fire before the batch insert (saves 4×N SDK round-trips).
    """
    svc = make_engine(tmp_path, monkeypatch)
    users = [make_user(am_id=i) for i in range(1, 21)]

    sdk_cls = MagicMock()
    sdk_inst = MagicMock()
    sdk_cls.return_value = sdk_inst
    sdk_inst.get_device_data_rows.return_value = []
    sdk_inst.set_device_data.return_value = 0
    sdk_inst.set_device_data_batch.return_value = (20, [])
    sdk_inst.clear_device_table.return_value = 0
    sdk_inst.delete_device_data.return_value = 0
    sdk_inst.supports_delete_device_data.return_value = True
    sdk_inst.__enter__ = lambda s: s
    sdk_inst.__exit__ = MagicMock(return_value=False)

    with patch("app.core.device_sync.PullSDK", sdk_cls):
        svc._sync_one_device(
            device=make_device(),
            users=users,
            local_fp_index={},
            default_door_id=15,
        )

    # No per-pin delete_device_data calls for pins_to_sync (only stale-pin bulk).
    # Since device_pins is empty in this test, there are no stale pins either.
    assert sdk_inst.delete_device_data.call_count == 0, (
        f"Expected zero per-pin delete calls under upsert; got "
        f"{sdk_inst.delete_device_data.call_count}"
    )

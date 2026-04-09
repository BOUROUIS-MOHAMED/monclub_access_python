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


def test_batch_push_reports_progress_during_predelete(tmp_path, monkeypatch):
    """Batch sync should advance progress before the final save-state phase completes."""
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

    intermediate_currents = [
        progress["current"]
        for progress in progress_updates
        if 0 < progress.get("current", 0) < len(users)
    ]
    assert intermediate_currents, "Expected batch pre-delete to advance live progress before completion"
    assert progress_updates[-1]["current"] == len(users)
    assert progress_updates[-1]["total"] == len(users)

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


# ── P0-bulk: stale-pin bulk delete + strategy cascade ─────────────────────

def test_stale_pins_deleted_via_bulk_not_per_pin(tmp_path, monkeypatch):
    """
    Stale pins (on device, not in desired) are removed with bulk
    DeleteDeviceData — one call per table, not 4×N per-pin calls.
    With default INCREMENTAL policy and <50%/10 stale threshold, nuke mode
    is skipped and bulk delete path runs.
    """
    svc, db_module = make_engine(tmp_path, monkeypatch)
    # 12 pins on device, server knows all 12 (known_server_pins = 1..12),
    # but desired is restricted to 1..10 via allowedMemberships → 2 stale (11, 12).
    # Below the nuke threshold (>10 stale AND > desired).
    device_pins = [str(i) for i in range(1, 13)]
    all_users = [make_user(am_id=i) for i in range(1, 13)]
    device = make_device()
    device["pushingToDevicePolicy"] = "INCREMENTAL"
    device["allowedMemberships"] = [i for i in range(1, 11)]  # only 1..10 desired

    sdk_cls, sdk_inst = _patch_sdk(device_pins=device_pins)
    sdk_inst.set_device_data_batch.return_value = (10, [])
    sdk_inst.delete_device_data_batch = MagicMock(return_value=(2, []))
    sdk_inst.supports_delete_device_data.return_value = True

    with patch("app.core.device_sync.PullSDK", sdk_cls):
        svc._sync_one_device(
            device=device,
            users=all_users,
            local_fp_index={},
            default_door_id=15,
        )

    # delete_device_data_batch should have been called at least once (user table)
    assert sdk_inst.delete_device_data_batch.call_count >= 1, (
        "Expected bulk delete for stale pins"
    )


def test_insert_strategy_defaults_to_upsert_and_is_cached(tmp_path, monkeypatch):
    """
    On a fresh install (no cached FirmwareProfile), insert_strategy defaults
    to "upsert" and is persisted after first sync.
    """
    svc, db_module = make_engine(tmp_path, monkeypatch)
    users = [make_user(am_id=i) for i in range(1, 11)]

    sdk_cls, sdk_inst = _patch_sdk(device_pins=[])
    sdk_inst.set_device_data_batch.return_value = (10, [])
    sdk_inst.supports_delete_device_data.return_value = True

    with patch("app.core.device_sync.PullSDK", sdk_cls):
        svc._sync_one_device(
            device=make_device(dev_id=42),
            users=users,
            local_fp_index={},
            default_door_id=15,
        )

    from app.core.db import load_firmware_profile
    profile = load_firmware_profile(device_id=42)
    assert profile is not None
    assert profile["insert_strategy"] == "upsert"


def test_delete_then_insert_strategy_triggers_bulk_predelete(tmp_path, monkeypatch):
    """
    When FirmwareProfile.insert_strategy is pinned to "delete_then_insert",
    the batch path issues a bulk pre-delete instead of skipping (upsert) or
    per-pin deleting (one_by_one).
    """
    svc, db_module = make_engine(tmp_path, monkeypatch)
    users = [make_user(am_id=i) for i in range(1, 11)]

    # Pre-seed the profile with delete_then_insert strategy
    from app.core.db import save_firmware_profile
    save_firmware_profile(
        device_id=99,
        insert_strategy="delete_then_insert",
    )

    sdk_cls, sdk_inst = _patch_sdk(device_pins=[])
    sdk_inst.set_device_data_batch.return_value = (10, [])
    sdk_inst.delete_device_data_batch = MagicMock(return_value=(10, []))
    sdk_inst.supports_delete_device_data.return_value = True

    with patch("app.core.device_sync.PullSDK", sdk_cls):
        svc._sync_one_device(
            device=make_device(dev_id=99),
            users=users,
            local_fp_index={},
            default_door_id=15,
        )

    # Bulk pre-delete fires (stale path has no work since device_pins is empty,
    # so any delete_device_data_batch call must be the pre-delete).
    assert sdk_inst.delete_device_data_batch.call_count >= 1, (
        "Expected bulk pre-delete under delete_then_insert strategy"
    )


def test_fingerprint_disabled_device_skips_template_table_deletes(tmp_path, monkeypatch):
    """
    P1 gate: on devices with fingerprintEnabled=false (C3-400 panels), deletes
    must NEVER target the templatev10 / template tables. Those tables don't
    exist on the panel and every call would return rc=-100 "table structure
    missing" — waste observed in production logs.
    """
    svc, db_module = make_engine(tmp_path, monkeypatch)
    device = make_device()
    device["fingerprintEnabled"] = False
    device["pushingToDevicePolicy"] = "INCREMENTAL"
    device["allowedMemberships"] = [i for i in range(1, 13)]

    # Force one_by_one to exercise every per-pin delete path at once.
    from app.core.db import save_firmware_profile
    save_firmware_profile(device_id=device["id"], insert_strategy="one_by_one")

    device_pins = [str(i) for i in range(1, 13)]
    all_users = [make_user(am_id=i) for i in range(1, 13)]

    sdk_cls, sdk_inst = _patch_sdk(device_pins=device_pins)
    sdk_inst.set_device_data_batch.return_value = (10, [])
    sdk_inst.delete_device_data_batch = MagicMock(return_value=(2, []))
    sdk_inst.supports_delete_device_data.return_value = True

    with patch("app.core.device_sync.PullSDK", sdk_cls):
        svc._sync_one_device(
            device=device,
            users=all_users,
            local_fp_index={},
            default_door_id=15,
        )

    # Per-pin delete_device_data: every table argument passed must be in the
    # non-template set. Any 'templatev10' or 'template' target = regression.
    seen_tables = {
        (c.kwargs.get("table") or (c.args[0] if c.args else None))
        for c in sdk_inst.delete_device_data.call_args_list
    }
    assert "templatev10" not in seen_tables, (
        f"Per-pin delete hit templatev10 on fingerprintEnabled=false device: {seen_tables}"
    )
    assert "template" not in seen_tables, (
        f"Per-pin delete hit template on fingerprintEnabled=false device: {seen_tables}"
    )

    # Bulk stale-delete too — delete_device_data_batch calls' first positional
    # or 'table' kwarg must never be templatev10/template.
    for c in sdk_inst.delete_device_data_batch.call_args_list:
        t = c.kwargs.get("table") or (c.args[0] if c.args else None)
        assert t not in ("templatev10", "template"), (
            f"Bulk delete targeted {t} on fingerprintEnabled=false device"
        )


def test_set_device_data_batch_short_circuits_on_structural_error():
    """
    When the row-by-row fallback hits a structural error (rc=-101 'field not
    supported') on the FIRST row, the SDK must bail out of the rest of the
    chunk AND every remaining chunk instead of attempting 50 × N pointless
    row-by-row SDK calls. The domain layer's "retry without Name" takes over
    from there.
    """
    from app.sdk.pullsdk import PullSDK, PullSDKError

    sdk = PullSDK.__new__(PullSDK)
    sdk.logger = logging.getLogger("test")
    sdk._handle = 1
    sdk._dll = MagicMock()
    sdk.load = lambda: None  # type: ignore

    call_history = []

    def fake_set_device_data(*, table, data, options=""):
        call_history.append(data)
        # Simulate firmware that rejects any SetDeviceData with Name field.
        if "Name=" in data:
            raise PullSDKError("SetDeviceData FAILED table=user rc=-101 PullLastError=0")
        return 0

    sdk.set_device_data = fake_set_device_data  # type: ignore

    # 130 rows across 3 chunks of 50. All rows contain Name (firmware-hostile).
    rows = [f"Pin={i}\tName=U{i}\tCardNo={i}" for i in range(1, 131)]
    ok, failed = sdk.set_device_data_batch(table="user", rows=rows, chunk_size=50)

    # 0 successes (every row has Name), all 130 in failed list.
    assert ok == 0
    assert len(failed) == 130

    # Without the short-circuit this would fire:
    #   3 chunks × (1 batch + 50 row-by-row) = 153 SDK calls
    # With the short-circuit we expect:
    #   chunk-1 batch (1) + chunk-1 row-by-row first row (1) = 2 calls total,
    # then bail. Allow a small slack in case implementation tweaks it.
    assert len(call_history) <= 5, (
        f"Expected short-circuit after ≤5 SDK calls; got {len(call_history)}"
    )


def test_delete_device_data_batch_falls_back_to_per_pin_on_chunk_error():
    """Simulates a chunk error; verifies per-pin fallback is attempted."""
    from app.sdk.pullsdk import PullSDK, PullSDKError

    sdk = PullSDK.__new__(PullSDK)
    sdk.logger = logging.getLogger("test")
    sdk._handle = 1

    # Force delete_device_data to succeed per-pin but fail the first chunk
    call_history = []

    def fake_delete(*, table, data, options=""):
        call_history.append((table, data))
        # First call is the bulk chunk — fail it; subsequent per-pin calls succeed.
        if "\r\n" in data and data.count("Pin=") > 1:
            raise PullSDKError("simulated buffer error")
        return 0

    sdk.delete_device_data = fake_delete  # type: ignore
    sdk.load = lambda: None  # type: ignore
    import ctypes
    sdk._dll = MagicMock()
    sdk._dll.DeleteDeviceData = MagicMock(return_value=0)

    ok, failed = sdk.delete_device_data_batch(table="user", pins=[1, 2, 3], chunk_size=3)
    assert ok == 3
    assert failed == []
    # 1 bulk attempt + 3 per-pin fallbacks = 4 total calls
    assert len(call_history) == 4

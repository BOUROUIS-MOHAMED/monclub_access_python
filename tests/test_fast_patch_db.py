from __future__ import annotations

import importlib

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    importlib.reload(db_module)
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "fast_patch.db"), raising=False)
    db_module.init_db()
    db_module.invalidate_sync_cache()
    return db_module


def _bundle(*items, bundle_id: str = "bundle-1", generated_at: str = "2026-04-12T12:00:00Z") -> dict:
    return {
        "schemaVersion": 1,
        "bundleId": bundle_id,
        "gymId": 42,
        "generatedAt": generated_at,
        "items": list(items),
        "requiresReconcile": True,
    }


def _item(
    *,
    kind: str,
    entity_type: str,
    revision: str,
    entity_id: int | None = None,
    payload: dict | None = None,
    impact: dict | None = None,
) -> dict:
    return {
        "itemId": f"{entity_type}-{entity_id}-{revision}",
        "kind": kind,
        "entityType": entity_type,
        "entityId": entity_id,
        "revision": revision,
        "payload": payload or {},
        "impact": impact or {},
    }


def _member(active_membership_id: int, *, full_name: str = "Mohamed Test", membership_id: int = 7) -> dict:
    return {
        "userId": active_membership_id + 1000,
        "activeMembershipId": active_membership_id,
        "membershipId": membership_id,
        "fullName": full_name,
        "phone": "0600000000",
        "email": f"user{active_membership_id}@example.com",
        "validFrom": "2026-01-01",
        "validTo": "2026-12-31",
        "firstCardId": str(active_membership_id * 100),
        "secondCardId": None,
        "image": None,
        "fingerprints": [
            {
                "id": active_membership_id * 10,
                "fingerId": 1,
                "templateVersion": 10,
                "templateEncoding": "BASE64",
                "templateData": "dGVzdA==",
                "templateSize": 4,
                "label": "Right Thumb",
                "enabled": True,
                "lastPushError": None,
            }
        ],
        "faceId": None,
        "accountUsernameId": f"account-{active_membership_id}",
        "qrCodePayload": f"qr-{active_membership_id}",
        "birthday": "1990-01-01",
        "imageSource": None,
        "userImageStatus": None,
    }


def _device(device_id: int, *, name: str = "Gate A", access_mode: str = "ULTRA") -> dict:
    return {
        "id": device_id,
        "name": name,
        "description": "Main gate",
        "allowedMemberships": [7, 9],
        "active": True,
        "accessDevice": True,
        "ipAddress": "10.0.0.5",
        "macAddress": "AA:BB:CC:DD:EE:FF",
        "password": "",
        "portNumber": "4370",
        "accessDataMode": access_mode,
        "model": "ProFace X",
        "installedModels": ["ProFace X"],
        "doorIds": [15],
        "zone": "Entry",
        "showNotifications": True,
        "winNotifyEnabled": True,
        "popupEnabled": True,
        "popupDurationSec": 3,
        "popupShowImage": True,
        "totpPrefix": "9",
        "totpDigits": 7,
        "totpPeriodSeconds": 30,
        "totpDriftSteps": 1,
        "totpMaxPastAgeSeconds": 32,
        "totpMaxFutureSkewSeconds": 3,
        "rfidMinDigits": 1,
        "rfidMaxDigits": 16,
        "pulseTimeMs": 3000,
        "cmdTimeoutMs": 4000,
        "timeoutMs": 5000,
        "rtlogTable": "rtlog",
        "saveHistory": True,
        "deviceAttendanceHistoryReadingDelay": 30,
        "platform": "PULLSDK",
        "doorPresets": [
            {
                "id": 701,
                "deviceId": device_id,
                "doorNumber": 1,
                "pulseSeconds": 4,
                "doorName": "Turnstile",
                "createdAt": "2026-04-12T12:00:00Z",
                "updatedAt": "2026-04-12T12:00:00Z",
            }
        ],
        "totpEnabled": True,
        "rfidEnabled": True,
        "fingerprintEnabled": True,
        "faceIdEnabled": False,
        "adaptiveSleep": True,
        "busySleepMinMs": 0,
        "busySleepMaxMs": 500,
        "emptySleepMinMs": 200,
        "emptySleepMaxMs": 500,
        "emptyBackoffFactor": 1.35,
        "emptyBackoffMaxMs": 2000,
        "authorizeTimezoneId": 1,
        "pushingToDevicePolicy": "ALL",
        "createdAt": "2026-04-12T12:00:00Z",
        "updatedAt": "2026-04-12T12:00:00Z",
        "antiFraudeCard": True,
        "antiFraudeQrCode": True,
        "antiFraudeDuration": 30,
    }


def _settings(*, port: int) -> dict:
    return {
        "accessSoftwareSettings": {
            "id": 1,
            "gymId": 42,
            "accessServerHost": "127.0.0.1",
            "accessServerPort": port,
            "accessServerEnabled": True,
            "imageCacheEnabled": True,
            "imageCacheTimeoutSec": 2,
            "imageCacheMaxBytes": 5242880,
            "imageCacheMaxFiles": 1000,
            "eventQueueMax": 5000,
            "notificationQueueMax": 5000,
            "historyQueueMax": 5000,
            "popupQueueMax": 5000,
            "decisionWorkers": 2,
            "decisionEmaAlpha": 0.2,
            "historyRetentionDays": 30,
            "notificationRateLimitPerMinute": 30,
            "notificationDedupeWindowSec": 30,
            "notificationServiceEnabled": True,
            "historyServiceEnabled": True,
            "agentSyncBackendRefreshMin": 30,
            "defaultAuthorizeDoorId": 15,
            "sdkReadInitialBytes": 1048576,
            "optionalDataSyncDelayMinutes": 60,
            "createdAt": "2026-04-12T12:00:00Z",
            "updatedAt": "2026-04-12T12:00:00Z",
        },
        "contractStatus": True,
        "contractEndDate": "2026-12-31",
    }


def _credential(account_id: int, *, secret_hex: str) -> dict:
    return {
        "id": account_id + 500,
        "gymId": 42,
        "accountId": account_id,
        "secretHex": secret_hex,
        "enabled": True,
        "rotatedAt": "2026-04-12T12:00:00Z",
        "createdAt": "2026-04-12T12:00:00Z",
        "updatedAt": "2026-04-12T12:00:00Z",
        "grantedActiveMembershipIds": [11, 12],
    }


def test_apply_fast_patch_bundle_upserts_member_and_ignores_duplicate_and_stale_updates(db):
    bundle = _bundle(
        _item(
            kind="ENTITY_UPSERT",
            entity_type="ACTIVE_MEMBERSHIP",
            entity_id=11,
            revision="2026-04-12T12:00:01Z",
            payload={"member": _member(11, full_name="Mohamed Fresh")},
        )
    )

    result = db.apply_fast_patch_bundle(bundle)

    assert result == {"applied": 1, "skipped": 0, "ignored": None}
    assert db.list_sync_users()[0]["fullName"] == "Mohamed Fresh"

    duplicate = db.apply_fast_patch_bundle(bundle)

    assert duplicate == {"applied": 0, "skipped": 0, "ignored": "duplicate_bundle"}

    stale = db.apply_fast_patch_bundle(
        _bundle(
            _item(
                kind="ENTITY_UPSERT",
                entity_type="ACTIVE_MEMBERSHIP",
                entity_id=11,
                revision="2026-04-12T11:59:59Z",
                payload={"member": _member(11, full_name="Mohamed Stale")},
            ),
            bundle_id="bundle-2",
        )
    )

    assert stale == {"applied": 0, "skipped": 1, "ignored": None}
    assert db.list_sync_users()[0]["fullName"] == "Mohamed Fresh"


def test_apply_fast_patch_bundle_deletes_member(db):
    db.apply_fast_patch_bundle(
        _bundle(
            _item(
                kind="ENTITY_UPSERT",
                entity_type="ACTIVE_MEMBERSHIP",
                entity_id=11,
                revision="2026-04-12T12:00:01Z",
                payload={"member": _member(11)},
            )
        )
    )

    result = db.apply_fast_patch_bundle(
        _bundle(
            _item(
                kind="ENTITY_DELETE",
                entity_type="ACTIVE_MEMBERSHIP",
                entity_id=11,
                revision="2026-04-12T12:00:02Z",
            ),
            bundle_id="bundle-delete-member",
        )
    )

    assert result == {"applied": 1, "skipped": 0, "ignored": None}
    assert db.list_sync_users() == []


def test_apply_fast_patch_bundle_upserts_and_deletes_device(db):
    upsert = db.apply_fast_patch_bundle(
        _bundle(
            _item(
                kind="ENTITY_UPSERT",
                entity_type="GYM_DEVICE",
                entity_id=77,
                revision="2026-04-12T12:01:00Z",
                payload={"device": _device(77)},
            ),
            bundle_id="bundle-device-upsert",
        )
    )

    devices = db.list_sync_devices_payload()
    assert upsert == {"applied": 1, "skipped": 0, "ignored": None}
    assert devices[0]["id"] == 77
    assert devices[0]["doorPresets"][0]["doorNumber"] == 1

    deleted = db.apply_fast_patch_bundle(
        _bundle(
            _item(
                kind="ENTITY_DELETE",
                entity_type="GYM_DEVICE",
                entity_id=77,
                revision="2026-04-12T12:01:01Z",
            ),
            bundle_id="bundle-device-delete",
        )
    )

    assert deleted == {"applied": 1, "skipped": 0, "ignored": None}
    assert db.list_sync_devices_payload() == []


def test_apply_fast_patch_bundle_replaces_settings_and_contract_snapshot(db):
    result = db.apply_fast_patch_bundle(
        _bundle(
            _item(
                kind="SECTION_REPLACE",
                entity_type="SETTINGS",
                revision="2026-04-12T12:02:00Z",
                payload=_settings(port=8765),
            ),
            bundle_id="bundle-settings",
        )
    )

    assert result == {"applied": 1, "skipped": 0, "ignored": None}
    assert db.load_sync_access_software_settings()["accessServerPort"] == 8765
    assert db.load_sync_contract_meta() == {
        "contractStatus": True,
        "contractEndDate": "2026-12-31",
        "updatedAt": "2026-04-12T12:02:00Z",
    }


def test_apply_fast_patch_bundle_replaces_credentials_infrastructures_and_membership_types(db):
    result = db.apply_fast_patch_bundle(
        _bundle(
            _item(
                kind="SECTION_REPLACE",
                entity_type="CREDENTIALS",
                revision="2026-04-12T12:03:00Z",
                payload={
                    "gymAccessCredentials": [
                        _credential(3, secret_hex="abc123"),
                        _credential(4, secret_hex="def456"),
                    ]
                },
            ),
            _item(
                kind="SECTION_REPLACE",
                entity_type="INFRASTRUCTURES",
                revision="2026-04-12T12:03:00Z",
                payload={
                    "infrastructures": [
                        {"id": 91, "name": "Main Hall", "gymAgent": {"id": 8}},
                        {"id": 92, "name": "VIP Room", "gymAgent": {"id": 8}},
                    ]
                },
            ),
            _item(
                kind="SECTION_REPLACE",
                entity_type="MEMBERSHIP_TYPE",
                revision="2026-04-12T12:03:00Z",
                payload={
                    "membership": [
                        {"id": 7, "title": "Gold", "description": "Gold plan", "price": "100", "durationInDays": 30},
                        {"id": 9, "title": "VIP", "description": "VIP plan", "price": "200", "durationInDays": 60},
                    ]
                },
            ),
            bundle_id="bundle-sections",
        )
    )

    creds = db.list_sync_gym_access_credentials()
    infra = db.list_sync_infrastructures()
    memberships = db.list_sync_memberships()

    assert result == {"applied": 3, "skipped": 0, "ignored": None}
    assert [row["accountId"] for row in creds] == [3, 4]
    assert [row["name"] for row in infra] == ["Main Hall", "VIP Room"]
    assert [row["title"] for row in memberships] == ["Gold", "VIP"]


def test_apply_fast_patch_bundle_merges_targeted_credentials_without_deleting_other_accounts(db):
    db.apply_fast_patch_bundle(
        _bundle(
            _item(
                kind="SECTION_REPLACE",
                entity_type="CREDENTIALS",
                revision="2026-04-12T12:03:00Z",
                payload={
                    "gymAccessCredentials": [
                        _credential(3, secret_hex="abc123"),
                        _credential(4, secret_hex="def456"),
                    ]
                },
            ),
            bundle_id="bundle-credentials-seed",
        )
    )

    result = db.apply_fast_patch_bundle(
        _bundle(
            _item(
                kind="SECTION_REPLACE",
                entity_type="CREDENTIALS",
                revision="2026-04-12T12:03:01Z",
                payload={
                    "mergeMode": "UPSERT_ONLY",
                    "gymAccessCredentials": [
                        {
                            **_credential(3, secret_hex="updated999"),
                            "grantedActiveMembershipIds": [11],
                        }
                    ],
                },
            ),
            bundle_id="bundle-credentials-merge",
        )
    )

    creds = db.list_sync_gym_access_credentials()

    assert result == {"applied": 1, "skipped": 0, "ignored": None}
    assert [row["accountId"] for row in creds] == [3, 4]
    assert creds[0]["secretHex"] == "updated999"
    assert creds[0]["grantedActiveMembershipIds"] == [11]
    assert creds[1]["secretHex"] == "def456"

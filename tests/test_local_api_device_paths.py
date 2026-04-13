from __future__ import annotations

import sys
from types import SimpleNamespace
from types import ModuleType
from unittest.mock import patch

sys.modules.setdefault("requests", ModuleType("requests"))

from app.api import local_access_api_v2


def test_handle_device_door_presets_list_uses_direct_synced_lookup() -> None:
    sent: list[tuple[int, dict]] = []
    ctx = SimpleNamespace(
        param_int=lambda _name: 7,
        send_json=lambda status, payload: sent.append((status, payload)),
    )
    synced_presets = [
        {
            "id": 41,
            "deviceId": 7,
            "doorNumber": 1,
            "pulseSeconds": 5,
            "doorName": "Entry",
        }
    ]

    with (
        patch(
            "app.core.db.list_sync_device_door_presets_payload",
            return_value=synced_presets,
            create=True,
        ),
        patch(
            "access.store.get_sync_device_payload",
            side_effect=AssertionError("full sync device payload lookup should not be used"),
        ),
        patch(
            "access.store.list_device_door_presets",
            side_effect=AssertionError("local editable presets fallback should not be used"),
        ),
    ):
        local_access_api_v2._handle_device_door_presets_list(ctx)

    assert sent == [(200, {"presets": synced_presets})]


def test_handle_sync_cache_devices_prefers_cached_sync_snapshot() -> None:
    sent: list[tuple[int, dict]] = []
    ctx = SimpleNamespace(
        q=lambda *_args, **_kwargs: "1",
        send_json=lambda status, payload: sent.append((status, payload)),
    )
    cache = SimpleNamespace(
        devices=[
            {
                "id": 7,
                "name": "Door 7",
                "access_data_mode": "ULTRA",
                "door_presets": [
                    {
                        "id": 81,
                        "deviceId": 7,
                        "doorNumber": 1,
                        "pulseSeconds": 5,
                        "doorName": "Entry",
                    }
                ],
            }
        ]
    )

    with (
        patch("app.core.db.peek_sync_cache", return_value=cache, create=True),
        patch(
            "app.core.db.list_sync_devices_payload",
            side_effect=AssertionError("direct DB device payload lookup should not be used when cache exists"),
            create=True,
        ),
    ):
        local_access_api_v2._handle_sync_cache_devices(ctx)

    assert len(sent) == 1
    status, payload = sent[0]
    assert status == 200
    devices = payload["devices"]
    assert len(devices) == 1
    assert devices[0]["id"] == 7
    assert devices[0]["name"] == "Door 7"
    assert devices[0]["accessDataMode"] == "ULTRA"
    assert devices[0]["doorPresets"] == [
        {
            "id": 81,
            "deviceId": 7,
            "doorNumber": 1,
            "pulseSeconds": 5,
            "doorName": "Entry",
        }
    ]


def test_handle_device_door_presets_list_prefers_cached_sync_snapshot() -> None:
    sent: list[tuple[int, dict]] = []
    ctx = SimpleNamespace(
        param_int=lambda _name: 7,
        send_json=lambda status, payload: sent.append((status, payload)),
    )
    cache = SimpleNamespace(
        devices=[
            {
                "id": 7,
                "door_presets": [
                    {
                        "id": 41,
                        "deviceId": 7,
                        "doorNumber": 1,
                        "pulseSeconds": 5,
                        "doorName": "Entry",
                    }
                ],
            }
        ]
    )

    with (
        patch("app.core.db.peek_sync_cache", return_value=cache, create=True),
        patch(
            "app.core.db.list_sync_device_door_presets_payload",
            side_effect=AssertionError("direct synced preset lookup should not be used when cache exists"),
            create=True,
        ),
        patch(
            "access.store.list_device_door_presets",
            side_effect=AssertionError("local editable presets fallback should not be used"),
        ),
    ):
        local_access_api_v2._handle_device_door_presets_list(ctx)

    assert sent == [(
        200,
        {
            "presets": [
                {
                    "id": 41,
                    "deviceId": 7,
                    "doorNumber": 1,
                    "pulseSeconds": 5,
                    "doorName": "Entry",
                }
            ]
        },
    )]

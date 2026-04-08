from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.core.db import ACCESS_HISTORY_SOURCE_ULTRA, ACCESS_HISTORY_SYNC_PENDING, AccessHistoryRow
from app.core.device_attendance import DeviceAttendanceMaintenanceEngine


def _make_row() -> AccessHistoryRow:
    return AccessHistoryRow(
        id=41,
        created_at="2026-04-06T17:03:21Z",
        event_id="evt-41",
        device_id=5,
        door_id=1,
        card_no="13206664",
        event_time="2026-04-06 17:03:21",
        event_type="ACCESS",
        allowed=1,
        reason="granted",
        poll_ms=None,
        decision_ms=None,
        cmd_ms=None,
        cmd_ok=None,
        cmd_error=None,
        raw_json=json.dumps({"pin": "17406", "verifyType": "0", "direction": "IN"}),
        history_source=ACCESS_HISTORY_SOURCE_ULTRA,
        backend_sync_state=ACCESS_HISTORY_SYNC_PENDING,
        backend_attempt_count=0,
        backend_failure_count=0,
        backend_last_attempt_at=None,
        backend_next_retry_at=None,
        backend_synced_at=None,
        backend_last_error=None,
    )


def _make_user() -> dict[str, object]:
    return {
        "userId": 77,
        "activeMembershipId": 17406,
        "membershipId": 910,
        "fullName": "Youssef Habel",
        "phone": "12345678",
        "email": "youssef@example.com",
        "firstCardId": "13206664",
    }


def test_serialize_row_for_backend_includes_active_membership_field() -> None:
    engine = DeviceAttendanceMaintenanceEngine(cfg=SimpleNamespace(), logger=MagicMock())
    row = _make_row()

    item = engine._serialize_row_for_backend(
        row=row,
        users_by_am={17406: _make_user()},
        users_by_card={"13206664": _make_user()},
        devices_by_id={5: {"name": "door 1"}},
    )

    assert item["activeMembership"] == 17406
    assert item["activeMembershipId"] == 17406
    assert item["pin"] == 17406


def test_sync_pending_history_posts_raw_array_payload() -> None:
    engine = DeviceAttendanceMaintenanceEngine(cfg=SimpleNamespace(), logger=MagicMock())
    row = _make_row()
    fake_api = MagicMock()
    fake_api.sync_access_history.return_value = {"ok": True}

    with (
        patch("app.core.device_attendance.build_access_api_endpoints", return_value=SimpleNamespace()),
        patch("app.core.device_attendance.list_pending_access_history_for_sync", return_value=[row]),
        patch("app.core.device_attendance.list_sync_devices_payload", return_value=[{"id": 5, "name": "door 1"}]),
        patch("app.core.device_attendance.MonClubApi", return_value=fake_api),
        patch("app.core.device_attendance.mark_access_history_synced", return_value=1),
        patch("access.store.load_sync_cache", return_value=SimpleNamespace(users=[_make_user()])),
    ):
        result = engine._sync_pending_history(token="local-token", sync_online=True)

    payload = fake_api.sync_access_history.call_args.kwargs["payload"]
    assert isinstance(payload, list)
    assert payload[0]["activeMembership"] == 17406
    assert result == {"uploaded": 1, "failed": 0}

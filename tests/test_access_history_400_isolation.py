"""HTTP 400 on a history batch must isolate the poison row, not block the gym's history.

FIELD INCIDENT — OXYGENE_FIT, 2026-08-30
----------------------------------------
``bulk_save_gym_access_history`` answered ``400 "Invalid access history payload."`` for a
28-row batch::

    [DeviceAttendance] access history upload failed (http): syncAccessHistory failed:
    HTTP 400 -> {"status":false,"errorMsg":"Invalid access history payload.", ...}
    [DeviceAttendance] source=timer ... uploaded=0 upload_failed=28

The uploader marked every row retryable, so the SAME batch was re-sent and re-rejected
every 300 s. One row the backend's Jackson mapper could not convert silenced the whole
gym's door history indefinitely, and nothing said which row.

Backend-side (``GymAccessController.normalizeBulkSaveGymAccessHistoryPayload``) the 400
is raised for ANY element that fails ``convertValue`` into ``GymAccessDoorHistoryDto`` —
a batch-level verdict for a row-level fault.

These tests pin the new behaviour: on a batch 400, re-post rows one at a time; rows that
pass are synced; a row that is 400'd alone is quarantined as TERMINAL with the backend's
reason stored on it; any non-400 failure mid-way stops the loop and leaves the rest
retryable, so a flapping backend is never hammered.
"""

from __future__ import annotations

import json
import re
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.core.db import (
    ACCESS_HISTORY_SOURCE_ULTRA,
    ACCESS_HISTORY_SYNC_PENDING,
    AccessHistoryRow,
)
from app.core.device_attendance import (
    DeviceAttendanceMaintenanceEngine,
    _normalize_datetime_text,
)
from shared.api.monclub_api import MonClubApiHttpError


def _user() -> dict:
    return {
        "userId": 77, "activeMembershipId": 17406, "membershipId": 910,
        "fullName": "Youssef Habel", "phone": "12345678",
        "email": "youssef@example.com", "firstCardId": "13206664",
    }


def _row(row_id: int, event_id: str) -> AccessHistoryRow:
    return AccessHistoryRow(
        id=row_id,
        created_at="2026-08-30T14:01:00Z",
        event_id=event_id,
        device_id=8,
        door_id=1,
        card_no="",
        event_time="2026-08-30 13:51:31",
        event_type="0",
        allowed=1,
        reason="granted",
        poll_ms=None, decision_ms=None, cmd_ms=None, cmd_ok=None, cmd_error=None,
        raw_json=json.dumps({"pin": "17406", "scan_mode_hint": "FINGERPRINT", "direction": "IN"}),
        history_source=ACCESS_HISTORY_SOURCE_ULTRA,
        backend_sync_state=ACCESS_HISTORY_SYNC_PENDING,
        backend_attempt_count=0, backend_failure_count=0,
        backend_last_attempt_at=None, backend_next_retry_at=None,
        backend_synced_at=None, backend_last_error=None,
    )


def _http(status: int, msg: str) -> MonClubApiHttpError:
    return MonClubApiHttpError(
        f"syncAccessHistory failed: HTTP {status} -> {msg}", status_code=status, body=msg,
    )


def _run_upload(rows, fake_api):
    engine = DeviceAttendanceMaintenanceEngine(cfg=SimpleNamespace(), logger=MagicMock())
    synced = MagicMock(return_value=1)
    failed = MagicMock(return_value=1)
    with (
        patch("app.core.device_attendance.build_access_api_endpoints", return_value=SimpleNamespace()),
        patch("app.core.device_attendance.list_pending_access_history_for_sync", return_value=list(rows)),
        patch("app.core.device_attendance.list_sync_devices_payload", return_value=[{"id": 8, "name": "Sortie"}]),
        patch("app.core.device_attendance.MonClubApi", return_value=fake_api),
        patch("app.core.device_attendance.mark_access_history_synced", synced),
        patch("app.core.device_attendance.mark_access_history_sync_failure", failed),
        patch("access.store.load_sync_cache", return_value=SimpleNamespace(users=[_user()])),
    ):
        result = engine._sync_pending_history(token="local-token", sync_online=True)
    return result, synced, failed


def test_http_400_isolates_the_poison_row_and_uploads_the_rest() -> None:
    good, bad = _row(41, "evt-41"), _row(43, "evt-43")
    fake_api = MagicMock()

    def _post(*, token, payload, timeout=15):
        ids = [it["localRowId"] for it in payload]
        if len(ids) > 1:
            raise _http(400, 'Invalid access history payload. ...GymAccessDoorHistoryDto["date"]')
        if ids == [43]:
            raise _http(400, 'Invalid access history payload. Cannot deserialize LocalDateTime from "2026-00-30T13:51:31"')
        return {"ok": True}

    fake_api.sync_access_history.side_effect = _post
    result, synced, failed = _run_upload([good, bad], fake_api)

    assert fake_api.sync_access_history.call_count == 3, "batch + one request per row"
    synced.assert_called_once()
    assert synced.call_args.kwargs["row_ids"] == [41]
    failed.assert_called_once()
    kw = failed.call_args.kwargs
    assert kw["row_ids"] == [43]
    assert kw["terminal"] is True, "the poison row must leave the retry queue for good"
    assert "400" in kw["error"] and "2026-00-30" in kw["error"], "the backend's reason must be stored on the row"
    assert result == {"uploaded": 1, "failed": 1}


def test_http_5xx_keeps_whole_batch_retryable_without_fan_out() -> None:
    rows = [_row(41, "evt-41"), _row(43, "evt-43")]
    fake_api = MagicMock()
    fake_api.sync_access_history.side_effect = _http(503, "upstream down")
    result, synced, failed = _run_upload(rows, fake_api)

    assert fake_api.sync_access_history.call_count == 1, "a server fault must not trigger per-row requests"
    synced.assert_not_called()
    failed.assert_called_once()
    kw = failed.call_args.kwargs
    assert kw["row_ids"] == [41, 43] and kw["terminal"] is False
    assert result == {"uploaded": 0, "failed": 2}


def test_single_row_400_is_quarantined_without_a_second_request() -> None:
    fake_api = MagicMock()
    fake_api.sync_access_history.side_effect = _http(400, 'Invalid access history payload. ...["date"]')
    result, synced, failed = _run_upload([_row(41, "evt-41")], fake_api)

    assert fake_api.sync_access_history.call_count == 1, "the batch IS the row; no re-post"
    synced.assert_not_called()
    kw = failed.call_args.kwargs
    assert kw["row_ids"] == [41] and kw["terminal"] is True
    assert result == {"uploaded": 0, "failed": 1}


def test_isolation_stops_on_non_400_and_leaves_the_rest_retryable() -> None:
    rows = [_row(41, "evt-41"), _row(43, "evt-43"), _row(45, "evt-45")]
    fake_api = MagicMock()

    def _post(*, token, payload, timeout=15):
        ids = [it["localRowId"] for it in payload]
        if len(ids) > 1:
            raise _http(400, "Invalid access history payload.")
        if ids == [43]:
            raise _http(503, "upstream down")  # backend flaps mid-isolation
        return {"ok": True}

    fake_api.sync_access_history.side_effect = _post
    result, synced, failed = _run_upload(rows, fake_api)

    assert fake_api.sync_access_history.call_count == 3, "batch, 41, 43 -- never 45"
    assert synced.call_args.kwargs["row_ids"] == [41]
    kw = failed.call_args.kwargs
    assert kw["row_ids"] == [43, 45], "the failing row AND every un-attempted row stay retryable"
    assert kw["terminal"] is False
    assert result == {"uploaded": 1, "failed": 1}


def test_unparseable_event_time_uses_fallback_instead_of_forwarding_junk() -> None:
    # Junk (month 00) is no longer forwarded for the backend's LocalDateTime to choke on.
    assert _normalize_datetime_text("2026-00-30 13:51:31", fallback="2026-08-30 14:01:00") == "2026-08-30T14:01:00"
    # Valid inputs are untouched.
    assert _normalize_datetime_text("2026-08-30 13:51:31") == "2026-08-30T13:51:31"
    assert _normalize_datetime_text("2026-08-30T13:51:31Z") == "2026-08-30T13:51:31"
    # Junk with a junk fallback degrades to a real timestamp, never to junk text.
    assert re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",
        _normalize_datetime_text("garbage", fallback="also-garbage"),
    )

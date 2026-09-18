"""A door event the backend keeps calling unresolved must not be retried forever.

THE DEFECT
----------
``bulk_save_gym_access_history`` reports an event whose identifier does not resolve as
RETRYABLE (``failedIds``). The uploader re-armed such a row every
UPLOAD_FAILURE_RETRY_SECONDS with no bound, and ``prune_access_history`` never deletes
FAILED_RETRYABLE -- so a row naming a person who will never again resolve at the gym was
re-uploaded on every sync tick and kept for good. Because the uploader takes the oldest due
rows first, enough such rows also fill every UPLOAD_BATCH_SIZE batch ahead of newer events.

The backend now reports a person id that names a deleted row as TERMINAL. It cannot prove
"never" for a person who still exists but has no membership at the gym (the reported gym-58
population is exactly that), so those stay retryable and THIS side bounds them.

WHAT THESE TESTS PIN
--------------------
* Only an explicit backend verdict raises ``backend_unresolved_count``. 5xx, network errors
  and bodies that name no row never do, so an outage cannot expire an event.
* The delay doubles per verdict up to a cap.
* Expiry needs BOTH the verdict floor and the history-retention age. Expired rows become
  FAILED_TERMINAL (never uploaded again) and the unchanged prune deletes them.
* Wire compatibility in both directions:
    - old client + new backend: the parser shipped in access_1.4.30, 1.4.31, 1.4.33 and
      master (copied verbatim below) routes the new backend's body correctly;
    - new client + old backend: the bare "DONE" body acks every row and never counts a
      verdict, and the pre-change structured body (every unresolved row retryable) is bounded.

The backend half of the contract is ``VERDICT_CONTRACT_RESPONSE`` in monclub_backend's
``GymAccessHistoryIdentityResolutionTest``; ``NEW_BACKEND_CONTRACT_RESPONSE`` below mirrors it.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock, call, patch

import pytest

from app.core.db import (
    ACCESS_HISTORY_SOURCE_ULTRA,
    ACCESS_HISTORY_SYNC_FAILED_RETRYABLE,
    ACCESS_HISTORY_SYNC_FAILED_TERMINAL,
    ACCESS_HISTORY_SYNC_PENDING,
    AccessHistoryRow,
)
from app.core.device_attendance import (
    UNRESOLVED_MIN_VERDICTS_TO_EXPIRE,
    UNRESOLVED_RETRY_MAX_SECONDS,
    UPLOAD_FAILURE_RETRY_SECONDS,
    DeviceAttendanceMaintenanceEngine,
    _coerce_id_values,
    _safe_int,
)
from app.core.utils import format_ts
from shared.api.monclub_api import MonClubApiHttpError

# One row per verdict class, as the new backend answers localRowIds 1..4:
# resolved / person exists but not resolvable here / person id names no row / no identifier.
NEW_BACKEND_CONTRACT_RESPONSE: Dict[str, Any] = {
    "ok": False, "saved": 1, "failedCount": 3,
    "successIds": ["1"], "failedIds": ["2"], "terminalFailedIds": ["3", "4"],
    "resolvedByUserId": 1, "resolvedByMainAccountId": 0, "resolvedByActiveMembership": 0,
}

# claude/door-history-person-identity before this change: a deleted person was retryable too.
PRE_CHANGE_BACKEND_RESPONSE: Dict[str, Any] = {
    "ok": False, "saved": 1, "failedCount": 3,
    "successIds": ["1"], "failedIds": ["2", "3"], "terminalFailedIds": ["4"],
}

# monclub_backend main: `return ResponseEntity.ok("DONE")`. A 200 whose body is not JSON is
# returned by MonClubApi as {"ok": True, "raw": <text>}.
DONE_BACKEND_RESPONSE: Dict[str, Any] = {"ok": True, "raw": "DONE"}


# ── The deployed client's parser, frozen ─────────────────────────────────────────────────
#
# Verbatim from DeviceAttendanceMaintenanceEngine._parse_upload_response at master 7e2c2d3. Its
# source segment is identical (compared with ast.get_source_segment) in the access_1.4.30,
# access_1.4.31 and access_1.4.33 tags, as are _coerce_id_values and _safe_int, which it calls.
# Do not "fix" or refactor this copy: it stands for clients already installed in gyms.
def _deployed_parse_upload_response(
    self,
    *,
    response: Dict[str, Any],
    row_ids_by_event: Dict[str, int],
    row_ids_by_local: Dict[str, int],
    attempted_ids: List[int],
) -> Tuple[List[int], List[int], List[int]]:
    payload: Dict[str, Any] = response if isinstance(response, dict) else {"raw": response}
    data = payload.get("data")
    if isinstance(data, dict):
        payload = data

    ok_flag = payload.get("ok")
    success_flag = payload.get("success")
    status_flag = payload.get("status")
    overall_ok = True
    if ok_flag is not None:
        overall_ok = bool(ok_flag)
    elif success_flag is not None:
        overall_ok = bool(success_flag)
    elif status_flag is not None and isinstance(status_flag, bool):
        overall_ok = bool(status_flag)

    def map_tokens(tokens: List[str]) -> List[int]:
        ids: List[int] = []
        for token in tokens:
            if token in row_ids_by_local:
                ids.append(int(row_ids_by_local[token]))
                continue
            if token in row_ids_by_event:
                ids.append(int(row_ids_by_event[token]))
                continue
        return ids

    success_tokens: List[str] = []
    for key in (
        "successIds",
        "successEventIds",
        "insertedIds",
        "insertedEventIds",
        "syncedIds",
        "syncedEventIds",
        "duplicateIds",
        "duplicateEventIds",
    ):
        success_tokens.extend(_coerce_id_values(payload.get(key)))

    retry_tokens: List[str] = []
    for key in (
        "failedIds",
        "failedEventIds",
        "failedInsertionIds",
        "failedInsertionEventIds",
        "retryableFailedIds",
        "retryableFailedEventIds",
    ):
        retry_tokens.extend(_coerce_id_values(payload.get(key)))

    terminal_tokens: List[str] = []
    for key in (
        "terminalFailedIds",
        "terminalFailedEventIds",
        "validationFailedIds",
        "validationFailedEventIds",
    ):
        terminal_tokens.extend(_coerce_id_values(payload.get(key)))

    success_ids = sorted(set(map_tokens(success_tokens)))
    retryable_ids = sorted(set(map_tokens(retry_tokens)))
    terminal_ids = sorted(set(map_tokens(terminal_tokens)))

    if not overall_ok and not success_ids and not retryable_ids and not terminal_ids:
        return [], list(sorted(set(int(x) for x in attempted_ids))), []

    attempted_set = set(int(x) for x in attempted_ids)
    success_set = set(success_ids)
    retry_set = set(retryable_ids)
    terminal_set = set(terminal_ids)
    unresolved = attempted_set - success_set - retry_set - terminal_set

    failed_count = _safe_int(
        payload.get("failedCount")
        or payload.get("failedInsertionCount")
        or payload.get("numberOfFailedInsertion"),
        0,
    )

    if not success_set and not retry_set and not terminal_set and overall_ok and failed_count == 0:
        return list(sorted(attempted_set)), [], []

    if failed_count > 0 and unresolved:
        retry_set.update(unresolved)
        unresolved = set()

    if overall_ok and not retry_set and not terminal_set and unresolved:
        success_set.update(unresolved)
        unresolved = set()

    if unresolved:
        retry_set.update(unresolved)

    return list(sorted(success_set)), list(sorted(retry_set)), list(sorted(terminal_set))


# ── Wire compatibility ───────────────────────────────────────────────────────────────────

_LOCAL_TOKENS = {"1": 1, "2": 2, "3": 3, "4": 4}


def test_deployed_client_routes_every_verdict_class_of_the_new_backend() -> None:
    """Old client + new backend: no client release is needed for the terminal verdict."""
    success, retry, terminal = _deployed_parse_upload_response(
        None,
        response=NEW_BACKEND_CONTRACT_RESPONSE,
        row_ids_by_event={},
        row_ids_by_local=_LOCAL_TOKENS,
        attempted_ids=[1, 2, 3, 4],
    )
    assert success == [1]
    assert retry == [2]
    assert terminal == [3, 4], "a deleted person (3) must leave the deployed client's retry queue"


@pytest.mark.parametrize(
    "response",
    [
        NEW_BACKEND_CONTRACT_RESPONSE,
        PRE_CHANGE_BACKEND_RESPONSE,
        DONE_BACKEND_RESPONSE,
        {"ok": False},
        {"ok": True},
        {"ok": False, "failedCount": 2, "successIds": ["1"], "failedIds": ["2"]},
        {"data": {"success": False, "retryableFailedIds": ["3"], "validationFailedIds": ["4"]}},
        {"status": True, "failedEventIds": ["evt-2"], "failedCount": 1},
        {"ok": True, "successIds": ["1", "2"]},
    ],
    ids=["new", "pre-change", "done", "ok-false-bare", "ok-true-bare", "unaccounted",
         "data-wrapper", "event-tokens", "partial-success"],
)
def test_live_parser_still_agrees_with_the_deployed_parser(response: Dict[str, Any]) -> None:
    """The retry-key refactor must not change what any body means."""
    engine = DeviceAttendanceMaintenanceEngine(cfg=SimpleNamespace(), logger=MagicMock())
    kwargs = dict(
        response=response,
        row_ids_by_event={"evt-2": 2},
        row_ids_by_local=_LOCAL_TOKENS,
        attempted_ids=[1, 2, 3, 4],
    )
    assert engine._parse_upload_response(**kwargs) == _deployed_parse_upload_response(None, **kwargs)


# ── Uploader routing (database calls mocked) ─────────────────────────────────────────────


def _row(row_id: int) -> AccessHistoryRow:
    return AccessHistoryRow(
        id=row_id,
        created_at="2026-09-12 10:00:00",
        event_id=f"evt-{row_id}",
        device_id=8,
        door_id=1,
        card_no="",
        event_time="2026-09-12 09:59:00",
        event_type="0",
        allowed=1,
        reason="granted",
        poll_ms=None, decision_ms=None, cmd_ms=None, cmd_ok=None, cmd_error=None,
        raw_json=json.dumps({"direction": "IN"}),
        history_source=ACCESS_HISTORY_SOURCE_ULTRA,
        backend_sync_state=ACCESS_HISTORY_SYNC_PENDING,
        backend_attempt_count=0, backend_failure_count=0,
        backend_last_attempt_at=None, backend_next_retry_at=None,
        backend_synced_at=None, backend_last_error=None,
    )


def _count_rows(**kw: Any) -> int:
    return len(list(kw["row_ids"]))


def _run_upload(rows: List[AccessHistoryRow], *, response: Any = None, side_effect: Any = None):
    engine = DeviceAttendanceMaintenanceEngine(cfg=SimpleNamespace(), logger=MagicMock())
    api = MagicMock()
    if side_effect is not None:
        api.sync_access_history.side_effect = side_effect
    else:
        api.sync_access_history.return_value = response
    marks = SimpleNamespace(
        synced=MagicMock(side_effect=_count_rows),
        failure=MagicMock(side_effect=_count_rows),
        unresolved=MagicMock(side_effect=_count_rows),
    )
    with (
        patch("app.core.device_attendance.build_access_api_endpoints", return_value=SimpleNamespace()),
        patch("app.core.device_attendance.list_pending_access_history_for_sync", return_value=list(rows)),
        patch("app.core.device_attendance.list_sync_devices_payload", return_value=[{"id": 8, "name": "Porte"}]),
        patch("app.core.device_attendance.MonClubApi", return_value=api),
        patch("app.core.device_attendance.mark_access_history_synced", marks.synced),
        patch("app.core.device_attendance.mark_access_history_sync_failure", marks.failure),
        patch("app.core.device_attendance.mark_access_history_unresolved", marks.unresolved),
        # Unpatched, this reads the pin-scheme switch table of whatever database is active --
        # the installed gym database when no override is set.
        patch("app.core.device_attendance.list_device_pin_scheme_switches", return_value={}),
        patch("access.store.load_sync_cache", return_value=SimpleNamespace(users=[])),
    ):
        result = engine._sync_pending_history(token="local-token", sync_online=True)
    return result, marks, api


def test_new_backend_body_counts_a_verdict_only_for_the_unresolved_row() -> None:
    result, marks, _ = _run_upload([_row(i) for i in (1, 2, 3, 4)], response=NEW_BACKEND_CONTRACT_RESPONSE)

    assert marks.synced.call_args.kwargs["row_ids"] == [1]
    marks.unresolved.assert_called_once()
    kw = marks.unresolved.call_args.kwargs
    assert kw["row_ids"] == [2]
    assert kw["base_retry_seconds"] == UPLOAD_FAILURE_RETRY_SECONDS
    assert kw["max_retry_seconds"] == UNRESOLVED_RETRY_MAX_SECONDS
    marks.failure.assert_called_once()
    assert marks.failure.call_args.kwargs["row_ids"] == [3, 4]
    assert marks.failure.call_args.kwargs["terminal"] is True
    assert result == {"uploaded": 1, "failed": 3}


def test_old_done_backend_acks_every_row_and_never_counts_a_verdict() -> None:
    """New client + old backend (main's bare "DONE")."""
    result, marks, _ = _run_upload([_row(1), _row(2)], response=DONE_BACKEND_RESPONSE)

    assert marks.synced.call_args.kwargs["row_ids"] == [1, 2]
    marks.unresolved.assert_not_called()
    marks.failure.assert_not_called()
    assert result == {"uploaded": 2, "failed": 0}


def test_pre_change_backend_body_is_bounded_rather_than_retried_forever() -> None:
    """New client + the backend before this change, which called a deleted person retryable."""
    _, marks, _ = _run_upload([_row(i) for i in (1, 2, 3, 4)], response=PRE_CHANGE_BACKEND_RESPONSE)

    assert marks.unresolved.call_args.kwargs["row_ids"] == [2, 3]
    assert marks.failure.call_args.kwargs["row_ids"] == [4]
    assert marks.failure.call_args.kwargs["terminal"] is True


def test_a_body_naming_no_row_is_retried_without_counting_a_verdict() -> None:
    # ok=false with no lists: the parser returns every attempted row as retryable, but nothing
    # in the body was about any of them.
    _, marks, _ = _run_upload([_row(1), _row(2)], response={"ok": False})

    marks.unresolved.assert_not_called()
    kw = marks.failure.call_args.kwargs
    assert kw["row_ids"] == [1, 2] and kw["terminal"] is False


def test_rows_left_over_by_failed_count_are_retried_without_counting_a_verdict() -> None:
    response = {"ok": False, "failedCount": 2, "successIds": ["1"], "failedIds": ["2"]}
    _, marks, _ = _run_upload([_row(1), _row(2), _row(3)], response=response)

    assert marks.unresolved.call_args.kwargs["row_ids"] == [2]
    kw = marks.failure.call_args.kwargs
    assert kw["row_ids"] == [3] and kw["terminal"] is False


def test_http_5xx_never_counts_a_verdict() -> None:
    down = MonClubApiHttpError("syncAccessHistory failed: HTTP 503 -> down", status_code=503, body="down")
    _, marks, _ = _run_upload([_row(1), _row(2)], side_effect=down)

    marks.unresolved.assert_not_called()
    kw = marks.failure.call_args.kwargs
    assert kw["row_ids"] == [1, 2] and kw["terminal"] is False


def test_http_400_isolation_counts_the_verdict_a_single_row_gets() -> None:
    def _post(*, token, payload, timeout=15):
        ids = [it["localRowId"] for it in payload]
        if len(ids) > 1:
            raise MonClubApiHttpError("HTTP 400 -> Invalid access history payload.", status_code=400, body="bad")
        if ids == [2]:
            return {"ok": False, "failedCount": 1, "failedIds": ["2"]}
        return {"ok": True, "successIds": [str(ids[0])]}

    _, marks, _ = _run_upload([_row(1), _row(2)], side_effect=_post)

    assert marks.synced.call_args.kwargs["row_ids"] == [1]
    assert marks.unresolved.call_args.kwargs["row_ids"] == [2]
    marks.failure.assert_not_called()


def test_maintenance_expires_before_it_prunes_with_the_configured_retention() -> None:
    engine = DeviceAttendanceMaintenanceEngine(cfg=SimpleNamespace(), logger=MagicMock())
    order = MagicMock()
    order.expire.return_value = 2
    order.prune.return_value = 5
    with (
        patch("app.core.device_attendance.get_backend_global_settings", return_value={"history_retention_days": 12}),
        patch.object(engine, "_list_device_candidates", return_value=[]),
        patch.object(engine, "_sync_pending_history", return_value={"uploaded": 0, "failed": 0}),
        patch("app.core.device_attendance.expire_unresolved_access_history", order.expire),
        patch("app.core.device_attendance.prune_access_history", order.prune),
    ):
        summary = engine.run_blocking(source="test", sync_online=True, token="t")

    assert order.mock_calls == [
        call.expire(retention_days=12, min_unresolved_verdicts=UNRESOLVED_MIN_VERDICTS_TO_EXPIRE),
        call.prune(retention_days=12),
    ]
    assert summary["expired"] == 2 and summary["pruned"] == 5


# ── Database behaviour (real temporary SQLite) ───────────────────────────────────────────


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "unresolved.db"), raising=False)
    db_module.init_db()
    return db_module


def _insert(db, event_id: str, *, created_days_ago: int = 0) -> int:
    rc = db.insert_access_history(
        event_id=event_id, device_id=1, door_id=1, card_no="CARD-U",
        event_time="2026-08-01 10:00:00", event_type="scan", allowed=True, reason=None,
        poll_ms=None, decision_ms=None, cmd_ms=None, cmd_ok=None, cmd_error=None, raw=None,
        backend_sync_state=ACCESS_HISTORY_SYNC_PENDING,
    )
    assert rc == 1
    with db.get_conn() as conn:
        rid = int(conn.execute("SELECT id FROM access_history WHERE event_id=?", (event_id,)).fetchone()["id"])
        if created_days_ago:
            conn.execute(
                "UPDATE access_history SET created_at=? WHERE id=?",
                (format_ts(datetime.now() - timedelta(days=created_days_ago)), rid),
            )
            conn.commit()
    return rid


def _stored(db, rid: int):
    with db.get_conn() as conn:
        r = conn.execute("SELECT * FROM access_history WHERE id=?", (rid,)).fetchone()
    return dict(r) if r is not None else None


def _unresolved(db, rid: int, *, attempted_at: str | None = None, cap: int = UNRESOLVED_RETRY_MAX_SECONDS) -> None:
    db.mark_access_history_unresolved(
        row_ids=[rid], error="unresolved", base_retry_seconds=UPLOAD_FAILURE_RETRY_SECONDS,
        max_retry_seconds=cap, attempted_at=attempted_at,
    )


def test_outage_failures_do_not_count_but_an_explicit_verdict_does(db) -> None:
    rid = _insert(db, "outage-then-verdict")
    for _ in range(3):
        db.mark_access_history_sync_failure(row_ids=[rid], error="HTTP 503", retry_after_seconds=300, terminal=False)
    assert _stored(db, rid)["backend_unresolved_count"] == 0

    _unresolved(db, rid)

    stored = _stored(db, rid)
    assert stored["backend_unresolved_count"] == 1
    assert stored["backend_sync_state"] == ACCESS_HISTORY_SYNC_FAILED_RETRYABLE
    assert stored["backend_attempt_count"] == 4 and stored["backend_failure_count"] == 4


def test_unresolved_delay_doubles_per_verdict_up_to_the_cap(db) -> None:
    rid = _insert(db, "backoff")
    attempted = "2026-09-12 10:00:00"
    start = datetime(2026, 9, 12, 10, 0, 0)
    for verdicts, delay in enumerate([300, 600, 1200, 1500, 1500], start=1):
        _unresolved(db, rid, attempted_at=attempted, cap=1500)
        stored = _stored(db, rid)
        assert stored["backend_unresolved_count"] == verdicts
        assert stored["backend_next_retry_at"] == format_ts(start + timedelta(seconds=delay))


def test_an_unresolved_row_is_still_uploaded_once_its_delay_elapses(db) -> None:
    rid = _insert(db, "still-due")
    _unresolved(db, rid, attempted_at=format_ts(datetime.now() - timedelta(seconds=400)))

    # Also proves SELECT * still hydrates AccessHistoryRow with the new column present.
    assert rid in [r.id for r in db.list_pending_access_history_for_sync(limit=50)]


def test_expiry_needs_the_verdict_floor_and_the_retention_age_together(db) -> None:
    doomed = _insert(db, "doomed", created_days_ago=40)
    too_few = _insert(db, "too-few-verdicts", created_days_ago=40)
    outage = _insert(db, "outage-only", created_days_ago=40)
    young = _insert(db, "young", created_days_ago=5)
    for rid, verdicts in ((doomed, 3), (too_few, 2), (young, 10)):
        for _ in range(verdicts):
            _unresolved(db, rid)
    for _ in range(50):
        db.mark_access_history_sync_failure(row_ids=[outage], error="HTTP 503", retry_after_seconds=300, terminal=False)

    assert db.expire_unresolved_access_history(retention_days=30, min_unresolved_verdicts=3) == 1

    expired = _stored(db, doomed)
    assert expired["backend_sync_state"] == ACCESS_HISTORY_SYNC_FAILED_TERMINAL
    assert expired["backend_next_retry_at"] is None
    assert expired["backend_last_error"] == (
        "retries stopped after 3 unresolved verdicts from the backend; "
        "event older than the 30-day history retention"
    )
    for rid in (too_few, outage, young):
        assert _stored(db, rid)["backend_sync_state"] == ACCESS_HISTORY_SYNC_FAILED_RETRYABLE
    with db.get_conn() as conn:
        conn.execute("UPDATE access_history SET backend_next_retry_at=NULL")
        conn.commit()
    assert doomed not in [r.id for r in db.list_pending_access_history_for_sync(limit=50)]

    assert db.prune_access_history(retention_days=30) == 1
    assert _stored(db, doomed) is None
    assert _stored(db, outage) is not None, "an outage longer than retention must lose nothing"


def test_a_row_the_backend_keeps_rejecting_is_expired_and_pruned_end_to_end(db) -> None:
    """Real uploader against the real temporary database: three verdicts, expiry, prune."""
    doomed = _insert(db, "e2e-doomed", created_days_ago=40)
    outage = _insert(db, "e2e-outage", created_days_ago=40)
    db.mark_access_history_sync_failure(row_ids=[outage], error="HTTP 503", retry_after_seconds=10**7, terminal=False)

    engine = DeviceAttendanceMaintenanceEngine(cfg=SimpleNamespace(), logger=MagicMock())
    api = MagicMock()
    api.sync_access_history.side_effect = lambda *, token, payload, timeout=15: {
        "ok": False, "saved": 0, "failedCount": len(payload),
        "successIds": [], "failedIds": [str(it["localRowId"]) for it in payload], "terminalFailedIds": [],
    }
    with (
        patch("app.core.device_attendance.build_access_api_endpoints", return_value=SimpleNamespace()),
        patch("app.core.device_attendance.list_sync_devices_payload", return_value=[]),
        patch("app.core.device_attendance.MonClubApi", return_value=api),
        patch("access.store.load_sync_cache", return_value=SimpleNamespace(users=[])),
    ):
        for _ in range(UNRESOLVED_MIN_VERDICTS_TO_EXPIRE):
            with db.get_conn() as conn:  # the backoff elapses between ticks
                conn.execute("UPDATE access_history SET backend_next_retry_at=NULL WHERE id=?", (doomed,))
                conn.commit()
            engine._sync_pending_history(token="local-token", sync_online=True)

        assert _stored(db, doomed)["backend_unresolved_count"] == UNRESOLVED_MIN_VERDICTS_TO_EXPIRE
        assert db.expire_unresolved_access_history(
            retention_days=30, min_unresolved_verdicts=UNRESOLVED_MIN_VERDICTS_TO_EXPIRE
        ) == 1

        with db.get_conn() as conn:
            conn.execute("UPDATE access_history SET backend_next_retry_at=NULL WHERE id=?", (doomed,))
            conn.commit()
        engine._sync_pending_history(token="local-token", sync_online=True)

    assert api.sync_access_history.call_count == UNRESOLVED_MIN_VERDICTS_TO_EXPIRE, "an expired row is never re-uploaded"
    assert db.prune_access_history(retention_days=30) == 1
    assert _stored(db, doomed) is None
    assert _stored(db, outage)["backend_unresolved_count"] == 0

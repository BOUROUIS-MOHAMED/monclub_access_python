from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.core import db, device_attendance, offline_overlay
from tests.test_offline_overlay_filter import overlay_db, entry
from tests.test_offline_overlay_reconcile import decision, NOW


def add_event():
    db.insert_access_history(event_id="offline-door-event", device_id=1, door_id=1,
        card_no="", event_time="2026-10-31T12:30:00", event_type="0", allowed=True,
        reason="DEVICE_ALLOWED", poll_ms=None, decision_ms=None, cmd_ms=None, cmd_ok=None, cmd_error=None,
        raw={"pin": "900100001", "scan_mode_hint": "FINGERPRINT"}, history_source="ULTRA")


def uploader(monkeypatch, scheme):
    api = Mock()
    api.sync_access_history.return_value = {"ok": True, "saved": 1, "failedCount": 0}
    monkeypatch.setattr(device_attendance, "MonClubApi", lambda **kw: api)
    monkeypatch.setattr(device_attendance, "build_access_api_endpoints", lambda cfg: SimpleNamespace())
    monkeypatch.setattr(device_attendance, "list_sync_devices_payload", lambda: [{"id": 1, "pinScheme": scheme}])
    monkeypatch.setattr(device_attendance, "list_device_pin_scheme_switches", lambda: {1: [
        {"scheme": scheme, "previous_scheme": "MEMBERSHIP", "switched_at": "2026-01-01T00:00:00"}]})
    monkeypatch.setattr("access.store.load_sync_cache", lambda: SimpleNamespace(users=[]))
    return device_attendance.DeviceAttendanceMaintenanceEngine(cfg=SimpleNamespace(), logger=Mock()), api


def test_temp_pin_history_held_then_rewritten(overlay_db, monkeypatch):
    db.insert_offline_overlay(entry())
    add_event()
    engine, api = uploader(monkeypatch, "MEMBERSHIP")
    assert engine._sync_pending_history(token="gym", sync_online=True)["uploaded"] == 0
    api.sync_access_history.assert_not_called()
    with db.get_conn() as conn:
        assert conn.execute("SELECT offline_local_id FROM access_history").fetchone()[0] == "temp"
        conn.execute("UPDATE access_history SET created_at='2020-01-01 12:00:00'")
        conn.commit()
    assert db.prune_access_history(retention_days=1) == 0
    offline_overlay.reconcile_decisions([decision()], now=NOW)
    assert engine._sync_pending_history(token="gym", sync_online=True)["uploaded"] == 1
    sent, = api.sync_access_history.call_args.kwargs["payload"]
    assert sent["eventId"] == "offline-door-event" and sent["date"] == "2026-10-31T12:30:00"
    assert (sent["activeMembershipId"], sent["mainAccountId"], sent["userId"]) == (31000, 5, 900)
    assert sent["pin"] == 900100001
    with db.get_conn() as conn:
        row = conn.execute("SELECT * FROM access_history").fetchone()
        assert row["user_id"] == 900 and row["active_membership_id"] == 31000


def test_account_scheme_temp_history_not_lost(overlay_db, monkeypatch):
    db.insert_offline_overlay(entry())
    add_event()
    engine, api = uploader(monkeypatch, "ACCOUNT")
    engine._sync_pending_history(token="gym", sync_online=True)
    api.sync_access_history.assert_not_called()
    offline_overlay.reconcile_decisions([decision()], now=NOW)
    engine._sync_pending_history(token="gym", sync_online=True)
    sent = api.sync_access_history.call_args.kwargs["payload"][0]
    assert sent["mainAccountId"] == 5 and sent["mainAccountId"] != sent["pin"]


@pytest.mark.parametrize("reason", ["REFUSED", "EXPIRED", "REJECTED", "UNKNOWN"])
def test_undeliverable_temp_history_is_terminal_locally(overlay_db, monkeypatch, reason):
    db.insert_offline_overlay(entry())
    add_event()
    db.drop_offline_overlay("temp", reason)
    engine, api = uploader(monkeypatch, "ACCOUNT")
    engine._sync_pending_history(token="gym", sync_online=True)
    api.sync_access_history.assert_not_called()
    assert db.get_recent_access_history(limit=1)[0].backend_sync_state == "FAILED_TERMINAL"


def test_temp_pin_popup_resolves_without_person_id(overlay_db, monkeypatch):
    from tests.test_standalone_incremental_sync import _worker
    db.insert_offline_overlay(entry())
    worker, _ = _worker(monkeypatch)
    worker._device["id"] = worker._device_id = 1
    worker._get_cached_local_state = lambda: ([], {}, {})
    worker._enqueue_notification = Mock()
    worker._enqueue_history = Mock()
    worker._handle_allow("900100001", "2026-10-31T12:30:00", "event", 1, "0", {"pin": "900100001"})
    popup = worker._enqueue_notification.call_args.kwargs
    assert popup["user_full_name"] == "Ali" and popup["user_membership_title"] == "Accès provisoire"
    assert worker._enqueue_history.call_args.kwargs["raw"]["offlineLocalId"] == "temp"


def test_temp_event_never_enters_the_immediate_history_upload_queue(overlay_db, monkeypatch):
    import queue
    from tests.test_standalone_incremental_sync import _worker
    db.insert_offline_overlay(entry())
    worker, _ = _worker(monkeypatch)
    worker._device["id"] = worker._device_id = 1
    worker._poll_ema_ms = 0
    worker._history_q = queue.Queue()
    worker._enqueue_history(event_id="live-temp", allowed=True, reason="DEVICE_ALLOWED", event_type="0",
        card_no="", event_time="2026-10-31T12:30:00", raw={"pin": "900100001"})
    assert worker._history_q.empty()
    row, = db.get_recent_access_history(limit=1)
    assert row.offline_local_id == "temp" and row.user_id is None

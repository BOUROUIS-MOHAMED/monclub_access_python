from unittest.mock import MagicMock

from app.core import db, off_hours_push
from app.core.ultra_engine import UltraEngine, UltraDeviceWorker
from tests.test_p3b1_app_wiring import flip_app, fake_tel
from types import SimpleNamespace
import threading


def test_hours_move_after_date_step_uses_only_targeted_channel(flip_app, fake_tel, monkeypatch):
    app = flip_app
    order = []
    monkeypatch.setattr(db, "apply_local_date_flips", lambda **k: order.append("date") or {"moved": 0})
    monkeypatch.setattr(db, "off_hours_in_play", lambda: True)
    monkeypatch.setattr(db, "apply_off_hours", lambda **k: order.append("hours") or
                        {"moved": 1, "newly_held": [1], "released": [2]})
    monkeypatch.setattr(off_hours_push, "still_on_devices", lambda ids, **k: set(ids))
    app._after_date_flip_moved = MagicMock()
    app._request_running_ultra_sync = MagicMock(return_value=True)
    app._apply_date_flips("test")
    assert order == ["date", "hours"]
    app._after_date_flip_moved.assert_not_called()
    app.t.invalidate.assert_called_with(clear_cached=True)
    app._request_running_ultra_sync.assert_called_once_with(refresh={"members": True, "devices": False},
        changed_ids={2}, revoked_ids={1}, reason="off_hours")
    assert "OFF_HOURS" in [c.args[0] for c in fake_tel.event.call_args_list]
    assert "DATE_FLIP" not in [c.args[0] for c in fake_tel.event.call_args_list]


def test_minute_no_hours_does_not_write_or_check_date(flip_app, monkeypatch):
    monkeypatch.setattr(db, "off_hours_in_play", lambda: False)
    precheck = MagicMock()
    monkeypatch.setattr(db, "gym_date_status", precheck)
    flip_app._spawn_date_flip_thread = MagicMock()
    flip_app._off_hours_tick()
    precheck.assert_not_called()
    flip_app._spawn_date_flip_thread.assert_not_called()


def test_minute_hours_with_unchanged_date_skips_date_write(flip_app, monkeypatch):
    monkeypatch.setattr(db, "off_hours_in_play", lambda: True)
    monkeypatch.setattr(db, "gym_date_status", lambda **k: {"needs_flip": False})
    flip_app._spawn_date_flip_thread = lambda source, target: target()
    flip_app._apply_date_flips = MagicMock()
    flip_app._apply_off_hours_db = MagicMock(return_value={})
    flip_app._off_hours_tick()
    flip_app._apply_date_flips.assert_not_called()
    flip_app._apply_off_hours_db.assert_called_once()


def test_manual_mode_pending_retries_and_reverses_at_window_end(flip_app, monkeypatch):
    app = flip_app
    app.t.settings["manual_sync_mode"] = True
    monkeypatch.setattr(off_hours_push, "still_on_devices", lambda ids, **k: set(ids))
    app._request_running_ultra_sync = MagicMock(return_value=False)
    app._dispatch_off_hours({"newly_held": [1], "released": [2]}, "test")
    assert app._off_hours_pending == {"hold": {1}, "release": {2}}
    app._request_running_ultra_sync.return_value = True
    app._dispatch_off_hours({"retry": [1]}, "test")
    assert app._request_running_ultra_sync.call_args.kwargs["revoked_ids"] == {1}
    assert app._request_running_ultra_sync.call_args.kwargs["changed_ids"] == {2}
    assert app._off_hours_pending == {"hold": set(), "release": set()}
    app._off_hours_pending = {"hold": {1}, "release": set()}
    app._dispatch_off_hours({"released": [1]}, "test")
    assert app._request_running_ultra_sync.call_args.kwargs["revoked_ids"] == set()
    assert app._request_running_ultra_sync.call_args.kwargs["changed_ids"] == {1}


def test_hours_failure_does_not_stop_date_dispatch(flip_app, fake_tel, monkeypatch):
    monkeypatch.setattr(db, "off_hours_in_play", lambda: True)
    monkeypatch.setattr(db, "apply_off_hours", MagicMock(side_effect=RuntimeError("unreadable")))
    flip_app.t.results.append({"moved": 1})
    flip_app._after_date_flip_moved = MagicMock()
    flip_app._apply_date_flips("test")
    flip_app._after_date_flip_moved.assert_called_once()
    assert "OFF_HOURS_FAILED" in [c.args[0] for c in fake_tel.warn.call_args_list]


def test_off_hours_never_falls_back_to_a_general_scheduler():
    eng = object.__new__(UltraEngine)
    eng._running = True
    eng._sync_scheduler = MagicMock(_devices=[{"id": 1}])
    eng._workers = {}
    eng._logger = MagicMock()
    assert not eng.request_sync_now(changed_ids={2}, revoked_ids={1}, reason="off_hours")
    eng._sync_scheduler.request_sync_now.assert_not_called()


def command_worker():
    worker = object.__new__(UltraDeviceWorker)
    worker._member_sync_lock = threading.Lock()
    worker._wake_evt = threading.Event()
    worker._sdk = SimpleNamespace(owns_event_source=True)
    worker._connected = True
    worker._prefix = "test"
    worker._pending_member_syncs = []
    return worker


def test_release_replaces_queued_hold_and_failed_release_is_retried(monkeypatch):
    worker = command_worker()
    monkeypatch.setattr(db, "list_sync_users_by_active_membership_ids", lambda ids: [{"activeMembershipId": 1}])
    worker._run_standalone_member_revoke = MagicMock(return_value=True)
    worker._run_standalone_member_sync = MagicMock(return_value=False)
    worker.request_off_hours(held_ids={1}, released_ids=set())
    worker.request_off_hours(held_ids=set(), released_ids={1})
    assert worker._drain_off_hours_commands() == 1
    worker._run_standalone_member_revoke.assert_not_called()
    assert worker._off_hours_commands[1][0] is False
    worker._run_standalone_member_sync.return_value = True
    worker.request_off_hours(held_ids=set(), released_ids={1})
    worker._drain_off_hours_commands()
    assert not worker._off_hours_commands


def test_failed_hold_cannot_escalate_and_active_release_wins(monkeypatch):
    worker = command_worker()
    monkeypatch.setattr(db, "list_off_hours_held_rows", lambda: [{"activeMembershipId": 1}])

    def failed(am):
        assert not worker.request_full_sync(reason="revoke-failed", revoked_ids={am})
        worker.request_off_hours(held_ids=set(), released_ids={am})
        return False
    worker._run_standalone_member_revoke = failed
    worker.request_off_hours(held_ids={1}, released_ids=set())
    worker._drain_off_hours_commands()
    assert worker._off_hours_commands[1] == (False, 0.0)


def test_revokes_are_owned_and_use_payload_mode_and_device_plan_filter(monkeypatch):
    monkeypatch.setattr(db, "list_off_hours_held_rows", lambda: [
        {"activeMembershipId": 1, "mainAccountId": 7, "membershipId": 1},
        {"activeMembershipId": 2, "mainAccountId": 8, "membershipId": 1}])
    monkeypatch.setattr(db, "list_sync_users", lambda: [
        {"activeMembershipId": 3, "mainAccountId": 7, "membershipId": 2}])
    monkeypatch.setattr(db, "list_sync_devices_payload", lambda: [
        {"id": 1, "accessDataMode": "ULTRA", "pinScheme": "ACCOUNT", "allowedMemberships": [1]}])
    monkeypatch.setattr(db, "list_confirmed_device_sync_pins", lambda **k: {"7"})
    assert off_hours_push.still_on_devices({1, 2}) == {1}


def test_release_survives_hold_discovery_failure(flip_app, monkeypatch):
    monkeypatch.setattr(off_hours_push, "still_on_devices", MagicMock(side_effect=RuntimeError("read")))
    monkeypatch.setattr(db, "apply_off_hours", lambda **kw: {"released": []})
    flip_app._request_running_ultra_sync = MagicMock(return_value=False)
    flip_app._dispatch_off_hours({"released": [1], "newly_held": [2]}, "test")
    assert flip_app._off_hours_pending == {"hold": set(), "release": {1}}
    flip_app._request_running_ultra_sync.assert_called_once_with(
        refresh={"members": True, "devices": False}, changed_ids={1}, revoked_ids=set(), reason="off_hours")


def test_discovery_error_releases_existing_holds_too(flip_app, monkeypatch):
    monkeypatch.setattr(off_hours_push, "still_on_devices", MagicMock(side_effect=RuntimeError("read")))
    opened = MagicMock(return_value={"released": [2], "moved": 1})
    monkeypatch.setattr(db, "apply_off_hours", opened)
    flip_app._request_running_ultra_sync = MagicMock(return_value=True)
    flip_app._dispatch_off_hours({"retry": [2]}, "test")
    assert opened.call_args.kwargs["force_release"] is True
    assert flip_app._request_running_ultra_sync.call_args.kwargs["changed_ids"] == {2}
    assert not flip_app._request_running_ultra_sync.call_args.kwargs["revoked_ids"]

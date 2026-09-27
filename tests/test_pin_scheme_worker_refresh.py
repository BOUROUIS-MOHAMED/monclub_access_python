"""Release MUST (cutover release checklist §3a, guide §3.2e): a pinScheme switch reaches the
running ULTRA workers before any pass is queued, and no pass pushes a pin derived under a scheme
the database no longer records.

Before: a GYM_DEVICE fast patch recorded the switch (db._insert_device_row) and queued a full pass
through _request_running_ultra_sync, but the running workers kept their own device copy until the
next successful server sync refreshed them -- so the queued pass pushed MEMBERSHIP pins onto a
terminal the operator had just wiped for ACCOUNT pins. The same held for a pass queued while the
link was down, for a pass already pushing when the patch arrived, and for any pass drained between
a sync's device-section save and the end of that sync tick.

Real code throughout: MainApp.apply_fast_patch_bundle -> db.apply_fast_patch_bundle on a temp
database, a real (never started) UltraEngine + UltraDeviceWorker, and a fake MB2000 driver that
records every user row handed to it. The roster carries the collision the scheme gate exists for
(guide §3.2b): membership 5 is Alice, and 5 is also Bob's account id -- so a MEMBERSHIP pin "5" is
Alice and an ACCOUNT pin "5" is Bob.
"""
from __future__ import annotations

import logging
import queue
import threading
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

_DEVICE_ID = 9


def _member(am_id: int, user_id: int, account_id: int, name: str) -> Dict[str, Any]:
    return {
        "activeMembershipId": am_id, "userId": user_id, "mainAccountId": account_id,
        "membershipId": 7, "fullName": name, "phone": "0600000000",
        "email": f"u{user_id}@example.com", "validFrom": "2026-01-01T00:00:00",
        "validTo": "2026-12-31T00:00:00", "firstCardId": str(1000 + user_id),
        "secondCardId": None, "image": None, "fingerprints": [], "faceId": None,
        "accountUsernameId": None, "qrCodePayload": None, "birthday": None,
        "imageSource": None, "userImageStatus": None, "userProfileImage": None,
    }


# Alice: membership 5, account 700. Bob: membership 6, account 5 (= Alice's membership id).
# Carol: membership 8, account 800. Enough rows for a multi-chunk push (one member a chunk).
_USERS = [
    _member(5, 105, 700, "Alice"),
    _member(6, 106, 5, "Bob"),
    _member(8, 108, 800, "Carol"),
]
_MEMBERSHIP_PINS = {"5": "Alice", "6": "Bob", "8": "Carol"}
_ACCOUNT_PINS = {"700": "Alice", "5": "Bob", "800": "Carol"}


def _device(scheme: str) -> Dict[str, Any]:
    return {
        "id": _DEVICE_ID, "name": "Entree", "ipAddress": "192.168.9.10", "portNumber": 4370,
        "deviceProtocol": "ZK_STANDALONE", "accessDataMode": "ULTRA", "active": True,
        "accessDevice": True, "rosterPushingPolicy": "PRESERVE", "doorIds": [1],
        "allowedMemberships": [], "pinScheme": scheme,
    }


def _payload(users, devices) -> Dict[str, Any]:
    return {
        "users": users, "membersDeltaMode": False, "validMemberIds": None, "devices": devices,
        "gymAccessCredentials": [], "infrastructures": [], "membership": [],
        "contractStatus": True, "contractEndDate": "2026-12-31", "accessSoftwareSettings": {},
    }


def _switch_bundle(scheme: str, *, bundle_id: str = "b-switch") -> Dict[str, Any]:
    return {
        "bundleId": bundle_id,
        "requiresReconcile": False,
        "items": [{
            "kind": "ENTITY_UPSERT", "entityType": "GYM_DEVICE", "entityId": _DEVICE_ID,
            "revision": "2026-09-26T21:00:00",
            "payload": {"device": _device(scheme)},
            "impact": {"affectedMemberIds": [], "affectedDeviceIds": [_DEVICE_ID],
                       "requiresDeviceRescope": True},
        }],
    }


class _RecordingMb2000:
    """A push driver that records every (pin, name) it is handed, one member per chunk.

    It honours push_roster's between_chunks contract (zkemkeeper_guide §5): the hook runs after
    a chunk returned and before the next is sent -- never before the first, never after the last
    -- and pins it returns are dropped from the chunks not sent yet, reported as superseded.
    ``during_chunk[n]`` runs while chunk ``n`` (0-based) is in flight -- after its rows were
    handed over, before it returns: a test uses it to land a fast patch in the middle of a push,
    the way a dashboard edit reaches the app while the worker's STA command is running.
    """

    owns_event_source = True
    is_connected = True

    def __init__(self) -> None:
        self.sent: List[tuple] = []
        self.during_chunk: Dict[int, Any] = {}

    def push_roster(self, users, templates_by_pin=None, *, remove_fingers_by_pin=None,
                    bracket_enable_device=False, on_chunk=None, between_chunks=None, **_kw):
        remaining = [dict(u) for u in users]
        sent: List[Dict[str, Any]] = []
        superseded: List[str] = []
        n = 0
        while remaining:
            if n and between_chunks is not None:
                drop = {str(p) for p in (between_chunks() or ())}
                superseded += [u["pin"] for u in remaining if str(u["pin"]) in drop]
                remaining = [u for u in remaining if str(u["pin"]) not in drop]
                if not remaining:
                    break
            part = [remaining.pop(0)]
            for u in part:
                self.sent.append((str(u["pin"]), str(u.get("name") or "")))
            hook = self.during_chunk.get(n)
            if hook is not None:
                hook()
            res = {"ok": True, "pushed": len(part), "failed": 0, "templates_failed": 0,
                   "skipped_pin": 0, "failed_pins": [], "user_written": [u["pin"] for u in part]}
            if on_chunk is not None:
                on_chunk(part, res)
            sent += part
            n += 1
        return {"ok": True, "pushed": len(sent), "failed": 0, "templates_failed": 0,
                "skipped_pin": 0, "chunks_wedged": 0, "errors": [], "failed_pins": [],
                "superseded_pins": superseded, "user_written": [u["pin"] for u in sent],
                "del_attempted": 0, "del_ok": 0}


@pytest.fixture
def world(tmp_path, monkeypatch):
    import app.core.db as db
    import app.core.ultra_engine as ue
    import app.ui.app as app_module
    from app.core.settings_reader import normalize_device_settings

    monkeypatch.setattr(db, "_DB_PATH", str(tmp_path / "scheme_refresh.db"), raising=False)
    db.init_db()
    monkeypatch.setattr(db, "refresh_sync_cache_async", MagicMock())
    db.save_sync_cache(_payload(_USERS, [_device("MEMBERSHIP")]))
    db.invalidate_sync_cache(clear_cached=True)

    [payload] = db.list_sync_devices_payload()
    assert payload["pinScheme"] == "MEMBERSHIP"
    settings = normalize_device_settings(payload)
    payload["_settings"] = settings
    worker = ue.UltraDeviceWorker(payload, settings, queue.Queue(), queue.Queue(), threading.Event())
    worker.is_alive = lambda: True          # a live worker, driven by hand (never started)
    driver = _RecordingMb2000()
    worker._sdk = driver
    worker._connected = True

    log = logging.getLogger("test.scheme_refresh")
    engine = ue.UltraEngine(cfg=None, logger_inst=log)
    engine._running = True
    engine._workers = {_DEVICE_ID: worker}
    engine._sync_scheduler = ue.UltraSyncScheduler(None, log)
    engine._sync_scheduler.set_workers(engine._workers)
    engine._sync_scheduler.update_devices([payload])

    app = object.__new__(app_module.MainApp)
    app.logger = log
    app._ultra_lock = threading.Lock()
    app._ultra_engine = engine
    app._ultra_defer_until_mono = None
    app._apply_date_flips = MagicMock()
    app.request_sync_now = MagicMock()
    yield {"db": db, "app": app, "worker": worker, "driver": driver, "engine": engine}
    db.invalidate_sync_cache(clear_cached=True)
    if hasattr(db, "_shutdown_db_writer_for_tests"):
        db._shutdown_db_writer_for_tests()


def _pushed(driver) -> Dict[str, str]:
    return dict(driver.sent)


def _assert_only_account_pins(driver) -> None:
    sent = list(driver.sent)
    assert sent, "the pass pushed nothing at all"
    for pin, name in sent:
        assert _ACCOUNT_PINS.get(pin) == name, (
            f"pin {pin!r} was pushed as {name!r}: a pin derived under the scheme the database no "
            f"longer records (MEMBERSHIP pin 5 is Alice; ACCOUNT pin 5 is Bob). Sent: {sent}")


def test_a_membership_to_account_fast_patch_refreshes_the_worker_before_the_pass(world):
    app, worker, driver = world["app"], world["worker"], world["driver"]

    app.apply_fast_patch_bundle(_switch_bundle("ACCOUNT"))

    assert worker._device.get("pinScheme") == "ACCOUNT", "the running worker still holds the old device row"
    assert worker._pending_full_sync_request is not None, "the fast patch queued no pass"
    worker._drain_full_sync_commands()
    _assert_only_account_pins(driver)
    assert _pushed(driver) == _ACCOUNT_PINS


def test_a_pass_queued_while_the_link_was_down_pushes_under_the_new_scheme(world):
    app, worker, driver = world["app"], world["worker"], world["driver"]
    # A pass queued before the switch, drained while the link is down: re-queued for the
    # reconnect (ultra_engine._drain_full_sync_commands), nothing sent.
    worker.request_full_sync(reason="timer")
    worker._connected = False
    worker._drain_full_sync_commands()
    assert driver.sent == [] and worker._pending_full_sync_request is not None

    app.apply_fast_patch_bundle(_switch_bundle("ACCOUNT"))

    worker._connected = True          # the link comes back
    worker._drain_full_sync_commands()
    _assert_only_account_pins(driver)


def test_a_switch_that_lands_mid_push_stops_the_old_scheme_push(world):
    app, worker, driver = world["app"], world["worker"], world["driver"]
    # A MEMBERSHIP pass is already pushing when the operator's switch arrives: the fast patch
    # lands while its first chunk is in flight. That chunk was handed over before the switch
    # existed (the residual guide §3.2e states: at most the chunk in flight); nothing derived
    # under MEMBERSHIP may be sent after it.
    worker.request_full_sync(reason="timer")
    switched = []

    def _switch_now():
        app.apply_fast_patch_bundle(_switch_bundle("ACCOUNT"))
        switched.append(len(driver.sent))

    driver.during_chunk[0] = _switch_now
    worker._drain_full_sync_commands()

    assert switched == [1], "the switch did not land mid-push"
    in_flight, after = driver.sent[:1], driver.sent[1:]
    assert _MEMBERSHIP_PINS.get(in_flight[0][0]) == in_flight[0][1], in_flight
    assert after == [], f"old-scheme pins were pushed after the switch was recorded: {after}"
    assert worker._pending_full_sync_request is not None, "no pass queued for the new scheme"

    # The pass the fast patch queued then pushes the new scheme.
    driver.sent.clear()
    worker._drain_full_sync_commands()
    _assert_only_account_pins(driver)


def test_a_switch_between_the_roster_build_and_the_push_sends_nothing(world, monkeypatch):
    app, worker, driver = world["app"], world["worker"], world["driver"]
    # The pass started under MEMBERSHIP (its roster is built) and the switch lands just before
    # its first write -- here while the write-ahead intents are recorded.
    worker.request_full_sync(reason="timer")
    real_record = worker._record_push_intents

    def _switch_then_record(*a, **kw):
        if not getattr(_switch_then_record, "done", False):
            _switch_then_record.done = True
            app.apply_fast_patch_bundle(_switch_bundle("ACCOUNT"))
        return real_record(*a, **kw)

    monkeypatch.setattr(worker, "_record_push_intents", _switch_then_record)
    worker._drain_full_sync_commands()
    assert driver.sent == [], f"a roster built before the switch was pushed: {driver.sent}"

    worker._drain_full_sync_commands()
    _assert_only_account_pins(driver)


def test_a_pass_drained_before_the_workers_are_refreshed_writes_nothing(world):
    db, worker, driver = world["db"], world["worker"], world["driver"]
    # The server-sync path: the device section (with the switch) is saved, and a pass drains
    # BEFORE the tick refreshes the workers -- e.g. a removal retry or a date-flip pass. The
    # worker still holds MEMBERSHIP; the database records ACCOUNT.
    db.save_sync_cache_delta(
        {"devices": [_device("ACCOUNT")]},
        {"members": False, "devices": True, "credentials": False, "settings": False},
    )
    db.invalidate_sync_cache(clear_cached=True)
    assert worker._device.get("pinScheme") == "MEMBERSHIP"

    worker.request_full_sync(reason="removal-retry")
    worker._drain_full_sync_commands()

    assert driver.sent == [], f"a stale device copy pushed old-scheme pins: {driver.sent}"


def test_an_unchanged_scheme_still_pushes(world):
    """Control: a GYM_DEVICE patch that keeps the scheme changes nothing about the push."""
    app, worker, driver = world["app"], world["worker"], world["driver"]

    app.apply_fast_patch_bundle(_switch_bundle("MEMBERSHIP", bundle_id="b-same"))

    worker._drain_full_sync_commands()
    assert _pushed(driver) == _MEMBERSHIP_PINS


# ================================================================== the PullSDK path
# The ULTRA worker hands a PullSDK panel to DeviceSyncEngine with its own device copy (§3.3),
# and the DEVICE-mode engine reads the device from the sync-cache snapshot, which is served
# stale while it reloads. Both derive pins from that copy.
from tests.test_account_pin_device_sites import (  # noqa: E402,F401  (fixture + helpers)
    _engine, _pullsdk_device, _record_schemes, _sdk, _written_pins, _deleted_pins, sqlite_db,
)
from tests.test_account_pin_device_sites import _member as _panel_member  # noqa: E402


def _panel_users():
    # Same collision as above: membership 5 is Alice; account 5 is Bob.
    return [_panel_member(5, 105, 700, "Alice", card="1105"),
            _panel_member(6, 106, 5, "Bob", card="1106")]


def _run_panel(users, device, sdk):
    from unittest.mock import patch

    with patch("app.core.device_sync.PullSDK", MagicMock(return_value=sdk)):
        _engine()._sync_one_device(device=device, users=users, local_fp_index={},
                                   default_door_id=1, changed_ids=None)


def test_a_panel_pass_from_a_device_row_older_than_the_switch_touches_nothing(sqlite_db):
    from app.core.device_sync import PinSchemeSwitchedError

    _record_schemes(sqlite_db, "MEMBERSHIP", "ACCOUNT")       # the database says ACCOUNT
    sdk = _sdk()

    with pytest.raises(PinSchemeSwitchedError):
        _run_panel(_panel_users(), _pullsdk_device(pinScheme="MEMBERSHIP"), sdk)

    assert _written_pins(sdk) == [] and _deleted_pins(sdk) == []
    assert not [c for c in sdk.mock_calls if c[0] == "connect"], "no session was even opened"


def test_a_switch_recorded_during_a_panel_pass_stops_it_before_the_user_batch(sqlite_db):
    from app.core.device_sync import PinSchemeSwitchedError

    _record_schemes(sqlite_db, "MEMBERSHIP")
    sdk = _sdk()
    real_rows = sdk.get_device_data_rows.return_value

    def _read_then_switch(*_a, **_kw):
        # The pass reads the panel's pins under MEMBERSHIP; meanwhile the switch is recorded.
        _record_schemes(sqlite_db, "ACCOUNT")
        return real_rows

    sdk.get_device_data_rows.side_effect = _read_then_switch

    with pytest.raises(PinSchemeSwitchedError):
        _run_panel(_panel_users(), _pullsdk_device(pinScheme="MEMBERSHIP"), sdk)

    assert _written_pins(sdk) == [], f"old-scheme rows were written: {_written_pins(sdk)}"


def test_a_targeted_panel_member_sync_from_an_old_device_row_is_deferred(sqlite_db):
    from app.core.device_sync import MEMBER_SYNC_DEFERRED
    from tests.test_account_pin_device_sites import _cache

    _cache(sqlite_db, _panel_users())
    _record_schemes(sqlite_db, "MEMBERSHIP", "ACCOUNT")
    sdk = _sdk()
    engine = _engine()

    ok = engine.sync_member_on_connected_sdk(
        sdk=sdk, device=_pullsdk_device(pinScheme="MEMBERSHIP"), member_id=5)

    assert ok is False and engine._last_member_sync_outcome == MEMBER_SYNC_DEFERRED
    assert _written_pins(sdk) == [] and _deleted_pins(sdk) == []


def test_the_ultra_worker_panel_pass_from_an_old_copy_fails_and_writes_nothing(sqlite_db, monkeypatch):
    import app.core.ultra_engine as ue
    from types import SimpleNamespace

    _record_schemes(sqlite_db, "MEMBERSHIP", "ACCOUNT")
    raw = _sdk()
    w = ue.UltraDeviceWorker(device=_pullsdk_device(pinScheme="MEMBERSHIP"), settings={},
                             popup_q=queue.Queue(), history_q=queue.Queue(),
                             stop_event=threading.Event())
    w._connected = True
    w._sdk = SimpleNamespace(owns_event_source=False, _sdk=raw)
    w._on_full_sync_finished = MagicMock()
    monkeypatch.setattr(ue, "load_sync_cache",
                        lambda: SimpleNamespace(users=_panel_users(), devices=[]))

    w.request_full_sync(reason="timer", fingerprint_hash="h", revoked_ids={6})
    assert w._drain_full_sync_commands(limit=1) == 1

    assert _written_pins(raw) == [] and _deleted_pins(raw) == []
    finished = w._on_full_sync_finished.call_args.kwargs
    assert finished["ok"] is False and finished["fingerprint_hash"] is None
    assert finished["revoked_ids"] == {6}, "the revocation stays pending for the next pass"


# ================================================================== the sync tick
from tests.test_p3b1_app_wiring import _Api, _NOTHING, _run_worker, fake_tel, wired  # noqa: E402,F401


def test_a_sync_that_saved_a_device_section_refreshes_the_workers_before_anything_else(wired, monkeypatch):
    import app.ui.app as app_module

    ev = wired.events
    devices_changed = dict(_NOTHING, refreshDevices=True, devices=[])
    wired.app._api = lambda: _Api([devices_changed], ev)
    wired.app._maybe_apply_date_flips = lambda source: None
    wired.app._apply_date_flips = lambda source, **_kw: ev.append(("flip", source))
    wired.app._refresh_running_ultra_devices = (
        lambda *, reason: ev.append(("refresh", reason)) or True)
    wired.app._device_attendance_engine.run_blocking = lambda **_kw: ev.append(("attendance",))
    monkeypatch.setattr(app_module, "save_sync_cache_delta",
                        lambda data, refresh: ev.append(("save",)) or {})
    monkeypatch.setattr(app_module, "device_membership_scope_changed", lambda *_a: False)

    _run_worker(wired)

    # refreshed before the flip too (R1-F6): a flip that moves rows queues a pass itself
    assert ev[:4] == [("fetch",), ("save",), ("refresh", "sync-save"), ("flip", "save")], ev
    assert ev.index(("refresh", "sync-save")) < ev.index(("attendance",))


def test_a_sync_without_a_device_section_does_not_refresh_the_workers(wired, monkeypatch):
    import app.ui.app as app_module

    ev = wired.events
    wired.app._api = lambda: _Api([_NOTHING], ev)
    wired.app._maybe_apply_date_flips = lambda source: None
    wired.app._apply_date_flips = lambda source, **_kw: None
    wired.app._refresh_running_ultra_devices = (
        lambda *, reason: ev.append(("refresh", reason)) or True)
    monkeypatch.setattr(app_module, "save_sync_cache_delta", lambda data, refresh: {})

    _run_worker(wired)

    assert ("refresh", "sync-save") not in ev


# ================================================================== the refresh helper
def test_a_failed_refresh_still_dispatches_and_asks_for_a_full_reconcile(monkeypatch):
    """The passes refuse pins of a scheme the database no longer records, so a failed refresh
    does not hold the bundle's dispatch (its revocations included) back; the full reconcile
    refreshes the copies."""
    import app.ui.app as app_module
    from types import SimpleNamespace

    monkeypatch.setattr("app.core.db.apply_fast_patch_bundle",
                        lambda bundle: {"applied": 1, "skipped": 0, "ignored": None})
    monkeypatch.setattr("app.core.db.invalidate_sync_cache", MagicMock())
    monkeypatch.setattr("app.core.db.refresh_sync_cache_async", MagicMock())
    app = SimpleNamespace(
        logger=MagicMock(), reset_runtime_fast_patch_caches=MagicMock(),
        _apply_date_flips=MagicMock(), _defer_ultra_reconnects=MagicMock(),
        _request_running_ultra_sync=MagicMock(return_value=True),
        _refresh_running_ultra_devices=MagicMock(return_value=False),
        request_sync_now=MagicMock(),
    )

    app_module.MainApp.apply_fast_patch_bundle(app, _switch_bundle("ACCOUNT"))

    app._request_running_ultra_sync.assert_called_once()
    app.request_sync_now.assert_called_once()
    assert app.request_sync_now.call_args.kwargs["trigger_source"] == "FAST_PATCH_BUNDLE"


def test_the_refresh_reads_nothing_when_no_ultra_engine_runs(monkeypatch):
    import app.ui.app as app_module

    app = object.__new__(app_module.MainApp)
    app.logger = logging.getLogger("test.scheme_refresh")
    app._ultra_lock = threading.Lock()
    app._ultra_engine = MagicMock(running=False)
    monkeypatch.setattr("app.core.db.list_sync_devices_payload",
                        MagicMock(side_effect=AssertionError("read while no engine runs")))

    assert app._refresh_running_ultra_devices(reason="test") is True
    app._ultra_engine.refresh_devices.assert_not_called()


def test_the_refresh_reports_an_unreadable_device_table(monkeypatch):
    import app.ui.app as app_module

    app = object.__new__(app_module.MainApp)
    app.logger = logging.getLogger("test.scheme_refresh")
    app._ultra_lock = threading.Lock()
    app._ultra_engine = MagicMock(running=True)
    monkeypatch.setattr("app.core.db.list_sync_devices_payload",
                        MagicMock(side_effect=RuntimeError("disk I/O error")))

    assert app._refresh_running_ultra_devices(reason="test") is False
    app._ultra_engine.refresh_devices.assert_not_called()


# ================================================================== review round 1
def test_r1_the_refresh_gives_the_scheduler_no_device_without_a_worker(world):
    """R1-F2: refresh_devices also replaces the ULTRA scheduler's device list, and the scheduler
    pushes a device WITHOUT a worker over its own session (the no-worker fallback). A fast patch
    that adds an ULTRA device must not hand it to the scheduler before the engine restarts."""
    app, engine = world["app"], world["engine"]
    added = dict(_device("MEMBERSHIP"), id=10, name="Sortie", ipAddress="192.168.9.11")
    bundle = {"bundleId": "b-add", "requiresReconcile": False, "items": [{
        "kind": "ENTITY_UPSERT", "entityType": "GYM_DEVICE", "entityId": 10,
        "revision": "2026-09-26T21:00:00", "payload": {"device": added},
        "impact": {"affectedMemberIds": [], "affectedDeviceIds": [10]}}]}

    app.apply_fast_patch_bundle(bundle)

    assert [d.get("id") for d in engine._sync_scheduler._devices] == [_DEVICE_ID]


def test_r1_a_worker_whose_lease_is_not_drive_still_gets_its_new_device_row(world):
    """R1-F5: the lease filter decides who DRIVES, not whose device copy is current. A copy left
    stale while the lease was away made the pass guard stop every pass once it came back."""
    from app.core.v2 import lease_gate as lg

    app, worker = world["app"], world["worker"]
    lg.install(lg.snapshot_from_assignment({
        "gymUsesAssignments": True, "role": "DRIVER", "readerOf": [], "release": [],
        "drive": [{"gymDeviceId": _DEVICE_ID, "generation": 1, "state": "WAIT_FOR_RELEASE",
                   "handoverForced": False}]}, source="server"))
    try:
        app.apply_fast_patch_bundle(_switch_bundle("ACCOUNT"))
        assert worker._device.get("pinScheme") == "ACCOUNT"
        # R2-4: the scheduler's list is left alone while not every worker is driven -- it used
        # to lose the device here, and nothing put it back when the lease returned.
        assert [d.get("id") for d in world["engine"]._sync_scheduler._devices] == [_DEVICE_ID]
    finally:
        lg.reset_for_tests()


def test_r1_the_fast_patch_refreshes_the_workers_before_its_date_flip(world):
    """R1-F6: the date flip after a fast patch may queue a pass itself; the copies are fresh
    before it runs."""
    app = world["app"]
    order = []
    real_refresh = app._refresh_running_ultra_devices
    app._refresh_running_ultra_devices = lambda **kw: order.append("refresh") or real_refresh(**kw)
    app._apply_date_flips = lambda source, **_kw: order.append(("flip", source))

    app.apply_fast_patch_bundle(_switch_bundle("ACCOUNT"))

    assert order[:2] == ["refresh", ("flip", "fast-patch")], order


def test_r1_a_switch_during_a_panel_pass_removes_nothing_either(sqlite_db):
    """R1-F3: the stale-pin delete and the FULL_REPLACE clear ran before the batch re-check."""
    from app.core.device_sync import PinSchemeSwitchedError

    _record_schemes(sqlite_db, "MEMBERSHIP")
    sqlite_db.save_device_sync_state(device_id=1, pin="99", desired_hash="h", ok=True, error=None)
    sdk = _sdk(["99"])
    rows = sdk.get_device_data_rows.return_value

    def _read_then_switch(*_a, **_kw):
        _record_schemes(sqlite_db, "ACCOUNT")
        return rows

    sdk.get_device_data_rows.side_effect = _read_then_switch

    with pytest.raises(PinSchemeSwitchedError):
        _run_panel(_panel_users(), _pullsdk_device(pinScheme="MEMBERSHIP"), sdk)

    assert _deleted_pins(sdk) == [], f"a removal ran after the switch: {_deleted_pins(sdk)}"
    assert _written_pins(sdk) == []

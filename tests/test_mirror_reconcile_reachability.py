"""The MIRROR reconcile must be reachable from a trigger production can actually emit.

WHY THIS FILE EXISTS
--------------------
``_maybe_mirror_reconcile`` gated on
``reason in ("user-sync", "daily-forced-sync", "hard-reset")``. But ``reason`` is a
*trigger_source* token -- ``app/ui/app.py`` passes ``trigger_context.trigger_source``,
whose entire vocabulary is ``API_MANUAL``, ``CHANGE_DETECTOR``, ``FAST_PATCH_BUNDLE``,
``FINGERPRINT_ENROLLED``, ``MANUAL``, ``MANUAL_EVALUATE``, ``STARTUP``, ``SYNC_NOW_API``,
``TIMER`` (plus the scheduler's own ``startup``/``timer`` and the worker's
``revoke-*``). No producer has ever emitted any of the three gate literals: every
occurrence in the repo's history is a TEST that hand-passed the literal straight into
the gate, which is exactly why the dead gate survived review.

Those three strings were reaching for a real distinction that lives one field over, in
``trigger_hint`` -- and not even verbatim: the genuine tokens are ``user-sync`` and
``daily-auto-sync`` (never ``daily-forced-sync``), and a hard reset is
``run_type="HARD_RESET"`` / ``hint["hardReset"]`` rather than a reason at all.
``sync_observability.is_explicit_user_sync`` already folds all three into one
predicate and already gates ``_should_push`` in manual-sync mode, so the engine now
carries that ONE boolean instead of guessing from a string.

The failure was silent: ``MIRROR_SKIP_REASON`` telemetry, ``mirror_reconcile_record_plan``
never called, ``GET /devices/{id}/mirror-plan`` stuck at ``lastPlanCount: null``, and the
dashboard's "Activer les suppressions" button permanently disabled (DevicesPage.tsx
disables it on ``count == null``).

These tests drive the SHIPPED plumbing at every hop -- app layer, engine, scheduler,
worker -- and never hand a literal straight to the gate.
"""

from __future__ import annotations

import threading
from collections import deque
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

import app.core.ultra_engine as ue
from app.core.sync_observability import SyncTriggerContext, is_explicit_user_sync


@pytest.fixture(autouse=True)
def _temp_db(tmp_path, monkeypatch):
    """Documented `_DB_PATH` override: a full sync writes per-pin state, and these
    tests must never touch the developer's installed database (leftover
    ownership_confirmed rows there make OTHER suites' revoke passes fire)."""
    import app.core.db as db_module
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "mirror_gate.db"),
                        raising=False)


# --------------------------------------------------------------------------- #
# Hop 1 — the app layer derives the flag and hands it to the engine
# --------------------------------------------------------------------------- #

def _app_with_engine():
    request_sync_now = MagicMock(return_value=True)
    app = SimpleNamespace(
        _ultra_lock=threading.Lock(),
        _ultra_engine=SimpleNamespace(running=True, request_sync_now=request_sync_now),
        logger=MagicMock(),
    )
    return app, request_sync_now


@pytest.mark.parametrize(
    "context",
    [
        SyncTriggerContext(run_type="TRIGGERED", trigger_source="SYNC_NOW_API",
                           trigger_hint={"reason": "user-sync"}),
        SyncTriggerContext(run_type="TRIGGERED", trigger_source="SYNC_NOW_API",
                           trigger_hint={"reason": "daily-auto-sync"}),
        SyncTriggerContext(run_type="HARD_RESET", trigger_source="SYNC_NOW_API",
                           trigger_hint={"hardReset": True}),
    ],
)
def test_an_explicit_sync_reaches_the_engine_marked_as_a_full_reconcile(context):
    """The three triggers the dead literals were reaching for, via the real predicate."""
    import app.ui.app as app_module

    app, request_sync_now = _app_with_engine()
    assert is_explicit_user_sync(context) is True, "precondition: this IS an explicit sync"

    app_module.MainApp._request_running_ultra_sync(
        app,
        refresh={"members": True, "devices": False},
        changed_ids=None,
        reason=context.trigger_source,
        full_reconcile=is_explicit_user_sync(context),
    )

    assert request_sync_now.call_args.kwargs["full_reconcile"] is True


@pytest.mark.parametrize(
    "context",
    [
        SyncTriggerContext(run_type="PERIODIC", trigger_source="TIMER", trigger_hint=None),
        SyncTriggerContext(run_type="PERIODIC", trigger_source="STARTUP", trigger_hint=None),
        SyncTriggerContext(run_type="TRIGGERED", trigger_source="CHANGE_DETECTOR",
                           trigger_hint=None),
        # the dashboard's per-edit auto-dispatch: SYNC_NOW_API WITHOUT the marker
        SyncTriggerContext(run_type="TRIGGERED", trigger_source="SYNC_NOW_API",
                           trigger_hint={"entityType": "ACTIVE_MEMBERSHIP",
                                         "operation": "UPDATE"}),
    ],
)
def test_an_automatic_sync_is_never_marked_as_a_full_reconcile(context):
    """A daytime/spurious sync must not authorise deletes off a live turnstile."""
    import app.ui.app as app_module

    app, request_sync_now = _app_with_engine()
    assert is_explicit_user_sync(context) is False, "precondition: this is automatic"

    app_module.MainApp._request_running_ultra_sync(
        app,
        refresh={"members": True, "devices": False},
        changed_ids=None,
        reason=context.trigger_source,
        full_reconcile=is_explicit_user_sync(context),
    )

    assert request_sync_now.call_args.kwargs["full_reconcile"] is False


def test_the_app_layer_defaults_to_not_a_full_reconcile():
    """Any call site that forgets the flag must fail CLOSED, never open."""
    import app.ui.app as app_module

    app, request_sync_now = _app_with_engine()
    app_module.MainApp._request_running_ultra_sync(
        app,
        refresh={"members": True, "devices": False},
        changed_ids=None,
        reason="FAST_PATCH_BUNDLE",
    )
    assert request_sync_now.call_args.kwargs["full_reconcile"] is False


# --------------------------------------------------------------------------- #
# Hop 2 — the scheduler's pending-request merge/drain
# --------------------------------------------------------------------------- #

def _scheduler():
    s = ue.UltraSyncScheduler.__new__(ue.UltraSyncScheduler)
    s._logger = MagicMock()
    s._pending_sync_lock = threading.Lock()
    s._pending_sync_requested = False
    s._pending_full_sync = False
    s._pending_changed_ids = set()
    s._pending_revoked_ids = set()
    s._pending_all_devices = False
    s._pending_device_ids = set()
    s._pending_reason = "manual"
    s._pending_full_reconcile = False
    s._wake_sync = threading.Event()
    return s


def test_the_scheduler_carries_the_flag_through_merge_and_drain():
    s = _scheduler()
    s.request_sync_now(changed_ids=None, reason="sync_now_api", full_reconcile=True)

    _changed, _revoked, _devices, _reason, full_reconcile = s._drain_pending_sync_request()
    assert full_reconcile is True


def test_an_automatic_sync_merged_into_a_pending_explicit_one_stays_a_full_reconcile():
    """Coalescing must never DOWNGRADE an operator's reconcile into a timer push."""
    s = _scheduler()
    s.request_sync_now(changed_ids=None, reason="sync_now_api", full_reconcile=True)
    s.request_sync_now(changed_ids=None, reason="timer", full_reconcile=False)

    *_rest, full_reconcile = s._drain_pending_sync_request()
    assert full_reconcile is True


def test_an_explicit_sync_merged_into_a_pending_automatic_one_upgrades_it():
    s = _scheduler()
    s.request_sync_now(changed_ids=None, reason="timer", full_reconcile=False)
    s.request_sync_now(changed_ids=None, reason="sync_now_api", full_reconcile=True)

    *_rest, full_reconcile = s._drain_pending_sync_request()
    assert full_reconcile is True


def test_the_drained_flag_resets_so_the_next_timer_push_is_not_a_reconcile():
    s = _scheduler()
    s.request_sync_now(changed_ids=None, reason="sync_now_api", full_reconcile=True)
    s._drain_pending_sync_request()

    s.request_sync_now(changed_ids=None, reason="timer", full_reconcile=False)
    *_rest, full_reconcile = s._drain_pending_sync_request()
    assert full_reconcile is False


def test_a_request_preserved_for_a_dead_worker_keeps_the_flag():
    """A worker that was dead when the operator clicked must still reconcile on retry."""
    s = _scheduler()
    s._preserve_sync_request_for_retry(
        changed_ids=None, revoked_ids=set(), device_ids={9},
        reason="sync_now_api", full_reconcile=True,
    )
    *_rest, full_reconcile = s._drain_pending_sync_request()
    assert full_reconcile is True


# --------------------------------------------------------------------------- #
# Hop 3 — scheduler -> live worker
# --------------------------------------------------------------------------- #

def test_the_scheduler_hands_the_flag_to_the_live_worker():
    worker = SimpleNamespace(request_full_sync=MagicMock(return_value=True))
    ue._worker_full_sync_accepted_or_pending(
        worker, reason="sync_now_api", fingerprint_hash="h1", full_reconcile=True,
    )
    assert worker.request_full_sync.call_args.kwargs["full_reconcile"] is True


def test_the_scheduler_does_not_invent_a_reconcile_for_a_timer_push():
    worker = SimpleNamespace(request_full_sync=MagicMock(return_value=True))
    ue._worker_full_sync_accepted_or_pending(
        worker, reason="timer", fingerprint_hash="h1", full_reconcile=False,
    )
    assert worker.request_full_sync.call_args.kwargs.get("full_reconcile", False) is False


# --------------------------------------------------------------------------- #
# Hop 4 — worker queue -> the standalone roster path -> the reconcile itself
# --------------------------------------------------------------------------- #

class _RosterDriver:
    """Minimal ZK_STANDALONE surface for a full-sync drain."""
    owns_event_source = True

    def __init__(self):
        self.push_calls: List[tuple] = []

    def push_roster(self, users, templates_by_pin=None, *, remove_fingers_by_pin=None,
                    bracket_enable_device=False, **_kw):
        self.push_calls.append((list(users), bool(bracket_enable_device)))
        return {"ok": True, "pushed": len(users), "failed": 0, "templates_failed": 0,
                "skipped_pin": 0, "chunks_wedged": 0, "errors": [], "failed_pins": []}


class _FakeState:
    """In-memory device_sync_state, so these tests never read the installed DB."""

    def __init__(self):
        self.rows: Dict[str, tuple] = {}

    def list(self, *, device_id):
        return dict(self.rows)

    def list_owned(self, *, device_id):
        return {pin for pin, (_h, ok) in self.rows.items() if ok}

    def save_batch(self, *, device_id, rows):
        for row in list(rows):
            pin, h, ok = row[0], row[1], row[2]
            prev = self.rows.get(pin, ("", False))
            self.rows[pin] = ((h if ok else prev[0]), bool(ok))
        return len(list(rows))

    def prune(self, *, device_id, keep_pins):
        keep = {str(k) for k in keep_pins}
        for pin in [p for p in self.rows if p not in keep]:
            self.rows.pop(pin)
        return 0

    def delete(self, *, device_id, pin):
        self.rows.pop(str(pin), None)


def _standalone_worker(monkeypatch, *, users, policy="PRESERVE"):
    w = ue.UltraDeviceWorker.__new__(ue.UltraDeviceWorker)
    w._device = {"id": 9, "name": "Entree", "rosterPushingPolicy": policy}
    w._device_id = 9
    w._device_name = "Entree"
    w._settings = {"fingerprint_enabled": False}
    w._cfg = None
    w._prefix = "[ULTRA:9]"
    w._tel_wid = "ULTRA:9"
    w._sdk = _RosterDriver()
    w._connected = True
    w._full_sync_lock = threading.Lock()
    w._pending_full_sync_request = None
    w._member_sync_lock = threading.Lock()
    w._pending_member_syncs = deque()
    w._pending_member_sync_ids = set()
    w._pending_member_revoke_ids = set()
    w._active_member_revoke_ids = set()
    w._confirmed_member_revoke_ids = set()
    w._full_sync_revocation_phase = {}
    w._wake_evt = threading.Event()
    w._active_sync_lock = threading.Lock()
    w._active_sync_engine = None
    w._recent_member_push = {}
    w._on_full_sync_started = MagicMock()
    w._on_full_sync_finished = MagicMock()

    cache = SimpleNamespace(users=list(users))
    monkeypatch.setattr(ue, "load_sync_cache", lambda: cache)
    monkeypatch.setattr(ue, "insert_push_batch", MagicMock(return_value=1))
    monkeypatch.setattr(ue, "update_push_batch", lambda **kw: None)

    import app.core.db as dbmod
    st = _FakeState()
    monkeypatch.setattr(dbmod, "list_device_sync_hashes_and_status", st.list)
    monkeypatch.setattr(dbmod, "list_confirmed_device_sync_pins", st.list_owned)
    monkeypatch.setattr(dbmod, "save_device_sync_state_batch", st.save_batch)
    monkeypatch.setattr(dbmod, "prune_device_sync_state", st.prune)
    monkeypatch.setattr(dbmod, "delete_device_sync_state", st.delete)
    monkeypatch.setattr(dbmod, "clear_device_revocation_state", st.delete, raising=False)
    monkeypatch.setattr(dbmod, "list_device_pushed_fingers", lambda **kw: {}, raising=False)

    import app.core.device_sync as ds
    monkeypatch.setattr(ds.DeviceSyncEngine, "_build_local_fp_index_for_pins",
                        lambda self, *, pins, fingerprint_enabled: {}, raising=True)
    return w


def _users(n: int) -> List[Dict[str, Any]]:
    return [{"activeMembershipId": 100 + i, "mainAccountId": 100 + i,
             "firstName": f"M{i}", "lastName": "X", "firstCardId": str(10 + i),
             "membershipStatus": "ACTIVE"} for i in range(n)]


def test_an_explicit_reconcile_reaches_the_mirror_gate(monkeypatch):
    """THE regression: the operator's click must actually arrive at the reconcile."""
    w = _standalone_worker(monkeypatch, users=_users(4))
    seen: Dict[str, Any] = {}
    monkeypatch.setattr(w, "_maybe_mirror_reconcile",
                        lambda *, full_reconcile, roster_users: seen.update(
                            full_reconcile=full_reconcile, n=len(roster_users)))

    w.request_full_sync(reason="sync_now_api", fingerprint_hash="h1", full_reconcile=True)
    assert w._drain_full_sync_commands(limit=1) == 1

    assert seen["full_reconcile"] is True
    assert seen["n"] == 4


def test_a_timer_sync_reaches_the_gate_but_not_marked_as_a_reconcile(monkeypatch):
    w = _standalone_worker(monkeypatch, users=_users(4))
    seen: Dict[str, Any] = {}
    monkeypatch.setattr(w, "_maybe_mirror_reconcile",
                        lambda *, full_reconcile, roster_users: seen.update(
                            full_reconcile=full_reconcile))

    w.request_full_sync(reason="timer", fingerprint_hash="h1")
    assert w._drain_full_sync_commands(limit=1) == 1

    assert seen["full_reconcile"] is False


def test_a_queued_explicit_reconcile_is_not_downgraded_by_a_later_timer_request(monkeypatch):
    """Two requests coalesce into one pending command; the reconcile must survive."""
    w = _standalone_worker(monkeypatch, users=_users(4))
    seen: Dict[str, Any] = {}
    monkeypatch.setattr(w, "_maybe_mirror_reconcile",
                        lambda *, full_reconcile, roster_users: seen.update(
                            full_reconcile=full_reconcile))

    w.request_full_sync(reason="sync_now_api", fingerprint_hash="h1", full_reconcile=True)
    w.request_full_sync(reason="timer", fingerprint_hash="h1", require_full_refresh=True)
    assert w._drain_full_sync_commands(limit=1) == 1

    assert seen["full_reconcile"] is True


def test_a_disconnected_worker_requeues_the_reconcile_without_downgrading_it(monkeypatch):
    """The device was unreachable; the operator's intent must survive the requeue."""
    w = _standalone_worker(monkeypatch, users=_users(4))
    w._connected = False
    w._sdk = None

    w.request_full_sync(reason="sync_now_api", fingerprint_hash="h1", full_reconcile=True)
    w._drain_full_sync_commands(limit=1)

    assert w._pending_full_sync_request is not None, "an undelivered reconcile must requeue"
    assert w._pending_full_sync_request["full_reconcile"] is True


# --------------------------------------------------------------------------- #
# The gate itself — driven by the flag, never by a reason string
# --------------------------------------------------------------------------- #

class _ListingDriver:
    def __init__(self, device_pins: List[str]):
        self._device_pins = [str(p) for p in device_pins]
        self.list_calls = 0
        self.deleted: List[str] | None = None

    def list_device_users(self, **_kw):
        self.list_calls += 1
        return {"ok": True, "users": [{"pin": p} for p in self._device_pins]}

    def delete_users(self, pins, **_kw):
        self.deleted = list(pins)
        return {"ok": True, "deleted": len(pins), "failed": 0, "errors": []}


def _gate_worker(*, policy="MIRROR", device_pins=None):
    w = ue.UltraDeviceWorker.__new__(ue.UltraDeviceWorker)
    w._device = {"id": 9, "rosterPushingPolicy": policy, "deviceCapabilities": None}
    w._sdk = _ListingDriver(device_pins or [])
    w._tel_wid = "TEST:9"
    w._device_id = 9
    w._prefix = "[TEST:9]"
    w._recent_member_push = {}
    return w


def test_an_ordinary_sync_never_reconciles(monkeypatch):
    w = _gate_worker(device_pins=["40000"])
    w._maybe_mirror_reconcile(full_reconcile=False,
                              roster_users=[{"pin": str(p)} for p in range(100, 120)])
    assert w._sdk.list_calls == 0, "must bail BEFORE enumerating the terminal"
    assert w._sdk.deleted is None


def test_a_full_reconcile_on_a_preserve_device_is_still_a_noop(monkeypatch):
    """Gym 45's reality: both turnstiles are ZK_STANDALONE + PRESERVE.

    The policy gate precedes every other gate, so fixing the trigger does NOT make
    MIRROR run there -- that needs the backend to change roster_pushing_policy.
    """
    w = _gate_worker(policy="PRESERVE", device_pins=["40000"])
    w._maybe_mirror_reconcile(full_reconcile=True,
                              roster_users=[{"pin": str(p)} for p in range(100, 120)])
    assert w._sdk.list_calls == 0
    assert w._sdk.deleted is None


def test_a_full_reconcile_records_a_dry_run_plan_so_the_dashboard_can_arm(monkeypatch):
    """The whole operator-facing chain: plan recorded -> /mirror-plan -> arm button."""
    recorded: Dict[str, Any] = {}
    monkeypatch.setattr("app.core.db.mirror_reconcile_is_armed", lambda **kw: False)
    monkeypatch.setattr("app.core.db.mirror_reconcile_record_plan",
                        lambda **kw: recorded.update(kw))
    monkeypatch.setattr("app.core.db.delete_device_mirror_pin", lambda **kw: None)

    w = _gate_worker(device_pins=["40000"])
    w._maybe_mirror_reconcile(full_reconcile=True,
                              roster_users=[{"pin": str(p)} for p in range(100, 120)])

    assert recorded["count"] == 1, "the dry run must record a plan, not stay null"
    assert recorded["sample"] == "40000"
    assert w._sdk.deleted is None, "dry run deletes NOTHING"


def test_the_dead_reason_vocabulary_is_gone():
    """Guard against a well-meaning revert to a string the producers never emit."""
    assert not hasattr(ue, "_MIRROR_RECONCILE_REASONS")


# --------------------------------------------------------------------------- #
# The deliberately UNCHANGED half — EnableDevice bracketing stays off
# --------------------------------------------------------------------------- #

def test_a_full_reconcile_still_does_not_enabledevice_lock_the_terminal(monkeypatch):
    """Deliberate: `bracket_enable_device` stays False even for an explicit reconcile.

    ``push_roster`` collapses the roster into ONE command when bracketing
    (``chunks = [users]``), which bypasses the per-chunk timeout and the wedge
    recovery added because a single-command 950-member push meant "the gym never got
    more than the first 10 members". It also holds ``EnableDevice(False)`` across the
    whole push, and the terminal is the gym's sole verifier. Turning bracketing on is
    a separate, hardware-gated decision -- see guide §3.2c.
    """
    w = _standalone_worker(monkeypatch, users=_users(4))
    monkeypatch.setattr(w, "_maybe_mirror_reconcile",
                        lambda *, full_reconcile, roster_users: None)

    w.request_full_sync(reason="sync_now_api", fingerprint_hash="h1", full_reconcile=True)
    assert w._drain_full_sync_commands(limit=1) == 1

    assert w._sdk.push_calls, "the roster was pushed"
    assert all(bracketed is False for _users_, bracketed in w._sdk.push_calls)


# --------------------------------------------------------------------------- #
# The two skips that would have made the repaired flag dead again
# --------------------------------------------------------------------------- #

def test_an_explicit_reconcile_survives_an_unchanged_roster_fingerprint(monkeypatch):
    """The reconcile's whole point is stale rows the ROSTER cannot see.

    `_sync_all` skips a device whose desired-roster fingerprint is unchanged. That is
    right for a timer tick, but an operator clicks "Sync data" precisely because the
    TERMINAL holds something the roster no longer does -- and that never moves the
    roster hash. Skipping there would leave the repaired flag just as unreachable.
    """
    worker = SimpleNamespace(
        request_member_sync=MagicMock(return_value=True),
        request_full_sync=MagicMock(return_value=True),
    )
    scheduler = ue.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())
    scheduler.set_workers({5: worker})
    scheduler._devices = [{"id": 5, "name": "Door 1", "accessDataMode": "ULTRA",
                           "_settings": {}}]
    scheduler._last_hash = {5: "unchanged-hash"}

    class _FakeDeviceSyncEngine:
        def __init__(self, cfg, logger):
            pass

        def build_device_sync_fingerprint(self, *, device, users, local_fp_index=None,
                                          detail_out=None):
            return ("unchanged-hash", 1)

    monkeypatch.setattr(ue, "load_sync_cache",
                        lambda: SimpleNamespace(users=[{"activeMembershipId": 11}], devices=[]))
    monkeypatch.setattr("app.core.device_sync.DeviceSyncEngine", _FakeDeviceSyncEngine)
    monkeypatch.setattr(scheduler, "_sync_device", MagicMock(return_value=True))

    scheduler._sync_all(changed_ids=None, reason="sync_now_api", full_reconcile=True)

    assert worker.request_full_sync.called, "an explicit reconcile must not be hash-skipped"
    assert worker.request_full_sync.call_args.kwargs["full_reconcile"] is True


def test_an_unchanged_roster_still_skips_an_ordinary_timer_push(monkeypatch):
    """The hash skip stays intact for everything that is not an explicit reconcile."""
    worker = SimpleNamespace(
        request_member_sync=MagicMock(return_value=True),
        request_full_sync=MagicMock(return_value=True),
    )
    scheduler = ue.UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())
    scheduler.set_workers({5: worker})
    scheduler._devices = [{"id": 5, "name": "Door 1", "accessDataMode": "ULTRA",
                           "_settings": {}}]
    scheduler._last_hash = {5: "unchanged-hash"}

    class _FakeDeviceSyncEngine:
        def __init__(self, cfg, logger):
            pass

        def build_device_sync_fingerprint(self, *, device, users, local_fp_index=None,
                                          detail_out=None):
            return ("unchanged-hash", 1)

    monkeypatch.setattr(ue, "load_sync_cache",
                        lambda: SimpleNamespace(users=[{"activeMembershipId": 11}], devices=[]))
    monkeypatch.setattr("app.core.device_sync.DeviceSyncEngine", _FakeDeviceSyncEngine)
    monkeypatch.setattr(scheduler, "_sync_device", MagicMock(return_value=True))

    scheduler._sync_all(changed_ids=None, reason="timer", full_reconcile=False)

    worker.request_full_sync.assert_not_called()


def test_an_explicit_reconcile_with_delta_changed_ids_still_routes_a_full_sync():
    """A "Sync data" click whose backend answer was a DELTA must still reconcile.

    UltraEngine.request_sync_now routes targeted member syncs whenever changed_ids is
    not None. A delta-mode explicit sync would then never request a full sync, and the
    reconcile would be unreachable again -- for the commonest shape of the click.
    """
    worker = SimpleNamespace(
        request_member_sync=MagicMock(return_value=True),
        has_pending_member_sync=MagicMock(return_value=False),
        request_full_sync=MagicMock(return_value=True),
        is_alive=MagicMock(return_value=True),
    )
    engine = ue.UltraEngine.__new__(ue.UltraEngine)
    engine._running = True
    engine._logger = MagicMock()
    engine._workers = {5: worker}
    engine._sync_scheduler = SimpleNamespace(_devices=[], request_sync_now=MagicMock())

    engine.request_sync_now(changed_ids={11}, device_ids={5},
                            reason="sync_now_api", full_reconcile=True)

    assert worker.request_full_sync.called, "an explicit reconcile needs a FULL sync"
    assert worker.request_full_sync.call_args.kwargs["full_reconcile"] is True


# --------------------------------------------------------------------------- #
# The third MIRROR blocker — survives this fix, and settles the cutover question
# --------------------------------------------------------------------------- #

def test_a_cutover_sized_diff_aborts_mirror_before_any_plan_is_recorded(monkeypatch):
    """Gate 8 (the 25 % floor) precedes gate 9 (record the dry-run plan).

    So even on a hypothetically-MIRROR gym 45, a pin-scheme cutover -- where EVERY
    device pin is absent from the new roster -- aborts on MIRROR_ABORT_FLOOR and writes
    no plan. `/mirror-plan` keeps returning lastPlanCount: null and the dashboard's arm
    button stays disabled, which is the very symptom the trigger repair fixes for
    ORDINARY churn. Mirror's floor is purely fractional -- no absolute allowance like
    _REVOKE_ABSOLUTE_FLOOR -- so a full re-key is refused at any roster size.

    This is why "manual wipe" is settled rather than "settled unless you flip the
    policy". See guide §3.2c.
    """
    planned: List[Dict[str, Any]] = []
    monkeypatch.setattr("app.core.db.mirror_reconcile_is_armed", lambda **kw: False)
    monkeypatch.setattr("app.core.db.mirror_reconcile_record_plan",
                        lambda **kw: planned.append(kw))
    monkeypatch.setattr("app.core.db.delete_device_mirror_pin", lambda **kw: None)

    old_scheme_pins = [str(p) for p in range(20000, 20900)]      # what the terminal holds
    new_scheme_pins = [str(p) for p in range(30000, 30900)]      # what the roster now says
    w = _gate_worker(device_pins=old_scheme_pins)

    w._maybe_mirror_reconcile(full_reconcile=True,
                              roster_users=[{"pin": p} for p in new_scheme_pins])

    assert planned == [], "the floor must abort BEFORE a plan is recorded"
    assert w._sdk.deleted is None
    assert w._sdk.list_calls == 1, "it did enumerate -- it aborted on the diff, not earlier"


def test_ordinary_churn_still_records_a_plan_on_a_mirror_device(monkeypatch):
    """The contrast: a handful of departed members is under the floor and DOES plan."""
    planned: List[Dict[str, Any]] = []
    monkeypatch.setattr("app.core.db.mirror_reconcile_is_armed", lambda **kw: False)
    monkeypatch.setattr("app.core.db.mirror_reconcile_record_plan",
                        lambda **kw: planned.append(kw))
    monkeypatch.setattr("app.core.db.delete_device_mirror_pin", lambda **kw: None)

    roster = [str(p) for p in range(30000, 30100)]
    w = _gate_worker(device_pins=roster + ["20001", "20002"])

    w._maybe_mirror_reconcile(full_reconcile=True,
                              roster_users=[{"pin": p} for p in roster])

    assert len(planned) == 1 and planned[0]["count"] == 2
    assert w._sdk.deleted is None, "still a dry run until armed"


# --------------------------------------------------------------------------- #
# The revoke-only short-circuit must not swallow an explicit reconcile
# --------------------------------------------------------------------------- #

def test_a_reconcile_riding_an_already_owned_revocation_is_still_queued(monkeypatch):
    """request_full_sync returns early for a revoke-only request whose ids are already
    owned by a targeted command. That is right for the revocation -- someone else will
    deliver it -- but the RECONCILE half has no other carrier, so it must still queue."""
    w = _standalone_worker(monkeypatch, users=_users(4))
    w._active_member_revoke_ids = {7}          # already owned by a live targeted revoke

    assert w.request_full_sync(reason="sync_now_api", revoked_ids={7},
                               full_reconcile=True) is True

    assert w._pending_full_sync_request is not None, "the reconcile must not be dropped"
    assert w._pending_full_sync_request["full_reconcile"] is True
    # the revocation stays owned by the targeted command, not re-queued here
    assert w._pending_full_sync_request["revoked_ids"] == set()
    assert 7 in w._pending_full_sync_request["excluded_ids"]


def test_a_revoke_only_request_without_a_reconcile_still_short_circuits(monkeypatch):
    """The guard must be narrow: no reconcile asked for, no new full sync invented."""
    w = _standalone_worker(monkeypatch, users=_users(4))
    w._active_member_revoke_ids = {7}

    assert w.request_full_sync(reason="fast_patch_bundle", revoked_ids={7}) is True
    assert w._pending_full_sync_request is None

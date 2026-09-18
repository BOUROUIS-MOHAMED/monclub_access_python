"""P3a-2 item 2: removals first, and retried fast.

Before P3a-2 the MB2000 full sync pushed first and ran its revoke pass only after a
SUCCESSFUL push: one unrelated member's refused finger (sync_ok=False) meant no
departed member was removed that pass. And a removal that failed was not retried on
any timer: the pass still reported success, the scheduler stamped the roster hash and
skipped the device as "unchanged" until the roster changed (a failed PullSDK stale
delete even erased its own state row). Upserts, meanwhile, backed off to 24 h.

Now: the revoke pass runs BEFORE the push; a revocation whose pin that step removed is
confirmed even if the push then fails; a failed removal re-requests a pass after 30 s,
doubling to at most 300 s, whatever the roster hash says; the upsert backoff caps at
6 h. No device, no installed database.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import app.core.ultra_engine as ue
from app.core.device_sync import DeviceSyncEngine, _SYNC_RETRY_FREE_ATTEMPTS, _SYNC_RETRY_MAX_SEC
from tests.test_standalone_finger_removal_state import FingerState, fstate  # noqa: F401
from tests.test_standalone_incremental_sync import _full_sync, _user, _worker
from tests.test_standalone_revoked_pin_removal import (
    FailingFallbackDriver, RevokeDriver, _authoritative_full_sync,
)


class OrderDriver(RevokeDriver):
    """Records the order of device operations; can fail the push."""

    def __init__(self, *, fail_push: bool = False, **kw):
        super().__init__(**kw)
        self.ops: list[str] = []
        self.fail_push = fail_push

    def delete_users(self, pins, *, timeout_sec: float = 300.0):
        self.ops.append("delete")
        return super().delete_users(pins, timeout_sec=timeout_sec)

    def push_roster(self, users, templates_by_pin=None, **kw):
        res = super().push_roster(users, templates_by_pin, **kw)
        if users and all(u.get("enabled") is False for u in users):
            self.ops.append("neutralise")
            return res
        self.ops.append("push")
        if self.fail_push:
            return {"ok": False, "pushed": 0, "failed": len(users), "templates_failed": 0,
                    "skipped_pin": 0, "chunks_wedged": 0, "errors": ["refused"],
                    "failed_pins": [str(u["pin"]) for u in users]}
        return res


class TestRemovalsFirst:

    def test_the_revoke_pass_runs_before_the_push(self, monkeypatch, fstate):
        drv = OrderDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "new", "1")])
        fstate.rows["34439"] = ("old-hash", True, {0})            # owned, departed
        _full_sync(w)
        assert drv.ops == ["delete", "push"]

    def test_a_failed_push_no_longer_blocks_a_departed_members_removal(self, monkeypatch, fstate):
        drv = OrderDriver(fail_push=True)
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "new", "1")])
        fstate.rows["34439"] = ("old-hash", True, {0})
        _full_sync(w)
        assert drv.delete_calls == [["34439"]], (
            "one member's refused push used to stop every removal of that pass")

    def test_a_revocation_removed_before_a_failing_push_is_not_requeued(self, monkeypatch, fstate):
        drv = OrderDriver(fail_push=True)
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "new", "1")])
        fstate.rows["34439"] = ("old-hash", True, {0})
        result = _authoritative_full_sync(w, 34439)
        assert drv.delete_calls == [["34439"]]
        assert result["ok"] is False, "the push did fail"
        assert 34439 not in (result.get("revoked_ids") or set()), (
            "the revocation itself was confirmed on the device: nothing to redo")


class TestFailedRemovalIsRetriedFast:

    def test_a_failed_removal_rerequests_a_pass_within_the_cap(self, monkeypatch, fstate):
        clock = {"t": 1000.0}
        monkeypatch.setattr(ue.time, "monotonic", lambda: clock["t"])
        drv = FailingFallbackDriver(fail_delete={"34439"})
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "a", "")])
        fstate.rows["34439"] = ("old-hash", True, {0})

        _full_sync(w)                                        # removal fails
        assert w._removal_retry_at_mono == pytest.approx(1030.0)
        w._maybe_request_removal_retry()
        assert w._pending_full_sync_request is None, "not due yet"

        clock["t"] = 1031.0
        w._maybe_request_removal_retry()
        assert w._pending_full_sync_request["reason"] == "removal-retry", (
            "re-requested by the worker itself: the scheduler's unchanged-roster skip "
            "no longer strands it")

        delays = []
        for _ in range(6):
            assert w._drain_full_sync_commands(limit=1) == 1
            delays.append(round(w._removal_retry_at_mono - clock["t"]))
            clock["t"] = w._removal_retry_at_mono + 1
            w._maybe_request_removal_retry()
        assert delays == [60, 120, 240, 300, 300, 300], "30 s doubling, capped at 300 s"

    def test_success_clears_the_retry(self, monkeypatch, fstate):
        drv = FailingFallbackDriver(fail_delete={"34439"})
        w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "a", "")])
        fstate.rows["34439"] = ("old-hash", True, {0})
        _full_sync(w)
        assert w._removal_retry_at_mono is not None
        drv._fail_delete.clear()
        w._removal_retry_at_mono = 0.0
        w._maybe_request_removal_retry()
        assert w._drain_full_sync_commands(limit=1) == 1
        assert w._removal_retry_at_mono is None and w._removal_retry_streak == 0
        assert "34439" not in fstate.rows

    def test_an_above_ceiling_abort_is_not_fast_retried(self, monkeypatch, fstate):
        """Refused by the ceiling is not 'failed': retrying every 30 s changes nothing."""
        w, _c = _worker(monkeypatch, driver=RevokeDriver(), users=[_user(30001, "a", "")])
        for i in range(50):
            fstate.rows[str(40000 + i)] = ("old-hash", True, {0})
        _full_sync(w)
        assert w._removal_retry_at_mono is None

    def test_a_failed_pullsdk_stale_delete_is_fast_retried(self, monkeypatch):
        import queue
        import threading

        class _Engine:
            def __init__(self, cfg, logger):
                self._last_single_device_error = ""
                self._last_removal_report = {"aborted": 0, "failed": ["40002"]}

            def sync_member_on_connected_sdk(self, **kw):
                return True

            def run_one_device_on_connected_sdk(self, **kw):
                return True

        w = ue.UltraDeviceWorker(
            device={"id": 5, "name": "Door", "ipAddress": "10.0.0.5", "portNumber": 4370},
            settings={}, popup_q=queue.Queue(), history_q=queue.Queue(),
            stop_event=threading.Event(),
        )
        w._connected = True
        w._sdk = SimpleNamespace(owns_event_source=False, _sdk="raw")
        w._on_full_sync_finished = MagicMock()
        monkeypatch.setattr(ue, "load_sync_cache",
                            lambda: SimpleNamespace(users=[{"activeMembershipId": 1}], devices=[]))
        monkeypatch.setattr("app.core.device_sync.DeviceSyncEngine", _Engine)
        w.request_full_sync(reason="timer", fingerprint_hash="h")
        assert w._drain_full_sync_commands(limit=1) == 1
        assert w._removal_retry_at_mono is not None


class TestUpsertBackoffCap:

    def test_the_cap_is_six_hours(self):
        assert _SYNC_RETRY_MAX_SEC == 6 * 3600

    def test_a_long_failing_pin_is_retried_within_six_hours(self):
        def _stamp(sec):
            return (datetime.now() - timedelta(seconds=sec)).strftime("%Y-%m-%d %H:%M:%S")

        assert DeviceSyncEngine._retry_due(fail_streak=500, updated_at=_stamp(6 * 3600 + 60)) is True
        assert DeviceSyncEngine._retry_due(fail_streak=500, updated_at=_stamp(6 * 3600 - 60)) is False
        # the free attempts are unchanged
        assert DeviceSyncEngine._retry_due(
            fail_streak=_SYNC_RETRY_FREE_ATTEMPTS, updated_at=_stamp(0)) is True

"""P3a-2 item 1: no automatic wipe; every bulk removal goes through ONE ceiling.

Before P3a-2 a PullSDK INCREMENTAL sync cleared the ``user`` and ``userauthorize``
tables (``DeleteDeviceData(table, "", "")`` -- every row, foreign users included)
whenever ``stale > desired and stale > 10``. Gym 58's two C3-400s are INCREMENTAL
with ``pinScheme`` '' -- no scheme-switch row, so the only suppression never applied
-- and the ULTRA worker hands the engine a copy relabelled ``accessDataMode=DEVICE``,
so nothing downstream could even tell the device was ULTRA. The stale-pin delete
itself had no ceiling and no empty-roster rail.

Now: the heuristic is gone, the stale delete and any table clear pass
``push_safety.check_bulk_removal`` (``max(10, 25 % of the desired roster)``), a
refused step removes nothing, keeps the per-pin state (no prune), reports
``REVOKE_ABORTED`` and the rest of the pass still runs. A stale delete that FAILS
keeps its state row so the removal can be retried; only confirmed deletions are
forgotten.

Real temp SQLite (``_DB_PATH``) + a MagicMock PullSDK: nothing reaches a device or
the installed database.
"""
from __future__ import annotations

import queue
import threading
from types import SimpleNamespace
from typing import List
from unittest.mock import MagicMock, patch

import pytest

import app.core.telemetry as tel
from tests.test_account_pin_device_sites import (  # noqa: F401  (fixture)
    _deleted_pins, _engine, _member, _pullsdk_device, _removed_pins, _sdk, _written_pins,
    sqlite_db,
)


@pytest.fixture
def warns(monkeypatch):
    seen: list[tuple[str, dict]] = []
    monkeypatch.setattr(tel, "warn", lambda name, **f: seen.append((name, f)))
    return seen


def _aborts(warns) -> List[dict]:
    return [f for n, f in warns if n == "REVOKE_ABORTED"]


def _gym58_device(**kw):
    """Gym 58's shape: ULTRA, C3-400 (no fingerprints), INCREMENTAL policy '1', pinScheme ''."""
    d = _pullsdk_device(pinScheme="", pushingToDevicePolicy="1")
    d.update(kw)
    return d


def _users(*ams: int):
    return [_member(am, 9000 + am, None, f"M{am}", card=str(100000 + am)) for am in ams]


def _run(users, device, device_pins, *, sdk=None, changed_ids=None):
    sdk = sdk or _sdk(device_pins)
    with patch("app.core.device_sync.PullSDK", MagicMock(return_value=sdk)):
        _engine()._sync_one_device(device=device, users=users, local_fp_index={},
                                   default_door_id=1, changed_ids=changed_ids)
    return sdk


def _clears(sdk):
    return [c for c in sdk.mock_calls if "clear_device_table" in c[0]]


class TestNoAutomaticWipe:
    def test_the_gym58_shape_never_clears_a_table(self, sqlite_db, warns):
        old = [str(40000 + i) for i in range(12)]
        for pin in old:
            sqlite_db.save_device_sync_state(device_id=1, pin=pin, desired_hash="h-old",
                                             ok=True, error=None)
        foreign = ["70001", "70002", "70003"]          # never pushed by MonClub
        sdk = _run(_users(101, 102), _gym58_device(), device_pins=old + foreign + ["101"])

        assert _clears(sdk) == [], "stale 12 > desired 2 used to wipe every table"
        assert not (set(old) | set(foreign)) & _removed_pins(sdk), (
            "12 stale pins against a roster of 2 is above the ceiling (10): nothing removed")
        assert "102" in _written_pins(sdk), "the rest of the pass still runs"
        [abort] = _aborts(warns)
        assert abort["count"] == 12 and abort["roster"] == 2 and abort["ceiling"] == 10
        assert abort["path"] == "stale" and abort["reason"] == "above_ceiling"
        assert set(old) <= set(sqlite_db.list_device_sync_pins(device_id=1)), (
            "an aborted removal must not be followed by a prune -- that would strand the pins"
        )

    def test_a_stale_delete_within_the_ceiling_still_runs(self, sqlite_db, warns):
        for pin in ("40001", "40002"):
            sqlite_db.save_device_sync_state(device_id=1, pin=pin, desired_hash="h",
                                             ok=True, error=None)
        sdk = _run(_users(101, 102), _gym58_device(), device_pins=["40001", "40002", "101"])
        assert _removed_pins(sdk) == {"40001", "40002"}
        assert _aborts(warns) == []

    def test_a_large_stale_set_below_the_old_nuke_line_is_also_capped(self, sqlite_db, warns):
        """stale 11 < desired 12: no nuke before either, but 11 > max(10, 3) was deleted
        with no ceiling at all."""
        old = [str(40000 + i) for i in range(11)]
        for pin in old:
            sqlite_db.save_device_sync_state(device_id=1, pin=pin, desired_hash="h",
                                             ok=True, error=None)
        users = _users(*range(101, 113))
        sdk = _run(users, _gym58_device(), device_pins=old)
        assert not set(old) & set(_deleted_pins(sdk))
        assert [a["count"] for a in _aborts(warns)] == [11]

    def test_an_empty_desired_roster_removes_nothing(self, sqlite_db, warns):
        for pin in ("40001", "40002", "40003"):
            sqlite_db.save_device_sync_state(device_id=1, pin=pin, desired_hash="h",
                                             ok=True, error=None)
        sdk = _run([], _gym58_device(), device_pins=["40001", "40002", "40003"])
        assert _removed_pins(sdk) == set() and _clears(sdk) == []
        [abort] = _aborts(warns)
        assert abort["reason"] == "empty_roster" and abort["count"] == 3
        assert set(sqlite_db.list_device_sync_pins(device_id=1)) >= {"40001", "40002", "40003"}

    def test_full_replace_clears_only_within_the_ceiling(self, sqlite_db, warns):
        device = _gym58_device(pushingToDevicePolicy="DELETE_ALL_BEFORE_PUSHING")
        small = _run(_users(101, 102), dict(device), device_pins=["101", "102", "7"])
        assert _clears(small), "3 rows on the panel <= ceiling 10: the explicit policy runs"

        big_panel = [str(70000 + i) for i in range(20)]
        sdk = _run(_users(101, 102), dict(device), device_pins=big_panel)
        assert _clears(sdk) == [], "a clear removes EVERY row: 20 > ceiling 10"
        assert {"101", "102"} <= set(_written_pins(sdk)), "still pushes the whole roster"
        assert [(a["path"], a["count"]) for a in _aborts(warns)] == [("table_clear", 20)]

    def test_a_failed_stale_delete_keeps_its_state_for_the_retry(self, sqlite_db, warns):
        for pin in ("40001", "40002"):
            sqlite_db.save_device_sync_state(device_id=1, pin=pin, desired_hash="h",
                                             ok=True, error=None)
        sdk = _sdk(["40001", "40002", "101"])
        sdk.delete_device_data_batch.side_effect = lambda *, table, pins, chunk_size: (
            (1, ["40002"]) if table == "user" else (len(pins), []))
        _run(_users(101), _gym58_device(), [], sdk=sdk)
        pins = set(sqlite_db.list_device_sync_pins(device_id=1))
        assert "40001" not in pins, "confirmed deletion: state forgotten"
        assert "40002" in pins, "failed deletion: the ownership row is the retry's only handle"
        assert sqlite_db.get_device_sync_ownership_for_pin(device_id=1, pin="40002") is True


class TestTheProductionUltraPath:
    """The ULTRA worker relabels the device to DEVICE before handing it over; the rule
    must hold on that exact path, not only on a hand-built ULTRA dict."""

    def _worker(self, monkeypatch, device, users):
        import app.core.ultra_engine as ue

        w = ue.UltraDeviceWorker(device=device, settings={}, popup_q=queue.Queue(),
                                 history_q=queue.Queue(), stop_event=threading.Event())
        w._connected = True
        w._on_full_sync_finished = MagicMock()
        monkeypatch.setattr(ue, "load_sync_cache",
                            lambda: SimpleNamespace(users=list(users), devices=[]))
        return w

    def test_worker_full_sync_never_wipes(self, sqlite_db, monkeypatch, warns):
        old = [str(40000 + i) for i in range(12)]
        for pin in old:
            sqlite_db.save_device_sync_state(device_id=1, pin=pin, desired_hash="h-old",
                                             ok=True, error=None)
        raw = _sdk(old + ["101"])
        device = _gym58_device()
        w = self._worker(monkeypatch, device, _users(101, 102))
        w._sdk = SimpleNamespace(owns_event_source=False, _sdk=raw)
        w.request_full_sync(reason="timer", fingerprint_hash="h")
        assert w._drain_full_sync_commands(limit=1) == 1
        assert _clears(raw) == []
        assert not set(old) & _removed_pins(raw)
        assert _aborts(warns) and _aborts(warns)[0]["count"] == 12
        assert w._on_full_sync_finished.call_args.kwargs["ok"] is True, (
            "an aborted removal step does not fail the rest of the pass")

    def test_scheduler_fallback_never_wipes(self, sqlite_db, monkeypatch, warns):
        import app.core.ultra_engine as ue

        old = [str(40000 + i) for i in range(12)]
        for pin in old:
            sqlite_db.save_device_sync_state(device_id=1, pin=pin, desired_hash="h-old",
                                             ok=True, error=None)
        raw = _sdk(old + ["101"])
        monkeypatch.setattr(ue, "load_sync_cache",
                            lambda: SimpleNamespace(users=_users(101, 102), devices=[]))
        sched = ue.UltraSyncScheduler(cfg=SimpleNamespace(plcomm_dll_path="x", timeout_ms=3000),
                                      logger_inst=MagicMock())
        with patch("app.core.device_sync.PullSDK", MagicMock(return_value=raw)):
            sched._sync_device(_gym58_device())
        assert _clears(raw) == []
        assert not set(old) & _removed_pins(raw)

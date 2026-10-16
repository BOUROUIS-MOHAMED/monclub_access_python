"""Card H item 10: a sync run lists each device's push result -- by a real link, never by time.

The sync tick's run id rides on the ULTRA full-sync request (app._request_running_ultra_sync ->
UltraEngine.request_sync_now -> worker.request_full_sync) to the pass's push_batch_history row,
as push_batch_sync_run rows. A worker coalesces requests, so the ids are a SET, unioned on merge.
"""
from __future__ import annotations

import importlib
import logging
import threading
from collections import deque
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _no_erase_holds():
    from app.core import device_hold

    device_hold.reset_for_tests()
    yield
    device_hold.reset_for_tests()


@pytest.fixture()
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    importlib.reload(db_module)
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()
    return db_module


def _run(db, created_at="2026-10-16T10:00:00+00:00"):
    return db.insert_sync_run(run_type="PERIODIC", trigger_source="TIMER", status="IN_PROGRESS",
                              created_at=created_at)


def _batch(db, *, device_id=1, sync_run_id=None, sync_run_ids=None, created_at="2026-10-16T10:00:05Z"):
    return db.insert_push_batch(sync_run_id=sync_run_id, device_id=device_id, device_name=f"Porte {device_id}",
                                policy="PRESERVE", status="IN_PROGRESS", created_at=created_at,
                                sync_run_ids=sync_run_ids)


# ------------------------------------------------------------------------------ database

def test_one_batch_links_every_run_it_answers_and_only_those(db):
    r1, r2, r3 = _run(db), _run(db), _run(db)
    b = _batch(db, sync_run_ids={r1, r2})
    _batch(db, device_id=2, created_at="2026-10-16T10:00:06Z")       # same second, no link

    assert [x["id"] for x in db.list_push_batches_for_sync_run(r1)] == [b]
    assert [x["id"] for x in db.list_push_batches_for_sync_run(r2)] == [b]
    assert db.list_push_batches_for_sync_run(r3) == []               # never matched by time
    assert db.get_push_batch(b)["sync_run_ids"] == [r1, r2]
    assert db.get_push_batch(b)["sync_run_id"] is None              # the DEVICE column is untouched


def test_device_mode_column_still_counts_for_its_run(db):
    r = _run(db)
    b = _batch(db, sync_run_id=r)

    assert [x["id"] for x in db.list_push_batches_for_sync_run(r)] == [b]
    assert db.list_push_batches(page=0, size=10)["items"][0]["sync_run_ids"] == [r]


def test_a_run_that_no_longer_exists_is_not_linked_and_the_batch_is_still_written(db):
    b = _batch(db, sync_run_ids={987654})

    assert db.get_push_batch(b) is not None
    with db.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) FROM push_batch_sync_run").fetchone()[0] == 0


def test_link_rows_go_with_the_run_or_the_batch(db):
    r1, r2 = _run(db), _run(db)
    b1 = _batch(db, sync_run_ids={r1})
    _batch(db, sync_run_ids={r2})

    with db.get_conn() as conn:
        conn.execute("DELETE FROM sync_run_history WHERE id = ?", (r2,))
        conn.execute("DELETE FROM push_batch_history WHERE id = ?", (b1,))
        conn.commit()
        assert conn.execute("SELECT COUNT(*) FROM push_batch_sync_run").fetchone()[0] == 0


def test_detail_handler_returns_the_linked_batches(db):
    from app.api import local_access_api_v2 as api

    r = _run(db)
    b = _batch(db, sync_run_ids={r})
    db.update_push_batch(id=b, pins_attempted=4, pins_success=3, pins_failed=1, status="PARTIAL", duration_ms=900)

    sent = {}
    ctx = SimpleNamespace(param_int=lambda name, default=0: r,
                          send_json=lambda status, payload: sent.update(status=status, payload=payload))
    api._handle_sync_history_detail(ctx)

    assert sent["status"] == 200
    [row] = sent["payload"]["pushBatches"]
    assert (row["device_id"], row["pins_attempted"], row["pins_success"], row["pins_failed"], row["status"]) \
        == (1, 4, 3, 1, "PARTIAL")


def test_device_sync_writes_the_link_with_the_batch(tmp_path, monkeypatch, db):
    from app.core.device_sync import DeviceSyncEngine

    engine = DeviceSyncEngine(cfg=SimpleNamespace(plcomm_dll_path="", timeout_ms=5000),
                              logger=logging.getLogger("test"))
    r = _run(db)
    sdk_cls = MagicMock()
    sdk = sdk_cls.return_value
    sdk.get_device_data_rows.return_value = []
    sdk.set_device_data.return_value = 0
    sdk.set_device_data_batch.return_value = (50, [])
    sdk.set_device_param.return_value = 0
    device = {
        "id": 1, "name": "Porte", "ipAddress": "10.0.0.1", "portNumber": 4370, "password": "",
        "active": True, "accessDevice": True, "accessDataMode": "DEVICE", "fingerprintEnabled": False,
        "authorizeTimezoneId": 1, "doorIds": [15], "doorPresets": [], "pushingToDevicePolicy": "ALL",
    }
    user = {"activeMembershipId": 1, "userId": 1001, "membershipId": 1, "fullName": "A",
            "validFrom": "2026-01-01", "validTo": "2026-12-31", "firstCardId": "100", "fingerprints": []}
    with patch("app.core.device_sync.PullSDK", sdk_cls):
        engine._sync_one_device(device=device, users=[user], local_fp_index={}, default_door_id=15,
                                sync_run_ids={r})

    [row] = db.list_push_batches_for_sync_run(r)
    assert row["device_id"] == 1


def test_connected_sdk_entry_point_passes_the_ids_down(db):
    from app.core.device_sync import DeviceSyncEngine

    engine = DeviceSyncEngine(cfg=SimpleNamespace(plcomm_dll_path="", timeout_ms=5000),
                              logger=logging.getLogger("test"))
    seen = {}
    engine._sync_one_device = lambda **kw: seen.update(kw)
    device = {"id": 3, "name": "P", "active": True, "accessDevice": True, "fingerprintEnabled": False}

    engine.run_one_device_on_connected_sdk(sdk=MagicMock(), cache=SimpleNamespace(users=[]),
                                           device=device, source="timer", sync_run_ids={5})
    assert seen.get("sync_run_ids") == {5}

    seen.clear()
    engine.run_one_device_on_connected_sdk(sdk=MagicMock(), cache=SimpleNamespace(users=[]),
                                           device=device, source="timer")
    assert "sync_run_ids" not in seen


# ------------------------------------------------------------------------------ worker

def _worker():
    import app.core.ultra_engine as ultra_module

    worker = object.__new__(ultra_module.UltraDeviceWorker)
    worker._member_sync_lock = threading.Lock()
    worker._pending_member_syncs = deque()
    worker._pending_member_sync_ids = set()
    worker._pending_member_revoke_ids = set()
    worker._active_member_revoke_ids = set()
    worker._confirmed_member_revoke_ids = set()
    worker._full_sync_lock = threading.Lock()
    worker._pending_full_sync_request = None
    worker._full_sync_revocation_phase = {}
    worker._wake_evt = threading.Event()
    return worker


def test_coalesced_requests_keep_every_run_id():
    w = _worker()
    assert w.request_full_sync(reason="timer", require_full_refresh=True, sync_run_ids={11})
    assert w.request_full_sync(reason="timer", require_full_refresh=True)          # no run: no change
    assert w.request_full_sync(reason="sync_now_api", require_full_refresh=True, sync_run_ids={12})

    assert w._pending_full_sync_request["sync_run_ids"] == {11, 12}


def test_a_request_without_a_run_adds_no_key():
    w = _worker()
    w.request_full_sync(reason="intent-promoted")
    assert "sync_run_ids" not in w._pending_full_sync_request


def test_the_pass_receives_the_ids_and_a_worker_follow_up_does_not():
    w = _worker()
    w._sdk = SimpleNamespace(owns_event_source=True)
    w._connected = True
    w._device_id = 9
    calls = []
    w._run_standalone_full_sync = lambda **kw: calls.append(kw)

    w.request_full_sync(reason="timer", require_full_refresh=True, sync_run_ids={21})
    assert w._drain_full_sync_commands(limit=1) == 1
    w.request_full_sync(reason="push-capped")
    assert w._drain_full_sync_commands(limit=1) == 1

    assert calls[0]["sync_run_ids"] == {21}
    assert "sync_run_ids" not in calls[1]


def test_a_request_requeued_for_a_dead_link_keeps_its_ids():
    w = _worker()
    w._sdk = SimpleNamespace(owns_event_source=True, is_connected=False)
    w._connected = True
    w._device_id = 9
    w._finalize_full_sync_revokes = lambda *a, **k: None

    w.request_full_sync(reason="timer", require_full_refresh=True, sync_run_ids={31})
    w._drain_full_sync_commands(limit=1)

    assert w._pending_full_sync_request["sync_run_ids"] == {31}


# ------------------------------------------------------------------------------ engine / app

def test_engine_routes_the_ids_to_the_live_worker_full_request_only():
    import app.core.ultra_engine as ultra_module

    worker = SimpleNamespace(request_member_sync=MagicMock(return_value=True),
                             request_full_sync=MagicMock(return_value=True))
    scheduler = SimpleNamespace(request_sync_now=MagicMock())
    engine = SimpleNamespace(_running=True, _sync_scheduler=scheduler, _workers={5: worker},
                             _logger=MagicMock())

    ultra_module.UltraEngine.request_sync_now(engine, changed_ids=None, device_ids={5},
                                              reason="timer", sync_run_ids={41})
    worker.request_full_sync.assert_called_once_with(reason="timer", require_full_refresh=True,
                                                     sync_run_ids={41})

    worker.request_full_sync.reset_mock()
    ultra_module.UltraEngine.request_sync_now(engine, changed_ids={7}, device_ids={5},
                                              reason="timer", sync_run_ids={42})
    worker.request_full_sync.assert_not_called()          # a member delta writes no batch
    worker.request_member_sync.assert_called_once_with(7)


def test_app_passes_the_tick_run_id_only_when_given():
    from app.ui.app import MainApp

    engine = SimpleNamespace(running=True, request_sync_now=MagicMock(return_value=True))
    app = SimpleNamespace(_ultra_lock=threading.Lock(), _ultra_engine=engine, logger=MagicMock())

    MainApp._request_running_ultra_sync(app, refresh={"devices": True}, changed_ids=None,
                                        reason="TIMER", sync_run_id=77)
    assert engine.request_sync_now.call_args.kwargs["sync_run_ids"] == {77}

    MainApp._request_running_ultra_sync(app, refresh={"devices": True}, changed_ids=None, reason="TIMER")
    assert "sync_run_ids" not in engine.request_sync_now.call_args.kwargs

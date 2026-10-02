"""Mode changes without a restart: AGENT first, then single ULTRA workers (ULTRA merge plan 2,
Task 13; spec section 6 "Taking effect")."""
from __future__ import annotations

import logging
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

from app.core import access_mode_refresh as amr


def _dev(did, mode="ULTRA", **extra):
    d = {"id": did, "name": f"d{did}", "accessDataMode": mode, "deviceProtocol": "ZK_PULLSDK",
         "active": True, "accessDevice": True}
    d.update(extra)
    return d


def _app(engine, *, order=None):
    order = order if order is not None else []
    agent = MagicMock()
    agent.is_running.return_value = True
    agent.refresh_devices.side_effect = lambda: order.append("agent")
    return SimpleNamespace(logger=logging.getLogger("test.amr"), _ultra_lock=threading.Lock(),
                           _ultra_engine=engine, _agent_engine=agent, _ultra_history_consumer=None,
                           get_access_mode_summary=MagicMock())


def test_the_fast_path_refreshes_agent_first_then_reconciles_the_ultra_workers(monkeypatch):
    order = []
    engine = MagicMock(running=True)
    engine.reconcile_devices.side_effect = lambda devices, **kw: (
        order.append(("ultra", [d["id"] for d in devices], kw)) or {"started": 1, "stopped": 0, "refreshed": 2})
    app = _app(engine, order=order)
    monkeypatch.setattr("app.core.db.list_sync_devices_payload",
                        lambda: [_dev(9), _dev(10, "AGENT"), _dev(11)])

    assert amr.refresh_running_ultra_devices(app, reason="test") is True
    assert order == ["agent", ("ultra", [9, 11], {"stop_undriven": False})]


def test_the_fast_path_reads_nothing_without_a_running_engine(monkeypatch):
    app = _app(MagicMock(running=False))
    monkeypatch.setattr("app.core.db.list_sync_devices_payload", MagicMock(side_effect=AssertionError("read")))

    assert amr.refresh_running_ultra_devices(app, reason="test") is True
    app._agent_engine.refresh_devices.assert_not_called()


def test_the_fast_path_reports_an_unreadable_device_table(monkeypatch):
    engine = MagicMock(running=True)
    app = _app(engine)
    monkeypatch.setattr("app.core.db.list_sync_devices_payload", MagicMock(side_effect=RuntimeError("disk")))

    assert amr.refresh_running_ultra_devices(app, reason="test") is False
    engine.reconcile_devices.assert_not_called()


def test_the_tick_starts_the_engine_for_the_first_ultra_device(monkeypatch):
    engine = MagicMock(running=False, _workers={})
    engine.start.side_effect = lambda devices: setattr(engine, "running", True)
    app = _app(engine)
    app.get_access_mode_summary.return_value = {"ULTRA": 1}
    monkeypatch.setattr("app.core.db.list_sync_devices_payload", lambda: [_dev(9), _dev(10, "AGENT")])
    consumer = MagicMock()
    monkeypatch.setattr("app.core.realtime_agent.HistoryService", MagicMock(return_value=consumer))

    assert amr.apply_modes_on_tick(app, refresh={"devices": True}) is True
    assert [d["id"] for d in engine.start.call_args.args[0]] == [9]
    app._agent_engine.refresh_devices.assert_called_once()
    consumer.start.assert_called_once()


def test_the_tick_adds_a_worker_in_place_instead_of_restarting(monkeypatch):
    engine = MagicMock(running=True, _workers={9: object()})
    engine.reconcile_devices.return_value = {"started": 1, "stopped": 0, "refreshed": 2}
    app = _app(engine)
    app.get_access_mode_summary.return_value = {"ULTRA": 2}
    monkeypatch.setattr("app.core.db.list_sync_devices_payload", lambda: [_dev(9), _dev(11)])

    assert amr.apply_modes_on_tick(app, refresh={"devices": False}) is False
    engine.stop.assert_not_called()
    engine.start.assert_not_called()
    args, kwargs = engine.reconcile_devices.call_args
    assert [d["id"] for d in args[0]] == [9, 11]
    assert kwargs == {"stop_undriven": True, "refresh_copies": False}


def test_the_tick_only_refreshes_copies_when_the_workers_are_right(monkeypatch):
    engine = MagicMock(running=True, _workers={9: object()})
    app = _app(engine)
    app.get_access_mode_summary.return_value = {"ULTRA": 1}
    monkeypatch.setattr("app.core.db.list_sync_devices_payload", lambda: [_dev(9)])

    amr.apply_modes_on_tick(app, refresh={"devices": True})

    engine.reconcile_devices.assert_not_called()
    assert [d["id"] for d in engine.refresh_devices.call_args.args[0]] == [9]


def test_the_tick_stops_the_engine_when_no_ultra_device_is_in_service(monkeypatch):
    engine = MagicMock(running=True, _workers={9: object()})
    app = _app(engine)
    consumer = MagicMock()
    app._ultra_history_consumer = consumer
    app.get_access_mode_summary.return_value = {"ULTRA": 1}
    monkeypatch.setattr("app.core.db.list_sync_devices_payload", lambda: [_dev(9, active=False)])

    amr.apply_modes_on_tick(app, refresh={})

    engine.stop.assert_called_once()
    consumer.stop.assert_called_once()
    assert app._ultra_history_consumer is None


def test_the_tick_stops_the_engine_when_no_ultra_device_is_left():
    engine = MagicMock(running=True, _workers={9: object()})
    app = _app(engine)
    app.get_access_mode_summary.return_value = {"ULTRA": 0}

    amr.apply_modes_on_tick(app, refresh={})

    engine.stop.assert_called_once()

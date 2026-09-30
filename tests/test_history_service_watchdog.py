"""The HistoryService watchdog reports a death only for a thread that was running.

Gym 45 (2026-09-29 23:56:23, first start after install):
    [RT] History service not started (AGENT mode writes history directly)
    [RT] HistoryService died — restarting            <- ERROR, 1 ms later
AgentRealtimeEngine builds ``_hist`` but deliberately never starts it in AGENT mode; the
watchdog read "not alive" as a death and started the idle thread. Nothing puts on the agent's
``_history_q`` (the ULTRA engine has its own), so no history write depended on it.
"""
from __future__ import annotations

import queue
import threading
from unittest.mock import MagicMock

from app.core import realtime_agent as ra


def _agent(hist):
    eng = ra.AgentRealtimeEngine.__new__(ra.AgentRealtimeEngine)
    eng.logger = MagicMock()
    eng._deciders = []
    eng._notif = None
    eng._hist = hist
    eng._history_q = queue.Queue()
    eng.get_global_settings = lambda: {"history_service_enabled": True}
    return eng


def _errors(eng):
    return [c.args[0] for c in eng.logger.error.call_args_list]


def test_a_never_started_history_service_is_not_a_death():
    never = ra.HistoryService(logger=MagicMock(), history_q=queue.Queue(),
                              global_settings=lambda: {})
    eng = _agent(never)
    eng._check_thread_health()
    assert _errors(eng) == [], "23:56:23: 'HistoryService died' for a thread never started"
    assert eng._hist is never and not never.is_alive(), "and it is not started behind AGENT's back"


def test_a_real_death_is_still_reported_and_restarted():
    dead = ra.HistoryService(logger=MagicMock(), history_q=queue.Queue(),
                             global_settings=lambda: {})
    dead.stop()
    dead.start()
    dead.join(timeout=5)
    assert dead.ident is not None and not dead.is_alive()
    eng = _agent(dead)
    eng._check_thread_health()
    assert any("HistoryService died" in e for e in _errors(eng))
    assert eng._hist is not dead and eng._hist.is_alive()
    eng._hist.stop()
    eng._hist.join(timeout=5)

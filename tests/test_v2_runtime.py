"""P3b-2: the v2 runtime's control loop (availability, polling, notice-driven syncs)."""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from app.core.v2 import lease_gate as lg
from app.core.v2 import runtime as rtmod
from app.core.v2.api import V2ApiError


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    import app.core.db as dbmod
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "rt.db"), raising=False)
    dbmod.init_db()
    lg.reset_for_tests()
    monkeypatch.setattr(rtmod, "_pc_uuid", lambda app: "uuid-1")
    yield
    lg.reset_for_tests()
    __import__('app.core.v2.server_clock', fromlist=['x']).set_default(None)   # set by the runtime
    dbmod._shutdown_db_writer_for_tests()


class FakeApp:
    def __init__(self):
        self.after_calls = []
        self.sync_requests = []

    def after(self, ms, fn):
        self.after_calls.append(ms)
        fn()

    def request_sync_now(self, *, trigger_source, trigger_hint=None, run_type="TRIGGERED"):
        self.sync_requests.append(trigger_source)


def _runtime(assign=None, pending=None):
    app = FakeApp()
    rt = rtmod.V2Runtime(app, base_url="http://127.0.0.1:1", token_provider=lambda: "tok", app_version="1.4.35")
    calls = {"assignment": 0, "pending": 0}

    def assignment():
        calls["assignment"] += 1
        if isinstance(assign, Exception):
            raise assign
        return assign or {"gymUsesAssignments": False, "role": "ALL_TURNSTILES", "drive": [], "release": [],
                          "readerOf": []}

    def pend():
        calls["pending"] += 1
        return pending or {"commands": []}

    rt.api.assignment = assignment
    rt.api.pending = pend
    rt.api.claim = lambda *a: (_ for _ in ()).throw(V2ApiError(409, "COMMAND_EXPIRED", backend=True))
    return rt, app, calls


def test_an_old_server_keeps_everything_dormant():
    rt, app, calls = _runtime(assign=V2ApiError(404, "NOT_FOUND", backend=True))
    rt.tick()
    assert rt.availability == "OFF"
    assert calls["pending"] == 0, "no poll, no socket, nothing uploaded while the switch is off"
    assert not rt.notice._enabled()
    assert lg.current().mode == lg.MODE_ALL
    rt.tick()
    assert calls["assignment"] == 1, "re-probed only every 30 min"


def test_offline_keeps_the_last_state_and_does_not_disable_anything():
    rt, app, calls = _runtime(assign=V2ApiError(0, "UNREACHABLE"))
    rt.tick()
    assert rt.availability == "UNKNOWN" and calls["pending"] == 0


def test_with_the_socket_down_pending_commands_are_polled_every_interval():
    rt, app, calls = _runtime()
    rt.tick()
    assert rt.availability == "ON" and calls["pending"] == 1
    rt.tick()
    assert calls["pending"] == 1, "not before pollIntervalSec"
    rt._next_poll = 0.0
    rt.notice.connected = True
    rt.tick()
    assert calls["pending"] == 1, "no poll while the socket is up"


def test_notices_become_one_spaced_sync_request():
    rt, app, calls = _runtime()
    rt.tick()
    rt._last_notice_sync = time.monotonic() - 3600
    rt._rand = lambda: 0.0
    rt.on_changed(["members"], {})
    rt.on_changed(["credentials"], {})
    rt._sync_due = time.monotonic() - 1          # pretend the jitter elapsed
    rt.tick()
    assert app.sync_requests == ["REALTIME_NOTICE"]
    rt.on_changed(["members"], {})
    assert rt._sync_due >= time.monotonic() + 55, "at most one notice-driven sync a minute"


def test_an_assignment_notice_refreshes_the_roles_without_a_sync():
    rt, app, calls = _runtime()
    rt.tick()
    rt.on_changed(["assignment"], {})
    assert rt._next_refresh == 0.0 and rt._sync_due is None


def test_a_role_change_asks_the_engines_to_re_evaluate():
    rt, app, calls = _runtime(assign={"gymUsesAssignments": True, "role": "READER", "drive": [], "release": [],
                                      "readerOf": []})
    rt.tick()
    assert "LEASE_CHANGE" in app.sync_requests
    assert not lg.device_allowed(8)


def test_a_reader_is_a_reader_at_a_cold_start_before_any_worker():
    rt, app, calls = _runtime(assign={"gymUsesAssignments": True, "role": "READER", "drive": [], "release": [],
                                      "readerOf": []})
    rt.tick()
    lg.reset_for_tests()
    assert rtmod.load_cached_roles(SimpleNamespace())
    assert lg.current().role == "READER" and not lg.device_allowed(8)


def test_the_welcome_measures_the_clock_and_learns_the_gym_offset():
    rt, app, calls = _runtime()
    now = time.time()
    st = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now + 3600 + 42)) + "+01:00"
    rt.on_welcome({"serverTime": st}, now, now)
    assert rt.clock.utc_offset == 3600
    assert rt.clock.offset() == pytest.approx(42.0, abs=1.5)


def test_the_heartbeat_carries_the_measured_offset_only_once_measured(monkeypatch):
    from access import pc_identity
    monkeypatch.setattr("app.core.db.peek_sync_cache", lambda: SimpleNamespace(devices=[]))
    app = SimpleNamespace(_update_manager=SimpleNamespace(get_current_version=lambda: "1.4.35"),
                          _agent_engine=None, _ultra_engine=None)
    __import__('app.core.v2.server_clock', fromlist=['x']).set_default(None)
    assert "clockOffset" not in pc_identity.build_heartbeat_payload(app)
    rt, _app, _calls = _runtime()
    now = time.time()
    rt.clock.add_sample(now - 2.5, now, now, source="welcome")
    assert pc_identity.build_heartbeat_payload(app)["clockOffset"] == {
        "offsetSec": pytest.approx(-2.5, abs=0.01), "samples": 1, "source": "welcome"}

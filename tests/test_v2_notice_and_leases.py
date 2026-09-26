"""P3b-2 step 3: the notice loop over a real localhost socket, and the lease manager.

Server behaviour modelled from backend main c7d4b532 (AccessNoticeHub): the first frame is
``welcome`` (no seq); ``changed``/``rollover``/``command`` carry a per-session ``seq``; close
codes 4001 (token expired), 4003 (revoked/adopted), 4009 (replaced by a newer socket).
"""
from __future__ import annotations

import json
import threading
import time

import pytest

from app.core.v2 import lease_gate as lg
from app.core.v2.api import V2ApiError
from app.core.v2.leases import LeaseManager, OFF, ON, UNREACHABLE
from app.core.v2.notice import NoticeCallbacks, NoticeLoop
from app.core.v2.ws_client import OP_TEXT
from tests.v2_ws_server import ScriptedWsServer


WELCOME = {"type": "welcome", "v": 1, "sessionId": "s1", "mode": "PC", "pcId": 7, "gymId": 45,
           "serverTime": "2026-09-26T10:00:00.12+01:00", "pingIntervalSec": 25,
           "readIdleTimeoutSec": 60, "pollIntervalSec": 120, "commands": True}


class Rec(NoticeCallbacks):
    def __init__(self):
        self.events = []
        self.done = threading.Event()

    def on_welcome(self, msg, s, r):
        self.events.append(("welcome", msg["sessionId"]))

    def on_changed(self, scopes, msg):
        self.events.append(("changed", tuple(scopes)))

    def on_rollover(self, msg):
        self.events.append(("rollover", msg.get("day")))

    def on_command(self, cid, ctype, msg):
        self.events.append(("command", cid, ctype))
        self.done.set()

    def on_disconnected(self, reason):
        self.events.append(("disconnected", reason))

    def on_switched_off(self):
        self.events.append(("off",))

    def on_token_expired(self):
        self.events.append(("token",))


def _loop(url, rec, **kw):
    return NoticeLoop(url=url, headers_provider=lambda: {"Authorization": "Bearer t"}, callbacks=rec,
                      first_delay_max=0.0, **kw)


def test_welcome_notices_and_acks_flow_through_the_callbacks():
    acks = []

    def script(conn):
        conn.send_text(WELCOME)
        conn.send_text({"type": "changed", "seq": 1, "scopes": ["credentials", "members"], "at": "x"})
        conn.send_text({"type": "rollover", "seq": 2, "day": "2026-09-27", "spreadSec": 90})
        conn.send_text({"type": "command", "seq": 3, "id": "0b0f9a5e-1111-4222-8333-444455556666",
                        "commandType": "DOOR_OPEN", "claimBy": "2026-09-26T10:00:15+01:00"})
        for _ in range(3):
            fr = conn.read_frame(3)
            if fr and fr[0] == OP_TEXT:
                acks.append(json.loads(fr[1]))
        time.sleep(0.5)

    srv = ScriptedWsServer(script)
    rec = Rec()
    loop = _loop(srv.url, rec)
    loop.start()
    try:
        assert rec.done.wait(5)
        time.sleep(0.3)
        assert rec.events[:4] == [("welcome", "s1"), ("changed", ("credentials", "members")),
                                  ("rollover", "2026-09-27"),
                                  ("command", "0b0f9a5e-1111-4222-8333-444455556666", "DOOR_OPEN")]
        assert acks == [{"type": "ack", "seq": 1}, {"type": "ack", "seq": 2}, {"type": "ack", "seq": 3}]
        assert loop.poll_interval_sec == 120 and loop.sessions == 1
    finally:
        loop.stop()
        srv.close()


@pytest.mark.parametrize("code,reason,expected_wait", [
    (4003, "ACCESS_PC_REVOKED", 1800.0),
    (4009, "REPLACED", 300.0),
])
def test_close_codes_set_the_wait_before_the_next_connect(code, reason, expected_wait):
    srv = ScriptedWsServer(lambda conn: (conn.send_text(WELCOME), conn.send_close(code, reason),
                                         conn.read_frame(2)))
    rec = Rec()
    loop = _loop(srv.url, rec)
    try:
        assert loop._one_session() == expected_wait
        assert rec.events[-1] == ("disconnected", f"close {code} {reason}")
    finally:
        srv.close()


def test_a_token_expiry_close_asks_for_a_new_token_and_reconnects_within_a_minute():
    srv = ScriptedWsServer(lambda conn: (conn.send_text(WELCOME), conn.send_close(4001, "TOKEN_EXPIRED"),
                                         conn.read_frame(2)))
    rec = Rec()
    loop = _loop(srv.url, rec, rand=lambda: 0.5)
    try:
        assert loop._one_session() == pytest.approx(30.0)
        assert ("token",) in rec.events
    finally:
        srv.close()


def test_a_handshake_404_not_found_is_the_switch_off():
    srv = ScriptedWsServer(lambda conn: None, refuse=(404, {"status": False, "errorMsg": "Resource not found",
                                                            "code": "NOT_FOUND"}, {}))
    rec = Rec()
    loop = _loop(srv.url, rec)
    try:
        loop._one_session()
        assert rec.events == [("off",)]
    finally:
        srv.close()


def test_a_revoked_pc_waits_half_an_hour_and_a_busy_server_is_honoured():
    for refuse, low in (((403, {"status": False, "code": "ACCESS_PC_REVOKED"}, {}), 1800.0),
                        ((503, {"status": False, "code": "SERVER_SHUTTING_DOWN"}, {"Retry-After": "40"}), 40.0)):
        srv = ScriptedWsServer(lambda conn: None, refuse=refuse)
        try:
            assert _loop(srv.url, Rec())._one_session() >= low
        finally:
            srv.close()


def test_a_silent_socket_is_dropped_as_half_open():
    hold = threading.Event()
    srv = ScriptedWsServer(lambda conn: (conn.send_text(WELCOME), hold.wait(10)))
    rec = Rec()
    loop = _loop(srv.url, rec)
    loop.half_open_margin_sec = -59.5         # welcome says readIdle 60 s: drop after 0.5 s of silence
    try:
        t0 = time.monotonic()
        loop._one_session()
        assert time.monotonic() - t0 < 5
        assert rec.events[-1][1].startswith("half-open")
    finally:
        hold.set()
        srv.close()


def test_a_wall_clock_jump_is_read_as_a_resume_and_the_socket_rebuilt():
    hold = threading.Event()
    srv = ScriptedWsServer(lambda conn: (conn.send_text(WELCOME), hold.wait(10)))
    rec = Rec()
    jump = {"v": 0.0}
    loop = _loop(srv.url, rec, wall=lambda: time.time() + jump["v"])
    threading.Timer(0.5, lambda: jump.__setitem__("v", 3600.0)).start()
    try:
        loop._one_session()
        assert rec.events[-1] == ("disconnected", "resume (clock jump)")
    finally:
        hold.set()
        srv.close()


def test_no_token_means_no_connection_attempt():
    rec = Rec()
    loop = NoticeLoop(url="ws://127.0.0.1:1/x", headers_provider=lambda: None, callbacks=rec)
    assert loop._one_session() == 60.0 and rec.events == []


# --------------------------------------------------------------------------- leases

class FakeApi:
    def __init__(self, outcome):
        self.outcome = outcome

    def assignment(self):
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def _mgr(api, kv, uuid="uuid-1", changes=None):
    return LeaseManager(api=api, pc_uuid_provider=lambda: uuid,
                        on_change=(lambda a, b: changes.append((a.role, b.role))) if changes is not None else None,
                        kv_get=kv.get, kv_put=lambda k, v, **_: kv.__setitem__(k, v),
                        kv_delete=lambda k: kv.pop(k, None))


READER = {"gymUsesAssignments": True, "role": "READER", "drive": [], "release": [], "readerOf": []}
DRIVER = {"gymUsesAssignments": True, "role": "DRIVER", "readerOf": [], "release": [],
          "drive": [{"gymDeviceId": 8, "generation": 3, "state": "DRIVE", "handoverForced": False}]}


@pytest.fixture(autouse=True)
def _reset():
    lg.reset_for_tests()
    yield
    lg.reset_for_tests()


def test_a_fetched_assignment_is_installed_and_cached_for_offline_cold_starts():
    kv, changes = {}, []
    assert _mgr(FakeApi(READER), kv, changes=changes).refresh() == ON
    assert lg.current().role == "READER" and not lg.device_allowed(8)
    assert kv["assignment_cache"]["pcUuid"] == "uuid-1"
    assert changes == [("UNKNOWN", "READER")]
    lg.reset_for_tests()
    # Power-on, no internet: the cache makes the PC a reader again before any worker starts.
    m = _mgr(FakeApi(V2ApiError(0, "UNREACHABLE")), kv)
    assert m.load_cache() and lg.current().role == "READER" and lg.current().source == "cache"
    assert m.refresh() == UNREACHABLE and lg.current().role == "READER"


def test_the_switch_off_clears_the_cache_and_every_turnstile_is_allowed_again():
    kv = {}
    _mgr(FakeApi(READER), kv).refresh()
    off = V2ApiError(404, "NOT_FOUND", backend=True)
    assert _mgr(FakeApi(off), kv).refresh() == OFF
    assert "assignment_cache" not in kv and lg.device_allowed(8)


@pytest.mark.parametrize("err", [V2ApiError(404, "UNREACHABLE"), V2ApiError(502, "UNREACHABLE"),
                                 V2ApiError(0, "NO_PC_TOKEN"), V2ApiError(401, "ACCESS_PC_TOKEN_INVALID", backend=True)])
def test_anything_but_the_backend_404_keeps_the_roles(err):
    kv = {}
    _mgr(FakeApi(READER), kv).refresh()
    assert _mgr(FakeApi(err), kv).refresh() == UNREACHABLE
    assert lg.current().role == "READER" and "assignment_cache" in kv


def test_the_cache_of_another_installation_is_ignored():
    kv = {}
    _mgr(FakeApi(READER), kv).refresh()
    lg.reset_for_tests()
    assert not _mgr(FakeApi(READER), kv, uuid="uuid-2").load_cache()
    assert lg.current().mode == lg.MODE_ALL


def test_a_new_lease_is_add_only_until_its_ownership_backup_is_restored():
    kv, changes = {}, []
    m = _mgr(FakeApi(DRIVER), kv, changes=changes)
    m.refresh()
    assert lg.device_allowed(8) and lg.removals_blocked(8) == "add_only"
    m.mark_restored(8, 3)
    assert lg.removals_blocked(8) is None
    assert len(changes) == 2, "restoring changes what the engines may do"
    # A new generation (the lease moved away and back) needs a new restore.
    moved = dict(DRIVER, drive=[dict(DRIVER["drive"][0], generation=5)])
    m._api = FakeApi(moved)
    m.refresh()
    assert lg.removals_blocked(8) == "add_only"

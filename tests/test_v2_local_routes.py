"""P3b-2 step 8: the local routes the Access UI uses for roles, reader history and requests."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from access import v2_routes
from app.core.v2 import lease_gate as lg
from app.core.v2.api import V2ApiError


@pytest.fixture(autouse=True)
def _gate():
    lg.reset_for_tests()
    yield
    lg.reset_for_tests()


class Ctx:
    def __init__(self, app, params=None, body=None, q=None):
        self.app, self._p, self._b, self._q = app, params or {}, body or {}, q or {}
        self.sent = None

    def param_int(self, name, default=0):
        return int(self._p.get(name, default))

    def body(self):
        return dict(self._b)

    def q(self, name, default=None):
        return self._q.get(name, default)

    def send_json(self, status, payload):
        self.sent = (status, payload)


class Api:
    def __init__(self):
        self.requests = []

    def request_command(self, body):
        self.requests.append(body)
        return {"command": {"id": body["id"], "targetPcId": 101}, "created": True, "targetConnected": True}

    def reader_door_history(self, before, limit):
        return {"turnstiles": [{"gymDeviceId": 8, "name": "Sortie", "driverPcId": 101, "driverPcName": "Accueil"}],
                "items": [{"id": 5}], "nextBeforeId": None}


def _rt(availability="ON"):
    return SimpleNamespace(availability=availability, api=Api(), status=lambda: {"availability": availability})


def test_the_routes_are_registered():
    from access.local_api_routes import register_access_local_api_routes
    added = []
    register_access_local_api_routes(SimpleNamespace(add=lambda m, p, h: added.append((m, p))))
    for method, pattern, _h in v2_routes.ROUTES:
        assert (method, pattern) in added


def test_status_without_a_runtime_reports_the_installed_roles():
    ctx = Ctx(SimpleNamespace())
    v2_routes._handle_v2_status(ctx)
    assert ctx.sent[0] == 200 and ctx.sent[1]["availability"] == "NOT_STARTED" and ctx.sent[1]["mode"] == "ALL"


def test_a_reader_files_a_door_request_it_never_opens_the_door_itself():
    app = SimpleNamespace(_v2_runtime=_rt())
    ctx = Ctx(app, {"deviceId": 8}, {"doorNumber": 2})
    v2_routes._handle_v2_request_door(ctx)
    assert ctx.sent[0] == 202 and ctx.sent[1]["targetPcId"] == 101 and ctx.sent[1]["targetConnected"]
    [body] = app._v2_runtime.api.requests
    assert body["type"] == "DOOR_OPEN" and body["gymDeviceId"] == 8 and body["payload"] == {"doorNumber": 2}
    assert "targetPcId" not in body, "the server routes it to the turnstile's driver"


def test_a_request_is_refused_while_the_server_has_no_v2():
    ctx = Ctx(SimpleNamespace(_v2_runtime=_rt("OFF")), {"deviceId": 8})
    v2_routes._handle_v2_request_resync(ctx)
    assert ctx.sent[0] == 409 and ctx.sent[1]["code"] == "REALTIME_OFF"


def test_a_server_refusal_is_passed_on_with_its_code():
    rt = _rt()
    rt.api.request_command = lambda body: (_ for _ in ()).throw(V2ApiError(409, "DEVICE_HAS_NO_DRIVER", backend=True))
    ctx = Ctx(SimpleNamespace(_v2_runtime=rt), {"deviceId": 8})
    v2_routes._handle_v2_request_door(ctx)
    assert ctx.sent[0] == 409 and ctx.sent[1]["code"] == "DEVICE_HAS_NO_DRIVER"


def test_reader_history_is_the_servers_page():
    ctx = Ctx(SimpleNamespace(_v2_runtime=_rt()), q={"limit": "20"})
    v2_routes._handle_v2_reader_history(ctx)
    assert ctx.sent[0] == 200 and ctx.sent[1]["available"] and ctx.sent[1]["items"] == [{"id": 5}]


def test_a_readers_enrolment_lists_each_turnstile_as_waiting_for_its_driver():
    lg.install(lg.snapshot_from_assignment({"gymUsesAssignments": True, "role": "READER", "drive": [],
                                            "release": [], "readerOf": []}, source="server"))
    ctx = Ctx(SimpleNamespace(_v2_runtime=_rt()))
    v2_routes._handle_v2_enroll_turnstiles(ctx)
    assert ctx.sent[1]["turnstiles"] == [{"gymDeviceId": 8, "name": "Sortie", "driverPcName": "Accueil",
                                          "status": "PENDING_DRIVER"}]


def test_without_assignments_every_local_turnstile_is_this_pcs(monkeypatch):
    monkeypatch.setattr("app.core.db.list_sync_devices_payload", lambda: [{"id": 8, "name": "Sortie"}])
    ctx = Ctx(SimpleNamespace())
    v2_routes._handle_v2_enroll_turnstiles(ctx)
    assert ctx.sent[1]["turnstiles"][0]["status"] == "THIS_PC"


class _DoorCtx(Ctx):
    def param_int(self, name, default=0):
        return int(self._p.get(name, default))


def _door_handler_ran():
    ran = []

    def _handle_device_door_open(ctx):
        ran.append(ctx)
    return ran, _handle_device_door_open


def _reader():
    lg.install(lg.snapshot_from_assignment({"gymUsesAssignments": True, "role": "READER",
                                            "drive": [], "release": [], "readerOf": []}, source="server"))


def test_round5_every_door_caller_on_a_reader_files_the_request_on_the_server(monkeypatch):
    """The tray menu, the favourite shortcuts, the overlay and the tray panel all POST the local
    door route: the gate files the request for them (202 requested), never opens the door."""
    from access.local_api_routes import gated_handler
    import app.api.local_access_api_v2 as la2
    monkeypatch.setattr(la2, "_door_open_last", {})
    _reader()
    rt = _rt()
    ran, h = _door_handler_ran()
    ctx = _DoorCtx(SimpleNamespace(_v2_runtime=rt), {"deviceId": 8}, {"doorNumber": 2, "pulseSeconds": 3})
    gated_handler(h)(ctx)
    status, body = ctx.sent
    assert ran == [] and status == 202 and body["ok"] and body["requested"] and body["notDriver"]
    assert rt.api.requests[0]["type"] == "DOOR_OPEN" and rt.api.requests[0]["payload"] == {"doorNumber": 2}
    ctx2 = _DoorCtx(SimpleNamespace(_v2_runtime=rt), {"deviceId": 8}, {"doorNumber": 2})
    gated_handler(h)(ctx2)                               # a held shortcut: the 1 s cooldown
    assert ctx2.sent[0] == 429 and len(rt.api.requests) == 1


@pytest.mark.parametrize("availability", ["OFF", "UNKNOWN", None])
def test_round5_without_v2_on_the_reader_answers_not_driver_as_before(monkeypatch, availability):
    from access.local_api_routes import gated_handler
    import app.api.local_access_api_v2 as la2
    monkeypatch.setattr(la2, "_door_open_last", {})
    _reader()
    app = SimpleNamespace(_v2_runtime=_rt(availability) if availability else None)
    ran, h = _door_handler_ran()
    ctx = _DoorCtx(app, {"deviceId": 8}, {"doorNumber": 1})
    gated_handler(h)(ctx)
    assert ran == [] and ctx.sent[0] == 409 and ctx.sent[1]["notDriver"]


def test_round5_other_device_routes_still_answer_not_driver(monkeypatch):
    from access.local_api_routes import gated_handler
    _reader()
    ran = []

    def _handle_device_info(ctx):
        ran.append(1)
    ctx = _DoorCtx(SimpleNamespace(_v2_runtime=_rt()), {"deviceId": 8})
    gated_handler(_handle_device_info)(ctx)
    assert ran == [] and ctx.sent[0] == 409

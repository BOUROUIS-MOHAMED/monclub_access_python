from __future__ import annotations

from types import SimpleNamespace

from access.local_api_routes import ACCESS_LOCAL_ROUTE_SPECS, register_access_local_api_routes
from access.pc_identity import PcIdentityApiError


class _Ctx:
    def __init__(self, *, body=None, params=None) -> None:
        self.app = SimpleNamespace()
        self._request_body = body or {}
        self._params = params or {}
        self.sent = []

    def body(self):
        return self._request_body

    def param_int(self, name, default=0):
        try:
            return int(self._params.get(name, default))
        except (TypeError, ValueError):
            return default

    def send_json(self, status, payload):
        self.sent.append((status, payload))


class _Service:
    def __init__(self) -> None:
        self.register_names = []
        self.adopt_ids = []

    def status(self):
        return {"registered": False, "state": "first_run"}

    def list_pcs(self):
        return {
            "pcs": [{"id": 7, "name": "Réception", "status": "ACTIVE", "stale": False}],
            "cap": 2,
            "activeCount": 1,
            "stalenessWindowDays": 30,
        }

    def register(self, *, name):
        self.register_names.append(name)
        return {
            "id": 8,
            "pcUuid": "uuid-new",
            "pcSecret": "must-never-reach-webview",
            "name": name,
            "status": "ACTIVE",
            "tokenReady": True,
        }

    def adopt(self, *, pc_id):
        self.adopt_ids.append(pc_id)
        return {
            "id": pc_id,
            "pcUuid": "uuid-adopted",
            "pcSecret": "must-never-reach-webview",
            "name": "Réception",
            "status": "ACTIVE",
            "tokenReady": True,
        }


def test_pc_identity_routes_are_registered_from_access_owned_handlers() -> None:
    expected = {
        ("GET", "/api/v2/pc-identity/status", "_handle_pc_identity_status"),
        ("GET", "/api/v2/pc-identity/pcs", "_handle_pc_identity_list"),
        ("POST", "/api/v2/pc-identity/register", "_handle_pc_identity_register"),
        ("POST", "/api/v2/pc-identity/pcs/{pcId}/adopt", "_handle_pc_identity_adopt"),
    }
    assert expected.issubset(set(ACCESS_LOCAL_ROUTE_SPECS))

    registered = []
    router = SimpleNamespace(add=lambda method, pattern, handler: registered.append((method, pattern, handler)))
    register_access_local_api_routes(router)

    handlers = {handler.__name__: handler.__module__ for _, _, handler in registered}
    assert handlers["_handle_pc_identity_status"] == "access.pc_identity_routes"
    assert handlers["_handle_pc_identity_register"] == "access.pc_identity_routes"


def test_status_and_list_return_service_data(monkeypatch) -> None:
    from access import pc_identity_routes as routes

    service = _Service()
    monkeypatch.setattr(routes, "_service", lambda _ctx: service)
    status_ctx = _Ctx()
    list_ctx = _Ctx()

    routes._handle_pc_identity_status(status_ctx)
    routes._handle_pc_identity_list(list_ctx)

    assert status_ctx.sent == [(200, {"ok": True, "registered": False, "state": "first_run"})]
    assert list_ctx.sent[0][0] == 200
    assert list_ctx.sent[0][1]["pcs"][0]["name"] == "Réception"


def test_registration_never_returns_the_pc_secret_to_the_webview(monkeypatch) -> None:
    from access import pc_identity_routes as routes

    service = _Service()
    monkeypatch.setattr(routes, "_service", lambda _ctx: service)
    ctx = _Ctx(body={"name": " Accueil "})

    routes._handle_pc_identity_register(ctx)

    assert service.register_names == ["Accueil"]
    assert ctx.sent[0][0] == 201
    assert ctx.sent[0][1]["pcUuid"] == "uuid-new"
    assert "pcSecret" not in ctx.sent[0][1]


def test_cap_reached_response_explicitly_drives_takeover(monkeypatch) -> None:
    from access import pc_identity_routes as routes

    error = PcIdentityApiError(
        status_code=409,
        code="ACCESS_PC_CAP_REACHED",
        message="cap reached",
        details={"cap": 2, "activeCount": 2},
    )
    service = SimpleNamespace(register=lambda **_kwargs: (_ for _ in ()).throw(error))
    monkeypatch.setattr(routes, "_service", lambda _ctx: service)
    ctx = _Ctx(body={"name": "Accueil"})

    routes._handle_pc_identity_register(ctx)

    assert ctx.sent == [
        (
            409,
            {
                "ok": False,
                "error": "cap reached",
                "code": "ACCESS_PC_CAP_REACHED",
                "details": {"cap": 2, "activeCount": 2},
                "cap": 2,
                "activeCount": 2,
                "takeoverRequired": True,
            },
        )
    ]


def test_takeover_uses_the_selected_existing_row_and_hides_rotated_secret(monkeypatch) -> None:
    from access import pc_identity_routes as routes

    service = _Service()
    monkeypatch.setattr(routes, "_service", lambda _ctx: service)
    monkeypatch.setattr(routes, "wake_pc_identity_runtime", lambda _app: None)
    ctx = _Ctx(params={"pcId": "7"})

    routes._handle_pc_identity_adopt(ctx)

    assert service.adopt_ids == [7]
    assert ctx.sent[0][0] == 200
    assert ctx.sent[0][1]["id"] == 7
    assert "pcSecret" not in ctx.sent[0][1]

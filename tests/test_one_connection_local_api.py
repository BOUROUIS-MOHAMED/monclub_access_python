"""One connection per turnstile: the local API never opens a second one while a ULTRA worker
holds the device (owner, 2026-10-16; guide §3.1a "One connection per turnstile").

``/devices/{id}/info``, ``/table/{name}`` and ``/users`` used to call ``_connect_device`` (a
one-shot ``PullSDK.connect``) even when this PC's ULTRA worker held the turnstile. They now run
on the worker's held connection through ``_run_on_device_sdk`` -> ``request_run_sdk``, as the
settings/clock handlers already did. A table read on the worker blocks its loop (rtlog, doors),
so it counts first and refuses a table above ``_LIVE_TABLE_READ_MAX_ROWS``.
"""

from __future__ import annotations

import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import app.api.local_access_api_v2 as la2
from app.sdk.pullsdk import PullSDK, PullSDKDevice


DID = 8


class _Ctx:
    def __init__(self, app, *, params=None, query=None, body=None):
        self.app = app
        self._params = {"deviceId": str(DID), **(params or {})}
        self._query = query or {}
        self._body = body or {}
        self.sent = []

    def param(self, name):
        return self._params.get(name, "")

    def param_int(self, name, default=0):
        try:
            return int(self._params.get(name, default))
        except (TypeError, ValueError):
            return default

    def q(self, *names, default=""):
        for n in names:
            if n in self._query:
                return self._query[n]
        return default

    def q_int(self, *names, default=0):
        v = self.q(*names, default="")
        try:
            return int(v)
        except (TypeError, ValueError):
            return default

    def body(self):
        return dict(self._body)

    def send_json(self, status, payload):
        self.sent.append((status, payload))

    @property
    def last(self):
        assert self.sent, "the handler answered nothing"
        return self.sent[-1]


def _raw(rows=None, count=None):
    """The worker's held low-level PullSDK handle."""
    raw = MagicMock(spec=PullSDK)
    raw.supports_get_device_param.return_value = True
    raw.get_device_param.return_value = "~DeviceName=C3-200,~SerialNumber=SN1"
    rows = list(rows or [])
    raw.get_device_data_rows.return_value = rows
    raw.get_device_data_count.return_value = len(rows) if count is None else count
    raw.supports_delete_device_data.return_value = True
    raw.set_device_data.return_value = 0
    raw.delete_device_data.return_value = 0
    return raw


def _driver(raw):
    """The worker's driver: a real PullSDKDevice whose held handle is ``raw``."""
    drv = PullSDKDevice({"id": DID, "ip": "192.0.2.8", "port": 4370})
    drv._sdk = raw
    drv._connected = raw is not None
    return drv


class _Worker:
    """Runs fn on the worker's driver, as ``_drain_sdk_commands`` does, unless told to answer
    with a canned box (what ``request_run_sdk`` returns when nothing ran, or no answer came)."""

    def __init__(self, drv, answer=None):
        self._sdk = drv
        self._connected = True
        self.answer = answer
        self.calls = []

    def _down_for_seconds(self):
        return 0.0

    def request_run_sdk(self, fn, *, label, timeout):
        self.calls.append((label, timeout))
        if self.answer is not None:
            return dict(self.answer)
        try:
            return {"ok": True, "result": fn(self._sdk), "error": ""}
        except Exception as e:
            return {"ok": False, "result": None, "error": str(e)}


def _app(worker):
    return SimpleNamespace(_ultra_engine=SimpleNamespace(running=True, _workers={DID: worker}),
                           cfg=SimpleNamespace(plcomm_dll_path=""), logger=MagicMock())


@pytest.fixture(autouse=True)
def _no_second_connection(monkeypatch):
    """Any second connection fails the test: the one-shot helper and the DLL connect itself."""
    monkeypatch.setattr(la2, "_device_protocol_of", lambda did: "ZK_PULLSDK")
    monkeypatch.setattr(la2, "_connect_device",
                        lambda *a, **k: pytest.fail("a second connection was opened (_connect_device)"))
    monkeypatch.setattr(PullSDK, "connect",
                        lambda *a, **k: pytest.fail("a second connection was opened (PullSDK.connect)"))


# ─────────────────────────────── /info ───────────────────────────────

def test_info_reads_on_the_worker_connection_never_a_second_one():
    raw = _raw()
    raw.get_device_data_count.side_effect = lambda table, **kw: {"user": 914, "transaction": 50000}.get(table, 0)
    worker = _Worker(_driver(raw))
    ctx = _Ctx(_app(worker))
    la2._handle_device_info(ctx)
    status, payload = ctx.last
    assert status == 200 and payload["ok"] is True
    assert payload["params"] == {"~DeviceName": "C3-200", "~SerialNumber": "SN1"}
    assert payload["counts"]["user"] == 914 and payload["counts"]["transaction"] == 50000
    assert payload["raw"] == "~DeviceName=C3-200,~SerialNumber=SN1"
    assert [c[0] for c in worker.calls] == ["device_info"]
    raw.get_device_data_rows.assert_not_called()       # counts only: no table is read
    raw.disconnect.assert_not_called()                  # the worker's connection stays up


def test_info_drops_a_refused_count_as_before():
    raw = _raw()
    raw.get_device_data_count.side_effect = lambda table, **kw: -1 if table == "holiday" else 3
    ctx = _Ctx(_app(_Worker(_driver(raw))))
    la2._handle_device_info(ctx)
    assert "holiday" not in ctx.last[1]["counts"] and ctx.last[1]["counts"]["user"] == 3


@pytest.mark.parametrize("error,status", [
    ("timeout", 503), ("device not connected", 503), ("expired (not executed)", 503),
    ("sent, no answer", 500), ("GetDeviceData FAILED rc=-2", 500),
])
def test_info_maps_worker_errors_like_the_control_panel(error, status):
    ctx = _Ctx(_app(_Worker(_driver(_raw()), answer={"ok": False, "result": None, "error": error})))
    la2._handle_device_info(ctx)
    assert ctx.last == (status, {"ok": False, "error": error})


def test_a_worker_without_its_handle_answers_not_connected_nothing_sent():
    ctx = _Ctx(_app(_Worker(_driver(None))))
    la2._handle_device_info(ctx)
    assert ctx.last == (503, {"ok": False, "error": "device not connected"})


# ─────────────────────────────── /table ───────────────────────────────

def test_table_reads_on_the_worker_and_keeps_its_shape():
    rows = [{"Pin": str(i)} for i in range(300)]
    raw = _raw(rows)
    worker = _Worker(_driver(raw))
    ctx = _Ctx(_app(worker), params={"tableName": "user"}, query={"maxRows": "250"})
    la2._handle_device_table(ctx)
    status, payload = ctx.last
    assert status == 200
    assert payload == {"ok": True, "table": "user", "rows": rows[:250], "count": 300}
    raw.get_device_data_count.assert_called_once_with(table="user", filter_expr="")
    assert worker.calls[0][0] == "table_read:user"


def test_a_table_above_the_cap_is_refused_before_it_is_read():
    raw = _raw(count=la2._LIVE_TABLE_READ_MAX_ROWS + 1)
    ctx = _Ctx(_app(_Worker(_driver(raw))), params={"tableName": "transaction"}, query={"maxRows": "250"})
    la2._handle_device_table(ctx)
    status, payload = ctx.last
    assert status == 409 and payload["code"] == "TABLE_TOO_LARGE_FOR_LIVE_READ"
    assert payload["count"] == la2._LIVE_TABLE_READ_MAX_ROWS + 1
    assert payload["maxRows"] == la2._LIVE_TABLE_READ_MAX_ROWS
    assert "Lecture refusée" in payload["error"]
    raw.get_device_data_rows.assert_not_called()


def test_a_table_at_the_cap_is_read():
    raw = _raw([{"Pin": "1"}], count=la2._LIVE_TABLE_READ_MAX_ROWS)
    ctx = _Ctx(_app(_Worker(_driver(raw))), params={"tableName": "user"})
    la2._handle_device_table(ctx)
    assert ctx.last[0] == 200
    raw.get_device_data_rows.assert_called_once()


def test_a_table_whose_size_cannot_be_read_is_not_read_on_the_worker():
    raw = _raw(count=-1)
    ctx = _Ctx(_app(_Worker(_driver(raw))), params={"tableName": "templatev10"})
    la2._handle_device_table(ctx)
    status, payload = ctx.last
    assert status == 409 and payload["count"] is None and "n'a pas pu être lu" in payload["error"]
    raw.get_device_data_rows.assert_not_called()


def test_without_a_worker_the_one_shot_read_is_not_capped(monkeypatch):
    raw = _raw([{"Pin": "1"}], count=10 ** 6)
    monkeypatch.setattr(la2, "_connect_device", lambda ctx, did: (raw, None))
    ctx = _Ctx(SimpleNamespace(_ultra_engine=None), params={"tableName": "transaction"})
    la2._handle_device_table(ctx)
    assert ctx.last == (200, {"ok": True, "table": "transaction", "rows": [{"Pin": "1"}], "count": 1})
    raw.get_device_data_count.assert_not_called()
    raw.disconnect.assert_called_once()


def test_without_a_worker_a_failed_connect_is_503_nothing_sent(monkeypatch):
    monkeypatch.setattr(la2, "_connect_device", lambda ctx, did: (None, "connect failed"))
    ctx = _Ctx(SimpleNamespace(_ultra_engine=None), params={"tableName": "user"})
    la2._handle_device_table(ctx)
    assert ctx.last == (503, {"ok": False, "error": "connect failed"})


# ─────────────────────────────── /users ───────────────────────────────

def test_users_list_reads_on_the_worker_and_keeps_its_shape():
    raw = _raw([{"Pin": "101", "Name": "A", "CardNo": "55"}])
    worker = _Worker(_driver(raw))
    ctx = _Ctx(_app(worker))
    la2._handle_device_users_list(ctx)
    assert ctx.last == (200, {"ok": True, "users": [{"pin": "101", "name": "A", "cardNo": "55"}]})
    raw.get_device_data_rows.assert_called_once_with(table="user", fields="Pin;Name;CardNo",
                                                     filter_expr="", options="")
    assert worker.calls[0][0] == "users_list"


def test_users_list_above_the_cap_is_refused():
    raw = _raw(count=la2._LIVE_TABLE_READ_MAX_ROWS + 5)
    ctx = _Ctx(_app(_Worker(_driver(raw))))
    la2._handle_device_users_list(ctx)
    assert ctx.last[0] == 409 and ctx.last[1]["table"] == "user"
    raw.get_device_data_rows.assert_not_called()


# ───────────────────── end to end through the real worker queue ─────────────────────

def test_info_goes_through_the_real_worker_queue():
    from tests.test_ultra_engine import _make_worker

    raw = _raw()
    worker = _make_worker()
    worker._connected = True
    worker._sdk = _driver(raw)
    stop = threading.Event()

    def _drainer():
        while not stop.is_set():
            worker._drain_sdk_commands()
            stop.wait(0.005)

    t = threading.Thread(target=_drainer, daemon=True)
    t.start()
    try:
        ctx = _Ctx(_app(worker))
        la2._handle_device_info(ctx)
    finally:
        stop.set()
        t.join(2.0)
    assert ctx.last[0] == 200 and ctx.last[1]["params"]["~DeviceName"] == "C3-200"
    raw.get_device_param.assert_called_once()


# ─────────────────────── writes: /users/push and /users/delete ───────────────────────

@pytest.fixture()
def writes(monkeypatch, tmp_path):
    """A temp database (the template push reads firmware profiles), no hold, no hand-over,
    a recorded reset, a device with no stored payload."""
    from app.core import device_hold
    from app.core.v2 import lease_gate
    import app.core.db as dbmod

    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "test.db"), raising=False)
    dbmod.init_db()

    state = {"held": False, "frozen": False, "order": []}
    monkeypatch.setattr(device_hold, "is_held", lambda did: state["held"])
    monkeypatch.setattr(lease_gate, "writes_frozen", lambda did: state["frozen"])
    monkeypatch.setattr(dbmod, "reset_push_results_for_pins",
                        lambda device_id, pins: state["order"].append(("reset", device_id, tuple(pins))))
    monkeypatch.setattr(dbmod, "get_sync_device_payload", lambda did: {})
    return state


def _push_ctx(worker):
    return _Ctx(_app(worker), body={"pin": "101", "name": "A", "cardNo": "55", "doorIds": [1, 2]})


def test_users_push_writes_on_the_worker_connection(writes):
    raw = _raw()
    raw.set_device_data.side_effect = lambda **kw: writes["order"].append(("write", kw["table"])) or 0
    worker = _Worker(_driver(raw))
    ctx = _push_ctx(worker)
    la2._handle_device_users_push(ctx)
    status, payload = ctx.last
    assert status == 200 and payload["ok"] is True and payload["authResult"] == "OK"
    assert payload["templateResult"] == "0/0 pushed" and payload["errors"] == []
    # The pin's result is reset to unknown before the first write (contract 4.1 §1.1).
    assert writes["order"][:3] == [("reset", DID, ("101",)), ("write", "user"), ("write", "userauthorize")]
    datas = [c.kwargs["data"] for c in raw.set_device_data.call_args_list]
    assert datas == ["Pin=101\tName=A\tCardNo=55\r\n",
                     "Pin=101\tAuthorizeTimezoneId=1\tAuthorizeDoorId=3\r\n"]
    assert worker.calls == [("users_push", la2._USER_WRITE_TIMEOUT_SEC)]


def test_users_push_sent_no_answer_is_unknown_never_a_clean_failure(writes):
    ctx = _push_ctx(_Worker(_driver(_raw()), answer={"ok": False, "result": None, "error": "sent, no answer"}))
    la2._handle_device_users_push(ctx)
    status, payload = ctx.last
    assert status == 500 and payload["outcome"] == "unknown" and payload["detail"] == "sent, no answer"
    assert "peut-être été écrit" in payload["error"]
    assert writes["order"] == [("reset", DID, ("101",))], "the result stays unknown"


def test_users_push_not_taken_by_the_worker_is_503_nothing_sent(writes):
    raw = _raw()
    ctx = _push_ctx(_Worker(_driver(raw), answer={"ok": False, "result": None, "error": "timeout"}))
    la2._handle_device_users_push(ctx)
    assert ctx.last == (503, {"ok": False, "error": "timeout"})
    raw.set_device_data.assert_not_called()


@pytest.mark.parametrize("guard,code", [("held", "DEVICE_ON_HOLD"), ("frozen", "HANDOVER_IN_PROGRESS")])
def test_users_push_guards_refuse_before_anything_is_queued(writes, guard, code):
    writes[guard] = True
    worker = _Worker(_driver(_raw()))
    ctx = _push_ctx(worker)
    la2._handle_device_users_push(ctx)
    assert ctx.last[0] == 409 and ctx.last[1]["code"] == code
    assert worker.calls == [] and writes["order"] == []


def test_users_delete_deletes_on_the_worker_connection(writes):
    raw = _raw()
    worker = _Worker(_driver(raw))
    ctx = _Ctx(_app(worker), body={"pin": "101"})
    la2._handle_device_users_delete(ctx)
    assert ctx.last == (200, {"ok": True})
    assert [c.kwargs["table"] for c in raw.delete_device_data.call_args_list] == \
        ["templatev10", "template", "userauthorize", "user"]
    assert all(c.kwargs["data"] == "Pin=101" for c in raw.delete_device_data.call_args_list)
    assert worker.calls == [("users_delete", la2._USER_WRITE_TIMEOUT_SEC)]


def test_users_delete_sent_no_answer_is_unknown(writes):
    ctx = _Ctx(_app(_Worker(_driver(_raw()), answer={"ok": False, "result": None, "error": "sent, no answer"})),
               body={"pin": "101"})
    la2._handle_device_users_delete(ctx)
    status, payload = ctx.last
    assert status == 500 and payload["outcome"] == "unknown" and "peut-être été supprimé" in payload["error"]


@pytest.mark.parametrize("guard,code", [("held", "DEVICE_ON_HOLD"), ("frozen", "HANDOVER_IN_PROGRESS")])
def test_users_delete_guards_refuse_before_anything_is_queued(writes, guard, code):
    writes[guard] = True
    worker = _Worker(_driver(_raw()))
    ctx = _Ctx(_app(worker), body={"pin": "101"})
    la2._handle_device_users_delete(ctx)
    assert ctx.last[0] == 409 and ctx.last[1]["code"] == code and worker.calls == []


# ─────────────────────── manual session: /connect and /disconnect ───────────────────────

@pytest.fixture()
def pool(monkeypatch):
    p = {}
    monkeypatch.setattr(la2, "_device_sdk_pool", p)
    return p


def test_connect_is_refused_while_the_worker_holds_the_turnstile(pool):
    ctx = _Ctx(_app(_Worker(_driver(_raw()))))
    la2._handle_device_connect(ctx)
    status, payload = ctx.last
    assert status == 409 and payload["code"] == "HELD_BY_ULTRA_WORKER"
    assert payload["error"].startswith("La connexion à ce tourniquet est tenue par le service ULTRA")
    assert pool == {}


def test_connect_without_a_worker_still_opens_the_manual_session(pool, monkeypatch):
    sdk = MagicMock()
    monkeypatch.setattr(la2, "_connect_device", lambda ctx, did: (sdk, None))
    ctx = _Ctx(SimpleNamespace(_ultra_engine=SimpleNamespace(running=True, _workers={})))
    la2._handle_device_connect(ctx)
    assert ctx.last == (200, {"ok": True}) and pool == {DID: sdk}


def test_disconnect_with_nothing_manual_open_does_not_claim_it_disconnected(pool):
    drv = _driver(_raw())
    ctx = _Ctx(_app(_Worker(drv)))
    la2._handle_device_disconnect(ctx)
    assert ctx.last[0] == 409 and ctx.last[1]["code"] == "HELD_BY_ULTRA_WORKER"
    drv._sdk.disconnect.assert_not_called()             # the worker's connection is untouched


def test_disconnect_always_closes_a_manual_session_even_with_a_worker(pool):
    manual = MagicMock()
    pool[DID] = manual
    ctx = _Ctx(_app(_Worker(_driver(_raw()))))
    la2._handle_device_disconnect(ctx)
    assert ctx.last == (200, {"ok": True}) and pool == {}
    manual.disconnect.assert_called_once()


def test_disconnect_without_a_worker_is_unchanged(pool):
    ctx = _Ctx(SimpleNamespace(_ultra_engine=None))
    la2._handle_device_disconnect(ctx)
    assert ctx.last == (200, {"ok": True})

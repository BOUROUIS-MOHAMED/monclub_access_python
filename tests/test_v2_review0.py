"""P3b-2 self-review before the independent reviews (advisor checkpoint).

1. A PC whose lease was taken away (a forced move: no release[], the entry just leaves drive[])
   writes nothing more to that turnstile from that moment -- not only once the engine restarts.
2. The desk card scanner and the network discovery connect by IP address: a reader never
   reaches a turnstile through them either.
3. A removal logged before a state this PC already uploaded never resurfaces as the newest fact.
4. The connect-time user count is compared off the door thread (no DB write on the worker).
5. Repeated "unreachable" assignment probes back off to 30 minutes.
"""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

import app.core.db as dbmod
from app.core.v2 import lease_gate as lg
from app.core.v2 import loss
from app.core.v2 import ownership as own
from app.core.v2 import timefmt
from app.core.v2.server_clock import ServerClock
from tests.test_standalone_finger_removal_state import FingerState, fstate  # noqa: F401
from tests.test_standalone_incremental_sync import _user, _worker


@pytest.fixture(autouse=True)
def _gate():
    lg.reset_for_tests()
    yield
    lg.reset_for_tests()


def _driver_of(*dids):
    lg.install(lg.snapshot_from_assignment(
        {"gymUsesAssignments": True, "role": "DRIVER", "readerOf": [], "release": [],
         "drive": [{"gymDeviceId": d, "generation": 1, "state": "DRIVE", "handoverForced": False} for d in dids]},
        source="server"))


# ------------------------------------------------------------------ 1
def test_a_lost_lease_stops_every_write_at_once(monkeypatch, fstate):
    w, _c = _worker(monkeypatch, users=[_user(30001, "a", "")])
    _driver_of(w._device_id + 1000)                       # this turnstile moved to another PC
    assert w.request_full_sync(reason="timer", fingerprint_hash="h") is True
    assert w._drain_full_sync_commands(limit=1) == 0
    assert w._pending_full_sync_request is not None, "kept queued (the engine drops the worker)"
    w._pending_member_syncs.append(30001)
    assert w._drain_member_sync_commands(limit=1) == 0


def test_writes_resume_while_the_pc_drives_the_turnstile(monkeypatch, fstate):
    w, _c = _worker(monkeypatch, users=[_user(30001, "a", "")])
    _driver_of(w._device_id)
    assert w.request_full_sync(reason="timer", fingerprint_hash="h") is True
    assert w._drain_full_sync_commands(limit=1) == 1


# ------------------------------------------------------------------ 2
class Ctx:
    def __init__(self, body):
        self._b = body
        self.app = SimpleNamespace()
        self.sent = None

    def body(self):
        return dict(self._b)

    def send_json(self, status, payload):
        self.sent = (status, payload)


@pytest.fixture
def turnstiles(monkeypatch):
    monkeypatch.setattr("app.core.db.list_sync_devices_payload",
                        lambda: [{"id": 8, "ipAddress": "192.168.1.8"}, {"id": 10, "ipAddress": "192.168.1.10"}])
    import app.api.local_access_api_v2 as la2
    monkeypatch.setattr(la2, "_get_runtime_access_config",
                        lambda ctx: SimpleNamespace(scanner_mode="zkemkeeper", scanner_network_ip="192.168.1.8"))


@pytest.mark.parametrize("name", ["_handle_scan_start", "_handle_scan_quick", "_handle_scanner_start"])
def test_a_reader_never_starts_the_scanner_on_a_turnstiles_address(turnstiles, name):
    from access.local_api_routes import SCANNER_GATED_HANDLERS, scanner_gated_handler
    assert name in SCANNER_GATED_HANDLERS
    _driver_of(10)
    ran = []
    ctx = Ctx({})
    scanner_gated_handler(lambda c: ran.append(1))(ctx)
    assert ctx.sent[0] == 409 and ctx.sent[1]["notDriver"] and ran == []
    ctx2 = Ctx({"ip": "192.168.1.10"})                  # the turnstile it drives
    scanner_gated_handler(lambda c: ran.append(1))(ctx2)
    ctx3 = Ctx({"mode": "usb"})                         # a USB reader is not a turnstile
    scanner_gated_handler(lambda c: ran.append(1))(ctx3)
    assert ran == [1, 1]


def test_without_assignments_the_scanner_is_unchanged(turnstiles):
    from access.local_api_routes import scanner_gated_handler
    ran = []
    scanner_gated_handler(lambda c: ran.append(1))(Ctx({}))
    assert ran == [1]


def test_discovery_never_probes_a_turnstile_this_pc_does_not_drive(turnstiles, monkeypatch):
    import app.core.network_discovery as nd
    from app.core.v2.device_ips import undriven_ips
    probed = []
    monkeypatch.setattr(nd, "_probe_port", lambda ip, port, timeout: probed.append(ip) or False)
    _driver_of(10)
    nd.scan_subnet(subnet="192.168.1.0/28", do_handshake=False, skip_ips=undriven_ips())
    assert "192.168.1.8" not in probed and "192.168.1.10" in probed and len(probed) == 13


# ------------------------------------------------------------------ 3
@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "r0.db"), raising=False)
    dbmod.init_db()
    yield dbmod
    dbmod._shutdown_db_writer_for_tests()


def test_an_older_removal_never_resurfaces_after_a_later_upload(db, monkeypatch):
    # 1) MonClub removes pin 100 (logged), 2) the pin is written again and uploaded APPLIED,
    # 3) its state row goes away without a device removal (a prune).
    db.clear_device_revocation_state(device_id=8, pin="100")
    db._run_db_write_sync("s", lambda c, p: c.execute(
        "INSERT INTO device_sync_state (device_id, pin, desired_hash, last_ok, updated_at, ownership_confirmed) "
        "VALUES (8, '100', 'h', 1, ?, 1)", (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() + 5)),)))
    clock = ServerClock()
    now = time.time()
    clock.add_sample(now, now, now, source="t")
    sent = []
    api = SimpleNamespace(ownership_page=lambda did, a, l: {"generation": 1, "pinScheme": "MEMBERSHIP", "rows": []},
                          ownership_upload=lambda body: (sent.append(body), {"stored": len(body["rows"])})[1])
    sync = own.OwnershipSync(SimpleNamespace(api=api, clock=clock))
    monkeypatch.setattr(sync, "_device_scheme", lambda did: "MEMBERSHIP")
    time.sleep(0.01)
    sync.upload(8)
    assert [r["state"] for r in sent[-1]["rows"]] == ["APPLIED"]
    db._run_db_write_sync("prune", lambda c, p: c.execute("DELETE FROM device_sync_state WHERE pin='100'"))
    n = len(sent)
    sync.upload(8)
    assert len(sent) == n, "the old REMOVED is not a newer fact: nothing is sent"


# ------------------------------------------------------------------ 4
def test_the_connect_time_count_is_compared_off_the_worker_thread(monkeypatch, fstate, db):
    w, _c = _worker(monkeypatch, users=[])
    w._sdk = SimpleNamespace(owns_event_source=True, _device_status={"users": 900})

    def no_write(*a, **k):
        raise AssertionError("a database write on the worker thread at connect")

    real = dbmod._run_db_write_sync
    dbmod._run_db_write_sync = no_write
    try:
        w._note_user_count_at_connect()
    finally:
        dbmod._run_db_write_sync = real
    loss.pop_user_counts()
    # The control thread's LossWatch does the comparison and flags the worker.
    rt = SimpleNamespace(app=SimpleNamespace(_ultra_engine=SimpleNamespace(_workers={w._device_id: w})))
    watch = loss.LossWatch(rt)
    monkeypatch.setattr(loss, "_enabled", True)   # the server has v2 (review R5)
    loss.note_user_count(w._device_id, 900)
    watch.tick(rt)
    loss.note_user_count(w._device_id, 890)
    watch.tick(rt)
    assert getattr(w, "_loss_check_due", False) is True


# ------------------------------------------------------------------ 5
def test_unreachable_probes_back_off_to_half_an_hour(monkeypatch, db):
    from app.core.v2 import runtime as rtmod
    from app.core.v2.api import V2ApiError
    monkeypatch.setattr(rtmod, "_pc_uuid", lambda app: "u")
    app = SimpleNamespace(after=lambda ms, fn: fn(), request_sync_now=lambda **kw: None)
    rt = rtmod.V2Runtime(app, base_url="http://127.0.0.1:1", token_provider=lambda: "t")
    rt.api.assignment = lambda: (_ for _ in ()).throw(V2ApiError(0, "UNREACHABLE"))
    waits = []
    for _ in range(7):
        t0 = time.monotonic()
        rt.refresh_assignment()
        waits.append(round(rt._next_refresh - t0))
    assert waits[0] == 120 and waits[-1] == 1800 and waits == sorted(waits)
    __import__("app.core.v2.server_clock", fromlist=["x"]).set_default(None)

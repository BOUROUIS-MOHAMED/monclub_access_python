"""P3b-2 independent review, round 1 -- one test per confirmed finding.

R1  a duplicate offer between "handler done" and "outcome written" reported a door that opened
    as FAILED INTERRUPTED.
R2  a revoked or adopted PC kept its cached DRIVE leases while online.
R3  a release was acknowledged while a DeviceSync pass still wrote the turnstile.
R4  with no gym UTC offset known, a clock more than 5 min off was refused for ever.
R5  loss re-add ran against a server without v2 (old server: behaviour must not change).
R7  ownership facts of a turnstile this PC no longer drives were never uploaded.
R9  a snapshot was posted before the removal step ran, hiding the stored REVOKE_ABORTED list.
R11 a pass kept pushing after its lease was lost; "not_leased" was recorded as a ceiling abort.
"""
from __future__ import annotations

import threading
import time
import types
from datetime import datetime, timedelta, timezone

import pytest

import app.core.telemetry as tel
from app.core.v2 import lease_gate as lg
from app.core.v2 import loss
from app.core.v2 import ownership
from app.core.v2 import problems as pr
from app.core.v2 import runtime as rtmod
from app.core.v2.api import V2Api, V2ApiError
from app.core.v2.commands import START_MARGIN_SEC, CommandExecutor, Journal
from app.core.v2.leases import UNREACHABLE, LeaseManager
from app.core.v2.reports import ProblemReporter
from app.core.v2.server_clock import ServerClock
from tests.test_standalone_finger_removal_state import FingerState, fstate  # noqa: F401
from tests.test_standalone_incremental_sync import _user, _worker
from tests.test_standalone_revoked_pin_removal import RevokeDriver, _authoritative_full_sync


@pytest.fixture(autouse=True)
def _clean():
    lg.reset_for_tests()
    pr.registry.reset_for_tests()
    loss.set_enabled(False)
    yield
    lg.reset_for_tests()
    pr.registry.reset_for_tests()
    loss.set_enabled(False)


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as dbmod
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "review1.db"), raising=False)
    dbmod.init_db()
    yield dbmod
    dbmod._shutdown_db_writer_for_tests()


def _drive(did, generation=3, **extra):
    lg.install(lg.snapshot_from_assignment({"gymUsesAssignments": True, "role": "DRIVER", "drive": [
        dict({"gymDeviceId": did, "generation": generation, "state": "DRIVE", "handoverForced": False},
             **extra)], "release": [], "readerOf": []}, source="server"))


# ---------------------------------------------------------------------------------- R11
def test_r11_pass_stops_writing_once_the_lease_is_lost(monkeypatch, fstate):
    seen = []
    monkeypatch.setattr(tel, "warn", lambda name, **f: seen.append((name, f.get("reason"))))
    drv = RevokeDriver()
    w, _c = _worker(monkeypatch, driver=drv, users=[_user(30001, "active", "")])
    did = w._device_id
    _drive(did)
    fstate.rows["30002"] = ("old-hash", True, {0})           # a departed member this PC owns
    orig = w._neutralise_revoked_pins

    def revoke_then_lose_lease(**kw):
        lg.install(lg.snapshot_from_assignment({"gymUsesAssignments": True, "role": "READER",
                                                "drive": [], "release": []}, source="server"))
        return orig(**kw)
    monkeypatch.setattr(w, "_neutralise_revoked_pins", revoke_then_lose_lease)
    _authoritative_full_sync(w, 34439)
    pushed = [u["pin"] for c in drv.push_calls for u in c["users"]]
    assert not lg.device_allowed(did)
    assert "30001" not in pushed and drv.delete_calls == []
    assert "REVOKE_ABORTED" not in [n for n, _ in seen]
    assert ("REMOVAL_DEFERRED", "not_leased") in seen
    assert all(p["code"] != pr.REVOKE_ABORTED for p in pr.registry.snapshot(did))


def test_r11_push_yield_drops_the_rest_once_the_lease_is_lost(monkeypatch, fstate):
    w, _c = _worker(monkeypatch, driver=RevokeDriver(), users=[])
    _drive(w._device_id)
    w._pass_all_pins = {"1", "2"}
    lg.install(lg.snapshot_from_assignment({"gymUsesAssignments": True, "role": "READER",
                                            "drive": [], "release": []}, source="server"))
    assert w._standalone_push_yield() == {"1", "2"}


# ---------------------------------------------------------------------------------- R1
CID = "0b0f9a5e-1111-4222-8333-444455556666"


class _CmdApi:
    def __init__(self):
        self.stored = None

    def claim(self, cid, token):
        return {"command": {"id": cid, "type": "DOOR_OPEN", "gymDeviceId": 8, "payload": None,
                            "finishBy": "2026-09-26T10:00:30.000", "serverTime": "2026-09-26T10:00:10.000"}}

    def result(self, cid, token, outcome, code, detail):
        if self.stored is None:
            self.stored = (outcome, code)
            return {}
        if self.stored == (outcome, code):
            return {}
        raise V2ApiError(409, "COMMAND_FINISHED", "", backend=True)

    def progress(self, *a):
        return {}


class _SlowOutcomeJournal(Journal):
    gate = threading.Event()

    def set_outcome(self, cid, outcome, code, detail, *, state="STARTED"):
        if threading.current_thread().name.startswith("v2-cmd-"):
            self.gate.set()
            time.sleep(0.3)
        return super().set_outcome(cid, outcome, code, detail, state=state)


def test_r1_duplicate_offer_while_the_outcome_is_written_keeps_the_real_outcome(db):
    opened = []
    api = _CmdApi()
    ex = CommandExecutor(api=api, handlers={"DOOR_OPEN": lambda run: (opened.append(1) or ("SUCCEEDED", "OPENED", None))},
                         journal=_SlowOutcomeJournal(), token_factory=lambda: "tok-" + "a" * 20)
    ex.process(CID)
    assert _SlowOutcomeJournal.gate.wait(3)
    ex.process(CID)                                     # the duplicate, in the gap
    deadline = time.time() + 3
    while api.stored is None and time.time() < deadline:
        time.sleep(0.05)
    assert len(opened) == 1
    assert api.stored == ("SUCCEEDED", "OPENED")


def test_r6_door_open_start_margin():
    assert START_MARGIN_SEC["DOOR_OPEN"] >= 10.0


# ---------------------------------------------------------------------------------- R2
_BODY = {"gymUsesAssignments": True, "role": "DRIVER",
         "drive": [{"gymDeviceId": 8, "name": "T8", "generation": 3, "state": "DRIVE",
                    "handoverForced": False}], "release": [], "readerOf": []}


class _Kv(dict):
    def get_(self, k):
        return self.get(k)

    def put(self, k, v, **_):
        self[k] = v

    def delete(self, k):
        self.pop(k, None)


class _AssignApi:
    def __init__(self):
        self.err = None

    def assignment(self):
        if self.err:
            raise self.err
        return _BODY


def _mgr(api, kv, identity=None):
    kv["restored:8"] = {"leaseGeneration": 3}
    return LeaseManager(api=api, pc_uuid_provider=lambda: "uuid-1", identity_state_provider=identity,
                        kv_get=kv.get_, kv_put=kv.put, kv_delete=kv.delete)


@pytest.mark.parametrize("err,identity", [
    (V2ApiError(403, "ACCESS_PC_REVOKED", "revoked", backend=True), None),
    (V2ApiError(403, "ACCESS_PC_ADOPTED", "adopted", backend=True), None),
    (V2ApiError(0, "NO_PC_TOKEN", "no token"), "revoked"),
    (V2ApiError(0, "NO_PC_TOKEN", "no token"), "invalid_credentials"),
])
def test_r2_revoked_pc_stops_driving_and_stays_stopped_after_restart(err, identity):
    api, kv = _AssignApi(), _Kv()
    m = _mgr(api, kv, identity=lambda: identity)
    assert m.refresh() == "ON" and lg.device_allowed(8)
    api.err = err
    assert m.refresh() == UNREACHABLE
    assert not lg.device_allowed(8)
    assert lg.current().mode == lg.MODE_LEASED          # a reader: not "every PC drives"
    lg.reset_for_tests()
    assert _mgr(_AssignApi(), kv).load_cache()          # a cold start keeps "drives nothing"
    assert not lg.device_allowed(8)


def test_r2_offline_pc_keeps_its_cached_leases():
    api, kv = _AssignApi(), _Kv()
    m = _mgr(api, kv, identity=lambda: "active")
    assert m.refresh() == "ON"
    api.err = V2ApiError(0, "NO_PC_TOKEN", "no token")   # token not minted: offline, identity fine
    assert m.refresh() == UNREACHABLE
    assert lg.device_allowed(8)


# ---------------------------------------------------------------------------------- R3
class _RelApi:
    def __init__(self):
        self.calls = []

    def ownership_page(self, did, after, limit):
        return {"generation": 1, "pinScheme": "MEMBERSHIP", "rows": [], "nextAfterId": None,
                "serverTime": "2026-09-26T10:00:00"}

    def ownership_upload(self, body):
        self.calls.append(("upload", body["finalPage"]))
        return {"releaseRecorded": bool(body["finalPage"]), "stored": 0}

    def release(self, did, gen):
        self.calls.append(("release", did, gen))
        return {"outcome": "RELEASED"}

    last_body = None


@pytest.mark.parametrize("app", [
    types.SimpleNamespace(_ultra_engine=None, _device_sync_engine=types.SimpleNamespace(_running=True)),
    types.SimpleNamespace(_ultra_engine=types.SimpleNamespace(_workers={8: types.SimpleNamespace(
        _full_sync_running=False, _active_sync_engine=object())}), _device_sync_engine=None),
    # round 2: the ULTRA scheduler's PullSDK fallback pass (the worker is not usable)
    types.SimpleNamespace(_ultra_engine=types.SimpleNamespace(
        _workers={}, _sync_scheduler=types.SimpleNamespace(_active_sync_engine=object())),
        _device_sync_engine=None),
])
def test_r3_release_waits_for_every_pass_writing_the_turnstile(db, monkeypatch, app):
    monkeypatch.setattr(ownership, "RELEASE_IDLE_GRACE_SEC", 0.0)
    lg.install(lg.snapshot_from_assignment(
        {"gymUsesAssignments": True, "role": "DRIVER", "drive": [],
         "release": [{"gymDeviceId": 8, "generation": 3, "newDriverPcId": 77}]}, source="server"))
    api = _RelApi()
    rt = types.SimpleNamespace(app=app, api=api, clock=ServerClock(),
                               refresh_assignment=lambda: "ON", leases=None)
    sync = ownership.OwnershipSync(rt)
    assert not sync._worker_idle(8)
    assert sync.release(8, 3) != "RELEASED"
    assert ("release", 8, 3) not in api.calls


# ---------------------------------------------------------------------------------- R4
class _Resp:
    def __init__(self, status, body):
        self.status_code, self._b, self.headers = status, body, {}

    def json(self):
        return self._b


class _SkewSession:
    """Server clock = PC clock + 600 s (gym local = UTC+1, times sent without an offset);
    refuses any sentAt more than 300 s off, with skewSeconds = serverNow - sentAt."""

    def __init__(self, timestamp_offset: str):
        self.sent, self.accepted, self.ts_offset = [], [], timestamp_offset

    def _server_now(self):
        return datetime.now(timezone.utc) + timedelta(seconds=600)

    def request(self, method, url, **kw):
        body = kw.get("json")
        now = self._server_now()
        local = (now + timedelta(hours=1)).replace(tzinfo=None)
        if body is None:
            return _Resp(200, {"serverTime": local.isoformat(timespec="milliseconds"),
                               "generation": 1, "rows": []})
        sent = datetime.fromisoformat(body["sentAt"].replace("Z", "+00:00"))
        self.sent.append(sent)
        skew = (now - sent).total_seconds()
        if abs(skew) > 300:
            return _Resp(409, {"status": False, "code": "CLOCK_SKEW", "errorMsg": "clock skew",
                               "details": {"timestamp": local.isoformat() + self.ts_offset,
                                           "serverTime": local.isoformat(timespec="milliseconds"),
                                           "skewSeconds": round(skew)}})
        self.accepted.append(sent)
        return _Resp(200, {"stored": 0})


@pytest.mark.parametrize("ts_offset", ["", "+01:00"])
def test_r4_clock_learns_from_a_refusal_without_a_known_gym_offset(ts_offset):
    clock = ServerClock()
    assert clock.utc_offset is None
    s = _SkewSession(ts_offset)
    api = V2Api(base_url="http://x", token_provider=lambda: "tok", session=s, clock=clock)
    api.ownership_upload({"gymDeviceId": 8, "pinScheme": "MEMBERSHIP", "generation": 1,
                          "finalPage": True, "rows": []})           # refused once, then accepted
    assert len(s.sent) == 2 and len(s.accepted) == 1
    assert clock.has_sample() and abs(clock.offset() - 600) < 5
    if ts_offset:
        assert clock.utc_offset == 3600


# ---------------------------------------------------------------------------------- R5
class _OffApi:
    def assignment(self):
        raise V2ApiError(404, "NOT_FOUND", "Resource not found", backend=True)


def test_r5_no_loss_re_add_on_a_server_without_v2(db):
    worker = types.SimpleNamespace(_loss_check_due=False)
    app = types.SimpleNamespace(_ultra_engine=types.SimpleNamespace(_workers={8: worker}),
                                after=lambda *_a, **_k: None)
    rt = rtmod.V2Runtime(app, base_url="http://x", token_provider=lambda: "tok", app_version="t")
    rt.leases._api = _OffApi()
    rt.local_extensions.append(loss.LossWatch(rt))
    rt.tick()
    assert rt.availability == "OFF" and not loss.is_enabled()
    loss.note_user_count(8, 900)
    rt.tick()
    loss.note_user_count(8, 880)
    rt.tick()
    assert worker._loss_check_due is False
    out = loss.evaluate_listing(8, on_device=["1"], owned=["1", "2"], desired=["1", "2"])
    assert not out.get("readd")


# ---------------------------------------------------------------------------------- R7
def _state_row(did, pin):
    from app.core.db import _run_db_write_sync
    _run_db_write_sync("t", lambda c, _p: c.execute(
        "INSERT INTO device_sync_state (device_id, pin, desired_hash, last_ok, last_error, updated_at, "
        "pushed_finger_ids, ownership_confirmed, finger_slots_swept) VALUES (?, ?, 'h', 1, NULL, "
        "'2026-09-26 09:00:00', '', 1, 1)", (did, pin)))


class _UpApi:
    """The backend's rule: GET /ownership (the restore route) answers only the lease holder;
    POST /ownership/upload is open to any ACTIVE PC of the gym (round 2 found the first R7 fix
    used the GET)."""

    def __init__(self, driven=(9,), upload_error=None):
        self.uploads, self.gets, self.driven, self.upload_error = [], [], set(driven), upload_error

    def ownership_page(self, did, after, limit):
        self.gets.append(did)
        if did not in self.driven:
            raise V2ApiError(409, "NOT_DEVICE_DRIVER", "", backend=True)
        return {"generation": 1, "pinScheme": "MEMBERSHIP", "rows": [], "nextAfterId": None}

    def ownership_upload(self, body):
        if self.upload_error is not None:
            raise self.upload_error
        self.uploads.append((body["gymDeviceId"], body["generation"], [r["pin"] for r in body["rows"]]))
        return {"stored": len(body["rows"])}

    last_body = None


def _uploaded_row(did, pin, generation=1):
    from app.core.db import _run_db_write_sync
    _run_db_write_sync("t", lambda c, _p: c.execute(
        "INSERT INTO v2_ownership_uploaded (device_id, pin_scheme, generation, pin, state, pushed_hash, "
        "pushed_finger_ids, observed_at) VALUES (?, 'MEMBERSHIP', ?, ?, 'APPLIED', 'old', '', 1.0)",
        (did, generation, pin)))


def _own_rt(api):
    clock = ServerClock()
    now = time.time()
    clock.add_sample(now, now, now, source="t")
    return types.SimpleNamespace(app=types.SimpleNamespace(_ultra_engine=None), api=api, clock=clock,
                                 refresh_assignment=lambda: "ON",
                                 leases=types.SimpleNamespace(restored_generation=lambda d: 2 if d == 9 else None))


def test_r7_facts_of_a_turnstile_no_longer_driven_are_uploaded_without_the_restore_route(db):
    _state_row(8, "1001")                     # pushed while this PC drove turnstile 8
    _uploaded_row(8, "0999", generation=4)    # this PC uploaded for 8 before (generation 4)
    _state_row(9, "2001")
    _drive(9, generation=2)
    api = _UpApi()
    sync = ownership.OwnershipSync(_own_rt(api))
    sync.tick(None)
    assert 8 not in api.gets                  # the holder-only GET is never asked for 8
    assert (8, 4, ["1001"]) in api.uploads and (9, 1, ["2001"]) in api.uploads
    n = len(api.uploads)
    sync._next_upload.clear()
    sync.tick(None)
    assert len(api.uploads) == n              # nothing changed: nothing re-sent


def test_r7_a_turnstile_never_uploaded_by_this_pc_sends_nothing(db):
    _state_row(8, "1001")                     # pushed only before the gym used leases
    _drive(9, generation=2)
    api = _UpApi()
    sync = ownership.OwnershipSync(_own_rt(api))
    for _ in range(3):
        sync._next_upload.clear()
        sync.tick(None)
    assert 8 not in api.gets and all(u[0] != 8 for u in api.uploads)


def test_r7_a_refused_upload_is_not_retried_every_minute(db):
    _state_row(8, "1001")
    _uploaded_row(8, "0999", generation=1)
    lg.install(lg.snapshot_from_assignment({"gymUsesAssignments": True, "role": "READER",
                                            "drive": [], "release": []}, source="server"))
    calls = []
    api = _UpApi(driven=())
    api.upload_error = V2ApiError(409, "STALE_OWNERSHIP_GENERATION", "", backend=True)
    real = api.ownership_upload
    api.ownership_upload = lambda body: (calls.append(1), real(body))[1]
    sync = ownership.OwnershipSync(_own_rt(api))
    for _ in range(3):
        sync._next_upload.clear()
        sync.tick(None)
    assert len(calls) == 1 and api.gets == []


# ---------------------------------------------------------------------------------- R9
class _ProbApi:
    def __init__(self):
        self.posts = []

    def turnstile_problems(self, body):
        self.posts.append([p["code"] for p in body["problems"]])
        return {"stale": False}


def _report():
    api = _ProbApi()
    rt = types.SimpleNamespace(api=api, clock=ServerClock())
    rep = ProblemReporter(rt)
    rep._scheme = lambda did: "MEMBERSHIP"
    rep.tick(rt)
    return api.posts


@pytest.mark.parametrize("signal", [
    lambda: pr.registry.clear_code(8, pr.CAPACITY_FULL),
    lambda: pr.registry.removal_allowed(8, "table_clear"),
    lambda: pr.registry.skipped_not_owned(8, ["4711"]),
])
def test_r9_nothing_is_reported_before_the_removal_step_ran(signal):
    signal()
    assert _report() == []
    pr.registry.removal_allowed(8, "standalone_revoke")     # the step ran: now it is reported
    assert len(_report()) == 1


# ---------------------------------------------------------------------------------- round 3
def test_round3_lost_turnstile_follows_its_own_wipe_generation(db):
    _state_row(8, "1001")
    _uploaded_row(8, "0999", generation=1)          # last upload under 1; the wipe bumped it to 2
    lg.install(lg.snapshot_from_assignment({"gymUsesAssignments": True, "role": "READER",
                                            "drive": [], "release": []}, source="server"))
    api = _UpApi(driven=())
    real = api.ownership_upload

    def upload(body):
        if body["generation"] != 2:
            raise V2ApiError(409, "STALE_OWNERSHIP_GENERATION", "", backend=True,
                             details={"gymDeviceId": 8, "currentGeneration": 2, "pinScheme": "MEMBERSHIP"})
        return real(body)
    api.ownership_upload = upload
    sync = ownership.OwnershipSync(_own_rt(api))
    sync.tick(None)
    assert any(u[:2] == (8, 2) and "1001" in u[2] for u in api.uploads)
    assert 8 not in sync._lost_done
    assert api.gets == []


def test_round3_clock_skew_is_retried_not_parked(db):
    _state_row(8, "1001")
    _uploaded_row(8, "0999", generation=1)
    lg.install(lg.snapshot_from_assignment({"gymUsesAssignments": True, "role": "READER",
                                            "drive": [], "release": []}, source="server"))
    api = _UpApi(driven=(), upload_error=V2ApiError(409, "CLOCK_SKEW", "", backend=True))
    sync = ownership.OwnershipSync(_own_rt(api))
    sync.tick(None)
    assert 8 not in sync._lost_done and sync._next_upload[8] > 0


def test_round3_a_transient_claim_failure_is_retried(db, monkeypatch):
    import app.core.v2.commands as cmds

    class FlakyApi(_CmdApi):
        def __init__(self):
            super().__init__()
            self.claims = 0

        def claim(self, cid, token):
            self.claims += 1
            if self.claims == 1:
                raise V2ApiError(0, "UNREACHABLE", "timeout")
            return super().claim(cid, token)
    api = FlakyApi()
    opened = []
    ex = CommandExecutor(api=api, handlers={"DOOR_OPEN": lambda run: (opened.append(1) or ("SUCCEEDED", "OPENED", None))},
                         journal=Journal(), token_factory=lambda: "tok-" + "b" * 20)
    clock = [1000.0]
    monkeypatch.setattr(ex, "_mono", lambda: clock[0])
    monkeypatch.setattr(cmds.timefmt, "local_seconds_between", lambda a, b: 20.0)
    ex.offer(CID)
    cid = ex._q.get_nowait(); ex._queued.discard(cid)
    with pytest.raises(V2ApiError):
        ex.process(cid)
    ex._schedule_retry(cid)
    ex._offer_due_retries()
    assert ex._q.empty()                            # not due yet
    clock[0] += 2.5
    ex._offer_due_retries()
    cid = ex._q.get_nowait(); ex._queued.discard(cid)
    ex.process(cid)
    deadline = time.time() + 3
    while api.stored is None and time.time() < deadline:
        time.sleep(0.05)
    assert api.claims == 2 and opened == [1] and api.stored == ("SUCCEEDED", "OPENED")

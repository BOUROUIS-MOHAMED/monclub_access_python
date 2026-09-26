"""P3b-2 step 5: the ownership backup — upload, restore, release, read-back, wipe."""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from app.core.v2 import lease_gate as lg
from app.core.v2 import ownership as own
from app.core.v2 import timefmt
from app.core.v2.api import V2ApiError
from app.core.v2.server_clock import ServerClock


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as dbmod
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "own.db"), raising=False)
    dbmod.init_db()
    lg.reset_for_tests()
    yield dbmod
    lg.reset_for_tests()
    dbmod._shutdown_db_writer_for_tests()


def _state(dbmod, device_id, pin, *, owned=True, h="h1", fingers="0,3", updated="2026-09-20 10:00:00"):
    def op(conn, _p):
        conn.execute("INSERT OR REPLACE INTO device_sync_state (device_id, pin, desired_hash, last_ok, updated_at, "
                     "pushed_finger_ids, ownership_confirmed) VALUES (?, ?, ?, 1, ?, ?, ?)",
                     (device_id, pin, h, updated, fingers, 1 if owned else 0))
    dbmod._run_db_write_sync("t", op)


class FakeApi:
    def __init__(self):
        self.uploads = []
        self.pages = {}
        self.releases = []
        self.readbacks = []
        self.wiped = []
        self.meta = {"generation": 4, "pinScheme": "MEMBERSHIP"}
        self.release_recorded = True
        self.upload_error = None

    def ownership_page(self, did, after, limit):
        if limit == 1:
            return dict(self.meta, rows=[])
        rows = self.pages.get(after, [])
        nxt = (after + 1) if (after + 1) in self.pages else None
        return dict(self.meta, rows=rows, nextAfterId=nxt)

    def ownership_upload(self, body):
        if self.upload_error:
            e, self.upload_error = self.upload_error, None
            raise e
        self.uploads.append(body)
        return {"stored": len(body["rows"]), "releaseRecorded": bool(body["finalPage"] and self.release_recorded)}

    def release(self, did, gen):
        self.releases.append((did, gen))
        return {"outcome": "RELEASED"}

    def read_back(self, did, gen):
        self.readbacks.append((did, gen))
        return {"outcome": "CONFIRMED", "clearedReason": "OWNER_FORCED"}

    def ownership_wiped(self, did, gen, at):
        self.wiped.append((did, gen, at))
        return {"outcome": "BUMPED"}


class FakeLeases:
    def __init__(self):
        self.restored = {}

    def restored_generation(self, did):
        return self.restored.get(did)

    def mark_restored(self, did, gen, **kw):
        self.restored[did] = gen


def _rt(api=None, offset=0.0, listing=("1",)):
    clock = ServerClock()
    now = time.time()
    clock.add_sample(now + offset, now, now, source="t")
    rt = SimpleNamespace(api=api or FakeApi(), clock=clock, leases=FakeLeases(),
                         app=SimpleNamespace(_ultra_engine=None), refreshed=[])
    rt.refresh_assignment = lambda: rt.refreshed.append(1)
    rt.handlers = SimpleNamespace(_list_device_pins=lambda did, timeout: list(listing) if listing is not None else None)
    return rt


def test_facts_map_to_the_contract_states_and_removed_only_from_the_log(db):
    _state(db, 8, "100", owned=True)
    _state(db, 8, "101", owned=False)
    db.record_push_intents(device_id=8, rows=[("102", "A", "", "x")], protocol="ZK_STANDALONE")
    _state(db, 8, "103", owned=True)
    db.clear_device_revocation_state(device_id=8, pin="103")      # MonClub removed it
    _state(db, 8, "104", owned=True)
    db._run_db_write_sync("prune", lambda c, p: c.execute("DELETE FROM device_sync_state WHERE pin='104'"))
    facts = own.local_facts(8)
    assert facts["100"]["state"] == "APPLIED" and facts["101"]["state"] == "FAILED"
    assert facts["103"]["state"] == "REMOVED"
    assert "104" not in facts, "a vanished row (a prune) is never uploaded as removed"
    assert facts["102"]["state"] == "INTENT"


def test_rows_older_than_the_last_pin_scheme_switch_are_not_uploaded(db):
    _state(db, 8, "100", updated="2026-09-01 10:00:00")
    _state(db, 8, "200", updated="2026-09-25 10:00:00")
    db._run_db_write_sync("sw", lambda c, p: c.execute(
        "INSERT INTO device_pin_scheme_switch (device_id, previous_scheme, scheme, switched_at, cleared_rows) "
        "VALUES (8, 'MEMBERSHIP', 'ACCOUNT', '2026-09-10 00:00:00', 0)"))
    assert set(own.local_facts(8)) == {"200"}


def test_upload_sends_changes_only_with_fact_times_on_the_server_clock(db, monkeypatch):
    _state(db, 8, "100", updated="2026-09-20 10:00:00")
    api = FakeApi()
    rt = _rt(api, offset=120.0)
    sync = own.OwnershipSync(rt)
    monkeypatch.setattr(sync, "_device_scheme", lambda did: "MEMBERSHIP")
    sync.upload(8)
    [body] = api.uploads
    assert (body["gymDeviceId"], body["pinScheme"], body["generation"], body["finalPage"]) == (8, "MEMBERSHIP", 4, False)
    [row] = body["rows"]
    expected = time.mktime(time.strptime("2026-09-20 10:00:00", "%Y-%m-%d %H:%M:%S")) + 120.0
    assert timefmt.to_epoch(row["observedAt"]) == pytest.approx(expected, abs=1.0)
    assert (row["state"], row["pushedHash"], row["pushedFingerIds"]) == ("APPLIED", "h1", "0,3")
    sync.upload(8)
    assert len(api.uploads) == 1, "nothing changed -> nothing sent"
    _state(db, 8, "100", h="h2", updated="2026-09-20 10:00:00")     # same time, new content
    sync.upload(8)
    t2 = timefmt.to_epoch(api.uploads[-1]["rows"][0]["observedAt"])
    assert t2 > timefmt.to_epoch(row["observedAt"]), "a changed state is strictly newer"


def test_a_fact_is_never_dated_after_now(db, monkeypatch):
    _state(db, 8, "100", updated="2099-01-01 00:00:00")               # a PC clock that ran ahead
    api = FakeApi()
    sync = own.OwnershipSync(_rt(api))
    monkeypatch.setattr(sync, "_device_scheme", lambda did: "MEMBERSHIP")
    sync.upload(8)
    assert timefmt.to_epoch(api.uploads[0]["rows"][0]["observedAt"]) <= time.time() + 1


def test_a_scheme_mismatch_uploads_nothing(db, monkeypatch):
    _state(db, 8, "100")
    api = FakeApi()
    sync = own.OwnershipSync(_rt(api))
    monkeypatch.setattr(sync, "_device_scheme", lambda did: "ACCOUNT")
    assert sync.upload(8)["skipped"] == "scheme_or_generation_unknown" and api.uploads == []


def test_a_final_upload_sends_everything_in_pages_of_1000(db, monkeypatch):
    for i in range(2100):
        _state(db, 8, str(10000 + i))
    api = FakeApi()
    sync = own.OwnershipSync(_rt(api))
    monkeypatch.setattr(sync, "_device_scheme", lambda did: "MEMBERSHIP")
    sync.upload(8)
    n_first = len(api.uploads)
    out = sync.upload(8, final=True)
    finals = api.uploads[n_first:]
    assert [len(b["rows"]) for b in finals] == [1000, 1000, 100]
    assert [b["finalPage"] for b in finals] == [False, False, True]
    assert out["releaseRecorded"] is True


def test_a_stale_generation_forgets_the_cached_generation(db, monkeypatch):
    _state(db, 8, "100")
    api = FakeApi()
    api.upload_error = V2ApiError(409, "STALE_OWNERSHIP_GENERATION", backend=True,
                                  details={"currentGeneration": 5})
    sync = own.OwnershipSync(_rt(api))
    monkeypatch.setattr(sync, "_device_scheme", lambda did: "MEMBERSHIP")
    with pytest.raises(V2ApiError):
        sync.upload(8)
    assert 8 not in sync._meta


def test_restore_adopts_what_this_pc_lacks_and_never_lowers_its_own_proof(db):
    _state(db, 8, "100", owned=True, h="mine")
    _state(db, 8, "101", owned=False, h="attempt")
    api = FakeApi()
    api.pages = {0: [{"id": 1, "pin": "100", "state": "APPLIED", "pushedHash": "theirs", "pushedFingerIds": "1"},
                     {"id": 2, "pin": "101", "state": "APPLIED", "pushedHash": "h101", "pushedFingerIds": "0,2"}],
                 1: [{"id": 3, "pin": "102", "state": "APPLIED", "pushedHash": "h102", "pushedFingerIds": ""},
                     {"id": 4, "pin": "103", "state": "REMOVED"}, {"id": 5, "pin": "104", "state": "INTENT"}]}
    rt = _rt(api)
    assert own.OwnershipSync(rt).restore(8, 3) == 2
    with db.get_conn() as conn:
        rows = {r[0]: r[1:] for r in conn.execute(
            "SELECT pin, desired_hash, last_ok, ownership_confirmed, pushed_finger_ids, finger_slots_swept "
            "FROM device_sync_state WHERE device_id = 8").fetchall()}
    assert rows["100"][0] == "mine", "this PC's own proof wins"
    assert rows["101"] == ("h101", 1, 1, "0,2", 1)
    assert rows["102"] == ("h102", 1, 1, "", 1)
    assert "103" not in rows and "104" not in rows
    assert rt.leases.restored == {8: 3}


def test_a_release_uploads_the_final_record_then_acknowledges(db, monkeypatch):
    _state(db, 8, "100")
    api = FakeApi()
    rt = _rt(api)
    sync = own.OwnershipSync(rt)
    monkeypatch.setattr(sync, "_device_scheme", lambda did: "MEMBERSHIP")
    assert sync.release(8, 3) is None, "a short grace lets a write in flight finish first"
    sync._release_since[8] -= 10
    assert sync.release(8, 3) == "RELEASED"
    assert api.uploads[-1]["finalPage"] is True and api.releases == [(8, 3)]


def test_no_acknowledgement_without_a_recorded_release_upload(db, monkeypatch):
    api = FakeApi()
    api.release_recorded = False
    rt = _rt(api)
    sync = own.OwnershipSync(rt)
    monkeypatch.setattr(sync, "_device_scheme", lambda did: "MEMBERSHIP")
    sync._release_since[8] = time.monotonic() - 10
    assert sync.release(8, 3) == "NOT_RECORDED" and api.releases == [] and rt.refreshed


def test_a_release_waits_for_a_full_pass_in_progress(db, monkeypatch):
    api = FakeApi()
    rt = _rt(api)
    worker = SimpleNamespace(_full_sync_running=True)
    rt.app = SimpleNamespace(_ultra_engine=SimpleNamespace(_workers={8: worker}))
    sync = own.OwnershipSync(rt)
    sync._release_since[8] = time.monotonic() - 10
    assert sync.release(8, 3) is None and api.uploads == []


def test_read_back_confirms_only_after_a_listing(db):
    api = FakeApi()
    rt = _rt(api, listing=None)
    assert own.OwnershipSync(rt).read_back(8, 3) is False and api.readbacks == []
    rt2 = _rt(api, listing=("1", "2"))
    assert own.OwnershipSync(rt2).read_back(8, 3) is True and api.readbacks == [(8, 3)]


def test_a_wipe_is_reported_in_the_current_generation(db):
    own.note_wipe(8)
    api = FakeApi()
    sync = own.OwnershipSync(_rt(api))
    sync.report_wipes([8])
    assert api.wiped and api.wiped[0][:2] == (8, 4)
    sync.report_wipes([8])
    assert len(api.wiped) == 1, "reported once"


def test_the_tick_restores_a_new_lease_before_anything_else(db, monkeypatch):
    api = FakeApi()
    rt = _rt(api)
    lg.install(lg.snapshot_from_assignment({"gymUsesAssignments": True, "role": "DRIVER", "readerOf": [],
                                            "release": [], "drive": [{"gymDeviceId": 8, "generation": 3,
                                                                      "state": "DRIVE", "handoverForced": True}]},
                                           source="server", add_only=[8]))
    sync = own.OwnershipSync(rt)
    monkeypatch.setattr(sync, "_device_scheme", lambda did: "MEMBERSHIP")
    sync.tick(rt)
    assert rt.leases.restored == {8: 3} and api.readbacks == [], "restore first, read-back on a later tick"
    sync.tick(rt)
    assert api.readbacks == [(8, 3)]

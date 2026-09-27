"""Lane 1 item 4: the last push result, per pin, per turnstile, in the ownership upload.

Contract: backend branch claude/v2-last-push-and-clock,
docs/plans/2026-09-27-ownership-last-push-contract.md (revision 3.1), §1 and §5.1.

APPLIED is sticky (``ownership_confirmed`` never goes back to 0), so the server could not tell "the
member is there" from "MonClub once put the member there and the last push failed". Each upload
row now carries ``lastPushOk`` / ``lastPushAt`` / ``lastPushError``:
* only a real write of the pin produces a result -- recorded where the outcome is decided (the
  MB2000 chunk/targeted recording, the PullSDK Phase D and per-pin paths), never by the unchanged-pin
  backfill, a restore, a read-back promotion, a hash clear or a deferral;
* an attempt that STARTS (its write-ahead intent) makes the result unknown in the intent's own
  transaction, so an interrupted attempt never leaves the previous ``true`` standing;
* a restore (this PC acquiring the turnstile) makes every result unknown;
* the three fields are part of "has this row changed", a changed row gets a newer observedAt, and
  lastPushAt is capped at sentAt like observedAt;
* the heartbeat's clockOffset gains ``ageSec``, the age of the OLDEST sample in the median window.
"""
from __future__ import annotations

import json
import queue
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import app.core.db as dbmod
import app.core.ultra_engine as ue
from app.core.v2 import lease_gate as lg
from app.core.v2 import ownership as own
from app.core.v2 import timefmt
from app.core.v2.server_clock import ServerClock
from tests.fake_terminal import TerminalZkem
from tests.test_standalone_incremental_sync import _make_driver, _tpl, _user
from tests.test_v2_ownership import FakeApi, _rt, _state


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "lastpush.db"), raising=False)
    dbmod.init_db()
    lg.reset_for_tests()
    yield dbmod
    lg.reset_for_tests()
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


def _results(did):
    return {p: (r[0], r[3]) for p, r in dbmod.list_push_results(device_id=did).items()}


# ─────────────────────────── storage: the attempt start resets ───────────────────────────

def test_an_attempt_start_makes_the_result_unknown_in_the_intent_transaction(db):
    db.record_push_results(device_id=8, rows=[("100", True, None), ("101", False, "USER_WRITE_FAILED")])
    assert _results(8) == {"100": (True, None), "101": (False, "USER_WRITE_FAILED")}
    db.record_push_intents(device_id=8, rows=[("100", "A", "", "h")], protocol="ZK_STANDALONE")
    assert _results(8)["100"] == (None, None), "the write is about to start: nothing is known"
    assert _results(8)["101"] == (False, "USER_WRITE_FAILED")


def test_a_failed_intent_write_resets_nothing(db, monkeypatch):
    db.record_push_results(device_id=8, rows=[("100", True, None)])
    real = dbmod._reset_push_results_on

    def reset_then_fail(conn, did, pins):
        real(conn, did, pins)
        raise RuntimeError("disk full")

    monkeypatch.setattr(dbmod, "_reset_push_results_on", reset_then_fail)
    with pytest.raises(RuntimeError):
        db.record_push_intents(device_id=8, rows=[("100", "A", "", "h")], protocol="ZK_STANDALONE")
    assert _results(8)["100"] == (True, None), "the intent did not commit, nor did the reset"
    assert db.list_push_intents(device_id=8) == {}


def test_a_code_that_is_not_a_short_machine_code_is_never_stored(db):
    db.record_push_results(device_id=8, rows=[("100", False, "rc=-101 SetDeviceData FAILED"),
                                              ("101", True, "USER_WRITE_FAILED")])
    assert _results(8) == {"100": (False, "OTHER"), "101": (True, None)}


# ─────────────────────────── MB2000: recorded where the outcome is decided ───────────────────────────

class RefusingTerminal(TerminalZkem):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.refuse: set = set()
        self.refuse_tpl: set = set()

    def SSR_SetUserInfo(self, machine, pin, name, pw, priv, enabled):
        if str(pin) in self.refuse:
            self._rec("SSR_SetUserInfo", machine, pin, name, pw, priv, enabled)
            return False
        return super().SSR_SetUserInfo(machine, pin, name, pw, priv, enabled)

    def SetUserTmpExStr(self, machine, pin, finger, flag, tmp):
        if str(pin) in self.refuse_tpl:
            self._rec("SetUserTmpExStr", machine, pin, finger, flag, tmp)
            return False
        return super().SetUserTmpExStr(machine, pin, finger, flag, tmp)


def _mb_worker(monkeypatch, drv, users):
    w = ue.UltraDeviceWorker(device={"id": 9, "name": "Entree 1"}, settings={"fingerprint_enabled": True},
                             popup_q=queue.Queue(), history_q=queue.Queue(),
                             stop_event=threading.Event())
    w._sdk = drv
    w._connected = True
    w._on_full_sync_started = MagicMock()
    w._on_full_sync_finished = MagicMock()
    cache = SimpleNamespace(users=list(users), devices=[])
    monkeypatch.setattr(ue, "load_sync_cache", lambda: cache)
    monkeypatch.setattr(ue, "insert_push_batch", MagicMock(return_value=1))
    monkeypatch.setattr(ue, "update_push_batch", lambda **kw: None)
    import app.core.device_sync as ds
    monkeypatch.setattr(ds.DeviceSyncEngine, "_build_local_fp_index_for_pins",
                        lambda self, *, pins, fingerprint_enabled: {}, raising=True)
    return w, cache


def _pass(w):
    w.request_full_sync(reason="timer", fingerprint_hash="h")
    assert w._drain_full_sync_commands(limit=1) == 1


class TestStandalone:

    def test_each_pushed_pin_gets_its_own_outcome(self, db, monkeypatch):
        term = RefusingTerminal()
        term.refuse = {"30002"}
        term.refuse_tpl = {"30003"}
        users = [_user(30001, "A", "101"), _user(30002, "B", "102"),
                 _user(30003, "C", "103", [_tpl(0, "AAAA")])]
        drv = _make_driver(term)
        try:
            w, _ = _mb_worker(monkeypatch, drv, users)
            _pass(w)
        finally:
            drv.disconnect()
        r = _results(9)
        assert r["30001"] == (True, None)
        assert r["30002"] == (False, "USER_WRITE_FAILED")
        assert r["30003"] == (False, "TEMPLATE_REFUSED")

    def test_the_unchanged_pin_backfill_is_not_an_attempt(self, db, monkeypatch):
        term = RefusingTerminal()
        users = [_user(30001, "A", "101")]
        drv = _make_driver(term)
        try:
            w, _ = _mb_worker(monkeypatch, drv, users)
            _pass(w)
            first = dbmod.list_push_results(device_id=9)["30001"]
            time.sleep(1.1)
            _pass(w)                      # unchanged: no write, the backfill runs
        finally:
            drv.disconnect()
        assert dbmod.list_push_results(device_id=9)["30001"] == first

    def test_an_interrupted_attempt_never_keeps_the_previous_true(self, db, monkeypatch):
        term = RefusingTerminal()
        users = [_user(30001, "A", "101")]
        drv = _make_driver(term)
        try:
            w, cache = _mb_worker(monkeypatch, drv, users)
            _pass(w)
            assert _results(9)["30001"] == (True, None)
            cache.users = [_user(30001, "A renamed", "101")]

            def crash(*a, **k):
                raise KeyboardInterrupt("power cut mid-push")
            monkeypatch.setattr(drv, "push_roster", crash)
            with pytest.raises(KeyboardInterrupt):
                w._run_standalone_full_sync(reason="timer", fingerprint_hash="h2")
        finally:
            drv.disconnect()
        assert _results(9)["30001"] == (None, None), "the intent reset it; no outcome followed"

    def test_a_wedged_chunk_is_a_timeout_and_an_unsent_chunk_stays_unknown(self, db, monkeypatch):
        term = RefusingTerminal()
        users = [_user(30001 + i, f"M{i}", str(100 + i)) for i in range(12)]
        drv = _make_driver(term)
        try:
            w, _ = _mb_worker(monkeypatch, drv, users)
            real = drv.push_roster

            def two_chunks(users_, templates, *, on_chunk=None, between_chunks=None, **kw):
                first, rest = users_[:10], users_[10:]
                on_chunk(first, {"ok": False, "error": "chunk wedged"})
                return {"ok": False, "pushed": 0, "failed": 12, "templates_failed": 0,
                        "skipped_pin": 0, "chunks_wedged": 1, "errors": ["wedged"],
                        "failed_pins": [u["pin"] for u in users_],
                        "failed_reasons": {**{u["pin"]: "chunk_wedged_or_unconfirmed" for u in first},
                                           **{u["pin"]: "not_attempted" for u in rest}}}
            monkeypatch.setattr(drv, "push_roster", two_chunks)
            _pass(w)
        finally:
            drv.disconnect()
        r = _results(9)
        assert all(r[str(30001 + i)] == (False, "TIMEOUT") for i in range(10))
        assert r["30011"] == (None, None) and r["30012"] == (None, None)


# ─────────────────────────── PullSDK ───────────────────────────

def _pull_users(*ams):
    from tests.test_account_pin_device_sites import _member
    return [_member(am, 9000 + am, None, f"M{am}", card=str(100000 + am)) for am in ams]


def _run_pull(users, sdk):
    from tests.test_account_pin_device_sites import _engine, _pullsdk_device
    with patch("app.core.device_sync.PullSDK", MagicMock(return_value=sdk)):
        _engine()._sync_one_device(device=_pullsdk_device(), users=users, local_fp_index={},
                                   default_door_id=1, changed_ids=None)


class TestPullSdk:

    def test_the_batch_path_confirms_each_pin_explicitly(self, db):
        from tests.test_account_pin_device_sites import _sdk
        sdk = _sdk()
        ams = list(range(101, 109))                       # > 5 pins: the batch path

        def batch(*, table, rows, chunk_size=50, progress_cb=None):
            if table == "user":
                failed = [r for r in rows if r.startswith("Pin=103\t")]
                return len(rows) - len(failed), failed
            return len(rows), []
        sdk.set_device_data_batch.side_effect = batch
        sdk.set_device_data.side_effect = lambda **kw: (_ for _ in ()).throw(
            RuntimeError("SetDeviceData FAILED rc=-2")) if "Pin=103" in kw.get("data", "") else 0
        _run_pull(_pull_users(*ams), sdk)
        r = _results(1)
        assert r["103"] == (False, "USER_WRITE_FAILED")
        assert all(r[str(a)] == (True, None) for a in ams if a != 103)

    def test_an_authorize_refusal_on_the_per_pin_path(self, db):
        from tests.test_account_pin_device_sites import _sdk
        sdk = _sdk()

        def set_data(*, table, data, options=""):
            if table == "userauthorize" and data.startswith("Pin=102"):
                raise RuntimeError("SetDeviceData FAILED table=userauthorize rc=-1")
            return 0
        sdk.set_device_data.side_effect = set_data
        _run_pull(_pull_users(101, 102), sdk)
        r = _results(1)
        assert r["101"] == (True, None)
        assert r["102"][0] is False and r["102"][1] == "AUTHORIZE_FAILED"

    def test_the_targeted_member_push(self, db):
        from tests.test_account_pin_device_sites import _cache, _engine, _pullsdk_device, _sdk
        _cache(db, _pull_users(101))
        assert _engine().sync_member_on_connected_sdk(sdk=_sdk(), device=_pullsdk_device(),
                                                      member_id=101) is True
        assert _results(1)["101"] == (True, None)


# ─────────────────────────── restore and upload ───────────────────────────

def test_a_restore_makes_every_result_of_that_turnstile_unknown(db):
    _state(db, 8, "100")
    db.record_push_results(device_id=8, rows=[("100", True, None)])
    db.record_push_results(device_id=9, rows=[("100", True, None)])
    api = FakeApi()
    api.pages = {0: [{"pin": "200", "state": "APPLIED", "pushedHash": "h", "pushedFingerIds": "",
                      "observedAt": "2026-09-27T09:00:00Z"}]}
    own.OwnershipSync(_rt(api)).restore(8, 3)
    assert _results(8)["100"] == (None, None), "acquiring the turnstile resets this PC's own result"
    assert "200" not in _results(8) or _results(8)["200"] == (None, None), "a restored pin reports null"
    assert _results(9)["100"] == (True, None), "another turnstile is not touched"


def _rows_of(api, n=-1):
    return {r["pin"]: r for r in api.uploads[n]["rows"]}


class TestUpload:

    def test_rows_carry_the_three_fields_with_their_exact_types(self, db):
        _state(db, 8, "100", h="h1", fingers="0")
        _state(db, 8, "101", h="h2", fingers="")
        _state(db, 8, "102", h="h3", fingers="1")
        db.record_push_results(device_id=8, rows=[("100", True, None), ("101", False, "TEMPLATE_REFUSED")])
        api = FakeApi()
        own.OwnershipSync(_rt(api)).upload(8)
        rows = _rows_of(api)
        assert rows["100"]["lastPushOk"] is True and rows["100"]["lastPushError"] is None
        assert isinstance(rows["100"]["lastPushAt"], str) and rows["100"]["lastPushAt"].endswith("Z")
        assert rows["101"]["lastPushOk"] is False and rows["101"]["lastPushError"] == "TEMPLATE_REFUSED"
        assert rows["102"]["lastPushOk"] is None and rows["102"]["lastPushAt"] is None
        assert rows["102"]["lastPushError"] is None
        json.dumps(api.uploads[-1], allow_nan=False)

    def test_a_flip_of_the_result_alone_is_uploaded_strictly_newer(self, db):
        _state(db, 8, "100", h="h1", fingers="0")
        db.record_push_results(device_id=8, rows=[("100", True, None)])
        api = FakeApi()
        sync = own.OwnershipSync(_rt(api))
        sync.upload(8)
        first = timefmt.to_epoch(_rows_of(api)["100"]["observedAt"])
        time.sleep(0.01)
        assert sync.upload(8) == {"rows": 0}, "nothing changed: nothing sent"
        db.record_push_results(device_id=8, rows=[("100", False, "USER_WRITE_FAILED")])
        sync.upload(8)
        row = _rows_of(api)["100"]
        assert row["lastPushOk"] is False and row["state"] == "APPLIED"
        assert timefmt.to_epoch(row["observedAt"]) > first, "the server keeps only a newer fact"

    def test_a_reset_to_unknown_is_a_change_too(self, db):
        _state(db, 8, "100")
        db.record_push_results(device_id=8, rows=[("100", True, None)])
        api = FakeApi()
        sync = own.OwnershipSync(_rt(api))
        sync.upload(8)
        db.record_push_intents(device_id=8, rows=[("100", "A", "", "h1")], protocol="ZK_STANDALONE")
        sync.upload(8)
        assert _rows_of(api)["100"]["lastPushOk"] is None

    def test_after_the_upgrade_nothing_is_re_sent_in_bulk(self, db):
        """Rows uploaded by the previous build (no result columns) and no result recorded yet:
        unchanged -- nothing goes up."""
        _state(db, 8, "100")
        api = FakeApi()
        sync = own.OwnershipSync(_rt(api))
        sync.upload(8)
        with db.get_conn() as conn:
            conn.execute("UPDATE v2_ownership_uploaded SET last_push_ok=NULL, last_push_src_at=NULL, "
                         "last_push_error=NULL, last_push_sent_at=NULL")
            conn.commit()
        assert sync.upload(8) == {"rows": 0}

    def test_last_push_at_is_capped_at_sent_at_and_recorded_as_sent(self, db):
        from app.core.v2.api import _cap_fact_times
        sent = 1_800_000_000.0
        body = {"rows": [{"pin": "1", "observedAt": timefmt.format_utc(sent + 30),
                          "lastPushOk": True, "lastPushAt": timefmt.format_utc(sent + 60),
                          "lastPushError": None},
                         {"pin": "2", "observedAt": timefmt.format_utc(sent - 5),
                          "lastPushOk": None, "lastPushAt": None, "lastPushError": None}]}
        out = _cap_fact_times(body, sent)
        assert timefmt.to_epoch(out["rows"][0]["lastPushAt"]) == pytest.approx(sent)
        assert timefmt.to_epoch(out["rows"][0]["observedAt"]) == pytest.approx(sent)
        assert out["rows"][1]["lastPushAt"] is None

    def test_a_full_re_send_keeps_the_recorded_last_push_time(self, db):
        _state(db, 8, "100")
        db.record_push_results(device_id=8, rows=[("100", True, None)])
        api = FakeApi()
        sync = own.OwnershipSync(_rt(api))
        sync.upload(8)
        at1 = _rows_of(api)["100"]["lastPushAt"]
        sync.upload(8, final=True)
        assert _rows_of(api)["100"]["lastPushAt"] == at1

    def test_a_removed_row_carries_no_result(self, db):
        _state(db, 8, "103")
        db.record_push_results(device_id=8, rows=[("103", True, None)])
        db.clear_device_revocation_state(device_id=8, pin="103")
        api = FakeApi()
        own.OwnershipSync(_rt(api)).upload(8)
        row = _rows_of(api)["103"]
        assert row["state"] == "REMOVED" and row["lastPushOk"] is None


# ─────────────────────────── the heartbeat clock: ageSec ───────────────────────────

def test_the_clock_report_carries_the_age_of_the_oldest_sample():
    t = {"wall": 1_000_000.0}
    clk = ServerClock(wall=lambda: t["wall"])
    clk.add_sample(t["wall"] + 5, t["wall"], t["wall"], source="welcome")
    t["wall"] += 100
    clk.add_sample(t["wall"] + 5, t["wall"], t["wall"], source="rest:x")
    t["wall"] += 20
    rep = clk.report()
    assert rep["ageSec"] == pytest.approx(120.0)
    assert rep["samples"] == 2


def test_the_age_follows_the_window_and_restarts_after_a_clock_skew_refusal():
    t = {"wall": 1_000_000.0}
    clk = ServerClock(wall=lambda: t["wall"])
    for _ in range(9):                   # WINDOW is 7: the two oldest drop out
        clk.add_sample(t["wall"] + 5, t["wall"], t["wall"], source="rest:x")
        t["wall"] += 10
    assert clk.report()["ageSec"] == pytest.approx(70.0)
    clk.add_sample(t["wall"] - 400, t["wall"], t["wall"], source="clock_skew", authoritative=True)
    t["wall"] += 3
    assert clk.report()["ageSec"] == pytest.approx(3.0)


def test_a_remembered_offset_counts_its_age_from_its_original_measurement():
    t = {"wall": 2_000_000.0}
    saved = {}
    clk = ServerClock(wall=lambda: t["wall"], persist=saved.update)
    clk.add_sample(t["wall"] + 5, t["wall"], t["wall"], source="welcome")
    t["wall"] += 30
    clk.add_sample(t["wall"] + 5, t["wall"], t["wall"], source="rest:x")
    clk.flush()
    t["wall"] += 600
    again = ServerClock(wall=lambda: t["wall"], load=lambda: dict(saved))
    rep = again.report()
    assert rep["samples"] == 0 and rep["ageSec"] == pytest.approx(630.0)
    older = ServerClock(wall=lambda: t["wall"],
                        load=lambda: {k: v for k, v in saved.items() if k != "oldest_at"})
    assert "ageSec" not in older.report(), "unknown age: left out"

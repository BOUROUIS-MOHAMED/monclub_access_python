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

Master corrections (2026-09-27, before contract revision 4): ``true`` needs the door authorization
read from ``_push_userauthorize``'s (0, error) answer everywhere; a reset row is stamped at the attempt
start; the heartbeat's clockOffset is a VIEW over the samples of the last 30 minutes.
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

    def reset_then_fail(conn, did, pins, **kw):
        real(conn, did, pins, **kw)
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
    engine = _engine()
    with patch("app.core.device_sync.PullSDK", MagicMock(return_value=sdk)):
        engine._sync_one_device(device=_pullsdk_device(), users=users, local_fp_index={},
                                default_door_id=1, changed_ids=None)
    return engine


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

def _paired(t, **kw):
    """A clock whose wall and monotonic time move together (no step), from t["wall"]."""
    return ServerClock(wall=lambda: t["wall"], mono=lambda: t["wall"] - 999_000.0, **kw)


def test_the_clock_report_carries_the_age_of_the_oldest_sample():
    t = {"wall": 1_000_000.0}
    clk = _paired(t)
    clk.add_sample(t["wall"] + 5, t["wall"], t["wall"], source="welcome")
    t["wall"] += 100
    clk.add_sample(t["wall"] + 5, t["wall"], t["wall"], source="rest:x")
    t["wall"] += 20
    rep = clk.report()
    assert rep["ageSec"] == pytest.approx(120.0)
    assert rep["samples"] == 2


def test_the_view_counts_every_sample_of_the_last_30_minutes_and_restarts_after_a_skew_refusal():
    """The heartbeat view is not the median window: all 9 samples of the last 30 minutes count
    (the window of 7 that drives ``offset()`` keeps only 7). A CLOCK_SKEW refusal restarts both."""
    t = {"wall": 1_000_000.0}
    clk = _paired(t)
    for _ in range(9):
        clk.add_sample(t["wall"] + 5, t["wall"], t["wall"], source="rest:x")
        t["wall"] += 10
    rep = clk.report()
    assert rep["ageSec"] == pytest.approx(90.0) and rep["samples"] == 9
    clk.add_sample(t["wall"] - 400, t["wall"], t["wall"], source="clock_skew", authoritative=True)
    t["wall"] += 3
    rep = clk.report()
    assert rep["ageSec"] == pytest.approx(3.0) and rep["samples"] == 1


def test_a_remembered_offset_counts_its_age_from_its_original_measurement():
    t = {"wall": 2_000_000.0}
    saved = {}
    clk = _paired(t, persist=saved.update)
    clk.add_sample(t["wall"] + 5, t["wall"], t["wall"], source="welcome")
    t["wall"] += 30
    clk.add_sample(t["wall"] + 5, t["wall"], t["wall"], source="rest:x")
    clk.flush()
    t["wall"] += 600
    again = ServerClock(wall=lambda: t["wall"], load=lambda: dict(saved))
    rep = again.report()
    # The remembered samples (each with its own time) still count in the view after a restart.
    assert rep["samples"] == 2 and rep["ageSec"] == pytest.approx(630.0)
    older = ServerClock(wall=lambda: t["wall"],
                        load=lambda: {k: v for k, v in saved.items() if k != "recent"})
    rep = older.report()
    assert "ageSec" not in rep and rep["samples"] == 0, "a row saved before: unknown age, left out"


def test_one_sample_every_ten_minutes_keeps_the_age_within_30_minutes():
    """Correction 3: with the socket up the guaranteed samples are the assignment refreshes, one
    every 600 s. The window of 7 then spans an hour, so its oldest sample never passed the
    dashboard's 30-minute freshness rule. The view reports only the last 30 minutes."""
    t = {"wall": 1_000_000.0}
    clk = _paired(t)
    for i in range(8):                   # minutes 0, 10, ..., 70; offsets 1 .. 8 s
        clk.add_sample(t["wall"] + (i + 1), t["wall"], t["wall"], source="assignment")
        if i < 7:
            t["wall"] += 600
    rep = clk.report()
    assert rep["ageSec"] == pytest.approx(1800.0) and rep["ageSec"] <= 1800.0
    assert rep["samples"] == 4                        # minutes 40, 50, 60, 70
    assert rep["offsetSec"] == pytest.approx(6.5)     # their median
    assert clk.offset() == pytest.approx(5.0), "the window that drives sentAt keeps its 7 samples"


def test_no_sample_in_the_last_30_minutes_sends_no_age():
    t = {"wall": 1_000_000.0}
    clk = _paired(t)
    clk.add_sample(t["wall"] + 5, t["wall"], t["wall"], source="welcome")
    t["wall"] += 600
    clk.add_sample(t["wall"] + 7, t["wall"], t["wall"], source="assignment")
    t["wall"] += 35 * 60
    rep = clk.report()
    assert "ageSec" not in rep
    assert rep["samples"] == 0, "samples counts the view: none recent (contract revision 4.1 §5.1)"
    assert rep["offsetSec"] == pytest.approx(6.0), "the offset is the window's"


# ─────────────────────────── master corrections (2026-09-27, before contract revision 4) ───────────────────────────

class TestTrueNeedsTheDoorRights:
    """Correction 2: on PullSDK ``true`` needs the user row, the door authorization AND the
    templates, each positively confirmed; ``_push_userauthorize`` answers ``(0, error)`` without
    raising, and every place that calls it must read that answer."""

    def test_an_authorize_error_in_discovery_and_in_the_fallback_is_false(self, db):
        from tests.test_account_pin_device_sites import _sdk
        sdk = _sdk()
        ams = list(range(101, 109))                        # > 5 pins: the batch path
        sdk.set_device_data_batch.side_effect = (
            lambda *, table, rows, chunk_size=50, progress_cb=None: (len(rows), []))

        def set_data(*, table, data, options=""):
            # Every pattern of 101 (the pattern discovery) and of 104 (the per-pin fallback
            # that follows a failed discovery) is refused: both answer (0, error).
            if table == "userauthorize" and (data.startswith("Pin=101\t")
                                             or data.startswith("Pin=104\t")):
                raise RuntimeError("SetDeviceData FAILED table=userauthorize rc=-1")
            return 0
        sdk.set_device_data.side_effect = set_data
        engine = _run_pull(_pull_users(*ams), sdk)
        r = _results(1)
        assert r["101"] == (False, "AUTHORIZE_FAILED"), "discovery's (0, error) is read"
        assert r["104"] == (False, "AUTHORIZE_FAILED"), "the fallback's (0, error) is read"
        assert all(r[str(a)] == (True, None) for a in ams if a not in (101, 104))
        # Lane 1b (review F16): the RETRY is what the fix is for, and the result table does not
        # drive it -- the sync state does (last_ok=0: pushed again, counted as waiting).
        state = db.list_device_sync_hashes_and_status(device_id=1)
        assert state["101"][1] is False and state["104"][1] is False, "retried, never in sync"
        assert all(state[str(a)][1] is True for a in ams if a not in (101, 104))
        assert engine._last_waiting_pins == 2, "the heartbeat's N waiting counts both"

    def test_the_fallback_serves_the_door_between_pins(self, db):
        """Lane 1b (review F9): with no cached pattern every pin may take 4 SetDeviceData;
        the door and the scans are served between two pins, never after the whole roster."""
        from tests.test_account_pin_device_sites import _engine, _pullsdk_device, _sdk
        sdk = _sdk()
        ams = list(range(101, 109))
        sdk.set_device_data_batch.side_effect = (
            lambda *, table, rows, chunk_size=50, progress_cb=None: (len(rows), []))
        events = []

        def set_data(*, table, data, options=""):
            if table == "userauthorize":
                events.append(("auth", data.split("	", 1)[0]))
                raise RuntimeError("SetDeviceData FAILED table=userauthorize rc=-1")
            return 0
        sdk.set_device_data.side_effect = set_data
        engine = _engine()
        engine._door_yield_cb = lambda: events.append(("door",))
        engine._rtlog_yield_cb = lambda: events.append(("rtlog",))
        with patch("app.core.device_sync.PullSDK", MagicMock(return_value=sdk)):
            engine._sync_one_device(device=_pullsdk_device(), users=_pull_users(*ams),
                                    local_fp_index={}, default_door_id=1, changed_ids=None)
        firsts = []
        for i, e in enumerate(events):
            if e[0] == "auth" and e[1] != "Pin=101" and e[1] not in [events[j][1] for j in firsts]:
                firsts.append(i)
        assert len(firsts) == 7, "every pin after the failed discovery went through the fallback"
        for a, b in zip(firsts, firsts[1:]):
            between = {e[0] for e in events[a:b]}
            assert {"door", "rtlog"} <= between, (events[a:b])

    @pytest.mark.parametrize("path", ["per_pin", "targeted"])
    def test_any_authorize_error_is_false_even_with_a_count(self, db, path):
        """``auth_complete`` used to be ``ok_count == len(door_ids)`` when an error came back:
        an error with a matching count read as complete. Any error is now a failure."""
        from app.core.device_sync import DeviceSyncEngine
        from tests.test_account_pin_device_sites import _cache, _engine, _pullsdk_device, _sdk
        with patch.object(DeviceSyncEngine, "_push_userauthorize",
                          lambda self, sdk, **kw: (1, "partial answer")):
            if path == "per_pin":
                _run_pull(_pull_users(101), _sdk())
            else:
                _cache(db, _pull_users(101))
                assert _engine().sync_member_on_connected_sdk(
                    sdk=_sdk(), device=_pullsdk_device(), member_id=101) is False
        assert _results(1)["101"] == (False, "AUTHORIZE_FAILED")


class TestStandaloneTrueNeedsTheVacatedSlotsCleared:

    def test_a_refused_vacated_slot_is_false(self, db, monkeypatch):
        class _NoClear(RefusingTerminal):
            def SSR_DelUserTmpExt(self, machine, pin, finger_id):
                if (str(pin), int(finger_id)) == ("30001", 1):
                    self._rec("SSR_DelUserTmpExt", machine, pin, finger_id)
                    return False
                return super().SSR_DelUserTmpExt(machine, pin, finger_id)

        term = _NoClear()
        users = [_user(30001, "A", "101", [_tpl(0, "AAAA"), _tpl(1, "BBBB")])]
        drv = _make_driver(term)
        try:
            w, cache = _mb_worker(monkeypatch, drv, users)
            _pass(w)
            assert _results(9)["30001"] == (True, None)
            cache.users = [_user(30001, "A", "101", [_tpl(0, "AAAA")])]   # finger 1 revoked
            w.request_full_sync(reason="timer", fingerprint_hash="h2")
            assert w._drain_full_sync_commands(limit=1) == 1
        finally:
            drv.disconnect()
        assert _results(9)["30001"] == (False, "FINGER_CLEAR_FAILED")


class TestAResetRowIsANewerFact:
    """Correction 4: a result reset at an attempt start is uploaded with an observedAt no earlier
    than that START (corrected clock) -- not the previous upload + 1 ms -- so the server takes it
    over another PC's later ``true``. Every new attempt re-sends it."""

    def test_the_reset_row_is_stamped_at_the_attempt_start(self, db):
        _state(db, 8, "100", updated="2026-09-20 10:00:00")
        db.record_push_results(device_id=8, rows=[("100", True, None)])
        api = FakeApi()
        sync = own.OwnershipSync(_rt(api))
        sync.upload(8)
        before = timefmt.to_epoch(_rows_of(api)["100"]["observedAt"])
        time.sleep(0.05)
        t_start = time.time()
        db.record_push_intents(device_id=8, rows=[("100", "A", "", "h1")], protocol="ZK_STANDALONE")
        sync.upload(8)
        row = _rows_of(api)["100"]
        assert row["lastPushOk"] is None and row["lastPushAt"] is None
        at = timefmt.to_epoch(row["observedAt"])
        assert at >= t_start - 0.01 and at > before + 0.01, "the attempt start, not previous + 1 ms"

    def test_every_new_attempt_re_sends_the_reset_row(self, db):
        _state(db, 8, "100")
        db.record_push_intents(device_id=8, rows=[("100", "A", "", "h1")], protocol="ZK_STANDALONE")
        api = FakeApi()
        sync = own.OwnershipSync(_rt(api))
        sync.upload(8)
        first = timefmt.to_epoch(_rows_of(api)["100"]["observedAt"])
        assert sync.upload(8) == {"rows": 0}, "unchanged: not re-sent"
        time.sleep(0.05)
        db.record_push_intents(device_id=8, rows=[("100", "A", "", "h2")], protocol="ZK_STANDALONE")
        sync.upload(8)
        assert timefmt.to_epoch(_rows_of(api)["100"]["observedAt"]) > first

    def test_the_reset_keeps_its_time_on_the_result_row(self, db):
        db.record_push_results(device_id=8, rows=[("100", True, None)])
        db.record_push_intents(device_id=8, rows=[("100", "A", "", "h")], protocol="ZK_STANDALONE")
        ok, at, _corrected, err = dbmod.list_push_results(device_id=8)["100"]
        assert ok is None and err is None and at is not None and abs(at - time.time()) < 60


# ─────────────────────────── review round 3 (2026-09-27) ───────────────────────────

def test_a_sample_taken_before_a_clock_step_back_never_returns_to_the_view():
    """A sample stamped later than the PC's clock (taken before Windows stepped the clock back)
    is dropped, not merely hidden until the clock catches up with it again."""
    real = {"t": 1_000_000.0}
    pc = {"wall": real["t"] + 3600.0}                  # the PC clock runs 1 h ahead
    clk = ServerClock(wall=lambda: pc["wall"], mono=lambda: real["t"])
    clk.add_sample(real["t"], pc["wall"], pc["wall"], source="welcome")     # offset -3600
    real["t"] += 60
    pc["wall"] = real["t"]                             # stepped back to the real time
    clk.add_sample(real["t"], pc["wall"], pc["wall"], source="assignment")
    real["t"] += 3600 - 60 + 10
    pc["wall"] = real["t"]
    rep = clk.report()
    # The good sample is 58 min old, the pre-step one was dropped: nothing in the view, so
    # samples 0, no age, and the window's offset (it keeps both: offset() is not this view).
    assert "ageSec" not in rep and rep["samples"] == 0
    assert rep["offsetSec"] == pytest.approx(-1800.0)


def test_a_persisted_sample_from_the_future_is_dropped_at_load():
    t = {"wall": 2_000_000.0}
    row = {"offset_sec": 1.0, "measured_at": t["wall"] - 10, "source": "rest:x",
           "recent": [[1.0, t["wall"] - 10], [-3600.0, t["wall"] + 3000]]}
    clk = _paired(t, load=lambda: dict(row))
    t["wall"] += 3100
    rep = clk.report()
    assert "ageSec" not in rep and rep["samples"] == 0 and rep["offsetSec"] == pytest.approx(1.0)


def test_an_mb2000_pin_the_driver_skips_as_invalid_gets_no_result(db, monkeypatch):
    """Round 3 (nit): the driver skips a pin of more than 9 digits without writing it and
    without naming it failed; the engine used to record it true."""
    term = RefusingTerminal()
    users = [_user(30001, "A", "101"), _user(1234567890, "B", "102")]
    drv = _make_driver(term)
    try:
        w, _ = _mb_worker(monkeypatch, drv, users)
        _pass(w)
    finally:
        drv.disconnect()
    r = _results(9)
    assert r["30001"] == (True, None)
    assert "1234567890" not in term.users
    assert r.get("1234567890") in (None, (None, None)), r


def test_the_engine_pin_guard_is_the_drivers():
    from app.sdk.zk_standalone import _MAX_PIN_DIGITS
    assert ue.UltraDeviceWorker._STANDALONE_MAX_PIN_DIGITS == _MAX_PIN_DIGITS


def test_a_pre_step_sample_leaves_the_view_even_with_no_sample_before_the_catch_up():
    """Review round 4: dropping at add_sample/load only caught a step back when a sample landed
    while the old one was still "ahead". The monotonic time kept with each sample detects the
    step whatever happens next: the PC clock 5 min ahead, one sample, a step back 60 s later, no
    sample for 400 s -- the pre-step sample never returns, nor is it persisted."""
    real = {"t": 1_000_000.0}
    pc = {"wall": real["t"] + 300.0}
    saved = []
    clk = ServerClock(wall=lambda: pc["wall"], mono=lambda: real["t"], persist=saved.append)
    clk.add_sample(real["t"], pc["wall"], pc["wall"], source="assignment")   # offset -300
    real["t"] += 60
    pc["wall"] = real["t"]
    assert "ageSec" not in clk.report()
    real["t"] += 400
    pc["wall"] = real["t"]
    assert "ageSec" not in clk.report(), "the catch-up does not bring it back"
    real["t"] += 140
    pc["wall"] = real["t"]
    clk.add_sample(real["t"], pc["wall"], pc["wall"], source="assignment")   # offset 0
    rep = clk.report()
    assert rep["samples"] == 1 and rep["offsetSec"] == pytest.approx(0.0) and rep["ageSec"] == 0.0
    clk.flush()
    assert [r[0] for r in saved[-1]["recent"]] == [pytest.approx(0.0)]


def test_a_forward_step_also_retires_the_samples_before_it():
    t = {"wall": 1_000_000.0, "mono": 10.0}
    clk = ServerClock(wall=lambda: t["wall"], mono=lambda: t["mono"])
    clk.add_sample(t["wall"] + 5, t["wall"], t["wall"], source="a")
    t["mono"] += 30
    t["wall"] += 30 + 3600                             # the PC clock jumps 1 h forward
    assert "ageSec" not in clk.report()


@pytest.mark.parametrize("step", [-300.0, -30.0])
def test_a_loaded_sample_is_retired_by_a_step_after_the_restart(step):
    """Review round 5: a sample loaded from disk had no monotonic time, so a wall-clock step after
    the restart went unseen -- a step back larger than its age hid it until the clock caught up,
    then it came back; a smaller one understated its age. Loaded samples are pinned at load."""
    t = {"wall": 3_000_000.0}
    row = {"offset_sec": -300.0, "measured_at": t["wall"] - 60, "source": "rest:x",
           "recent": [[-300.0, t["wall"] - 60]]}
    real = {"m": 500.0}
    clk = ServerClock(wall=lambda: t["wall"], mono=lambda: real["m"], load=lambda: dict(row))
    assert clk.report()["ageSec"] == pytest.approx(60.0), "loaded: aged on the wall clock"
    t["wall"] += step                                  # Windows steps the clock after the restart
    assert "ageSec" not in clk.report()
    real["m"] += 400
    t["wall"] += 400
    assert "ageSec" not in clk.report(), "and it never comes back"


# ─────────────────────────── contract revision 4.1: the fifth writer ───────────────────────────

class TestTheAdminUsersPushRoute:
    """``POST /api/v2/devices/{id}/users/push`` writes a user row, door rights and templates for any
    pin, outside the sync. Not a MonClub attempt -- never ``true`` -- but it changes what the
    turnstile holds: the pin's result becomes unknown, durably, before the first device write."""

    def _call(self, monkeypatch, sdk):
        import app.api.local_access_api_v2 as la2
        monkeypatch.setattr(la2, "_unsupported_for_protocol", lambda *a, **k: False)
        monkeypatch.setattr(la2, "_connect_device", lambda ctx, did: (sdk, None))
        sent = []
        ctx = SimpleNamespace(app=SimpleNamespace(), param_int=lambda name, default=0: 5,
                              body=lambda: {"pin": "101", "name": "A", "cardNo": "1001"},
                              send_json=lambda status, payload: sent.append((status, payload)))
        la2._handle_device_users_push(ctx)
        return sent

    def test_the_result_is_reset_before_the_first_write_and_never_true(self, db, monkeypatch):
        db.record_push_results(device_id=5, rows=[("101", True, None)])
        seen = []
        sdk = MagicMock()
        sdk.set_device_data.side_effect = lambda **kw: seen.append(
            dbmod.list_push_results(device_id=5)["101"]) or 0
        self._call(monkeypatch, sdk)
        assert seen, "the route wrote to the turnstile"
        ok, at, _corr, err = seen[0]
        assert ok is None and err is None and at is not None, "unknown, and stamped, before the write"
        assert dbmod.list_push_results(device_id=5)["101"][0] is None, "never true afterwards"

    def test_no_write_when_the_reset_cannot_be_recorded(self, db, monkeypatch):
        def _broken(**kw):
            raise RuntimeError("disk full")

        monkeypatch.setattr(dbmod, "reset_push_results_for_pins", _broken)
        sdk = MagicMock()
        sent = self._call(monkeypatch, sdk)
        assert sent and sent[-1][0] == 500
        assert not sdk.set_device_data.called and sdk.disconnect.called

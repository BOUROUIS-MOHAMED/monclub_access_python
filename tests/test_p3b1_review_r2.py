"""P3b-1 adversarial review, round 2: regressions for the confirmed findings.

Real temp SQLite through the ``app.core.db._DB_PATH`` override; no network.
"""
from __future__ import annotations

from datetime import date

import pytest

import app.core.db as dbmod
from app.core import access_dates as ad
from tests.test_protocol2_save_and_flip import _flip, _ids, _seed_full_v2


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "r2.db"), raising=False)
    dbmod._shutdown_db_writer_for_tests()
    dbmod.init_db()
    yield dbmod
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


# ================================================================== 1. a huge offline grace
@pytest.mark.parametrize("grace", [9_999_999, 10 ** 12])
def test_a_huge_grace_is_a_grace_not_an_overflow(grace):
    w = ad.AccessWindow(date(2026, 9, 1), date(2026, 9, 19), frozenset())
    assert ad.window_status(w, date(2026, 9, 20), horizon_end=date(2026, 9, 26),
                            server_today=date(2026, 9, 19), grace_days=grace) == "grace"


def test_the_grace_boundary_is_unchanged():
    w = ad.AccessWindow(date(2026, 9, 1), date(2026, 9, 19), frozenset())
    kw = dict(horizon_end=date(2026, 9, 26), server_today=date(2026, 9, 19), grace_days=2)
    assert ad.window_status(w, date(2026, 9, 21), **kw) == "grace"
    assert ad.window_status(w, date(2026, 9, 22), **kw) == "expired"


def test_an_offline_flip_with_a_huge_grace_still_moves_the_other_rows(db):
    # 1 ends on the 19th (kept by the grace); 2 is frozen on the 20th (held); 3 starts (promoted).
    _seed_full_v2(db)
    r = _flip(db, "2026-09-20T07:30:00+01:00", grace=9_999_999)
    assert r["held"] == 1 and r["promoted"] == 1
    assert 1 in _ids("sync_users") and 2 in _ids("sync_users_held") and 3 in _ids("sync_users")


# ================================================================== 2. a renewal on a full MB2000
import queue  # noqa: E402

import app.core.telemetry as tel  # noqa: E402
import app.core.ultra_engine as ue  # noqa: E402
from tests.fake_terminal import TerminalZkem  # noqa: E402
from tests.test_standalone_incremental_sync import _make_driver, _worker  # noqa: E402

PERSON, OLD, NEW = 900, 34439, 30001
USER_CAPACITY = 5          # the terminal holds 5 users; it is full with OLD + 4 others


@pytest.fixture
def events(monkeypatch):
    seen = []
    real_event, real_warn = tel.event, tel.warn
    monkeypatch.setattr(tel, "event", lambda n, **f: (seen.append((n, f)), real_event(n, **f))[1])
    monkeypatch.setattr(tel, "warn", lambda n, **f: (seen.append((n, f)), real_warn(n, **f))[1])
    return seen


class _FullTerm(TerminalZkem):
    """GetDeviceStatus 11 (users_free) follows the live user table; 10 = plenty of finger slots."""

    def GetDeviceStatus(self, machine, idx, box):
        self.status = {11: max(0, USER_CAPACITY - len(self.users)), 10: 1000}
        return super().GetDeviceStatus(machine, idx, box)


def _mrow(am, uid, name="Ali", card=""):
    return {"activeMembershipId": am, "userId": uid, "membershipId": 3, "fullName": name,
            "firstCardId": card, "fingerprints": []}


def test_a_renewal_on_a_full_terminal_removes_the_old_pin_first_and_the_new_one_lands(
        db, monkeypatch, events):
    # Review R2: the hold kept OLD's user slot, capacity admission refused NEW (CAPACITY_FULL)
    # on every pass, and a card moved from OLD to NEW opened nothing. Base removed OLD first.
    term = _FullTerm()
    term.add_user(str(OLD), "Ali", "")                  # the card was moved to NEW at the sale
    db.save_device_sync_state_batch(device_id=9, rows=[(str(OLD), "h-old", True, None, "")])
    others = [_mrow(30100 + i, 800 + i, f"M{i}", str(9000 + i)) for i in range(4)]
    for r in others:
        e = {"pin": str(r["activeMembershipId"]), "name": r["fullName"], "card": r["firstCardId"]}
        term.add_user(e["pin"], e["name"], e["card"])
        db.save_device_sync_state_batch(device_id=9, rows=[
            (e["pin"], ue._standalone_pin_hash(e, []), True, None, "")])
    new_row = _mrow(NEW, PERSON, card="777")
    db.upsert_delta_users([_mrow(OLD, PERSON)] + [new_row] + others)
    db.delete_users_by_am_ids({OLD})                    # the flip held OLD out
    drv = _make_driver(term)
    term.sink = drv._on_att_event
    w, _cache = _worker(monkeypatch, driver=drv, users=[new_row] + others)
    w._cmd_queue = queue.Queue()
    try:
        w.request_full_sync(reason="date-flip", fingerprint_hash="h", revoked_ids=set())
        assert w._drain_full_sync_commands(limit=1) == 1
    finally:
        drv.disconnect()
    assert str(OLD) not in term.users
    assert (term.users.get(str(NEW)) or {}).get("card") == "777"
    assert not [f for n, f in events if n == "CAPACITY_FULL"]


# ================================================================== 3. 00:17 on the server's clock
@pytest.mark.parametrize(("skew", "expected"), [(121.0, 1015 + 121), (-60.0, 1015), (None, 1015)])
def test_the_first_day_sync_waits_for_00_17_on_the_servers_clock(tests_flip_app, monkeypatch,
                                                                 skew, expected):
    app, _ = tests_flip_app
    state = {"utc_offset_sec": 3600}
    if skew is not None:
        state["skew_sec"] = skew
    monkeypatch.setattr("app.core.db.get_access_v2_state", lambda: dict(state))
    app._arm_first_day_credentials_sync({"starters": [3]}, _flip_epoch("2026-09-20T00:00:05+01:00"))
    [delay] = _scheduled(app, app._run_first_day_credentials_sync)
    assert delay == pytest.approx(expected, abs=1)


def _flip_epoch(iso):
    from datetime import datetime
    return datetime.fromisoformat(iso).timestamp()


def _scheduled(app, callback):
    import time as _time
    now = _time.monotonic()
    with app._sched_lock:
        return [t - now for t, _sid, cb in app._scheduled if cb == callback]


@pytest.fixture
def tests_flip_app(tmp_path, monkeypatch):
    import threading
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from app.ui.app import MainApp

    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "r2_0017.db"), raising=False)
    app = object.__new__(MainApp)
    app.logger = MagicMock()
    app.cfg = SimpleNamespace(offline_revoke_grace_days=0)
    app._stop_event = threading.Event()
    MainApp._init_scheduler(app)
    MainApp._init_date_flip_state(app)
    app.request_sync_now = MagicMock()
    return app, None


# ================================================================== 4. the ULTRA rescue's day: index or loop
import random  # noqa: E402
import time  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from unittest.mock import patch  # noqa: E402

from app.core import access_verification as av  # noqa: E402
from tests.test_totp_index import _settings  # noqa: E402
from tests.test_totp_roster_check import _ultra_worker  # noqa: E402

SECTIONS = {"members": True, "devices": False, "credentials": True, "settings": False}
OLD, NEW, OTHER, ACCOUNT = 606, 909, 101, 5006


def _r2_epoch(iso):
    return datetime.fromisoformat(iso).timestamp()


@pytest.fixture
def _fresh_ultra():
    av._reset_access_days_cache_for_tests()
    ue._set_shared_local_state(None, -1)
    ue._set_shared_totp_index(None, -1)
    yield
    av._reset_access_days_cache_for_tests()
    ue._set_shared_local_state(None, -1)
    ue._set_shared_totp_index(None, -1)


@pytest.fixture
def _r2b_db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "r2b.db"), raising=False)
    dbmod._shutdown_db_writer_for_tests()
    dbmod.init_db()
    yield dbmod
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


def _r2_row(am, frm, until, main):
    return {"activeMembershipId": am, "userId": 7606 if am in (OLD, NEW) else 7000 + am,
            "membershipId": 3, "fullName": f"M{am}", "mainAccountId": main,
            "accessFrom": frm, "accessUntil": until, "offDays": []}


def _code_at(cred, s, t):
    period, drift, digits, prefix = av._totp_params(s)
    return prefix + av._totp_hotp(av._totp_hex_to_bytes(cred["secretHex"]),
                                  av._totp_counter(int(t), period), digits)


def _scan(worker, code, t_scan, eid):
    from tests.test_ultra_engine import _make_event
    iso = datetime.fromtimestamp(t_scan, tz=timezone.utc).isoformat()
    with (
        patch("app.core.ultra_engine.insert_access_history", return_value=1),
        patch("app.core.ultra_engine.get_staff_membership_ids_cached", return_value=set()),
        patch.object(worker, "_trigger_bg_cache_refresh", lambda *a, **k: None),
    ):
        worker._sdk.open_door.reset_mock()
        worker._process_event(_make_event(event_id=eid, card_no=code, event_type=1, door_id=1,
                                          event_time=iso))
    return worker._history_q.get_nowait()


def _late_scan_setup(db, main):
    rng = random.Random(7)
    c = {"id": 6, "gymId": 1, "accountId": ACCOUNT, "enabled": True,
         "secretHex": "".join(rng.choice("0123456789abcdef") for _ in range(32)),
         "grantedActiveMembershipIds": [OLD], "updatedAt": "2026-09-01T10:00:00Z"}
    o = {"id": 1, "gymId": 1, "accountId": 5101, "enabled": True,
         "secretHex": "".join(rng.choice("0123456789abcdef") for _ in range(32)),
         "grantedActiveMembershipIds": [OTHER], "updatedAt": "2026-09-01T10:00:00Z"}
    new_up = dict(_r2_row(NEW, "2026-09-20", "2026-10-20", main), qrAccountId=ACCOUNT)
    eve = {"syncMeta": {"protocol": 2, "today": "2026-09-19", "horizonDays": 7,
                        "horizonEnd": "2026-09-26", "serverTime": "2026-09-19T20:00:00.000+01:00",
                        "snapshotAt": "2026-09-19T20:00:00.000+01:00", "reconcileSec": 600,
                        "capabilities": ["accessWindows", "upcoming", "upcomingCredentials"]},
           "currentWindowsVersion": "p2.7.a.b", "refreshMembers": True, "membersDeltaMode": False,
           "users": [_r2_row(OLD, "2026-08-20", "2026-09-19", main), _r2_row(OTHER, "2026-09-01", "2026-09-30", 5101)],
           "memberWindows": [], "upcoming": [new_up], "upcomingIds": [NEW], "upcomingCredentials": [],
           "gymAccessCredentials": [c, o], "_clientReceivedAtEpoch": _r2_epoch("2026-09-19T20:00:02+01:00")}
    db.save_sync_cache_delta(eve, SECTIONS)
    db.apply_local_date_flips(pc_now_epoch=_r2_epoch("2026-09-19T20:00:05+01:00"), grace_days=0, source="save")

    s = {**_settings(), "totp_roster_check_mode": "trial"}
    g0 = db.get_local_state_generation()
    state0 = av.load_local_state()
    a = _ultra_worker(s, state0[0], state0[1])        # (_make_worker clears the shared state)
    b = _ultra_worker(s, state0[0], state0[1])
    ue._set_shared_local_state(state0, g0)                       # the pre-flip refresh published
    ue._set_shared_totp_index(av.build_totp_index(state0[0], s, time.time(), margin=1), g0)
    for w in (a, b):
        w._cached_state = state0
        w._cached_state_gen = g0
        w._cached_pair = (state0, g0)
    out = db.apply_local_date_flips(pc_now_epoch=_r2_epoch("2026-09-20T07:30:00+01:00"), grace_days=0,
                                    source="startup")
    assert out["held"] == 1 and out["promoted"] == 1
    a.reset_fast_patch_caches()
    b.reset_fast_patch_caches()
    # Door A has an event first: adopts the (pre-flip) shared list; its own refresh is slow.
    with patch.object(a, "_trigger_bg_cache_refresh", lambda *x, **k: None):
        a._get_cached_local_state()
    assert a._cached_pair[0] is state0          # door A holds the pre-flip list
    # Door B then refreshes for real: post-flip list + index published.
    target = db.get_local_state_generation()
    b._trigger_bg_cache_refresh()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if ue._get_shared_local_state()[1] >= target and ue._get_shared_totp_index()[1] >= target:
            break
        time.sleep(0.02)
    b._stop_evt.set()
    time.sleep(0.2)
    return c, s, a, b


@pytest.mark.parametrize("main", [None, ACCOUNT])
def test_a_late_scan_at_the_lagging_door_uses_the_day_of_the_credentials_it_matched(
        _r2b_db, _fresh_ultra, main):
    # Review R2: the index did not cover a 70 s late event, so verify_totp looped over door A's
    # own pre-flip credentials (grants [606]) -- but the rescue had bounded the day by the
    # index's post-flip generation, and refused a renewing member (trial) that door B admits.
    c, s, a, b = _late_scan_setup(_r2b_db, main)
    now = time.time()
    t_late = now - 70
    assert _scan(a, _code_at(c, s, now), now, "live-a").allowed is True
    assert _scan(a, _code_at(c, s, t_late), t_late, "late-a").allowed is True
    assert _scan(b, _code_at(c, s, t_late), t_late, "late-b").allowed is True

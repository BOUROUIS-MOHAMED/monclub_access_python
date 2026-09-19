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

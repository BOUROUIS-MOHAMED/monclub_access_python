"""P3b-2 step 7: loss detection and re-add (owner decision 6).

Re-add ONLY MonClub members missing from a TRUSTED listing; never a user MonClub cannot prove it
owns; never after a listing that loses more than the ceiling (P3a-2 R6-02/03: a cut-short
listing re-pushed most of the roster). The re-add is a marker the next pass reads, never a
cleared hash.
"""
from __future__ import annotations

import time

import pytest

from app.core.v2 import loss
from app.core.v2 import problems as pr
from app.core.v2 import store
from tests.test_standalone_finger_removal_state import FingerState, fstate  # noqa: F401
from tests.test_standalone_incremental_sync import _user, _worker


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as dbmod
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "loss.db"), raising=False)
    dbmod.init_db()
    pr.registry.reset_for_tests()
    yield dbmod
    pr.registry.reset_for_tests()
    dbmod._shutdown_db_writer_for_tests()


OWNED = {str(100 + i) for i in range(40)}


def test_a_trusted_listing_re_adds_only_missing_desired_owned_members(db):
    on_device = (OWNED - {"100", "101", "102"}) | {"900"}          # 900: not MonClub's
    out = loss.evaluate_listing(8, on_device=on_device, owned=OWNED, desired=OWNED - {"102"})
    assert out["trusted"] and out["missing"] == ["100", "101", "102"]
    assert out["readd"] == ["100", "101"], "102 left the roster: reported, not re-added"
    assert loss.readd_pins(8) == {"100", "101"}
    [p] = pr.registry.snapshot(8)
    assert p["code"] == "MISSING_OWNED" and p["pins"] == ["100", "101", "102"]


def test_a_listing_that_loses_more_than_the_ceiling_is_not_believed(db):
    on_device = {"100", "101"}                                        # cut short: 38 "missing"
    out = loss.evaluate_listing(8, on_device=on_device, owned=OWNED, desired=OWNED)
    assert not out["trusted"] and out["readd"] == [] and loss.readd_pins(8) == set()
    assert pr.registry.snapshot(8)[0]["count"] == 38, "still reported"


@pytest.mark.parametrize("on_device", [set(), {"900", "901"}])
def test_an_empty_listing_or_one_with_no_monclub_pin_changes_nothing(db, on_device):
    out = loss.evaluate_listing(8, on_device=on_device, owned=OWNED, desired=OWNED)
    assert out["readd"] == [] and loss.readd_pins(8) == set() and pr.registry.snapshot(8) == []


def test_a_full_listing_resolves_missing_owned(db):
    loss.evaluate_listing(8, on_device=OWNED - {"100"}, owned=OWNED, desired=OWNED)
    loss.evaluate_listing(8, on_device=OWNED, owned=OWNED, desired=OWNED)
    assert pr.registry.snapshot(8) == []


def test_a_marker_is_tried_a_bounded_number_of_times(db):
    loss.mark_readd(8, ["100"])
    for _ in range(loss.READD_MAX_ATTEMPTS):
        assert loss.readd_pins(8) == {"100"}
        loss.note_attempts(8, ["100"])
    assert loss.readd_pins(8) == set()


def test_the_next_pass_pushes_a_re_add_pin_the_state_calls_in_sync(db, monkeypatch, fstate):
    w, _c = _worker(monkeypatch, users=[_user(30001, "a", ""), _user(30002, "b", "")])
    monkeypatch.setattr("app.core.db.list_device_sync_hashes_and_status",
                        lambda device_id: {"30001": ("h1", True), "30002": ("h2", True)})
    monkeypatch.setattr("app.core.db.list_device_sync_retry_state", lambda device_id: {})
    users = [{"pin": "30001"}, {"pin": "30002"}]
    to_push, skipped = w._standalone_pins_needing_push(users, {"30001": "h1", "30002": "h2"})
    assert to_push == [] and skipped == 2
    loss.mark_readd(w._device_id, ["30002"])
    to_push, _ = w._standalone_pins_needing_push(users, {"30001": "h1", "30002": "h2"})
    assert [u["pin"] for u in to_push] == ["30002"] and w._last_push_kinds["30002"] == "readd"
    w._note_template_version_problems([{"pin": "30002"}], {"failed_pins": []})
    assert loss.readd_pins(w._device_id) == set(), "a confirmed push clears the marker"


def test_a_pin_in_retry_backoff_is_not_forced_by_a_re_add(db, monkeypatch, fstate):
    w, _c = _worker(monkeypatch, users=[])
    monkeypatch.setattr("app.core.db.list_device_sync_hashes_and_status",
                        lambda device_id: {"30002": ("h2", False)})
    monkeypatch.setattr("app.core.db.list_device_sync_retry_state",
                        lambda device_id: {"30002": ("h2", False, 9, "h2", time.strftime("%Y-%m-%d %H:%M:%S"))})
    loss.mark_readd(w._device_id, ["30002"])
    to_push, _ = w._standalone_pins_needing_push([{"pin": "30002"}], {"30002": "h2"})
    assert to_push == [], "its own retry clock decides, untouched (R6-03)"


def test_a_user_count_drop_beyond_monclubs_removals_asks_for_a_loss_check(db):
    assert loss.user_count_dropped(8, 900) is False              # first sighting: baseline only
    assert loss.user_count_dropped(8, 905) is False              # growth
    assert loss.user_count_dropped(8, 903) is True               # 2 gone, MonClub removed none
    db.clear_device_revocation_state(device_id=8, pin="100")     # MonClub removes one...
    assert loss.user_count_dropped(8, 902) is False              # ...which explains this drop


def test_a_loss_check_lists_the_terminal_even_with_no_departed_intent(db, monkeypatch, fstate):
    class Lister:
        owns_event_source = True

        def list_device_users(self, timeout_sec=60.0):
            return {"ok": True, "users": [{"pin": p, "name": "", "card": ""} for p in ("30001",)]}

    w, _c = _worker(monkeypatch, driver=Lister(), users=[])
    monkeypatch.setattr("app.core.db.list_confirmed_device_sync_pins", lambda device_id: {"30001", "30002"})
    assert w._promote_intents_by_readback(desired_pins={"30001", "30002"}) is None, "no intents: no listing"
    w._promote_intents_by_readback(desired_pins={"30001", "30002"}, loss_check=True)
    assert loss.readd_pins(w._device_id) == {"30002"}

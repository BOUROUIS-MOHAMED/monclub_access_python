"""Per-member repeat block for PC-decided entries (ULTRA merge plan 2, Task 4; spec sections 3, 5)."""
from __future__ import annotations

from app.core.repeat_guard import RepeatGuard, member_key


def test_the_key_is_the_person_main_account_first():
    assert member_key({"mainAccountId": 700, "userId": 105, "activeMembershipId": 5}) == "acc:700"
    assert member_key(None, 700) == "acc:700"
    assert member_key({"userId": 105, "activeMembershipId": 5}) == "user:105"
    assert member_key({"activeMembershipId": 5}) == "am:5"
    assert member_key({"mainAccountId": "0", "userId": None}) is None
    assert member_key(None) is None


def test_a_qr_account_and_a_card_row_of_the_same_person_share_the_key():
    assert member_key(None, "700") == member_key({"mainAccountId": 700, "userId": 1})


def test_blocked_inside_the_window_free_after_it():
    g = RepeatGuard()
    g.arm("acc:7", 30, now=100.0)
    assert g.remaining("acc:7", now=100.0) == 30.0
    assert g.remaining("acc:7", now=129.5) == 0.5
    assert g.remaining("acc:7", now=130.0) == 0.0
    assert g.remaining("acc:8", now=101.0) == 0.0


def test_zero_seconds_or_no_key_arms_nothing():
    g = RepeatGuard()
    g.arm("acc:7", 0, now=100.0)
    g.arm(None, 30, now=100.0)
    assert g.remaining("acc:7", now=100.0) == 0.0
    assert g.remaining(None, now=100.0) == 0.0


def test_a_new_entry_restarts_the_window():
    g = RepeatGuard()
    g.arm("acc:7", 30, now=100.0)
    g.arm("acc:7", 30, now=120.0)
    assert g.remaining("acc:7", now=140.0) == 10.0


def test_expired_entries_are_pruned_when_the_table_is_large():
    g = RepeatGuard()
    for i in range(RepeatGuard.PRUNE_AT):
        g.arm(f"acc:{i}", 1, now=0.0)
    g.arm("acc:new", 30, now=100.0)
    assert g.size() == 1
    assert g.remaining("acc:new", now=100.0) == 30.0

"""The device pin becomes the PERSON (main_account.id), not the membership.

Why it changes: active_membership.id churns. Delete and recreate a membership and the pin
changes, which on a preserve-policy device orphans the old row with its fingerprints and card
still resident. main_account.id never changes. It also matches the data model now that a
fingerprint template belongs to the account rather than to a membership.

The dangerous half is the collapse. One person holding two memberships at one gym used to be
two device rows; under an account pin it is ONE, and a device row carries one validity window
and one fingerprint list. Getting that wrong locks a paid-up member out, or deletes a finger.
"""

from types import SimpleNamespace

from app.core.device_sync import DeviceSyncEngine


def _engine() -> DeviceSyncEngine:
    return DeviceSyncEngine(cfg=SimpleNamespace(), logger=None)


def _device(**kw):
    # The push-side tests below exercise the ACCOUNT scheme. MEMBERSHIP (the default) is
    # pinned byte-for-byte against the pre-account derivation in test_pin_scheme_gate.py.
    d = {"doorIds": [1], "pinScheme": "ACCOUNT"}
    d.update(kw)
    return d


def _user(**kw):
    u = {
        "userId": 900,
        "membershipId": 7,
        "fullName": "Ali",
        "validFrom": "2026-01-01T00:00:00",
        "validTo": "2026-12-31T00:00:00",
        "fingerprints": [],
    }
    u.update(kw)
    return u


# ── derivation order ────────────────────────────────────────────────────────────────────

def test_pin_prefers_main_account_id():
    out = _engine()._filter_users_for_device(
        users=[_user(mainAccountId=5, activeMembershipId=31000, userId=900)],
        device=_device(), default_door_id=1,
    )
    assert list(out) == ["5"], "the person is the pin, not the membership"


def test_a_membership_device_uses_the_membership_id_whatever_the_backend_sends():
    """Deployed backends do not send mainAccountId, and a device the operator has not
    switched stays MEMBERSHIP even when the backend does."""
    for extra in ({}, {"mainAccountId": 5}):
        out = _engine()._filter_users_for_device(
            users=[_user(activeMembershipId=31000, userId=900, **extra)],
            device=_device(pinScheme="MEMBERSHIP"), default_door_id=1,
        )
        assert list(out) == ["31000"]


def test_an_account_device_never_falls_back_to_the_membership_id():
    """A fallback would put a membership pin on an account terminal: never mix schemes."""
    out = _engine()._filter_users_for_device(
        users=[_user(activeMembershipId=31000, userId=900)],
        device=_device(), default_door_id=1,
    )
    assert out == {}


def test_falls_back_to_user_id_when_there_is_no_membership():
    out = _engine()._filter_users_for_device(
        users=[_user(userId=900)], device=_device(pinScheme="MEMBERSHIP"), default_door_id=1,
    )
    assert list(out) == ["900"]


# ── the collapse ────────────────────────────────────────────────────────────────────────

def test_two_memberships_collapse_to_one_row_keeping_the_furthest_reach():
    """Ali: a 3-month gym plan and a 1-month spa plan, on a turnstile accepting both."""
    spa = _user(mainAccountId=5, activeMembershipId=1, membershipId=7,
                validTo="2026-10-01T00:00:00", fullName="Ali SPA")
    gym = _user(mainAccountId=5, activeMembershipId=2, membershipId=8,
                validTo="2026-12-31T00:00:00", fullName="Ali GYM")

    out = _engine()._filter_users_for_device(
        users=[spa, gym], device=_device(), default_door_id=1)

    assert list(out) == ["5"], "one person, one device row"
    assert out["5"]["validTo"] == "2026-12-31T00:00:00", (
        "the membership that reaches furthest wins the single validity window; keeping the "
        "shorter one would lock a paid-up member out the day their other plan lapses"
    )


def test_the_collapse_is_order_independent():
    spa = _user(mainAccountId=5, activeMembershipId=1, validTo="2026-10-01T00:00:00")
    gym = _user(mainAccountId=5, activeMembershipId=2, validTo="2026-12-31T00:00:00")

    a = _engine()._filter_users_for_device(users=[spa, gym], device=_device(), default_door_id=1)
    b = _engine()._filter_users_for_device(users=[gym, spa], device=_device(), default_door_id=1)

    assert a["5"]["validTo"] == b["5"]["validTo"] == "2026-12-31T00:00:00", (
        "plain last-wins would make the device row depend on payload ordering"
    )


def test_fingerprints_are_unioned_not_taken_from_the_winner():
    """The bug this test exists for: Ali's finger was scanned on the SPA plan, the GYM plan
    wins the row on end date, and _collect_templates_for_pin treats user['fingerprints'] as
    the whole answer -- so taking only the winner's list deletes his finger from the device."""
    spa = _user(mainAccountId=5, activeMembershipId=1, validTo="2026-10-01T00:00:00",
                fingerprints=[{"id": 11, "fingerId": 6, "templateVersion": 10}])
    gym = _user(mainAccountId=5, activeMembershipId=2, validTo="2026-12-31T00:00:00",
                fingerprints=[])

    out = _engine()._filter_users_for_device(
        users=[spa, gym], device=_device(), default_door_id=1)

    ids = {fp["id"] for fp in out["5"]["fingerprints"]}
    assert ids == {11}, "the losing membership's fingerprint must survive the collapse"


def test_the_same_template_on_both_rows_is_not_duplicated():
    shared = {"id": 11, "fingerId": 6, "templateVersion": 10}
    a = _user(mainAccountId=5, activeMembershipId=1, validTo="2026-10-01T00:00:00",
              fingerprints=[dict(shared)])
    b = _user(mainAccountId=5, activeMembershipId=2, validTo="2026-12-31T00:00:00",
              fingerprints=[dict(shared)])

    out = _engine()._filter_users_for_device(users=[a, b], device=_device(), default_door_id=1)

    assert len(out["5"]["fingerprints"]) == 1, (
        "an account-level template legitimately arrives on both rows; pushing it twice "
        "would consume two of the device's finger slots for one finger"
    )


def test_an_empty_card_slot_is_filled_from_the_losing_row():
    a = _user(mainAccountId=5, activeMembershipId=1, validTo="2026-10-01T00:00:00",
              firstCardId="1111", secondCardId="")
    b = _user(mainAccountId=5, activeMembershipId=2, validTo="2026-12-31T00:00:00",
              firstCardId="", secondCardId="")

    out = _engine()._filter_users_for_device(users=[a, b], device=_device(), default_door_id=1)

    assert out["5"]["firstCardId"] == "1111", "a card the member actually carries is not discarded"


def test_a_membership_the_device_does_not_accept_never_reaches_the_collapse():
    """"Longest" means longest among the memberships THIS DEVICE ACCEPTS. A gym plan running
    to December must not hand its end date to the spa turnstile."""
    spa = _user(mainAccountId=5, activeMembershipId=1, membershipId=7,
                validTo="2026-10-01T00:00:00")
    gym = _user(mainAccountId=5, activeMembershipId=2, membershipId=8,
                validTo="2026-12-31T00:00:00")

    out = _engine()._filter_users_for_device(
        users=[spa, gym],
        device=_device(allowedMemberships=[7]),   # spa turnstile
        default_door_id=1,
    )

    assert out["5"]["validTo"] == "2026-10-01T00:00:00", (
        "the gym plan is filtered out before the collapse, so it cannot extend the spa door"
    )


def test_an_absent_end_date_counts_as_furthest():
    open_ended = _user(mainAccountId=5, activeMembershipId=1, validTo=None)
    dated = _user(mainAccountId=5, activeMembershipId=2, validTo="2026-12-31T00:00:00")

    out = _engine()._filter_users_for_device(
        users=[open_ended, dated], device=_device(), default_door_id=1)

    assert out["5"]["validTo"] is None, (
        "no end date means no end; treating an unknown as 'expired' would revoke people "
        "we simply cannot date"
    )


# ── inbound: a pin coming BACK from a device ────────────────────────────────────────────

from app.core.device_attendance import _user_indexes, _resolve_history_user
from types import SimpleNamespace as _NS


def _roster_row(**kw):
    r = {
        "activeMembershipId": 1,
        "mainAccountId": 5,
        "userId": 900,
        "fullName": "Ali",
        "validTo": "2026-12-31T00:00:00",
        "firstCardId": "",
        "secondCardId": "",
    }
    r.update(kw)
    return r


def _hist(pin):
    return _NS(id=1, device_id=1, card_no="", event_id="e1", event_time="", created_at="",
               raw_json='{"pin": "%s"}' % pin, door_id=1, allowed=1, reason="", event_type="")


def test_an_account_pin_resolves_to_the_right_person():
    rows = [_roster_row(activeMembershipId=31000, mainAccountId=5)]
    by_am, by_card, by_account = _user_indexes(rows)

    got = _resolve_history_user(_hist(5), {"pin": "5"}, by_am, by_card, by_account)
    assert got is not None and got["activeMembershipId"] == 31000


def test_an_ambiguous_pin_resolves_as_a_membership_the_pre_cutover_reality():
    """On the 2026-09-12 production data, 110 main_account ids numerically equal an existing
    active_membership.id, and for 99 of them the two are DIFFERENT people (0 are the same
    person). Such a pin cannot be disambiguated by inspection.

    An earlier revision consulted the account index unconditionally first. That INVERTED
    correctness during the rollout window: a device still holding old membership pins would
    have had those 110 resolved to the account owner -- a wrong-person bug that did not exist
    before the account index was added. The safe default is the membership reading, because
    that is what a device actually holds until it is wiped and re-pushed."""
    ali = _roster_row(activeMembershipId=31000, mainAccountId=5, fullName="Ali")
    sonia = _roster_row(activeMembershipId=5, mainAccountId=777, fullName="Sonia", userId=901)
    by_am, by_card, by_account = _user_indexes([ali, sonia])

    got = _resolve_history_user(_hist(5), {"pin": "5"}, by_am, by_card, by_account)

    assert got is not None
    assert got["fullName"] == "Sonia", (
        "pin 5 is Sonia's membership id and Ali's account id; until the device is cut over "
        "it holds membership pins, so the membership reading is the correct default"
    )


def test_an_unambiguous_account_pin_still_resolves_to_the_person():
    """The common case: no collision, so the account reading is unambiguous and wins."""
    ali = _roster_row(activeMembershipId=31000, mainAccountId=5, fullName="Ali")
    by_am, by_card, by_account = _user_indexes([ali])

    got = _resolve_history_user(_hist(5), {"pin": "5"}, by_am, by_card, by_account)
    assert got is not None and got["fullName"] == "Ali"


def test_a_legacy_membership_pin_still_resolves():
    """Devices not yet cut over still hold membership-derived pins, and older backends send
    no mainAccountId at all. Those must keep working."""
    rows = [_roster_row(activeMembershipId=31000, mainAccountId=None)]
    by_am, by_card, by_account = _user_indexes(rows)

    got = _resolve_history_user(_hist(31000), {"pin": "31000"}, by_am, by_card, by_account)
    assert got is not None and got["activeMembershipId"] == 31000


def test_the_account_index_picks_the_same_membership_the_push_did():
    """The device row represents the furthest-reaching membership. The inbound resolver must
    agree, or a door event is attributed to a different plan than the one that opened it."""
    spa = _roster_row(activeMembershipId=1, mainAccountId=5, validTo="2026-10-01T00:00:00")
    gym = _roster_row(activeMembershipId=2, mainAccountId=5, validTo="2026-12-31T00:00:00")
    _by_am, _by_card, by_account = _user_indexes([spa, gym])

    assert by_account[5]["activeMembershipId"] == 2

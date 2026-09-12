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
    d = {"doorIds": [1]}
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


def test_falls_back_to_active_membership_when_backend_is_older():
    """Deployed backends do not send mainAccountId. The client must not regress on them."""
    out = _engine()._filter_users_for_device(
        users=[_user(activeMembershipId=31000, userId=900)],
        device=_device(), default_door_id=1,
    )
    assert list(out) == ["31000"]


def test_falls_back_to_user_id_when_there_is_no_membership():
    out = _engine()._filter_users_for_device(
        users=[_user(userId=900)], device=_device(), default_door_id=1,
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

"""pinScheme decides, PER DEVICE, whether a device PIN is the membership or the person.

WHY A GATE AND NOT A FALLBACK CHAIN
-----------------------------------
c13d1c2 derived ``mainAccountId -> activeMembershipId -> userId`` unconditionally. On the
2026-09-12 production data 110 main_account.id values equal an existing
active_membership.id and 99 of those are a DIFFERENT person. The moment ``mainAccountId``
reaches the roster, every deployed client would push account pins onto terminals that still
hold membership pins: on a PRESERVE device pin X for person A overwrites device user X that
belongs to person B. So the scheme is a device setting (``GymDeviceDto.pinScheme``) that an
operator switches after wiping the terminal, and the client never mixes schemes on one device.

These tests pin:
  * MEMBERSHIP (the default for absent / unknown values) is BYTE-IDENTICAL to the derivation
    that shipped before account pins existed -- same keys, same order, same row objects --
    checked against a verbatim copy of that loop over randomised rosters;
  * ACCOUNT keys by mainAccountId only and WITHHOLDS a deliverable row without one;
  * push and inbound agree on the membership a collapsed pin represents, including ties;
  * pinScheme survives ingest -> sync_devices -> payload projection -> _normalize_device.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Dict, List, Set

import pytest

from app.core import device_sync as ds
from app.core.device_sync import (
    PIN_SCHEME_ACCOUNT,
    PIN_SCHEME_MEMBERSHIP,
    DeviceSyncEngine,
    _merge_same_pin_entries,
    _norm_int_list,
    _parse_dt_any,
    _pin_str,
    _to_int,
    derive_member_pin,
    device_pin_scheme,
    furthest_reach,
)


def _engine() -> DeviceSyncEngine:
    return DeviceSyncEngine(cfg=SimpleNamespace(), logger=None)


# ── the reference: the loop as it shipped before account pins ──────────────────────────

def _pre_account_pin_filter(*, users: List[Dict[str, Any]], device: Dict[str, Any],
                            default_door_id: int) -> Dict[str, Dict[str, Any]]:
    """VERBATIM body of DeviceSyncEngine._filter_users_for_device at c13d1c2^ (the parent of
    the commit that introduced account pins). Do not "tidy" it: it is the oracle."""
    allowed_raw = device.get("allowedMemberships") or []
    allowed_set: Set[int] = set()
    for x in allowed_raw:
        xi = _to_int(x, default=None)
        if xi is not None:
            allowed_set.add(int(xi))

    door_ids = _norm_int_list(device.get("doorIds") or [])
    if not door_ids:
        door_ids = [int(default_door_id)]
    device["doorIds"] = door_ids  # keep for downstream use

    policy = str(device.get("pushingToDevicePolicy") or "").strip().upper()
    filter_by_validity = (policy == "VALID_ONLY")

    now = datetime.now(tz=timezone.utc)
    out: Dict[str, Dict[str, Any]] = {}

    for u in users or []:
        if not isinstance(u, dict):
            continue

        am_pin = _pin_str(u.get("activeMembershipId"))
        pin = am_pin or _pin_str(u.get("userId"))
        if not pin:
            continue
        if not pin.isdigit():
            continue

        if pin in out and not am_pin:
            continue

        mid = _to_int(u.get("membershipId"), default=None)
        if allowed_set and (mid is None or int(mid) not in allowed_set):
            continue

        if filter_by_validity:
            vf = _parse_dt_any(u.get("validFrom") or "")
            vt = _parse_dt_any(u.get("validTo") or "")
            if vf and now < vf:
                continue
            if vt and now > vt:
                continue

        out[pin] = u

    return out


def _random_roster(rng: random.Random, n: int) -> List[Any]:
    now = datetime.now(tz=timezone.utc)

    def _date(days_lo: int, days_hi: int):
        if rng.random() < 0.2:
            return None
        return (now + timedelta(days=rng.randint(days_lo, days_hi))).strftime("%Y-%m-%dT%H:%M:%S")

    rows: List[Any] = []
    for _ in range(n):
        if rng.random() < 0.03:
            rows.append("not-a-dict")
            continue
        rows.append({
            "userId": rng.choice([None, "", "u7", rng.randint(1, 40), str(rng.randint(1, 40))]),
            "activeMembershipId": rng.choice(
                [None, "", " ", "x9", rng.randint(1, 40), str(rng.randint(1, 40))]),
            # Present on most rows: MEMBERSHIP must ignore it entirely.
            "mainAccountId": rng.choice([None, rng.randint(1, 40), rng.randint(1, 40)]),
            "membershipId": rng.choice([None, 1, 2, 3, "2"]),
            "validFrom": _date(-30, 5),
            "validTo": _date(-5, 30),
            "fullName": f"N{rng.randint(1, 999)}",
            "fingerprints": [],
        })
    return rows


@pytest.mark.parametrize("scheme_value", [
    "__absent__", None, "", "membership", " MEMBERSHIP ", "garbage", "ACCOUNTS",
])
@pytest.mark.parametrize("seed", list(range(12)))
def test_membership_scheme_is_byte_identical_to_the_pre_account_derivation(seed, scheme_value):
    rng = random.Random(seed)
    users = _random_roster(rng, 60)
    device: Dict[str, Any] = {
        "doorIds": rng.choice([[], [1], [1, 2]]),
        "allowedMemberships": rng.choice([[], [1], [2, 3], ["2"]]),
        # The backend's enum values (AccessSoftwareInDeviceDataModePushingPolicy), None, and an
        # unknown token. "VALID_ONLY" was drawn here until lane B (2026-09-26) removed the client
        # filter it drove: no backend version has that value, so the oracle's VALID_ONLY branch
        # can no longer be reached by a real device -- test_no_pushing_policy_filters_by_date.
        "pushingToDevicePolicy": rng.choice([
            None, "ALL", "DELETE_ALL_KNOWING_PINS_BUT_NO_LONGER_DESIRED_BEFORE_PUSHING",
            "PUSH_WITHOUT_DELETING", "DELETE_ALL_BEFORE_PUSHING",
        ]),
    }
    if scheme_value != "__absent__":
        device["pinScheme"] = scheme_value

    ref = _pre_account_pin_filter(users=users, device=dict(device), default_door_id=1)
    got = _engine()._filter_users_for_device(users=users, device=dict(device), default_door_id=1)

    assert device_pin_scheme(device) == PIN_SCHEME_MEMBERSHIP
    assert [(k, id(v)) for k, v in got.items()] == [(k, id(v)) for k, v in ref.items()], (
        "MEMBERSHIP must emit the same pins, in the same order, carrying the same row objects "
        "as the derivation that shipped before account pins -- mainAccountId included in the "
        "payload must change nothing"
    )


def test_membership_ignores_main_account_id_even_when_present():
    out = _engine()._filter_users_for_device(
        users=[{"userId": 900, "activeMembershipId": 31000, "mainAccountId": 5}],
        device={"doorIds": [1]}, default_door_id=1,
    )
    assert list(out) == ["31000"]


# ── ACCOUNT ─────────────────────────────────────────────────────────────────────────────

def test_account_scheme_keys_by_main_account_id():
    out = _engine()._filter_users_for_device(
        users=[{"userId": 900, "activeMembershipId": 31000, "mainAccountId": 5}],
        device={"doorIds": [1], "pinScheme": "ACCOUNT"}, default_door_id=1,
    )
    assert list(out) == ["5"]


def test_account_scheme_withholds_a_row_without_main_account_id_and_reports_it():
    """The upgrade trap: a cache row written before sync_users had the column has
    mainAccountId=None. Emitting it under 31000 would put a MEMBERSHIP pin on an ACCOUNT
    terminal -- and 31000 may be another person's account id."""
    stats: Dict[str, Any] = {}
    out = _engine()._filter_users_for_device(
        users=[
            {"userId": 900, "activeMembershipId": 31000, "mainAccountId": None},
            {"userId": 901, "activeMembershipId": 31001, "mainAccountId": 7},
        ],
        device={"doorIds": [1], "pinScheme": "ACCOUNT"}, default_door_id=1,
        stats_out=stats,
    )
    assert list(out) == ["7"]
    assert "31000" not in out and "900" not in out
    assert stats["pin_scheme"] == PIN_SCHEME_ACCOUNT
    assert stats["withheld_missing_account"] == 1
    assert stats["withheld_sample"] == [{"userId": 900, "activeMembershipId": 31000}]


def test_withheld_counts_only_rows_this_device_would_have_carried():
    stats: Dict[str, Any] = {}
    _engine()._filter_users_for_device(
        users=[{"userId": 900, "activeMembershipId": 31000, "membershipId": 8,
                "mainAccountId": None}],
        device={"doorIds": [1], "pinScheme": "ACCOUNT", "allowedMemberships": [7]},
        default_door_id=1, stats_out=stats,
    )
    assert stats["withheld_missing_account"] == 0, (
        "a row the device does not accept is not missing from its roster"
    )


def test_pin_sources_name_the_field_that_produced_each_pin():
    stats: Dict[str, Any] = {}
    _engine()._filter_users_for_device(
        users=[{"userId": 1, "activeMembershipId": 31000}, {"userId": 2, "activeMembershipId": None}],
        device={"doorIds": [1]}, default_door_id=1, stats_out=stats,
    )
    assert stats["pin_sources"] == {"31000": "MEMBERSHIP", "2": "USER"}

    stats = {}
    _engine()._filter_users_for_device(
        users=[{"userId": 1, "activeMembershipId": 31000, "mainAccountId": 5}],
        device={"doorIds": [1], "pinScheme": "ACCOUNT"}, default_door_id=1, stats_out=stats,
    )
    assert stats["pin_sources"] == {"5": "ACCOUNT"}


def test_derive_member_pin_is_the_single_derivation():
    row = {"userId": 900, "activeMembershipId": 31000, "mainAccountId": 5}
    assert derive_member_pin(row, "MEMBERSHIP") == ("31000", "MEMBERSHIP")
    assert derive_member_pin(row, "ACCOUNT") == ("5", "ACCOUNT")
    assert derive_member_pin({"userId": 900}, "MEMBERSHIP") == ("900", "USER")
    assert derive_member_pin({"userId": 900, "activeMembershipId": 31000}, "ACCOUNT") == ("", None)


# ── tie-break: push and inbound must pick the same membership ─────────────────────────

def _row(am: int, name: str, valid_to: str = "2026-12-31T00:00:00") -> Dict[str, Any]:
    return {"userId": 900, "mainAccountId": 5, "activeMembershipId": am, "membershipId": 1,
            "validTo": valid_to, "fullName": name, "fingerprints": []}


def test_equal_reach_is_broken_by_the_larger_membership_id_on_both_sides():
    """Before the shared rank the push kept the FIRST row on a tie and the inbound resolver
    kept the LARGER id: the device row said one name, its door events said another."""
    a, b = _row(10, "Plan A"), _row(20, "Plan B")

    assert _merge_same_pin_entries(a, b)["fullName"] == "Plan B"
    assert _merge_same_pin_entries(b, a)["fullName"] == "Plan B"
    assert furthest_reach([a, b])["activeMembershipId"] == 20
    assert furthest_reach([b, a])["activeMembershipId"] == 20

    for order in ([a, b], [b, a]):
        out = _engine()._filter_users_for_device(
            users=order, device={"doorIds": [1], "pinScheme": "ACCOUNT"}, default_door_id=1)
        assert out["5"]["activeMembershipId"] == 20


def test_reach_still_dominates_the_id():
    longer_small_id = _row(10, "Long", "2027-06-30T00:00:00")
    shorter_big_id = _row(20, "Short", "2026-10-01T00:00:00")
    assert _merge_same_pin_entries(shorter_big_id, longer_small_id)["fullName"] == "Long"
    assert furthest_reach([shorter_big_id, longer_small_id])["fullName"] == "Long"


def test_a_collapse_that_drops_a_card_reports_it(caplog):
    """Review #5. Every push writes ONE card per device user -- PullSDK `CardNo` from
    firstCardId (targeted and full-sync writes), the standalone entry's single "card" from
    firstCardId -- so a collapsed row can carry one card to the terminal. Under MEMBERSHIP each
    membership's firstCardId reached the device on its own user; under ACCOUNT only the reach
    winner's does. That loss was silent; it must be counted and logged."""
    gym = {**_row(10, "Ali", "2027-06-30T00:00:00"), "firstCardId": "111"}
    spa = {**_row(20, "Ali", "2026-10-01T00:00:00"), "firstCardId": "222"}
    same_card = {**_row(30, "Ali", "2026-11-01T00:00:00"), "firstCardId": "111"}

    for order in ([gym, spa, same_card], [same_card, spa, gym]):
        stats: Dict[str, Any] = {}
        with caplog.at_level("WARNING"):
            out = _engine()._filter_users_for_device(
                users=order, device={"doorIds": [1], "pinScheme": "ACCOUNT", "id": 9},
                default_door_id=1, stats_out=stats)
        assert out["5"]["firstCardId"] == "111", "the reach winner's card is the one pushed"
        assert stats["dropped_cards"] == 1, "card 222 of membership 20 reaches no device user"
    assert any("card" in r.getMessage() and "20" in r.getMessage() for r in caplog.records)


def test_the_template_pushed_for_a_finger_does_not_depend_on_row_order():
    """Review #7. Finger 1 enrolled under two memberships arrives as two templates with
    distinct ids; _collect_templates_for_pin keeps the LAST per finger, so the unioned list's
    order decided which bytes (and which hash) a collapsed row carried."""
    import itertools

    def fp(tid, data):
        return {"id": tid, "fingerId": 1, "templateVersion": 10, "templateData": data,
                "templateSize": 4, "enabled": True}

    rows = [{**_row(30, "Ali"), "fingerprints": []},
            {**_row(20, "Ali"), "fingerprints": [fp(201, "QkJC")]},
            {**_row(10, "Ali"), "fingerprints": [fp(101, "Q0ND")]}]
    engine = _engine()
    seen = set()
    for order in itertools.permutations(rows):
        out = engine._filter_users_for_device(
            users=list(order), device={"doorIds": [1], "pinScheme": "ACCOUNT"}, default_door_id=1)
        tpls = engine._collect_templates_for_pin(
            user=out["5"], pin="5", local_fp_index={}, fingerprint_enabled=True)
        seen.add(tuple(t.get("templateData") for t in tpls))
    assert len(seen) == 1, f"order-dependent templates: {seen}"


def test_a_membership_device_never_reports_dropped_cards():
    stats: Dict[str, Any] = {}
    _engine()._filter_users_for_device(
        users=[{**_row(10, "A"), "firstCardId": "111"}, {**_row(20, "B"), "firstCardId": "222"}],
        device={"doorIds": [1]}, default_door_id=1, stats_out=stats)
    assert stats["dropped_cards"] == 0


# ── the roster hash ─────────────────────────────────────────────────────────────────────

def test_a_membership_device_keeps_its_roster_hash_and_an_account_device_does_not():
    users = [{"userId": 900, "activeMembershipId": 5, "mainAccountId": 5, "fullName": "A",
              "fingerprints": []}]
    eng = _engine()
    base = {"id": 1, "name": "T", "doorIds": [1]}
    h_absent, _ = eng.build_device_sync_fingerprint(device=dict(base), users=users, local_fp_index={})
    h_member, _ = eng.build_device_sync_fingerprint(
        device={**base, "pinScheme": "MEMBERSHIP"}, users=users, local_fp_index={})
    h_account, _ = eng.build_device_sync_fingerprint(
        device={**base, "pinScheme": "ACCOUNT"}, users=users, local_fp_index={})
    assert h_absent == h_member, "upgrading the client must not move a MEMBERSHIP roster hash"
    assert h_account != h_member, (
        "same digits under both schemes here (5 == 5), so only the header can tell them apart"
    )


# ── plumbing: backend DTO -> sync_devices -> payload -> engine ─────────────────────────

@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "scheme.db"), raising=False)
    db_module.init_db()
    yield db_module
    if hasattr(db_module, "_shutdown_db_writer_for_tests"):
        db_module._shutdown_db_writer_for_tests()


def _ingest(db, device):
    with db.get_conn() as conn:
        cur = conn.cursor()
        db._insert_device_row(cur, device)
        conn.commit()


def test_pin_scheme_survives_ingest_to_the_engine(db):
    _ingest(db, {"id": 42, "name": "Entree", "accessDataMode": "ULTRA",
                 "rosterPushingPolicy": "PRESERVE", "pinScheme": "account"})
    payload = db.list_sync_devices_payload()[0]
    assert payload["pinScheme"] == "ACCOUNT"
    assert db.get_sync_device_payload(42)["pinScheme"] == "ACCOUNT"
    assert device_pin_scheme(payload) == PIN_SCHEME_ACCOUNT
    assert _engine()._normalize_device(payload)["pinScheme"] == "ACCOUNT", (
        "_normalize_device is an allowlist; a dropped key silently derives MEMBERSHIP pins"
    )


def test_absent_pin_scheme_is_membership_end_to_end(db):
    _ingest(db, {"id": 43, "name": "Sortie", "accessDataMode": "ULTRA"})
    payload = db.list_sync_devices_payload()[0]
    assert payload["pinScheme"] is None
    assert device_pin_scheme(payload) == PIN_SCHEME_MEMBERSHIP
    assert device_pin_scheme(_engine()._normalize_device(payload)) == PIN_SCHEME_MEMBERSHIP


def test_pin_scheme_survives_the_delta_device_refresh(db):
    db.save_sync_cache_delta(
        {"devices": [{"id": 44, "name": "Lane", "accessDataMode": "ULTRA", "pinScheme": "ACCOUNT"}]},
        {"members": False, "devices": True, "credentials": False, "settings": False},
    )
    assert db.get_sync_device_payload(44)["pinScheme"] == "ACCOUNT"


@pytest.mark.parametrize("policy", [
    None, "DELETE_ALL_BEFORE_PUSHING", "DELETE_ALL_KNOWING_PINS_BUT_NO_LONGER_DESIRED_BEFORE_PUSHING",
    "PUSH_WITHOUT_DELETING", "DELETE_ALL_NOT_KNOWING_PINS_AND_DONT_PUSH",
    "DELETE_ALL_NOT_DESIRED_PINS_BEFORE_PUSHING",
    "VALID_ONLY",          # not a backend value; the filter it drove was removed (lane B)
])
@pytest.mark.parametrize("scheme", ["MEMBERSHIP", "ACCOUNT"])
def test_no_pushing_policy_filters_by_date(policy, scheme):
    """The roster is the server's list of the day (P3b-1 flips hold rows by date); no push policy
    drops a member by validFrom/validTo."""
    now = datetime.now(tz=timezone.utc)
    past = (now - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S")
    future = (now + timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S")
    users = [
        {"activeMembershipId": 11, "userId": 1, "mainAccountId": 101, "membershipId": 1,
         "validFrom": "2026-01-01T00:00:00", "validTo": past, "fullName": "Ended", "fingerprints": []},
        {"activeMembershipId": 12, "userId": 2, "mainAccountId": 102, "membershipId": 1,
         "validFrom": future, "validTo": None, "fullName": "Starts", "fingerprints": []},
    ]
    device = {"doorIds": [1], "allowedMemberships": [], "pushingToDevicePolicy": policy,
              "pinScheme": scheme}
    got = _engine()._filter_users_for_device(users=users, device=device, default_door_id=1)
    assert sorted(got) == (["11", "12"] if scheme == "MEMBERSHIP" else ["101", "102"])

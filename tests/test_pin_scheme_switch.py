"""A device's pinScheme change is recorded once, clears its hashes safely, and is never lost.

WHY
---
A terminal that switches from MEMBERSHIP to ACCOUNT pins still holds membership-pin users
until an operator wipes it. The client must therefore (1) make the next sync re-evaluate every
pin for that device -- through the existing safe path, UPDATE not DELETE, because
``ownership_confirmed`` rows are the only proof Access owns a pin on a shared terminal
(guide §3.2c) -- and (2) remember WHEN it switched, so a door event is read under the scheme
its pin was minted with. The switch time cannot live in ``sync_devices``: every device-section
refresh deletes and re-inserts that table.
"""
from __future__ import annotations

from datetime import datetime

import pytest

from app.core.pin_scheme import scheme_at


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "switch.db"), raising=False)
    db_module.init_db()
    yield db_module
    if hasattr(db_module, "_shutdown_db_writer_for_tests"):
        db_module._shutdown_db_writer_for_tests()


def _ingest(db, device):
    """Upsert one device the way the fast-patch GYM_DEVICE path does: delete, then insert."""
    with db.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM sync_device_door_presets WHERE device_id = ?", (device["id"],))
        cur.execute("DELETE FROM sync_devices WHERE id = ?", (device["id"],))
        db._insert_device_row(cur, device)
        conn.commit()


def _device(device_id=42, **kw):
    d = {"id": device_id, "name": f"Lane {device_id}", "accessDataMode": "ULTRA",
         "deviceProtocol": "ZK_STANDALONE", "rosterPushingPolicy": "PRESERVE"}
    d.update(kw)
    return d


def _seed_state(db, device_id, pins):
    with db.get_conn() as conn:
        for pin in pins:
            conn.execute(
                "INSERT INTO device_sync_state (device_id, pin, desired_hash, last_ok, last_error, "
                "updated_at, pushed_finger_ids, ownership_confirmed) "
                "VALUES (?, ?, 'h-old', 1, NULL, '2026-09-01 10:00:00', '1,6', 1)",
                (device_id, str(pin)),
            )
        conn.commit()


def _state(db, device_id):
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT pin, desired_hash, last_ok, ownership_confirmed, pushed_finger_ids "
            "FROM device_sync_state WHERE device_id=? ORDER BY pin",
            (device_id,),
        ).fetchall()
    return {r[0]: (r[1], r[2], r[3], r[4]) for r in rows}


def test_a_device_without_pin_scheme_records_nothing(db):
    _ingest(db, _device())
    _ingest(db, _device(pinScheme="MEMBERSHIP"))
    assert db.list_device_pin_scheme_switches() == {}


def test_switching_to_account_records_once_and_clears_hashes_without_deleting(db):
    _ingest(db, _device(42, pinScheme="MEMBERSHIP"))  # seen on MEMBERSHIP: the next change is a switch
    _seed_state(db, 42, [31000, 31001, 5])
    _seed_state(db, 43, [777])

    _ingest(db, _device(42, pinScheme="ACCOUNT"))

    [switch] = db.list_device_pin_scheme_switches(device_id=42)[42]
    assert (switch["previous_scheme"], switch["scheme"]) == ("MEMBERSHIP", "ACCOUNT")

    state = _state(db, 42)
    assert set(state) == {"31000", "31001", "5"}, "UPDATE, never DELETE"
    for desired_hash, last_ok, ownership, fingers in state.values():
        assert desired_hash is None and last_ok == 0
        assert ownership == 1, "ownership evidence must survive (guide §3.2c)"
        assert fingers == "1,6", "the finger slots still to clear must survive"

    assert _state(db, 43) == {"777": ("h-old", 1, 1, "1,6")}, "another device is untouched"
    with db.get_conn() as conn:
        cleared = conn.execute("SELECT cleared_rows FROM device_pin_scheme_switch").fetchone()[0]
    assert cleared == 3


def test_repeating_the_same_scheme_is_not_a_switch(db):
    _ingest(db, _device(42, pinScheme="ACCOUNT"))
    _seed_state(db, 42, [5])

    _ingest(db, _device(42, pinScheme="account "))

    assert len(db.list_device_pin_scheme_switches(device_id=42)[42]) == 1
    assert _state(db, 42)["5"][0] == "h-old", "no second clear on an unchanged scheme"


def test_every_device_write_path_sees_the_switch_exactly_once(db):
    refresh_devices = {"members": False, "devices": True, "credentials": False, "settings": False}

    db.save_sync_cache({"users": [], "devices": [_device(42, pinScheme="ACCOUNT")],
                        "contractStatus": True})
    db.save_sync_cache_delta({"devices": [_device(42, pinScheme="ACCOUNT")]}, refresh_devices)
    db.apply_fast_patch_bundle({
        "bundleId": "b-dev",
        "items": [{"kind": "ENTITY_UPSERT", "entityType": "GYM_DEVICE", "entityId": 42,
                   "revision": "2026-09-12T10:00:00",
                   "payload": {"device": _device(42, pinScheme="ACCOUNT")}}],
    })

    assert len(db.list_device_pin_scheme_switches(device_id=42)[42]) == 1
    assert db.get_sync_device_payload(42)["pinScheme"] == "ACCOUNT"


def test_the_switch_time_survives_a_device_section_refresh(db):
    """Every device refresh DELETEs sync_devices. The switch record must not go with it."""
    _ingest(db, _device(42, pinScheme="ACCOUNT"))
    db.save_sync_cache_delta(
        {"devices": [_device(42, pinScheme="ACCOUNT")]},
        {"members": False, "devices": True, "credentials": False, "settings": False},
    )
    db.save_sync_cache_delta(
        {"devices": []},
        {"members": False, "devices": True, "credentials": False, "settings": False},
    )
    assert len(db.list_device_pin_scheme_switches(device_id=42)[42]) == 1


def test_switching_back_is_a_second_switch_and_each_window_resolves(db, monkeypatch):
    times = iter(["2026-09-01 08:00:00", "2026-09-12 10:00:00", "2026-09-20 18:30:00"])
    monkeypatch.setattr(db, "now_iso", lambda: next(times))

    _ingest(db, _device(42, pinScheme="MEMBERSHIP"))
    _ingest(db, _device(42, pinScheme="ACCOUNT"))
    _ingest(db, _device(42, pinScheme="MEMBERSHIP"))

    history = db.list_device_pin_scheme_switches(device_id=42)[42]
    assert [(h["previous_scheme"], h["scheme"]) for h in history] == [
        ("MEMBERSHIP", "ACCOUNT"), ("ACCOUNT", "MEMBERSHIP")]

    switches = [(h["scheme"], datetime.strptime(h["switched_at"], "%Y-%m-%d %H:%M:%S"))
                for h in history]
    assert scheme_at(switches, datetime(2026, 9, 12, 9, 59, 59)) == "MEMBERSHIP"
    assert scheme_at(switches, datetime(2026, 9, 12, 10, 0, 0)) == "ACCOUNT"
    assert scheme_at(switches, datetime(2026, 9, 15, 8, 0, 0)) == "ACCOUNT"
    assert scheme_at(switches, datetime(2026, 9, 21, 8, 0, 0)) == "MEMBERSHIP"


_DEVICES_ONLY = {"members": False, "devices": True, "credentials": False, "settings": False}


@pytest.mark.parametrize("later", [
    {},                               # an older backend: no key at all
    {"pinScheme": None},              # a partial payload: key present, value null
    {"pinScheme": ""},
    {"pinScheme": "FACE"},            # a token this client does not know
], ids=["absent", "null", "empty", "unrecognised"])
def test_a_payload_without_a_recognised_pin_scheme_keeps_the_last_known_scheme(db, later):
    """Review #6. Folding an absent/unknown pinScheme to MEMBERSHIP recorded an ACCOUNT ->
    MEMBERSHIP switch, cleared every hash, and made the next roster derive membership pins
    for a terminal that holds account pins -- with no wipe. Only an explicit, recognised
    value may switch; the backend's own rule for this field is "absent keeps the current"."""
    from app.core.device_sync import device_pin_scheme

    db.save_sync_cache_delta({"devices": [_device(42, pinScheme="ACCOUNT")]}, _DEVICES_ONLY)
    _seed_state(db, 42, [5])

    db.save_sync_cache_delta({"devices": [_device(42, **later)]}, _DEVICES_ONLY)

    assert len(db.list_device_pin_scheme_switches(device_id=42)[42]) == 1, "not a switch"
    assert _state(db, 42)["5"][:2] == ("h-old", 1), "no hash clear without a switch"
    payload = db.get_sync_device_payload(42)
    assert device_pin_scheme(payload) == "ACCOUNT", (
        "the device must keep deriving ACCOUNT pins; NULL here reads as MEMBERSHIP"
    )


def test_an_explicit_membership_after_account_is_still_a_switch(db):
    db.save_sync_cache_delta({"devices": [_device(42, pinScheme="ACCOUNT")]}, _DEVICES_ONLY)
    _seed_state(db, 42, [5])

    db.save_sync_cache_delta({"devices": [_device(42, pinScheme="MEMBERSHIP")]}, _DEVICES_ONLY)

    history = db.list_device_pin_scheme_switches(device_id=42)[42]
    assert [h["scheme"] for h in history][-1] == "MEMBERSHIP"
    assert _state(db, 42)["5"][:2] == (None, 0), "the explicit switch clears hashes (UPDATE)"
    assert db.get_sync_device_payload(42)["pinScheme"] == "MEMBERSHIP"


def _history_resolver(db):
    from app.core.device_attendance import HistoryPinResolver

    ali = {"activeMembershipId": 31000, "userId": 900, "mainAccountId": 5, "membershipId": 7,
           "fullName": "Ali", "validTo": "2026-12-31T00:00:00", "fingerprints": []}
    sonia = {"activeMembershipId": 5, "userId": 901, "mainAccountId": 777, "membershipId": 7,
             "fullName": "Sonia", "validTo": "2026-12-31T00:00:00", "fingerprints": []}
    return HistoryPinResolver(
        users=[ali, sonia],
        devices_by_id={42: db.get_sync_device_payload(42)},
        switches_by_device=db.list_device_pin_scheme_switches(),
    )


def _event(event_time, pin):
    import dataclasses
    import json

    from tests.test_access_history_sync import _make_row

    return dataclasses.replace(_make_row(), device_id=42, event_time=event_time,
                               card_no="", raw_json=json.dumps({"pin": str(pin)}))


def test_a_first_sighting_on_account_is_not_a_switch_and_earlier_events_are_unknown(db, monkeypatch):
    """Review #1 / #14. A DB that first sees a device already on ACCOUNT (a new or reinstalled
    PC, a lost SQLite file) recorded MEMBERSHIP -> ACCOUNT at PC-now, so every backlog event
    stamped before this PC's first sync read as MEMBERSHIP 'known' and pin 5 (Ali's account)
    was filed on Sonia (membership 5). When the device ran before it was first seen is not
    known: those events take the unknown-scheme rule."""
    monkeypatch.setattr(db, "now_iso", lambda: "2026-09-13 09:00:00")
    _ingest(db, _device(42, pinScheme="ACCOUNT"))

    [first] = db.list_device_pin_scheme_switches(device_id=42)[42]
    assert (first["previous_scheme"], first["scheme"]) == ("UNKNOWN", "ACCOUNT")

    resolver = _history_resolver(db)
    assert resolver.scheme_for(_event("2026-09-12 18:00:00", 5)) is None, "before the sighting"
    assert resolver.scheme_for(_event("2026-09-13 09:30:00", 5)) == "ACCOUNT"

    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from app.core.device_attendance import DeviceAttendanceMaintenanceEngine

    engine = DeviceAttendanceMaintenanceEngine(cfg=SimpleNamespace(), logger=MagicMock())
    item = engine._serialize_row_for_backend(
        row=_event("2026-09-12 18:00:00", 424242), users_by_am=resolver.users_by_am,
        users_by_card=resolver.users_by_card, devices_by_id={},
        users_by_account=resolver.users_by_account, resolver=resolver,
    )
    assert item["activeMembership"] is None, "an account pin must not go out as a membership"


def test_a_device_seen_on_membership_then_account_is_a_real_switch(db, monkeypatch):
    times = iter(["2026-09-01 08:00:00", "2026-09-12 10:00:00"])
    monkeypatch.setattr(db, "now_iso", lambda: next(times))
    _ingest(db, _device(42, pinScheme="MEMBERSHIP"))
    assert db.list_device_pin_scheme_switches() == {}, "a MEMBERSHIP sighting records no switch"

    _ingest(db, _device(42, pinScheme="ACCOUNT"))

    [switch] = db.list_device_pin_scheme_switches(device_id=42)[42]
    assert (switch["previous_scheme"], switch["scheme"]) == ("MEMBERSHIP", "ACCOUNT")
    resolver = _history_resolver(db)
    assert resolver.scheme_for(_event("2026-09-12 09:00:00", 5)) == "MEMBERSHIP"
    assert resolver.scheme_for(_event("2026-09-12 11:00:00", 5)) == "ACCOUNT"


def test_scheme_at_reads_the_scheme_before_the_first_row_from_that_row():
    t1, t2 = datetime(2026, 9, 13, 9, 0, 0), datetime(2026, 9, 20, 18, 30, 0)
    first_sighting = [("ACCOUNT", t1, "UNKNOWN"), ("MEMBERSHIP", t2, "ACCOUNT")]
    assert scheme_at(first_sighting, datetime(2026, 9, 12)) is None
    assert scheme_at(first_sighting, datetime(2026, 9, 15)) == "ACCOUNT"
    assert scheme_at(first_sighting, datetime(2026, 9, 21)) == "MEMBERSHIP"
    real_switch = [("ACCOUNT", t1, "MEMBERSHIP")]
    assert scheme_at(real_switch, datetime(2026, 9, 12)) == "MEMBERSHIP"
    # An unparseable row makes events unknowable only until the next parseable row in force.
    broken = [("ACCOUNT", None, "MEMBERSHIP"), ("MEMBERSHIP", t2, "ACCOUNT")]
    assert scheme_at(broken, datetime(2026, 9, 15)) is None
    assert scheme_at(broken, datetime(2026, 9, 21)) == "MEMBERSHIP"


def test_scheme_at_rules():
    at = datetime(2026, 9, 12, 10, 0, 0)
    assert scheme_at([], None) == "MEMBERSHIP", "never switched: known, not a guess"
    assert scheme_at([], at) == "MEMBERSHIP"
    assert scheme_at([("ACCOUNT", at)], None) is None, "switched + unparseable time: unknown"
    assert scheme_at([("ACCOUNT", None)], at) is None

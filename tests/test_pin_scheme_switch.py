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
    times = iter(["2026-09-12 10:00:00", "2026-09-20 18:30:00"])
    monkeypatch.setattr(db, "now_iso", lambda: next(times))

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


def test_scheme_at_rules():
    at = datetime(2026, 9, 12, 10, 0, 0)
    assert scheme_at([], None) == "MEMBERSHIP", "never switched: known, not a guess"
    assert scheme_at([], at) == "MEMBERSHIP"
    assert scheme_at([("ACCOUNT", at)], None) is None, "switched + unparseable time: unknown"
    assert scheme_at([("ACCOUNT", None)], at) is None

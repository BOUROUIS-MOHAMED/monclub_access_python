"""The device store moved out of db.py (ULTRA merge plan 2, Task 1): the same row in, the same
payload out, and db.py still exposes every moved name."""
from __future__ import annotations

import importlib

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    importlib.reload(db_module)
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "store.db"), raising=False)
    db_module.init_db()
    return db_module


def _ingest(db, device):
    with db.get_conn() as conn:
        cur = conn.cursor()
        db._insert_device_row(cur, device)
        conn.commit()


def _device(**extra):
    d = {
        "id": 42, "name": "Entree 1", "description": "main door", "allowedMemberships": [3, 4],
        "active": True, "accessDevice": False, "ipAddress": "192.168.1.50", "macAddress": "aa",
        "password": "x", "portNumber": "4370", "accessDataMode": "ultra", "model": "C3_200",
        "installedModels": [], "doorIds": [1, 2], "zone": "Z", "popupDurationSec": 7,
        "totpPrefix": "9", "totpDigits": 7, "rfidMinDigits": 4, "rfidMaxDigits": 10,
        "pulseTimeMs": 2500, "saveHistory": False, "fingerprintEnabled": True,
        "emptyBackoffFactor": 1.5, "emptyBackoffMaxMs": 900, "antiFraudeCard": False,
        "antiFraudeQrCode": True, "antiFraudeDuration": 45, "frequentPassLimit": 3,
        "frequentPassWindowMinutes": 10, "deviceProtocol": "zk_pullsdk", "pinScheme": "MEMBERSHIP",
        "deviceCapabilities": {"fingerprintTemplateVersion": 9},
        "doorPresets": [{"id": 900, "deviceId": 42, "doorNumber": 1, "pulseSeconds": 3,
                         "doorName": "Lane 1"}],
    }
    d.update(extra)
    return d


def test_db_reexports_the_moved_functions():
    from app.core import db, db_values, sync_device_store

    assert db._insert_device_row is sync_device_store._insert_device_row
    assert db._coerce_device_row_to_payload is sync_device_store._coerce_device_row_to_payload
    assert db._device_capabilities_to_text is sync_device_store._device_capabilities_to_text
    assert db._device_capabilities_from_stored is sync_device_store._device_capabilities_from_stored
    for name in ("_bool_to_i", "_to_int_or_none", "_to_float_or_none", "_safe_str"):
        assert getattr(db, name) is getattr(db_values, name)


def test_a_device_survives_ingest_and_projection(db):
    _ingest(db, _device())

    [p] = db.list_sync_devices_payload()

    assert (p["id"], p["name"], p["accessDataMode"]) == (42, "Entree 1", "ULTRA")
    assert (p["accessDevice"], p["saveHistory"], p["fingerprintEnabled"]) == (False, False, True)
    assert p["allowedMemberships"] == [3, 4] and p["doorIds"] == [1, 2]
    assert (p["popupDurationSec"], p["rfidMinDigits"], p["rfidMaxDigits"]) == (7, 4, 10)
    assert (p["pulseTimeMs"], p["emptyBackoffFactor"], p["emptyBackoffMaxMs"]) == (2500, 1.5, 900)
    assert (p["antiFraudeCard"], p["antiFraudeQrCode"], p["antiFraudeDuration"]) == (False, True, 45)
    assert (p["frequentPassLimit"], p["frequentPassWindowMinutes"]) == (3, 10)
    assert (p["deviceProtocol"], p["pinScheme"]) == ("ZK_PULLSDK", "MEMBERSHIP")
    assert p["deviceCapabilities"] == {"fingerprintTemplateVersion": 9}
    assert [x["doorNumber"] for x in p["doorPresets"]] == [1]


# ---------------------------------------------------------------- Task 2: the ULTRA-merge keys
def test_the_four_ultra_merge_keys_survive_ingest_and_projection(db):
    _ingest(db, _device(cardDecision="pc", memberBlockSeconds=45,
                        fingerprintEraseRequestId="0f0e0d0c-0b0a-4908-8706-050403020100",
                        cardRemovalRequestId="1a2b3c4d-0000-4000-8000-000000000001"))

    [p] = db.list_sync_devices_payload()

    assert p["cardDecision"] == "PC"
    assert p["memberBlockSeconds"] == 45
    assert p["fingerprintEraseRequestId"] == "0f0e0d0c-0b0a-4908-8706-050403020100"
    assert p["cardRemovalRequestId"] == "1a2b3c4d-0000-4000-8000-000000000001"
    single = db.get_sync_device_payload(42)
    assert (single["cardDecision"], single["cardRemovalRequestId"]) == ("PC", "1a2b3c4d-0000-4000-8000-000000000001")


def test_absent_keys_read_back_as_none(db):
    _ingest(db, _device())

    [p] = db.list_sync_devices_payload()

    assert (p["cardDecision"], p["memberBlockSeconds"], p["fingerprintEraseRequestId"],
            p["cardRemovalRequestId"]) == (None, None, None, None)


def test_a_zero_member_block_is_kept_as_zero_not_none(db):
    _ingest(db, _device(memberBlockSeconds=0, cardDecision="TURNSTILE"))

    [p] = db.list_sync_devices_payload()

    assert (p["memberBlockSeconds"], p["cardDecision"]) == (0, "TURNSTILE")


def test_init_db_creates_the_columns(db):
    with db.get_conn() as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(sync_devices)").fetchall()}
    assert {"card_decision", "member_block_seconds", "fingerprint_erase_request_id",
            "card_removal_request_id"} <= cols


def _old_table(conn):
    conn.execute("CREATE TABLE sync_devices (id INTEGER, name TEXT)")
    conn.execute("CREATE TABLE sync_version_tokens (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute("INSERT INTO sync_version_tokens VALUES ('devicesVersion', 'd1'), ('membersVersion', 'm1')")


def _tokens(conn):
    return dict(conn.execute("SELECT key, value FROM sync_version_tokens").fetchall())


def test_an_existing_table_gains_the_columns_and_drops_devices_version_once():
    import sqlite3

    from app.core.sync_device_store import ensure_ultra_merge_device_columns

    conn = sqlite3.connect(":memory:")
    _old_table(conn)

    assert ensure_ultra_merge_device_columns(conn, table_existed=True) is True
    cols = {r[1] for r in conn.execute("PRAGMA table_info(sync_devices)").fetchall()}
    assert {"card_decision", "member_block_seconds", "fingerprint_erase_request_id",
            "card_removal_request_id"} <= cols
    assert _tokens(conn) == {"membersVersion": "m1"}

    conn.execute("INSERT INTO sync_version_tokens VALUES ('devicesVersion', 'd2')")
    assert ensure_ultra_merge_device_columns(conn, table_existed=True) is False
    assert _tokens(conn) == {"membersVersion": "m1", "devicesVersion": "d2"}


def test_a_fresh_table_keeps_its_tokens():
    import sqlite3

    from app.core.sync_device_store import ensure_ultra_merge_device_columns

    conn = sqlite3.connect(":memory:")
    _old_table(conn)

    assert ensure_ultra_merge_device_columns(conn, table_existed=False) is False
    assert _tokens(conn) == {"devicesVersion": "d1", "membersVersion": "m1"}

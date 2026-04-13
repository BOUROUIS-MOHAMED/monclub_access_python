from __future__ import annotations

import threading
from contextlib import contextmanager

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()
    yield db_module
    if hasattr(db_module, "_shutdown_db_writer_for_tests"):
        db_module._shutdown_db_writer_for_tests()


def _make_user(am_id=1, user_id=100, full_name="Alice Smith", card="12345"):
    return {
        "activeMembershipId": am_id,
        "userId": user_id,
        "membershipId": 50,
        "fullName": full_name,
        "phone": "0600000000",
        "email": "alice@example.com",
        "validFrom": "2026-01-01",
        "validTo": "2026-12-31",
        "firstCardId": card,
        "secondCardId": None,
        "image": None,
        "fingerprints": [],
        "faceId": None,
        "accountUsernameId": None,
        "qrCodePayload": None,
        "birthday": None,
        "imageSource": None,
        "userImageStatus": None,
    }


def _make_credential(*, cred_id: int, account_id: int, gym_id: int = 58, secret_hex: str = "abc123", granted_ids=None):
    return {
        "id": cred_id,
        "gymId": gym_id,
        "accountId": account_id,
        "secretHex": secret_hex,
        "enabled": True,
        "rotatedAt": f"2026-04-{cred_id:02d}T00:00:00",
        "createdAt": f"2026-04-{cred_id:02d}T00:00:00",
        "updatedAt": f"2026-04-{cred_id:02d}T00:00:00",
        "grantedActiveMembershipIds": list(granted_ids or [account_id]),
    }


def test_save_sync_cache_delta_records_db_write_profile(db):
    data = {
        "users": [_make_user(am_id=10, user_id=110)],
        "membersDeltaMode": True,
        "validMemberIds": [10],
        "devices": [],
        "gymAccessCredentials": [_make_credential(cred_id=1, account_id=10)],
        "infrastructures": [],
        "membership": [],
        "contractStatus": True,
        "contractEndDate": "2026-12-31",
        "accessSoftwareSettings": {},
    }

    db.save_sync_cache_delta(
        data,
        {"members": True, "devices": False, "credentials": True, "settings": False},
    )

    profile = db.get_last_db_write_profile("save_sync_cache_delta")

    assert profile["label"] == "save_sync_cache_delta"
    for key in (
        "queue_wait_ms",
        "begin_wait_ms",
        "transaction_ms",
        "commit_ms",
        "total_ms",
        "meta_ms",
        "members_ms",
        "credentials_ms",
    ):
        assert key in profile
        assert float(profile[key]) >= 0.0


def test_db_writer_serializes_concurrent_write_jobs(db):
    started = threading.Event()
    release = threading.Event()
    order: list[str] = []

    def first_job(conn, profile):
        order.append("first-start")
        started.set()
        assert release.wait(timeout=1.0)
        order.append("first-end")
        return "first"

    def second_job(conn, profile):
        order.append("second")
        return "second"

    results: list[str] = []

    first_thread = threading.Thread(
        target=lambda: results.append(db._run_db_write_sync("first-job", first_job)),
        daemon=True,
    )
    second_thread = threading.Thread(
        target=lambda: (started.wait(timeout=1.0), results.append(db._run_db_write_sync("second-job", second_job))),
        daemon=True,
    )

    first_thread.start()
    second_thread.start()

    assert started.wait(timeout=1.0) is True
    assert order == ["first-start"]

    release.set()
    first_thread.join(timeout=1.0)
    second_thread.join(timeout=1.0)

    assert order == ["first-start", "first-end", "second"]
    assert results == ["first", "second"]


def test_load_sync_cache_db_builds_after_snapshot_fetch_connection_closes(monkeypatch):
    import app.core.db as db_module

    state = {"closed": False}

    class _Cursor:
        def __init__(self, rows):
            self._rows = rows

        def fetchone(self):
            return self._rows[0] if self._rows else None

        def fetchall(self):
            return list(self._rows)

    class _Conn:
        row_factory = None

        def execute(self, sql, params=()):
            normalized = " ".join(str(sql).split())
            if "FROM sync_meta" in normalized:
                return _Cursor([{"contract_status": 1, "contract_end_date": "2026-12-31", "updated_at": "meta-updated"}])
            if "FROM sync_access_software_settings" in normalized:
                return _Cursor([])
            if "FROM sync_users" in normalized:
                return _Cursor([])
            if "FROM sync_memberships" in normalized:
                return _Cursor([])
            if "FROM sync_devices" in normalized:
                return _Cursor([])
            if "FROM sync_device_door_presets" in normalized:
                return _Cursor([])
            if "FROM sync_infrastructures" in normalized:
                return _Cursor([])
            if "FROM sync_gym_access_credentials" in normalized:
                return _Cursor([])
            raise AssertionError(f"unexpected query: {normalized}")

        def close(self):
            state["closed"] = True

    @contextmanager
    def _fake_get_conn():
        conn = _Conn()
        try:
            yield conn
        finally:
            conn.close()

    sentinel = object()

    def _fake_build(snapshot):
        assert state["closed"] is True
        return sentinel

    monkeypatch.setattr(db_module, "get_conn", _fake_get_conn)
    monkeypatch.setattr(db_module, "_build_sync_cache_state_from_snapshot", _fake_build)

    result = db_module._load_sync_cache_db()

    assert result is sentinel

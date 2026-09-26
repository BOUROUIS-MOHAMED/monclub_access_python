"""The first start of a build with the grant-aware credential diff forces ONE full credentials re-send.

``_sync_gym_access_credentials_rows`` writes a grant-only change since 0e45be5, but a row the
previous build left stale (a renewed member keeps the old ActiveMembership id) is rewritten
only when the backend re-sends the credentials -- and backend ``main`` re-sends them only when
the client's ``credentialsVersion`` is absent or differs from its own. Upgrading the client
moves neither. ``init_db`` therefore drops the stored ``credentialsVersion`` once, recorded in
``local_one_shot_steps`` (never in ``sync_version_tokens``: every row there is sent to the
backend as a request param). guide §3.1b "The upgrade window".

The "previous build" database is built by the CURRENT ``init_db`` with the marker table then
dropped, so every other upgrade helper (members, pin scheme) sees a current schema and keeps
its tokens -- only this step can drop one.
"""
from __future__ import annotations

import sqlite3
from types import SimpleNamespace
from typing import Any, Dict

import pytest

_STEP = "credentials_resend_for_grant_diff"
_CREDS_ONLY = {"members": False, "devices": False, "credentials": True, "settings": False}
_TOKENS = {
    "membersVersion": "1080:2026-09-18T09:00:00:5:x",
    "membersUpdatedAfter": "2026-09-18T09:00:00",
    "devicesVersion": "2:2026-09-01",
    "credentialsVersion": "3:2026-09-10T08:00:00:abc",
    "settingsVersion": "2026-09-01T00:00:00:true:true:null:1:4",
}


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    data_root = tmp_path / "data-root"
    data_root.mkdir()
    monkeypatch.setenv("MONCLUB_ACCESS_DATA_ROOT", str(data_root))
    path = tmp_path / "one_shot.db"
    monkeypatch.setattr(db_module, "_DB_PATH", str(path), raising=False)
    db_module._close_thread_local_conn()
    db_module.invalidate_sync_cache(clear_cached=True)
    yield db_module, path
    db_module._close_thread_local_conn()
    db_module.invalidate_sync_cache(clear_cached=True)
    if hasattr(db_module, "_shutdown_db_writer_for_tests"):
        db_module._shutdown_db_writer_for_tests()


def _raw(path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def _as_previous_build(db, path, creds=None) -> None:
    """A database as the build before this change left it: current schema, no marker table,
    all five tokens stored, optionally some credential rows."""
    db.init_db()
    if creds:
        db.save_sync_cache_delta(
            {"gymAccessCredentials": creds, "contractStatus": True, "contractEndDate": "2026-12-31"},
            _CREDS_ONLY,
        )
    db._close_thread_local_conn()
    conn = _raw(path)
    conn.execute("DROP TABLE local_one_shot_steps")
    conn.execute("DELETE FROM sync_version_tokens")
    conn.executemany(
        "INSERT INTO sync_version_tokens (key, value) VALUES (?, ?)", list(_TOKENS.items()),
    )
    conn.commit()
    conn.close()


def _markers(path) -> list[str]:
    conn = _raw(path)
    try:
        return [r["name"] for r in conn.execute("SELECT name FROM local_one_shot_steps")]
    except sqlite3.OperationalError:
        return []            # no table
    finally:
        conn.close()


def _stored_tokens(path) -> Dict[str, str]:
    conn = _raw(path)
    try:
        return {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM sync_version_tokens")}
    finally:
        conn.close()


def _cred(account_id: int, grants) -> dict:
    return {
        "id": account_id + 1, "gymId": 58, "accountId": account_id,
        "secretHex": f"{account_id:040x}", "enabled": True, "rotatedAt": None,
        "createdAt": "2026-04-01T00:00:00", "updatedAt": "2026-04-01T00:00:00",
        "grantedActiveMembershipIds": list(grants),
    }


def test_the_token_is_dropped_exactly_once_across_two_starts(db):
    db, path = db
    _as_previous_build(db, path)

    db.init_db()
    after_first = db.load_version_tokens()
    assert "credentialsVersion" not in after_first
    assert _markers(path) == [_STEP]

    # The sync that follows stores the backend's new token; the next start must keep it.
    db.save_version_tokens({"credentialsVersion": "3:2026-09-25T10:00:00:def"})
    db.init_db()
    assert db.load_version_tokens().get("credentialsVersion") == "3:2026-09-25T10:00:00:def"
    assert _markers(path) == [_STEP]


def test_every_other_token_is_kept(db):
    db, path = db
    _as_previous_build(db, path)

    db.init_db()

    expected = {k: v for k, v in _TOKENS.items() if k != "credentialsVersion"}
    assert db.load_version_tokens() == expected


def test_the_marker_is_never_sent_to_the_backend(db):
    """Evidence it TRIGGERS: the tokens the sync tick loads are what MonClubApi.get_sync_data
    sends. The request carries no credentialsVersion (the backend then re-sends every
    credential), every other token, and nothing named after the marker."""
    db, path = db
    _as_previous_build(db, path)
    db.init_db()

    from app.api.monclub_api import MonClubApi
    from app.core.sync_scope import apply_trigger_hint_to_version_tokens

    sent: Dict[str, Any] = {}

    class _Resp:
        status_code = 200
        text = "{}"

        @staticmethod
        def json():
            return {}

    api = MonClubApi.__new__(MonClubApi)
    api.endpoints = SimpleNamespace(sync_url="https://backend.invalid/manager/gym/access/v1/sync")
    api.logger = SimpleNamespace(info=lambda *a, **k: None, debug=lambda *a, **k: None,
                                 warning=lambda *a, **k: None)
    api._session = SimpleNamespace(get=lambda url, params, headers, timeout: (sent.update(params), _Resp)[1])

    api.get_sync_data(token="t", version_tokens=apply_trigger_hint_to_version_tokens(db.load_version_tokens(), None))

    assert "credentialsVersion" not in sent
    assert {k: sent.get(k) for k in _TOKENS if k != "credentialsVersion"} == {
        k: v for k, v in _TOKENS.items() if k != "credentialsVersion"
    }
    assert not any(_STEP in str(k) or _STEP in str(v) for k, v in sent.items())


def test_the_full_resend_rewrites_only_the_stale_rows(db):
    db, path = db
    # The previous build stored 5002's grant before the renewal and never rewrote it.
    _as_previous_build(db, path, creds=[_cred(5001, [101]), _cred(5002, [202]), _cred(5003, [303, 304])])
    db.init_db()
    assert "credentialsVersion" not in db.load_version_tokens()

    # The backend's full answer: 5002 renewed (new membership id), 5003's grants in another order.
    summary = db.save_sync_cache_delta(
        {"gymAccessCredentials": [_cred(5001, [101]), _cred(5002, [909]), _cred(5003, [304, 303])],
         "contractStatus": True, "contractEndDate": "2026-12-31"},
        _CREDS_ONLY,
    )["credentials"]

    assert summary["mode"] == "delta" and summary["upserted"] == 1 and summary["deleted"] == 0
    grants = {c["accountId"]: c["grantedActiveMembershipIds"] for c in db.list_sync_gym_access_credentials()}
    assert grants == {5001: [101], 5002: [909], 5003: [303, 304]}


def test_a_fresh_install_gets_the_marker_and_nothing_else(db):
    db, path = db

    db.init_db()

    assert db.load_version_tokens() == {}
    assert _markers(path) == [_STEP]
    assert db.load_sync_cache() is None, "no contract snapshot is invented before the first sync"

    # Its first sync stores tokens; no later start touches them.
    db.save_version_tokens(dict(_TOKENS))
    db.init_db()
    assert db.load_version_tokens() == _TOKENS


class _PowerCut(BaseException):
    """The process dying: not an Exception, so no handler in init_db catches it."""


class _CutBeforeMarker:
    """Delegates to a real connection; dies at the marker INSERT, after checking the DELETE ran."""

    def __init__(self, real: sqlite3.Connection, seen: Dict[str, Any]):
        self._real = real
        self._seen = seen

    def execute(self, sql, *args):
        if "INSERT" in sql and "local_one_shot_steps" in sql:
            keys = {r[0] for r in self._real.execute("SELECT key FROM sync_version_tokens")}
            self._seen["token_gone_before_marker"] = "credentialsVersion" not in keys
            self._seen["in_transaction"] = self._real.in_transaction
            raise _PowerCut()
        return self._real.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self._real, name)


def test_a_crash_between_the_delete_and_the_marker_rolls_both_back(db, monkeypatch):
    db, path = db
    _as_previous_build(db, path)

    seen: Dict[str, Any] = {}
    real_open = db._open_sqlite_connection
    real_reuse = db._REUSE_CONN_ENABLED
    # A fresh connection per get_conn, closed without commit when the exception unwinds it.
    monkeypatch.setattr(db, "_REUSE_CONN_ENABLED", False)
    monkeypatch.setattr(db, "_open_sqlite_connection",
                        lambda p, **kw: _CutBeforeMarker(real_open(p, **kw), seen))
    db._close_thread_local_conn()

    with pytest.raises(_PowerCut):
        db.init_db()
    monkeypatch.setattr(db, "_open_sqlite_connection", real_open)
    monkeypatch.setattr(db, "_REUSE_CONN_ENABLED", real_reuse)
    db._close_thread_local_conn()

    # At the cut the DELETE had run, inside init_db's open transaction ...
    assert seen == {"token_gone_before_marker": True, "in_transaction": True}
    # ... and nothing of it survived the connection closing uncommitted.
    assert _stored_tokens(path) == _TOKENS
    assert _markers(path) == []

    # The next start acts again, and this time commits both.
    db.init_db()
    assert "credentialsVersion" not in db.load_version_tokens()
    assert _markers(path) == [_STEP]


def test_a_failed_marker_write_repeats_the_drop_never_loses_it(db, monkeypatch):
    """An ordinary error at the INSERT is caught by init_db, which commits the rest: the token
    is dropped without the marker, so the next start drops it again -- a second full re-send,
    never a lost one. This is why the DELETE comes first."""
    db, path = db
    _as_previous_build(db, path)

    real_now = db.now_iso
    calls = {"n": 0}

    def _failing_now():
        calls["n"] += 1
        raise RuntimeError("disk full")

    monkeypatch.setattr(db, "now_iso", _failing_now)
    db.init_db()
    monkeypatch.setattr(db, "now_iso", real_now)
    assert calls["n"] >= 1

    assert "credentialsVersion" not in db.load_version_tokens()
    assert _markers(path) == []

    db.save_version_tokens({"credentialsVersion": "3:2026-09-25T10:00:00:def"})
    db.init_db()
    assert "credentialsVersion" not in db.load_version_tokens(), "the step runs again"
    assert _markers(path) == [_STEP]

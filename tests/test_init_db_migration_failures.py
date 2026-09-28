"""A schema migration that fails inside ``init_db`` stops startup -- on purpose.

Four migrations sat in inline ``try/except`` wrappers written to log and carry on, but
``init_db`` also imported ``logging`` in its own body (the stale-lock resets after its ``with``
block), which made ``logging`` a local name for the whole function: every one of those
``except`` branches raised ``UnboundLocalError`` instead of logging. A failing migration
therefore escaped ``init_db`` and the app did not start -- by accident. The owner chose that as
the intended behaviour (2026-09-25): the wrappers are gone, the migration's own error
propagates, and whatever ``init_db`` did inside its open transaction rolls back, so the next
start retries from a clean state. Carrying on was measured to commit half a migration (a
legacy rebuild whose leftover copy then fails every later start, a lost forced device
refresh). guide §3.2d "A failing migration stops startup".

The mid-statement tests put the failure BETWEEN two statements of one migration -- the point
the §3.2d atomicity claims are about -- through a connection proxy, not at the helper's entry.
"""
from __future__ import annotations

import logging
import sqlite3

import pytest

_WRAPPED = (
    "_relax_firmware_profiles_not_null",
    "_rebuild_sync_users_without_legacy_fingerprint",
    "_ensure_main_account_id_column",
    "_ensure_pin_scheme_column",
)


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    data_root = tmp_path / "data-root"
    data_root.mkdir()
    monkeypatch.setenv("MONCLUB_ACCESS_DATA_ROOT", str(data_root))
    path = tmp_path / "migrations.db"
    monkeypatch.setattr(db_module, "_DB_PATH", str(path), raising=False)
    db_module._close_thread_local_conn()
    db_module.invalidate_sync_cache(clear_cached=True)
    yield db_module, path
    db_module._close_thread_local_conn()
    db_module.invalidate_sync_cache(clear_cached=True)
    if hasattr(db_module, "_shutdown_db_writer_for_tests"):
        db_module._shutdown_db_writer_for_tests()


def _fail_once(db, monkeypatch, fragment: str) -> dict:
    """Every connection ``init_db`` opens raises sqlite3.OperationalError on the FIRST statement
    containing ``fragment`` (whitespace-normalised) and passes everything else through.

    Returns a dict whose ``in_transaction`` is the connection's state at the cut. On the
    databases seeded below the only DML that can run before each cut is the migration's own
    first write, so True there shows that write ran -- and the post-failure checks show it was
    rolled back, not skipped."""
    state = {"fired": False, "in_transaction": None}

    class _Conn:
        def __init__(self, real):
            self._real = real

        def execute(self, sql, *args):
            if not state["fired"] and fragment in " ".join(str(sql).split()):
                state["fired"] = True
                state["in_transaction"] = self._real.in_transaction
                raise sqlite3.OperationalError(f"injected at: {fragment}")
            return self._real.execute(sql, *args)

        def __getattr__(self, name):
            return getattr(self._real, name)

    # get_conn's warm path opens through _open_read_connection, its nested path through
    # _open_sqlite_connection.
    for opener in ("_open_read_connection", "_open_sqlite_connection"):
        real = getattr(db, opener)
        monkeypatch.setattr(db, opener, lambda *a, _real=real, **k: _Conn(_real(*a, **k)))
    db._close_thread_local_conn()
    return state


def _raw(path, sql, params=()):
    conn = sqlite3.connect(str(path))
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def _columns(path, table) -> list[str]:
    return [r[1] for r in _raw(path, f"PRAGMA table_info({table})")]


def _tables(path) -> set[str]:
    return {r[0] for r in _raw(path, "SELECT name FROM sqlite_master WHERE type='table'")}


def _token_keys(path) -> set[str]:
    return {r[0] for r in _raw(path, "SELECT key FROM sync_version_tokens")}


def _seed(path, *statements) -> None:
    conn = sqlite3.connect(str(path))
    for sql, params in statements:
        conn.execute(sql, params)
    conn.commit()
    conn.close()


def _start(db) -> None:
    db._close_thread_local_conn()
    db.init_db()
    db._close_thread_local_conn()


def test_init_db_binds_no_local_logging(db):
    """The root cause, pinned: a name bound anywhere in a function body is local to all of it,
    so one ``import logging`` inside ``init_db`` turned every ``logging.`` read in it into a
    read of an unbound local."""
    db_module, _ = db
    code = db_module.init_db.__code__
    assert "logging" not in code.co_varnames
    assert "logging" in code.co_names


@pytest.mark.parametrize("name", _WRAPPED)
def test_a_failing_migration_raises_its_own_error_and_the_next_start_completes(db, monkeypatch, name):
    db_module, path = db
    original = getattr(db_module, name)

    def _boom(*args, **kwargs):
        raise RuntimeError(f"injected failure in {name}")

    monkeypatch.setattr(db_module, name, _boom)
    with pytest.raises(RuntimeError, match="injected failure"):
        _start(db_module)
    # Only the transaction rolls back: the CREATE TABLEs that ran before its first DML are kept.
    assert "sync_users" in _tables(path)

    monkeypatch.setattr(db_module, name, original)
    _start(db_module)
    assert "main_account_id" in _columns(path, "sync_users")
    assert "pin_scheme" in _columns(path, "sync_devices")
    assert "sync_firmware_profiles" in _tables(path)


def test_a_legacy_rebuild_that_fails_midway_leaves_no_copy_behind(db, monkeypatch):
    """Carrying on after this failure committed a FULL sync_users_new; the next start copied the
    rows into it again and every later start failed on the UNIQUE index."""
    db_module, path = db
    _seed(path, (
        "CREATE TABLE sync_users (user_id INTEGER, active_membership_id INTEGER, membership_id INTEGER,"
        " full_name TEXT, phone TEXT, email TEXT, valid_from TEXT, valid_to TEXT, first_card_id TEXT,"
        " second_card_id TEXT, image TEXT, fingerprint TEXT, face_id TEXT, account_username_id TEXT,"
        " qr_code_payload TEXT)", ()), (
        "INSERT INTO sync_users (user_id, active_membership_id, full_name) VALUES (900, 31000, 'Ali')", ()),
    )
    cut = _fail_once(db_module, monkeypatch, "DROP TABLE sync_users;")

    with pytest.raises(sqlite3.OperationalError, match="injected"):
        _start(db_module)
    assert cut["in_transaction"] is True, "the copy into sync_users_new ran before the cut"

    assert "fingerprint" in _columns(path, "sync_users")
    # Its CREATE ran before any DML, so it autocommitted; the copy into it rolled back.
    assert _raw(path, "SELECT count(*) FROM sync_users_new") == [(0,)]

    _start(db_module)
    _start(db_module)
    cols = _columns(path, "sync_users")
    assert "fingerprint" not in cols and "main_account_id" in cols
    assert _raw(path, "SELECT user_id, active_membership_id, full_name FROM sync_users") == [
        (900, 31000, "Ali")
    ]
    assert "sync_users_new" not in _tables(path)


def test_a_firmware_profile_rebuild_that_fails_midway_keeps_the_cached_profile(db, monkeypatch):
    """Carrying on after a failed RENAME committed the DROP of the old table; a later CREATE TABLE
    IF NOT EXISTS then made an empty one and the cached profile stayed in the orphan copy."""
    db_module, path = db
    _seed(path, (
        "CREATE TABLE sync_firmware_profiles (device_id INTEGER PRIMARY KEY,"
        " template_table TEXT NOT NULL, template_body_index INTEGER NOT NULL,"
        " authorize_body_index INTEGER NOT NULL, updated_at TEXT NOT NULL DEFAULT '')", ()), (
        "INSERT INTO sync_firmware_profiles VALUES (7, 'templatev10', 4, 3, 'x')", ()),
    )
    cut = _fail_once(db_module, monkeypatch, "ALTER TABLE sync_firmware_profiles__new RENAME")

    with pytest.raises(sqlite3.OperationalError, match="injected"):
        _start(db_module)
    assert cut["in_transaction"] is True, "the copy into sync_firmware_profiles__new ran before the cut"

    assert _raw(path, "SELECT device_id, template_table FROM sync_firmware_profiles") == [(7, "templatev10")]
    # Its CREATE ran before any DML, so it autocommitted; the copy into it rolled back.
    assert _raw(path, "SELECT count(*) FROM sync_firmware_profiles__new") == [(0,)]

    _start(db_module)
    assert _raw(path, "SELECT device_id, template_table FROM sync_firmware_profiles") == [(7, "templatev10")]
    notnull = {r[1]: r[3] for r in _raw(path, "PRAGMA table_info(sync_firmware_profiles)")}
    assert notnull["template_table"] == 0, "the NOT NULL was relaxed on the retry"
    assert "sync_firmware_profiles__new" not in _tables(path)


def test_a_main_account_column_that_fails_after_the_token_drop_rolls_the_drop_back(db, monkeypatch):
    """guide §3.2d: the token DELETE runs before the ALTER, in one transaction. An ERROR between
    them -- not only a crash -- must leave the tokens stored, or the column would be added on
    the retry with nothing left to force the refresh its NULL rows need."""
    db_module, path = db
    _seed(path, (
        "CREATE TABLE sync_users (user_id INTEGER, active_membership_id INTEGER, membership_id INTEGER,"
        " full_name TEXT, phone TEXT, email TEXT, valid_from TEXT, valid_to TEXT, first_card_id TEXT,"
        " second_card_id TEXT, image TEXT, fingerprints_json TEXT, face_id TEXT, account_username_id TEXT,"
        " qr_code_payload TEXT, birthday TEXT)", ()), (
        "INSERT INTO sync_users (user_id, active_membership_id, full_name) VALUES (900, 31000, 'Ali')", ()), (
        "CREATE TABLE sync_version_tokens (key TEXT PRIMARY KEY, value TEXT NOT NULL)", ()), (
        "INSERT INTO sync_version_tokens (key, value) VALUES ('membersVersion', 'm'),"
        " ('membersUpdatedAfter', 'u'), ('devicesVersion', 'd')", ()),
    )
    cut = _fail_once(db_module, monkeypatch, "ALTER TABLE sync_users ADD COLUMN main_account_id")

    with pytest.raises(sqlite3.OperationalError, match="injected"):
        _start(db_module)
    assert cut["in_transaction"] is True, "the token DELETE ran before the cut"

    assert "main_account_id" not in _columns(path, "sync_users")
    assert _token_keys(path) == {"membersVersion", "membersUpdatedAfter", "devicesVersion"}

    _start(db_module)
    assert "main_account_id" in _columns(path, "sync_users")
    assert _token_keys(path) == {"devicesVersion"}


def test_a_pin_scheme_column_that_fails_after_the_token_drop_rolls_the_drop_back(db, monkeypatch):
    """Same claim for the device helper (review #13). Its old fallback added the column after a
    failure, so a failure before the DELETE lost the one forced device refresh for good."""
    db_module, path = db
    _start(db_module)
    cols = [c for c in _columns(path, "sync_devices") if c != "pin_scheme"]
    col_list = ", ".join(f'"{c}"' for c in cols)
    _seed(path,
          ("DROP INDEX IF EXISTS uq_sync_devices_id", ()),
          (f"CREATE TABLE sync_devices_old AS SELECT {col_list} FROM sync_devices", ()),
          ("DROP TABLE sync_devices", ()),
          ("ALTER TABLE sync_devices_old RENAME TO sync_devices", ()),
          ("DROP TABLE device_pin_scheme_switch", ()),
          ("DROP TABLE IF EXISTS device_pin_scheme_seen", ()),
          ("INSERT INTO sync_devices (id, name) VALUES (42, 'Lane')", ()),
          ("DELETE FROM sync_version_tokens", ()),
          ("INSERT INTO sync_version_tokens (key, value) VALUES ('devicesVersion', 'd'),"
           " ('settingsVersion', 's')", ()))
    cut = _fail_once(db_module, monkeypatch, "INSERT OR IGNORE INTO device_pin_scheme_seen")

    with pytest.raises(sqlite3.OperationalError, match="injected"):
        _start(db_module)
    assert cut["in_transaction"] is True, "the devicesVersion DELETE ran before the cut"

    assert "pin_scheme" not in _columns(path, "sync_devices")
    assert _token_keys(path) == {"devicesVersion", "settingsVersion"}

    _start(db_module)
    assert "pin_scheme" in _columns(path, "sync_devices")
    assert _token_keys(path) == {"settingsVersion"}
    assert _raw(path, "SELECT device_id, first_scheme FROM device_pin_scheme_seen") == [(42, "MEMBERSHIP")]


def test_the_hold_column_that_fails_stops_the_start_and_the_next_start_adds_it(db, monkeypatch):
    """Lane 1f (review of lane 1e, nit C3): the inline ``device_write_hold.pin_scheme`` ALTER is a
    fifth hard step, on purpose not ``_ensure_column`` (whose swallowed failure would make every
    hold read fail -- and hold every turnstile). A lanes 1-1d table with a held row: the ALTER
    fails, init_db raises, the row is untouched; the next start adds the column and keeps it."""
    db_module, path = db
    _start(db_module)
    _seed(path,
          ("DROP TABLE device_write_hold", ()),
          ("CREATE TABLE device_write_hold (device_id INTEGER PRIMARY KEY, reason TEXT NOT NULL, "
           "run_id TEXT, created_at TEXT NOT NULL)", ()),
          ("INSERT INTO device_write_hold VALUES (5, 'erase', 'r0', '2026-09-28 01:00:00')", ()))
    _fail_once(db_module, monkeypatch, "ALTER TABLE device_write_hold ADD COLUMN pin_scheme")

    with pytest.raises(sqlite3.OperationalError, match="injected"):
        _start(db_module)
    assert "pin_scheme" not in _columns(path, "device_write_hold")
    assert _raw(path, "SELECT device_id, reason FROM device_write_hold") == [(5, "erase")]

    _start(db_module)
    assert "pin_scheme" in _columns(path, "device_write_hold")
    assert _raw(path, "SELECT device_id, reason, pin_scheme FROM device_write_hold") == [
        (5, "erase", None)]


def test_a_hold_column_read_that_fails_stops_the_start_as_itself(db, monkeypatch):
    """The column check reads with a PRAGMA that raises (lane 1f, nit C3): a read error stops the
    start as its own error -- ``_table_columns`` answered [] there, which turned it into the ALTER's
    misleading 'duplicate column name'."""
    db_module, path = db
    _start(db_module)
    _fail_once(db_module, monkeypatch, "PRAGMA table_info(device_write_hold)")

    with pytest.raises(sqlite3.OperationalError, match="injected at: PRAGMA table_info"):
        _start(db_module)

    _start(db_module)
    assert "pin_scheme" in _columns(path, "device_write_hold")


def test_the_stale_lock_resets_still_log_through_the_module_logging(db, monkeypatch, caplog):
    """The two blocks that used to import logging locally still log -- warnings on a reset,
    errors on a failure -- and a failure there does not stop startup."""
    db_module, _ = db
    monkeypatch.setattr(db_module, "reset_stale_processing_locks", lambda: 2)
    monkeypatch.setattr(db_module, "reset_stale_offline_mutation_locks", lambda: 3)
    with caplog.at_level(logging.WARNING, logger="db"):
        _start(db_module)
    messages = [r.getMessage() for r in caplog.records if r.name == "db"]
    assert any("Reset 2 stale processing lock(s)" in m for m in messages)
    assert any("Reset 3 stale processing lock(s) in offline_mutation_queue" in m for m in messages)

    def _boom():
        raise RuntimeError("locked")

    caplog.clear()
    monkeypatch.setattr(db_module, "reset_stale_processing_locks", _boom)
    monkeypatch.setattr(db_module, "reset_stale_offline_mutation_locks", _boom)
    with caplog.at_level(logging.ERROR, logger="db"):
        _start(db_module)
    errors = [r.getMessage() for r in caplog.records if r.name == "db" and r.levelno == logging.ERROR]
    assert any("Failed to reset stale processing locks" in m for m in errors)
    assert any("Failed to reset stale mutation locks" in m for m in errors)

"""The warm read connections are pooled across threads (2026-10-02).

Kept per thread, a warm connection died with its thread, and the local API starts one thread
per request: gym 45 opened 1,235 warm connections for 1,238 history reads (1.4.32), each
~90-160 ms. An outer get_conn() now borrows an idle one from a shared pool.
"""
from __future__ import annotations

import sqlite3
import threading

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    data_root = tmp_path / "data-root"
    data_root.mkdir()
    monkeypatch.setenv("MONCLUB_ACCESS_DATA_ROOT", str(data_root))
    path = tmp_path / "pool.db"
    monkeypatch.setattr(db_module, "_DB_PATH", str(path), raising=False)
    monkeypatch.setattr(db_module, "_REUSE_CONN_ENABLED", True)
    db_module._close_thread_local_conn()
    with sqlite3.connect(str(path)) as raw:
        raw.execute("PRAGMA journal_mode=WAL")
        raw.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        raw.execute("INSERT INTO t (v) VALUES ('a')")
    opens: list[int] = []
    real_open = db_module._open_read_connection

    def counting_open(*a, **k):
        opens.append(1)
        return real_open(*a, **k)

    monkeypatch.setattr(db_module, "_open_read_connection", counting_open)
    yield db_module, opens
    db_module._close_thread_local_conn()
    if hasattr(db_module, "_shutdown_db_writer_for_tests"):
        db_module._shutdown_db_writer_for_tests()


def _read_in_new_thread(db_module) -> int:
    out: list[int] = []

    def work():
        with db_module.get_conn() as conn:
            out.append(conn.execute("SELECT COUNT(*) FROM t").fetchone()[0])

    th = threading.Thread(target=work)
    th.start()
    th.join()
    return out[0]


def test_one_thread_per_request_reuses_one_warm_connection(db):
    db_module, opens = db
    for _ in range(50):  # like 50 local-API requests, each on its own new thread
        assert _read_in_new_thread(db_module) == 1
    assert len(opens) == 1  # was 50 with per-thread connections


def test_a_returned_connection_carries_no_open_transaction(db):
    db_module, _ = db
    with db_module.get_conn() as conn:
        conn.execute("INSERT INTO t (v) VALUES ('uncommitted')")
        assert conn.in_transaction
    with db_module.get_conn() as conn2:
        assert not conn2.in_transaction
        assert conn2.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 1


def test_a_connection_that_raised_is_closed_not_pooled(db):
    db_module, opens = db
    with pytest.raises(ZeroDivisionError):
        with db_module.get_conn() as conn:
            bad = conn
            1 / 0
    with pytest.raises(sqlite3.ProgrammingError):
        bad.execute("SELECT 1")  # closed
    with db_module.get_conn() as conn:
        assert conn is not bad
    assert len(opens) == 2


def test_a_nested_get_conn_gets_its_own_connection(db):
    db_module, _ = db
    with db_module.get_conn() as outer:
        with db_module.get_conn() as inner:
            assert inner is not outer
            inner.execute("INSERT INTO t (v) VALUES ('inner')")
            inner.commit()  # an independent transaction, as before the pool
        assert outer.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 2


def test_concurrent_borrowers_never_share_and_the_pool_stays_bounded(db):
    db_module, _ = db
    n = db_module._READ_POOL_MAX_IDLE + 4
    held: list[sqlite3.Connection] = []
    lock = threading.Lock()
    all_in = threading.Barrier(n)

    def work():
        with db_module.get_conn() as conn:
            with lock:
                held.append(conn)
            all_in.wait(timeout=10)  # every thread holds one at the same moment

    threads = [threading.Thread(target=work) for _ in range(n)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert len({id(c) for c in held}) == n
    assert len(db_module._read_pool) == db_module._READ_POOL_MAX_IDLE


def test_a_db_path_change_never_hands_back_a_connection_to_the_old_file(db, tmp_path, monkeypatch):
    db_module, _ = db
    with db_module.get_conn() as conn:
        old = conn
    other = tmp_path / "other.db"
    with sqlite3.connect(str(other)) as raw:
        raw.execute("CREATE TABLE u (x)")
    monkeypatch.setattr(db_module, "_DB_PATH", str(other), raising=False)
    with db_module.get_conn() as conn:
        assert conn is not old
        conn.execute("SELECT * FROM u").fetchall()
    with pytest.raises(sqlite3.ProgrammingError):
        old.execute("SELECT 1")  # the stale one was closed, not left open

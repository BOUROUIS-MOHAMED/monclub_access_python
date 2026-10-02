"""The DbWriter is the only application writer (guide §3.11).

* A tripwire: an AST scan of ``app/``, ``access/`` and ``shared/`` fails on a new direct
  write -- a ``.commit()`` / ``executescript`` / ``isolation_level`` / ``sqlite3.connect``
  outside the allowlist, or an INSERT/UPDATE/DELETE/... executed inside a
  ``with get_conn() as conn:`` block. The scanner is tested on a synthetic snippet, so
  it cannot pass by never firing.
* The door-path lane: a door job runs before every QUEUED normal job, never before the
  one already running, FIFO inside each lane.
* The AGENT history claim under a saturated writer still answers (the old direct write
  failed with "database is locked" after ~30 s -- tools/bench_door_history_claim.py).
* A converted write called from inside a write job runs inline, in that transaction.
* A read-modify-write that moved into one job is atomic (apply_fast_patch_bundle).
* Every converted function still returns what it did and runs on the DbWriter thread.
"""
from __future__ import annotations

import ast
import re
import sqlite3
import threading
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# The tripwire
# ---------------------------------------------------------------------------

# Functions (outermost def) allowed to write on their own connection, and why.
ALLOWED_DIRECT: dict[str, set[str] | str] = {
    # init_db: the startup schema + migrations, one transaction of its own before the
    # engines start (guide §3.2d "A failing migration stops startup"). _db_writer_loop:
    # the writer itself. The two connection factories open connections (no write).
    "app/core/db.py": {"init_db", "_db_writer_loop", "_open_sqlite_connection", "_open_read_connection"},
    # Startup copy of legacy tables into the live file, run by access/store.py::init_db
    # between the two init_db() calls, before any engine starts.
    "shared/storage_migration.py": "*",
    # The TV app's own database (tv.store.get_conn -> tv.storage), a different file.
    "app/core/tv_local_cache.py": "*",
}

_WRITE_SQL = re.compile(
    r"^\s*(INSERT|UPDATE|DELETE|REPLACE|UPSERT|CREATE|DROP|ALTER|BEGIN|COMMIT|END|VACUUM|REINDEX)\b",
    re.IGNORECASE,
)
_GET_CONN_NAMES = {"get_conn", "_get_conn"}


def _leading_sql(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                if part.value.strip():
                    return part.value
                continue
            return None
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _leading_sql(node.left)
    return None


def _is_get_conn_with(node: ast.With) -> list[str]:
    names = []
    for item in node.items:
        ce = item.context_expr
        if isinstance(ce, ast.Call):
            fn = ce.func
            name = fn.id if isinstance(fn, ast.Name) else (fn.attr if isinstance(fn, ast.Attribute) else None)
            if name in _GET_CONN_NAMES and isinstance(item.optional_vars, ast.Name):
                names.append(item.optional_vars.id)
    return names


def _walk_same_scope(node: ast.AST):
    """Children, not descending into nested defs/lambdas (a job body is not the with's)."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        yield child
        yield from _walk_same_scope(child)


def scan_direct_writes(source: str, rel: str) -> list[str]:
    """Violations in one module: ``"<rel>:<line> <function> <what>"``."""
    tree = ast.parse(source)
    allowed = ALLOWED_DIRECT.get(rel, set())
    if allowed == "*":
        return []
    out: list[str] = []

    def visit(node: ast.AST, outer: str | None) -> None:
        for child in ast.iter_child_nodes(node):
            name = outer
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and outer is None:
                name = child.name
            if name not in allowed:
                check(child, name)
            visit(child, name)

    def check(node: ast.AST, fn: str | None) -> None:
        where = f"{rel}:{getattr(node, 'lineno', '?')} {fn or '<module>'}"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr in ("commit", "executescript"):
                out.append(f"{where} .{attr}()")
            if attr == "connect" and isinstance(node.func.value, ast.Name) and node.func.value.id == "sqlite3":
                out.append(f"{where} sqlite3.connect()")
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Attribute) and t.attr == "isolation_level":
                    out.append(f"{where} isolation_level=")
        if isinstance(node, ast.With):
            conns = _is_get_conn_with(node)
            if conns:
                for inner in _walk_same_scope(node):
                    if isinstance(inner, ast.With):
                        for item in inner.items:
                            if isinstance(item.context_expr, ast.Name) and item.context_expr.id in conns:
                                out.append(f"{rel}:{inner.lineno} {fn} with <conn>: (commits)")
                    if (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute)
                            and inner.func.attr in ("execute", "executemany") and inner.args):
                        sql = _leading_sql(inner.args[0])
                        if sql is not None and _WRITE_SQL.match(sql):
                            out.append(f"{rel}:{inner.lineno} {fn} write SQL on a get_conn() connection: "
                                       f"{sql.strip().split()[0].upper()}")

    visit(tree, None)
    return out


def _scanned_modules() -> list[Path]:
    files: list[Path] = []
    for top in ("app", "access", "shared"):
        files.extend(sorted((REPO / top).rglob("*.py")))
    return files


def test_no_direct_write_outside_the_db_writer():
    violations: list[str] = []
    for path in _scanned_modules():
        rel = path.relative_to(REPO).as_posix()
        violations.extend(scan_direct_writes(path.read_text(encoding="utf-8"), rel))
    assert not violations, (
        "Direct database writes outside the DbWriter (route them through "
        "db._run_db_write_sync, one job per function -- guide §3.11):\n" + "\n".join(violations)
    )


def test_the_tripwire_fires_on_a_direct_write():
    src = '''
def bad_commit():
    with get_conn() as conn:
        conn.execute("UPDATE t SET x = 1")
        conn.commit()

def bad_fstring():
    with get_conn() as conn:
        conn.execute(f"DELETE FROM t WHERE id IN ({ph})", ids)

def bad_concat():
    with get_conn() as conn:
        conn.executemany("INSERT INTO t " + "VALUES (?)", rows)

def bad_conn_cm():
    with get_conn() as conn:
        with conn:
            pass

def bad_script(c):
    c.executescript("DELETE FROM t")

def bad_connect():
    return sqlite3.connect("x.db")

def bad_autocommit(c):
    c.isolation_level = None

def ok():
    with get_conn() as conn:
        rows = conn.execute("SELECT 1").fetchall()
    def _write(conn, _p):
        conn.execute("INSERT INTO t VALUES (1)")
    return _run_db_write_sync("ok", _write)
'''
    found = scan_direct_writes(src, "app/core/fake.py")
    by_fn = {}
    for v in found:
        by_fn.setdefault(v.split()[1], []).append(v)
    assert set(by_fn) == {"bad_commit", "bad_fstring", "bad_concat", "bad_conn_cm", "bad_script",
                          "bad_connect", "bad_autocommit"}, found
    assert len(by_fn["bad_commit"]) == 2, found      # the UPDATE and the commit
    # The allowlist really exempts what it names, and only that.
    assert scan_direct_writes(src, "shared/storage_migration.py") == []


def test_init_db_is_the_only_db_py_function_left_writing_directly():
    """The allowlist is exact: every listed db.py function still exists (a rename would
    silently exempt nothing) and every other db.py commit is gone."""
    src = (REPO / "app/core/db.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    top = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    assert ALLOWED_DIRECT["app/core/db.py"] <= top
    committers = set()
    for fn in tree.body:
        if isinstance(fn, ast.FunctionDef):
            for n in ast.walk(fn):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "commit":
                    committers.add(fn.name)
    assert committers == {"init_db", "_db_writer_loop"}


# ---------------------------------------------------------------------------
# Behaviour
# ---------------------------------------------------------------------------

@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "single_writer.db"), raising=False)
    db_module._shutdown_db_writer_for_tests()
    db_module.init_db()
    yield db_module
    db_module._shutdown_db_writer_for_tests()


def _wait_qsize(db, n: int) -> None:
    deadline = time.monotonic() + 5.0
    while db._db_writer_queue.qsize() < n:
        assert time.monotonic() < deadline, f"queue never reached {n}"
        time.sleep(0.005)


def test_door_lane_runs_before_queued_normal_jobs_never_before_the_running_one(db):
    gate = threading.Event()
    started = threading.Event()
    order: list[str] = []

    def blocker(conn, _p):
        order.append("running")
        started.set()
        assert gate.wait(10)

    threads = [threading.Thread(target=db._run_db_write_sync, args=("blocker", blocker))]
    threads[0].start()
    assert started.wait(5)

    def submit(name: str, priority: bool, depth: int) -> None:
        def op(conn, _p):
            order.append(name)
        t = threading.Thread(target=lambda: db._run_db_write_sync(name, op, priority=priority))
        t.start()
        threads.append(t)
        _wait_qsize(db, depth)

    submit("normal-1", False, 1)
    submit("normal-2", False, 2)
    submit("door-1", True, 3)
    submit("normal-3", False, 4)
    submit("door-2", True, 5)
    gate.set()
    for t in threads:
        t.join(10)
        assert not t.is_alive()
    assert order == ["running", "door-1", "door-2", "normal-1", "normal-2", "normal-3"]
    assert db.get_last_db_write_profile("door-1").get("priority") is True
    assert "priority" not in db.get_last_db_write_profile("normal-1")


_HISTORY = dict(
    device_id=1, door_id=1, card_no="123", event_time="2026-10-02 10:00:00", event_type="RTLOG",
    allowed=True, reason="ALLOW", poll_ms=1.0, decision_ms=1.0, cmd_ms=0.0, cmd_ok=None,
    cmd_error=None, raw={},
)


def test_the_door_claim_answers_while_the_writer_is_saturated(db):
    """Two threads keep the writer busy back to back (each job holds the write transaction
    100 ms). In the door lane the claim waits for the job in hand only. Red on aeb8682 (the
    claim a direct write): 5.25 s in the one run made; tools/bench_door_history_claim.py on
    aeb8682 shows such claims mostly failing with "database is locked" after ~32 s."""
    db._run_db_write_sync("mk", lambda conn, _p: conn.execute("CREATE TABLE IF NOT EXISTS bulk (x REAL)"))
    stop = threading.Event()

    def bulk(conn, _p):
        conn.execute("INSERT INTO bulk (x) VALUES (?)", (time.perf_counter(),))
        time.sleep(0.1)

    def loader():
        while not stop.is_set():
            db._run_db_write_sync("bulk", bulk)

    loaders = [threading.Thread(target=loader, daemon=True) for _ in range(2)]
    for t in loaders:
        t.start()
    try:
        _wait_qsize(db, 1)
        t0 = time.perf_counter()
        first = db.insert_access_history(event_id="evt-saturated", **_HISTORY)
        waited = time.perf_counter() - t0
        again = db.insert_access_history(event_id="evt-saturated", **_HISTORY)
    finally:
        stop.set()
        for t in loaders:
            t.join(10)
    assert (first, again) == (1, 0), "the claim: 1 for the first worker, 0 for a duplicate"
    assert waited < 5.0, f"door claim waited {waited:.2f}s behind the bulk jobs"
    prof = db.get_last_db_write_profile("insert_access_history")
    assert prof["priority"] is True and prof["writer_thread"] == "DbWriter"


def test_concurrent_claims_of_one_event_have_exactly_one_winner(db):
    barrier = threading.Barrier(8)
    results: list[int] = []

    def claim():
        barrier.wait(5)
        results.append(db.insert_access_history(event_id="evt-race", **_HISTORY))

    ts = [threading.Thread(target=claim) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(10)
    assert sorted(results) == [0] * 7 + [1]


def test_a_converted_write_called_inside_a_write_job_runs_inline_in_its_transaction(db):
    """Before: the inner function opened its own connection on the DbWriter thread and
    waited 30 s for the lock its own job held, then raised "database is locked"."""
    def outer_fails(conn, _p):
        db.arm_mirror_reconcile(device_id=7)
        raise RuntimeError("roll back both")

    t0 = time.perf_counter()
    with pytest.raises(RuntimeError, match="roll back both"):
        db._run_db_write_sync("outer", outer_fails)
    assert time.perf_counter() - t0 < 5.0
    assert db.mirror_reconcile_is_armed(device_id=7) is False, "the inner write went with the outer rollback"

    def outer_ok(conn, _p):
        db.arm_mirror_reconcile(device_id=7)
        return "done"

    assert db._run_db_write_sync("outer", outer_ok) == "done"
    assert db.mirror_reconcile_is_armed(device_id=7) is True


def test_apply_fast_patch_bundle_is_atomic_check_and_insert(db, monkeypatch):
    """The duplicate check and the bundle row are one writer transaction now. On the base
    commit the SELECT ran before the deferred transaction's implicit BEGIN, so two threads
    applying the same bundle both passed the check and the second raised IntegrityError
    (fast_patch_bundles.bundle_id is the PRIMARY KEY)."""
    def slow_item(cur, item):
        time.sleep(0.2)        # widen the window between the check and the commit
        return False

    monkeypatch.setattr(db, "_apply_fast_patch_item", slow_item)
    bundle = {"bundleId": "same-bundle", "generatedAt": "2026-10-02T10:00:00",
              "items": [{"entityType": "X", "entityId": 1, "revision": "r1"}]}
    barrier = threading.Barrier(4)
    results: list = []
    errors: list = []

    def apply():
        barrier.wait(5)
        try:
            results.append(db.apply_fast_patch_bundle(dict(bundle)))
        except Exception as exc:          # noqa: BLE001 -- the assertion reports it
            errors.append(exc)

    ts = [threading.Thread(target=apply) for _ in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(15)
    assert errors == []
    assert sorted(r["applied"] for r in results) == [0, 0, 0, 1]
    assert sorted(str(r["ignored"]) for r in results) == ["None"] + ["duplicate_bundle"] * 3


# ---------------------------------------------------------------------------
# Every converted function: same return, on the DbWriter thread
# ---------------------------------------------------------------------------

CONVERTED = [
    "save_firmware_profile", "reset_firmware_template_combo", "clear_firmware_profile",
    "upsert_device_mirror_pin", "delete_device_mirror_pin", "clear_device_mirror",
    "mirror_reconcile_record_plan", "arm_mirror_reconcile", "disarm_mirror_reconcile",
    "upsert_delta_users", "delete_users_by_am_ids", "insert_fingerprint", "delete_fingerprint",
    "confirm_fingerprint_uploaded", "create_device_door_preset", "update_device_door_preset",
    "delete_device_door_preset", "set_device_open_door_switch", "save_auth_token",
    "save_refresh_session_data", "clear_auth_token", "_save_sync_cache", "apply_fast_patch_bundle",
    "save_optional_sync_state", "delete_passed_optional_events", "replace_optional_events",
    "replace_optional_products", "replace_optional_deals", "prune_sync_run_history",
    "prune_push_batch_history", "cleanup_stale_in_progress_sync_runs", "save_agent_rtlog_state",
    "insert_access_history", "insert_access_history_batch", "prune_access_history",
    "prune_offline_creation_queue", "mark_access_history_synced", "mark_access_history_sync_failure",
    "mark_access_history_unresolved", "expire_unresolved_access_history",
    "mark_access_history_sync_attempt", "save_device_attendance_state", "reset_stale_processing_locks",
    "insert_offline_creation", "update_offline_creation_payload", "set_offline_creation_try_to_create",
    "cancel_offline_creation", "archive_offline_creation", "claim_offline_creation_for_processing",
    "mark_offline_creation_success", "mark_offline_creation_failure", "insert_offline_subresource",
    "mark_offline_subresource_done", "mark_offline_subresource_failed",
    "cancel_offline_subresources_for", "insert_offline_mutation", "claim_offline_mutation_for_processing",
    "mark_offline_mutation_success", "mark_offline_mutation_failure", "mark_offline_mutation_conflict",
    "cancel_offline_mutation", "archive_offline_mutation", "set_offline_mutation_try",
    "reset_stale_offline_mutation_locks",
]


def _user(am_id: int) -> dict:
    return {"activeMembershipId": am_id, "userId": am_id + 100, "membershipId": 50,
            "fullName": "Alice", "phone": "0600000000", "validFrom": "2026-01-01",
            "validTo": "2026-12-31", "firstCardId": str(am_id), "fingerprints": []}


def test_every_converted_function_returns_as_before_on_the_db_writer(db, monkeypatch):
    seen: list[str] = []
    real = db._run_db_write_sync

    def spy(label, operation, **kw):
        if threading.current_thread().name != "DbWriter":
            seen.append(label)
        return real(label, operation, **kw)

    monkeypatch.setattr(db, "_run_db_write_sync", spy)

    def on_writer(name: str, call):
        with db._db_write_profiles_lock:
            db._db_write_profiles.pop(name, None)
        result = call()
        prof = db.get_last_db_write_profile(name)
        assert prof is not None and prof["writer_thread"] == "DbWriter", name
        return result

    W = on_writer
    # firmware profile
    assert W("save_firmware_profile", lambda: db.save_firmware_profile(device_id=1, template_table="templatev10")) is None
    assert db.load_firmware_profile(device_id=1)["template_table"] == "templatev10"
    assert W("reset_firmware_template_combo",
             lambda: db.reset_firmware_template_combo(device_id=1, template_version_bias=10)) is None
    assert db.load_firmware_profile(device_id=1)["template_table"] is None
    assert W("clear_firmware_profile", lambda: db.clear_firmware_profile(device_id=1)) is None
    assert db.load_firmware_profile(device_id=1) is None
    # content mirror + MIRROR ack
    mirror = dict(device_id=1, pin="5", full_name="A", card_no="1", door_bitmask=1, authorize_tz_id=1)
    assert W("upsert_device_mirror_pin", lambda: db.upsert_device_mirror_pin(**mirror)) is None
    assert len(db.list_device_mirror(device_id=1)) == 1
    assert W("delete_device_mirror_pin", lambda: db.delete_device_mirror_pin(device_id=1, pin="5")) is None
    assert db.list_device_mirror(device_id=1) == []
    db.upsert_device_mirror_pin(**mirror)
    assert W("clear_device_mirror", lambda: db.clear_device_mirror(device_id=1)) is None
    assert db.list_device_mirror(device_id=1) == []
    assert W("mirror_reconcile_record_plan",
             lambda: db.mirror_reconcile_record_plan(device_id=1, count=2, sample="1,2")) is None
    assert W("arm_mirror_reconcile", lambda: db.arm_mirror_reconcile(device_id=1)) is None
    assert db.mirror_reconcile_is_armed(device_id=1) is True
    assert W("disarm_mirror_reconcile", lambda: db.disarm_mirror_reconcile(device_id=1)) is None
    assert db.mirror_reconcile_is_armed(device_id=1) is False
    # delta users
    assert W("upsert_delta_users", lambda: db.upsert_delta_users([_user(10)])) is None
    assert 10 in db.get_all_cached_user_am_ids()
    assert W("delete_users_by_am_ids", lambda: db.delete_users_by_am_ids({10})) is None
    assert 10 not in db.get_all_cached_user_am_ids()
    # fingerprints
    fp = dict(label="x", pin="5", card_no="1", finger_id=0, template_version=10,
              template_encoding="base64", template_data="QUJD", template_size=3)
    fp_id = W("insert_fingerprint", lambda: db.insert_fingerprint(**fp))
    assert isinstance(fp_id, int) and fp_id > 0 and db.get_fingerprint(fp_id) is not None
    assert W("confirm_fingerprint_uploaded", lambda: db.confirm_fingerprint_uploaded(fp_id)) is None
    assert W("delete_fingerprint", lambda: db.delete_fingerprint(fp_id)) is None
    assert db.get_fingerprint(fp_id) is None
    # door presets (the count check and the insert are one job; its ValueError still raises)
    pid = W("create_device_door_preset", lambda: db.create_device_door_preset(
        device_id=1, door_number=1, pulse_seconds=3, door_name="A", max_per_device=1))
    assert isinstance(pid, int) and pid > 0
    with pytest.raises(ValueError, match="Max presets per device is 1"):
        db.create_device_door_preset(device_id=1, door_number=2, pulse_seconds=3, door_name="B", max_per_device=1)
    assert W("update_device_door_preset", lambda: db.update_device_door_preset(
        preset_id=pid, device_id=1, door_number=2, pulse_seconds=4, door_name="A2")) is None
    assert [p.door_name for p in db.list_device_door_presets(1)] == ["A2"]
    assert W("delete_device_door_preset", lambda: db.delete_device_door_preset(pid)) is None
    assert db.list_device_door_presets(1) == []
    assert W("set_device_open_door_switch", lambda: db.set_device_open_door_switch(1, True)) is None
    assert db.get_device_open_door_switch(1) is True
    # auth
    assert W("save_auth_token", lambda: db.save_auth_token(email="a@b.c", token="tok")) is None
    assert db.load_auth_token() is not None
    assert W("save_refresh_session_data", lambda: db.save_refresh_session_data(
        refresh_token="r", next_refresh_at="2026-10-03T00:00:00")) is None
    assert W("clear_auth_token", lambda: db.clear_auth_token()) is None
    # sync cache: the logout clear and a full replace
    assert W("_save_sync_cache", lambda: db.save_sync_cache(None)) is None
    assert W("_save_sync_cache", lambda: db.save_sync_cache({"users": [_user(11)], "devices": []})) is None
    assert 11 in db.get_all_cached_user_am_ids()
    # fast patch
    assert W("apply_fast_patch_bundle", lambda: db.apply_fast_patch_bundle({"bundleId": "b1", "items": []})) == {
        "applied": 0, "skipped": 0, "ignored": None, "appliedItemIndexes": []}
    assert db.apply_fast_patch_bundle({"bundleId": "b1", "items": []})["ignored"] == "duplicate_bundle"
    # optional content
    assert W("save_optional_sync_state", lambda: db.save_optional_sync_state(
        events_version_at=None, products_version_at=None, deals_version_at=None,
        last_sync_at="2026-10-02T10:00:00", refresh_events=True, refresh_products=True,
        refresh_deals=True)) is None
    assert W("delete_passed_optional_events", lambda: db.delete_passed_optional_events()) == 0
    assert W("replace_optional_events", lambda: db.replace_optional_events([])) is None
    assert W("replace_optional_products", lambda: db.replace_optional_products([])) is None
    assert W("replace_optional_deals", lambda: db.replace_optional_deals([])) is None
    # sync-run housekeeping
    assert W("prune_sync_run_history", lambda: db.prune_sync_run_history()) == 0
    assert W("prune_push_batch_history", lambda: db.prune_push_batch_history()) == 0
    assert W("cleanup_stale_in_progress_sync_runs", lambda: db.cleanup_stale_in_progress_sync_runs()) == 0
    # realtime: both in the door lane
    assert W("save_agent_rtlog_state", lambda: db.save_agent_rtlog_state(
        device_id=1, last_event_at="2026-10-02 10:00:00", last_event_id="e1")) is None
    assert db.get_last_db_write_profile("save_agent_rtlog_state")["priority"] is True
    assert db.load_agent_rtlog_state(1).last_event_id == "e1"
    assert W("insert_access_history", lambda: db.insert_access_history(event_id="h1", **_HISTORY)) == 1
    assert db.insert_access_history(event_id="h1", **_HISTORY) == 0
    assert db.insert_access_history(event_id="  ", **_HISTORY) == 0          # no job at all
    assert W("insert_access_history_batch", lambda: db.insert_access_history_batch(
        rows=[{"event_id": "h2", "allowed": True}, {"event_id": "h1", "allowed": True}])) == 1
    ids = [r.id for r in db.get_recent_access_history(limit=10)]
    assert len(ids) == 2
    assert W("mark_access_history_sync_attempt", lambda: db.mark_access_history_sync_attempt(row_ids=ids)) == 2
    assert W("mark_access_history_sync_failure", lambda: db.mark_access_history_sync_failure(
        row_ids=ids[:1], error="x")) == 1
    assert W("mark_access_history_unresolved", lambda: db.mark_access_history_unresolved(
        row_ids=ids[1:], error="x", base_retry_seconds=60, max_retry_seconds=600)) == 1
    assert W("mark_access_history_synced", lambda: db.mark_access_history_synced(row_ids=ids[:1])) == 1
    assert W("expire_unresolved_access_history", lambda: db.expire_unresolved_access_history(
        retention_days=30, min_unresolved_verdicts=3)) == 0
    assert W("prune_access_history", lambda: db.prune_access_history(retention_days=30)) == 0
    assert W("save_device_attendance_state", lambda: db.save_device_attendance_state(
        device_id=1, last_read_event_count=3)) is None
    assert db.load_device_attendance_state(1) is not None
    # offline creation queue
    assert W("reset_stale_processing_locks", lambda: db.reset_stale_processing_locks()) == 0
    assert W("prune_offline_creation_queue", lambda: db.prune_offline_creation_queue()) == 0
    row = W("insert_offline_creation", lambda: db.insert_offline_creation(
        creation_kind="membership", payload={"a": 1}, client_request_id="req-1"))
    lid = row["local_id"]
    again = db.insert_offline_creation(creation_kind="membership", payload={"a": 1}, client_request_id="req-1")
    assert again["local_id"] == lid, "same client_request_id -> the existing row"
    assert W("update_offline_creation_payload", lambda: db.update_offline_creation_payload(
        lid, payload={"b": 2}))["payload"] == {"b": 2}
    assert W("set_offline_creation_try_to_create",
             lambda: db.set_offline_creation_try_to_create(lid, True))["try_to_create"] is True
    claimed = W("claim_offline_creation_for_processing", lambda: db.claim_offline_creation_for_processing(lid))
    assert claimed["state"] == "processing" and claimed["processing_lock_token"]
    assert db.claim_offline_creation_for_processing(lid) is None, "locked: a second claim gets nothing"
    failed = W("mark_offline_creation_failure", lambda: db.mark_offline_creation_failure(
        lid, failure_type="validation", failure_code=None, http_status=400, message="boom"))
    assert failed["state"] == "failed_retryable" and failed["failure_count"] == 1
    assert W("mark_offline_creation_success", lambda: db.mark_offline_creation_success(
        lid, reconciled=False))["state"] == "succeeded"
    lid2 = db.insert_offline_creation(creation_kind="membership", payload={})["local_id"]
    assert W("cancel_offline_creation", lambda: db.cancel_offline_creation(lid2))["state"] == "cancelled"
    assert W("archive_offline_creation", lambda: db.archive_offline_creation(lid2))["state"] == "archived"
    # sub-resources
    sub = W("insert_offline_subresource", lambda: db.insert_offline_subresource(
        creation_local_id=lid, kind="photo", payload={}))
    assert sub["state"] == "pending"
    assert W("mark_offline_subresource_failed", lambda: db.mark_offline_subresource_failed(
        sub["id"], message="x"))["attempt_count"] == 1
    assert W("mark_offline_subresource_done", lambda: db.mark_offline_subresource_done(
        sub["id"]))["state"] == "done"
    db.insert_offline_subresource(creation_local_id=lid, kind="photo", payload={})
    assert W("cancel_offline_subresources_for", lambda: db.cancel_offline_subresources_for(lid)) == 1
    # mutation queue
    assert W("reset_stale_offline_mutation_locks", lambda: db.reset_stale_offline_mutation_locks()) == 0
    mut = dict(op_kind="edit", target_kind="active_membership", target_id=5, payload={})
    m = W("insert_offline_mutation", lambda: db.insert_offline_mutation(client_request_id="m-1", **mut))
    mid = m["local_id"]
    assert db.insert_offline_mutation(client_request_id="m-1", **mut)["local_id"] == mid
    assert W("claim_offline_mutation_for_processing",
             lambda: db.claim_offline_mutation_for_processing(mid))["processing_lock_token"]
    assert db.claim_offline_mutation_for_processing(mid) is None
    assert W("mark_offline_mutation_failure", lambda: db.mark_offline_mutation_failure(
        mid, failure_type="validation", failure_code=None, http_status=400, message="x"))["failure_count"] == 1
    done = W("mark_offline_mutation_success", lambda: db.mark_offline_mutation_success(
        mid, reconciled=False, result={"version": 3}))
    assert done["state"] == "succeeded" and done["server_new_version"] == 3
    mid2 = db.insert_offline_mutation(**mut)["local_id"]
    assert W("set_offline_mutation_try", lambda: db.set_offline_mutation_try(mid2, enabled=False))["try_to_apply"] in (0, False)
    assert W("mark_offline_mutation_conflict", lambda: db.mark_offline_mutation_conflict(
        mid2, message="stale"))["state"] == "conflict"
    assert W("cancel_offline_mutation", lambda: db.cancel_offline_mutation(mid2))["state"] == "cancelled"
    assert W("archive_offline_mutation", lambda: db.archive_offline_mutation(mid2))["state"] == "archived"

    assert set(CONVERTED) <= set(seen), sorted(set(CONVERTED) - set(seen))

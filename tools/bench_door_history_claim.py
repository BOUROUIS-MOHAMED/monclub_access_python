"""Benchmark: how long the AGENT door-path history claim waits while the DB writer is busy.

``realtime_agent.py::DecisionService`` calls ``db.insert_access_history`` BEFORE it opens the
door and uses the result as the claim (1 = this worker owns the event, 0 = a duplicate). Any
time that call spends waiting is added to the door. This times it while K background threads
keep the DB writer busy: each loops ``_run_db_write_sync`` jobs that hold the write transaction
for D ms (an INSERT, then a sleep inside the transaction -- a stand-in for a long sync write).
``_run_db_write_sync`` is synchronous, so each loader has at most one job queued: the writer's
queue depth is K.

Modes (``--mode``):

* ``as-is``   -- whatever the code under test does (before the single-writer change: a direct
  write on the caller's own connection, contending for SQLite's write lock with busy_timeout;
  after it: a job in the writer's priority lane).
* ``no-lane`` -- after the change only: the same job forced into the normal FIFO lane, to show
  what the lane buys. (``_run_db_write_sync`` is wrapped so ``priority=False``.)

A claim that raises is counted as ``failed`` (DecisionService would deny the door) and timed.
Every claim that answers must return 1 (fresh event id) and a repeat of the same id must return 0; the bench
fails loudly otherwise.

Usage (from the repo root)::

    python tools/bench_door_history_claim.py                       # no load, then K=2,4 x D=50,400 ms
    python tools/bench_door_history_claim.py --mode no-lane --claims 30
    python tools/bench_door_history_claim.py --idle-ms 0 100 --claims 5

It never touches the installed database: ``MONCLUB_ACCESS_DATA_ROOT`` points at an empty temp
folder before ``app`` is imported, the database is a temp file, and the folder is removed at
the end. A measurement on this machine, not a pass/fail test.
"""
from __future__ import annotations

import argparse
import os
import shutil
import statistics
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _pct(values: list[float], p: float) -> float:
    s = sorted(values)
    if not s:
        return 0.0
    k = min(len(s) - 1, max(0, int(round(p / 100.0 * (len(s) - 1)))))
    return s[k]


def _run_case(db, *, loaders: int, hold_ms: float, claims: int, gap_ms: float, idle_ms: float) -> dict:
    stop = threading.Event()
    bulk_jobs = [0]

    def _bulk(conn, _profile):
        conn.execute("INSERT INTO bench_bulk (x) VALUES (?)", (time.perf_counter(),))
        time.sleep(hold_ms / 1000.0)

    def _loader():
        while not stop.is_set():
            db._run_db_write_sync("bench_bulk", _bulk)
            bulk_jobs[0] += 1
            if idle_ms > 0:
                time.sleep(idle_ms / 1000.0)

    threads = [threading.Thread(target=_loader, daemon=True) for _ in range(loaders)]
    for t in threads:
        t.start()
    time.sleep(max(0.2, 2 * hold_ms / 1000.0))  # let the writer queue fill

    lat: list[float] = []
    failed: list[str] = []
    try:
        for _ in range(claims):
            eid = "bench-" + uuid.uuid4().hex
            kwargs = dict(
                event_id=eid, device_id=1, door_id=1, card_no="123", event_time="2026-10-02 10:00:00",
                event_type="RTLOG", allowed=True, reason="ALLOW", poll_ms=1.0, decision_ms=1.0,
                cmd_ms=0.0, cmd_ok=None, cmd_error=None, raw={},
            )
            t0 = time.perf_counter()
            try:
                got = db.insert_access_history(**kwargs)
            except Exception as exc:  # the door would be denied: DecisionService catches and denies
                lat.append((time.perf_counter() - t0) * 1000.0)
                failed.append(type(exc).__name__)
                continue
            lat.append((time.perf_counter() - t0) * 1000.0)
            if got != 1:
                raise SystemExit(f"claim of a fresh event returned {got!r}, expected 1")
            try:
                again = db.insert_access_history(**kwargs)
            except Exception as exc:
                failed.append("repeat:" + type(exc).__name__)
                continue
            if again != 0:
                raise SystemExit(f"repeat claim returned {again!r}, expected 0")
            time.sleep(gap_ms / 1000.0)
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=30)
    return {
        "loaders": loaders, "hold_ms": hold_ms, "claims": len(lat),
        "p50": statistics.median(lat), "p95": _pct(lat, 95), "max": max(lat),
        "bulk_jobs": bulk_jobs[0], "failed": failed,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=("as-is", "no-lane"), default="as-is")
    ap.add_argument("--loaders", type=int, nargs="*", default=[0, 2, 4])
    ap.add_argument("--hold-ms", type=float, nargs="*", default=[50.0, 400.0])
    ap.add_argument("--claims", type=int, default=20)
    ap.add_argument("--gap-ms", type=float, default=120.0, help="pause between two claims")
    ap.add_argument("--idle-ms", type=float, nargs="*", default=[0.0],
                    help="pause of each loader between its jobs (0 = back to back)")
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="bench_door_claim_"))
    os.environ["MONCLUB_ACCESS_DATA_ROOT"] = str(tmp / "data_root")
    sys.path.insert(0, str(REPO))
    try:
        import app.core.db as db

        db._DB_PATH = str(tmp / "bench.db")
        db.init_db()
        db._run_db_write_sync(
            "bench_setup", lambda conn, _p: conn.execute("CREATE TABLE IF NOT EXISTS bench_bulk (x REAL)"))

        if args.mode == "no-lane":
            orig = db._run_db_write_sync

            def _fifo(label, operation, **kw):
                kw["priority"] = False
                return orig(label, operation, **kw)

            db._run_db_write_sync = _fifo  # bench-only: force the normal lane

        print(f"python {sys.version.split()[0]} ({8 * __import__('struct').calcsize('P')}-bit), "
              f"mode={args.mode}, claims/case={args.claims}")
        print("loaders  hold_ms  idle_ms   p50_ms   p95_ms   max_ms  bulk_jobs  failed")
        for k in args.loaders:
            for d in (args.hold_ms if k else args.hold_ms[:1]):
                for idle in (args.idle_ms if k else args.idle_ms[:1]):
                    r = _run_case(db, loaders=k, hold_ms=d, claims=args.claims, gap_ms=args.gap_ms,
                                  idle_ms=idle)
                    fails = (f"{len(r['failed'])}/{r['claims']} {sorted(set(r['failed']))}"
                             if r["failed"] else f"0/{r['claims']}")
                    print(f"{r['loaders']:>7}  {r['hold_ms']:>7.0f}  {idle:>7.0f}  {r['p50']:>7.1f}  "
                          f"{r['p95']:>7.1f}  {r['max']:>7.1f}  {r['bulk_jobs']:>9}  {fails}", flush=True)
        db._shutdown_db_writer_for_tests()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

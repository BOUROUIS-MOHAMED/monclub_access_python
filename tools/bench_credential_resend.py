"""Benchmark: the one full credentials re-send after the upgrade (guide §3.1b, "The upgrade window").

``db.py::_force_one_credentials_resend`` drops ``credentialsVersion`` once, so the next
``getSyncData`` carries every credential. This times that sync's cache write end to end --
``save_sync_cache_delta`` with only ``credentials`` refreshed, through the DB writer thread,
commit included -- against the write the same sync would have done without the drop (every
section skipped, ``gymAccessCredentials: []``). The paired median of (with - without) per run is
the one-time cost on this machine.

Stale share: the fraction of credential rows whose stored grant set differs from the backend's
(renewed members the previous build never rewrote). 0 % is the floor (full scan + diff, nothing
written), 100 % the ceiling (every row rewritten). The real share at a gym is not measured.
Each run first restores the stale rows (untimed), so every timed write finds the same work.

Usage (from the repo root)::

    python tools/bench_credential_resend.py                  # n=1500 and 3000, 21 runs
    python tools/bench_credential_resend.py --n 3000 --runs 51

It never touches the installed database: ``MONCLUB_ACCESS_DATA_ROOT`` points at an empty temp
folder before ``app`` is imported, the database is a temp file, and the folder is removed at
the end. A measurement, not a pass/fail test.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import statistics
import struct
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_NOTHING = {"members": False, "devices": False, "credentials": False, "settings": False}
_CREDS_ONLY = {"members": False, "devices": False, "credentials": True, "settings": False}


def _cred(i: int, grants: list[int]) -> dict:
    # The backend DTO's fields (GymAccessCredentialDto); the secret is 20 random bytes as hex
    # (GymAccessController.randomSecretHex(20)).
    return {
        "id": i + 1, "gymId": 58, "accountId": 5000 + i,
        "secretHex": f"{i:040x}", "enabled": True, "rotatedAt": None,
        "createdAt": "2026-04-01T10:22:33.123456", "updatedAt": "2026-04-01T10:22:33.123456",
        "grantedActiveMembershipIds": grants, "totpValidation": False,
    }


def _payloads(n: int, stale_share: float) -> tuple[list[dict], list[dict], int]:
    """(what the previous build left, what the backend re-sends, rows that differ)."""
    every = max(1, round(1 / stale_share)) if stale_share > 0 else 0
    old, new, stale = [], [], 0
    for i in range(n):
        current = [100000 + i * 10]
        is_stale = bool(every) and i % every == 0
        stale += is_stale
        old.append(_cred(i, [current[0] - 1] if is_stale else current))
        new.append(_cred(i, current))
    return old, new, stale


def _sync(db, creds: list[dict], refresh: dict) -> dict:
    return db.save_sync_cache_delta(
        {"gymAccessCredentials": creds, "contractStatus": True, "contractEndDate": "2026-12-31"},
        refresh,
    ) or {}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--n", type=int, nargs="+", default=[1500, 3000], help="credentials")
    ap.add_argument("--runs", type=int, default=21, help="timed runs per scenario")
    args = ap.parse_args(argv)

    tmp = Path(tempfile.mkdtemp(prefix="bench_credential_resend_"))
    db = None
    try:
        root = tmp / "data-root"
        root.mkdir()
        os.environ["MONCLUB_ACCESS_DATA_ROOT"] = str(root)
        sys.path.insert(0, str(REPO))
        import logging

        logging.disable(logging.WARNING)       # the per-write [SYNC-DEBUG] lines
        import app.core.db as db

        print(f"python {sys.version.split()[0]} ({8 * struct.calcsize('P')}-bit), "
              f"sqlite {sqlite3.sqlite_version}, runs={args.runs}")
        for n in args.n:
            for share in (0.0, 0.05, 1.0):
                db._DB_PATH = str(tmp / f"bench_{n}_{int(share * 100)}.db")
                db._close_thread_local_conn()
                db.init_db()
                old, new, stale = _payloads(n, share)
                wire = len(json.dumps(new, separators=(",", ":")).encode("utf-8"))
                _sync(db, old, _CREDS_ONLY)
                with_ms, without_ms, upserted = [], [], set()
                for _ in range(args.runs + 1):             # the first pair is a warm-up
                    _sync(db, old, _CREDS_ONLY)            # restore the stale rows (untimed)
                    t0 = time.perf_counter()
                    _sync(db, [], _NOTHING)
                    t1 = time.perf_counter()
                    summary = _sync(db, new, _CREDS_ONLY).get("credentials") or {}
                    t2 = time.perf_counter()
                    without_ms.append((t1 - t0) * 1000.0)
                    with_ms.append((t2 - t1) * 1000.0)
                    upserted.add(summary.get("upserted"))
                with_ms, without_ms = with_ms[1:], without_ms[1:]
                paired = statistics.median(w - wo for w, wo in zip(with_ms, without_ms))
                print(f"n={n:5d} stale={share:4.0%} ({stale:4d} rows, upserted={sorted(upserted)}) "
                      f"credentials JSON {wire / 1024:6.1f} KiB | write with re-send "
                      f"median {statistics.median(with_ms):7.2f} ms (max {max(with_ms):7.2f}) | "
                      f"without {statistics.median(without_ms):5.2f} ms | one-time cost "
                      f"(paired median) {paired:+7.2f} ms")
                db._close_thread_local_conn()
                if hasattr(db, "_shutdown_db_writer_for_tests"):
                    db._shutdown_db_writer_for_tests()
    finally:
        if db is not None:
            db._close_thread_local_conn()
            if hasattr(db, "_shutdown_db_writer_for_tests"):
                db._shutdown_db_writer_for_tests()
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

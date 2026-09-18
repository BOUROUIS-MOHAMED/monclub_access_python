"""Benchmark: the credential diff before and after it compared grants (guide §3.1b).

Runs ``db.py::_sync_gym_access_credentials_rows`` from a BASE commit (``git show``) and
from this working tree, interleaved on the same seeded SQLite file, and prints medians
plus the paired median of (after - before) per run -- the paired figure cancels most of
the machine noise that moves whole runs.

Usage (from the repo root)::

    python tools/bench_credential_diff.py                       # base d09f88f, 2000 creds
    python tools/bench_credential_diff.py --base <ref> --n 2000 --runs 101

``d09f88f`` is the last commit before the grant comparison. Scenarios, each for
1-3 grants per credential (an assumed mix, not measured on a gym) and for 20:
identical resync, a grant-only change on 5 % of rows, every grant list reordered.

It never touches the installed database: ``MONCLUB_ACCESS_DATA_ROOT`` points at an empty
temp folder before ``app`` is imported, the database is a temp file, and the folder is
removed at the end. A measurement, not a pass/fail test.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import random
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _load_modules(base: str, tmp: Path):
    root = tmp / "data-root"
    root.mkdir()
    os.environ["MONCLUB_ACCESS_DATA_ROOT"] = str(root)
    sys.path.insert(0, str(REPO))

    import app.core.db as after_mod

    before_src = subprocess.run(
        ["git", "show", f"{base}:app/core/db.py"],
        cwd=REPO, check=True, capture_output=True,
    ).stdout
    before_path = tmp / "db_before.py"
    before_path.write_bytes(before_src)
    spec = importlib.util.spec_from_file_location("app.core._db_bench_before", before_path)
    before_mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = before_mod  # dataclasses look the module up
    spec.loader.exec_module(before_mod)
    return before_mod, after_mod


def _payload(n: int, heavy: bool, rng: random.Random) -> list[dict]:
    out = []
    for i in range(n):
        if heavy:
            k = 20
        else:
            r = rng.random()
            k = 1 if r < 0.85 else (2 if r < 0.97 else 3)
        base = 100000 + i * 10
        out.append({
            "id": i + 1, "gymId": 58, "accountId": 5000 + i,
            "secretHex": f"{i:040x}", "enabled": True,
            "rotatedAt": None, "createdAt": "2026-04-01T00:00:00", "updatedAt": "2026-04-01T00:00:00",
            "grantedActiveMembershipIds": [base + j for j in range(k)],
        })
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", default="d09f88f", help="commit whose db.py is BEFORE")
    ap.add_argument("--n", type=int, default=2000, help="credentials")
    ap.add_argument("--runs", type=int, default=101, help="timed runs per scenario")
    args = ap.parse_args(argv)

    tmp = Path(tempfile.mkdtemp(prefix="bench_credential_diff_"))
    conn = None
    try:
        before_mod, after_mod = _load_modules(args.base, tmp)
        db_file = str(tmp / "bench.db")
        after_mod._DB_PATH = db_file
        after_mod.init_db()
        if hasattr(after_mod, "_shutdown_db_writer_for_tests"):
            after_mod._shutdown_db_writer_for_tests()

        conn = sqlite3.connect(db_file, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")

        def seed(payload):
            conn.execute("BEGIN")
            after_mod._replace_sync_credentials(
                conn.cursor(), [after_mod._normalize_sync_credential_payload_row(c) for c in payload]
            )
            conn.execute("COMMIT")

        def timed(mod, payload):
            conn.execute("BEGIN")
            t0 = time.perf_counter()
            summary = mod._sync_gym_access_credentials_rows(conn.cursor(), payload)
            total = (time.perf_counter() - t0) * 1000.0
            conn.execute("ROLLBACK")
            return total, float(summary.get("existing_fetch_ms") or 0.0) + float(summary.get("diff_ms") or 0.0), summary

        def scenario(name, seeded, incoming):
            seed(seeded)
            sides = (("before", before_mod), ("after", after_mod))
            for _label, mod in sides:
                timed(mod, incoming)  # warm-up
            total = {"before": [], "after": []}
            fd = {"before": [], "after": []}
            upserted = {}
            for _ in range(args.runs):
                for label, mod in sides:
                    t, f, s = timed(mod, incoming)
                    total[label].append(t)
                    fd[label].append(f)
                    upserted[label] = s.get("upserted")
            print(f"\n[{name}]")
            print(f"  {'':7} {'total_ms':>9} {'fetch+diff_ms':>14} {'upserted':>9}")
            for label in ("before", "after"):
                print(f"  {label:7} {statistics.median(total[label]):9.2f} "
                      f"{statistics.median(fd[label]):14.2f} {upserted[label]!s:>9}")
            d_t = statistics.median(a - b for a, b in zip(total["after"], total["before"]))
            d_fd = statistics.median(a - b for a, b in zip(fd["after"], fd["before"]))
            print(f"  paired median (after - before): total {d_t:+.2f} ms, fetch+diff {d_fd:+.2f} ms")

        print(f"python {sys.version.split()[0]} ({8 * __import__('struct').calcsize('P')}-bit), "
              f"sqlite {sqlite3.sqlite_version}, base {args.base}, n={args.n}, runs={args.runs}")
        plan = conn.execute(
            "EXPLAIN QUERY PLAN SELECT id, gym_id, account_id, secret_hex, enabled, rotated_at, "
            "created_at, updated_at, granted_active_membership_ids_json FROM sync_gym_access_credentials"
        ).fetchall()
        print(f"  diff scan plan: {[tuple(r)[-1] for r in plan]}")

        rng = random.Random(1234)
        for heavy in (False, True):
            tag = "20 grants/cred" if heavy else "1-3 grants/cred"
            base = _payload(args.n, heavy, rng)
            avg = statistics.mean(len(json.dumps(c["grantedActiveMembershipIds"])) for c in base)
            print(f"\n=== {tag}: grants JSON {avg:.1f} bytes on average ===")
            scenario(f"{tag} / identical resync", base, base)
            changed = [dict(c) for c in base]
            for c in changed[::20]:
                c["grantedActiveMembershipIds"] = [c["grantedActiveMembershipIds"][0] + 7]
            scenario(f"{tag} / grant-only change on 5%", base, changed)
            reordered = [dict(c, grantedActiveMembershipIds=c["grantedActiveMembershipIds"][::-1]) for c in base]
            scenario(f"{tag} / every list reordered", base, reordered)
    finally:
        if conn is not None:
            conn.close()
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

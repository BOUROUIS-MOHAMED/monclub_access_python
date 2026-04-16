from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path


def _spawn_guard_probe(lock_dir: Path, mode: str) -> subprocess.Popen[str]:
    repo_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root) + os.pathsep + env.get("PYTHONPATH", "")
    script = textwrap.dedent(
        """
        import pathlib
        import sys

        from shared.single_instance import (
            SingleInstanceAlreadyRunning,
            acquire_single_instance_guard,
        )

        lock_root = pathlib.Path(sys.argv[1])
        mode = sys.argv[2]

        try:
            guard = acquire_single_instance_guard(
                component_id="access",
                lock_dir=lock_root,
            )
        except SingleInstanceAlreadyRunning:
            print("ALREADY_RUNNING", flush=True)
            raise SystemExit(23)

        print("ACQUIRED", flush=True)
        if mode == "hold":
            sys.stdin.readline()
        guard.release()
        """
    )
    return subprocess.Popen(
        [sys.executable, "-c", script, str(lock_dir), mode],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )


def test_access_single_instance_guard_blocks_second_process(tmp_path: Path) -> None:
    holder = _spawn_guard_probe(tmp_path, "hold")
    try:
        assert holder.stdout is not None
        first_line = holder.stdout.readline().strip()
        if first_line != "ACQUIRED":
            holder_out, holder_err = holder.communicate(timeout=10)
            raise AssertionError(
                "holder process failed to acquire guard: "
                f"stdout={first_line!r}{holder_out!r} stderr={holder_err!r}"
            )

        challenger = _spawn_guard_probe(tmp_path, "once")
        out, err = challenger.communicate(timeout=10)

        assert challenger.returncode == 23
        assert "ALREADY_RUNNING" in out
        assert err == ""
    finally:
        if holder.poll() is None:
            assert holder.stdin is not None
            holder.stdin.write("\n")
            holder.stdin.flush()
            holder_out, holder_err = holder.communicate(timeout=10)
            assert holder.returncode == 0
            assert holder_err == ""
            assert holder_out == ""
        else:
            holder.communicate(timeout=10)

    probe = _spawn_guard_probe(tmp_path, "once")
    out, err = probe.communicate(timeout=10)

    assert probe.returncode == 0
    assert out.strip() == "ACQUIRED"
    assert err == ""

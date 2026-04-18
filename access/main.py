from __future__ import annotations

import os
import sys
import tempfile
import faulthandler
from pathlib import Path


def _ensure_console_streams() -> None:
    if sys.stderr is None or sys.stdout is None:
        log_path = os.path.join(tempfile.gettempdir(), "MonClubAccess.log")
        log_file = open(log_path, "a", buffering=1, encoding="utf-8")
        if sys.stderr is None:
            sys.stderr = log_file
        if sys.stdout is None:
            sys.stdout = log_file


def main() -> None:
    _ensure_console_streams()
    faulthandler.enable(all_threads=True)
    try:
        from shared.dev_dependency_sync import ensure_local_requirements_synced

        ensure_local_requirements_synced(
            repo_root=Path(__file__).resolve().parents[1],
            python_executable=Path(sys.executable),
        )
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(1) from e
    from access.bootstrap import run_access_app

    run_access_app()


if __name__ == "__main__":
    main()

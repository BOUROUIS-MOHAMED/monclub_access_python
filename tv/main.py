from __future__ import annotations

import os
import sys
import tempfile
import faulthandler


def _ensure_console_streams() -> None:
    if sys.stderr is None or sys.stdout is None:
        log_path = os.path.join(tempfile.gettempdir(), "MonClubTV.log")
        log_file = open(log_path, "a", buffering=1, encoding="utf-8")
        if sys.stderr is None:
            sys.stderr = log_file
        if sys.stdout is None:
            sys.stdout = log_file


def main() -> None:
    _ensure_console_streams()
    faulthandler.enable(all_threads=True)
    # Updater v2: restore an install interrupted mid-copy before anything loads (design 8.0).
    try:
        from shared.update_startup import check_install_journal

        if check_install_journal(exe_name="MonClubTV.exe"):
            raise SystemExit(0)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"Install journal check failed: {exc}", file=sys.stderr)
    from tv.bootstrap import run_tv_app

    run_tv_app()


if __name__ == "__main__":
    main()

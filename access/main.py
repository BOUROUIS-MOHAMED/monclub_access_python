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

    from shared.single_instance import (
        SingleInstanceAlreadyRunning,
        acquire_single_instance_guard,
    )

    try:
        guard = acquire_single_instance_guard(component_id="access")
    except SingleInstanceAlreadyRunning:
        print("MonClub Access is already running — exiting this instance.", file=sys.stderr)
        raise SystemExit(0)

    # Updater v2: Setup killed mid-copy (power cut) leaves install_journal.json. Restore
    # previous\ before anything loads from a half-copied current\ (design 8.0); the helper
    # restarts the app once this process has exited.
    try:
        from shared.update_startup import check_install_journal

        if check_install_journal(exe_name="MonClubAccess.exe"):
            guard.release()
            raise SystemExit(0)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"Install journal check failed: {exc}", file=sys.stderr)

    # Before anything writes under the data root (crash capture, logging, init_db): an elevated
    # launch repairs a ProgramData root an earlier elevated launch left read-only for normal
    # launches; a launch that still cannot write gets a dialog saying what to do, not a traceback.
    from shared.data_root_permissions import (
        check_data_root_at_startup,
        is_readonly_database_error,
        report_unwritable,
    )
    from app.core.utils import ACCESS_CONFIG_PATH, DATA_ROOT
    from access.storage import current_access_runtime_db_path

    db_path = current_access_runtime_db_path()
    if not check_data_root_at_startup(
        app_name="MonClub Access",
        data_root=DATA_ROOT,
        db_path=db_path,
        extra_files=(ACCESS_CONFIG_PATH,),
        before_dialog=guard.release,
    ):
        raise SystemExit(2)

    # Only the instance that holds the guard: a second start must not wipe the running
    # instance's crash evidence. Moves faulthandler from stderr to its own file.
    from app.core import crash_capture

    crash_capture.install()

    from access.bootstrap import run_access_app

    try:
        run_access_app()
    except BaseException as exc:
        crash_capture.record_fatal(exc)  # kept for the next start, even through atexit
        if is_readonly_database_error(exc):
            # The startup probe passed but SQLite still could not write: same dialog, no traceback.
            report_unwritable("MonClub Access", DATA_ROOT, [db_path], before_dialog=guard.release)
            raise SystemExit(2) from None
        raise
    finally:
        try:
            guard.release()
        except Exception:
            pass


if __name__ == "__main__":
    main()

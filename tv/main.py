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
    # TV's tv\ lives in the data root SHARED with Access: same read-only trap, same repair.
    from shared.data_root_permissions import (
        check_data_root_at_startup,
        is_readonly_database_error,
        report_unwritable,
    )
    from app.core.utils import DATA_ROOT, TV_CONFIG_PATH
    from tv.storage import current_tv_runtime_db_path

    db_path = current_tv_runtime_db_path()
    if not check_data_root_at_startup(
        app_name="MonClub TV",
        data_root=DATA_ROOT,
        db_path=db_path,
        extra_files=(TV_CONFIG_PATH,),
    ):
        raise SystemExit(2)

    from tv.bootstrap import run_tv_app

    try:
        run_tv_app()
    except BaseException as exc:
        if is_readonly_database_error(exc):
            report_unwritable("MonClub TV", DATA_ROOT, [db_path])
            raise SystemExit(2) from None
        raise


if __name__ == "__main__":
    main()

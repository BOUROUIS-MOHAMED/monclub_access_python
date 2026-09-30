"""Evidence for a process that ends without "App shutting down".

Field, 2026-09-30 (gym PC "Accueil", 1.4.35): the app log stops at 07:50:31 in the middle of its
5-second dashboard cadence, and a new process starts at 07:50:48 on the same Windows boot (its
``monotonic_s`` continues). The app log alone cannot tell a native crash from a fatal Python
error, an interpreter exit that skipped ``quit_app`` or an external kill. faulthandler was already
enabled, but it wrote to stderr, which a windowed build points at ``%TEMP%\\MonClubAccess.log``
(``access/main.py::_ensure_console_streams``): a file nobody collects, never truncated.

``install`` (called once by ``access/main.py``, AFTER the single-instance guard -- a second
double-click must not wipe the running instance's files) adds, for this process:

* faulthandler writes to ``<access data>/crash/faulthandler.txt``, truncated at each start
  (after the previous run's content has been read);
* a run marker (pid, start time, boot estimate) that only a normal interpreter exit removes;
* unhandled exceptions of the main thread and of other threads are logged to the app log.

``report_previous`` (called by ``setup_logging`` once the app log exists) writes ONE line into the
app log -- which the log uploader ships -- when the previous run left its marker behind, with the
tail of that run's faulthandler output. On Windows faulthandler also prints first-chance
exceptions that were handled later, so a dump alone is not proof of a crash; the marker is.
"""
from __future__ import annotations

import atexit
import faulthandler
import json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional, Tuple

_LOGGER_NAME = "zkapp"
_DUMP_NAME = "faulthandler.txt"
_MARKER_NAME = "running.json"
_DUMP_TAIL_BYTES = 16 * 1024
# A boot is estimated as wall time minus monotonic time. NTP steps move the estimate by seconds;
# a restart of Windows moves it by at least the reboot time.
_SAME_BOOT_TOLERANCE_SEC = 300.0

_state: dict[str, Any] = {"dump_file": None, "marker": None, "pending": None}


def default_state_dir() -> Path:
    from app.core.utils import ACCESS_DATA_DIR

    return ACCESS_DATA_DIR / "crash"


def _boot_epoch(wall: float, mono: float) -> float:
    return float(wall) - float(mono)


def previous_run_report(state_dir: Path, *, wall: float, mono: float) -> Optional[Tuple[int, str]]:
    """``(log level, message)`` for a previous run that did not exit cleanly, else None.

    Reads only: the marker and the dump of the previous run are left as they are.
    """
    marker_path = Path(state_dir) / _MARKER_NAME
    if not marker_path.exists():
        return None
    try:
        prev = json.loads(marker_path.read_text(encoding="utf-8") or "{}")
    except Exception:
        prev = {}
    dump = ""
    size = 0
    try:
        dump_path = Path(state_dir) / _DUMP_NAME
        if dump_path.exists():
            data = dump_path.read_bytes()
            size = len(data)
            dump = data[-_DUMP_TAIL_BYTES:].decode("utf-8", errors="replace").strip()
    except Exception:
        dump = ""
    prev_boot = prev.get("boot_epoch")
    same_boot = (
        isinstance(prev_boot, (int, float))
        and abs(_boot_epoch(wall, mono) - float(prev_boot)) <= _SAME_BOOT_TOLERANCE_SEC
    )
    head = (
        f"[CRASH] previous run pid={prev.get('pid', '?')} "
        f"started={prev.get('started', '?')} ended WITHOUT a clean exit"
    )
    if same_boot:
        why = ("while Windows kept running: a native crash, a fatal Python error, or an external "
               "kill (Task Manager, taskkill, an installer)")
        level = logging.ERROR
    else:
        why = "and Windows has restarted since: a shutdown or power loss (or a crash before it)"
        level = logging.WARNING if dump else logging.INFO
    if dump:
        shown = min(size, _DUMP_TAIL_BYTES)
        body = (f"faulthandler output (last {shown} of {size} bytes; may include first-chance "
                f"Windows exceptions that were handled):\n{dump}")
    else:
        body = "no faulthandler output (an external kill or a power loss leaves none)"
    return level, f"{head} {why}. {body}"


def _log() -> logging.Logger:
    return logging.getLogger(_LOGGER_NAME)


def _on_clean_exit() -> None:
    marker = _state.get("marker")
    try:
        _log().info("[CRASH] interpreter exiting normally pid=%s", os.getpid())
    except Exception:
        pass
    if marker is not None:
        try:
            Path(marker).unlink(missing_ok=True)
        except Exception:
            pass


def _install_exception_hooks() -> None:
    prev_sys_hook = sys.excepthook
    prev_thread_hook = threading.excepthook

    def _sys_hook(exc_type, exc, tb):
        try:
            _log().critical("[CRASH] unhandled exception in the main thread",
                            exc_info=(exc_type, exc, tb))
        except Exception:
            pass
        prev_sys_hook(exc_type, exc, tb)

    def _thread_hook(args):
        if args.exc_type is not SystemExit:
            try:
                name = getattr(args.thread, "name", "?")
                _log().error("[CRASH] unhandled exception in thread %s", name,
                             exc_info=(args.exc_type, args.exc_value, args.exc_traceback))
            except Exception:
                pass
        prev_thread_hook(args)

    sys.excepthook = _sys_hook
    threading.excepthook = _thread_hook


def install(state_dir: Optional[Path] = None) -> bool:
    """Set up the crash evidence for THIS process. Never raises; False when it could not."""
    try:
        d = Path(state_dir) if state_dir is not None else default_state_dir()
        d.mkdir(parents=True, exist_ok=True)
        wall, mono = time.time(), time.monotonic()
        _state["pending"] = previous_run_report(d, wall=wall, mono=mono)
        dump_file = open(d / _DUMP_NAME, "w", encoding="utf-8", buffering=1)
        faulthandler.enable(file=dump_file, all_threads=True)
        _state["dump_file"] = dump_file  # faulthandler keeps only the fd: keep the object alive
        marker = d / _MARKER_NAME
        marker.write_text(json.dumps({
            "pid": os.getpid(),
            "started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(wall)),
            "boot_epoch": round(_boot_epoch(wall, mono), 1),
        }), encoding="utf-8")
        _state["marker"] = str(marker)
        atexit.register(_on_clean_exit)
        _install_exception_hooks()
        return True
    except Exception as exc:
        try:
            print(f"[CRASH] crash capture not installed: {exc}", file=sys.stderr)
        except Exception:
            pass
        return False


def report_previous(logger: logging.Logger) -> None:
    """Log the previous run's unclean end, once per process. No-op without ``install``."""
    pending = _state.get("pending")
    _state["pending"] = None
    if not pending:
        return
    level, message = pending
    try:
        logger.log(level, message)
    except Exception:
        pass

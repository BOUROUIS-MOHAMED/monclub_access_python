"""Start-up journal check (design 7 "Journal check at start-up", 8.0).

STANDARD LIBRARY ONLY: called from access/main.py and tv/main.py right after the
single-instance guard, before the app (and its database migrations) load -- after a power
cut ``current\\`` may be half-copied.

A stale ``{app}\\state\\install_journal.json`` means Setup died mid-install. The app cannot
overwrite its own locked files, so it starts the hidden restore helper
(shared/update_wrapper.py) and exits; the helper waits for this process, puts
``previous\\`` back, writes ``ROLLED_BACK`` reason ``interrupted`` and restarts the app,
which then reports it.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Callable, Optional

from shared.update_files import (
    UpdatePaths,
    journal_decision,
    last_boot_epoch,
    live_restore_claims,
    previous_is_complete,
    read_json,
    running_process_names,
    setup_is_running,
    target_for_exe,
    utc_now_iso,
)
from shared.update_wrapper import HelperLaunchError, build_restore_script, launch_hidden_powershell, setup_image_ps_re

TEST_OVERRIDE_ENV = "MONCLUB_UPDATER_JOURNAL_ROOT"


def _install_root_for(exe_name: str) -> Optional[Path]:
    """``{app}`` when this process is the installed exe in ``{app}\\current``, else None."""
    if not getattr(sys, "frozen", False):
        override = os.environ.get(TEST_OVERRIDE_ENV)  # tests / source runs only
        return Path(override) if override else None
    exe = Path(sys.executable)
    if exe.name.lower() != exe_name.lower() or exe.parent.name.lower() != "current":
        return None
    return exe.parent.parent


def _pid_alive(pid: object) -> Optional[bool]:
    """Whether any process has this pid (any image name); None when unknown."""
    try:
        wanted = int(str(pid).strip())
    except (TypeError, ValueError):
        return None
    if wanted <= 0:
        return None
    procs = running_process_names()
    return None if procs is None else wanted in procs


def _note(paths: UpdatePaths, message: str) -> None:
    try:
        paths.logs_dir.mkdir(parents=True, exist_ok=True)
        with (paths.logs_dir / "update-startup.log").open("a", encoding="utf-8") as f:
            f.write(f"{utc_now_iso()} pid={os.getpid()} {message}\n")
    except OSError:
        pass


def check_install_journal(
    *,
    exe_name: str,
    install_root: Optional[Path] = None,
    launcher: Callable[..., int] = launch_hidden_powershell,
    setup_running: Optional[Callable[..., bool]] = None,
    pid_alive: Optional[Callable[[object], Optional[bool]]] = None,
    now: Optional[float] = None,
    boot_epoch: Optional[float] = None,
) -> bool:
    """True = a restore helper is running and this process must exit now."""
    root = install_root if install_root is not None else _install_root_for(exe_name)
    if root is None:
        return False
    paths = UpdatePaths(Path(root))
    target = target_for_exe(exe_name)
    check_setup = setup_running or (lambda setup_pid=None: setup_is_running(setup_pid=setup_pid, target=target))
    live = live_restore_claims(paths)
    if live:
        # Another restorer (watchdog, wrapper, an earlier start) is rewriting current right
        # now and restarts the app when done: do not start from a half-restored folder.
        _note(paths, f"restore in progress ({live[0].name}); exiting without starting")
        return True
    if not paths.journal.exists():
        return False
    journal = read_json(paths.journal) or {}  # unreadable: phase unknown, "at" unknown = stale
    decision = journal_decision(
        journal,
        now=time.time() if now is None else now,
        boot_epoch=last_boot_epoch() if boot_epoch is None else boot_epoch,
        setup_running=check_setup(setup_pid=journal.get("setupPid")),
        previous_complete=previous_is_complete(paths, exe_name),
        setup_pid_alive=(pid_alive or _pid_alive)(journal.get("setupPid")),
    )
    if decision == "wait":
        _note(paths, f"install journal present, Setup still working ({journal}); starting normally")
        return False
    if decision == "delete":
        # current is intact (backing_up) or there is nothing to restore from: claim + delete.
        claim = paths.state_dir / f"install_journal.restoring-{os.getpid()}.json"
        try:
            os.replace(paths.journal, claim)
            claim.unlink()
            _note(paths, f"stale install journal deleted without restore ({journal})")
        except OSError as exc:
            _note(paths, f"stale journal not deleted ({exc}); another restorer owns it")
        return False
    # restore: the helper claims the journal and re-checks the phase and previous\.
    script = build_restore_script(
        setup_image_re=setup_image_ps_re(target),
        app_pid=os.getpid(),
        install_root=paths.install_root,
        exe_name=exe_name,
        restore_log=paths.logs_dir / "update-restore.log",
    )
    try:
        pid = launcher(script, cwd=paths.state_dir)
    except HelperLaunchError as exc:
        _note(paths, f"RESTORE HELPER DID NOT START ({exc}); starting the app as it is")
        return False
    _note(paths, f"interrupted install ({journal}): restore helper pid={pid} started; exiting")
    return True


__all__ = ["TEST_OVERRIDE_ENV", "check_install_journal"]

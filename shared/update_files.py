"""The updater's files under the install root, shared with the installer (design sections 7, 8).

STANDARD LIBRARY ONLY: access/main.py and tv/main.py import this before anything else to
restore an interrupted install, when ``current\\`` may be half-copied and the rest of the
app may not even import.

``{app}`` = the install root (the parent of ``current\\``):

- ``state\\install_journal.json`` -- Setup, ``{"phase","from","to","at","setupPid"}``
- ``state\\last_update.json`` -- Setup / the wrapper / the restore helper,
  ``{"result","from","to","reason","log","at"}``
- ``state\\boot_ok.json`` -- this app, ``{"version","pid","at"}``, once the local API listens
- ``state\\update_state.json`` -- this app only (pending update, attempts, bans, outbox)
- ``logs\\update-<version>-<ts>.log`` -- Setup's /LOG, ``logs\\update-wrapper.log``
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional

JOURNAL_STALE_SEC = 10 * 60

# Inno Setup runs as monclub_<target>_<ver>.exe, which starts the real work as
# %TEMP%\is-XXXXX.tmp\monclub_<target>_<ver>.tmp (L2, 2026-10-09; the watchdog uses the same
# rule). "_" is allowed after the version for L2's failure-injection test builds
# (monclub_access_<ver>_TESTFAIL_<x>.exe), which must also count as a running Setup.
SETUP_IMAGE_RE = re.compile(r"^monclub_(access|tv)_[0-9][0-9A-Za-z._\-]*\.(exe|tmp)\Z", re.IGNORECASE)
CLAIM_GLOB = "install_journal.restoring-*.json"
# Every restorer (the app's restore helper, the install wrapper, L2's watchdog / helper) is
# PowerShell: a claim pid running anything else is a reused pid, not a restorer.
_RESTORER_IMAGES = {"powershell.exe", "pwsh.exe"}
# A restorer touches its claim right after renaming the journal, so it started BEFORE the
# claim's mtime; a process that started later only reuses the pid (installer/update_helper.ps1
# Test-ClaimLive uses the same 5 s slack).
CLAIM_START_SLACK_SEC = 5.0


def setup_image_re(target: Optional[str] = None) -> "re.Pattern[str]":
    """The Setup image-name rule, for one product only when ``target`` is given.

    A component checks only ITS OWN Setup: an Access restore must not wait for, or stop, a
    TV Setup that runs in the same morning boot (different install roots)."""
    if not target:
        return SETUP_IMAGE_RE
    return re.compile(rf"^monclub_{re.escape(target.lower())}_[0-9][0-9A-Za-z._\-]*\.(exe|tmp)\Z", re.IGNORECASE)


def target_for_exe(exe_name: str) -> Optional[str]:
    name = (exe_name or "").lower()
    return {"monclubaccess.exe": "access", "monclubtv.exe": "tv"}.get(name)


@dataclass(frozen=True)
class UpdatePaths:
    install_root: Path

    @property
    def current_dir(self) -> Path:
        return self.install_root / "current"

    @property
    def previous_dir(self) -> Path:
        return self.install_root / "previous"

    @property
    def state_dir(self) -> Path:
        return self.install_root / "state"

    @property
    def logs_dir(self) -> Path:
        return self.install_root / "logs"

    @property
    def downloads_dir(self) -> Path:
        return self.install_root / "downloads"

    @property
    def journal(self) -> Path:
        return self.state_dir / "install_journal.json"

    @property
    def last_update(self) -> Path:
        return self.state_dir / "last_update.json"

    @property
    def last_update_consumed(self) -> Path:
        return self.state_dir / "last_update.consumed.json"

    @property
    def boot_ok(self) -> Path:
        return self.state_dir / "boot_ok.json"

    @property
    def update_state(self) -> Path:
        return self.state_dir / "update_state.json"


def utc_now_iso(epoch: Optional[float] = None) -> str:
    t = time.time() if epoch is None else epoch
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc_iso(value: Any) -> Optional[float]:
    """Epoch seconds of an ISO-8601 instant ("...Z" or with an offset); None if unparseable."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def read_json(path: Path) -> Optional[Dict[str, Any]]:
    """The JSON object in ``path``; None when missing, unreadable or not an object."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_json_atomic(path: Path, data: Dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(json.dumps(data, ensure_ascii=True, indent=1, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def write_boot_ok(paths: UpdatePaths, *, version: str, pid: Optional[int] = None) -> Dict[str, Any]:
    """The health marker Setup waits for (design section 7 / 8 step 3)."""
    payload = {"version": str(version), "pid": int(pid if pid is not None else os.getpid()), "at": utc_now_iso()}
    write_json_atomic(paths.boot_ok, payload)
    return payload


# ---------------------------------------------------------------- processes (Windows)

def running_process_names() -> Optional[Dict[int, str]]:
    """pid -> image name of every process, or None when it cannot be listed."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_wchar * 260),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
        kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
        if not snapshot or snapshot == wintypes.HANDLE(-1).value:
            return None
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            result: Dict[int, str] = {}
            ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            while ok:
                result[int(entry.th32ProcessID)] = str(entry.szExeFile)
                ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
            return result
        finally:
            kernel32.CloseHandle(snapshot)
    except Exception:
        return None


def setup_is_running(
    processes: Optional[Dict[int, str]] = None, *, setup_pid: Any = None, target: Optional[str] = None
) -> bool:
    """True when a MonClub Setup process is running, or when the list cannot be read
    (unknown counts as running: never restore under a live Setup)."""
    procs = running_process_names() if processes is None else processes
    if procs is None:
        return True
    rule = setup_image_re(target)
    if any(rule.match(name or "") for name in procs.values()):
        return True
    try:
        pid = int(setup_pid)
    except (TypeError, ValueError):
        return False
    name = procs.get(pid)
    return bool(name) and rule.match(name) is not None


def process_creation_epoch(pid: int) -> Optional[float]:
    """Wall-clock creation time of a running process, or None when it cannot be read."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel32.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return None
        try:
            times = [wintypes.FILETIME() for _ in range(4)]
            if not kernel32.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
                return None
            created = (int(times[0].dwHighDateTime) << 32) | int(times[0].dwLowDateTime)
            if created <= 0:
                return None
            return created / 10_000_000.0 - 11_644_473_600.0  # FILETIME (1601, 100 ns) -> epoch
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return None


def last_boot_epoch() -> Optional[float]:
    """Wall-clock time of the last Windows boot, or None when unknown."""
    if os.name != "nt":
        return None
    try:
        import ctypes

        ticks = ctypes.windll.kernel32.GetTickCount64
        ticks.restype = ctypes.c_ulonglong
        return time.time() - ticks() / 1000.0
    except Exception:
        return None


# ---------------------------------------------------------------- journal rule (design 8.0)

def previous_is_complete(paths: UpdatePaths, main_exe_name: str) -> bool:
    return (paths.previous_dir / main_exe_name).is_file() and (paths.previous_dir / "version.json").is_file()


def journal_decision(
    journal: Optional[Dict[str, Any]],
    *,
    now: float,
    boot_epoch: Optional[float],
    setup_running: bool,
    previous_complete: bool,
    setup_pid_alive: Optional[bool] = None,
) -> str:
    """What the start-up check does with ``install_journal.json``.

    ``"none"`` no journal; ``"wait"`` Setup may still be working (fresh or running);
    ``"delete"`` stale and ``current\\`` is intact (or nothing to restore from);
    ``"restore"`` stale and ``previous\\`` must be copied back.

    Stale (design 8.0, binding L2/L3 text) = no Setup image is running AND (``at`` unknown,
    older than 10 min or earlier than the last Windows boot, OR no live process has the pid
    ``setupPid`` -- any image name, so a killed Setup goes stale at once).
    ``setup_pid_alive``: None = not known (only the time rules apply). Phases: ``backing_up``
    (current still intact) -> delete; ``copying`` / ``verifying`` / ``restoring`` ->
    restore; anything else -> restore only when previous\\ is complete.
    """
    if journal is None:
        return "none"
    if setup_running:
        return "wait"
    at = parse_utc_iso(journal.get("at"))
    has_setup_pid = str(journal.get("setupPid") or "").strip() not in ("", "0")
    stale = (
        at is None
        or (now - at) >= JOURNAL_STALE_SEC
        or (boot_epoch is not None and at < boot_epoch)
        or (has_setup_pid and setup_pid_alive is False)
    )
    if not stale:
        return "wait"
    phase = str(journal.get("phase") or "").strip().lower()
    if phase == "backing_up":
        return "delete"
    if not previous_complete:
        return "delete"
    return "restore"


def consume_marker(data: Dict[str, Any]) -> str:
    """A stable identity of one last_update.json content (to consume it once)."""
    return json.dumps(data, sort_keys=True, ensure_ascii=True)


def live_restore_claims(
    paths: UpdatePaths,
    processes: Optional[Dict[int, str]] = None,
    *,
    boot_epoch: Optional[float] = None,
    creation_times: Optional[Dict[int, float]] = None,
) -> list[Path]:
    """Claimed journals (``install_journal.restoring-<pid>.json``) whose restorer still runs.

    While one exists, ``current`` is being rewritten: nothing may start from it. A claim is
    live only when its pid runs PowerShell, that process started no later than the claim
    (+5 s) -- a restorer touches its claim after it starts, a later process only reuses the
    pid -- AND the claim was made since the last Windows boot. The start-time rule is what
    holds under Fast Startup, where a shutdown does not reset the boot time (L4 inbox 2); an
    unreadable start time skips it, as installer/update_helper.ps1 Test-ClaimLive does. Any
    other claim is a restorer that died -- it is handed back as a journal (renamed back).
    ``creation_times``: pid -> epoch for an injected ``processes`` table (tests)."""
    live: list[Path] = []
    procs = running_process_names() if processes is None else processes
    boot = last_boot_epoch() if boot_epoch is None else boot_epoch
    if creation_times is not None:
        started_at: Callable[[int], Optional[float]] = creation_times.get
    elif processes is None:
        started_at = process_creation_epoch
    else:  # an injected table without start times: the start-time rule cannot apply
        started_at = lambda _pid: None  # noqa: E731
    for claim in sorted(paths.state_dir.glob(CLAIM_GLOB)) if paths.state_dir.is_dir() else []:
        m = re.match(r"^install_journal\.restoring-(\d+)\.json\Z", claim.name)
        pid = int(m.group(1)) if m else -1
        if procs is None:
            # Unknown process list: trust a fresh claim only (a restore takes seconds),
            # never block start-up forever on an old one.
            try:
                fresh = (time.time() - claim.stat().st_mtime) < JOURNAL_STALE_SEC
            except OSError:
                fresh = False
            if fresh:
                live.append(claim)
                continue
        elif (procs.get(pid) or "").lower() in _RESTORER_IMAGES:
            try:
                claimed_at = claim.stat().st_mtime
            except OSError:
                claimed_at = None
            started = started_at(pid)
            restorer = started is None or (claimed_at is not None and started <= claimed_at + CLAIM_START_SLACK_SEC)
            since_boot = claimed_at is not None and (boot is None or claimed_at >= boot - 5)
            if restorer and since_boot:
                live.append(claim)
                continue
        try:
            if not paths.journal.exists():
                os.replace(claim, paths.journal)
            else:
                claim.unlink()
        except OSError:
            live.append(claim)
    return live


def find_setup_names(names: Iterable[str], target: Optional[str] = None) -> list[str]:
    rule = setup_image_re(target)
    return [n for n in names if rule.match(n or "")]


__all__ = [
    "JOURNAL_STALE_SEC",
    "SETUP_IMAGE_RE",
    "UpdatePaths",
    "consume_marker",
    "find_setup_names",
    "journal_decision",
    "live_restore_claims",
    "last_boot_epoch",
    "parse_utc_iso",
    "previous_is_complete",
    "read_json",
    "running_process_names",
    "setup_image_re",
    "setup_is_running",
    "target_for_exe",
    "utc_now_iso",
    "write_boot_ok",
    "write_json_atomic",
]

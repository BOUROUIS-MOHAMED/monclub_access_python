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
# %TEMP%\is-XXXXX.tmp\monclub_<target>_<ver>.tmp (L2, 2026-10-09; the watchdog uses the same rule).
SETUP_IMAGE_RE = re.compile(r"^monclub_(access|tv)_[0-9][0-9A-Za-z.\-]*\.(exe|tmp)$", re.IGNORECASE)


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


def setup_is_running(processes: Optional[Dict[int, str]] = None, *, setup_pid: Any = None) -> bool:
    """True when a MonClub Setup process is running, or when the list cannot be read
    (unknown counts as running: never restore under a live Setup)."""
    procs = running_process_names() if processes is None else processes
    if procs is None:
        return True
    if any(SETUP_IMAGE_RE.match(name or "") for name in procs.values()):
        return True
    try:
        pid = int(setup_pid)
    except (TypeError, ValueError):
        return False
    name = procs.get(pid)
    return bool(name) and SETUP_IMAGE_RE.match(name) is not None


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
) -> str:
    """What the start-up check does with ``install_journal.json``.

    ``"none"`` no journal; ``"wait"`` Setup may still be working (fresh or running);
    ``"delete"`` stale and ``current\\`` is intact (or nothing to restore from);
    ``"restore"`` stale and ``previous\\`` must be copied back.

    Stale = ``at`` older than 10 min, or earlier than the last Windows boot (a reboot kills
    Setup), and no Setup process is running. Phases (L2, 2026-10-09): ``backing_up``
    (current still intact) -> delete; ``copying`` / ``verifying`` / ``restoring`` ->
    restore; anything else -> restore only when previous\\ is complete.
    """
    if journal is None:
        return "none"
    if setup_running:
        return "wait"
    at = parse_utc_iso(journal.get("at"))
    stale = at is None or (now - at) >= JOURNAL_STALE_SEC or (boot_epoch is not None and at < boot_epoch)
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


def find_setup_names(names: Iterable[str]) -> list[str]:
    return [n for n in names if SETUP_IMAGE_RE.match(n or "")]


__all__ = [
    "JOURNAL_STALE_SEC",
    "SETUP_IMAGE_RE",
    "UpdatePaths",
    "consume_marker",
    "find_setup_names",
    "journal_decision",
    "last_boot_epoch",
    "parse_utc_iso",
    "previous_is_complete",
    "read_json",
    "running_process_names",
    "setup_is_running",
    "utc_now_iso",
    "write_boot_ok",
    "write_json_atomic",
]

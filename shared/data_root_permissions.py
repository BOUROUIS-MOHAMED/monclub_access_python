"""The ProgramData data root must stay writable by the NON-elevated app.

Field case (owner's PC, 2026-10-17): ``C:\\ProgramData\\MonClub Access`` was created by an
ELEVATED launch ("Run as administrator"). Files an elevated process creates there are owned by
BUILTIN\\Administrators and inherit only ``BUILTIN\\Users:(RX)`` from ProgramData, so every later
normal or watchdog launch (installer PrivilegesRequired=lowest, watchdog task RunLevel Limited)
could only READ ``access.db`` and ``init_db`` died with ``sqlite3.OperationalError: attempt to
write a readonly database``.

Two parts:

- elevated launch -> grant BUILTIN\\Users Modify, inherited by sub-folders and files, on the
  ProgramData data root and re-apply it to what is already there (``icacls /T``). One elevated
  launch heals the PC, for Access and TV alike (TV's ``tv\\`` lives in the same root).
- any launch -> probe the database files with a real read+write open. If Windows refuses, show a
  French/English dialog saying what to do, and exit -- never a raw traceback.

There is deliberately NO fallback to ``%LOCALAPPDATA%``: it would silently open an EMPTY database
on a live gym PC (no sign-in, a new PC identity, no ``device_write_hold`` row, no offline
creations queue). ``os.access`` is useless here: on Windows it only reads the read-only attribute
and said True for all five admin-owned files on the owner's PC.
"""

from __future__ import annotations

import ctypes
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence

USERS_SID = "S-1-5-32-545"  # BUILTIN\Users -- by SID: the group is "Utilisateurs" on French Windows
ICACLS_GRANT = f"*{USERS_SID}:(OI)(CI)M"

# "Modify" as icacls writes it: FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE.
_MODIFY_MASK = 0x001301BF
_OBJECT_INHERIT_ACE = 0x1
_CONTAINER_INHERIT_ACE = 0x2
_INHERIT_ONLY_ACE = 0x8
_ACCESS_ALLOWED_ACE_TYPE = 0

_ERROR_FILE_NOT_FOUND = 2
_ERROR_PATH_NOT_FOUND = 3
_ERROR_ACCESS_DENIED = 5

_ICACLS_TIMEOUT_S = 300.0


def _log(msg: str) -> None:
    # Runs before setup_logging: stderr is %TEMP%\MonClubAccess.log (MonClubTV.log) in the windowed
    # build (access/main.py::_ensure_console_streams); the app log folder may itself be unwritable.
    try:
        print(f"[DATA_ROOT] {msg}", file=sys.stderr, flush=True)
    except Exception:
        pass


def is_elevated() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def programdata_data_root() -> Optional[Path]:
    """The ProgramData candidate of ``app/core/utils.py::_candidate_data_roots``, or None when
    that list does not start with it (MONCLUB_ACCESS_DATA_ROOT set -- dev, tests -- or not
    Windows)."""
    from app.core.utils import _candidate_data_roots

    roots = _candidate_data_roots()
    if os.name != "nt" or (os.environ.get("MONCLUB_ACCESS_DATA_ROOT") or "").strip():
        return None
    program_data = (os.environ.get("PROGRAMDATA") or r"C:\ProgramData").strip()
    if not roots or not program_data:
        return None
    first = roots[0]
    try:
        if Path(program_data).resolve() != first.parent.resolve():
            return None
    except Exception:
        return None
    return first


def repair_applies(data_root: Path) -> bool:
    """Only the shared ProgramData root is repaired. A %LOCALAPPDATA% root is never touched: the
    user's own SID already has Full there, and Users-Modify would open one user's data to all."""
    pd = programdata_data_root()
    if pd is None:
        return False
    try:
        return os.path.normcase(str(Path(data_root).resolve())) == os.path.normcase(str(pd.resolve()))
    except Exception:
        return False


def users_can_modify(path: Path, *, inheritable: bool) -> Optional[bool]:
    """Does an allow ACE give BUILTIN\\Users Modify on ``path`` (and, for ``inheritable``, pass it
    on to sub-folders and files)? None = could not tell (pywin32 missing, read refused)."""
    try:
        import win32security  # pywin32, requirements.txt

        sd = win32security.GetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:  # a NULL DACL grants everyone everything
            return True
        users = win32security.ConvertStringSidToSid(USERS_SID)
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            (ace_type, ace_flags), mask, sid = ace[0], ace[1], ace[-1]
            if ace_type != _ACCESS_ALLOWED_ACE_TYPE or sid != users:
                continue
            if (mask & _MODIFY_MASK) != _MODIFY_MASK:
                continue
            if inheritable:
                need = _OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE
                if (ace_flags & need) != need or (ace_flags & _INHERIT_ONLY_ACE):
                    continue
            elif ace_flags & _INHERIT_ONLY_ACE:
                continue
            return True
        return False
    except Exception:
        return None


def icacls_exe() -> str:
    system_root = (os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows").strip()
    return str(Path(system_root) / "System32" / "icacls.exe")


def icacls_command(data_root: Path) -> List[str]:
    # /T: also every existing sub-folder and file (the admin-owned ones); /C: go on past a file it
    # cannot change; /Q: no per-file success lines. Output is localized (OEM code page): never parsed.
    return [icacls_exe(), str(data_root), "/grant", ICACLS_GRANT, "/T", "/C", "/Q"]


def manual_fix_command(data_root: Path) -> str:
    return f'icacls "{data_root}" /grant *{USERS_SID}:(OI)(CI)M /T'


def repair_needed(data_root: Path, files: Iterable[Path]) -> bool:
    """True unless the root passes Users-Modify on AND every existing file listed already has it.
    Unknown (None) counts as needed: a repeated grant is harmless."""
    if users_can_modify(data_root, inheritable=True) is not True:
        return True
    for f in files:
        if Path(f).exists() and users_can_modify(Path(f), inheritable=False) is not True:
            return True
    return False


def repair_data_root_acl(
    data_root: Path,
    files: Sequence[Path] = (),
    *,
    elevated: Optional[bool] = None,
    run: Callable[..., "subprocess.CompletedProcess"] = subprocess.run,
) -> str:
    """Elevated launch on the ProgramData root: grant Users Modify (see module doc).
    Returns 'not-elevated' | 'not-applicable' | 'already-ok' | 'repaired' | 'failed'. Never raises."""
    try:
        if not (is_elevated() if elevated is None else elevated):
            return "not-elevated"
        if not repair_applies(data_root) or not Path(data_root).is_dir():
            return "not-applicable"
        if not repair_needed(data_root, files):
            return "already-ok"
        cmd = icacls_command(Path(data_root))
        _log(f"elevated launch: granting BUILTIN\\Users Modify on {data_root} ({' '.join(cmd[2:])})")
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = run(cmd, capture_output=True, timeout=_ICACLS_TIMEOUT_S, creationflags=flags)
        if proc.returncode == 0:
            _log("ACL repair done: normal (non-elevated) launches can write the data root again")
            return "repaired"
        _log(f"ACL repair: icacls exit code {proc.returncode} (some files may still be read-only)")
        return "failed"
    except Exception as exc:
        _log(f"ACL repair failed: {type(exc).__name__}: {exc}")
        return "failed"


def probe_writable(path: Path) -> Optional[bool]:
    """Open an EXISTING file for read+write the way SQLite will, write nothing, close.
    True = Windows allows it; False = access denied (error 5, the read-only-ACL case);
    None = missing, or any other error (a sharing violation is not this problem)."""
    p = Path(path)
    if os.name != "nt":
        if not p.exists():
            return None
        return os.access(str(p), os.R_OK | os.W_OK)
    GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
    FILE_SHARE_ALL = 0x1 | 0x2 | 0x4
    OPEN_EXISTING = 3
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = ctypes.c_void_p
    k32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    h = k32.CreateFileW(str(p), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_ALL, None, OPEN_EXISTING, 0, None)
    if h is None or h == INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error()
        if err == _ERROR_ACCESS_DENIED:
            return False
        return None
    k32.CloseHandle(h)
    return True


def database_files(db_path: Path) -> List[Path]:
    db_path = Path(db_path)
    return [db_path, Path(str(db_path) + "-wal"), Path(str(db_path) + "-shm")]


def find_unwritable(paths: Iterable[Path], *, probe: Callable[[Path], Optional[bool]] = probe_writable) -> List[Path]:
    out: List[Path] = []
    for p in paths:
        try:
            if probe(Path(p)) is False:
                out.append(Path(p))
        except Exception:
            continue
    return out


def build_message(app_name: str, data_root: Path, unwritable: Sequence[Path], *, elevated: bool) -> tuple[str, str]:
    files = "\n".join(f"  {p}" for p in unwritable[:5])
    cmd = manual_fix_command(data_root)
    if elevated:
        fr_fix = ("Les droits n'ont pas pu être réparés automatiquement. Dans une invite de commandes "
                  "administrateur, exécutez :")
        en_fix = "The permissions could not be repaired automatically. In an administrator command prompt, run:"
    else:
        fr_fix = (f"Pour corriger (une seule fois) : clic droit sur {app_name} > « Exécuter en tant "
                  f"qu'administrateur ». L'application répare les droits puis démarre ; ensuite, lancez-la "
                  f"normalement.\nOu, dans une invite de commandes administrateur :")
        en_fix = (f"To fix it (once): right-click {app_name} > \"Run as administrator\". The app repairs the "
                  f"permissions and starts; after that, start it normally.\nOr, in an administrator command prompt:")
    text = (
        f"{app_name} ne peut pas écrire dans ses données :\n{files}\n\n"
        f"Ces fichiers ont probablement été créés par un lancement « en tant qu'administrateur » ; "
        f"Windows les laisse maintenant en lecture seule pour un lancement normal.\n\n"
        f"{fr_fix}\n  {cmd}\n\n"
        f"------------------------------\n\n"
        f"{app_name} cannot write to its data:\n{files}\n\n"
        f"These files were probably created by a \"Run as administrator\" launch; Windows now leaves them "
        f"read-only for a normal launch.\n\n"
        f"{en_fix}\n  {cmd}"
    )
    return f"{app_name} — données en lecture seule / read-only data", text


def show_error_dialog(title: str, text: str) -> None:
    if os.name != "nt":
        return
    MB_OK, MB_ICONERROR, MB_SETFOREGROUND, MB_TOPMOST = 0x0, 0x10, 0x10000, 0x40000
    try:
        ctypes.windll.user32.MessageBoxW(None, text, title, MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST)
    except Exception:
        pass


def report_unwritable(
    app_name: str,
    data_root: Path,
    unwritable: Sequence[Path],
    *,
    elevated: Optional[bool] = None,
    before_dialog: Optional[Callable[[], None]] = None,
    show: Optional[Callable[[str, str], None]] = None,
) -> None:
    """Log, then show the blocking dialog. The modal keeps the process alive, so the watchdog
    (process-presence check) does not relaunch it behind the user's back. ``before_dialog``
    releases the single-instance guard first: the user's "Run as administrator" must not exit
    as "already running" while this dialog is open."""
    elev = is_elevated() if elevated is None else elevated
    _log("NOT WRITABLE (access denied) for this launch: " + ", ".join(str(p) for p in unwritable)
         + f" -- elevated={elev}; fix: run once as administrator, or {manual_fix_command(data_root)}")
    if before_dialog is not None:
        try:
            before_dialog()
        except Exception:
            pass
    title, text = build_message(app_name, data_root, unwritable, elevated=elev)
    (show or show_error_dialog)(title, text)  # looked up at call time, not bound at import


def is_readonly_database_error(exc: BaseException) -> bool:
    return isinstance(exc, sqlite3.OperationalError) and "readonly database" in str(exc).lower()


def check_data_root_at_startup(
    *,
    app_name: str,
    data_root: Path,
    db_path: Path,
    extra_files: Sequence[Path] = (),
    before_dialog: Optional[Callable[[], None]] = None,
) -> bool:
    """Run once at process start, before anything writes under the data root. True = go on;
    False = a dialog was shown and the caller exits."""
    files = database_files(db_path) + [Path(p) for p in extra_files]
    elevated = is_elevated()
    result = repair_data_root_acl(data_root, files, elevated=elevated)
    if result not in ("not-elevated", "not-applicable", "already-ok"):
        _log(f"ACL repair result: {result}")
    unwritable = find_unwritable(files)
    if not unwritable:
        return True
    report_unwritable(app_name, data_root, unwritable, elevated=elevated, before_dialog=before_dialog)
    return False


__all__ = [
    "ICACLS_GRANT",
    "USERS_SID",
    "build_message",
    "check_data_root_at_startup",
    "database_files",
    "find_unwritable",
    "icacls_command",
    "is_elevated",
    "is_readonly_database_error",
    "manual_fix_command",
    "probe_writable",
    "programdata_data_root",
    "repair_applies",
    "repair_data_root_acl",
    "repair_needed",
    "report_unwritable",
    "show_error_dialog",
    "users_can_modify",
]

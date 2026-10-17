"""The ProgramData data root an elevated launch left read-only (owner's PC, 2026-10-17).

shared/data_root_permissions.py: an elevated launch grants BUILTIN\\Users Modify on the root;
any launch probes the database files with a real read+write open and shows a dialog instead
of dying on ``sqlite3.OperationalError: attempt to write a readonly database``.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import types
from pathlib import Path

import pytest

import shared.data_root_permissions as drp

REPO = Path(__file__).resolve().parents[1]
WINDOWS = os.name == "nt"
_REAL_REPAIR = drp.repair_data_root_acl  # conftest swaps it for a tripwire; this file tests it


@pytest.fixture(autouse=True)
def _no_real_dialog(monkeypatch):
    """A real MessageBoxW blocks the run until someone clicks OK: never let one through."""
    def _refuse(title, text):
        raise AssertionError("a test reached the real MessageBoxW")

    monkeypatch.setattr(drp, "show_error_dialog", _refuse)
    monkeypatch.setattr(drp, "repair_data_root_acl", _REAL_REPAIR)  # every icacls call is mocked here


def _icacls(*args: str) -> None:
    subprocess.run([drp.icacls_exe(), *args], capture_output=True, check=True)


# ------------------------------------------------------------------ probe (non-elevated check)


def test_probe_says_writable_for_an_ordinary_file(tmp_path):
    f = tmp_path / "access.db"
    f.write_bytes(b"x")
    assert drp.probe_writable(f) is True
    assert f.read_bytes() == b"x"  # the probe writes nothing


def test_probe_says_unknown_for_a_missing_file(tmp_path):
    assert drp.probe_writable(tmp_path / "nope.db") is None


@pytest.mark.skipif(not WINDOWS, reason="Windows ACLs")
def test_probe_sees_an_acl_that_refuses_writing_where_os_access_does_not(tmp_path):
    """The owner's PC: os.access(W_OK) said True for all five admin-owned files, a read+write
    open was refused. A deny-write ACE on Everyone reproduces the refusal for this user."""
    f = tmp_path / "access.db"
    f.write_bytes(b"x")
    _icacls(str(f), "/deny", "*S-1-1-0:(W)")
    try:
        assert os.access(str(f), os.W_OK) is True  # the trap: only the read-only attribute
        assert drp.probe_writable(f) is False
        assert drp.find_unwritable(drp.database_files(f)) == [f]  # -wal/-shm missing: skipped
    finally:
        _icacls(str(f), "/remove:d", "*S-1-1-0")


def test_find_unwritable_keeps_only_refused_paths():
    answers = {Path("a"): True, Path("b"): False, Path("c"): None, Path("d"): False}
    assert drp.find_unwritable(answers, probe=answers.__getitem__) == [Path("b"), Path("d")]


def test_find_unwritable_survives_a_probe_that_raises():
    def probe(p):
        raise OSError("boom")

    assert drp.find_unwritable([Path("a")], probe=probe) == []


def test_database_files_are_the_db_its_wal_and_its_shm(tmp_path):
    db = tmp_path / "access.db"
    assert drp.database_files(db) == [db, tmp_path / "access.db-wal", tmp_path / "access.db-shm"]


def test_the_crash_error_is_recognised(tmp_path):
    db = tmp_path / "ro.db"
    sqlite3.connect(str(db)).close()
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        with pytest.raises(sqlite3.OperationalError) as ei:
            conn.execute("CREATE TABLE t (x)")
    finally:
        conn.close()
    assert drp.is_readonly_database_error(ei.value)
    assert not drp.is_readonly_database_error(sqlite3.OperationalError("no such table: t"))
    assert not drp.is_readonly_database_error(RuntimeError("attempt to write a readonly database"))


# ------------------------------------------------------------------ which root is repaired


def test_no_repair_when_the_data_root_is_overridden(monkeypatch, tmp_path):
    monkeypatch.setenv("MONCLUB_ACCESS_DATA_ROOT", str(tmp_path))
    assert drp.programdata_data_root() is None
    assert drp.repair_applies(tmp_path) is False


@pytest.mark.skipif(not WINDOWS, reason="Windows data roots")
def test_only_the_programdata_root_is_repaired_never_localappdata(monkeypatch, tmp_path):
    monkeypatch.delenv("MONCLUB_ACCESS_DATA_ROOT", raising=False)
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "pd"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "lad"))
    assert drp.programdata_data_root() == tmp_path / "pd" / "MonClub Access"
    assert drp.repair_applies(tmp_path / "pd" / "MonClub Access") is True
    assert drp.repair_applies(tmp_path / "lad" / "MonClub Access") is False


# ------------------------------------------------------------------ ACE check (idempotent repair)


class _FakeDacl:
    def __init__(self, aces):
        self._aces = aces

    def GetAceCount(self):
        return len(self._aces)

    def GetAce(self, i):
        return self._aces[i]


def _fake_win32security(monkeypatch, aces):
    sd = types.SimpleNamespace(GetSecurityDescriptorDacl=lambda: _FakeDacl(aces))
    mod = types.SimpleNamespace(
        DACL_SECURITY_INFORMATION=4,
        GetFileSecurity=lambda path, info: sd,
        ConvertStringSidToSid=lambda s: ("SID", s),
    )
    monkeypatch.setitem(sys.modules, "win32security", mod)


USERS = ("SID", drp.USERS_SID)
OI_CI = 0x1 | 0x2


@pytest.mark.parametrize("aces, inheritable, expected", [
    ([((0, OI_CI), 0x1301BF, USERS)], True, True),            # icacls (OI)(CI)M
    ([((0, OI_CI | 0x10), 0x1F01FF, USERS)], True, True),     # inherited Full also counts
    ([((0, 0x2), 0x1301BF, USERS)], True, False),             # (CI) only: files do not get it
    ([((0, OI_CI), 0x1200A9, USERS)], True, False),           # (RX): the owner's PC
    ([((0, OI_CI | 0x8), 0x1301BF, USERS)], False, False),    # inherit-only: not on the item itself
    ([((0, 0x10), 0x1301BF, USERS)], False, True),            # a file's inherited (I)(M)
    ([((1, OI_CI), 0x1301BF, USERS)], True, False),           # a DENY ace is not a grant
    ([((0, OI_CI), 0x1301BF, ("SID", "S-1-5-32-544"))], True, False),  # Administrators
])
def test_users_can_modify_reads_the_ace(monkeypatch, aces, inheritable, expected):
    _fake_win32security(monkeypatch, aces)
    assert drp.users_can_modify(Path("x"), inheritable=inheritable) is expected


def test_users_can_modify_is_unknown_without_pywin32(monkeypatch):
    monkeypatch.setitem(sys.modules, "win32security", None)  # import raises ImportError
    assert drp.users_can_modify(Path("x"), inheritable=True) is None


@pytest.mark.skipif(not WINDOWS, reason="Windows ACLs")
def test_users_can_modify_on_a_real_folder_after_the_grant(tmp_path):
    root = tmp_path / "root"
    (root / "access").mkdir(parents=True)
    child = root / "access" / "access.db"
    child.write_bytes(b"x")
    before = drp.users_can_modify(root, inheritable=True)
    if before is None:
        pytest.skip("pywin32 not importable")
    if before:
        pytest.skip("the temp folder already passes Users-Modify on")
    _icacls(str(root), "/grant", f"*{drp.USERS_SID}:(OI)(CI)RX")
    assert drp.users_can_modify(root, inheritable=True) is False
    assert drp.repair_needed(root, [child]) is True
    _icacls(str(root), "/grant", drp.ICACLS_GRANT, "/T", "/C", "/Q")
    assert drp.users_can_modify(root, inheritable=True) is True
    assert drp.users_can_modify(child, inheritable=False) is True
    assert drp.repair_needed(root, [child, root / "access" / "access.db-wal"]) is False


def test_repair_needed_when_the_root_is_fine_but_a_file_is_not(monkeypatch, tmp_path):
    root = tmp_path
    good, bad = tmp_path / "a", tmp_path / "b"
    good.write_bytes(b""), bad.write_bytes(b"")
    verdict = {root: True, good: True, bad: False}
    monkeypatch.setattr(drp, "users_can_modify", lambda p, inheritable: verdict[Path(p)])
    assert drp.repair_needed(root, [good]) is False
    assert drp.repair_needed(root, [good, bad]) is True
    assert drp.repair_needed(root, [good, tmp_path / "missing"]) is False


def test_repair_needed_when_the_acl_cannot_be_read(monkeypatch, tmp_path):
    monkeypatch.setattr(drp, "users_can_modify", lambda p, inheritable: None)
    assert drp.repair_needed(tmp_path, []) is True


# ------------------------------------------------------------------ the elevated repair


class _Run:
    def __init__(self, returncode=0, exc=None):
        self.calls = []
        self.returncode = returncode
        self.exc = exc

    def __call__(self, cmd, **kw):
        self.calls.append((cmd, kw))
        if self.exc is not None:
            raise self.exc
        return subprocess.CompletedProcess(cmd, self.returncode, b"", b"")


@pytest.fixture
def applicable(monkeypatch, tmp_path):
    monkeypatch.setattr(drp, "repair_applies", lambda root: True)
    monkeypatch.setattr(drp, "repair_needed", lambda root, files: True)
    return tmp_path


def test_not_elevated_never_runs_icacls(applicable):
    run = _Run()
    assert drp.repair_data_root_acl(applicable, elevated=False, run=run) == "not-elevated"
    assert run.calls == []


def test_elevated_off_the_programdata_root_never_runs_icacls(monkeypatch, tmp_path):
    monkeypatch.setattr(drp, "repair_applies", lambda root: False)
    run = _Run()
    assert drp.repair_data_root_acl(tmp_path, elevated=True, run=run) == "not-applicable"
    assert run.calls == []


def test_elevated_and_already_granted_runs_nothing(monkeypatch, applicable):
    monkeypatch.setattr(drp, "repair_needed", lambda root, files: False)
    run = _Run()
    assert drp.repair_data_root_acl(applicable, elevated=True, run=run) == "already-ok"
    assert run.calls == []


def test_elevated_grants_users_modify_by_sid_on_the_tree_without_a_window(applicable):
    run = _Run()
    assert drp.repair_data_root_acl(applicable, elevated=True, run=run) == "repaired"
    (cmd, kw), = run.calls
    assert cmd[0].lower().endswith(os.path.join("system32", "icacls.exe"))
    assert os.path.isabs(cmd[0])
    assert cmd[1:] == [str(applicable), "/grant", "*S-1-5-32-545:(OI)(CI)M", "/T", "/C", "/Q"]
    assert kw["timeout"] > 0
    assert kw["creationflags"] == getattr(subprocess, "CREATE_NO_WINDOW", 0)


def test_a_failing_icacls_is_reported_not_raised(applicable):
    assert drp.repair_data_root_acl(applicable, elevated=True, run=_Run(returncode=5)) == "failed"


@pytest.mark.parametrize("exc", [subprocess.TimeoutExpired("icacls", 1), FileNotFoundError("icacls")])
def test_an_icacls_that_hangs_or_is_missing_never_raises(applicable, exc):
    assert drp.repair_data_root_acl(applicable, elevated=True, run=_Run(exc=exc)) == "failed"


def test_is_elevated_reads_isuseranadmin(monkeypatch):
    if not WINDOWS:
        assert drp.is_elevated() is False
        return
    fake = types.SimpleNamespace(shell32=types.SimpleNamespace(IsUserAnAdmin=lambda: 1))
    monkeypatch.setattr(drp.ctypes, "windll", fake)
    assert drp.is_elevated() is True
    fake.shell32.IsUserAnAdmin = lambda: 0
    assert drp.is_elevated() is False


# ------------------------------------------------------------------ the startup check and dialog


def test_startup_check_passes_and_shows_nothing_when_writable(monkeypatch, tmp_path):
    shown = []
    monkeypatch.setattr(drp, "is_elevated", lambda: False)
    monkeypatch.setattr(drp, "find_unwritable", lambda paths: [])
    monkeypatch.setattr(drp, "show_error_dialog", lambda t, x: shown.append(t))
    assert drp.check_data_root_at_startup(app_name="MonClub Access", data_root=tmp_path,
                                          db_path=tmp_path / "access.db") is True
    assert shown == []


def test_startup_check_releases_the_guard_then_shows_the_dialog(monkeypatch, tmp_path, capsys):
    events = []
    db = tmp_path / "access" / "access.db"
    monkeypatch.setattr(drp, "is_elevated", lambda: False)
    monkeypatch.setattr(drp, "find_unwritable", lambda paths: [p for p in paths if p == db])
    monkeypatch.setattr(drp, "show_error_dialog", lambda title, text: events.append(("show", title, text)))
    ok = drp.check_data_root_at_startup(app_name="MonClub Access", data_root=tmp_path, db_path=db,
                                        before_dialog=lambda: events.append(("release",)))
    assert ok is False
    assert [e[0] for e in events] == ["release", "show"]
    text = events[1][2]
    assert str(db) in text
    assert drp.manual_fix_command(tmp_path) in text
    assert "Exécuter en tant qu'administrateur" in text and "Run as administrator" in text
    err = capsys.readouterr().err
    assert "NOT WRITABLE" in err and str(db) in err


def test_startup_check_checks_the_db_its_wal_shm_and_the_extra_files(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(drp, "is_elevated", lambda: False)
    monkeypatch.setattr(drp, "find_unwritable", lambda paths: seen.extend(paths) or [])
    db, cfg = tmp_path / "access.db", tmp_path / "config.json"
    drp.check_data_root_at_startup(app_name="A", data_root=tmp_path, db_path=db, extra_files=(cfg,))
    assert seen == drp.database_files(db) + [cfg]


def test_startup_check_repairs_before_it_probes_when_elevated(monkeypatch, tmp_path):
    order = []
    monkeypatch.setattr(drp, "is_elevated", lambda: True)
    monkeypatch.setattr(drp, "repair_data_root_acl",
                        lambda root, files, elevated: order.append(("repair", elevated)) or "repaired")
    monkeypatch.setattr(drp, "find_unwritable", lambda paths: order.append(("probe",)) or [])
    assert drp.check_data_root_at_startup(app_name="A", data_root=tmp_path, db_path=tmp_path / "x.db")
    assert order == [("repair", True), ("probe",)]


def test_the_elevated_message_does_not_tell_the_user_to_run_as_admin(tmp_path):
    _, text = drp.build_message("MonClub Access", tmp_path, [tmp_path / "a.db"], elevated=True)
    assert "right-click" not in text and "clic droit" not in text  # already elevated
    assert "could not be repaired automatically" in text
    assert drp.manual_fix_command(tmp_path) in text


def test_the_manual_command_uses_the_sid_not_the_localized_group_name(tmp_path):
    cmd = drp.manual_fix_command(Path(r"C:\ProgramData\MonClub Access"))
    assert cmd == r'icacls "C:\ProgramData\MonClub Access" /grant *S-1-5-32-545:(OI)(CI)M /T'


# ------------------------------------------------------------------ wiring


def _src(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def test_access_checks_the_data_root_before_crash_capture_and_the_app():
    s = _src("access/main.py")
    check = s.index("check_data_root_at_startup(")
    assert s.index("acquire_single_instance_guard(component_id=") < check
    assert check < s.index("crash_capture.install()") < s.index("run_access_app()")
    assert "before_dialog=guard.release" in s
    assert "is_readonly_database_error(exc)" in s


def test_tv_checks_the_shared_data_root_before_the_app():
    s = _src("tv/main.py")
    assert s.index("check_data_root_at_startup(") < s.index("run_tv_app()")
    assert "current_tv_runtime_db_path()" in s
    assert "is_readonly_database_error(exc)" in s


def test_data_root_choice_still_has_no_silent_fallback_on_a_read_only_root():
    """A writability probe in _pick_data_root would switch a live gym PC to an EMPTY
    %LOCALAPPDATA% database. It must only test that the folder can be created."""
    s = _src("app/core/utils.py")
    body = s[s.index("def _pick_data_root"):s.index("DATA_ROOT = _pick_data_root()")]
    assert "mkdir(parents=True, exist_ok=True)" in body
    assert "probe" not in body and "access(" not in body


@pytest.mark.parametrize("iss", ["installer/MonClubAccess.iss", "installer/MonClubTV.iss"])
def test_installers_give_users_modify_on_the_programdata_data_root(iss):
    s = _src(iss)
    dirs = s[s.index("[Dirs]"):s.index("[Files]")]
    line = next(l for l in dirs.splitlines() if l.startswith('Name: "{commonappdata}\\MonClub Access"'))
    assert "Permissions: users-modify" in line
    assert "uninsneveruninstall" in line  # removal stays with CurUninstallStepChanged (D26)
    assert "Check: DataRootDirWanted" in line
    assert "function DataRootDirWanted(): Boolean;" in s
    assert "PrivilegesRequired=lowest" in s

"""shared/update_files.py + shared/update_wrapper.py (D1, D24, D36; design 7 / 8.0).

The two ``*_runs_for_real`` tests start a real hidden PowerShell (Windows only, a few
seconds each) with a stand-in "Setup" (whoami.exe, which rejects /VERYSILENT and exits 1)
and a stand-in app exe (whoami.exe again, which exits at once).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from shared import update_files as uf
from shared import update_wrapper as uw

WINDOWS = os.name == "nt"
WHOAMI = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "whoami.exe"


# ------------------------------------------------------------------ journal rule

NOW = 1_800_000_000.0


def _j(phase="copying", age_sec=11 * 60):
    return {"phase": phase, "from": "1.5.0", "to": "1.5.1", "at": uf.utc_now_iso(NOW - age_sec), "setupPid": 4242}


def test_no_journal_means_nothing_to_do():
    assert uf.journal_decision(None, now=NOW, boot_epoch=None, setup_running=False, previous_complete=True) == "none"


def test_a_running_setup_is_never_disturbed():
    assert uf.journal_decision(_j(age_sec=3600), now=NOW, boot_epoch=None, setup_running=True, previous_complete=True) == "wait"


def test_a_fresh_journal_waits_for_setup():
    assert uf.journal_decision(_j(age_sec=60), now=NOW, boot_epoch=None, setup_running=False, previous_complete=True) == "wait"


def test_a_journal_older_than_ten_minutes_restores():
    assert uf.journal_decision(_j(), now=NOW, boot_epoch=None, setup_running=False, previous_complete=True) == "restore"


def test_a_journal_from_before_the_last_boot_restores_at_once():
    j = _j(age_sec=120)
    assert uf.journal_decision(j, now=NOW, boot_epoch=NOW - 60, setup_running=False, previous_complete=True) == "restore"


@pytest.mark.parametrize("phase", ["copying", "verifying", "restoring", "something-new"])
def test_restoring_phases(phase):
    assert uf.journal_decision(_j(phase), now=NOW, boot_epoch=None, setup_running=False, previous_complete=True) == "restore"


def test_backing_up_means_current_is_intact_so_only_delete():
    assert uf.journal_decision(_j("backing_up"), now=NOW, boot_epoch=None, setup_running=False, previous_complete=True) == "delete"


def test_no_complete_previous_means_nothing_to_restore_from():
    assert uf.journal_decision(_j(), now=NOW, boot_epoch=None, setup_running=False, previous_complete=False) == "delete"


def test_setup_detection_by_image_name_and_pid():
    assert uf.setup_is_running({1: "explorer.exe", 2: "monclub_access_1.5.1.exe"}) is True
    assert uf.setup_is_running({1: "explorer.exe", 2: "MONCLUB_TV_1.5.1-beta.1.tmp"}) is True
    assert uf.setup_is_running({1: "explorer.exe", 2: "MonClubAccess.exe"}) is False
    assert uf.setup_is_running({4242: "monclub_access_1.5.1.tmp"}, setup_pid=4242) is True
    assert uf.setup_is_running({}) is False


def test_an_unreadable_process_list_counts_as_setup_running(monkeypatch):
    monkeypatch.setattr(uf, "running_process_names", lambda: None)
    assert uf.setup_is_running() is True


@pytest.mark.skipif(not WINDOWS, reason="Windows process list")
def test_the_real_process_list_contains_this_process():
    procs = uf.running_process_names()
    assert procs is not None and os.getpid() in procs
    assert uf.last_boot_epoch() < time.time()


def test_boot_ok_carries_version_pid_and_utc_time(tmp_path):
    paths = uf.UpdatePaths(tmp_path)
    payload = uf.write_boot_ok(paths, version="1.5.1", pid=99)
    on_disk = json.loads(paths.boot_ok.read_text(encoding="utf-8"))
    assert on_disk == payload and on_disk["version"] == "1.5.1" and on_disk["pid"] == 99
    assert on_disk["at"].endswith("Z") and len(on_disk["at"]) == 20


def test_parse_utc_iso_round_trip():
    assert uf.parse_utc_iso(uf.utc_now_iso(NOW)) == NOW
    assert uf.parse_utc_iso("nope") is None


# ------------------------------------------------------------------ wrapper script text

def _install_script(tmp_path, root_name="MonClub Access"):
    root = tmp_path / root_name
    return root, uw.build_install_script(
        app_pid=1234,
        installer=root / "downloads" / "access" / "stable" / "1.5.1" / "monclub_access_1.5.1.exe",
        install_root=root,
        exe_name="MonClubAccess.exe",
        from_version="1.5.0",
        to_version="1.5.1",
        setup_log=root / "logs" / "update-1.5.1-20261010080000.log",
        wrapper_log=root / "logs" / "update-wrapper.log",
    )


def test_wrapper_runs_setup_silently_with_a_quoted_log_and_neutral_cwd(tmp_path):
    root, script = _install_script(tmp_path)
    assert "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=\"" in script
    assert str(root / "logs" / "update-1.5.1-20261010080000.log") in script
    assert f"-WorkingDirectory '{root / 'state'}' -PassThru" in script
    assert "Get-Process -Id 1234" in script
    assert "$p.WaitForExit()" in script and " -Wait " not in script
    # The relaunch starts current\<exe> from current, only when not already running.
    assert f"'{root / 'current' / 'MonClubAccess.exe'}'" in script
    assert f"-WorkingDirectory '{root / 'current'}'" in script


def test_wrapper_escapes_single_quotes_in_paths(tmp_path):
    _root, script = _install_script(tmp_path, root_name="O'Brien gym")
    assert "O''Brien gym" in script


def test_powershell_command_uses_the_full_path_and_no_profile():
    cmd = uw.powershell_command("W 'x'")
    assert cmd[0].lower().endswith(r"system32\windowspowershell\v1.0\powershell.exe")
    assert "-NoProfile" in cmd and "-EncodedCommand" not in cmd and cmd[-2] == "-Command"


class _FakeProc:
    def __init__(self, code):
        self._code = code
        self.pid = 777

    def poll(self):
        return self._code


def test_launch_reports_the_pid_of_a_live_helper(tmp_path):
    calls = []

    def popen(cmd, **kw):
        calls.append(kw)
        return _FakeProc(None)

    assert uw.launch_hidden_powershell("x", cwd=tmp_path / "state", popen=popen, sleep=lambda s: None) == 777
    assert calls[0]["cwd"] == str(tmp_path / "state")
    assert (tmp_path / "state").is_dir()


def test_launch_raises_when_the_helper_dies_or_cannot_start(tmp_path):
    with pytest.raises(uw.HelperLaunchError):
        uw.launch_hidden_powershell("x", cwd=tmp_path, popen=lambda *a, **k: _FakeProc(1), sleep=lambda s: None)

    def boom(*a, **k):
        raise OSError("blocked by policy")

    with pytest.raises(uw.HelperLaunchError):
        uw.launch_hidden_powershell("x", cwd=tmp_path, popen=boom, sleep=lambda s: None)


def test_setup_log_path_is_under_logs_with_version_and_utc_stamp(tmp_path):
    p = uw.setup_log_path(tmp_path, "1.5.1-beta.1", now=0)
    assert p == tmp_path / "logs" / "update-1.5.1-beta.1-19700101000000.log"


# ------------------------------------------------------------------ real PowerShell runs

def _run(script: str, cwd: Path) -> None:
    subprocess.run(uw.powershell_command(script), cwd=str(cwd), timeout=90, check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _dead_pid() -> int:
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


@pytest.mark.skipif(not WINDOWS or not WHOAMI.exists(), reason="needs Windows PowerShell")
def test_install_wrapper_runs_for_real_writes_aborted_and_relaunches_the_old_app(tmp_path):
    root = tmp_path / "MonClub Access"
    (root / "current").mkdir(parents=True)
    (root / "state").mkdir()
    shutil.copy(WHOAMI, root / "current" / "FakeApp.exe")
    setup = root / "downloads" / "monclub_access_1.5.1.exe"
    setup.parent.mkdir(parents=True)
    shutil.copy(WHOAMI, setup)  # rejects /VERYSILENT: exit code 1, writes no result
    script = uw.build_install_script(
        app_pid=_dead_pid(), installer=setup, install_root=root, exe_name="FakeApp.exe",
        from_version="1.5.0", to_version="1.5.1",
        setup_log=root / "logs" / "update-1.5.1-x.log", wrapper_log=root / "logs" / "update-wrapper.log",
    )
    _run(script, root / "state")
    result = json.loads((root / "state" / "last_update.json").read_text(encoding="ascii"))
    assert result["result"] == "ABORTED" and result["reason"] == "setup_exit_1"
    assert (result["from"], result["to"]) == ("1.5.0", "1.5.1")
    assert uf.parse_utc_iso(result["at"]) is not None
    log = (root / "logs" / "update-wrapper.log").read_text(encoding="utf-8", errors="replace")
    assert "setup exit 1" in log and "relaunched" in log


@pytest.mark.skipif(not WINDOWS or not WHOAMI.exists(), reason="needs Windows PowerShell")
def test_install_wrapper_keeps_a_result_setup_wrote_itself(tmp_path):
    root = tmp_path / "root"
    (root / "current").mkdir(parents=True)
    (root / "state").mkdir()
    fake_setup = root / "monclub_access_1.5.1.cmd"
    # A .cmd "Setup" that writes its own ROLLED_BACK result, then fails.
    fake_setup.write_text(
        '@echo {"result":"ROLLED_BACK","reason":"crash"}> "%~dp0state\\last_update.json"\r\n@exit /b 3\r\n',
        encoding="ascii",
    )
    script = uw.build_install_script(
        app_pid=_dead_pid(), installer=fake_setup, install_root=root, exe_name="Missing.exe",
        from_version="1.5.0", to_version="1.5.1",
        setup_log=root / "logs" / "s.log", wrapper_log=root / "logs" / "w.log",
    )
    _run(script, root / "state")
    result = json.loads((root / "state" / "last_update.json").read_text(encoding="ascii"))
    assert result == {"result": "ROLLED_BACK", "reason": "crash"}
    log = (root / "logs" / "w.log").read_text(encoding="utf-8", errors="replace")
    assert "setup exit 3" in log and "nothing to relaunch" in log


@pytest.mark.skipif(not WINDOWS or not WHOAMI.exists(), reason="needs Windows PowerShell")
def test_restore_helper_runs_for_real_and_puts_previous_back(tmp_path):
    root = tmp_path / "MonClub Access"
    (root / "current" / "sub").mkdir(parents=True)
    (root / "current" / "half-copied.dll").write_text("new", encoding="ascii")
    (root / "current" / "sub" / "x.txt").write_text("new", encoding="ascii")
    (root / "previous" / "sub").mkdir(parents=True)
    shutil.copy(WHOAMI, root / "previous" / "FakeApp.exe")
    (root / "previous" / "version.json").write_text('{"version":"1.5.0"}', encoding="ascii")
    (root / "previous" / "sub" / "y.txt").write_text("old", encoding="ascii")
    (root / "state").mkdir()
    (root / "state" / "install_journal.json").write_text('{"phase":"copying"}', encoding="ascii")
    script = uw.build_restore_script(
        app_pid=_dead_pid(), install_root=root, exe_name="FakeApp.exe",
        journal_from="1.5.0", journal_to="1.5.1", restore_log=root / "logs" / "restore.log",
    )
    _run(script, root / "state")
    names = sorted(str(p.relative_to(root / "current")) for p in (root / "current").rglob("*"))
    assert names == ["FakeApp.exe", "sub", os.path.join("sub", "y.txt"), "version.json"]
    assert not (root / "state" / "install_journal.json").exists()
    result = json.loads((root / "state" / "last_update.json").read_text(encoding="ascii"))
    assert (result["result"], result["reason"], result["from"], result["to"]) == ("ROLLED_BACK", "interrupted", "1.5.1", "1.5.0")
    assert "relaunched" in (root / "logs" / "restore.log").read_text(encoding="utf-8", errors="replace")

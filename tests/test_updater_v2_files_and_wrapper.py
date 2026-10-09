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


def _j(phase="copying", age_sec=11 * 60, setup_pid=None):
    j = {"phase": phase, "from": "1.5.0", "to": "1.5.1", "at": uf.utc_now_iso(NOW - age_sec)}
    if setup_pid is not None:
        j["setupPid"] = setup_pid
    return j


def test_no_journal_means_nothing_to_do():
    assert uf.journal_decision(None, now=NOW, boot_epoch=None, setup_running=False, previous_complete=True) == "none"


def test_a_running_setup_is_never_disturbed():
    assert uf.journal_decision(_j(age_sec=3600), now=NOW, boot_epoch=None, setup_running=True, previous_complete=True) == "wait"


def test_a_fresh_journal_waits_for_setup():
    assert uf.journal_decision(_j(age_sec=60), now=NOW, boot_epoch=None, setup_running=False, previous_complete=True) == "wait"


def test_a_journal_older_than_ten_minutes_restores():
    assert uf.journal_decision(_j(), now=NOW, boot_epoch=None, setup_running=False, previous_complete=True) == "restore"


def test_a_fresh_journal_whose_setup_pid_is_gone_restores_at_once():
    j = _j(age_sec=30, setup_pid=4242)
    assert uf.journal_decision(j, now=NOW, boot_epoch=None, setup_running=False, previous_complete=True,
                               setup_pid_alive=False) == "restore"


def test_a_live_setup_pid_with_any_image_name_protects_a_fresh_journal():
    """L2: a technician's RENAMED installer (setup.exe) is not matched by the image rule;
    its live pid still protects the journal (within the 10-min / same-boot window)."""
    j = _j(age_sec=60, setup_pid=4242)
    assert uf.journal_decision(j, now=NOW, boot_epoch=NOW - 7200, setup_running=False, previous_complete=True,
                               setup_pid_alive=True) == "wait"
    assert uf.journal_decision(j, now=NOW, boot_epoch=NOW - 7200, setup_running=False, previous_complete=True,
                               setup_pid_alive=None) == "wait"


def test_a_journal_from_before_the_last_boot_is_stale_even_if_its_pid_was_reused():
    j = _j(age_sec=120, setup_pid=4242)
    assert uf.journal_decision(j, now=NOW, boot_epoch=NOW - 60, setup_running=False, previous_complete=True,
                               setup_pid_alive=True) == "restore"


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
    # L2's failure-injection builds must count too (review H1).
    assert uf.setup_is_running({7: "monclub_access_1.5.1_TESTFAIL_health.tmp"}) is True
    assert uf.setup_is_running({7: "monclub_access_1.5.1.exe.bak"}) is False


def test_a_live_restore_claim_is_reported_and_a_dead_one_is_handed_back(tmp_path):
    paths = uf.UpdatePaths(tmp_path)
    paths.state_dir.mkdir()
    (paths.state_dir / "install_journal.restoring-111.json").write_text("{}", encoding="ascii")
    assert [p.name for p in uf.live_restore_claims(paths, {111: "powershell.exe"})] == ["install_journal.restoring-111.json"]
    assert uf.live_restore_claims(paths, {222: "powershell.exe"}) == []
    assert paths.journal.exists() and not (paths.state_dir / "install_journal.restoring-111.json").exists()


def test_a_claim_is_live_only_for_a_powershell_pid_claimed_since_the_last_boot(tmp_path):
    paths = uf.UpdatePaths(tmp_path)
    paths.state_dir.mkdir()
    claim = paths.state_dir / "install_journal.restoring-111.json"
    claim.write_text("{}", encoding="ascii")
    now = time.time()
    # a reused pid: not PowerShell
    assert uf.live_restore_claims(paths, {111: "svchost.exe"}, boot_epoch=now - 60) == []
    assert paths.journal.exists()
    os.replace(paths.journal, claim)
    # PowerShell, but the claim predates the last boot: its restorer died in the reboot
    os.utime(claim, (now - 7200, now - 7200))
    assert uf.live_restore_claims(paths, {111: "powershell.exe"}, boot_epoch=now - 3600) == []
    assert paths.journal.exists()
    os.replace(paths.journal, claim)
    os.utime(claim, (now, now))
    assert uf.live_restore_claims(paths, {111: "pwsh.exe"}, boot_epoch=now - 3600) == [claim]


def test_each_component_waits_only_for_its_own_setup():
    """Advisor: an Access restore must not back off for (or stop) a TV Setup."""
    tv_setup = {9: "monclub_tv_1.5.1.tmp"}
    assert uf.setup_is_running(tv_setup, target="access") is False
    assert uf.setup_is_running(tv_setup, target="tv") is True
    assert uf.setup_is_running(tv_setup) is True
    assert uw.setup_image_ps_re("access") == r"^monclub_access_[0-9][0-9A-Za-z._\-]*\.(exe|tmp)$"
    assert uf.target_for_exe("MonClubTV.exe") == "tv" and uf.target_for_exe("MonClubAccess.exe") == "access"


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
    assert f"$p.WaitForExit({uw.SETUP_WAIT_MS})" in script and " -Wait " not in script
    assert "Stop-Setups" in script  # a hung Setup is stopped, then the journal restore runs
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

# Real runs must not depend on a MonClub Setup that happens to run on this PC (lane L2 tests
# real installers here): they use an image pattern no process has.
NO_SETUP = r"^monclub_never_running_test_pattern$"


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
        setup_image_re=NO_SETUP, app_pid=_dead_pid(), installer=setup, install_root=root, exe_name="FakeApp.exe",
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
        setup_image_re=NO_SETUP, app_pid=_dead_pid(), installer=fake_setup, install_root=root, exe_name="Missing.exe",
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
    (root / "state" / "install_journal.json").write_text(
        '{"phase":"copying","from":"1.5.0","to":"1.5.1","at":"2026-10-10T08:00:00Z","setupPid":1}', encoding="ascii")
    script = uw.build_restore_script(
        setup_image_re=NO_SETUP, app_pid=_dead_pid(), install_root=root, exe_name="FakeApp.exe", restore_log=root / "logs" / "restore.log",
    )
    _run(script, root / "state")
    names = sorted(str(p.relative_to(root / "current")) for p in (root / "current").rglob("*"))
    assert names == ["FakeApp.exe", "sub", os.path.join("sub", "y.txt"), "version.json"]
    assert sorted(p.name for p in (root / "state").iterdir()) == ["last_update.json"]  # claim deleted too
    result = json.loads((root / "state" / "last_update.json").read_text(encoding="utf-8"))
    assert (result["result"], result["reason"], result["from"], result["to"]) == ("ROLLED_BACK", "interrupted", "1.5.1", "1.5.0")
    assert "relaunched" in (root / "logs" / "restore.log").read_text(encoding="utf-8", errors="replace")


@pytest.mark.skipif(not WINDOWS or not WHOAMI.exists(), reason="needs Windows PowerShell")
def test_restore_helper_only_deletes_a_backing_up_journal(tmp_path):
    root = tmp_path / "root"
    (root / "current").mkdir(parents=True)
    (root / "current" / "intact.txt").write_text("current", encoding="ascii")
    (root / "previous").mkdir()
    (root / "state").mkdir()
    (root / "state" / "install_journal.json").write_text('{"phase":"backing_up","from":"1.5.0","to":"1.5.1"}', encoding="ascii")
    script = uw.build_restore_script(setup_image_re=NO_SETUP, app_pid=_dead_pid(), install_root=root, exe_name="Missing.exe",
                                     restore_log=root / "logs" / "r.log")
    _run(script, root / "state")
    assert (root / "current" / "intact.txt").read_text(encoding="ascii") == "current"
    assert list((root / "state").iterdir()) == []
    assert "backing_up" in (root / "logs" / "r.log").read_text(encoding="utf-8", errors="replace")


@pytest.mark.skipif(not WINDOWS or not WHOAMI.exists(), reason="needs Windows PowerShell")
def test_install_wrapper_restores_a_journal_setup_left_behind_before_relaunching(tmp_path):
    root = tmp_path / "root"
    (root / "current").mkdir(parents=True)
    (root / "current" / "half.dll").write_text("half", encoding="ascii")
    (root / "previous").mkdir()
    shutil.copy(WHOAMI, root / "previous" / "FakeApp.exe")
    (root / "previous" / "version.json").write_text('{"version":"1.5.0"}', encoding="ascii")
    (root / "state").mkdir()
    fake_setup = root / "monclub_access_1.5.1.cmd"
    # A "Setup" killed mid-copy: journal left, no result, non-zero exit.
    fake_setup.write_text(
        '@echo {"phase":"copying","from":"1.5.0","to":"1.5.1","at":"2026-10-10T08:00:00Z"}> "%~dp0state\\install_journal.json"\r\n'
        '@exit /b 5\r\n',
        encoding="ascii",
    )
    script = uw.build_install_script(
        setup_image_re=NO_SETUP, app_pid=_dead_pid(), installer=fake_setup, install_root=root, exe_name="FakeApp.exe",
        from_version="1.5.0", to_version="1.5.1",
        setup_log=root / "logs" / "s.log", wrapper_log=root / "logs" / "w.log",
    )
    _run(script, root / "state")
    assert sorted(p.name for p in (root / "current").iterdir()) == ["FakeApp.exe", "version.json"]
    result = json.loads((root / "state" / "last_update.json").read_text(encoding="utf-8"))
    assert (result["result"], result["reason"]) == ("ROLLED_BACK", "interrupted")
    log = (root / "logs" / "w.log").read_text(encoding="utf-8", errors="replace")
    assert "journal after Setup: restored" in log and "relaunched" in log


@pytest.mark.skipif(not WINDOWS or not WHOAMI.exists(), reason="needs Windows PowerShell")
def test_restore_helper_backs_off_while_a_setup_runs(tmp_path):
    """The restore checks for a running Setup itself (review L4); here 'Setup' = the
    helper's own powershell.exe, which is certainly running."""
    root = tmp_path / "root"
    (root / "current").mkdir(parents=True)
    (root / "current" / "new.dll").write_text("new", encoding="ascii")
    (root / "previous").mkdir()
    shutil.copy(WHOAMI, root / "previous" / "FakeApp.exe")
    (root / "previous" / "version.json").write_text("{}", encoding="ascii")
    (root / "state").mkdir()
    (root / "state" / "install_journal.json").write_text('{"phase":"copying"}', encoding="ascii")
    script = uw.build_restore_script(setup_image_re=r"^powershell\.exe$", app_pid=_dead_pid(), install_root=root,
                                     exe_name="FakeApp.exe", restore_log=root / "logs" / "r.log")
    _run(script, root / "state")
    assert (root / "state" / "install_journal.json").exists()
    assert (root / "current" / "new.dll").exists()
    assert "a Setup is still running" in (root / "logs" / "r.log").read_text(encoding="utf-8", errors="replace")


def test_a_claim_gets_a_fresh_timestamp_right_after_the_rename(tmp_path):
    """L2 review: a rename keeps the journal's LastWriteTime (before the boot after a power
    cut), so without the touch a live restorer's claim would look dead to the next one."""
    script = uw.build_restore_script(app_pid=1, install_root=tmp_path, exe_name="FakeApp.exe",
                                     restore_log=tmp_path / "r.log")
    rename = script.index("Rename-Item -LiteralPath $journal -NewName $claimName")
    touch = script.index("[IO.File]::SetLastWriteTimeUtc($claim, [DateTime]::UtcNow)")
    assert rename < touch < script.index("Get-Content -LiteralPath $claim")


@pytest.mark.skipif(not WINDOWS or not WHOAMI.exists(), reason="needs Windows PowerShell")
def test_timestamps_stay_gregorian_utc_under_an_arabic_culture(tmp_path):
    """L2 found PowerShell's ToString(fmt) writes a Hijri year under ar-SA (1448 in 2026)."""
    root = tmp_path / "root"
    (root / "current").mkdir(parents=True)
    (root / "state").mkdir()
    setup = root / "monclub_access_1.5.1.exe"
    shutil.copy(WHOAMI, setup)  # exits 1: the wrapper writes ABORTED with "at"
    script = uw.build_install_script(
        setup_image_re=NO_SETUP, app_pid=_dead_pid(), installer=setup, install_root=root, exe_name="Missing.exe",
        from_version="1.5.0", to_version="1.5.1", setup_log=root / "logs" / "s.log", wrapper_log=root / "logs" / "w.log",
    )
    script = "[Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]'ar-SA'\n" + script
    _run(script, root / "state")
    result = json.loads((root / "state" / "last_update.json").read_text(encoding="ascii"))
    year = time.gmtime().tm_year
    assert abs(uf.parse_utc_iso(result["at"]) - time.time()) < 300, result["at"]
    first_log_line = (root / "logs" / "w.log").read_text(encoding="utf-8", errors="replace").splitlines()[0]
    assert first_log_line.startswith(f"{year}-"), first_log_line

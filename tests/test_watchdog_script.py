"""Decision table for packaging/watchdog/monclub_access_watchdog.ps1.

The watchdog exists because nothing restarts MonClubAccess.exe when it dies --
no service, no scheduled task, no supervisor -- so the gym is left with a Tauri
window that looks alive over a dead backend ("TypeError: Failed to fetch") until
a human restarts it.

Its two failure modes are opposite and both bad:

  * restarting at the WRONG time -- racing the Inno Setup installer
    (KillRunningMonClubProcesses) or MonClubAccessUpdater.exe while they are
    swapping current\\ -- which can lock files mid-swap and break the update;
  * standing down when it SHOULDN'T, which silently defeats the whole feature.

The second is what these tests mostly guard. The installer-detection heuristic
originally matched ``.*install.*`` and hit the Windows built-in
``AppInstallerPythonRedirector`` on a plain dev box -- and would equally have hit
``SetupHost.exe`` for the entire duration of a Windows Update, leaving the app
down with only a log line to say why.

Run with ``-WhatIfOnly`` throughout: the script reports the decision it would
make and starts nothing.

The last two classes cover how the task gets installed: register_watchdog.ps1
must keep a task someone disabled disabled (an update used to switch it back
on), and the installer's "Keep MonClub Access running" box must be ticked for a
new install only.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "packaging" / "watchdog" / "monclub_access_watchdog.ps1"
REGISTER = REPO / "packaging" / "watchdog" / "register_watchdog.ps1"
INSTALLER = REPO / "installer" / "MonClubAccess.iss"

pwsh = shutil.which("pwsh") or shutil.which("powershell")
# The installer's [Run] entry calls powershell.exe, i.e. Windows PowerShell 5.1,
# so the register script is tested under that shell and nothing else.
winps = shutil.which("powershell") if sys.platform == "win32" else None
pytestmark = [
    pytest.mark.skipif(pwsh is None, reason="PowerShell not available"),
    pytest.mark.skipif(not SCRIPT.exists(), reason=f"{SCRIPT} missing"),
]


def _installer_match(process_name: str) -> bool:
    """Ask the SHIPPED Test-InstallerRunning whether *process_name* is our installer.

    Deliberately not a copy of the regex. These tests used to inline the pattern
    and -match it directly, which proved only that the literal in the test file
    matched itself: editing the real pattern in the .ps1 left them green. The
    narrowing they exist to protect lives in the script, so the script is what
    has to be executed.

    Test-InstallerRunning calls Get-Process with no seam, so lift just that
    function out of the file via the PowerShell AST -- running the script itself
    would execute a whole tick -- and shadow Get-Process in the same scope with a
    stub returning one object of the requested name. A function definition beats
    a cmdlet in name resolution, so the real body runs against fake input.
    """
    # as_posix(): a Python repr of a Windows path doubles its backslashes, and a
    # PowerShell single-quoted string takes those literally -> wrong path.
    # PowerShell accepts forward slashes everywhere a path is expected.
    ps = f"""
$ErrorActionPreference = 'Stop'
$src = Get-Content -Raw -LiteralPath '{SCRIPT.as_posix()}'
$ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
$fn = $ast.Find({{
    param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $n.Name -eq 'Test-InstallerRunning'
}}, $true)
if (-not $fn) {{ Write-Output 'NOFUNC'; exit 0 }}
Invoke-Expression $fn.Extent.Text
function Get-Process {{
    param([string] $Name, $ErrorAction)
    [pscustomobject]@{{ ProcessName = {process_name!r} }}
}}
if (Test-InstallerRunning) {{ Write-Output 'MATCH' }} else {{ Write-Output 'no' }}
"""
    out = subprocess.run(
        [pwsh, "-NoProfile", "-Command", ps],
        capture_output=True, text=True, timeout=60, check=False,
    )
    stdout = out.stdout.strip()
    assert "NOFUNC" not in stdout, (
        "Test-InstallerRunning no longer exists in the shipped watchdog script; "
        "this test can no longer verify the real detection logic"
    )
    assert stdout in ("MATCH", "no"), (
        f"could not evaluate the shipped Test-InstallerRunning: "
        f"stdout={out.stdout!r} stderr={out.stderr!r}"
    )
    return stdout == "MATCH"


def _run(root: Path, *extra: str) -> str:
    """Run one watchdog tick against *root*; return everything it logged THIS tick.

    Not just the last line: a single tick can log twice (e.g. "sentinel is
    stale" followed by the miss it then records), and asserting on the last line
    alone silently misses the first.
    """
    log = root / "logs" / "watchdog.log"
    before = 0
    if log.exists():
        before = len(log.read_text(encoding="utf-8", errors="replace").splitlines())

    subprocess.run(
        [pwsh, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(SCRIPT),
         "-InstallRoot", str(root), "-WhatIfOnly", *extra],
        capture_output=True, text=True, timeout=120, check=False,
    )
    if not log.exists():
        return ""
    lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(ln for ln in lines[before:] if ln.strip())


@pytest.fixture
def root(tmp_path: Path) -> Path:
    """An install root shaped like the real one, with the app exe present."""
    (tmp_path / "current").mkdir(parents=True)
    (tmp_path / "current" / "MonClubAccess.exe").write_text("stub")
    return tmp_path


class TestRestartsOnlyAfterConfirmation:
    def test_first_miss_waits_and_second_restarts(self, root: Path):
        first = _run(root)
        assert "miss 1/2" in first, f"expected a first-miss hold, got: {first!r}"

        second = _run(root)
        assert "WHATIF: would start" in second, (
            f"expected a restart on the confirming tick, got: {second!r}"
        )

    def test_a_single_tick_never_restarts(self, root: Path):
        """One missed sample is not evidence -- the updater's own gap looks like this."""
        assert "would start" not in _run(root)


class TestStandDownGuards:
    def test_missing_exe_is_treated_as_a_swap_in_progress(self, tmp_path: Path):
        (tmp_path / "current").mkdir(parents=True)      # no exe inside
        line = _run(tmp_path)
        assert "missing" in line and "standing down" in line

    def test_fresh_pause_sentinel_stands_down(self, root: Path):
        (root / ".update-in-progress").write_text("")
        line = _run(root)
        assert "sentinel" in line and "standing down" in line

    def test_stale_pause_sentinel_is_ignored(self, root: Path):
        """An aborted install must not disable the watchdog forever."""
        (root / ".update-in-progress").write_text("")
        line = _run(root, "-SentinelMaxAgeMinutes", "0")
        assert "stale" in line
        assert "{0" not in line, f"format placeholder leaked into the log: {line!r}"


class TestInstallerDetectionIsNarrow:
    """The regression that made this file worth writing."""

    @pytest.mark.parametrize("name", [
        "AppInstallerPythonRedirector",   # real Windows process, matched the old pattern
        "SetupHost",                      # runs for the whole of a Windows Update
        "vcredist_setup",
        "MonClubAccess",                  # the app itself
        "MonClubAccessUpdater",           # handled by its own guard, not this one
    ])
    def test_unrelated_processes_are_not_mistaken_for_our_installer(self, name: str):
        assert _installer_match(name) is False, (
            f"{name!r} would be mistaken for the MonClub installer, standing the "
            f"watchdog down while the app is dead"
        )

    @pytest.mark.parametrize("name", ["monclub_access", "monclub_access_1.4.33"])
    def test_our_own_installer_is_still_detected(self, name: str):
        assert _installer_match(name) is True


class TestCrashLoopCap:
    def _seed(self, root: Path, count: int, minutes_ago: int) -> None:
        """Seed restart stamps as UNIX EPOCH SECONDS.

        Deliberately integers, matching the script. These were ISO strings once,
        and that round-tripped through ConvertFrom-Json -> [DateTime] ->
        current-culture text -> [datetime]::Parse, which on a non-US locale read
        a 90-minute-old restart as a FUTURE one and latched the rate cap --
        disabling recovery entirely. This test caught that; keep it on integers.
        """
        import time
        now = int(time.time())
        stamps = [now - (minutes_ago + i) * 60 for i in range(count)]
        logs = root / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        (logs / "watchdog-state.json").write_text(
            json.dumps({"misses": 1, "restarts": stamps}), encoding="utf-8"
        )

    def test_repeated_restarts_inside_the_window_stop(self, root: Path):
        """A crash-looping build must not be relaunched forever."""
        self._seed(root, count=5, minutes_ago=1)
        line = _run(root)
        assert "NOT restarting" in line
        assert "5 time(s)" in line, f"counts did not render: {line!r}"

    def test_old_restarts_outside_the_window_do_not_count(self, root: Path):
        self._seed(root, count=5, minutes_ago=90)
        _run(root)                       # consumes the confirming tick
        line = _run(root)
        assert "NOT restarting" not in line, (
            f"restarts from 90+ min ago should have aged out: {line!r}"
        )

    def test_legacy_iso_string_stamps_are_discarded_not_trusted(self, root: Path):
        """The exact shape of the culture bug, pinned.

        An older build wrote ISO-8601 strings here. Read back through
        ConvertFrom-Json they become [DateTime], get re-serialised in the
        machine's own culture, and reparse as the WRONG DATE where day/month
        order differs -- making stale restarts look current and latching the cap
        so the app is never restarted again. Unparseable-as-integer entries must
        therefore be dropped, not interpreted.
        """
        import datetime
        now = datetime.datetime.now()
        stamps = [(now - datetime.timedelta(minutes=90 + i)).isoformat() for i in range(5)]
        logs = root / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        (logs / "watchdog-state.json").write_text(
            json.dumps({"misses": 1, "restarts": stamps}), encoding="utf-8"
        )

        line = _run(root)
        assert "NOT restarting" not in line, (
            f"legacy ISO stamps were trusted and latched the rate cap: {line!r}"
        )
        assert "would start" in line

    def test_corrupt_state_file_does_not_wedge_the_watchdog(self, root: Path):
        logs = root / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        (logs / "watchdog-state.json").write_text("not json{{{", encoding="utf-8")
        line = _run(root)
        assert "miss 1/2" in line, f"corrupt state should reset, got: {line!r}"


# Runs the SHIPPED register_watchdog.ps1 with the Task Scheduler cmdlets replaced
# by stubs that keep the fake tasks in memory. Nothing may reach the real Task
# Scheduler, so, in this order:
#   * ScheduledTasks is imported BEFORE the stubs are defined. Its commands are
#     functions (a CDXML module); auto-loaded later, they would be "added most
#     recently" and win over the stubs -- and the real Register-ScheduledTask
#     would run on the machine.
#   * Every stub is checked to be the command that resolves, before the script runs.
#   * The task name is a throwaway one, and afterwards the REAL cmdlets
#     (module-qualified) look for it: found means a stub leaked; it is removed
#     and the test fails on LEAKED.
# -WatchdogScript points at a folder without the hidden launcher, so the script
# takes its direct-launch fallback and starts no wscript probe.
_REGISTER_HARNESS = r"""
param(
    [string] $Script,
    [string] $TaskName,
    [string] $InstallRoot,
    [string] $WatchdogScript,
    [string] $Initial,         # 'none', or the tasks' States, comma-separated: the first
                               # at the root folder '\', any others in other folders
    [string] $HonourEnabled,   # 'yes': a task registered with Settings.Enabled = $false comes back Disabled
    [string] $DisableWorks,    # 'yes': Disable-ScheduledTask takes effect
    [string] $RegisterFails    # 'yes': the first (non -Xml) registration throws
)
$ErrorActionPreference = 'Stop'
Import-Module ScheduledTasks

$global:Calls      = New-Object System.Collections.ArrayList
$global:Tasks      = New-Object System.Collections.ArrayList
$global:Honour     = ($HonourEnabled -eq 'yes')
$global:DisableOk  = ($DisableWorks -eq 'yes')
$global:FailNext   = ($RegisterFails -eq 'yes')
$global:Expected   = $TaskName
$global:Registered = $null
if ($Initial -ne 'none') {
    $i = 0
    foreach ($s in ($Initial -split ',')) {
        $path = if ($i -eq 0) { '\' } else { "\Other$i\" }
        [void] $global:Tasks.Add([pscustomobject]@{ TaskName = $TaskName; TaskPath = $path; State = $s })
        $i++
    }
}
function global:Set-RootTask([string] $State) {
    foreach ($t in @($global:Tasks | Where-Object { $_.TaskPath -eq '\' })) { $global:Tasks.Remove($t) }
    [void] $global:Tasks.Add([pscustomobject]@{ TaskName = $global:Expected; TaskPath = '\'; State = $State })
}

function global:Get-ScheduledTask {
    param([string] $TaskName, [string] $TaskPath, $ErrorAction)
    if ($TaskName -ne $global:Expected) { throw "stub: unexpected task name '$TaskName'" }
    [void] $global:Calls.Add('get')
    $global:Tasks | Where-Object { -not $TaskPath -or $_.TaskPath -eq $TaskPath }
}
function global:Export-ScheduledTask {
    param([string] $TaskName, [string] $TaskPath)
    [void] $global:Calls.Add('export')
    $t = @($global:Tasks | Where-Object { $_.TaskPath -eq $TaskPath })[0]
    $enabled = if ($t.State -eq 'Disabled') { 'false' } else { 'true' }
    "<Task><Settings><Enabled>$enabled</Enabled></Settings></Task>"
}
function global:Unregister-ScheduledTask {
    param([string] $TaskName, $Confirm)
    [void] $global:Calls.Add('unregister')
    $global:Tasks.Clear()
}
function global:Register-ScheduledTask {
    param($TaskName, $Action, $Trigger, $Settings, $Principal, $Description, $Xml)
    if ($Xml) {
        [void] $global:Calls.Add('register-xml')
        Set-RootTask $(if ($Xml -match '<Enabled>false</Enabled>') { 'Disabled' } else { 'Ready' })
        return [pscustomobject]@{ TaskName = $TaskName }
    }
    if ($global:FailNext) {
        $global:FailNext = $false
        [void] $global:Calls.Add('register-failed')
        throw 'stub: registration failed'
    }
    [void] $global:Calls.Add('register')
    $global:Registered = [pscustomobject]@{
        name     = [string] $TaskName
        enabled  = [bool] $Settings.Enabled
        triggers = @($Trigger).Count
    }
    Set-RootTask $(if ($global:Honour -and -not $Settings.Enabled) { 'Disabled' } else { 'Ready' })
    [pscustomobject]@{ TaskName = $TaskName }
}
function global:Disable-ScheduledTask {
    param([string] $TaskName)
    [void] $global:Calls.Add('disable')
    if ($global:DisableOk) { foreach ($t in $global:Tasks) { $t.State = 'Disabled' } }
}
function global:Enable-ScheduledTask {
    param([string] $TaskName)
    [void] $global:Calls.Add('enable')
    foreach ($t in $global:Tasks) { $t.State = 'Ready' }
}
function global:Set-ScheduledTask {
    # The script has no reason to call it; if it ever does, fail rather than
    # let the real one change a task.
    throw 'stub: Set-ScheduledTask called'
}

$stubs = 'Get-ScheduledTask', 'Export-ScheduledTask', 'Unregister-ScheduledTask',
         'Register-ScheduledTask', 'Disable-ScheduledTask', 'Enable-ScheduledTask',
         'Set-ScheduledTask'
foreach ($name in $stubs) {
    $cmd = Get-Command $name
    if ($cmd.CommandType -ne 'Function' -or $cmd.ModuleName) {
        Write-Output "STUB_NOT_IN_EFFECT $name"
        exit 3
    }
}

$err = ''
$iv = @(); $wv = @()
try {
    & $Script -TaskName $TaskName -InstallRoot $InstallRoot -WatchdogScript $WatchdogScript `
        -InformationVariable iv -WarningVariable wv 3>$null 6>$null | Out-Null
} catch {
    $err = $_.Exception.Message
} finally {
    $real = ScheduledTasks\Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($real) {
        ScheduledTasks\Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Output 'LEAKED'
    }
}
$result = [pscustomobject]@{
    calls      = @($global:Calls)
    registered = $global:Registered
    final      = (@($global:Tasks | ForEach-Object { [string] $_.State }) -join ',')
    output     = (@($iv) + @($wv) | ForEach-Object { [string] $_ }) -join "`n"
    error      = $err
}
Write-Output ('RESULT ' + ($result | ConvertTo-Json -Compress -Depth 4))
"""


def _register(
    tmp_path: Path,
    *,
    initial: str,
    honour_enabled: bool = True,
    disable_works: bool = True,
    register_fails: bool = False,
) -> dict:
    """Run the shipped register_watchdog.ps1 once against a stubbed Task Scheduler."""
    harness = tmp_path / "register_harness.ps1"
    harness.write_text(_REGISTER_HARNESS, encoding="utf-8")
    watchdog_dir = tmp_path / "watchdog"          # no hidden launcher in here
    watchdog_dir.mkdir()
    watchdog = watchdog_dir / "monclub_access_watchdog.ps1"
    watchdog.write_text("# stand-in; never run\n", encoding="utf-8")
    task = f"MonClub TEST {uuid.uuid4().hex}"

    out = subprocess.run(
        [winps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(harness),
         "-Script", str(REGISTER),
         "-TaskName", task,
         "-InstallRoot", str(tmp_path / "root"),
         "-WatchdogScript", str(watchdog),
         "-Initial", initial,
         "-HonourEnabled", "yes" if honour_enabled else "no",
         "-DisableWorks", "yes" if disable_works else "no",
         "-RegisterFails", "yes" if register_fails else "no"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert "LEAKED" not in out.stdout, (
        f"a REAL scheduled task {task!r} was registered (and has been removed): "
        f"a stub did not take effect. stdout={out.stdout!r}"
    )
    assert "STUB_NOT_IN_EFFECT" not in out.stdout, out.stdout
    lines = [ln for ln in out.stdout.splitlines() if ln.startswith("RESULT ")]
    assert lines, f"harness gave no result: stdout={out.stdout!r} stderr={out.stderr!r}"
    result = json.loads(lines[-1][len("RESULT "):])
    assert any(c.startswith("register") for c in result["calls"]), (
        f"the script never reached the stubbed Register-ScheduledTask: {result!r}"
    )
    if result["registered"] is not None:
        assert result["registered"]["name"] == task, result
    return result


@pytest.mark.skipif(winps is None, reason="Windows PowerShell (powershell.exe) not available")
@pytest.mark.skipif(not REGISTER.exists(), reason=f"{REGISTER} missing")
class TestRegisterKeepsADisabledTaskDisabled:
    """An update must never switch a disabled watchdog back on.

    The installer runs register_watchdog.ps1 at every install and update where
    "Keep MonClub Access running" is ticked -- and UsePreviousTasks=yes re-ticks
    it wherever it was ticked before. The script removes the task and registers a
    new one, which came back ENABLED: an operator's Disable-ScheduledTask (the
    cutover runbook's C1 / D1) was undone by the next install, and the watchdog
    then started Access again a few minutes after every Quit.
    """

    def test_a_disabled_task_is_registered_again_disabled(self, tmp_path: Path):
        r = _register(tmp_path, initial="Disabled")
        assert r["error"] == "", r
        assert r["registered"]["enabled"] is False, (
            f"the task was re-registered ENABLED over a disabled one: {r!r}"
        )
        assert r["final"] == "Disabled"
        assert "enable" not in r["calls"]
        assert re.search(r"State:\s+Disabled \(kept\)", r["output"]), r["output"]

    def test_it_is_disabled_again_if_windows_registers_it_enabled(self, tmp_path: Path):
        """Settings.Enabled = $false not honoured -> an explicit Disable-ScheduledTask."""
        r = _register(tmp_path, initial="Disabled", honour_enabled=False)
        assert r["error"] == "", r
        assert "disable" in r["calls"]
        assert r["calls"].index("register") < r["calls"].index("disable")
        assert r["final"] == "Disabled"

    def test_it_fails_loudly_when_the_task_cannot_be_kept_disabled(self, tmp_path: Path):
        r = _register(tmp_path, initial="Disabled", honour_enabled=False, disable_works=False)
        assert "could not be kept disabled" in r["error"], r
        assert "Disable-ScheduledTask" in r["error"]

    def test_a_failed_registration_puts_the_disabled_task_back(self, tmp_path: Path):
        """The old task is removed before the new one is registered. Without the
        put-back, a failed registration left no task at all, and the NEXT update
        (box still ticked) registered a new, enabled one."""
        r = _register(tmp_path, initial="Disabled", register_fails=True)
        calls = r["calls"]
        assert calls.index("export") < calls.index("unregister") < calls.index("register-failed")
        assert calls.index("register-failed") < calls.index("register-xml"), calls
        assert r["final"] == "Disabled", r
        assert "stub: registration failed" in r["error"], (
            f"the failure must still be reported, not swallowed: {r!r}"
        )
        assert "put back" in r["output"], r["output"]

    def test_a_disabled_task_in_another_folder_also_counts(self, tmp_path: Path):
        """Get-ScheduledTask -TaskName finds the name in every folder; any
        disabled one keeps the new registration disabled (the safe side)."""
        r = _register(tmp_path, initial="Ready,Disabled")
        assert r["error"] == "", r
        assert r["registered"]["enabled"] is False, r
        assert r["final"] == "Disabled"

    def test_the_disabled_task_still_gets_the_new_definition(self, tmp_path: Path):
        """Kept off, but not frozen: the action and both triggers are refreshed,
        so a later Enable-ScheduledTask turns on the current watchdog, not an old one."""
        r = _register(tmp_path, initial="Disabled")
        assert r["calls"].index("unregister") < r["calls"].index("register")
        assert "register-xml" not in r["calls"]
        assert r["registered"]["triggers"] == 2

    def test_an_enabled_task_stays_enabled(self, tmp_path: Path):
        r = _register(tmp_path, initial="Ready")
        assert r["error"] == "", r
        assert r["registered"]["enabled"] is True
        assert r["final"] == "Ready"
        assert "disable" not in r["calls"]
        assert re.search(r"State:\s+Enabled", r["output"]), r["output"]

    def test_a_first_registration_is_enabled(self, tmp_path: Path):
        r = _register(tmp_path, initial="none")
        assert r["error"] == "", r
        assert r["registered"]["enabled"] is True
        assert r["final"] == "Ready"
        assert "unregister" not in r["calls"] and "disable" not in r["calls"]
        assert "export" not in r["calls"]


def _iss_section(text: str, name: str) -> list[str]:
    """The non-comment lines of one [Section] of the .iss, continuations joined."""
    lines: list[str] = []
    inside = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            inside = line.lower() == f"[{name.lower()}]"
            continue
        if not inside or not line or line.startswith(";"):
            continue
        if lines and lines[-1].endswith("\\"):
            lines[-1] = lines[-1][:-1].rstrip() + " " + line
        else:
            lines.append(line)
    return lines


def _iscc() -> str | None:
    """ISCC.exe, found the way build_installer.ps1 finds it."""
    import os
    for candidate in (
        os.environ.get("INNO_ISCC", ""),
        r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        r"C:\Program Files\Inno Setup 6\ISCC.exe",
    ):
        if candidate and Path(candidate).is_file():
            return candidate
    return shutil.which("ISCC.exe")


@pytest.mark.skipif(not INSTALLER.exists(), reason=f"{INSTALLER} missing")
class TestInstallerWatchdogTask:
    """"Keep MonClub Access running": ticked for a NEW install, and an existing
    install keeps its previous choice (owner decision, 2026-09-26).

    What Inno Setup does with these lines is its own code, not ours, read from
    its source (Setup.WizardForm.pas, TWizardForm.CreateTaskButtons, tag
    is-6_5_4): each entry starts from its base state (ticked unless
    ``unchecked``); a task in the previous install's "Selected Tasks" is then
    set to ``not checkedonce``, one in "Deselected Tasks" to unticked; a task in
    neither keeps its base state. So ``checkedonce`` is the WRONG flag here --
    it unticks a site that opted in -- and a plain ticked entry would tick the
    box on the first update of every PC whose version predates it (no
    ``access_*`` tag contains it yet). These tests pin the lines that give the
    owner's rule; the compile test proves ISCC accepts them.
    """

    def _tasks(self) -> list[str]:
        text = INSTALLER.read_text(encoding="utf-8", errors="replace")
        return [ln for ln in _iss_section(text, "Tasks") if re.search(r'Name:\s*"watchdog"', ln)]

    def test_use_previous_tasks_stays_on(self):
        text = INSTALLER.read_text(encoding="utf-8", errors="replace")
        setup = [ln.replace(" ", "").lower() for ln in _iss_section(text, "Setup")]
        assert "useprevioustasks=yes" in setup, (
            "without UsePreviousTasks=yes an update forgets the previous choice"
        )

    def test_ticked_only_when_the_install_is_new(self):
        tasks = self._tasks()
        assert len(tasks) == 2, f"expected the two watchdog entries, got: {tasks!r}"
        fresh = [ln for ln in tasks if re.search(r"Check:\s*IsFreshInstall\b", ln)]
        existing = [ln for ln in tasks if re.search(r"Check:\s*not\s+IsFreshInstall\b", ln)]
        assert len(fresh) == 1 and len(existing) == 1, tasks
        assert "unchecked" not in fresh[0], f"a new install must get it ticked: {fresh[0]!r}"
        assert re.search(r"Flags:[^;]*\bunchecked\b", existing[0]), (
            f"an existing install with no recorded choice must get it unticked: {existing[0]!r}"
        )

    def test_checkedonce_is_not_used(self):
        for ln in self._tasks():
            assert "checkedonce" not in ln.lower(), (
                f"checkedonce unticks a previously ticked box on every update: {ln!r}"
            )

    def test_a_new_install_means_no_trace_of_an_old_one(self):
        text = INSTALLER.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"function IsFreshInstall\(\): Boolean;.*?\nend;", text, re.S)
        assert m, "IsFreshInstall is gone from the [Code] section"
        body = m.group(0)
        # Both traces must be ABSENT for "new": an `or`, or a dropped `not`, would
        # tick the box on an existing install that left only one of them behind.
        assert re.search(
            r"Result\s*:=\s*\(\s*not\s+ExistingInstallDetected\s*\)\s+and\s+"
            r"\(\s*WizardForm\.PrevAppDir\s*=\s*''\s*\)\s*;",
            body,
        ), body

    def test_the_register_script_runs_only_when_the_box_is_ticked(self):
        text = INSTALLER.read_text(encoding="utf-8", errors="replace")
        runs = [ln for ln in _iss_section(text, "Run") if "register_watchdog.ps1" in ln]
        assert len(runs) == 1, runs
        assert re.search(r"Tasks:\s*watchdog\b", runs[0]), runs[0]
        assert "-Remove" not in runs[0]

    def test_the_hidden_launcher_ships_next_to_the_scripts(self):
        """register_watchdog.ps1 looks for it beside the watchdog script."""
        text = INSTALLER.read_text(encoding="utf-8", errors="replace")
        files = _iss_section(text, "Files")
        for name in ("monclub_access_watchdog.ps1", "register_watchdog.ps1",
                     "monclub_access_watchdog_hidden.vbs"):
            hits = [ln for ln in files if name in ln]
            assert len(hits) == 1, f"{name}: {hits!r}"
            assert re.search(r'DestDir:\s*"\{app\}\\watchdog"', hits[0]), hits[0]

    @pytest.mark.skipif(_iscc() is None, reason="Inno Setup (ISCC.exe) not installed")
    def test_the_installer_compiles(self, tmp_path: Path):
        stage = tmp_path / "stage" / "MonClubAccess"
        stage.mkdir(parents=True)
        (stage / "MonClubAccess.exe").write_text("stub")
        out = subprocess.run(
            [_iscc(), f"/O{tmp_path / 'out'}", "/DAppVersion=0.0.0-test",
             f"/DStageDir={stage}", "/DOutputBaseFilename=compile_test", str(INSTALLER)],
            capture_output=True, text=True, timeout=300, check=False,
        )
        assert out.returncode == 0, f"ISCC failed:\n{out.stdout}\n{out.stderr}"
        assert (tmp_path / "out" / "compile_test.exe").is_file()

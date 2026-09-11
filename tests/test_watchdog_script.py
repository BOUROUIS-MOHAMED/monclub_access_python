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
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "packaging" / "watchdog" / "monclub_access_watchdog.ps1"

pwsh = shutil.which("pwsh") or shutil.which("powershell")
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

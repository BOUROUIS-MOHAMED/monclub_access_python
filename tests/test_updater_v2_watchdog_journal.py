"""Updater v2 (lane L2, design.md section 8 step 12): the watchdog applies the install-journal
rule BEFORE its pause-sentinel and exe-missing guards -- a power cut mid-swap leaves both a
fresh-looking sentinel and a missing exe, which would otherwise stand it down for good."""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only")

REPO = Path(__file__).resolve().parents[1]
WATCHDOG = REPO / "packaging" / "watchdog" / "monclub_access_watchdog.ps1"
HELPER = REPO / "installer" / "update_helper.ps1"
POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"


def tick(root: Path) -> str:
    log = root / "logs" / "watchdog.log"
    before = len(log.read_text(encoding="utf-8-sig").splitlines()) if log.exists() else 0
    subprocess.run([str(POWERSHELL), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(WATCHDOG),
                    "-InstallRoot", str(root), "-HelperPath", str(HELPER), "-WhatIfOnly"],
                   capture_output=True, text=True, timeout=120)
    return "\n".join(log.read_text(encoding="utf-8-sig").splitlines()[before:]) if log.exists() else ""


def utc(minutes: float) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def payload(folder: Path, version: str) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "MonClubAccess.exe").write_bytes(b"exe " + version.encode())
    (folder / "version.json").write_text(json.dumps({"version": version}), encoding="utf-8")


def journal(root: Path, phase: str, at: str) -> None:
    (root / "state").mkdir(parents=True, exist_ok=True)
    (root / "state" / "install_journal.json").write_text(
        json.dumps({"phase": phase, "from": "1.4.35", "to": "1.5.0", "at": at, "setupPid": 0}), encoding="ascii")


def test_power_cut_mid_copy_is_rolled_back_although_exe_is_missing_and_sentinel_is_fresh(tmp_path: Path):
    payload(tmp_path / "previous", "1.4.35")
    (tmp_path / "current").mkdir()
    (tmp_path / "current" / "half.dll").write_bytes(b"x")
    (tmp_path / ".update-in-progress").write_text("install in progress")  # fresh
    journal(tmp_path, "copying", utc(-20))
    out = tick(tmp_path)
    assert "rolled back to previous" in out, out
    assert (tmp_path / "current" / "MonClubAccess.exe").read_bytes() == b"exe 1.4.35"
    assert not (tmp_path / "current" / "half.dll").exists()
    assert not (tmp_path / ".update-in-progress").exists()
    last = json.loads((tmp_path / "state" / "last_update.json").read_text(encoding="ascii"))
    assert (last["result"], last["reason"], last["to"]) == ("ROLLED_BACK", "interrupted", "1.4.35")


def test_a_stale_journal_is_recovered_even_while_a_broken_exe_sits_running_in_current(tmp_path: Path):
    r"""Review #2: after a power cut mid-copy the new exe may already be in current\ with
    _internal\ incomplete; started by the Run key it hangs on PyInstaller's error box and
    a name-only 'running' check called it healthy for ever. Stand-in: ping.exe renamed."""
    import shutil
    import subprocess as sp
    payload(tmp_path / "previous", "1.4.35")
    (tmp_path / "current").mkdir()
    stuck = tmp_path / "current" / "MonClubAccess.exe"
    shutil.copy(Path(os.environ["SystemRoot"]) / "System32" / "PING.EXE", stuck)
    proc = sp.Popen([str(stuck), "-n", "120", "127.0.0.1"], stdout=sp.DEVNULL, cwd=str(tmp_path / "current"))
    try:
        journal(tmp_path, "copying", utc(-20))
        out = tick(tmp_path)
        assert "rolled back to previous" in out, out
        assert proc.wait(timeout=30) is not None  # the stuck process was stopped by the restore
        assert stuck.read_bytes() == b"exe 1.4.35"
    finally:
        if proc.poll() is None:
            proc.kill()


def test_a_fresh_journal_makes_the_watchdog_stand_down(tmp_path: Path):
    payload(tmp_path / "previous", "1.4.35")
    payload(tmp_path / "current", "1.5.0")
    journal(tmp_path, "verifying", utc(-1))
    out = tick(tmp_path)
    assert "not stale yet" in out and "standing down" in out, out
    assert (tmp_path / "state" / "install_journal.json").exists()
    assert (tmp_path / "current" / "MonClubAccess.exe").read_bytes() == b"exe 1.5.0"


def test_a_stale_backing_up_journal_is_dropped_and_the_normal_checks_go_on(tmp_path: Path):
    payload(tmp_path / "current", "1.4.35")
    journal(tmp_path, "backing_up", utc(-20))
    out = tick(tmp_path)
    assert "exit 21" in out, out
    assert "miss 1/2" in out, out  # the ordinary two-tick confirmation follows
    assert (tmp_path / "current" / "MonClubAccess.exe").read_bytes() == b"exe 1.4.35"
    assert not (tmp_path / "state" / "install_journal.json").exists()


def test_a_live_restore_claim_makes_the_watchdog_stand_down_without_starting_the_app(tmp_path: Path):
    import subprocess as sp
    import sys
    payload(tmp_path / "previous", "1.4.35")
    (tmp_path / "current").mkdir()
    (tmp_path / "state").mkdir()
    alive = sp.Popen([str(POWERSHELL), "-NoProfile", "-Command", "Start-Sleep -Seconds 60"])
    try:
        (tmp_path / "state" / f"install_journal.restoring-{alive.pid}.json").write_text("{}", encoding="ascii")
        out = tick(tmp_path)
        assert "restore is in progress -- standing down" in out, out
        assert not (tmp_path / "current" / "MonClubAccess.exe").exists()
    finally:
        alive.kill()
        alive.wait()


def test_installed_watchdog_finds_the_helper_beside_itself(tmp_path: Path):
    """Run it the INSTALLED way: script and helper side by side in {app}\\watchdog and no
    -HelperPath. The E2E run found that default broken: $PSScriptRoot is empty inside a
    param() default under Windows PowerShell 5.1, so every tick died."""
    iss = (REPO / "installer" / "MonClubAccess.iss").read_text(encoding="utf-8")
    assert 'Source: "update_helper.ps1"; DestDir: "{app}\\watchdog"' in iss
    import shutil
    wd = tmp_path / "watchdog"
    wd.mkdir()
    shutil.copy(WATCHDOG, wd / WATCHDOG.name)
    shutil.copy(HELPER, wd / HELPER.name)
    payload(tmp_path / "previous", "1.4.35")
    (tmp_path / "current").mkdir()
    journal(tmp_path, "copying", utc(-20))
    r = subprocess.run([str(POWERSHELL), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                        str(wd / WATCHDOG.name), "-InstallRoot", str(tmp_path), "-WhatIfOnly"],
                       capture_output=True, text=True, timeout=120)
    log = tmp_path / "logs" / "watchdog.log"
    out = log.read_text(encoding="utf-8-sig") if log.exists() else ""
    assert "rolled back to previous" in out, out + r.stdout + r.stderr
    assert (tmp_path / "current" / "MonClubAccess.exe").read_bytes() == b"exe 1.4.35"

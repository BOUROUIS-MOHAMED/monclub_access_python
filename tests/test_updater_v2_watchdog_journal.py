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


def test_a_fresh_journal_makes_the_watchdog_stand_down(tmp_path: Path):
    payload(tmp_path / "previous", "1.4.35")
    payload(tmp_path / "current", "1.5.0")
    journal(tmp_path, "verifying", utc(-1))
    out = tick(tmp_path)
    assert "not stale yet -- standing down" in out, out
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


def test_installed_watchdog_finds_the_helper_beside_itself():
    # MonClubAccess.iss installs update_helper.ps1 into {app}\watchdog, next to the script.
    iss = (REPO / "installer" / "MonClubAccess.iss").read_text(encoding="utf-8")
    assert 'Source: "update_helper.ps1"; DestDir: "{app}\\watchdog"' in iss
    src = WATCHDOG.read_text(encoding="utf-8")
    assert "Join-Path $PSScriptRoot 'update_helper.ps1'" in src

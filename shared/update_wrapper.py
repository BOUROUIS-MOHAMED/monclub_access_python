"""Hidden PowerShell helpers that outlive the app (design section 7; D24, D36).

STANDARD LIBRARY ONLY (imported by the start-up journal check).

Install wrapper: wait for the app to exit -> run Setup with /LOG and wait for it -> if
Setup failed without writing a result, write ``ABORTED setup_exit_<code>`` -> if no
``<exe>`` is running from ``{app}\\current``, start it. This brings the old version back
after every Setup abort that happens before any installer code runs (corrupt exe, Windows
version, user cancel) -- the case nothing covered before (D24).

Restore helper: the start-up journal check's external half -- the running app cannot
overwrite its own locked files in ``current\\``.

Both start with cwd = ``{app}\\state`` and pass ``-WorkingDirectory`` explicitly, never
``{app}\\current``: Windows refuses to rename a folder that is a live process's working
directory (design 8.0). The relaunched app gets ``-WorkingDirectory {app}\\current``, as
the watchdog and Setup start it.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import List, Optional, Sequence

APP_EXIT_WAIT_MS = 90_000


def _ps(value: object) -> str:
    """A PowerShell single-quoted literal."""
    return "'" + str(value).replace("'", "''") + "'"


def _json_str(value: object) -> str:
    """A JSON string literal (ASCII-only, so the file is plain ASCII whatever the path)."""
    return json.dumps(str(value), ensure_ascii=True)


def powershell_exe() -> str:
    # Full path: this PC sets NoDefaultCurrentDirectoryInExePath, and a bare name would be
    # resolved through PATH.
    root = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    return str(Path(root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")


def _prelude(log_path: Path) -> List[str]:
    return [
        "$ErrorActionPreference = 'Continue'",
        f"$log = {_ps(log_path)}",
        "function W([string]$m) { try { $d = Split-Path -Parent $log; "
        "if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }; "
        "Add-Content -LiteralPath $log -Value ((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') + ' ' + $m) } catch {} }",
        "function NowZ { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }",
    ]


def _wait_for_pid(pid: int) -> List[str]:
    return [
        f"$app = Get-Process -Id {int(pid)} -ErrorAction SilentlyContinue",
        f"if ($app) {{ if (-not $app.WaitForExit({APP_EXIT_WAIT_MS})) {{ W 'app pid {int(pid)} still running after {APP_EXIT_WAIT_MS // 1000} s; continuing' }} }}",
    ]


def _relaunch_if_not_running(current_dir: Path, exe_name: str) -> List[str]:
    exe = current_dir / exe_name
    return [
        f"$exe = {_ps(exe)}",
        "$running = $false",
        "try {",
        f"  $found = Get-CimInstance Win32_Process -Filter {_ps('Name=' + chr(39) + exe_name.replace(chr(39), '') + chr(39))} -ErrorAction Stop",
        "  foreach ($q in $found) { if ($q.ExecutablePath -and ($q.ExecutablePath -ieq $exe)) { $running = $true } }",
        "} catch {",
        f"  foreach ($q in (Get-Process -Name {_ps(Path(exe_name).stem)} -ErrorAction SilentlyContinue)) {{ try {{ if ($q.Path -ieq $exe) {{ $running = $true }} }} catch {{ $running = $true }} }}",
        "}",
        "if ($running) { W 'app is running from current; nothing to relaunch' }",
        "elseif (Test-Path -LiteralPath $exe) {",
        f"  try {{ Start-Process -FilePath $exe -WorkingDirectory {_ps(current_dir)} | Out-Null; W ('relaunched ' + $exe) }} catch {{ W ('relaunch failed: ' + $_) }}",
        "} else { W ('nothing to relaunch: missing ' + $exe) }",
    ]


def build_install_script(
    *,
    app_pid: int,
    installer: Path,
    install_root: Path,
    exe_name: str,
    from_version: str,
    to_version: str,
    setup_log: Path,
    wrapper_log: Path,
) -> str:
    state_dir = install_root / "state"
    current_dir = install_root / "current"
    last_update = state_dir / "last_update.json"
    # One -ArgumentList string: the legacy root "MonClub Access" has a space, and /LOG
    # must reach Setup as a single quoted argument.
    setup_args = f'/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG="{setup_log}"'
    aborted_json_head = (
        '{"result":"ABORTED","from":' + _json_str(from_version) + ',"to":' + _json_str(to_version)
        + ',"log":' + _json_str(setup_log) + ',"reason":"setup_exit_'
    )
    lines = _prelude(wrapper_log) + [
        f"W ('wrapper start: app pid {int(app_pid)}, installer ' + {_ps(installer)})",
    ] + _wait_for_pid(app_pid) + [
        "$started = (Get-Date).ToUniversalTime()",
        "$code = $null",
        "try {",
        f"  $p = Start-Process -FilePath {_ps(installer)} -ArgumentList {_ps(setup_args)} -WorkingDirectory {_ps(state_dir)} -PassThru -ErrorAction Stop",
        # Touch Handle so ExitCode is kept after exit; WaitForExit on the Setup stub only
        # (Start-Process -Wait would also wait for the app Setup starts).
        "  $null = $p.Handle",
        "  $p.WaitForExit()",
        "  $code = $p.ExitCode",
        "  W ('setup exit ' + $code)",
        "} catch { W ('setup did not start: ' + $_); $code = -1 }",
        "if ($code -ne 0) {",
        f"  $lu = {_ps(last_update)}",
        "  $fresh = $false",
        "  if (Test-Path -LiteralPath $lu) { $fresh = ((Get-Item -LiteralPath $lu).LastWriteTimeUtc -ge $started) }",
        "  if (-not $fresh) {",
        f"    $j = {_ps(aborted_json_head)} + $code + '\",\"at\":\"' + (NowZ) + '\"}}'",
        "    try { [IO.File]::WriteAllText($lu, $j); W 'wrote ABORTED result' } catch { W ('could not write result: ' + $_) }",
        "  }",
        "}",
    ] + _relaunch_if_not_running(current_dir, exe_name) + ["W 'wrapper end'"]
    return "\n".join(lines)


def build_restore_script(
    *,
    app_pid: int,
    install_root: Path,
    exe_name: str,
    journal_from: str,
    journal_to: str,
    restore_log: Path,
) -> str:
    """Copy ``previous\\*`` back over ``current\\`` after an interrupted install (design 8.0)."""
    state_dir = install_root / "state"
    current_dir = install_root / "current"
    previous_dir = install_root / "previous"
    journal = state_dir / "install_journal.json"
    last_update = state_dir / "last_update.json"
    # The journal's "to" is the version that was being installed (now abandoned).
    result_head = (
        '{"result":"ROLLED_BACK","from":' + _json_str(journal_to) + ',"to":' + _json_str(journal_from)
        + ',"reason":"interrupted","log":' + _json_str(restore_log) + ',"at":"'
    )
    lines = _prelude(restore_log) + [
        f"W ('restore start: app pid {int(app_pid)}')",
    ] + _wait_for_pid(app_pid) + [
        f"$cur = {_ps(current_dir)}",
        f"$prev = {_ps(previous_dir)}",
        "$ok = $false",
        "for ($i = 0; $i -lt 15 -and -not $ok; $i++) {",
        "  try {",
        "    if (-not (Test-Path -LiteralPath $cur)) { New-Item -ItemType Directory -Path $cur -Force | Out-Null }",
        "    Get-ChildItem -LiteralPath $cur -Force | Remove-Item -Recurse -Force -ErrorAction Stop",
        "    Get-ChildItem -LiteralPath $prev -Force | Copy-Item -Destination $cur -Recurse -Force -ErrorAction Stop",
        "    $ok = $true",
        "  } catch { W ('restore attempt ' + $i + ' failed: ' + $_); Start-Sleep -Seconds 1 }",
        "}",
        "if ($ok) {",
        f"  try {{ [IO.File]::WriteAllText({_ps(last_update)}, ({_ps(result_head)} + (NowZ) + '\"}}')) }} catch {{ W ('could not write result: ' + $_) }}",
        f"  Remove-Item -LiteralPath {_ps(journal)} -Force -ErrorAction SilentlyContinue",
        "  W 'restored previous into current'",
        "} else { W 'RESTORE FAILED: journal kept for the watchdog / next start' }",
    ] + _relaunch_if_not_running(current_dir, exe_name) + ["W 'restore end'"]
    return "\n".join(lines)


def powershell_command(script: str) -> List[str]:
    return [
        powershell_exe(),
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-WindowStyle",
        "Hidden",
        "-Command",
        script,
    ]


class HelperLaunchError(RuntimeError):
    pass


def launch_hidden_powershell(
    script: str,
    *,
    cwd: Path,
    popen=subprocess.Popen,
    settle_sec: float = 0.5,
    sleep=time.sleep,
) -> int:
    """Start the helper and prove it is alive after ``settle_sec``. Returns its pid.

    Raises HelperLaunchError when it could not start or already exited -- the caller must
    then keep the app running (D1)."""
    Path(cwd).mkdir(parents=True, exist_ok=True)
    creationflags = 0
    if os.name == "nt":
        # No DETACHED_PROCESS: PowerShell spawned with it runs nothing (found 2026-03).
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    try:
        proc = popen(
            powershell_command(script),
            cwd=str(cwd),
            close_fds=True,
            creationflags=creationflags,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        raise HelperLaunchError(f"could not start PowerShell: {exc}") from exc
    if settle_sec > 0:
        sleep(settle_sec)
    code = proc.poll()
    if code is not None:
        raise HelperLaunchError(f"PowerShell helper exited immediately (code {code})")
    return int(getattr(proc, "pid", 0) or 0)


def setup_log_path(install_root: Path, version: str, *, now: Optional[float] = None) -> Path:
    stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime(time.time() if now is None else now))
    safe_version = "".join(ch for ch in str(version) if ch.isalnum() or ch in ".-") or "unknown"
    return install_root / "logs" / f"update-{safe_version}-{stamp}.log"


__all__: Sequence[str] = [
    "HelperLaunchError",
    "build_install_script",
    "build_restore_script",
    "launch_hidden_powershell",
    "powershell_command",
    "powershell_exe",
    "setup_log_path",
]

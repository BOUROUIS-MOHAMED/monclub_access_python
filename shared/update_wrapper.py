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
# Setup's own worst case: backup + copy + a 300 s health wait + a restore.
SETUP_WAIT_MS = 30 * 60 * 1000
# shared/update_files.py::SETUP_IMAGE_RE for PowerShell -match (case-insensitive by default).
SETUP_IMAGE_PS_RE = r"^monclub_(access|tv)_[0-9][0-9A-Za-z._\-]*\.(exe|tmp)$"


# The Tauri UI that runs beside each app (installer/*.iss TauriExe): it can outlive the app and
# lock current\ui\, so a restore stops it too (update_helper.ps1 -UiExe).
UI_EXE_FOR = {"monclubaccess.exe": "monclub-access-ui.exe", "monclubtv.exe": "monclub-tv-ui.exe"}
HELPER_WAIT_MS = 15 * 60 * 1000


def setup_image_ps_re(target: Optional[str]) -> str:
    """SETUP_IMAGE_PS_RE for one product (an Access wrapper never waits for / stops TV's Setup)."""
    if not target:
        return SETUP_IMAGE_PS_RE
    safe = "".join(ch for ch in str(target).lower() if ch.isalnum())
    return rf"^monclub_{safe}_[0-9][0-9A-Za-z._\-]*\.(exe|tmp)$"


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
        "Add-Content -LiteralPath $log -Value ((NowZ) + ' ' + $m) } catch {} }",
        # Invariant culture: a PC set to ar-SA would otherwise write a Hijri year, and ':'
        # is the culture's time separator in .NET custom formats (L2 found it, 2026-10-09).
        "function NowZ { (Get-Date).ToUniversalTime().ToString(\"yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'\", "
        "[Globalization.CultureInfo]::InvariantCulture) }",
    ]


def _wait_for_pid(pid: int) -> List[str]:
    # The wrapper is the app's child and Setup will be the wrapper's: Setup's
    # "taskkill /F /T /IM <exe>" on a still-running app would kill this whole tree, Setup's
    # own .tmp included, before any journal exists (L4 review M1). So an app that has not
    # exited after 90 s is stopped here -- that pid only -- before Setup starts.
    return [
        f"$app = Get-Process -Id {int(pid)} -ErrorAction SilentlyContinue",
        f"if ($app) {{ if (-not $app.WaitForExit({APP_EXIT_WAIT_MS})) {{ W 'app pid {int(pid)} still running after {APP_EXIT_WAIT_MS // 1000} s; stopping that pid only'; "
        f"try {{ Stop-Process -Id {int(pid)} -Force -ErrorAction Stop }} catch {{ W ('stop failed: ' + $_) }}; $null = $app.WaitForExit(10000) }} }}",
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
    setup_image_re: str = SETUP_IMAGE_PS_RE,
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
    lines = _prelude(wrapper_log) + _setup_functions(setup_image_re) + _restore_function(install_root, exe_name) + [
        f"W ('wrapper start: app pid {int(app_pid)}, installer ' + {_ps(installer)})",
    ] + _wait_for_pid(app_pid) + [
        "$started = (Get-Date).ToUniversalTime()",
        "$code = $null",
        "try {",
        f"  $p = Start-Process -FilePath {_ps(installer)} -ArgumentList {_ps(setup_args)} -WorkingDirectory {_ps(state_dir)} -PassThru -ErrorAction Stop",
        # Touch Handle so ExitCode is kept after exit; WaitForExit on the Setup stub only
        # (Start-Process -Wait would also wait for the app Setup starts).
        "  $null = $p.Handle",
        # Bounded: a hung Setup must not keep the gym without its app forever.
        f"  if ($p.WaitForExit({SETUP_WAIT_MS})) {{ $code = $p.ExitCode; W ('setup exit ' + $code) }}",
        "  else {",
        f"    W 'setup still running after {SETUP_WAIT_MS // 60000} min: stopping it'",
        "    Stop-Setups",
        "    $code = -2",
        "  }",
        "} catch { W ('setup did not start: ' + $_); $code = -1 }",
        "if ($code -ne 0) {",
        f"  $lu = {_ps(last_update)}",
        "  $fresh = $false",
        "  if (Test-Path -LiteralPath $lu) { $fresh = ((Get-Item -LiteralPath $lu).LastWriteTimeUtc -ge $started) }",
        # The relaunched old app may already have consumed Setup's result (renamed to
        # last_update.consumed.json, which keeps the mtime): it is fresh too (L4 review M3).
        f"  $luc = {_ps(state_dir / 'last_update.consumed.json')}",
        "  if (-not $fresh -and (Test-Path -LiteralPath $luc)) { $fresh = ((Get-Item -LiteralPath $luc).LastWriteTimeUtc -ge $started) }",
        "  if (-not $fresh) {",
        f"    $j = {_ps(aborted_json_head)} + $code + '\",\"at\":\"' + (NowZ) + '\"}}'",
        "    try { [IO.File]::WriteAllText($lu, $j); W 'wrote ABORTED result' } catch { W ('could not write result: ' + $_) }",
        "  }",
        "}",
        # Setup killed or crashed mid-copy leaves its journal: never start a half-written
        # current (design 8.0 claim rule).
        "$outcome = Restore-Journal",
        "if ($outcome -ne 'none') { W ('journal after Setup: ' + $outcome) }",
        "if ($outcome -eq 'backoff') { W 'another restorer starts the app'; W 'wrapper end'; exit 0 }",
    ] + _relaunch_if_not_running(current_dir, exe_name) + ["W 'wrapper end'"]
    return "\n".join(lines)


def _setup_functions(setup_image_re: str) -> List[str]:
    """``Get-Setups`` / ``Stop-Setups``: MonClub Setup processes by image name, the rule of
    shared/update_files.py::SETUP_IMAGE_RE (the stub .exe and Inno's .tmp worker)."""
    return [
        "function Get-Setups { try { @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { "
        f"$_.Name -match {_ps(setup_image_re)} }}) }} catch {{ @() }} }}",
        # Stop each Setup and its child processes (Setup's update_helper PowerShell and its robocopy
        # would keep writing current), then wait for them to be gone before any restore (L4 review L4).
        "function Stop-Setups { $ids = @(); foreach ($q in (Get-Setups)) { $ids += [int]$q.ProcessId; "
        "try { foreach ($c in @(Get-CimInstance Win32_Process -Filter ('ParentProcessId=' + $q.ProcessId) -ErrorAction Stop)) { "
        "$ids += [int]$c.ProcessId; foreach ($g in @(Get-CimInstance Win32_Process -Filter ('ParentProcessId=' + $c.ProcessId) -ErrorAction SilentlyContinue)) { $ids += [int]$g.ProcessId } } } catch {} }; "
        "foreach ($i in $ids) { try { Stop-Process -Id $i -Force -ErrorAction Stop; W ('stopped pid ' + $i) } catch {} }; "
        "foreach ($i in $ids) { try { Wait-Process -Id $i -Timeout 15 -ErrorAction SilentlyContinue } catch {} } }",
    ]


def _restore_function(install_root: Path, exe_name: str) -> List[str]:
    """PowerShell ``Restore-Journal``: run the INSTALLED ``{app}\\watchdog\\update_helper.ps1 -Action
    recover`` (lane L2, the same code Setup and the watchdog run) and map its exit code -- 0 none, 20
    restored, 21 deleted (current intact), 22 backoff (a live claim, a running Setup, or not stale),
    23/other failed. One implementation of design 8.0: live-claim stand-down, stop the app + UI running
    from current\\, robocopy /MIR previous -> current (L4 review H1: the inline copy below ignored
    claims and deleted current before copying). The inline function remains only for an install
    root without the helper (never a v2 install); it now also backs off on any claim and mirrors.
    """
    helper = install_root / "watchdog" / "update_helper.ps1"
    ui_exe = UI_EXE_FOR.get(exe_name.lower(), "")
    helper_args = (
        f'-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{helper}" -Action recover '
        f'-InstallRoot "{install_root}" -AppExe "{exe_name}" -UiExe "{ui_exe}" '
        f'-LogPath "{install_root / "logs" / "update-recover.log"}"'
    )
    return [
        "function Restore-Journal {",
        f"  $helper = {_ps(helper)}",
        "  if (-not (Test-Path -LiteralPath $helper)) { return (Restore-JournalInline) }",
        "  $rc = -1",
        "  try {",
        f"    $hp = Start-Process -FilePath {_ps(powershell_exe())} -ArgumentList {_ps(helper_args)} "
        f"-WorkingDirectory {_ps(install_root / 'state')} -WindowStyle Hidden -PassThru -ErrorAction Stop",
        "    $null = $hp.Handle",
        f"    if ($hp.WaitForExit({HELPER_WAIT_MS})) {{ $rc = $hp.ExitCode }} else {{ W 'recover helper still running; leaving it'; return 'backoff' }}",
        "  } catch { W ('recover helper did not start: ' + $_); return (Restore-JournalInline) }",
        "  W ('update_helper recover exit ' + $rc)",
        "  switch ($rc) { 0 { return 'none' } 20 { return 'restored' } 21 { return 'deleted' } 22 { return 'backoff' } default { return 'failed' } }",
        "}",
    ] + _restore_inline_function(install_root, exe_name)


def _restore_inline_function(install_root: Path, exe_name: str) -> List[str]:
    """Fallback ``Restore-JournalInline`` -- the journal contract of design 8.0 (L2/L3 2026-10-09).

    Claim first: rename to ``install_journal.restoring-<pid>.json``; a failed rename means
    another restorer (watchdog, Setup, the app) owns it -> back off. ``backing_up`` ->
    current is intact, delete. Otherwise, with a complete previous, copy it back, write
    ``ROLLED_BACK interrupted`` BEFORE anything starts the app, delete the claim. A failed
    restore puts the journal back for the next restorer. Returns
    ``restored`` / ``deleted`` / ``backoff`` / ``failed`` / ``none``."""
    return [
        "function Restore-JournalInline {",
        f"  $state = {_ps(install_root / 'state')}",
        f"  $cur = {_ps(install_root / 'current')}",
        f"  $prev = {_ps(install_root / 'previous')}",
        "  $journal = Join-Path $state 'install_journal.json'",
        # Any claim: another restorer may be copying right now -- never start the app under it.
        "  if (@(Get-ChildItem -LiteralPath $state -Filter 'install_journal.restoring-*.json' -ErrorAction SilentlyContinue).Count -gt 0) "
        "{ W 'a restore claim exists; standing down'; return 'backoff' }",
        "  if (-not (Test-Path -LiteralPath $journal)) { return 'none' }",
        "  if (@(Get-Setups).Count -gt 0) { W 'a Setup is still running; leaving the journal to it'; return 'backoff' }",
        "  $claimName = 'install_journal.restoring-' + $PID + '.json'",
        "  $claim = Join-Path $state $claimName",
        "  try { Rename-Item -LiteralPath $journal -NewName $claimName -ErrorAction Stop }",
        "  catch { W 'journal claimed by another restorer; backing off'; return 'backoff' }",
        # A rename keeps the journal's old LastWriteTime: after a power cut that is before the
        # boot, and the claim would look dead to the next restorer (design 8.0 claim liveness).
        "  try { [IO.File]::SetLastWriteTimeUtc($claim, [DateTime]::UtcNow) } catch { W ('claim not touched: ' + $_) }",
        "  $j = $null",
        "  try { $j = Get-Content -LiteralPath $claim -Raw | ConvertFrom-Json } catch { W ('journal unreadable: ' + $_) }",
        "  $phase = ''; $jfrom = ''; $jto = ''",
        "  if ($j) { $phase = [string]$j.phase; $jfrom = [string]$j.from; $jto = [string]$j.to }",
        "  if ($phase -eq 'backing_up') { Remove-Item -LiteralPath $claim -Force -ErrorAction SilentlyContinue; "
        "W 'journal phase backing_up: current is intact, journal deleted'; return 'deleted' }",
        f"  $complete = (Test-Path -LiteralPath (Join-Path $prev {_ps(exe_name)})) -and "
        "(Test-Path -LiteralPath (Join-Path $prev 'version.json'))",
        "  if (-not $complete) { Remove-Item -LiteralPath $claim -Force -ErrorAction SilentlyContinue; "
        "W 'no complete previous; journal deleted without restore'; return 'deleted' }",
        "  W ('restoring previous into current (phase ' + $phase + ', ' + $jfrom + ' -> ' + $jto + ')')",
        "  $ok = $false",
        "  for ($i = 0; $i -lt 15 -and -not $ok; $i++) {",
        "    try {",
        f"      foreach ($q in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {{ $_.ExecutablePath -and $_.ExecutablePath.ToLower().StartsWith(($cur + '\\').ToLower()) }})) "
        "{ try { Stop-Process -Id $q.ProcessId -Force -ErrorAction Stop; W ('stopped ' + $q.ExecutablePath) } catch {} }",
        "      $robo = Join-Path $env:SystemRoot 'System32\\robocopy.exe'",
        "      $null = & $robo $prev $cur /MIR /COPY:DAT /R:2 /W:1 /NP /NFL /NDL /NJH /NJS",
        "      if ($LASTEXITCODE -ge 8) { throw ('robocopy exit ' + $LASTEXITCODE) }",
        "      $ok = $true",
        "    } catch { W ('restore attempt ' + $i + ' failed: ' + $_); Start-Sleep -Seconds 1 }",
        "  }",
        "  if (-not $ok) {",
        "    try { Rename-Item -LiteralPath $claim -NewName 'install_journal.json' -ErrorAction Stop } catch {}",
        "    W 'RESTORE FAILED: journal kept for the next restorer'; return 'failed'",
        "  }",
        # The journal's "to" is the version that was being installed (now abandoned).
        "  $r = [ordered]@{ result = 'ROLLED_BACK'; from = $jto; to = $jfrom; reason = 'interrupted'; log = $log; at = (NowZ) }",
        "  try { [IO.File]::WriteAllText((Join-Path $state 'last_update.json'), ($r | ConvertTo-Json -Compress)) } "
        "catch { W ('could not write result: ' + $_) }",
        "  Remove-Item -LiteralPath $claim -Force -ErrorAction SilentlyContinue",
        "  W 'restored previous into current'",
        "  return 'restored'",
        "}",
    ]


def build_restore_script(
    *,
    app_pid: int,
    install_root: Path,
    exe_name: str,
    restore_log: Path,
    setup_image_re: str = SETUP_IMAGE_PS_RE,
) -> str:
    """The start-up journal check's external half: the running app cannot overwrite its
    own locked files in current. Waits for the app to exit, restores, relaunches."""
    lines = _prelude(restore_log) + _setup_functions(setup_image_re) + _restore_function(install_root, exe_name) + [
        f"W ('restore helper start: app pid {int(app_pid)}')",
    ] + _wait_for_pid(app_pid) + [
        "$outcome = Restore-Journal",
        "W ('journal: ' + $outcome)",
        "if ($outcome -eq 'backoff') { W 'another restorer starts the app'; W 'restore end'; exit 0 }",
    ] + _relaunch_if_not_running(install_root / "current", exe_name) + ["W 'restore end'"]
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
    "setup_image_ps_re",
    "setup_log_path",
]

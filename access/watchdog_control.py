"""The watchdog's status and on/off switch for Settings (design section 12, owner decision O7).

The watchdog is the per-user scheduled task ``MonClub Access Watchdog`` (registered by
``packaging/watchdog/register_watchdog.ps1``) running ``monclub_access_watchdog.ps1``. The
Windows task's own state IS the preference: Enabled = on, Disabled = off, missing = never
decided. This module

* reads that task through a hidden, time-bounded PowerShell (a per-user task: no admin),
  plus what the watchdog itself records under ``{app}\\logs``: ``watchdog-state.json``
  (``restarts``: epoch seconds of its restarts -- the crash-loop cap is 5 per 60 min) and
  the tail of ``watchdog.log``;
* turns it on / off with Enable- / Disable-ScheduledTask, registering it first through the
  INSTALLED ``{app}\\watchdog\\register_watchdog.ps1`` when it is missing. It never
  unregisters it: Off = Disabled, so later updates keep it off.

Only an installed build may change the task: a source run resolves no install root (on the
dev PC ``%LOCALAPPDATA%\\MonClubAccess`` is a real install) unless
``MONCLUB_WATCHDOG_INSTALL_ROOT`` names one. A change is refused while an install or update
of Access runs (its Setup process, or the installer's fresh pause sentinel): the installer
re-registers the task itself.

Every call runs in the caller's thread (the local API's per-request thread), never on the
app's main loop, and is bounded by a timeout.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from shared.runtime_support import is_frozen, runtime_base_dir

TASK_NAME = "MonClub Access Watchdog"
INSTALL_ROOT_ENV = "MONCLUB_WATCHDOG_INSTALL_ROOT"

# monclub_access_watchdog.ps1 defaults: $MaxRestartsPerWindow = 5, $RateWindowMinutes = 60,
# $SentinelMaxAgeMinutes = 30.
MAX_RESTARTS_PER_WINDOW = 5
RATE_WINDOW_SEC = 60 * 60
SENTINEL_MAX_AGE_SEC = 30 * 60

STATUS_TIMEOUT_SEC = 20
CHANGE_TIMEOUT_SEC = 30
# register_watchdog.ps1 probes its hidden launcher for up to 30 s before registering.
REGISTER_TIMEOUT_SEC = 120

LOG_TAIL_BYTES = 64 * 1024

# Task Scheduler result codes that are not a failure of the last check
# (SCHED_S_TASK_READY / _RUNNING / _DISABLED / _HAS_NOT_RUN / _TASK_QUEUED).
_RESULT_OK = {0, 0x41300, 0x41302}
_RESULT_RUNNING = {0x41301, 0x41325}
_RESULT_NOT_RUN = {0x41303}

Runner = Callable[[Sequence[str], float], Tuple[int, str, str]]


class WatchdogError(RuntimeError):
    """The change did not happen (or did not take). ``status`` is the fresh status."""

    def __init__(self, message: str, status: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.status = status


class WatchdogUnavailable(WatchdogError):
    """Not an installed MonClub Access: nothing may be changed."""


class WatchdogBusy(WatchdogError):
    """An install / update, or another change, is in progress."""


# ------------------------------------------------------------------ helpers


def iso_utc(epoch: Optional[float]) -> Optional[str]:
    if epoch is None:
        return None
    return dt.datetime.fromtimestamp(float(epoch), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def powershell_exe() -> str:
    # Full path: this PC sets NoDefaultCurrentDirectoryInExePath (shared/update_wrapper.py).
    root = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    return str(Path(root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")


def _decode(data: Any) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        # A -File script's own output goes through the console's OEM code page.
        try:
            return data.decode("oem")
        except (LookupError, UnicodeDecodeError):
            return data.decode("utf-8", errors="replace")


def run_powershell(args: Sequence[str], timeout: float) -> Tuple[int, str, str]:
    """Windows PowerShell with no window (no console flash at the front desk) and a hard
    timeout (subprocess.run kills it and raises TimeoutExpired)."""
    kwargs: Dict[str, Any] = {}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE
        kwargs["startupinfo"] = si
    proc = subprocess.run(
        [powershell_exe(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        check=False,
        **kwargs,
    )
    return int(proc.returncode), _decode(proc.stdout), _decode(proc.stderr)


def _ps_literal(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


# Output is ASCII-only JSON (non-ASCII as \\uXXXX): Windows error text is localized
# ("Accès refusé") and the pipe's code page is not UTF-8. Dates are epoch seconds
# (ConvertTo-Json in 5.1 writes "\/Date(...)\/"); a never-run task's 1999-11-30 is null.
_PS_PRELUDE = r"""
$ErrorActionPreference = 'Stop'
function Out-Ascii($obj) {
    $json = $obj | ConvertTo-Json -Compress -Depth 4
    [regex]::Replace($json, '[^\x00-\x7f]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
}
function Get-Epoch($d) {
    if ($d -is [datetime] -and $d.Year -ge 2000) { return ([DateTimeOffset] $d).ToUnixTimeSeconds() }
    return $null
}
"""

_STATUS_SCRIPT = _PS_PRELUDE + r"""
try {
    $tasks = @(Get-ScheduledTask -TaskName __NAME__ -ErrorAction SilentlyContinue)
    if ($tasks.Count -eq 0) { Out-Ascii ([ordered]@{ registered = $false }); exit 0 }
    $atRoot = @($tasks | Where-Object { $_.TaskPath -eq '\' })
    if ($atRoot.Count -gt 0) { $task = $atRoot[0] } else { $task = $tasks[0] }
    $info = $null
    try { $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath } catch { }
    $lastRun = $null; $nextRun = $null; $lastResult = $null
    if ($info) {
        $lastRun = Get-Epoch $info.LastRunTime
        $nextRun = Get-Epoch $info.NextRunTime
        $lastResult = [long] $info.LastTaskResult
    }
    $enabled = $false
    if ($task.Settings -and $task.Settings.Enabled) { $enabled = $true }
    $intervals = @()
    foreach ($tr in @($task.Triggers)) {
        if ($tr -and $tr.Repetition -and $tr.Repetition.Interval) { $intervals += [string] $tr.Repetition.Interval }
    }
    $execute = $null; $arguments = $null
    $act = @($task.Actions)
    if ($act.Count -gt 0 -and $act[0]) { $execute = [string] $act[0].Execute; $arguments = [string] $act[0].Arguments }
    Out-Ascii ([ordered]@{
        registered      = $true
        taskPath        = [string] $task.TaskPath
        state           = [string] $task.State
        settingsEnabled = $enabled
        lastRunAt       = $lastRun
        nextRunAt       = $nextRun
        lastTaskResult  = $lastResult
        intervals       = $intervals
        execute         = $execute
        arguments       = $arguments
    })
} catch {
    Out-Ascii ([ordered]@{ error = [string] $_.Exception.Message })
}
"""

_CHANGE_SCRIPT = _PS_PRELUDE + r"""
try {
    __VERB__ -TaskName __NAME__ -TaskPath __PATH__ | Out-Null
    Out-Ascii ([ordered]@{ ok = $true })
} catch {
    Out-Ascii ([ordered]@{ error = [string] $_.Exception.Message })
    exit 1
}
"""


def _interval_minutes(intervals: Any) -> Optional[int]:
    """Smallest repetition interval of the triggers ("PT2M", "PT1H5M") in minutes."""
    best: Optional[int] = None
    for raw in intervals or []:
        m = re.fullmatch(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", str(raw or "").strip())
        if not m or not any(m.groups()):
            continue
        d, h, mi, s = (int(x) if x else 0 for x in m.groups())
        total = d * 1440 + h * 60 + mi + (1 if s and not (d or h or mi) else 0)
        if total > 0 and (best is None or total < best):
            best = total
    return best


def _script_path(arguments: Any) -> Optional[str]:
    """The watchdog script the task runs: the quoted ``...monclub_access_watchdog.ps1``
    in the action's arguments (hidden launcher or direct PowerShell)."""
    for quoted in re.findall(r'"([^"]+)"', str(arguments or "")):
        if quoted.lower().endswith("monclub_access_watchdog.ps1"):
            return quoted
    m = re.search(r"(\S*monclub_access_watchdog\.ps1)", str(arguments or ""), re.I)
    return m.group(1) if m else None


def _last_result(code: Any) -> Optional[str]:
    if code is None:
        return None
    try:
        c = int(code)
    except (TypeError, ValueError):
        return None
    if c in _RESULT_OK:
        return "ok"
    if c in _RESULT_RUNNING:
        return "running"
    if c in _RESULT_NOT_RUN:
        return "not_run_yet"
    return "failed"


def resolve_install_root() -> Optional[Path]:
    """``{app}`` (the parent of ``current\\``) of an installed build; None in a source run
    unless ``MONCLUB_WATCHDOG_INSTALL_ROOT`` names one."""
    if is_frozen():
        return Path(runtime_base_dir()).parent
    raw = os.environ.get(INSTALL_ROOT_ENV, "").strip()
    return Path(raw) if raw else None


# ------------------------------------------------------------------ the control


class WatchdogControl:
    def __init__(
        self,
        *,
        install_root: Optional[Path],
        task_name: str = TASK_NAME,
        runner: Optional[Runner] = None,
        now: Callable[[], float] = time.time,
        setup_running: Optional[Callable[[], bool]] = None,
        cache_sec: float = 5.0,
    ):
        self.install_root = Path(install_root) if install_root else None
        self.task_name = task_name
        self._runner: Runner = runner or run_powershell
        self._now = now
        self._setup_running = setup_running or _access_setup_running
        self._cache_sec = cache_sec
        self._cache: Optional[Tuple[float, Dict[str, Any]]] = None
        self._cache_gen = 0  # bumped by every invalidation: a read started before it is not cached
        self._cache_lock = threading.Lock()
        self._change_lock = threading.Lock()

    # ---------------------------------------------------------------- paths

    @property
    def register_script(self) -> Optional[Path]:
        return self.install_root / "watchdog" / "register_watchdog.ps1" if self.install_root else None

    @property
    def available(self) -> bool:
        script = self.register_script
        return bool(script and script.is_file())

    def _logs(self) -> Optional[Path]:
        return self.install_root / "logs" if self.install_root else None

    # ---------------------------------------------------------------- task query

    def _query_task(self) -> Dict[str, Any]:
        script = _STATUS_SCRIPT.replace("__NAME__", _ps_literal(self.task_name))
        try:
            rc, out, err = self._runner(["-Command", script], STATUS_TIMEOUT_SEC)
        except subprocess.TimeoutExpired:
            return {"error": f"reading the scheduled task timed out after {STATUS_TIMEOUT_SEC} s"}
        except Exception as exc:  # PowerShell missing, access denied to start it, ...
            return {"error": f"could not run PowerShell: {exc}"}
        line = next((ln for ln in reversed((out or "").strip().splitlines()) if ln.strip().startswith("{")), "")
        try:
            data = json.loads(line)
        except ValueError:
            return {"error": f"unreadable scheduled-task answer (exit {rc}): {(err or out or '').strip()[:300]}"}
        if not isinstance(data, dict) or ("registered" not in data and "error" not in data):
            return {"error": f"unexpected scheduled-task answer (exit {rc})"}
        return data

    # ---------------------------------------------------------------- watchdog files

    def _restarts(self) -> List[int]:
        logs = self._logs()
        if not logs:
            return []
        try:
            data = json.loads((logs / "watchdog-state.json").read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            return []
        out: List[int] = []
        for r in (data.get("restarts") if isinstance(data, dict) else None) or []:
            # Integers only, as the watchdog itself reads them (date strings were a culture bug).
            if isinstance(r, bool) or not isinstance(r, (int, float)):
                continue
            if r > 0:
                out.append(int(r))
        return out

    def _log_lines(self) -> List[str]:
        logs = self._logs()
        if not logs:
            return []
        path = logs / "watchdog.log"
        try:
            with path.open("rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - LOG_TAIL_BYTES))
                data = f.read()
        except OSError:
            return []
        if data.startswith(b"\xef\xbb\xbf"):
            data = data[3:]
        lines = data.decode("utf-8", errors="replace").splitlines()
        if len(data) >= LOG_TAIL_BYTES and lines:
            lines = lines[1:]  # the first line may be cut
        return [ln for ln in lines if ln.strip()]

    @staticmethod
    def _parse_log_line(line: str) -> Dict[str, Any]:
        parts = line.split(" | ", 2)
        if len(parts) < 3:
            return {"at": None, "rawAt": None, "level": None, "message": line.strip()}
        raw_at, level, message = parts[0].strip(), parts[1].strip(), parts[2].strip()
        epoch: Optional[float] = None
        try:
            # Get-Date -Format 'yyyy-MM-dd HH:mm:ss': the PC's local time (and calendar).
            epoch = time.mktime(time.strptime(raw_at, "%Y-%m-%d %H:%M:%S"))
        except (ValueError, OverflowError):
            epoch = None
        return {"epoch": epoch, "at": iso_utc(epoch), "rawAt": raw_at, "level": level, "message": message}

    # ---------------------------------------------------------------- status

    def status(self) -> Dict[str, Any]:
        with self._cache_lock:
            if self._cache and self._cache_sec > 0 and self._now() - self._cache[0] < self._cache_sec:
                return dict(self._cache[1])
            gen = self._cache_gen
        result = self._build_status(self._query_task())
        with self._cache_lock:
            # A change finished while this read ran: its status is newer than ours (review #5).
            if gen == self._cache_gen:
                self._cache = (self._now(), result)
        return dict(result)

    def _invalidate(self) -> None:
        with self._cache_lock:
            self._cache = None
            self._cache_gen += 1

    def _build_status(self, task: Dict[str, Any]) -> Dict[str, Any]:
        now = self._now()
        error = task.get("error")
        known = error is None
        registered = bool(task.get("registered")) if known else None
        state = task.get("state") if registered else None
        if registered:
            enabled: Optional[bool] = bool(task.get("settingsEnabled")) and str(state) != "Disabled"
        else:
            enabled = False if known else None
        last_run = task.get("lastRunAt") if registered else None

        restarts = [r for r in self._restarts() if r > now - RATE_WINDOW_SEC]
        lines = self._log_lines()
        last_entry: Optional[Dict[str, Any]] = None
        if lines:
            parsed = self._parse_log_line(lines[-1])
            epoch = parsed.pop("epoch", None)
            parsed["fromLastCheck"] = bool(
                epoch is not None and last_run is not None and epoch >= float(last_run) - 5
            )
            last_entry = parsed

        # The watchdog refuses a restart exactly when 5+ of its restarts fall inside the last 60 min
        # (monclub_access_watchdog.ps1). So this is the rule, read from the same epoch stamps --
        # PREDICTIVE: the page is served by a running Access, so it says "would not restart it if it
        # stopped now", not that a refusal is happening. Its own "NOT restarting again" log line is
        # no extra signal: it is written only while that count holds (review #1).
        stood_down = False
        reason: Optional[str] = None
        if len(restarts) >= MAX_RESTARTS_PER_WINDOW:
            stood_down = True
            until = iso_utc(sorted(restarts)[-MAX_RESTARTS_PER_WINDOW] + RATE_WINDOW_SEC)
            reason = (f"Access was restarted {len(restarts)} times in the last 60 min; the watchdog "
                      f"will not restart it again before {until}")

        intervals = task.get("intervals") if registered else None
        return {
            "taskName": self.task_name,
            "registered": registered,
            "enabled": enabled,
            "state": state,
            "lastRunAt": iso_utc(last_run),
            "lastResult": _last_result(task.get("lastTaskResult")) if registered and last_run is not None
            else ("not_run_yet" if registered else None),
            "lastResultCode": task.get("lastTaskResult") if registered else None,
            "nextRunAt": iso_utc(task.get("nextRunAt")) if registered else None,
            "intervalMinutes": _interval_minutes(intervals) if intervals else None,
            "restartsLastHour": len(restarts),
            "stoodDown": stood_down,
            "stoodDownReason": reason,
            "scriptPath": _script_path(task.get("arguments")) if registered else None,
            "lastLogEntry": last_entry,
            "lastError": error,
            "available": self.available,
            "installRoot": str(self.install_root) if self.install_root else None,
            "checkedAt": iso_utc(now),
        }

    # ---------------------------------------------------------------- change

    def _update_in_progress(self) -> bool:
        try:
            if self._setup_running():
                return True
        except Exception:
            return True
        sentinel = self.install_root / ".update-in-progress" if self.install_root else None
        try:
            if sentinel and sentinel.exists():
                return self._now() - sentinel.stat().st_mtime <= SENTINEL_MAX_AGE_SEC
        except OSError:
            return True
        return False

    def _run_change(self, enable: bool, task_path: str) -> Optional[str]:
        script = (_CHANGE_SCRIPT
                  .replace("__VERB__", "Enable-ScheduledTask" if enable else "Disable-ScheduledTask")
                  .replace("__NAME__", _ps_literal(self.task_name))
                  .replace("__PATH__", _ps_literal(task_path or "\\")))
        try:
            rc, out, err = self._runner(["-Command", script], CHANGE_TIMEOUT_SEC)
        except subprocess.TimeoutExpired:
            return f"{'Enable' if enable else 'Disable'}-ScheduledTask timed out after {CHANGE_TIMEOUT_SEC} s"
        except Exception as exc:
            return f"could not run PowerShell: {exc}"
        if rc == 0:
            return None
        detail = ""
        for ln in reversed((out or "").strip().splitlines()):
            try:
                detail = str(json.loads(ln).get("error") or "")
                break
            except (ValueError, AttributeError):
                continue
        return detail or (err or out or "").strip()[:500] or f"exit {rc}"

    def _run_register(self, enable: bool) -> Optional[str]:
        args = ["-File", str(self.register_script), "-InstallRoot", str(self.install_root),
                "-WhenMissing", "Enabled" if enable else "Disabled"]
        try:
            rc, out, err = self._runner(args, REGISTER_TIMEOUT_SEC)
        except subprocess.TimeoutExpired:
            return f"registering the watchdog task timed out after {REGISTER_TIMEOUT_SEC} s"
        except Exception as exc:
            return f"could not run PowerShell: {exc}"
        if rc == 0:
            return None
        return ((err or "").strip() or (out or "").strip())[-500:] or f"register_watchdog.ps1 exit {rc}"

    def _append_register_log(self, outcome: str, message: str) -> None:
        logs = self._logs()
        if not logs:
            return
        try:
            logs.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self._now()))
            with (logs / "watchdog-register.log").open("a", encoding="utf-8") as f:
                f.write(f"{stamp} | {outcome} | {message} | task: {self.task_name}\n")
        except OSError:
            pass

    def set_enabled(self, enabled: bool, *, actor: str) -> Dict[str, Any]:
        """Turn the watchdog on or off; returns the fresh status. Raises WatchdogUnavailable,
        WatchdogBusy or WatchdogError (with the fresh status) -- never unregisters."""
        if not self.available:
            raise WatchdogUnavailable(
                "not an installed MonClub Access: "
                + (f"{self.register_script} is missing" if self.register_script else "no install folder"))
        if not self._change_lock.acquire(blocking=False):
            raise WatchdogBusy("another watchdog change is in progress")
        # Whatever happens, the next status reads the task again (a success re-fills it).
        self._invalidate()
        try:
            if self._update_in_progress():
                raise WatchdogBusy("an install or update of MonClub Access is in progress; try again after it")
            want = "Enabled" if enabled else "Disabled"
            task = self._query_task()
            current = self._build_status(task)
            if current["registered"] is None:
                raise WatchdogError(f"cannot read the watchdog task: {current['lastError']}", current)
            before = ("missing" if not current["registered"]
                      else ("Enabled" if current["enabled"] else "Disabled"))
            if not current["registered"]:
                failure = self._run_register(enabled)
                if failure:
                    status = self._build_status(self._query_task())
                    self._append_register_log("SETTINGS FAILED", f"register ({want}) by {actor}: {failure}")
                    raise WatchdogError(f"registering the watchdog task failed: {failure}", status)
                task = self._query_task()
                current = self._build_status(task)
                if not current["registered"]:
                    self._append_register_log("SETTINGS FAILED", f"register ({want}) by {actor}: no task after it")
                    raise WatchdogError("the watchdog task is still missing after registering it", current)
            if current["enabled"] != enabled:
                failure = self._run_change(enabled, str(task.get("taskPath") or "\\"))
                if failure:
                    status = self._build_status(self._query_task())
                    self._append_register_log("SETTINGS FAILED", f"{want} by {actor}: {failure}")
                    raise WatchdogError(f"turning the watchdog {'on' if enabled else 'off'} failed: {failure}",
                                        status)
                current = self._build_status(self._query_task())
            if current["enabled"] != enabled:
                self._append_register_log("SETTINGS FAILED", f"{want} by {actor}: the task did not change")
                raise WatchdogError(
                    f"the watchdog task did not change (it reads {current['state'] or 'unknown'})", current)
            self._append_register_log("SETTINGS", f"{want} by {actor} (was {before})")
            with self._cache_lock:
                self._cache_gen += 1
                self._cache = (self._now(), current)
            return dict(current)
        finally:
            self._change_lock.release()


def _access_setup_running() -> bool:
    from shared.update_files import setup_is_running

    return setup_is_running(target="access")


_shared_lock = threading.Lock()
_shared: Optional[WatchdogControl] = None


def shared_control() -> WatchdogControl:
    """One control per process (one change lock)."""
    global _shared
    with _shared_lock:
        if _shared is None:
            _shared = WatchdogControl(install_root=resolve_install_root())
        return _shared

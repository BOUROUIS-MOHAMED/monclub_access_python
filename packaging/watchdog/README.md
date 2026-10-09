# MonClub Access watchdog

Nothing in the product restarts `MonClubAccess.exe` when it dies. There is no
service, no scheduled task and no supervisor, and the installer has never had an
autostart entry at all.

That matters because `MonClubAccess.exe` is the Python process serving the local
HTTP API on `127.0.0.1`, and it is the **parent** of the Tauri UI shell
(`monclub-access-ui.exe`) — which **survives** it. So when it dies the gym is left
looking at a window that still seems alive, whose pages fail with
`TypeError: Failed to fetch`; door shortcuts stop working and no fingerprint can
be enrolled, until a human notices and restarts the app.

These scripts are that missing piece.

| File | Purpose |
|---|---|
| `monclub_access_watchdog.ps1` | One check: restart the app if it is down and nothing else is going on. |
| `register_watchdog.ps1` | Register / remove the per-user scheduled task that runs it. |
| `monclub_access_watchdog_hidden.vbs` | Starts each check with no window. The task runs it through `wscript.exe`: launching `powershell.exe` directly makes Windows draw a console before `-WindowStyle Hidden` takes effect, so a window flashed at every check. `register_watchdog.ps1` tests the launcher when it registers the task and falls back to the direct (flashing) launch if VBScript is unavailable, printing `Launch mode:`. |

## Installing

Ship it by ticking **"Keep MonClub Access running"** during setup.

- **A new install: ticked by default** (owner decision, 2026-09-26).
- **An existing install keeps its previous choice** (`UsePreviousTasks=yes`): ticked
  stays ticked, unticked stays unticked. An install whose version predates the box
  has no recorded choice and gets it **unticked** — it changes two behaviours at
  once (start at logon *and* restart on death), and a routine update, the silent
  in-app one included, must never give a PC a startup entry by itself.
- "New" means no trace of an old install: neither Inno's uninstall record nor the
  files (`IsFreshInstall` in `MonClubAccess.iss`). It takes two `[Tasks]` entries
  with the same name, one of them shown. **Not `checkedonce`**: in Inno Setup's own
  code a previously *ticked* `checkedonce` task comes back **unticked**, and a task
  missing from the previous install's record keeps its base state
  (`Setup.WizardForm.pas`, `CreateTaskButtons`, tag `is-6_5_4`).
- **A disabled task stays disabled.** Ticked, the installer runs
  `register_watchdog.ps1`, which replaces the task with the current definition — and
  keeps it **disabled** when someone had disabled it (`Disable-ScheduledTask`, e.g. the
  cutover runbook). It prints `State: Disabled (kept)`; `Enable-ScheduledTask -TaskName
  'MonClub Access Watchdog'` turns it back on. **Ticking the box never re-enables a
  disabled task; only `Enable-ScheduledTask` does.** "Disabled" is read from the task's
  definition (`Settings.Enabled = False`) as well as its `State`: Microsoft's
  `TASK_STATE_DISABLED` means "disabled and no instances of the task are queued or
  running", so a disabled task caught while a check runs reads `Running` -- the script
  before this change read `State` only and registered such a task **enabled**
  (`Test-WatchdogTaskDisabled`) `[CODE, TEST with the Task Scheduler stubbed]`.
- **A failure never leaves an enabled task where a disabled one was.** The old task is
  removed before the new one is registered, so the script first exports it. If the
  registration fails, it registers the old one again from that export; if the new task
  will not stay disabled, it removes it and puts the old one back the same way. Either
  put-back is read back: a task that was disabled and came back enabled is disabled
  again, and **removed** if even that does not hold -- no task rather than an enabled
  one. The run still fails. A task that was **removed** (`-Remove`, an uninstall) is not
  "disabled": the next install with the box ticked registers it enabled. Installers
  built before `18863bc` re-registered it **enabled**.
- **Every run leaves a trace** in `<InstallRoot>\logs\watchdog-register.log` (below). The
  installer runs the script hidden and nothing in it reads the script's exit code
  (Inno's `[Run]` section documents no exit-code handling); its output also goes into
  Setup's own log (`SetupLogging=yes`, `Flags: logoutput`), in the installing user's
  `%TEMP%` as `Setup Log <date> #<n>.txt` -- written even by the in-app update, which
  passes no `/LOG`. Whether `logoutput` captures every line (`Write-Host`, warnings) on a
  real install is `[UNVERIFIED]`; the script's own log does not depend on it.
- Unticked, the installer does not touch an existing task at all -- but it still
  replaces the three files in `<InstallRoot>\watchdog\` (`[Files]` has no task
  condition), so an existing task runs the new check script.
- **One Windows account per PC.** The install is per Windows user
  (`PrivilegesRequired=lowest`, `{localappdata}\MonClubAccess`), but the task name is one
  per PC (root folder of Task Scheduler), and every account's Access shares one data
  folder, `%ProgramData%\MonClub Access` (`app/core/utils.py::_candidate_data_roots`).
  **Install Access and register the watchdog only under the account that logs on by
  itself.** A second account's registration probably fails -- it cannot see or replace
  the first account's task, and the installer asks for no elevation, so an administrator
  account most likely runs it the same way `[UNVERIFIED: not tried]`. Uninstalling from
  another account removes the shared `%ProgramData%\MonClub Access` too
  (`MonClubAccess.iss` `[UninstallDelete]`) -- the gym's database, login and history. Do it
  on its own day, not a cutover night: stop Access in every account first (start-up box
  unticked, `Disable-ScheduledTask`, Quit), copy that folder, uninstall, put the copy back
  before Access starts again (autostart checklist §3a). The task
  name stays the same (not per user): the runbook, the checklists and every PC already
  registered use `'MonClub Access Watchdog'`, and a new name would leave the old task
  running beside the new one after the next update.

To register it by hand on a PC that is already installed:

```powershell
powershell -ExecutionPolicy Bypass -File register_watchdog.ps1
```

That, too, keeps a disabled task disabled. To turn a disabled task on:

```powershell
Enable-ScheduledTask -TaskName 'MonClub Access Watchdog'
Get-ScheduledTaskInfo 'MonClub Access Watchdog' | Select NextRunTime
```

`NextRunTime` must be a date and time (see below). Whether the time trigger, whose
start was the registration moment, gives a `NextRunTime` right after a later
`Enable-ScheduledTask` is **not verified**; if it is empty, no check runs before the
next Windows logon (the logon trigger).

and to remove it:

```powershell
powershell -ExecutionPolicy Bypass -File register_watchdog.ps1 -Remove
```

## What stops it firing at the wrong moment

Restarting the app mid-update can lock files inside `current\` while it is being
replaced and break the update. The Inno Setup installer legitimately stops the app for
minutes (back up `current\` to `previous\`, refill `current\`, start the new version and
wait up to 300 s for it to prove healthy, or roll back) and relaunches it itself. Guards:

1. Our own installer (`monclub_access*`, the `.exe` or Inno's `.tmp`) is running.
2. An install journal (`<InstallRoot>\state\install_journal.json`) is left behind: the
   watchdog runs `update_helper.ps1 -Action recover` (installed beside it) BEFORE guards 3
   and 4. A stale journal (no Setup running, and older than 10 min or written before the
   last boot) is claimed, `previous\` is restored when the phase says `current\` was
   touched, `state\last_update.json` gets `ROLLED_BACK` / `interrupted`, the sentinel is
   cleared and the app is started at once. A fresh journal: stand down. Contract:
   `docs/access-updater-v2/design.md` §8.0 (MonClub docs folder).
3. `<InstallRoot>\.update-in-progress` exists and is fresh — the installer writes
   it before killing anything and removes it at its terminal result. It ages out after
   30 minutes so an aborted install cannot disable recovery permanently.
4. `current\MonClubAccess.exe` is missing — the swap is in flight.
5. The app has been absent for only ONE tick — a restart needs two consecutive
   misses, which covers short legitimate gaps. A miss counts
   only when it comes at least 90 s after the previous counted one
   (`-MinSecondsBetweenMisses`): two checks that land close together are one miss.

A rate cap (5 restarts / 60 min) stops a crash-looping build being relaunched
forever; past it the watchdog logs loudly and stands down.

The guard set is deliberately narrow in one place: matching installers by name
was originally `.*install.*|.*setup.*`, which hit the Windows built-in
`AppInstallerPythonRedirector` and would have hit `SetupHost.exe` for the whole of
a Windows Update — standing the watchdog down while the app stayed dead. **A false
"something is installing" is the worst failure this script has**, so the pattern
now matches only `monclub_access[_<version>]`.

## ⚠️ Verify on the target PC before trusting it

**What was verified here:** the task registers, and the repetition survives
registration. That second part is not cosmetic — the natural way to express
"repeat forever" is `-RepetitionDuration ([TimeSpan]::MaxValue)`, which
serialises to `P99999999DT23H59M59S` and makes Task Scheduler **reject the whole
registration**. Omitting the duration is what works. Get it wrong in the other
direction and repetition is silently dropped, leaving a task that runs once at
logon and never again — autostart with no crash recovery, while still claiming
both.

**The trap that `Interval = PT2M` does not show.** An `-AtLogOn` trigger only fires
on a *future* logon, never for the session that is already open when the task is
registered -- and every install happens inside such a session. With that trigger
alone the task registered, read back `Interval = PT2M`, looked healthy, and had an
**empty `NextRunTime`**: no check ran until the next reboot, so there was no crash
recovery on install day. A manual `Start-ScheduledTask` runs the action once but does
not open the repetition window either. `register_watchdog.ps1` therefore adds a
second, time-based trigger that starts repeating immediately. The logon trigger
stays, so a repeating schedule is guaranteed after every logon even if the time
trigger does not survive a reboot. When both repeat, checks simply run more often --
harmless, because the only action is starting an absent app and MonClub Access
refuses to run twice (single-instance mutex, `access/main.py`).

*Note added 2026-09-27 (review of the paragraph above, not the owner's text):* the
two-misses rule counted **checks**, not minutes (`$RequiredConsecutiveMisses`,
`monclub_access_watchdog.ps1`). With two triggers on different starts, two checks can
land close together, so an absence of well under two minutes -- a tray Quit included --
could count as confirmed and be restarted. How close they land is not measured
(`[UNVERIFIED]`). **Fixed in the check script (`2f3d5bd`):** the second miss counts only
90 s or more after the first (`-MinSecondsBetweenMisses`, the time kept as integer epoch
seconds in `watchdog-state.json`, `missAt`), so Access comes back **no sooner than about
90 s** after the first check that found it gone `[CODE, TEST]`. The time is taken when a check
runs, so a check that starts late (at logon, under a virus scan) can put the next one under 90 s
later: that adds one 2-minute interval to the restart -- never a stand-down. A PC whose
`<InstallRoot>\watchdog\` still holds an older check script still counts checks. Either
way, **disable the task before a Quit that must stick** -- a restart after 90 s is still
a restart.

**Verified here (2026-09-13):** both triggers registered; `NextRunTime` populated
immediately; the task then ran **on its own**, two minutes apart, `LastTaskResult = 0`,
each run writing its log line. (An earlier revision of this note said scheduled
`powershell.exe` tasks hung on the development machine; that no longer reproduces.)

**Not verified here:** a real gym PC, and the schedule after a reboot and logon.

So on the first gym PC you enable this on, confirm it end to end:

```powershell
Get-ScheduledTaskInfo 'MonClub Access Watchdog' | Select NextRunTime, LastRunTime
```

`NextRunTime` must be a date and time. **Empty means nothing will ever run**, even
though `Triggers.Repetition` still reads `PT2M`.
Then force a run and check it completes and logs:

```powershell
Start-ScheduledTask 'MonClub Access Watchdog'
Get-ScheduledTaskInfo 'MonClub Access Watchdog' | Select LastRunTime, LastTaskResult
```

`LastTaskResult` of `0` is success; `267009` means still running (it should
finish in under a second). Then check `logs\watchdog.log` has a new line. The
safest live test is to kill `MonClubAccess.exe` and confirm it comes back within
about two ticks.

## Priority

Task Scheduler starts a task's action at the task's priority, **7 by default =
`BELOW_NORMAL_PRIORITY_CLASS`** (Microsoft, `TaskSettings.Priority`: 4-6 are normal), and a
process started by a below-normal process inherits that class (Microsoft, "Scheduling
Priorities"). So Access started by this task -- task → `wscript.exe` → `powershell.exe` →
`Start-Process` -- probably ran below normal `[UNVERIFIED: the chain was never measured]`,
while Access makes the door decisions. `register_watchdog.ps1` now sets **priority 5**
(`2f3d5bd`) `[CODE, TEST with the Task Scheduler stubbed]`. A task registered by an older
script keeps 7 until the script registers it again (a ticked install, or by hand). Check
on a PC, after the watchdog has restarted Access:

```powershell
(Get-ScheduledTask -TaskName 'MonClub Access Watchdog').Settings.Priority   # 5
Get-Process MonClubAccess | Select PriorityClass                             # Normal
```

## Power lost during an update

Since updater v2 the installer never deletes `current\` up front: it copies `current\*` to
`previous\`, writes `state\install_journal.json`, empties `current\` (files only) and copies
the new files (`installer/update_safety.iss`, `installer/update_helper.ps1`) `[CODE]`. A
power cut in that window leaves the journal; at the next start the watchdog (guard 2
above) or Access's own start-up check restores `previous\` and starts Access `[CODE]`.
Whoever renames the journal first does the restore; the other backs off.

By hand, if neither runs (watchdog off and Access not starting): copy
`%LOCALAPPDATA%\MonClubAccess\previous\*` over `current\`, delete
`state\install_journal.json`, start `current\MonClubAccess.exe`. Never uninstall first: the
uninstaller deletes `%ProgramData%\MonClub Access`, the gym's data.

`<InstallRoot>\.update-in-progress` may be left behind; the watchdog ignores it after 30
minutes (and the recovery deletes it).

## Logs

`<InstallRoot>\logs\watchdog.log` (rotated at 1 MB) and
`<InstallRoot>\logs\watchdog-state.json`.

`<InstallRoot>\logs\watchdog-register.log` (rotated at 1 MB): one line per run of
`register_watchdog.ps1` -- `OK` with `State: Enabled` or `State: Disabled (kept)`, the
`Launch mode` and the task's state read back; `WARN` for a put-back; `FAILED` with the
error and the task's state (a script-scope `trap` writes it, then the run fails as before).
`-Remove` logs the task's state before and after. Setup's own log (`SetupLogging=yes`) is in
`%TEMP%` of the user who installed.

Restart timestamps in the state file are **UNIX epoch seconds, never date
strings**. They were ISO strings once: `ConvertFrom-Json` coerced them to
`[DateTime]`, they were rewritten in the machine's own culture, and reparsing
under a locale that orders day/month differently read a 90-minute-old restart as
a *future* one. The rate cap then latched at 5/5 and the watchdog refused to
restart the app at all — the guard against crash-loops would have disabled
recovery on any non-US-English gym PC. Integers have no culture. Do not
reintroduce date strings.

## Tests

`tests/test_watchdog_script.py` drives the script through its decision table with
`-WhatIfOnly` (it reports what it would do and starts nothing). It skips when
PowerShell is unavailable.

The same file runs `register_watchdog.ps1` under Windows PowerShell 5.1 (what the
installer calls) against a **stubbed** Task Scheduler — a disabled task comes back
disabled (also when its check is running: `State = Running`, `Settings.Enabled =
False`), an enabled or absent one enabled, a failed registration puts the old task
back, a put-back or a new task that will not stay disabled ends with no task rather
than an enabled one (also when the put-back itself fails, or a failed registration had
created the task), every run is logged, priority 5 — and never registers a real
task: it uses a throwaway task name and fails with `LEAKED` if one reached Windows. It
also pins the installer's two `watchdog` task lines, `SetupLogging` and `logoutput`,
no `checkedonce` on any task, and compiles `MonClubAccess.iss` when `ISCC.exe` is
installed. One test runs the script as the installer does (`powershell -File`) on a path
that fails before any Task Scheduler cmdlet: it exits non-zero and logs `FAILED` (it
has the same `LEAKED` guard). The watchdog's own checks run under Windows PowerShell 5.1
when it is there, as the task runs them. What
Task Scheduler itself does with a task registered with `Settings.Enabled = $false`, or
with an exported task registered again, was **not** run here; both are read back
(definition and state) and disabled or removed if they come back enabled. The
predicate was run read-only against real tasks on the development PC (a `Ready` one and
a `Disabled` one; `Settings.Enabled` and `Settings.Priority = 7` read back). The put-back
covers a task in the root folder only (where this script registers it); a same-name task
someone moved to another folder is removed but not put back.

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

Ship it by ticking **"Keep MonClub Access running"** during setup. The task is
**unchecked by default** — it changes two behaviours at once (start at logon *and*
restart on death), and an existing install must never silently gain a startup
entry on a routine update. `UsePreviousTasks=yes` means a site that opts in stays
opted in.

To register it by hand on a PC that is already installed:

```powershell
powershell -ExecutionPolicy Bypass -File register_watchdog.ps1
```

and to remove it:

```powershell
powershell -ExecutionPolicy Bypass -File register_watchdog.ps1 -Remove
```

## What stops it firing at the wrong moment

Restarting the app mid-update can lock files inside `current\` while it is being
replaced and break the update. Both the Inno Setup installer
(`KillRunningMonClubProcesses`) and `MonClubAccessUpdater.exe` legitimately stop
the app for minutes at a time and relaunch it themselves. Five guards:

1. An updater process is running.
2. Our own installer (`monclub_access*`) is running.
3. `<InstallRoot>\.update-in-progress` exists and is fresh — the installer writes
   it before killing anything and removes it at `ssPostInstall`. It ages out after
   30 minutes so an aborted install cannot disable recovery permanently.
4. `current\MonClubAccess.exe` is missing — the swap is in flight.
5. The app has been absent for only ONE tick — a restart needs two consecutive
   misses, which covers short legitimate gaps without the updater having to
   cooperate (it is a compiled binary this change does not touch).

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

## Logs

`<InstallRoot>\logs\watchdog.log` (rotated at 1 MB) and
`<InstallRoot>\logs\watchdog-state.json`.

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

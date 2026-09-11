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

**What could NOT be verified here:** that the task actually *executes*. On the
development machine every `powershell.exe` (5.1) scheduled task hangs before its
first statement — including a three-line probe script that only writes a file, so
it is the invocation environment on that box, not this script. The script itself
runs correctly under 5.1 when launched directly.

So on the first gym PC you enable this on, confirm it end to end:

```powershell
Get-ScheduledTask 'MonClub Access Watchdog' | ForEach-Object { $_.Triggers.Repetition }
```

`Interval` must be `PT2M`; an empty `Duration` means indefinite, which is correct.
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

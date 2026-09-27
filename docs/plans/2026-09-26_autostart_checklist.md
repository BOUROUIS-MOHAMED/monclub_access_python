# Autostart checklist -- one sheet per reception PC

Goal: after the gym's power comes back in the morning, each PC starts, logs into Windows, starts
MonClub Access, and the turnstiles are updated before the first member arrives -- with nobody
touching the PC. Most gyms cut the PC and the electricity from closing to opening (owner,
2026-09-13), so this is the normal start of every day, not a rare case.

Three things are needed, all three: the PC switches itself on when power returns (BIOS), Windows
opens the session by itself (auto-logon), and MonClub Access starts in that session (watchdog, or the
"Ouvrir MonClub Access avec Windows" box). The installer's own default for the watchdog: **ticked for a
new install** from the release that contains branch `claude/installer-watchdog-fix` (built 2026-09-27,
merged into `master` as `3835ae3`; its later hardening, `2f3d5bd` and after, not merged yet; not
released); an existing install keeps its previous choice, and one whose version
predates the box gets it unticked (section 3). **Until that release, and on any existing install, tick
it by hand** -- except during the cutover night, when every install leaves it **unticked** and the
watchdog is switched on only at each gym's last step (section 4). **Install Access under the Windows
account that logs on by itself, and only that one** (section 3a).

**Grades.** The BIOS menu names and the Windows auto-logon screens below are general knowledge of
those products, not checked on the gym PCs: `[UNVERIFIED]`. What MonClub Access and its watchdog do is
read from the code (`[CODE]`, named). Times: none is measured yet -- the test in section 5 measures them.

---

## Sheet (copy once per PC)

| | |
|---|---|
| Gym / PC name in "Postes de réception" | |
| Windows computer name (Settings → System → About) | |
| Brand and model; desktop or laptop | |
| BIOS option found (exact name) and value set | |
| Auto-logon: method, Windows account used | |
| Access installed under that account only (section 3a) | yes / no -- other accounts: |
| Watchdog task "MonClub Access Watchdog" present | yes / no |
| Watchdog task priority (`.Settings.Priority`) / Access `PriorityClass` after a watchdog restart (section 3) | … / … |
| "Ouvrir MonClub Access avec Windows" ticked | yes / no |
| Sleep set to "Never" | yes / no |
| Test (section 5): power back → desktop / Access started / turnstile updated | … s / … s / … s |
| Date, who | |

## 1. BIOS: switch on when power returns `[UNVERIFIED]`

Enter the BIOS/UEFI setup right after switching the PC on (usually **Del** or **F2**; HP **F10**;
Lenovo ThinkCentre **F1**; Dell **F2**). Look in the Power / Advanced / Chipset menus for one of:

| Brand (desktop boards / office PCs) | Usual name | Set to |
|---|---|---|
| ASUS | "Restore AC Power Loss" (Advanced → APM Configuration) | Power On |
| Gigabyte | "AC BACK" | Always On |
| MSI | "Restore after AC Power Loss" | Power On |
| ASRock | "Restore on AC/Power Loss" | Power On |
| Dell OptiPlex / Vostro desktops | "AC Recovery" / "AC Behavior" (Power Management) | Power On |
| HP business desktops | "After Power Loss" (Advanced → Power-On Options) | On |
| Lenovo ThinkCentre | "After Power Loss" (Power) | Power On |
| Other | "Power On after Power Fail", "PWR-ON After PWR-Fail", "State after G3" | On / S0 |

Save (usually F10) and exit. **"Last State" is not enough**: when the power is cut at the wall, the
last state is "off" for many boards.

**Laptops** (gym 45 has one, "LAPTOP-T6KORL9V"): most have no such option. Some have "Power On with
AC Attach" (ThinkPad) or a similar "power on when AC is connected" setting. Without it, a laptop whose
battery ran flat overnight stays off until someone presses the button. Write "none" on the sheet if
there is none: that PC then cannot be the one that drives the turnstiles.

## 2. Windows opens the session by itself (auto-logon) `[UNVERIFIED]`

Use a local Windows account made for the reception, not an administrator and not the owner's own
account.

- **Microsoft's Autologon tool (Sysinternals):** enter the account and its password once; it stores the
  password encrypted by Windows. Downloading it is a file download: do it yourself, from Microsoft.
- **Or `netplwiz`:** untick "Users must enter a user name and password to use this computer", then give
  the password. On Windows 11 that box is hidden while Settings → Accounts → Sign-in options → "For
  improved security, only allow Windows Hello sign-in…" is on.
- A Microsoft account that signs in only with a PIN or Windows Hello cannot auto-logon this way.

**The security trade-off.** Whoever sits at the PC gets an open Windows session with MonClub Access
running: they can press "Ouvrir" on the turnstiles and see the member list, and anything the browser
has saved (the dashboard) is open too. Reduce it: the reception account has no admin rights; the
dashboard's admin password is not saved in that browser; staff lock the screen (Windows + L) when they
leave the desk -- a locked session keeps running `[UNVERIFIED for Access, the usual Windows
behaviour]`; a BIOS password stops someone changing the start-up settings; the PC stays where only
staff can reach it.

**Also:** Settings → System → Power → Screen and sleep → sleep **Never** (a sleeping PC does not update
the turnstiles). Windows Update may restart the PC at night: with auto-logon it comes back by itself.

## 3. MonClub Access starts in the session `[CODE]`

- **The watchdog** (recommended): the installer's box **"Keep MonClub Access running (start at logon,
  restart if it stops)"** -- unticked by default on `master` `d3725fa` (`installer/MonClubAccess.iss`,
  `[Tasks] watchdog`, `Flags: unchecked`); on branch `claude/installer-watchdog-fix` ticked for a new
  install only, an existing install keeping its previous choice (`IsFreshInstall`, release checklist
  §3b). It creates the task **"MonClub Access Watchdog"**, which runs at logon of that user and every 2
  minutes after, and starts Access when it is not running; it stands down while the installer is
  updating and limits how often it restarts (`packaging/watchdog/register_watchdog.ps1`,
  `monclub_access_watchdog.ps1`). Already installed without it: run
  `%LOCALAPPDATA%\MonClubAccess\watchdog\register_watchdog.ps1` as that user (no admin needed).
  Check: `Get-ScheduledTask -TaskName 'MonClub Access Watchdog'`, and
  `Get-ScheduledTaskInfo 'MonClub Access Watchdog' | Select NextRunTime` -- empty means no check will
  run before the next Windows logon. The script on `master` `d3725fa` has only a logon trigger, so right
  after an install that is expected; the owner's edit (committed 2026-09-27 as `b30ef60` on that branch,
  not merged) adds a second trigger that starts at once, and with it an empty `NextRunTime` right after
  the install is a fault for an **enabled** task (`packaging/watchdog/README.md`; a disabled task has
  none).
- **What the watchdog does not know:** a tray Quit. It restarts Access after two missed checks in a
  row (`monclub_access_watchdog.ps1`, `$RequiredConsecutiveMisses = 2`) `[CODE]`: about 2-4 minutes after
  any Quit with the logon trigger alone (every 2 minutes). The owner's second trigger (`b30ef60`) repeats
  every 2 minutes too, from a different start, so once both run two checks can come close together and,
  with a check script before `2f3d5bd`, the restart can come sooner -- how soon is `[UNVERIFIED]`. From
  `2f3d5bd` the second miss counts only 90 s or more after the first, so the restart comes **no sooner
  than about 90 s** after the first check that found Access gone `[CODE, TEST]`. Either way, to keep
  Access stopped, disable the task **first**: `Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'`.
- **What an install does to it:** when the box was ticked at the previous install, the installer ticks
  it again (`UsePreviousTasks=yes`) and runs `register_watchdog.ps1`, which removes the task and
  registers it again (`installer/MonClubAccess.iss` `[Run]` `Tasks: watchdog`) `[CODE]`. With the script
  on `master` `d3725fa` the new task is **enabled** -- a disabled task does not stay disabled. From the
  release that contains `claude/installer-watchdog-fix` (`18863bc`), a task that was disabled is
  registered again **disabled** (`State: Disabled (kept)`) `[CODE, TEST with the Task Scheduler
  stubbed]`. **So on such a release, ticking the box does NOT switch a disabled watchdog back on --
  `Enable-ScheduledTask -TaskName 'MonClub Access Watchdog'` does**, then the `NextRunTime` check above.
  From `2f3d5bd`, "disabled" is also read from the task's definition, so a disabled task caught while a
  check runs (`State` reads `Running`) stays disabled too. Unticked, the installer leaves the existing
  task as it is (it still replaces the check script, `[Files]`). Each run of the script writes one line
  to `%LOCALAPPDATA%\MonClubAccess\logs\watchdog-register.log` (from `2f3d5bd`): `OK` with the state, or
  `FAILED` with the error; Setup's own log is in `%TEMP%` (`Setup Log <date> #<n>.txt`).
- **Priority** (from `2f3d5bd`): the task is registered at priority 5, normal. Task Scheduler's default
  is 7, below normal, and Access started by the task probably inherited it `[UNVERIFIED]`
  (`packaging/watchdog/README.md`, "Priority"). Only a restart **by the watchdog** shows it: on a closed
  evening, never during an erase or a refill, with the task enabled, end `MonClubAccess.exe` once in Task
  Manager and wait for it to come back (within about 4 minutes) -- after a power cycle the start-up entry may have started Access instead. Then, in
  PowerShell: `Get-Process MonClubAccess | Select PriorityClass` must print `Normal`, and
  `(Get-ScheduledTask -TaskName 'MonClub Access Watchdog').Settings.Priority` `5`. `BelowNormal` / `7`:
  the task was registered by an older script -- as that user, `powershell -ExecutionPolicy Bypass -File
  "$env:LOCALAPPDATA\MonClubAccess\watchdog\register_watchdog.ps1"` (it keeps a disabled task disabled),
  then end and wait once more. Write both values on the sheet.
- **"Ouvrir MonClub Access avec Windows"** (Access → Config): a start-up entry for the user; it starts
  Access at logon but does not restart it after a crash. Access rewrites that entry from the box at
  every start (`app.py::_sync_startup_registration`).
- Both can be on: Access refuses a second copy of itself ("MonClub Access is already running — exiting
  this instance", `access/main.py`, `acquire_single_instance_guard`).
- **Both depend on a Windows session**, so they depend on section 2.
- Access pushes by itself at start-up when "manual sync" is off -- it is off at gyms 45 and 58 (12
  September copy) `[CODE: UltraSyncScheduler._run]`.
- **The start-up box is stored in the data folder, and off by default.** It is `start_on_system_startup`
  in `%ProgramData%\MonClub Access\access\config.json` (default `False`: `app/core/config.py`,
  `shared/config.py`), and at every start Access **deletes** its start-up entry when the box is off
  (`app/ui/app.py::_sync_startup_registration`) `[CODE]`. So a data folder copied back after the box was
  unticked (the runbook's A3 / C2 / D3 copies are taken after A1 / C1 / D1 untick it), or a fresh data
  folder, starts with it off: re-tick it by hand.

## 3a. One Windows account per PC `[CODE; the multi-account behaviour UNVERIFIED]`

The install is **per Windows user** (`PrivilegesRequired=lowest`: the program goes to that user's
`%LOCALAPPDATA%\MonClubAccess`, and its uninstall entry to that user's registry), but:
- the watchdog task name, **"MonClub Access Watchdog"**, is **one per PC** (Task Scheduler's root folder);
- every account's Access uses the **same data folder**, `%ProgramData%\MonClub Access` (database, login,
  history: `app/core/utils.py::_candidate_data_roots`);
- the uninstaller of **any** account deletes that folder (`MonClubAccess.iss` `[UninstallDelete]`).

**The rule:** install Access, and register the watchdog, **only under the account that logs on by
itself** (section 2). If another account has Access installed, uninstall it there **first** -- on its own
day, never a cutover night, with the gym closed `[UNVERIFIED: never done; whether one account's
uninstaller can delete folders another account's Access created depends on the folder's permissions]`:
1. In **every** account that has Access, stop it so nothing writes the data folder or starts it again:
   untick "Ouvrir MonClub Access avec Windows", `Disable-ScheduledTask -TaskName 'MonClub Access
   Watchdog'` (if it exists), tray icon → Quit; Task Manager shows no `MonClubAccess.exe` (runbook A1).
2. Copy the whole `%ProgramData%\MonClub Access` to the USB key -- that uninstall deletes it.
3. Uninstall from the other account; log off from it.
4. In the account that logs on by itself: if `%ProgramData%\MonClub Access` is gone or incomplete, put
   the copy back **before** Access starts; then start Access, and give autostart back as the runbook's
   F-end does (the box re-ticked, the watchdog back on by what exists, its `State` `Ready`).

To see which accounts have it, in an **administrator** PowerShell:
`Get-ChildItem 'C:\Users\*\AppData\Local\MonClubAccess\current\MonClubAccess.exe'` (one line per
account) and `(Get-ScheduledTask -TaskName 'MonClub Access Watchdog').Principal.UserId` (the account the
task runs as). What a second account's registration does is `[UNVERIFIED]`: it probably cannot see or
replace the first account's task, so it fails (logged in that account's own `watchdog-register.log`) --
the installer asks for no elevation (`PrivilegesRequired=lowest`), so an administrator account most
likely runs it the same way.

**Why one task name, not one per account:** the runbook, these checklists and every PC already
registered use `'MonClub Access Watchdog'`; a per-account name would leave the old task running beside
the new one after the next update and break every `Disable-ScheduledTask` / `Enable-ScheduledTask` line
of the runbook. One account per PC is what the gyms need anyway (section 2).

## 4. After the cutover night

The runbook unticks "Ouvrir MonClub Access avec Windows" and disables the watchdog for the night
(C1, D1), and every install that night is run with **"Keep MonClub Access running" unticked**, followed
by a check that the task reads `Disabled` or does not exist (runbook C3c, D9) -- otherwise the install
would switch the watchdog back on and Access would restart by itself in the middle of the night's
steps. The last step of each gym (C17, D19) re-enables both: re-tick the box in Access, and the
watchdog **by what exists now** (runbook part C, "Turning the watchdog back on"): a task there --
the old one, or the one registered at A7 and disabled at C1 -- `Enable-ScheduledTask -TaskName
'MonClub Access Watchdog'`; none, and the PC should have it, `register_watchdog.ps1` as in section 3.
Never `register_watchdog.ps1` over a disabled task to switch it on: it keeps it disabled. Then
`(Get-ScheduledTask -TaskName 'MonClub Access Watchdog').State` must read `Ready` (or `Running`
during a check) -- `NextRunTime` alone cannot tell a disabled task from an enabled one -- and check
`NextRunTime` (section 3): empty means the watchdog first runs at the next Windows logon -- that is
expected with the script on `master` `d3725fa` (a logon trigger only), and is the case every morning
after a power cut, which starts with a logon. With the owner's second trigger (`b30ef60`), whether
`Enable-ScheduledTask` on a task registered earlier gives a `NextRunTime` at once is `[UNVERIFIED]`
(that trigger's start is the registration time, now in the past); empty still means the first check
at the next logon. Check with the sheet before leaving.

**A night that ends in a rollback** (runbook part F, gym 45 plan §6) needs the same: the rollback rows
end with "start Access" and restore nothing of the above, and a data folder copied back was copied
with the box unticked (section 3). The runbook's closing step **F-end** does it whichever row ended the
night, and its row **E6** proves one power cycle (section 5) the next evening.

## 5. The test (do it on a closed evening, never during an erase or a refill)

1. Access running, the turnstiles up to date. Note the time.
2. Desktop PC: switch the power off **at the wall or the power strip** (not the button). Laptop: shut it
   down, unplug the charger, wait, plug it back (that is what a flat battery does).
3. Wait one minute. Switch the power back on. Write **t0**.
4. Write **t1** when the Windows desktop appears without anyone typing. None → section 1 or 2.
5. Write **t2** from the log: newest file in `%ProgramData%\MonClub Access\data\logs\`, the line
   `App started`. It carries `monotonic_s=`, the seconds since Windows started, so it also tells how long
   Windows took (from the first release that carries it, `15b4aeb`). No such line within 5 minutes →
   section 3.
6. Write **t3**, "turnstile updated", from the same log:
   - an MB2000 (gym 45): `full sync (reason=startup): all N desired pins already on the terminal -- nothing to push`;
   - a C3-400 (gym 58): `[DeviceSync] Device id=5: device_pins=N desired=N to_sync=0 stale=0` (and id=6).
7. Check "Postes de réception" shows the PC seen a moment ago. Test one card (or finger) at the door.
8. **Result:** t1 − t0, t2 − t0, t3 − t0 on the sheet. Compare t3 with the gym's opening time: the whole
   chain must finish before the first member.

9. If the watchdog task exists and is enabled, and the priority is not on the sheet yet: its check of
   section 3 ("Priority" -- end `MonClubAccess.exe` once and let the watchdog bring it back; the power
   cycle alone does not show it).

**STOP rules:** the PC stays off → BIOS; it stops at the login screen → auto-logon; Access does not start
→ watchdog / start-up box, and `%LOCALAPPDATA%\MonClubAccess\logs\watchdog.log`: a line
`... MonClubAccess.exe is missing -- current\ may be mid-swap; standing down` at every check means the
program folder is broken (section 6); Access starts but no "turnstile updated" line within 10 minutes →
read the log for `CONNECT`/`REVOKE_ABORTED`/`CAPACITY_FULL` and call the developer.

## 6. Power lost during an update `[CODE; the recovery never tried, UNVERIFIED]`

An update deletes `%LOCALAPPDATA%\MonClubAccess\current\` before copying the new program
(`MonClubAccess.iss::PrepareToInstall`), and the in-app updater swaps the same folder. Power lost in
that window can leave a PC that **cannot start Access by itself**: the program file is missing (the
watchdog then stands down at every check, and the start-up entry points at nothing), or it is there
without the rest (Access fails at start, `%TEMP%\MonClubAccess.log`; the watchdog restarts it at most 5
times in any hour, logging `NOT restarting` in between). Nothing repairs it on its own. Recovery, as the account Access is installed for
(section 3a) -- **never uninstall** (it deletes `%ProgramData%\MonClub Access`):
1. Run the installer of the version the PC was updating to, over the existing install.
2. If it answers "MonClub Access version X is already installed on this PC. Nothing will be changed.",
   rename `%LOCALAPPDATA%\MonClubAccess\current` to `current_broken` and run it again.
3. Start Access and check `App started` in the newest log; then the watchdog's state (section 3).

Details: `packaging/watchdog/README.md`, "Power lost during an update".

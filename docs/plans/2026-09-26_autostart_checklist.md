# Autostart checklist -- one sheet per reception PC

Goal: after the gym's power comes back in the morning, each PC starts, logs into Windows, starts
MonClub Access, and the turnstiles are updated before the first member arrives -- with nobody
touching the PC. Most gyms cut the PC and the electricity from closing to opening (owner,
2026-09-13), so this is the normal start of every day, not a rare case.

Three things are needed, all three: the PC switches itself on when power returns (BIOS), Windows
opens the session by itself (auto-logon), and MonClub Access starts in that session (watchdog, or the
"Ouvrir MonClub Access avec Windows" box). The installer's own default for the watchdog: **ticked for a
new install** from the release that contains branch `claude/installer-watchdog-fix` (built 2026-09-27,
not merged, not released); an existing install keeps its previous choice, and one whose version
predates the box gets it unticked (section 3). **Until that release, and on any existing install, tick
it by hand** -- except during the cutover night, when every install leaves it **unticked** and the
watchdog is switched on only at each gym's last step (section 4).

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
| Watchdog task "MonClub Access Watchdog" present | yes / no |
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
- **What the watchdog does not know:** a tray Quit. It restarts Access after two missed checks, so
  about 2-4 minutes after any Quit (`monclub_access_watchdog.ps1`, `$RequiredConsecutiveMisses = 2`,
  every 2 minutes) `[CODE]`. To keep Access stopped, disable the task first:
  `Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'`.
- **What an install does to it:** when the box was ticked at the previous install, the installer ticks
  it again (`UsePreviousTasks=yes`) and runs `register_watchdog.ps1`, which removes the task and
  registers it again (`installer/MonClubAccess.iss` `[Run]` `Tasks: watchdog`) `[CODE]`. With the script
  on `master` `d3725fa` the new task is **enabled** -- a disabled task does not stay disabled. From the
  release that contains `claude/installer-watchdog-fix` (`c0391d4`), a task that was disabled is
  registered again **disabled** (`State: Disabled (kept)`); `Enable-ScheduledTask` turns it on
  `[CODE, TEST with the Task Scheduler stubbed]`. Unticked, the installer leaves the existing task as
  it is.
- **"Ouvrir MonClub Access avec Windows"** (Access → Config): a start-up entry for the user; it starts
  Access at logon but does not restart it after a crash. Access rewrites that entry from the box at
  every start (`app.py::_sync_startup_registration`).
- Both can be on: Access refuses a second copy of itself ("MonClub Access is already running — exiting
  this instance", `access/main.py`, `acquire_single_instance_guard`).
- **Both depend on a Windows session**, so they depend on section 2.
- Access pushes by itself at start-up when "manual sync" is off -- it is off at gyms 45 and 58 (12
  September copy) `[CODE: UltraSyncScheduler._run]`.

## 4. After the cutover night

The runbook unticks "Ouvrir MonClub Access avec Windows" and disables the watchdog for the night
(C1, D1), and every install that night is run with **"Keep MonClub Access running" unticked**, followed
by a check that the task reads `Disabled` or does not exist (runbook C3c, D9) -- otherwise the install
would switch the watchdog back on and Access would restart by itself in the middle of the night's
steps. The last step of each gym (C17, D19) re-enables both: re-tick the box in Access, and
`Enable-ScheduledTask -TaskName 'MonClub Access Watchdog'` where the task existed (or, where it never
existed and the PC should have it, run `register_watchdog.ps1` as in section 3). Then check
`NextRunTime` (section 3): empty means the watchdog first runs at the next Windows logon -- that is
expected with the script on `master` `d3725fa` (a logon trigger only), and is the case every morning
after a power cut, which starts with a logon. With the owner's second trigger (`b30ef60`), whether
`Enable-ScheduledTask` on a task registered earlier gives a `NextRunTime` at once is `[UNVERIFIED]`
(that trigger's start is the registration time, now in the past); empty still means the first check
at the next logon. Check with the sheet before leaving.

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

**STOP rules:** the PC stays off → BIOS; it stops at the login screen → auto-logon; Access does not start
→ watchdog / start-up box; Access starts but no "turnstile updated" line within 10 minutes → read the log
for `CONNECT`/`REVOKE_ABORTED`/`CAPACITY_FULL` and call the developer.

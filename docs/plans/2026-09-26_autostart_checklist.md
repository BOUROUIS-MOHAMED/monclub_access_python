# Autostart checklist -- one sheet per reception PC

Goal: after the gym's power comes back in the morning, each PC starts, logs into Windows, starts
MonClub Access, and the turnstiles are updated before the first member arrives -- with nobody
touching the PC. Most gyms cut the PC and the electricity from closing to opening (owner,
2026-09-13), so this is the normal start of every day, not a rare case.

Three things are needed, all three: the PC switches itself on when power returns (BIOS), Windows
opens the session by itself (auto-logon), and MonClub Access starts in that session (watchdog, or the
"Ouvrir MonClub Access avec Windows" box). The installer's own default for the watchdog changes later,
after the owner's installer edits are committed: **until then it is ticked by hand.**

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
  restart if it stops)"** -- unticked by default today (`installer/MonClubAccess.iss`, `[Tasks]
  watchdog`, `Flags: unchecked`). It creates the task **"MonClub Access Watchdog"**, which runs at
  logon of that user and every 2 minutes after, and starts Access when it is not running; it stands down
  while the installer is updating and limits how often it restarts (`packaging/watchdog/register_watchdog.ps1`,
  `monclub_access_watchdog.ps1`, as committed on `master`; the owner's uncommitted edits to those files
  may change this). Already installed without it: run
  `%LOCALAPPDATA%\MonClubAccess\watchdog\register_watchdog.ps1` as that user (no admin needed).
  Check: `Get-ScheduledTask -TaskName 'MonClub Access Watchdog'`.
- **"Ouvrir MonClub Access avec Windows"** (Access → Config): a start-up entry for the user; it starts
  Access at logon but does not restart it after a crash. Access rewrites that entry from the box at
  every start (`app.py::_sync_startup_registration`).
- Both can be on: Access refuses a second copy of itself ("MonClub Access is already running — exiting
  this instance", `access/main.py`, `acquire_single_instance_guard`).
- **Both depend on a Windows session**, so they depend on section 2.
- Access pushes by itself at start-up when "manual sync" is off -- it is off at gyms 45 and 58 (12
  September copy) `[CODE: UltraSyncScheduler._run]`.

## 4. After the cutover night

The runbook unticks "Ouvrir MonClub Access avec Windows" and disables the watchdog for the night. The
last step of each gym re-enables both. Check with the sheet before leaving.

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

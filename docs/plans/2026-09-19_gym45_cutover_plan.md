# Gym 45 (Oxyfit) cutover -- wipe both MB2000s, account PINs, MonClub-only, re-push

**Status: PLAN ONLY.** Nothing here has been executed. No terminal was written to, erased or
reconfigured and no database was changed while writing it. The owner approves the plan and picks
the time; execution is a separate, later step. Written 2026-09-19 against Access `master`
`ca1e29a`, backend `main` `e40f8648`, dashboard `main` `e0eef4af`. Branch
`claude/gym45-cutover-plan` (not merged, not pushed).
Third round 2026-09-26 on Access `master` `aeeef69` (P3b-2 merged): §3.3, E10 and D2 re-read against
driver PCs and readers -- the night runs without drivers (runbook part H).

> **The cutover night follows the runbook's order, not this plan's** (added 2026-09-28, sixth round of the
> runbook, Access `master` `aa015e5`): [`2026-09-26_cutover_night_runbook.md`](2026-09-26_cutover_night_runbook.md)
> part D (D1-D19) and part F. This plan keeps the evidence and the commands the runbook cites -- Phase B
> (the survey), §3.3, §5.1-§5.3 (the retire SQL, the firewall block, P2/P3 later), E10's switch line,
> E10b's proven restart, E11's completion lines, E12's verify, §6's half-states. Where they differ, the
> runbook wins:
> - **No Phase D soak.** The new Access is installed and started on P1 on the night, **before** the erase,
>   still on "Par abonnement" (runbook D6, N1). A stop before the erase leaves P1 on it: runbook N3.
> - **The erase is the Erase wizard in Access** (Devices page, the bin icon; release checklist §3a), with
>   "hold until « Remplir »" -- not script 13 at E5, and not with Access stopped: the wizard runs inside
>   P1's Access, through its own connection. It keeps the administrators (privilege > 0) as script 13 does,
>   backs the terminal up first, and needs the gym's server switch (runbook B2c) `[CODE: app/core/erase_wizard.py]`.
> - **P1's retire is the wizard's « forget »**, forced for an MB2000 users erase and done inside D6 after
>   the erase is verified (runbook D10) -- not §5.1 with Access stopped at E8. So §2's order changes in one
>   place: the retire comes before the cut (D8), and the hold keeps P1 from writing any member until
>   « Remplir ». §5.1 (or a fresh data folder) stays for a PC that runs Access without having run the erase.
> - **P1 runs from D6 on**: E10's "Start Access on P1" is already done; E10's line and E10b's restart are
>   runbook D14-D15, and « Remplir » (D15b) comes **before** the cables go in (D16 = E11).
> - **E5b** (an administrator deleted with script 7) needs Access stopped on P1: between runbook D1 and D6,
>   while P1's Access is quit -- never while the wizard runs. The runbook's "change that administrator's
>   number" is the terminal's own menu, not E5b.
> - **§6:** runbook part F comes first. R4's "wipe again (E5-E6)" and R6's "script 13 again" mean the
>   wizard again (runbook part F, gym 45 "Every other row"); after a power cut during the wizard's erase,
>   the hold stays until « Remplir » (a hold whose run stopped before its first delete is released at the
>   next start -- unless its turnstile's scheme moved, or P1 starts after a full logout (its turnstile list
>   empty): then it is kept, guide §3.2h).

Every claim is graded as in the guides: `[CODE]` (an executable statement, named), `[TEST]`,
`[FIELD]` (a dated measurement), `[COMMENT]` (prose only), `[OWNER]` (the owner said so, dated;
nobody has checked it), `[UNVERIFIED]`, `[UNKNOWN]`.
`wigo-demo` numbers come from a scrubbed clone of the 2026-09-12 production dump that later test
sessions **mutated**: they are rehearsal numbers, **not production numbers**. The real run needs a
fresh production export (SELECT-only; never `wigo-db`).

The owner-facing page is the plain-language version of this file; this file is the evidence.

---

## 1. Where we start

| Fact | Grade / source |
|---|---|
| Gym 45 is **"Oxyfit"**, gym family 5 (with gym 44 "monclub") | `[FIELD]` wigo-demo `gym_model` |
| Device **8 "Sortie"** 192.168.1.247 and device **10 "Entrée"** 192.168.1.246: `ZK_STANDALONE`, `accessDataMode=ULTRA`, `rosterPushingPolicy=PRESERVE`, active; `pin_scheme` stored as `''`, which the backend sends as `MEMBERSHIP` (`GymDevice.effectivePinScheme`) | `[FIELD]` wigo-demo; `[CODE]` backend |
| Two older copies of a gym-45 PC database on the owner's desktop (2026-09-05/06) hold devices **8 and 9** -- the Entrée terminal apparently had another id before | `[FIELD]` local copies, aggregates only |
| **3 registered Access PCs**, all ACTIVE: "Accueil" (LAPTOP-T6KORL9V, 1.4.33, last seen 09-10), "Accuil Oxyfit" (no hostname, 1.4.33, last seen 09-12), "Accueil Oxyfit" (DESKTOP-6UCRVSG, 1.4.32, last seen 09-10) | `[FIELD]` wigo-demo `gym_access_pc` |
| **No published release has what the cutover needs.** Latest tag `access_1.4.33` (2026-09-09); 1.4.34 is a local shell-only bump, never published. None contains the pin-scheme gate (`30c3b93`, 2026-09-12), `sync_users.main_account_id`, or P3a-2 | `[CODE]` `git show <tag>:…` |
| An Access build without the gate ignores `pinScheme` and pushes membership pins | `[CODE]` no `pin_scheme` column on those tags; guide §3.2b |
| Roster on 2026-09-12: **919 deliverable memberships, 902 people**, 0 without an account; 836 people have ≥1 fingerprint in MonClub, **66 have none**; every template BASE64, version 10 | `[FIELD]` wigo-demo, measured twice (research seat SQL; `rehearsal_check.py`) |
| Account id vs membership id: among gym 45's 902 people **1** account id equals any membership id, **0** equal a membership pin in use at gym 45. The "110" in the code comments is platform-wide | `[FIELD]` wigo-demo |
| Terminal on 2026-09-06 (device 8, .247): users 1838, fingerprints 2023, fingerprints free 977, users free 1162 (capacity 3000/3000) | `[FIELD]` zkemkeeper_guide §4 |
| About 930 of those were not MonClub's: **353 duplicates** (same finger under the old system's pin and MonClub's) and **~577 old-system-only users** | `[COMMENT]` script 13's own scope comment, 2026-09-06 |
| The same evening an operator ran script 13 on "the live MB2000 at Oxyfit" and "cleared the users and fingerprints tables successfully" (~1800 users). **Which terminal, which scope (all users or a pin list) and how many were deleted were not recorded.** | `[FIELD]` commit `b6ed69e` message; details `[UNKNOWN]` |
| So **what is on the two terminals today is unknown**. The survey export (§5, phase B) answers it before anything else is decided | -- |
| `manual_sync_mode` is **off** for gym 45 → Access pushes by itself at start-up | `[FIELD]` wigo-demo `gym_access_software_settings`; `[CODE]` `UltraSyncScheduler._run` |
| The old system's person key in MonClub is its **card id** (`migration_entity_link_gms`, PERSON: 4280 rows, all numeric, 1-4 digits) | `[FIELD]` wigo-demo; `[CODE]` `GmsMigrationService` |
| Whether the old system used that card id as its terminal pin | `[UNVERIFIED]` -- the comparison measures it (`pin_is_a_gms_card_id`) |
| The terminals' fingerprint algorithm version (`~ZKFPVersion`) | `[UNKNOWN]` -- never recorded; the export reads it |

**Not available, checked:** `GET /api/v2/devices/{id}/users` refuses ZK_STANDALONE with 409 `[CODE]`;
no Access code reads templates from a terminal `[CODE]`; `DEVICE_AUDIT` exists only on the
unmerged backend branch `claude/p2b-realtime-commands` `[CODE]` -- none of them can be used here.

## 2. What changes, and why in this order

**Goal.** Both turnstiles end up holding only MonClub's current members, one user per person
(pin = `main_account.id`), with fingerprints from MonClub, and MonClub able to remove anyone who
leaves. The old system's users (and any finger enrolled only on the terminal) are gone.

**Why a wipe and not a switch.** A PRESERVE terminal keeps whatever MonClub did not provably write,
so switching the scheme without a wipe leaves every leftover in place and mixes two pin schemes on
one terminal -- the thing guide §3.2b forbids. The owner also wants the leftovers gone, and neither
automatic path can remove them (guide §3.2c: MIRROR is off and its 25 % floor refuses a
roster-sized diff; the revoke pass only removes pins MonClub owns, under the ceiling) `[CODE]`.

**Why the PC's old state must be deleted after the wipe ("retire").** After the switch, every old
membership pin in `device_sync_state` still says "MonClub owns this pin" (`ownership_confirmed=1`).
Every later full sync then sees ~900 departed pins, above the removal ceiling
`max(10, 25 % of the roster)`, and refuses the whole removal step (`REVOKE_ABORTED`) -- on every pass,
forever `[CODE: ultra_engine._neutralise_revoked_pins, push_safety.check_bulk_removal]`. Consequences
`[CODE]`: members who leave by expiry are **never removed from the turnstiles**; revocations that fall
back to a full sync stay "unconfirmed" and re-queue every ≤15 min; the daily finger sweep and intent
read-back never run (`MAINTENANCE_SKIPPED`). Nothing clears it: hard reset, force-resync and the switch
only UPDATE the rows, and clearing the ownership bit is undone at the next start (`init_db` promotes
rows with `pushed_finger_ids` back to owned). **No button, endpoint or tool deletes them today**
`[CODE]` -- guide §3.2e records it as "not built; needs a decision". On a **verified-empty** terminal
the rows are false claims and deleting them is the local half of the wipe; §3.2c's warning protects
rows for pins that are still on the terminal, which is exactly what the verification must exclude.

**The order is fixed, per terminal:** wipe → verify empty → cut the PC off from it → retire → switch →
reconnect and push. Retire before the wipe strands real pins; retire after the first ACCOUNT push erases
the new pins' ownership; retire while the PC can reach the terminal risks a push of ~900 membership
pins as new (next paragraph).

**Why the terminals stay unplugged until the switch is recorded.** The ULTRA engine starts inside the
first sync tick, after `getSyncData` `[CODE: app.py::_sync_tick]`. If that first call fails (no
network yet at boot), the engine starts from the cached device row -- still MEMBERSHIP -- and, with
manual sync off, pushes at once `[CODE]`. With the rows retired it would push ~900 membership pins
as new. Unplugging the terminals (or the proven firewall block of §5.2) makes that impossible
`[CODE: the worker's run loop does nothing while unconnected]`.

## 3. Prerequisites (all before the day)

### 3.1 Access build
A release built from `master` at or after `ca1e29a` (pin-scheme gate + P3a-2: write-ahead ownership,
removal ceiling, capacity and template-version checks, 50-pins-per-pass cap). Call it 1.4.35.
- Installed on **every PC that will ever connect to the turnstiles** at least **2 opening days
  before** the cutover, running normally on MEMBERSHIP -- and only AFTER the survey and the rescue
  (Phases B and C say why). The upgrade adds `sync_users.main_account_id` and
  forces ONE full member refresh to fill it, and adds `sync_devices.pin_scheme` and forces one
  device refresh `[CODE: db._ensure_main_account_id_column, ::_ensure_pin_scheme_column]`.
- Check each PC's version on the dashboard's **/access-pcs** page (it shows the app version from
  the heartbeat `[CODE: dashboard gym-access-pcs-table-row.tsx]`).
- **Decision D3** may add a small "retire" action to this release (§7, A1).

### 3.2 Backend and dashboard
Production must have: `GymDevice.pinScheme` and its emission in the sync (`effectivePinScheme`),
`mainAccountId` on every member row, person-scoped fingerprint delivery, and the dashboard's
"PIN scheme" choice on /gym-devices `[CODE: backend main 93c01af6/4b00d546, 7f0c2df7; dashboard
56f516d5/59c08cb2]`. **Which backend build runs in production cannot be read from anywhere**
(no build-info endpoint `[CODE]`). It is proven indirectly by gate G2 (§3.5): after the new client's
forced refresh, the PC's own database shows `pin_scheme='MEMBERSHIP'` for devices 8 and 10 (the
backend sent the field) and no member row without `main_account_id` (the backend sent it).

### 3.3 Who drives the turnstiles
Today every Access PC of the gym connects to every device; nothing in the software stops two PCs
driving one terminal `[CODE: backend sends every device to every PC; UltraEngine starts a worker
per ULTRA device]`. There is **no per-PC switch** to keep one PC off the turnstiles:
`device_local_settings` only gates the door button, `device_sync_enabled` does not gate ULTRA, and a
bogus `MONCLUB_DEVICE_PROTOCOL_OVERRIDES` value silently routes to PullSDK `[CODE]`.

*Corrected 2026-09-26 (third round, Access `master` `aeeef69`):* the per-turnstile driver/reader
feature is now built (P3b-2, merged as `318fb3d`): with the server's commands switch on and a driver
set for a turnstile in the dashboard, only that PC connects to it, and a PC with no driver lease
connects to none (`app/core/v2/lease_gate.py`, guide §3.9) `[CODE]`. **The cutover does not use it**
(runbook part H): the switch is off unless the server was started with it (the CI does not set it;
the running state is read on each PC by the runbook's page check, H4) and
every gym's driver screen stays locked until the owner opens it (`AccessAssignmentLock`, backend); only the new Access obeys a driver setting; a PC with no cached
roles -- a fresh data folder, D3 (c) -- connects to every turnstile until the server answers; and a
revoke stops a new Access only in a gym that uses drivers (`leases.py::LeaseManager._drop_leases`)
`[CODE]`. So without drivers the rest of this section holds for the new Access too, and the controls
of the cutover stay: stop the app, stop it from starting again, or block the terminals' IPs on that PC
with Windows Firewall (§5.2).

**P1** = the one PC that drives both turnstiles during and after the cutover (**decision D2**).
P2, P3 = the other two. They run 1.4.32 / 1.4.33, which ignore `pinScheme`: started after the switch
they would write membership pins onto the account terminals, pins only they own, which nothing then
removes `[CODE]`. Switching them off is not enough -- staff switch reception PCs on. So from step E1
on they carry the §5.2 firewall block until §5.3 is done for them (D2). **Revoking their record in
/access-pcs does not stop them**: 1.4.32/1.4.33 fetch the members with the gym login, and a revoke only
stops the PC's heartbeat (`git show access_1.4.33:access/pc_identity.py`, state `revoked`;
`…:app/ui/app.py::_sync_tick` → `get_sync_data` with the gym login token) `[CODE]`; the backend's
member sync checks no PC status (`GymAccessController`, review 2026-09-26). Only the block (or the PC
off the network) keeps them off the terminals.

How to fully stop Access on a PC and keep it stopped `[CODE]`:
- **Untick "Ouvrir MonClub Access avec Windows"** on Access's Config page FIRST. The app rewrites the
  Windows start-up value (`MonClubAccess` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`)
  from that setting every time it starts `[CODE: app.py::_sync_startup_registration]`, so deleting
  the value by hand does not last. Re-tick it at the end.
- Tray icon → **Quit** (it also closes the window process `monclub-access-ui.exe`). Task Manager must
  then show no `MonClubAccess.exe`.
- The **watchdog** task "MonClub Access Watchdog" (opt-in at install; restarts Access every 2 min):
  `Get-ScheduledTask -TaskName 'MonClub Access Watchdog'` to see if it exists, then
  `Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'`; `Enable-ScheduledTask …` at the end.
- On P1, **pause Windows Update** for the day (Settings → Windows Update → Pause), so no reboot
  starts anything mid-procedure.

### 3.4 Settings in /gym-devices, and when
Nothing changes before the day. At step E9, for each terminal that passed E6: **PIN scheme:
"Per person"** (`ACCOUNT`). The dashboard shows a wipe-first dialog with two checkboxes ("MonClub
Access has been updated…", "this terminal's users have been wiped") `[CODE: dashboard
gym-devices-view.tsx]`; each device is saved separately, and the save is refused (toast) if the page
cannot re-read the device first. Keep **Mode = ULTRA** and **roster policy = PRESERVE** (MIRROR buys
nothing after a wipe and would enumerate the terminal on every explicit sync, guide §3.2c). Do not
touch the "fingerprint template" dropdown: it has no effect on the MB2000 path
`[CODE: _resolve_template_version_override is PullSDK-only]`.

A pinScheme edit bumps the device's `updatedAt`, so every PC's next sync gets the device refresh
`[CODE: GymDeviceController.update, GymAccessController.computeDevicesVersion]`.

**Exposure created by this cutover (decision D8):** `POST /connected/gym-device/update` does no
permission check for a gym login `[CODE]` -- anyone with the gym's login can flip `pinScheme` without
the dialog and without a wipe. Before the cutover nobody had a reason to touch that field.

### 3.5 Go / no-go gates
| # | Gate | Read from | Checked |
|---|---|---|---|
| G1 | Every PC that will connect runs ≥ 1.4.35; the others carry the §5.2 block | /access-pcs version column; §5.2 proof | E4 |
| G2 | On a copy of P1's `access.db` taken after the upgrade: `rows_without_main_account = 0`, and `pin scheme recorded by the PC: MEMBERSHIP` for 8 and 10 (the upgrade adds the column empty; only the backend can fill it `[CODE: db._ensure_pin_scheme_column]`) | comparison `--access-db` | D3, E4 |
| G3 | Both terminals' fingerprint version = MonClub's (all `delivered_templates_version_10` → `fpVersion` 10). If the export's `fpVersion` is null, the second source is P1's current log: 1.4.33 writes `connected ip=… deviceFpVersion=…` at every connect `[CODE: git show access_1.4.33:app/sdk/zk_standalone.py]`. Both unknown → the push's version check is inert `[CODE: zk_standalone._versions_disagree]`; the owner accepts that explicitly or it is red. **Red → Phase D (upgrade) does not start**: 1.4.35 skips every mismatched template it pushes `[CODE]` | export + P1 log | after B6 |
| G4 | Every member in the Phase B comparison's `people_with_terminal_only_finger` / `people_losing_every_finger` is rescued or explicitly accepted (D4). **If the `sha self-check` is below 90 %, these counts are lower bounds** (a terminal-only finger on a finger number MonClub also holds reads as covered `[CODE]`): then every leftover tied to a current member (gms_id, card, pin_is_card) who has fingers also tests at the door after E11, or re-enrols | comparison + `--detail-csv` | E4 |
| G5 | Today's `-IncludeTemplates` backups: `complete: true`; each file's `device.ip` and `device.serial` match its terminal and differ between the two files; copied to two places | the files + `.sha256` | E2 |
| G6 | The retire method (D3) is ready and rehearsed on a copy of P1's `access.db` | dry run on the copy | E4 |
| G7 | /gym-devices shows the "PIN scheme" choice for devices 8 and 10 | dashboard | B0, E4 |
| G8 | `faces = 0` on both terminals, or the owner accepted losing them (nothing can back a face up) | export counter 21 | E4 |
| G9 | Every member listed with `terminal_only_via_own_pin` is re-enrolled (or accepted) **before Phase D**: 1.4.35's finger sweep clears finger slots MonClub does not deliver, on pins MonClub owns, ≤100 pins a day `[CODE: ultra_engine._sweep_check, ::_drain_finger_sweep]` | Phase C | before D1 |
| G10 | Both terminals' `clockSkewSec` within ±10 s, or corrected. Door events are read under the scheme in force at the TERMINAL's time vs the switch time on the PC, so a slow terminal names the wrong person for its first scans after the switch `[CODE: device_attendance.HistoryPinResolver]` | E3 export | E3 |
| G12 | The technician and the on-call developer are named (D12); the script pack is on P1 (and P2/P3) with the comm key set (B0) | §3.6 | E4 |
| G11 | The machine that runs the comparison during the window is named, has Python + the branch, and has run it on the Phase B files | rehearsal | E4 |

### 3.6 People and tools
The owner decides and watches; the hands-on steps need someone else. Named in D12:
- **An on-site technician** who can run the script pack (`START HERE.cmd` → menu, or PowerShell), use
  Task Scheduler (`taskschd.msc`) and Windows Defender Firewall (`wf.msc`), read a JSON file and search
  a log file -- and, if D3 = (b), run the §5.1 SQL with the official SQLite command-line tool.
- **The developer, on call for the whole window**: most failure branches of E10/E11 end with "call
  the developer".
- **A comparison machine** (G11) with Python 3.9+, `pymysql`, this branch and the production copy
  (D11); the comparison is run there, by the developer or the technician.
- The script pack is only on this branch: the technician copies the whole `tools/mb2000_scripts`
  folder (with its `sdk\` folder) to P1 -- and to P2/P3 for the §5.2 proof -- and starts it with
  `START HERE.cmd`. Never its menu `[1]` on a gym PC (it re-registers `zkemkeeper.dll` machine-wide at
  the pack's copy; Access already registered its own).

## 4. The tools (read-only; on branch `claude/gym45-cutover-plan`)

**`tools/mb2000_scripts/14_export_terminal_readonly.ps1`** -- one terminal to a JSON file:
identity, clock skew, counters (GetDeviceStatus 1-12, 21, 22), `~ZKFPVersion`, every user (pin,
name, card, privilege, enabled, has-password), with `-Fingers` each finger slot's size and SHA-256,
with `-IncludeTemplates` the templates (a backup script 10 can restore). Proof it never writes
`[TEST: tests/test_mb2000_export_readonly.py]`: every `$zk.` call in it and in `_common.ps1` is on the
allowlist `SetCommPassword, Connect_Net, Disconnect, GetFirmwareVersion, GetSerialNumber,
GetDeviceMAC, GetPlatform, GetVendor, GetDeviceIP, GetDeviceTime, GetDeviceStatus, GetSysOption,
ReadAllUserID, SSR_GetAllUserInfo, GetStrCardNumber, SSR_GetUserTmpStr`; in both files no write
method name appears outside a comment and there is no dynamic invocation; the COM object is only
created, returned and closed; the script dot-sources only `_common.ps1`, which dot-sources nothing;
and the shipped script, run against a fake terminal that has ONLY those methods and logs every call,
completes. Its enumeration and template read are the calls of script 10's Backup and script 13's
inspect mode; `GetSysOption('~ZKFPVersion')` is the Access driver's own read, not yet run from
PowerShell on an MB2000 (on failure `fpVersion` is null) `[UNVERIFIED]`. Unlike the Access driver it
never sends `EnableDevice`, `RegEvent` or `RefreshData`. What the firmware does inside a read is
beyond any test `[UNVERIFIED]`. The "template version" it gives is the terminal-wide algorithm
version (`~ZKFPVersion`); the terminal stores every template in its own algorithm, and no read on the
allowlist returns a per-template version (per slot it records size and SHA-256). Always pass
`-DeviceIp` and `-Label`: without `-DeviceIp`, `-Auto`
reads the IP last saved in `config.json`.

**`tools/gym45_cutover/compare_terminal_export.py`** -- the comparison (README in that folder).
Reads a copy of `access.db` query-only and a MySQL copy in a `READ ONLY` transaction, SELECT only,
templates hashed inside MySQL, `wigo-db` refused; every pin is compared in one normal form and pins
the terminal returns in another form are counted `[TEST: tests/test_gym45_compare_terminal_export.py]`.
Rehearsed against wigo-demo for 2026-09-12: its SQL roster gives 919 / 902 like the independent
measurement, and on a synthetic terminal with known answers all 9 checks pass `[TEST:
rehearsal_check.py, run 2026-09-19]`. Its SQL-only roster (no `--access-db`) does not apply the
backend's photo rule, unpaid-due rule or per-gym fingerprint gate; every step of this plan passes
`--access-db`, which is the exact roster.

## 5. The procedure

Order: **A → B → C → D → E → F.** Times marked *measured* come from a field record; everything else is
**unmeasured**, and the phase that measures it is named. Planning reserves are not estimates.

### Phase A -- build (developer)
A1. Build and publish 1.4.35 from `master` ≥ `ca1e29a`. If D3 = (a), it adds the retire action,
which must run while the ULTRA engine is NOT started (e.g. a command-line mode that exits), per
device, refuse for a device with push intents or rows written after the last recorded switch, and
update guide §3.2e.
A2. Suite green (`python -m pytest tests/ -q --ignore=tests/_pydeps`; one master test,
`test_review_round6::test_r6_01…`, fails while the PC has been up under ~83 min -- a test bug, being
fixed separately `[TEST: 2026-09-19, uptime 966 s]`).

### Phase B -- survey and first backup, on the build the PCs run today
**Why before the upgrade.** 1.4.35 brings P3a-2's finger-slot sweep (G9). The release the PCs run today
(1.4.33) has no sweep and does record ownership and finger ids `[CODE: git show
access_1.4.33:app/core/db.py]`, so the survey is complete on it. (1.4.32, on the third PC, is not
tagged.)

One hour with the gym closed and the power on, in the script-pack folder on P1 (technician):
B0. Before the day: copy the script pack to P1 (§3.6). In /gym-devices, open device 8 and device 10:
note whether a device **password** (COMM key) is set -- Access sends it on connect
(`zk_standalone`: `comm_key` from the device's `password`) `[CODE]`, while the scripts read it from
their own `config.json` (empty by default) `[CODE: _common.ps1::Get-Config]`. If set, enter it with
`START HERE.cmd` → `[C]` on every PC that runs a script. Also check G7 now (the dashboard shows the
"PIN scheme" choice), not first on the morning.
B1. Stop Access on all three PCs as in §3.3 (untick start-with-Windows, Quit, watchdog off).
B2. Time a sample -- **type each IP in full; .247 = device 8 "Sortie", .246 = device 10 "Entrée"**:
```powershell
.\14_export_terminal_readonly.ps1 -DeviceIp 192.168.1.247 -Label device8 -Fingers -MaxUsers 50 -Auto
```
`timings.msPerFingerRead` in the file × 10 × the terminal's user count = the full read time
(*measured* from here on). Decide from it whether B3 fits in the hour.
B3. Full read with templates, both terminals at once in two windows (the analysis input AND a first
backup; biometric data, keep private, D7):
```powershell
.\14_export_terminal_readonly.ps1 -DeviceIp 192.168.1.247 -Label device8  -IncludeTemplates -Auto
.\14_export_terminal_readonly.ps1 -DeviceIp 192.168.1.246 -Label device10 -IncludeTemplates -Auto
```
B4. Copy P1's `%ProgramData%\MonClub Access\access\` folder (`access.db` + `-wal` + `-shm`, Access
stopped) to a USB key. `MONCLUB_ACCESS_DATA_ROOT` overrides the path. It is not the install folder
`%LOCALAPPDATA%\MonClubAccess`; never uninstall Access without this copy -- the uninstaller deletes
the data folder `[CODE: installer/MonClubAccess.iss [UninstallDelete]]`.
B5. In P1's log folder `%ProgramData%\MonClub Access\data\logs\` search `deviceFpVersion=` (second
source for G3). Re-enable, restart Access where it normally runs.
B6. On the comparison machine (G11): `compare_terminal_export.py --export 8=<device8 file> --export
10=<device10 file> --access-db <copy> --mysql-* <the production copy of D11> --day <today>` → G3, G4, G8,
G9 and the facts §1 left unknown: how many leftovers remain (answers what the 2026-09-06 clear did),
admins, faces, `sha self-check`, `pin_is_a_gms_card_id`, `pins_not_in_canonical_form`.
B7. If the gym PC's script-pack folder still has `logs\clear_*.log` from 2026-09-06, it gives the time
per whole-user delete (one timestamped line per pin, written before each call `[CODE]`) -- the only
possible measurement of the erase time before the day.

### Phase C -- rescue, before the upgrade (G9, G4)
Per D4, for each member in `--detail-csv` as `member_terminal_only_finger`: re-enrol at the desk
through MonClub, re-enable a template MonClub has but does not deliver
(`terminal_only_but_template_in_monclub`), or import after a pilot (D4). Members tied only through
`terminal_only_via_own_pin` must be done before D1 (G9).

### Phase D -- upgrade, ≥ 2 opening days before the cutover
*Not on the cutover night (the banner at the top): the runbook installs on P1 on the night, before the
erase (D6). D2's log checks still apply to a P1 left on the new Access (runbook N3), but not D2's rollback:
the night takes no D0 copy, so `TEMPLATE_VERSION_MISMATCH` then means stop, call the developer (E11's fail column),
and the old Access comes back only as runbook N3 and D6 allow -- no « Effacer » pressed on either terminal that night,
else only on the developer's word, after that terminal's D16 completion (runbook D6): a pass without
`[T] FULL_SYNC_CAPPED` that ends with `[T] ZKEM_PUSH_DONE … failed=0 … tpl_failed=0` and `[T] FULL_SYNC_DONE … ok=True`,
then a Quit and restart whose start-up pass logs `all N desired pins already on the terminal -- nothing to push` (E11).*
D0. Just before installing: Quit Access on P1 and copy its data folder (as B4). This copy is Phase
D's rollback.
D1. Install 1.4.35 on P1 (and on P2/P3 only if D2 brings them back). Check /access-pcs.
D2. Let it run on MEMBERSHIP. In P1's log: `[T] TEMPLATE_VERSION_MISMATCH` → stop and go back
(G3 was wrong): restore the D0 copy of the data folder, then reinstall 1.4.33. Whether 1.4.33 runs on
a database 1.4.35 has migrated (new columns and tables) is `[UNVERIFIED]` and the installer has no
downgrade handling, hence the copy; `[T] FINGER_SWEEP … cleared=` above 0 on a pin in the B6 detail CSV → that
member just lost a finger: re-enrol them; `REVOKE_ABORTED`, `CAPACITY_FULL` → call the developer.
D3. The day before the cutover: Quit Access on P1 for a minute (Task Manager check), copy the data
folder, restart. Run the comparison on that copy → **G2**.
D4. *Optional, writes to the terminals (D10):* with the gym closed, press **"Réinitialisation
complète"** on Access's dashboard page on P1. It re-pushes every member under MEMBERSHIP, in the same
50-per-pass rounds as the cutover `[CODE]`, so the E11 duration is *measured* before the day (FT7).
The terminals already hold that content; each finger is cleared then rewritten, so wait for the
completion lines of E11 before opening.

### Phase E -- the cutover (gym closed, power on)
*On the cutover night the order is the runbook's D1-D19 (the banner at the top): E5's script 13 and E8's
§5.1 are the Erase wizard's run and its « forget » inside runbook D6; E10 runs from D6 on; « Remplir »
(runbook D15b) before E11.*
**Window.** Its length is: the B2-measured read time (E2) + a quick read (E3, E6) + the erase time
(B7, or unmeasured) + the fixed steps + the re-push (D4, or unmeasured) + the E12 read. If any term is
still unmeasured, the gym stays closed until E13 is done (D1). A **go/no-go clock** guards E5: if the
erase has not started by then, stop -- nothing has changed. The **half-state table** (§6) says which
states the gym can open in; only two can.

**Every step is per terminal where it touches a terminal.** One terminal may stop at "not wiped, still
MEMBERSHIP" while the other goes on (a hang, a failed check); it is finished another day. Never
retire or switch a terminal that did not pass E6.

| Step | Action | Proof it worked | If it fails |
|---|---|---|---|
| E1 | P2, P3: untick start-with-Windows, Quit, watchdog off, add the §5.2 block and **prove it**, shut down. P1: untick start-with-Windows, Quit, watchdog off, pause Windows Update. | Task Manager: no `MonClubAccess.exe` on P1; the §5.2 proof on P2/P3 | Nothing changed: undo, stop |
| E2 | Backup, both terminals at once, **full commands** (as B3). Copy both files + `.sha256` to a USB key and the owner's PC. Copy P1's data folder (as B4). | G5 | Nothing changed: retry or stop |
| E3 | Quick read of each terminal (`… -DeviceIp <ip> -Label <label> -Auto`); counters close to B3; **G10** clock skew | numbers | Investigate first. A skew above 10 s is corrected with `3_get_device_info.ps1`, answering `y` to "Set device clock to this PC's time?" -- a WRITE to the terminal (`SetDeviceTime2`) `[CODE]`, done here, before E4 |
| E4 | **Go / no-go**: G1-G11 green, clock time not passed | -- | Stop: re-tick start-with-Windows, watchdog on, restart P1. Nothing changed |
| E5 | **Erase, one terminal at a time:** `13_inspect_and_clear_tables.ps1` → at "Device IP" **type the IP in full** → step 2 `[N]` → step 3 **`[U] USERS whole rows`** → scope **`[A]`** (all non-admin users) → if faces > 0 it asks, answer per G8 → type **`CLEAR`**. Before each run: Task Manager shows no `MonClubAccess.exe` (script 13 does not check). It deletes every non-admin user with `SSR_DeleteEnrollData(1, pin, 12)`, logging each pin before the call, and keeps admins (privilege > 0) `[CODE]`. **It will print "SSR_DeleteEnrollData(pin, 12) has never been confirmed on this firmware" and label the choice "UNVERIFIED api": expected (D9), carry on.** **From the first deleted user on, never just restart Access: it would push nobody** (its records still say everyone is on the terminal `[CODE: ultra_engine._standalone_pins_needing_push]`) -- recover with §6 R2. | the script's BEFORE → AFTER table; log `DONE ok=… failed=0` | Failed pins: re-run (it re-reads the users). **A pin that does not return within 60 s:** close the window, note the pin (last log line), re-run once; hangs again on the same pin → abandon this terminal's wipe (it stays MEMBERSHIP, not retired, not switched), recover it with R2 for that device, and go on with the other terminal only. Whether the terminal still verifies at the door after a hang is `[UNVERIFIED]`: test it |
| E5b | **Only if D5 removes an admin:** Task Manager shows no `MonClubAccess.exe` (script 7 does not check), then `7_delete_device_fingerprint.ps1` → that admin's pin → choice **`U`** only (never `0`-`9`, the finger-index delete that hangs this firmware, zkemkeeper_guide §3). Irreversible: a restore brings users back as privilege 0. | the admin is gone from a quick export | -- |
| E6 | **Verify empty, per terminal**, three ways: (1) quick export -- only the admins script 13 listed (minus any E5b removed) remain, `fingerprints` = their fingers, `faces` = 0, and `users + users_free = user_capacity` (FT6); (2) the terminal's own user count on its screen; (3) one member's finger and card at that door must be **refused**. Then (4) the comparison on that export with `--scheme ACCOUNT --access-db <fresh copy>`: `account_pins_already_on_terminal` must be 0 (an admin whose pin equals a member's account id would be overwritten as privilege 0 by the push `[CODE: zk_standalone._do_push_roster SSR_SetUserInfo(1, pin, name, "", 0, …)]`). | all four agree | Not empty: E5 again. FT6 false or an admin collides: stop before E7 for that terminal (D5) |
| E7 | **Interlock**: unplug the network cable of every terminal that passed E6 (they keep power), or the §5.2 block on P1, **proven** | the §5.2 proof, or no link light | -- |
| E8 | **Retire on P1, per terminal that passed E6** (D3), with Access stopped -- or D3(a)'s action in its no-engine mode. §5.1. | counts 0 for that device | Restore the `access.db` copy; stop (R2) |
| E9 | Dashboard /gym-devices, per retired terminal: PIN scheme **"Per person"**, tick both boxes, save. | reopen EACH device: it reads "Per person" | Leave it; no PC is running |
| E10 | Start Access on P1. In `%ProgramData%\MonClub Access\data\logs\` (the newest file) wait for, per switched device: **`[T] PIN_SCHEME_SWITCH device_id=8 previous=MEMBERSHIP scheme=ACCOUNT cleared_rows=0 first_sighting=False`** (`device_id=10` likewise). `cleared_rows=0` confirms `device_sync_state` was empty when the switch arrived (it counts that table only `[CODE: db._clear_device_sync_hashes_on]`); the proof for all three tables is the §5.1 counts taken at E8. (The `[DB] … pinScheme …` line of guide §3.2e does not reach this folder: only the `zkapp` loggers write there `[CODE: app/core/logger.py]`.) *Third round:* P1's « Pilote / Lecteur » page shows one of the runbook's two expected readings (part H4) -- no driver is set at gym 45 | the line(s); the page | The page reads « PC pilote », « PC lecteur » or « REVOKED »: a driver is set -- do not plug in, Quit, call the developer (runbook part H3: the way back is the server's commands switch off). **`cleared_rows` ≠ 0 → STOP, do not plug in**: something pushed after the retire; Quit, E6 export, back to E5. One device switched, the other not → fix that device in /gym-devices and wait; do not switch back the one that switched. No line after a few minutes → check the log shows `getSyncData OK` (the PC reached the server); then **"Réinitialisation complète"** (clears the version tokens, forces the device refresh `[CODE]`). Still none → the switch was NOT recorded: do not plug in, go to **R3** (which first puts the dashboard back to "Per membership") and call the developer |
| E10b | *(added 2026-09-26, review of the cutover-night runbook; proof tightened in its second round)* **Quit and restart Access on P1, proven three ways**: (1) after the Quit, Task Manager shows no `MonClubAccess.exe`; (2) after the start, the newest log has an `App started. pid=… version=…` line (`app.py`, written at every start) later than the `PIN_SCHEME_SWITCH` lines, with another `pid` than the previous one; (3) a `getSyncData OK` line after it. "The new log" alone proves nothing: log files are cut by hour, not by process (`app/core/logger.py::active_log_name_for`), and a second launch while the first still runs exits at once, saying so only in `%TEMP%\MonClubAccess.log` (`access/main.py`) `[CODE]`. Why the restart: if the dashboard was open on P1, the switch reached P1 through a fast patch: it is recorded and logged, but the running workers keep their MEMBERSHIP copy of the device until a server sync refreshes them `[CODE: app.py::apply_fast_patch_bundle; the sync tick's refresh_devices; ultra_engine._drain_full_sync_commands uses self._device]` | the three checks; then, before E11, P1's « Pilote / Lecteur » page shows one of the runbook's two expected readings (part H4, the restart box) | a check fails, or no expected reading: do not plug in; call the developer |
| E11 | **Plug the cables in** (or remove the block). P1 reconnects within ≤ 140 s `[CODE: connect backoff ≤ 120 s + 20 s connect deadline]` and re-pushes: 50 pins per pass, passes back to back, both terminals in parallel `[CODE]`. **Done, per device**, when (1) the last pass has no `[T] FULL_SYNC_CAPPED` and ends with `[T] ZKEM_PUSH_DONE … failed=0 … tpl_failed=0` and `[T] FULL_SYNC_DONE … ok=True` (a refused template still counts as pushed, so `failed=0` alone is not enough `[CODE: zk_standalone.push_roster, ultra_engine._run_standalone_full_sync]`); then (2) **Quit and restart Access** (behind nothing now -- the switch is recorded): its start-up full pass logs `full sync (reason=startup): all N desired pins already on the terminal -- nothing to push` with N = the number of people, and no `[T] SYNC_RETRY_BACKOFF` (N also counts pins held back by the retry backoff `[CODE: ultra_engine._standalone_pins_needing_push]`). Pressing "Synchroniser" does not produce that line: without a server change it requests no push, and the timer skips an unchanged roster `[CODE: app.py::_request_running_ultra_sync, ultra_engine.UltraSyncScheduler._sync_all]`. Floor: ~902 people ÷ 50 = 19 passes × ≤ 22.6 s of writes ≈ **7 min per terminal**, from the one field rate (928 users / 419 s, device 8, v1.4.26, before P3a-2 `[FIELD]`); each pass also rebuilds the whole roster and runs a fingerprint-table query whose result is not used `[CODE]` (a comparable query took 6.8 s on this PC class `[FIELD]`), so it can be well above the floor -- D4 measures it. | the completion lines | `[T] PIN_SCHEME_ACCOUNT_WITHHELD` → "Réinitialisation complète" (full member refresh); persists → those members get in at the desk, call the developer. `[T] CAPACITY_FULL` → Quit, quick export, read `users_free`/`fingerprints_free`, call the developer. `[T] TEMPLATE_VERSION_MISMATCH` → stop, call the developer (G3 was wrong; those members' fingers are not written; their cards still are). `[T] REVOKE_ABORTED` → the retire missed rows: Quit, §5.1 counts |
| E12 | **Verify**: Quit Access on P1, `-Fingers` export of each terminal (full commands), comparison with `--scheme ACCOUNT --access-db <fresh copy>` on the G11 machine: `member_owned` = `deliverable_people`, `leftover` = the kept admins, `sha self-check` at the Phase B rate, no `people_with_terminal_only_finger`. Restart Access. `[TEST: TestVerifyingThePushUnderAccount -- the same terminal read as MEMBERSHIP shows no member]` | numbers as stated | Members missing: "Réinitialisation complète", redo E11-E12 |
| E13 | **Doors**: 3-5 people with MonClub fingers (finger AND card), one expired member (refused), one QR code, the reception "Open" button | all as expected | See the half-state table |
| E14 | P1: re-tick start-with-Windows, watchdog on, resume Windows Update. P2/P3 stay blocked (D2). **Open.** | -- | -- |

During E11 anyone not yet written back is refused by the terminal, the reception **Open** button can
time out (a chunk holds the worker ~4 s against the button's 2 s wait, and an expired press is never
executed later) `[CODE+TEST: guide §3.1a/§3.4e]`, and QR / staff-card rescues work between chunks.

#### 5.1 The retire, if done by hand (D3 = b) -- one transaction per terminal
With Access stopped on that PC, a copy of `access.db` taken, and for device `D` = 8 or 10 **only if
D passed E6**. Stopped means: Task Manager shows no `MonClubAccess.exe`, AND renaming the folder
`%ProgramData%\MonClub Access\access` to `access_x` and back succeeds (Windows refuses the rename while
any process holds `access.db` open). `BEGIN IMMEDIATE` is NOT a check: in WAL mode an idle Access passes
it and writes again afterwards `[CODE: db.py journal_mode=WAL]`.
```sql
-- baseline, recorded
SELECT device_id, COUNT(*), SUM(ownership_confirmed) FROM device_sync_state GROUP BY device_id;
SELECT device_id, COUNT(*) FROM device_push_intent GROUP BY device_id;
SELECT device_id, COUNT(*) FROM device_content_mirror GROUP BY device_id;
SELECT * FROM device_pin_scheme_switch;  SELECT * FROM device_pin_scheme_seen;
-- retire device D
BEGIN IMMEDIATE;
DELETE FROM device_sync_state     WHERE device_id = D;
DELETE FROM device_push_intent    WHERE device_id = D;
DELETE FROM device_content_mirror WHERE device_id = D;
COMMIT;
-- check: the three counts are 0 for D; the switch/seen rows are unchanged
```
Never touch `device_pin_scheme_switch`, `device_pin_scheme_seen` (the history door events are read
by), `access_history`, `member_account_link`. Rows of a device id that no longer exists (e.g. 9 in the
2026-09-05/06 copies) have no worker and are harmless. This needs a SQLite command-line tool on the gym
PC; none ships with Access. P2 and P3 drove both terminals too (§3.3), so they hold rows of their own.
**On a PC still running 1.4.33** there is no `device_push_intent` (nor the scheme-history tables):
`git show access_1.4.33:app/core/db.py` `[CODE]` -- there, retire `device_sync_state` and
`device_content_mirror` only, and skip the baseline SELECTs of the missing tables.

#### 5.2 The firewall block (P2/P3 from E1; P1 instead of unplugging)
Admin PowerShell:
```powershell
New-NetFirewallRule -DisplayName "MonClub cutover hold TCP" -Direction Outbound -RemoteAddress 192.168.1.246,192.168.1.247 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "MonClub cutover hold UDP" -Direction Outbound -RemoteAddress 192.168.1.246,192.168.1.247 -Protocol UDP -Action Block
```
(Or the same two rules in `wf.msc` → Outbound Rules → New Rule → Custom → Remote IP.) All ports, both
transports: which transport and port `Connect_Net` uses on these MB2000s is not recorded anywhere
`[UNVERIFIED]`. **Prove it on that PC, in two runs:** BEFORE adding the rules,
`14_export_terminal_readonly.ps1 -DeviceIp 192.168.1.247 -Label test -Auto` must connect (this proves
the IP and the comm key, B0); AFTER, the same command must end with "Connect_Net returned FALSE" --
it then waits for ENTER even with `-Auto` (`_common.ps1::Connect-Zkem` calls `Pause-End`) `[CODE]`.
Same for .246. If the second run connects, the block does not work: unplug instead (P1) or keep that PC
switched off and off the network (P2/P3). Remove with `Remove-NetFirewallRule -DisplayName "MonClub
cutover hold TCP"` (and UDP).

#### 5.3 P2 and P3 afterwards (D2)
Started as they are, each would record the switch, re-push every account pin once, and jam its own
removal step like §2; on 1.4.32/1.4.33 it pushes membership pins onto the account terminals `[CODE]`.
For each PC that D2 brings back, with the gym closed and its §5.2 block still on:
1. Access stopped on it (untick start-with-Windows, Quit, watchdog off, the §5.1 rename test).
2. Retire its rows for each of 8 and 10 switched to « Par personne » by then (a terminal the night left
   « Par abonnement », runbook D6's « Then, by the other terminal », keeps its rows -- lane 1h, 2026-09-28).
   **D3 was decided on 2026-09-27 as the Erase wizard's « forget »**
   (runbook D10 (a)), which retires only the PC that runs the erase -- P1. P2 and P3 run no erase, so
   for them it is one of (lane 1e, master review F6):
   - §5.1's SQL (D3 (b), runbook D10 (b)), **on the version it runs** (1.4.33: `device_sync_state`
     and `device_content_mirror` only), then step 3;
   - or a fresh data folder (runbook D10 (c): the old folder renamed and kept, `data\app.db` moved
     into it too), after step 3 and before step 4 -- step 4's line then reads `previous=UNKNOWN
     scheme=ACCOUNT cleared_rows=0 first_sighting=True` (runbook D14).

   The no-engine "forget" action that D3 (a) below described was never built -- the wizard replaced
   it. Never erase a live terminal again only to get a « forget » for P2 or P3.
3. Install 1.4.35 with the installer's last box **"Launch MonClub Access" unticked** (it is ticked by
   default and would start Access before the retire otherwise `[CODE: installer/MonClubAccess.iss [Run]
   postinstall]`) -- and **"Keep MonClub Access running" unticked** (ticked, it registers the watchdog,
   which starts Access by itself within minutes; runbook A7, C3c, D9), in the session of the Windows
   account Access is installed under (runbook A1).
4. Start Access. Its first start marks each device as seen on MEMBERSHIP and then receives ACCOUNT for
   each one switched, so its log must show `[T] PIN_SCHEME_SWITCH device_id=8 … cleared_rows=0` for 8 and
   the same for 10 -- for each terminal switched to « Par personne » by then (a terminal still « Par
   abonnement »: no line for it, expected; lane 1h) `[CODE: db._ensure_pin_scheme_column,
   ::_record_device_pin_scheme_switch records nothing when the scheme is unchanged]`. `cleared_rows` ≠ 0 → it wrote
   rows after the retire: Quit, retire again.
4b. **Restart it, proven** (runbook part C's box "Proving a restart", with its « Pilote / Lecteur » page
   reading -- the box's later-day sentence: « PC lecteur » when a driver is set by then, §7 D2), and no later `PIN_SCHEME_SWITCH …
   previous=ACCOUNT scheme=MEMBERSHIP` line (runbook C13, D15). Only then step 5 -- the order runbook C1b
   brings a gym 58 PC back in (lane 1f review, 2026-09-28).
5. Remove the block; its one re-push rewrites every member. Re-tick start-with-Windows, and the watchdog
   as the runbook's part C box "Turning the watchdog back on" says (by what exists now: a task,
   `Enable-ScheduledTask`; none, `register_watchdog.ps1`; its `State` must read `Ready`).

### Phase F -- the days after
Daily, P1's log: no `REVOKE_ABORTED`, no `MAINTENANCE_SKIPPED`, no `CAPACITY_FULL`, no
`PIN_SCHEME_ACCOUNT_WITHHELD`; `FINGER_SWEEP` lines are expected (every new row starts unswept, ≤100
pins a day `[CODE]`, harmless on a wiped terminal). **Any new `[T] PIN_SCHEME_SWITCH` after the cutover
day** (someone edited the scheme, D8) → stop and call the developer. On P2/P3 (D2 a): the two block rules
still exist in `wf.msc`. Once revoked (runbook D12) they send no heartbeat (§3.3), so their "last seen"
on /access-pcs stops moving: that says nothing about the block, which only `wf.msc` shows. Door complaints → check that person in MonClub (fingers
enrolled? membership deliverable?). Delete the biometric backup files per D7.

## 6. Half-states and rollback

*On the cutover night, runbook part F comes first (the banner at the top): a terminal the Erase wizard
holds takes no push until « Remplir », and « Remplir » needs the internet.*

**Which states the gym can open in:** only (a) before E5 -- nothing changed -- and (b) after E13 passed.
Anything between refuses members at that terminal (device 8 "Sortie" is the exit). If the gym must open
anyway, apply the row below for that state first; members already written back get in, the others are
let through by staff: the owner says the turnstile arm can be dropped by hand so everyone enters freely
`[OWNER, 2026-09-26, relayed by the master session]` -- nobody is then checked and nothing is logged,
so a staff member stays there until the push is proven and the arm is raised; how it is dropped and by
whom is not written down yet. The reception Open button can time out during a push, and cannot open a
terminal whose cable is out or that is blocked (`local_access_api_v2._handle_device_door_open`, 503)
`[CODE]`; QR codes work between chunks.

| Row | Point reached (per terminal) | Back to a working door | What cannot be undone |
|---|---|---|---|
| R1 | Before E5 | Re-tick start-with-Windows, watchdog on, restart Access on P1 | nothing changed |
| R2 | E5 started, **not retired** (before E8) | Cables in / block off, start Access on P1, press **"Réinitialisation complète"**: it clears every per-pin record's hash and the version tokens but keeps ownership `[CODE: local_access_api_v2._handle_sync_hard_reset, db.clear_all_device_sync_hashes]`, so every member is re-pushed under MEMBERSHIP. Done when the E11 completion lines appear; check with an E12 run using `--scheme MEMBERSHIP`. | the old system's users (the goal) |
| R3 | Retired (E8), **switch not recorded** | First make sure the dashboard says **"Per membership"** for that device (if E9 saved "Per person", set it back and reopen the device to check) -- otherwise a first sync that fails at boot would push ~919 membership pins that the later switch then strands above the removal ceiling (§2). Then start Access on P1 **behind the interlock**, wait for `getSyncData OK` in the log, plug in: every member is new to it and is pushed under MEMBERSHIP `[CODE]`. Same completion check as E11. | as R2 |
| R4 | Switch recorded (E10), before or during E11 | Count the account pins already pushed (P1's `device_sync_state` rows with `ownership_confirmed=1` for that device) and the unconfirmed ones (`device_push_intent` rows for it). **At or under the removal ceiling** `max(10, 25 % of the MEMBERSHIP roster)` (~229 for 919 memberships; use 225 to be safe; refused only strictly above `[CODE: push_safety.check_bulk_removal]`): unplug, Quit, set "Per membership", **do not retire**, start behind the interlock, plug in -- the MEMBERSHIP pass removes those owned account pins `[CODE: push_safety.check_bulk_removal]`; proof: no `REVOKE_ABORTED`, an export shows no account pin left -- except intent-only pins (a chunk cut off by the Quit), which leave only after the next day's read-back promotes them `[CODE: ultra_engine._promote_intents_by_readback]`. **Above it**: wipe again (E5-E6), retire, switch back, interlocked push. | -- |
| R5 | After opening | A full second procedure | the old system's users (the goal) |
| R6 | **Power lost during E5** (a terminal mid-erase) | At power-on: Access stays stopped (start-with-Windows unticked, watchdog off). Re-run script 13 on that terminal (it re-reads the users and deletes what is left `[CODE]`), then E6. If the day is over: R2 for that terminal before opening. | -- |
| R7 | **Power lost during E11** (switch recorded, push partial) | At power-on Access starts (start-with-Windows was re-ticked only at E14, so start it by hand); its start-up full pass continues the push: every written chunk is recorded, the chunk in flight is covered by its push intent `[CODE: guide §3.4a]`. Wait for E11's completion lines. | -- |
| R8 | A terminal **left for another day** (not wiped, or wipe abandoned + R2; on the cutover night also a terminal runbook D6 released by any stop of « Then, by the other terminal » while the other was left erased and held -- « To stop there », « Échec », the clock, and « Incomplet » twice after its « Remplir »: its « Remplir » already asked the full re-push, so no R2; lane 1h) | It stays on MEMBERSHIP with its old contents (after « Incomplet » twice: the members its « Remplir » wrote back; the people a partial erase removed that MonClub does not list are gone) and works overnight and the next days as it does today; finish it with its own E5-E13 on another closed morning. | -- |
| R9 | Phase D (1.4.35 installed) must be undone | Restore the D0 copy of the data folder, reinstall 1.4.33 (`[UNVERIFIED]` on a migrated database, D2) | -- |

**Every row that stops Access** (R2-R4, R6, R8, R9 with a reinstall) starts with the watchdog off --
`Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'`, if it exists -- then Quit (runbook part F,
"The watchdog during a rollback"). **Whichever row ends the day:** R2-R4, R8 and R9 end with Access
started and give none of its autostart back, and a data folder copied back was copied with
start-with-Windows unticked (Access then deletes its start-up entry at every start,
`app/ui/app.py::_sync_startup_registration`) `[CODE]`. So finish with the runbook's **F-end** step on
every PC that runs Access: re-tick start-with-Windows, the watchdog back on (runbook part C, "Turning the
watchdog back on": by what exists now, its `State` `Ready`), **resume Windows Update on P1** (paused at E1) -- and the next evening one
power cycle (runbook E6, autostart checklist §5). Not on a PC that must stay stopped (P2/P3 behind
their block, D2).

**Restoring the backup instead** (`10_backup_restore_device.ps1` → `[R]`): copy ONE file into
`backups\` at a time and check that its label matches the IP you type. It writes every user back as
privilege 0, **enabled**, without a password `[CODE]` -- a user the terminal had disabled (e.g. a member
who left) comes back able to open the door, and MonClub never removes a pin it does not own. If the E2
backup shows `disabled` > 0 or `privileged` > 0, the owner decides before E5 whether this route is
acceptable. Its duration is unmeasured. Faces are not in any backup, and neither is an admin's
privilege (E5b).

## 7. Decisions the owner must make before execution

- **D1 -- the window.** A morning with the gym closed and the power on -- write down when the power
  comes on at Oxyfit, since that is the real start of the window --, a go/no-go clock for E5, and:
  while any duration is unmeasured (read, erase, re-push), the gym stays closed until E13 passes --
  i.e. opening late is acceptable that day, or the date moves.
- **D2 -- which PC drives, and the other two.** Pick P1 among "Accueil" (LAPTOP-T6KORL9V),
  "Accuil Oxyfit" (no hostname recorded) and "Accueil Oxyfit" (DESKTOP-6UCRVSG) (§1). P2/P3: (a) blocked by the §5.2 firewall rule
  from E1 on, permanently, keeping the rest of Access (**default**; their reception "Open" button then
  stops working, since it goes through the terminal); (b) brought back one by one per
  §5.3; (c) Access removed from them until one-driver-per-turnstile exists.
  *Third round, 2026-09-26:* one-driver-per-turnstile now exists in the Access code (P3b-2, §3.3) but
  cannot be used before the server's commands switch is on and drivers are set -- after the night
  (runbook part H3, G question 17). Once P1 is the driver of 8 and 10, a PC brought back per §5.3 onto
  the new Access and given no driver lease connects to neither terminal, and its reception « Ouvrir »
  is sent through the server to P1 (a 3 s opening; it needs the internet and P1 on; the screen says
  « Demande envoyée au PC pilote. Son résultat n'est pas visible ici. », never that the door opened)
  `[CODE: lease_gate.py, local_api_routes.py::_door_request_via_driver,
  v2/handlers.py::CommandHandlers.door_open, tauri-ui/src/api/realtime.ts::doorRequestedMessage]`.
  Setting a driver is one-way: the dashboard cannot take it back (runbook H3). §5.3's order is kept for it: with no roles cached yet, a
  new Access connects to every terminal until the server answers `[CODE: runtime.py::load_cached_roles]`;
  before the block comes off, its « Pilote / Lecteur » page must read « PC lecteur ». Never tried on a
  gym PC `[UNVERIFIED — FIELD-TEST]`.
- **D3 -- how the retire is done.** **Decided 2026-09-27: the Erase wizard's « forget », on the PC that
  runs the erase (runbook D10 (a)) -- not the (a) below, which was never built; a PC that runs Access
  without having run the erase uses (b), or a fresh data folder (runbook D10 (c), §5.3).** As first
  written: (a) Recommended: a small operator-confirmed "forget this terminal's
  MonClub state after a verified wipe" action in 1.4.35, one device at a time, runnable only with the
  ULTRA engine not started, with tests and guide §3.2e updated; (b) a technician runs §5.1 with the
  official SQLite command-line tool; (c) not retiring is **not an option**: departures would never be
  removed.
- **D4 -- members whose fingers exist only on the terminal** (count from Phase B). (a) Re-enrol at the
  desk (recommended; the proven path); (b) import the template read by the backup into MonClub with the
  existing `POST /manager/userFingerprint/create` (BASE64/HEX, any existing membership, 10-finger cap
  `[CODE]`) -- only if the Phase B `sha self-check` is ≥ 90 % AND a one-person pilot (import, push under
  ACCOUNT, finger at the door) passes, because terminal → MonClub → terminal has never been tried
  `[UNVERIFIED]`; (c) accept the loss for some. Those tied through their own MonClub pin are done
  before the upgrade (G9).
- **D5 -- everyone but the administrators goes.** Confirm the other system is retired for good (its
  users go, including anyone it enrolled after 2026-08-25). Script 13 keeps admins (privilege > 0).
  Review each admin (pin, name) from the Phase B export: anyone who is not current staff is deleted
  before E7 with `7_delete_device_fingerprint.ps1`, choice **`U`** only -- **never** its `0`-`9`
  choices, which call the finger-index delete that hangs this firmware (zkemkeeper_guide §3).
  MonClub never removes an admin row; whether an admin's scan opens the door is `[UNVERIFIED]`.
- **D6 -- switch now or later.** Wipe + account PINs in the same window (recommended: one wipe), or wipe
  + MEMBERSHIP re-push now (R3's path) and a second wipe later for the switch.
- **D7 -- biometric backups.** Where the `-IncludeTemplates` files are kept and when they are deleted.
- **D8 -- the pinScheme field is editable by any gym login without the dialog** (§3.4). Accept for now,
  or tighten the backend first.
- **D9 -- script 13's labels.** Its menu still labels the whole-user delete "UNVERIFIED api", while
  `zkemkeeper_guide.md` §3 grades backup number 12 `[FIELD]` on the 2026-09-06 run (device and counts
  unrecorded). Fix one of them after the cutover; E6's checks do not rely on either.
- **D10 -- measure the re-push before the day** (D4 of Phase D): writes every member again to both
  terminals with the gym closed, in exchange for a measured E11 duration.
- **D11 -- the production copy for the comparison.** Who makes the export, how it is scrubbed (like
  wigo-demo: no emails, tokens, phone numbers), what the database is named, where it is restored and
  when it is deleted. The tool refuses only the name `wigo-db`; it cannot tell a scrubbed copy from an
  unscrubbed one, so this is a rule for people. Its output is aggregates; `--detail-csv` holds names.
- **D12 -- people.** The on-site technician and the developer on call for the window (§3.6), and who
  runs the comparison.
- **D13 -- what the owner accepts if it happens:** a terminal fingerprint version that cannot be read
  from anywhere (G3 -- the push's version check is then inert); faces on a terminal (G8 -- lost);
  a `sha self-check` below 90 % (G4 -- the lost-finger counts become lower bounds, so the members tied
  to leftovers test at the door or re-enrol); a backup with `disabled` or `privileged` users (§6 -- the
  restore route would re-enable or demote them).

## 8. Field tests (each needs the real terminals)

| ID | What | Exact check | When |
|---|---|---|---|
| FT1 | Duration of the template read | `timings.msPerFingerRead` in a `-MaxUsers 50` export | B2 |
| FT2 | `~ZKFPVersion` of both terminals | `device.fpVersion`; else `deviceFpVersion=` in P1's log | B3, B5 |
| FT3 | Template bytes round-trip (pushed = read back) | `sha self-check` rate in the comparison | B6 |
| FT4 | Old-system pin = its card id | `leftover_pin_is_a_gms_card_id` and `links_agree` | B6 |
| FT5 | Whole-user delete time and results | `logs\clear_*.log` timestamps; `DONE ok= failed=` | B7 / E5 |
| FT6 | Index 11 = users free | `users + users_free = user_capacity` in the E6 export | E6 |
| FT7 | Re-push per-pass setup and total time | `FULL_SYNC_START` → first `ZKEM_PUSH_CHUNK`; first to last pass | D4 (optional) / E11 |
| FT8 | The terminal keeps deciding during a push | someone already written back scans during E11 | E11 |
| FT9 | An admin whose pin equals an account id | `account_pins_already_on_terminal` = 0 in E6 (4) | E6 |
| FT10 | Template import rescue (only if D4 = b) | one person: import, push, finger at the door | C |
| FT11 | `GetSysOption` from PowerShell on an MB2000 | `fpVersion` not null in B3 | B3 |
| FT12 | Pin format returned by the terminal | `pins_not_in_canonical_form` = 0 | B6 |
| FT13 | The firewall block stops the SDK connection | §5.2 proof | E1 / E7 |
| FT14 | A terminal after a hung delete still verifies | a member at that door | E5 (only if it happens) |

Not tested, and never tried by this plan: a second SDK connection while Access holds one (gate G5b of
the driver plan; Access is always stopped before a script connects).

## 9. Still unknown after this plan
- What the 2026-09-06 script-13 run deleted, and so what the terminals hold today (Phase B answers it).
- The production numbers (roster, fingers, PCs' versions today) -- wigo-demo is a mutated rehearsal copy.
- Durations: full read, erase, per-pass setup (FT1, FT5, FT7).
- Whether the MB2000 sends events for scans made during a push chunk (guide §3.4e) -- the gym is closed.
- How the turnstile arm is dropped by hand, and who on staff can do it (the owner says it can be
  dropped, `[OWNER, 2026-09-26]`; the method is not recorded).

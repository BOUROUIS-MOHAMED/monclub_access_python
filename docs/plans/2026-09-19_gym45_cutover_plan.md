# Gym 45 (Oxyfit) cutover -- wipe both MB2000s, account PINs, MonClub-only, re-push

**Status: PLAN ONLY.** Nothing here has been executed. No terminal was written to, erased or
reconfigured and no database was changed while writing it. The owner approves the plan and picks
the time; execution is a separate, later step. Written 2026-09-19 against Access `master`
`ca1e29a`, backend `main` `e40f8648`, dashboard `main` `e0eef4af`. Branch
`claude/gym45-cutover-plan` (not merged, not pushed).

Every claim is graded as in the guides: `[CODE]` (an executable statement, named), `[TEST]`,
`[FIELD]` (a dated measurement), `[COMMENT]` (prose only), `[UNVERIFIED]`, `[UNKNOWN]`.
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

**The order is fixed:** wipe → verify empty → retire → switch → push. Retire before the wipe strands
real pins; retire after the first ACCOUNT push erases the new pins' ownership.

**Why the terminals stay unplugged until the switch is recorded.** The ULTRA engine starts inside the
first sync tick, after `getSyncData` `[CODE: app.py::_sync_tick]`. If that first call fails (no
network yet at boot), the engine starts from the cached device row -- still MEMBERSHIP -- and, with
manual sync off, pushes at once `[CODE]`. With the rows retired it would push ~900 membership pins
as new. Unplugging the terminals (or blocking TCP 4370 on that PC) makes that impossible
`[CODE: the worker's run loop does nothing while unconnected]`.

## 3. Prerequisites (all before the day)

### 3.1 Access build
A release built from `master` at or after `ca1e29a` (pin-scheme gate + P3a-2: write-ahead ownership,
removal ceiling, capacity and template-version checks, 50-pins-per-pass cap). Call it 1.4.35.
- Installed on **every PC that will ever connect to the turnstiles** at least **2 days before**
  the cutover, running normally on MEMBERSHIP -- and only AFTER the survey (Phase B says why). The upgrade adds `sync_users.main_account_id` and
  forces ONE full member refresh to fill it, and adds `sync_devices.pin_scheme` and forces one
  device refresh `[CODE: db._ensure_main_account_id_column, ::_ensure_pin_scheme_column]`.
- Check each PC's version on the dashboard's **/access-pcs** page (it shows the app version from
  the heartbeat `[CODE: dashboard gym-access-pcs-table-row.tsx]`).
- **Decision D3** may add a small "retire" action to this release (§7).

### 3.2 Backend and dashboard
Production must have: `GymDevice.pinScheme` and its emission in the sync (`effectivePinScheme`),
`mainAccountId` on every member row, person-scoped fingerprint delivery, and the dashboard's
"PIN scheme" choice on /gym-devices `[CODE: backend main 93c01af6/4b00d546, 7f0c2df7; dashboard
56f516d5/59c08cb2]`. **Which backend build runs in production cannot be read from anywhere**
(no build-info endpoint `[CODE]`). It is proven indirectly by gate G2 below: after the new client's
forced refresh, the PC's own database shows `pin_scheme='MEMBERSHIP'` for devices 8 and 10 (the
backend sent the field) and no member row without `main_account_id` (the backend sent it).

### 3.3 Who drives the turnstiles
Today every Access PC of the gym connects to every device; nothing in the software stops two PCs
driving one terminal `[CODE: backend sends every device to every PC; UltraEngine starts a worker
per ULTRA device]`. There is **no per-PC switch** to keep one PC off the turnstiles:
`device_local_settings` only gates the door button, `device_sync_enabled` does not gate ULTRA, and a
bogus `MONCLUB_DEVICE_PROTOCOL_OVERRIDES` value silently routes to PullSDK `[CODE]`. The per-turnstile
driver/reader feature is not built `[CODE]`. The controls that exist: stop the app, disable its
autostart, or block TCP 4370 from that PC to .246/.247 with Windows Firewall.

**P1** = the one PC that drives both turnstiles during and after the cutover (**decision D2**).
P2, P3 = the other two. During the window P2 and P3 are **switched off**. Afterwards they need the
same retire + interlocked first start as P1, or they stay off the turnstiles (D2).

How to fully stop Access on a PC `[CODE]`: tray icon → Quit (kills the UI process
`monclub-access-ui.exe` too). Then check Task Manager shows no `MonClubAccess.exe`. Two things can
start it again:
- the **watchdog** task "MonClub Access Watchdog" (opt-in at install; every 2 min):
  `Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'` / `Enable-ScheduledTask …` (check it
  exists first: `Get-ScheduledTask -TaskName 'MonClub Access Watchdog'`);
- the **Windows start-up** entry (Config page "Ouvrir MonClub Access avec Windows"): value
  `MonClubAccess` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` -- only at logon, so
  it matters only if the PC is restarted during the window.

### 3.4 Settings in /gym-devices, and when
Nothing changes before the day. On the day, after the retire (step E7): device 8 and device 10 →
**PIN scheme: "Per person"** (`ACCOUNT`). The dashboard shows a wipe-first dialog with two
checkboxes ("MonClub Access has been updated…", "this terminal's users have been wiped")
`[CODE: dashboard gym-devices-view.tsx]`. Keep **Mode = ULTRA** and **roster policy = PRESERVE**
(MIRROR buys nothing after a wipe and would enumerate the terminal on every explicit sync, §3.2c).
Do not touch the "fingerprint template" dropdown: it has no effect on the MB2000 path
`[CODE: _resolve_template_version_override is PullSDK-only]`.

A pinScheme edit bumps the device's `updatedAt`, so every PC's next sync gets the device refresh
`[CODE: GymDeviceController.update, GymAccessController.computeDevicesVersion]`.

**Exposure created by this cutover (decision D8):** `POST /connected/gym-device/update` does no
permission check for a gym login `[CODE]` -- anyone with the gym's login can flip `pinScheme` without
the dialog and without a wipe. Before the cutover nobody had a reason to touch that field.

### 3.5 Go / no-go gates (all green, or the wipe does not start)
| # | Gate | How it is read |
|---|---|---|
| G1 | Every PC that will connect runs ≥ 1.4.35 | /access-pcs version column |
| G2 | On a copy of P1's `access.db` taken after the upgrade (C3): `rows_without_main_account = 0`, and `pin scheme recorded by the PC: MEMBERSHIP` for 8 and 10 | `compare_terminal_export.py … --access-db` output |
| G3 | Both terminals report `fpVersion` equal to MonClub's template version (all `delivered_templates_version_10` → `fpVersion 10`). A mismatch makes the push skip every finger (`TEMPLATE_VERSION_MISMATCH`) `[CODE]` | survey export + comparison |
| G4 | The Phase B comparison's `people_with_terminal_only_finger` / `people_losing_every_finger` are each rescued or explicitly accepted by the owner (D4) | comparison + `--detail-csv` |
| G5 | On the day: the backup export (`-IncludeTemplates`) is `complete: true` for both terminals and copied to two places | the file + its `.sha256` |
| G6 | The retire method (D3) is ready and rehearsed on a copy of P1's `access.db` | dry run on the copy |
| G7 | /gym-devices shows the "PIN scheme" choice for devices 8 and 10 | dashboard |
| G8 | `faces = 0` on both terminals, or the owner accepted losing them (nothing can back a face up) | export counter 21 |

## 4. The tools (read-only; on branch `claude/gym45-cutover-plan`)

**`tools/mb2000_scripts/14_export_terminal_readonly.ps1`** -- one terminal to a JSON file:
identity, clock skew, counters (GetDeviceStatus 1-12, 21, 22), `~ZKFPVersion`, every user (pin,
name, card, privilege, enabled, has-password), with `-Fingers` each finger slot's size and SHA-256,
with `-IncludeTemplates` the templates (a backup script 10 can restore). Proof it never writes
`[TEST: tests/test_mb2000_export_readonly.py, 14 tests]`: every `$zk.` call in it and in
`_common.ps1` is on the allowlist `SetCommPassword, Connect_Net, Disconnect, GetFirmwareVersion,
GetSerialNumber, GetDeviceMAC, GetPlatform, GetVendor, GetDeviceIP, GetDeviceTime, GetDeviceStatus,
GetSysOption, ReadAllUserID, SSR_GetAllUserInfo, GetStrCardNumber, SSR_GetUserTmpStr`; no write
method name appears outside a comment; no dynamic invocation; only `_common.ps1` is dot-sourced;
and the shipped script, run against a fake terminal that has ONLY those methods and logs every call,
completes. Its enumeration and template read are the calls of script 10's Backup and script 13's
inspect mode; `GetSysOption('~ZKFPVersion')` is the Access driver's own read, not yet run from
PowerShell on an MB2000 (on failure `fpVersion` is null) `[UNVERIFIED]`. Unlike the Access driver
it never sends `EnableDevice`, `RegEvent` or `RefreshData`. What the firmware does inside a read is
beyond any test `[UNVERIFIED]`.

**`tools/gym45_cutover/compare_terminal_export.py`** -- the comparison (README in that folder).
Reads a copy of `access.db` query-only and a MySQL copy in a `READ ONLY` transaction, SELECT only,
templates hashed inside MySQL, `wigo-db` refused `[TEST: 36 tests]`. Rehearsed against wigo-demo
for 2026-09-12: its SQL roster gives 919 / 902 like the independent measurement, and on a synthetic
terminal with known answers all 9 checks pass `[TEST: rehearsal_check.py, run 2026-09-19]`.

## 5. The procedure

Times marked *measured* come from a field record; everything else is **unmeasured**, and the phase
that measures it is named. Planning reserves are reserves, not estimates.

### Phase A -- build (dev, before anything else)
A1. Build and publish 1.4.35 from `master` ≥ `ca1e29a` (+ the retire action if D3 = a).
A2. Guides updated for anything the release changes; suite green (`python -m pytest tests/ -q
--ignore=tests/_pydeps`; one test, `test_review_round6::test_r6_01…`, fails when the PC has been up
under ~83 min -- a test bug, not the app `[TEST: 2026-09-19, uptime 966 s]`).

### Phase B -- survey and first backup, on the build the PCs run today (before any upgrade)
**Why before the upgrade.** 1.4.35 brings P3a-2's finger-slot sweep: it clears the unused finger
slots of pins MonClub owns, ≤100 pins a day, after the first full sync of each day `[CODE:
ultra_engine._drain_finger_sweep]` -- and that includes fingers enrolled directly on the terminal
under a MonClub pin (guide §7, R3-25), which are exactly what this survey must find. The release the
PCs run today (1.4.33) has no sweep and does record ownership and finger ids `[CODE: git show
access_1.4.33:app/core/db.py]`, so the survey is complete on it. (1.4.32, on the third PC, is not
tagged.)

One hour with the gym closed and the power on:
B1. Stop Access on all three PCs (§3.3), watchdogs disabled.
B2. On P1, in the script pack: `14_export_terminal_readonly.ps1 -DeviceIp 192.168.1.247 -Label
device8 -Fingers -MaxUsers 50 -Auto` → `msPerFingerRead` in the file **measures the full read
time** (users × 10 × msPerFingerRead). Decide from it whether B3 fits in the hour.
B3. `-IncludeTemplates` export of both terminals (two windows, one per IP): the analysis input AND a
first backup of everything on them. Keep the files private (biometric data, D7).
B4. Copy P1's `%ProgramData%\MonClub Access\access\` folder (`access.db` + `-wal` + `-shm`, Access
stopped) to a USB key. (`MONCLUB_ACCESS_DATA_ROOT` overrides the path. Do not confuse it with the
install folder `%LOCALAPPDATA%\MonClubAccess`, and never uninstall Access without this copy -- the
uninstaller deletes the data folder `[CODE: installer/MonClubAccess.iss [UninstallDelete]]`.)
B5. Re-enable the watchdogs, start Access where it normally runs.
B6. Dev PC: `compare_terminal_export.py --export 8=… --export 10=… --access-db <copy> --mysql-*
<fresh production copy> --day <today>` → gates G3, G4, G8, and the facts §1 left unknown: how many
leftovers remain (answers what the 2026-09-06 clear did), admins, faces, `sha self-check` (whether
the terminal returns MonClub's template bytes -- decides whether an import rescue is credible, D4),
`pin_is_a_gms_card_id`.
B7. If the gym PC's script-pack folder still has `logs\clear_*.log` from 2026-09-06, it gives the
time per whole-user delete (one timestamped line per pin, written before each call `[CODE]`). That is
the only possible measurement of the erase time before the day.

### Phase C -- upgrade, ≥ 2 opening days before the cutover, after Phase B
C1. Install 1.4.35 on P1 (and on P2/P3 if they will ever connect again, D2). Check /access-pcs.
C2. Let it run on MEMBERSHIP. Watch P1's log for `REVOKE_ABORTED`, `CAPACITY_FULL`,
`TEMPLATE_VERSION_MISMATCH`, `FINGER_SWEEP`.
C3. The day before the cutover: Quit Access on P1 for a minute, copy the data folder, restart. Run
the comparison on that copy → **gate G2**: `rows_without_main_account = 0` and `pin scheme recorded
by the PC: MEMBERSHIP` for 8 and 10 (proof that the production backend sends both fields).

### Phase D -- rescue (between B and E)
Per D4, for each member listed in `--detail-csv` as `member_terminal_only_finger`: re-enrol at the
desk through MonClub, re-enable a template MonClub has but does not deliver
(`terminal_only_but_template_in_monclub`), or import (only after a pilot, D4).

### Phase E -- the cutover (gym closed, power on; morning before opening recommended, D1)
Reserve: the Phase B read time + the erase time (B7 or unknown) + about an hour of fixed steps +
the re-push (E11). Fix a **go/no-go clock time**: if E5 has not started by then, stop -- nothing has
changed yet.

| Step | Action | Proof it worked | If it fails |
|---|---|---|---|
| E1 | P2, P3: Quit Access, disable watchdog, **shut the PCs down**. P1: Quit Access, disable watchdog. | Task Manager: no `MonClubAccess.exe` on P1 | Nothing changed -- restart Access, stop |
| E2 | Backup: `14_… -IncludeTemplates -Auto` on both terminals (two windows). Copy both files + `.sha256` to two places (USB + owner PC). Copy P1's data folder (as B4). | both files `complete: true` (gate G5) | Nothing changed -- abort or retry |
| E3 | Quick export of both terminals; compare counters with the survey | user/fingerprint counts close to B3 | Investigate before going on |
| E4 | **Go / no-go.** All gates G1-G8 green? | -- | No-go: restart Access on P1, re-enable watchdogs. Nothing changed |
| E5 | **Erase, each terminal:** `13_inspect_and_clear_tables.ps1` → IP → step 2 `[N]` → step 3 **`[U] USERS whole rows`** → scope **`[A]`** (all non-admin users) → if faces > 0 the script asks, answer per G8 → type **`CLEAR`**. It deletes every non-admin user with `SSR_DeleteEnrollData(1, pin, 12)`, logs each pin before the call, preserves admins (privilege > 0) `[CODE]`. Duration **unmeasured** (B7). | the script's BEFORE → AFTER table; its log `DONE ok=… failed=0` | A pin that failed: re-run (it re-reads users). A wedge (script hangs): the log's last line names the pin. Rollback from here = restore (§6) |
| E6 | **Verify empty, both terminals:** quick export `14_… -Auto`; the terminal's own user count on its screen; one member's finger and card at each door must be **refused**. The export's users must be exactly the admins listed by script 13; `fingerprints` counter = those admins' fingers; `faces` = 0. | three independent reads agree | Not empty: repeat E5 for what is left. Never retire on a doubtful wipe |
| E7 | **Retire on P1** (Access still stopped), per D3: delete the rows of `device_sync_state`, `device_push_intent`, `device_content_mirror` for the terminal device ids (8, 10, plus any stale id of the same terminals such as 9) -- after a backup of `access.db`. Never touch `device_pin_scheme_switch`, `device_pin_scheme_seen`, `access_history`, `member_account_link`. SQL and checks in §5.1. | counts 0 for 8/10 | Restore the `access.db` backup; stop |
| E8 | **Unplug both terminals' network cables** (the interlock; or a firewall rule on P1, §5.2). The turnstiles keep power. | the terminal shows no link / P1 cannot reach them | -- |
| E9 | Dashboard /gym-devices: devices 8 and 10 → **PIN scheme "Per person"**, tick both boxes, save. Nothing else changes. | reload shows "Per person" | Leave as is; no PC is running |
| E10 | Start Access on P1. Wait for the switch in the log (`%ProgramData%\MonClub Access\access\logs`): **`[DB] device id=8 … pinScheme MEMBERSHIP -> ACCOUNT … cleared 0 per-pin sync hash(es)`** and the same for 10 (`cleared 0` is the durable proof the retire came first), plus `[T] PIN_SCHEME_SWITCH`. | both lines present | No line after a few minutes: Access "hard reset" (clears the version tokens, forces the device refresh `[CODE]`). Still nothing: backend lacks pinScheme -- stop, switch back to "Per membership" in the dashboard, then restart; the terminals are empty and get a MEMBERSHIP re-push (§6) |
| E11 | **Plug the cables back in.** P1 reconnects within ≤ 2 min `[CODE: backoff ≤120 s + ≤20 s connect]` and re-pushes: 50 pins per pass, the passes back to back, both terminals in parallel `[CODE]`. Floor: ~902 people ÷ 50 = **19 passes × ≤ 22.6 s of writes ≈ 7 min per terminal**, from the one field rate (928 users / 419 s, device 8, v1.4.26, before P3a-2 `[FIELD]`). Each pass also rebuilds the whole roster and runs a fingerprint-table query whose result is not used `[CODE]`; on this PC class a comparable query took 6.8 s `[FIELD]`, so the real time can be well above the floor -- **measure it:** each `FULL_SYNC_START` to that pass's first `ZKEM_PUSH_CHUNK`. Watch for `FULL_SYNC_CAPPED … left=0` then no more passes; `ZKEM_PUSH_DONE failed=0`. | the capped passes stop; the log shows no `REVOKE_ABORTED`, `CAPACITY_FULL`, `TEMPLATE_VERSION_MISMATCH`, `PIN_SCHEME_ACCOUNT_WITHHELD` | See §6 |
| E12 | **Verify:** Quit Access on P1 (watchdog still off), quick export `-Fingers` of both terminals, then `compare_terminal_export.py --scheme ACCOUNT --export … --access-db <fresh copy>` → `member_owned` = `deliverable_people`, `leftover` = the kept admins, `sha self-check` at the Phase B rate, `people_with_terminal_only_finger` absent. Start Access again. `[TEST: TestVerifyingThePushUnderAccount -- the same terminal read with the default MEMBERSHIP shows no member]` | numbers as stated | Missing members: see §6 |
| E13 | **Door test at both doors:** 3-5 staff/members with MonClub fingers (finger AND card), one expired member (refused), one QR code, the reception Open button | all as expected | See §6 |
| E14 | Re-enable P1's watchdog. P2/P3 per D2 (§5.3). **Open the gym.** | -- | -- |

During E11, members not yet pushed are refused by the terminal, the reception **Open** button times
out (a chunk can hold the worker ~4 s against the button's 2 s wait, and an expired press is never
executed later) `[CODE+TEST: guide §3.1a/§3.4e]`, and QR / staff-card rescues work between chunks.
The gym is closed, so none of this is seen by members.

#### 5.1 The retire, if done by hand (D3 = b)
With Access stopped on that PC and a copy of `access.db` taken:
```sql
-- baseline (record it)
SELECT device_id, COUNT(*), SUM(ownership_confirmed) FROM device_sync_state GROUP BY device_id;
SELECT device_id, COUNT(*) FROM device_push_intent GROUP BY device_id;
SELECT device_id, COUNT(*) FROM device_content_mirror GROUP BY device_id;
SELECT * FROM device_pin_scheme_switch;  SELECT * FROM device_pin_scheme_seen;
-- retire (BEGIN IMMEDIATE fails with "database is locked" if Access is still writing)
BEGIN IMMEDIATE;
DELETE FROM device_sync_state     WHERE device_id IN (8, 10);
DELETE FROM device_push_intent    WHERE device_id IN (8, 10);
DELETE FROM device_content_mirror WHERE device_id IN (8, 10);
COMMIT;
-- check: the three counts are 0 for 8/10; the switch/seen rows are unchanged
```
Rows of a device id that no longer exists (e.g. 9) have no worker and are harmless; delete them only
if they are the same terminals under an old id (the backend's current list of gym-45 devices decides).
This needs a SQLite command-line tool on the gym PC (none ships with Access). The same statements on
a PC that never pushed to 8/10 delete 0 rows.

#### 5.2 The interlock without unplugging
Admin PowerShell on P1: `New-NetFirewallRule -DisplayName "MonClub cutover hold" -Direction Outbound
-RemoteAddress 192.168.1.246,192.168.1.247 -Protocol TCP -RemotePort 4370 -Action Block`, then
`Remove-NetFirewallRule -DisplayName "MonClub cutover hold"` at E11. Whether `Connect_Net` fails fast
or waits its 20 s deadline behind a Block rule is `[UNVERIFIED]`; either way nothing is written.
Unplugging is simpler and needs no admin rights.

#### 5.3 P2 and P3 afterwards (D2)
A PC that did not take part still holds its own old rows. Started as is (new build), it records the
switch, re-pushes every account pin once (the terminal already has them), and its own removal step
jams exactly like §2 `[CODE]`; on an old build it pushes membership pins onto the account terminals.
So for each PC that will connect again: 1.4.35 installed; Access stopped; retire its rows (§5.1 or
D3's action); start it behind the firewall rule of §5.2 until its log shows the switch; remove the
rule. Do it with the gym closed (its one re-push writes every member again).

### Phase F -- the days after
Daily, P1's log: no `REVOKE_ABORTED`, no `MAINTENANCE_SKIPPED`, no `CAPACITY_FULL`, no
`PIN_SCHEME_ACCOUNT_WITHHELD`; `FINGER_SWEEP` lines are expected (every new row starts unswept; ≤100
pins a day `[CODE]`, harmless on a wiped terminal). Member complaints at the door → check that person
in MonClub (fingers enrolled? membership deliverable?). Delete the biometric backup files per D7.

## 6. Rollback

| Point reached | How to go back | What cannot be undone |
|---|---|---|
| Before E5 | Restart Access on P1 (watchdog on). | nothing changed |
| After E5, before E9 | Either restore the E2 backup onto each terminal with `10_backup_restore_device.ps1` → `[R]` (copy the export file into `backups\` first) -- it writes every user back as privilege 0, enabled, no password `[CODE]`, time unmeasured -- and restore P1's `access.db` copy; or (simpler, same goal) skip the switch: with the rows retired, start Access on P1 and it re-pushes all members under MEMBERSHIP as new pins. | faces (no backup exists); users' privilege/enabled/password if restored with script 10 |
| After E10 (switch recorded), before or during E11 | Unplug again, Quit Access, set "Per membership" in the dashboard, retire again (the ACCOUNT rows, if any), start behind the interlock → MEMBERSHIP re-push. If more than the removal ceiling (~225) account pins were already pushed, wipe again first `[CODE: guide §3.2b switch-back; research]`. | -- |
| After E11/E12 | Going back to MEMBERSHIP is a full second procedure: wipe, retire, switch, interlocked push. | the old system's users, unless restored from the E2 backup (the goal is that they are gone) |

## 7. Decisions the owner must make before execution

- **D1 -- the window.** Date and hours with the gym closed and the power on. Morning before opening
  is recommended: a failure then leaves the whole day to recover, while an evening window can be cut
  by the nightly power-off. Plus a go/no-go clock time for E4.
- **D2 -- which PC drives, and what happens to the other two.** Pick P1. For P2/P3: (a) Access stays
  off on them until one-driver-per-turnstile exists (recommended if they are not needed for daily
  work); (b) they are brought back one by one per §5.3; (c) a permanent firewall block to .246/.247
  on them (they keep the rest of Access).
- **D3 -- how the retire is done.** (a) Recommended: a small operator-confirmed "forget this
  terminal's MonClub state after a verified wipe" action in 1.4.35 (deletes the three tables' rows
  for one device in one transaction, keeps the switch history, logs it) -- new code, with tests and
  guide §3.2e updated; (b) a technician runs §5.1 with the official SQLite command-line tool;
  (c) not retiring is **not an option**: departures would never be removed.
- **D4 -- members whose fingers exist only on the terminal** (count from Phase B). (a) Re-enrol at the
  desk (recommended; the proven path); (b) import the template read by the backup into MonClub with
  the existing `POST /manager/userFingerprint/create` (BASE64/HEX, any existing membership, 10-finger
  cap `[CODE]`) -- only if the Phase B `sha self-check` is ≥ 90 % AND a one-person pilot (import, push
  under ACCOUNT, finger at the door) passes, because terminal → MonClub → terminal has never been
  tried `[UNVERIFIED]`; (c) accept the loss for some.
- **D5 -- delete everyone who is not an administrator.** Confirm the other system is retired for good
  (its ~930 users go, including anyone it still enrolled after 2026-08-25). Script 13 keeps the
  terminal's admins: keep them (the terminal menu stays protected) or remove them.
- **D6 -- switch now or later.** Wipe + account PINs in the same window (recommended: one wipe), or
  wipe + MEMBERSHIP re-push now and a second wipe later for the switch.
- **D7 -- biometric backups.** Where the `-IncludeTemplates` files are kept and when they are deleted.
- **D8 -- the pinScheme field is editable by any gym login without the dialog** (§3.4). Accept for
  now, or tighten the backend first.
- **D9 -- script 13's labels.** Its menu still labels the whole-user delete "UNVERIFIED api", while
  `zkemkeeper_guide.md` §3 grades backup number 12 `[FIELD]` on the 2026-09-06 run (device and counts
  unrecorded). Fix the script text or the guide after the cutover; E6's three-way check does not rely
  on either.

## 8. Field tests (each needs the real terminals)

| ID | What | Exact check | When |
|---|---|---|---|
| FT1 | Duration of the template read | `msPerFingerRead` in a `-MaxUsers 50` export | B2 |
| FT2 | `~ZKFPVersion` of both terminals | `device.fpVersion` in the export | B3 |
| FT3 | Template bytes round-trip (pushed = read back) | `sha self-check` rate in the comparison | B6 |
| FT4 | Old-system pin = its card id | `leftover_pin_is_a_gms_card_id` and `links_agree` | B6 |
| FT5 | Whole-user delete time and results | `logs\clear_*.log` timestamps; `DONE ok= failed=` | B7 / E5 |
| FT6 | Index 11 = users free | E6: `users + users_free = user_capacity` | E6 |
| FT7 | Re-push per-pass setup and total time | `FULL_SYNC_START` → first `ZKEM_PUSH_CHUNK`; first to last pass | E11 |
| FT8 | Terminal keeps deciding during a push | a member who is already pushed scans during E11 | E11 |
| FT9 | An admin whose pin equals an account id would be overwritten as privilege 0 | E6 export vs roster: `account_pins_already_on_terminal` must be 0 | E6 |
| FT10 | Template import rescue (only if D4 = b) | one person: import, push, finger at the door | D |
| FT11 | `GetSysOption` from PowerShell on an MB2000 | `fpVersion` not null in B3 | B3 |

Not tested, and never tried by this plan: a second SDK connection while Access holds one (gate G5b of
the driver plan; Access is always stopped before a script connects).

## 9. Still unknown after this plan
- What the 2026-09-06 script-13 run deleted, and so what the terminals hold today (Phase B answers it).
- The production numbers (roster, fingers, PCs' versions today) -- wigo-demo is a mutated rehearsal copy.
- Durations: full read, erase, per-pass setup (FT1, FT5, FT7).
- Whether the MB2000 sends events for scans made during a push chunk (guide §3.4e) -- the gym is closed.

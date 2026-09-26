# Gym 58 ("Le club Gammarth") cutover -- erase both C3-400 panels, account PINs, re-push

**Status: PLAN ONLY.** Nothing here has been executed. No panel was connected to, written to,
erased or reconfigured, and no database was changed while writing it. Written 2026-09-26 against
Access `master` `22c9cfc`, backend `main` `c7d4b532`, dashboard `main` `75025186`. Branch
`claude/cutover-night-runbook` (merged into `master` at `dbf865f`); second round 2026-09-26 on
`claude/cutover-runbook-round2` (the review findings: pre-install before the erase, the card
self-check, the firewall block, the restart proof); third round 2026-09-26 on `master` `aeeef69`
(P3b-2 merged: §3.3, G8, E3 and E7 re-read against driver PCs -- the night runs without drivers,
runbook part H). The owner-facing steps are in
[`2026-09-26_cutover_night_runbook.md`](2026-09-26_cutover_night_runbook.md); this file is the evidence.

It follows the gym 45 plan ([`2026-09-19_gym45_cutover_plan.md`](2026-09-19_gym45_cutover_plan.md)) and
only spells out what differs. Grades as there: `[CODE]` (an executable statement, named), `[TEST]`,
`[FIELD]` (a dated measurement), `[COMMENT]` (prose only), `[OWNER]` (the owner said so, dated;
nobody has checked it), `[UNVERIFIED]`, `[UNKNOWN]`.
**Every number below marked "copy" comes from `cutover_scratch_demo`, a scratch copy of `wigo-demo`
taken 2026-09-26: a scrubbed clone of the 2026-09-12 production dump that later test sessions
mutated. They are rehearsal numbers, not production numbers.** Aggregates only; `wigo-db` was not
queried.

---

## 1. Where we start

| Fact | Grade / source |
|---|---|
| Gym 58 is **"Le club Gammarth"**, no gym family | `[FIELD]` copy, `gym_model` |
| **It is the card + QR gym, gym 45 the fingerprint gym.** Door history 2026-08-13 → 09-12: gym 58 = 35,580 CARD and 3,778 QR_CODE allowed entries, **0 FINGER_PRINT**; gym 45 = 3,327 FINGER_PRINT, nothing else | `[FIELD]` copy, `gym_access_door_history` grouped by type |
| Two panels, both **`ZK_PULLSDK`, model `C3_400`, `accessDataMode=ULTRA`, `rosterPushingPolicy=PRESERVE`, `pushing_to_device_policy=1`, active**: device **5 "Door 1" 192.168.0.202:4370** and device **6 "Door 2" 192.168.0.203:4370**, zone "hall" (agent 23). `door_ids` "1-----2-----4-----8" (4 doors, mask 15). `fingerprint_enabled=0`, `rfid_enabled=1`, `totp_enabled=1`. No device password. `pin_scheme` stored as `''` = MEMBERSHIP | `[FIELD]` copy, `gym_device` |
| `ultra_totp_rescue_enabled=0` on both panels, **yet QR entries were allowed every day** up to 09-12 (device 5: 37-124 a day). With the flag off, `ultra_engine._is_totp_format` returns False and no QR rescue runs `[CODE]`. Which is true on the production server is `[UNKNOWN]` (the copy may have been mutated). **Read the setting in /gym-devices and test a real QR at the door** (runbook) | `[FIELD]` copy + `[CODE]` |
| **No registered Access PC** for gym 58. Pin-scheme history reads `NO_REGISTERED_PC` → ACCOUNT refused (§3.3) | `[FIELD]` copy, `gym_access_pc`; matches memory of 2026-09-19 |
| How many PCs gym 58 has, and which Access they run, is **`[UNKNOWN]`**: `access/pc_identity.py` first appears in the tag `access_1.4.33` `[CODE: git tag --contains]`, but gym 45 has a registered PC on 1.4.32, an untagged build, so registration may exist from 1.4.32; a PC runs unregistered until someone registers it. So each gym 58 PC runs ≤ 1.4.31, or 1.4.32/1.4.33 never registered | `[CODE]` + owner to answer |
| `manual_sync_mode=0` → Access pushes by itself at start-up (the drift re-push of §2 depends on it; with manual mode on, "Réinitialisation complète" or "Synchroniser" is needed); `ultra_sync_yield_to_rtlog=1` | `[FIELD]` copy, `gym_access_software_settings` |
| Opening hours: entries from about 05:00-06:00 to 22:00 (30 days: 39 at 05:xx, 282 at 06:xx, 198 at 22:xx, 3 at 23:xx, 5 between 01:00 and 02:59) | `[FIELD]` copy |

### 1.1 Roster on 2026-09-12 (copy, the comparison tool's SQL filters, gym 58)

| Measure | Value |
|---|---|
| Deliverable memberships / people | **1,690 / 1,690** (nobody holds two plans at once; 0 without an account). The guide's "1,602 rows" for gym 58 (§3.8) is another measure: a protocol-2 answer of a local backend on another mutated copy, 2026-09-19, with the backend's own filters |
| People with an enabled QR credential at gym 58 | **1,690** (1,691 enabled credentials) |
| Memberships with a first card in MonClub | **1,660**; 30 without any card; 1 with a second card |
| … of which MonClub can write to a panel | **1,558**. 102 carry a value outside the panel's 4-byte range, and 103 start with the `99999+` marker. `_normalize_device_card` keeps the digits and drops a value above 4,294,967,295, so those 102 get no card on a panel today and none after (the cutover changes nothing for them) `[CODE: device_sync._normalize_device_card]` |
| Same card on two people / two cards for one person | 0 / 0 |
| People with a fingerprint in MonClub | 8 (14 templates). **Never pushed**: both panels have `fingerprintEnabled=false` `[CODE: the fingerprint gate, test_batch_device_push.py]` |
| Account id equal to ANY membership id ever sold at gym 58 (13,845 memberships) | **0**. So no account pin can land on a MonClub membership pin still on the panel |
| GMS migration: old-system person links for gym 58 | 14,873 (12,831 numeric keys) -- the old system's users may still be on the panels; the export answers it |

**Not in the copy:** what each panel holds today. `GET /api/v2/devices/{id}/users` exists for
PullSDK `[CODE: local_access_api_v2.py::_handle_device_users_list]`, but it opens a second
connection while the ULTRA worker holds one, and needs Access running. The new export (§4) reads it
with Access stopped.

## 2. What is the same as gym 45, and what is not

The goal, the reason for the erase and the order are the same (gym 45 plan §2). Every PullSDK row
MonClub writes is `Pin`, `Name`, `CardNo` (the first card) and one `userauthorize` row per pin
`[CODE: device_sync._sync_one_device, ::_push_userauthorize]`. Under ACCOUNT the pin is
`main_account.id`. At gym 58 nobody holds two plans, so no card is dropped by the collapse (guide §3.2b).

| Topic | Gym 45 (MB2000, zkemkeeper) | Gym 58 (C3-400, PullSDK) | Grade |
|---|---|---|---|
| What the members use | fingers (836/902 have one in MonClub) | cards and QR codes | `[FIELD]` copy |
| Who decides at the door | the terminal; the PC rescues QR/staff cards | the panel (cards); the PC rescues QR codes (if the flag is on, §1) | `[CODE: ultra_engine._process_event]` |
| Survey export | `14_export_terminal_readonly.ps1` | **new** `tools/c3_panel_scripts/export_c3_panel_readonly.ps1` (§4) | `[TEST]` |
| Who loses something in the erase | members whose finger is only on the terminal | members whose card is only on the panel (a card not in MonClub, a second card, a card MonClub cannot write) | comparison, §4 |
| **The erase tool** | script 13 `[U]` whole users (`SSR_DeleteEnrollData(…,12)`), keeps admins | **none exists** (§3.1) | `[CODE]` |
| Admins on the device | privilege > 0 users, kept by script 13 | a C3 has no local enrolment screen; privilege is not a column MonClub writes | the export shows every column |
| Restart after the erase, still on MEMBERSHIP | pushes **nobody** (the per-pin hashes say everyone is there) → "Réinitialisation complète" needed | **re-pushes everyone**: each full pass reads the panel's `Pin`s and re-sends every desired pin that has a stored hash but is absent ("external removal detected"), and the ULTRA PullSDK full pass always runs with `changed_ids=None` | `[CODE: device_sync._sync_one_device drift check; ultra_engine._drain_full_sync_commands]` |
| **"Retire" of the PC's old state** | **required** (else `REVOKE_ABORTED` forever); no tool, decision D3 | **not required** (§3.2) | `[CODE]` |
| `cleared_rows` in `[T] PIN_SCHEME_SWITCH` | must be 0 (proves the retire) | will be > 0 on an in-place upgrade (the old rows are still there): expected, not a STOP | `[CODE: db._clear_device_sync_hashes_on]` |
| Push speed | 928 users / 419 s at v1.4.26, 50 pins per pass since P3a-2 | **unmeasured** on any C3-400. The full pass writes the `user` rows, then the `userauthorize` rows, with `set_device_data_batch`, 50 rows per call; no per-pass cap | `[FIELD]` / `[UNVERIFIED]` |
| QR during the refill | QR rescues between chunks | the full pass polls RTLog between user-row chunks when `ultra_sync_yield_to_rtlog` is on (it is, §1): `engine._rtlog_yield_cb = self._sync_yield_to_rtlog` | `[CODE]`; on a real panel `[UNVERIFIED]` |
| Clock skew | `GetDeviceTime` | `GetDeviceParam("DateTime")`, as `PullSDKDevice.get_device_time` reads it; C3-200s were measured 38-74 s behind (pullsdk_guide §7) | `[CODE]`, `[FIELD]` for the C3-200 only |

### 2.1 Why a PullSDK panel needs no retire

On the PullSDK path the stale set is **pins read from the panel** ∩ (the roster's pins ∪ this PC's
`device_sync_state` pins ∪ promoted intents) − the desired roster
`[CODE: device_sync._sync_one_device, "stale pins: only delete pins that are known-from-server"]`.
After a verified erase the panel holds only what the first ACCOUNT pass writes, so the stale set
is empty and the removal ceiling never refuses (`REVOKE_ABORTED` needs a stale step above the
ceiling). At the end of that clean pass the prune deletes every `device_sync_state` row whose pin
is not desired, not failed and not on the panel: all old membership rows go
`[CODE: ::_sync_one_device, prune_device_sync_state(keep_pins=desired ∪ failed ∪ device_pins ∪ renewal_kept); db.prune_device_sync_state deletes from device_sync_state only]`.
The other two tables: an old `device_push_intent` row for a pin that left the roster is dropped
when a non-empty panel listing does not show it `[CODE: ::_settle_pullsdk_intents]` (a database
from any released version has no such table: it came with P3a-2, gym 45 plan §5.1); `device_content_mirror` rows stay, but nothing in
`app/` or `access/` reads that table (`list_device_mirror` has no caller, grep 2026-09-26) `[CODE]`.

**Conditions** (each is a STOP in the runbook): the panel really is empty before the switch
(otherwise the old pins ARE on the panel, the stale step is ~1,690 against a ceiling of ~422 and is
refused on every pass -- the gym 45 jam, on a panel); the roster is complete (a withheld row skips
the prune: `roster_incomplete`, gate G2); and no PC pushes membership pins between the erase and
its switch (§3.2).

## 3. Differences in the procedure

### 3.1 The erase: no tool exists for a C3 panel (blocks the night)

`clear_device_table` (`DeleteDeviceData(h, table, "", "")`) has one caller: an explicit
`FULL_REPLACE` policy whose clear goes through the removal ceiling, counted as every row on the
panel -- so it is refused on any established panel `[CODE: device_sync.py ::_sync_one_device;
guide §3.2g]`. **Setting FULL_REPLACE is not an erase.** The per-pin `POST
/api/v2/devices/{id}/users/delete` deletes `templatev10`, `template`, `userauthorize`, `user` for one
pin `[CODE: _handle_device_users_delete]` but needs Access running and connected -- which is what the
interlock forbids -- and a second connection to a panel Access already holds has never been tried.
Nothing in `tools/` writes to a PullSDK panel.

**Decision E1 (owner):**
- **(a) Recommended:** the release adds a small erase tool, specified in the release checklist:
  32-bit PowerShell like the export, clears only `user`, `userauthorize`, `templatev10`, `template`
  (never `transaction`, `timezone`, `holiday` or any parameter), refuses while `MonClubAccess.exe`
  runs, prints the counts before and after, asks for a typed confirmation with the panel's IP, logs
  every call, tested against a fake DLL. Its duration is then unmeasured until the night.
- (b) the ZKTeco vendor software for C3 panels -- nothing in this repo describes it `[UNKNOWN]`.
- (c) a factory reset of the panel -- not described anywhere here, and it may reset the IP address
  and door parameters `[UNKNOWN]`. Not recommended.

**No restore exists for a panel.** There is no backup/restore script for PullSDK. After the erase,
a card that was only on the panel comes back only by being entered in MonClub.

### 3.2 The interlock is still needed

Between the erase and the moment a PC has recorded the switch, a PC whose Access runs on MEMBERSHIP
refills the panel with ~1,690 membership pins by itself (the drift re-push, §2). If that happens
after the switch was saved but before that PC recorded it -- its first `getSyncData` failed at boot,
so the ULTRA engine started from the cached MEMBERSHIP row (gym 45 plan §2, `[CODE: app.py::_sync_tick]`) --
the membership pins are on the panel, owned, and the later switch finds them in the stale step:
refused on every pass. The fix is another erase. So, as at gym 45: panel cables out (or the
firewall block proven with the new export: before the block it connects; after, it ends with
`CONNECT FAILED` and exit code 1 `[TEST: test_c3_panel_export_readonly.py::test_a_refused_connection_writes_nothing_and_exits_1]`)
until **that PC's** log shows `[T] PIN_SCHEME_SWITCH device_id=5 … scheme=ACCOUNT` and the same for 6.

The same drift re-push is the **rollback**: erase again, set "Par abonnement", start Access → it
re-sends every member under MEMBERSHIP (§5).

### 3.3 The server gate at gym 58

`ACCOUNT` is refused unless `monclub.access.account-pin.min-version` is set and every ACTIVE
registered PC of the gym reports at least that version; `NO_REGISTERED_PC` today
`[CODE: backend main AccessPinSchemeGateService; docs/access-account-pin-minimum.md]`. So each PC
that will run Access at gym 58 must be registered from the new Access ("Identité du poste" → **"C'est
un nouveau PC"**, a name) and heartbeat once before the switch. The dashboard's device page then says
"Tous les PC enregistrés de ce club font tourner au moins la version …"
`[CODE: dashboard main fr locale pinScheme.default.reason.allMeet]`. A PC that is not reinstalled
must not run Access afterwards (it never registered, so the gate cannot see it -- memory note of
2026-09-19: "`gym_access_pc` is not a census of the fleet"). Switching it off is not enough -- staff
switch reception PCs on (gym 45 plan section 3.3) -- and a revoke could not stop it even if it were
registered: an old Access syncs with the gym login (runbook D12) -- and a new Access drives on after a
revoke too, while gym 58 has no driver set (`app/core/v2/leases.py::LeaseManager._drop_leases`; runbook
part H) `[CODE]`. So it carries the firewall block of
the runbook's C1b (the gym 45 plan section 5.2 rules with gym 58's IPs, proven with this plan's export
before and after) or is unplugged from the network. **The same holds for a PC pre-installed on the new
Access that is not started on the night**: started later with a first sync that fails at boot, it works
from its stored MEMBERSHIP row (§3.2). Any such PC is brought back in the order of gym 45 plan §5.3:
block on, new Access, its `PIN_SCHEME_SWITCH … scheme=ACCOUNT` lines for 5 and 6, the restart proven,
then the block removed.

### 3.4 Upgrade in place, not a clean data folder, and BEFORE the erase

The upgrade is done and the new Access started once, still on MEMBERSHIP, **before** the erase
(runbook A7, required): the installer deletes the old program before copying
(`installer/MonClubAccess.iss::PrepareToInstall`) and a failing migration stops start-up, so a first
start after the erase could leave both panels empty with nothing able to refill them. On MEMBERSHIP
the new release writes the same pins, fields and rows as 1.4.22-1.4.33, clears no hash, records no
switch and never touches fingerprint rows; the exceptions (a PC on 1.4.19/1.4.21, the first full
refresh, protocol 2 and the QR roster check if on) are listed with their grades in the runbook, part A,
"What A7 changes at the door" (code read 2026-09-26).

The new Access upgrades the old database: it adds `sync_users.main_account_id` and forces one full
member refresh, adds `sync_devices.pin_scheme`, drops `devicesVersion` and records every known device
as seen on MEMBERSHIP (guide §3.2d). A failing migration stops start-up (guide §3.2d, owner decision
2026-09-25): the log is `%TEMP%\MonClubAccess.log`. Because the C3 path needs no retire (§2.1), the
in-place upgrade keeps the login, the local settings and any door history not yet uploaded. Gate
G2 of the gym 45 plan applies: no deliverable row without `main_account_id` once the forced refresh
has run, or the prune is skipped and every removal on the panel waits (guide §3.2b).

## 4. The tools (read-only)

**`tools/c3_panel_scripts/export_c3_panel_readonly.ps1`** (launcher `START_EXPORT.cmd`) -- one panel to
a JSON file: the parameter list Access itself reads for its device page, the clock skew, row counts
of `user`, `userauthorize`, `transaction`, `templatev10`, `template`, `timezone`, `holiday`, every `user`
row (pin, name, card, whether a password is set -- never the value -- and the other columns the
firmware returns), the `userauthorize` rows, and per pin the finger ids of `templatev10` (never the
template column). It reaches `plcommpro.dll` only through `_pullsdk_read.ps1`, which declares
`Connect, Disconnect, GetDeviceData, GetDeviceDataCount, GetDeviceParam, PullLastError` and nothing
else; the real-time log is never read. It refuses to run while `MonClubAccess.exe` runs on the PC
(that PC only). A negative `GetDeviceDataCount` answer is a PullSDK error, not a count: it is listed in
`errors` and the count is written as `null`; a failed count of `user`, `userauthorize` or `templatev10`
(the counts that prove a panel empty) makes the export partial (`complete: false`, exit 2), and
`templatev10` is still listed when its count is unknown.
`[TEST: tests/test_c3_panel_export_readonly.py -- static allowlist, no write entry point named, no
dynamic invocation, the connection string Access sends, the shipped script run against a fake
panel with only those six calls, the refusal while MonClub Access runs (exit 1, no Connect), and the
failed counts]`. Smoke run on the development PC, 32-bit PowerShell, the pack's
`plcommpro.dll`, `Connect` to 127.0.0.1:1 (no device): handle 0, `PullLastError=-307`, 2.3 s with
`timeout=2000` `[TEST: 2026-09-26, not committed]`. **Never run against a real panel.** Whether a
C3-400 answers every parameter name, returns the `user` table with `*`, and how long the reads take are
`[UNVERIFIED]` until the first run; a name that contains a comma breaks the comma-separated table
format for that row (counted as `userRowsMalformed`), as it does in Access's own parser
(`app/core/utils.py::parse_device_text`).

**`tools/gym45_cutover/compare_terminal_export.py`** (existing; now also reads the panel export) with
`--gym-id 58`. New `cards` section: per current person, the cards seen on the panel under their own
pin or on an old user strongly tied to them (same card number, pin = card) that MonClub will not write
-- another card, a second card, a value outside the 4-byte range. Detail rows `member_terminal_only_card`
in `--detail-csv` (names); the note says which case it is: `no card in MonClub` (MonClub holds
no first and no second card: the only case the desk may enter -- the note **ends with** that phrase --
after searching the card number in MonClub, since the tool sees only the current members it loaded), `MonClub card ... cannot be written to
a panel -- do not overwrite it`, `MonClub card ... -- do not overwrite it`, `MonClub holds only a second
card ... -- do not overwrite it`; a flag for a MonClub card starting with `99999`; and `that card is held
by another member in MonClub -- do not enter it` when the panel card is another person's MonClub card
(a recycled card, say). **The card self-check** (printed under `== cards`): on the pins MonClub owns (every member pin
when the PC records no ownership, as <= 1.4.31 does) that MonClub sends a card, the share whose panel
`CardNo` equals it. How a C3-400 returns `CardNo` is `[UNVERIFIED]` (`device_sync.py::_same_card`'s own
note; pullsdk_guide §5); below 90 % the list may be an artefact and is not acted on. The card rule
follows the export: a panel gets `_normalize_device_card`, an MB2000 the raw digits; exports of the two
kinds are refused in one run. `[TEST: tests/test_gym45_compare_terminal_export.py::TestPanelCards, including
a database in the `access_1.4.30` schema, the self-check at 90 % and on hex-returned cards]`. With `--access-db` alone (a copy of the PC's database) the
card list needs no production MySQL copy; add the MySQL copy to tie old users by their GMS id.
Limits: the C3 `user` table has no privilege or enabled column, so the export writes `privilege 0`,
`enabled true` for every row and the report's "privileged 0 / disabled 0" means "not read"; the `cards`
section counts every first card a person holds in MonClub as written, without the door filter
(`allowedMemberships`) or the ACCOUNT collapse -- exact at gym 58, where nobody holds two plans.

## 5. The procedure at gym 58 (evidence for the runbook's section C)

Order per panel: **export → compare → go/no-go → erase → verify empty → interlock → upgrade and
register every PC → switch → reconnect and push → verify → doors.** Durations: none is measured on a
C3-400; the export records its own timings.

| Step | Proof it worked | If it fails |
|---|---|---|
| G0. Every PC of the gym: untick "Ouvrir MonClub Access avec Windows", watchdog off (**before** the Quit: it restarts Access after any Quit), Quit (gym 45 plan §3.3). A PC that will not be started tonight, whatever its version: the firewall block, proven, or unplugged (§3.3; runbook C1b) | Task Manager: no `MonClubAccess.exe`; the watchdog task `Disabled` or absent | stop; nothing changed |
| G1. Copy the data folder `%ProgramData%\MonClub Access\access\` of each PC (Access stopped) | the copy exists | stop |
| G2. Export both panels, full commands, `-Label device5` / `-Label device6` (type each IP in full). Once per panel, the reference refusal: the panel's cable unplugged at the panel, the same command, its `PullLastError` written down (runbook A2b) | `complete: true`, `errors` empty; `counts.user` = `summary.users` | a connect failure: check cable, IP, device password; nothing changed. `errors` not empty: call the developer before G5 |
| G3. Compare each export with `--access-db <copy of the PC that drives it>` `--gym-id 58` -- the `cards` list and the card self-check come from this run; and a second run with `--scheme ACCOUNT`, only to confirm `account_pins_already_on_terminal` (expected 0, §1.1; its card self-check reads NOT MEASURED before the switch, since the panel holds no account pin) | the `cards` list and the card self-check line of the first run; `classes`; `leftovers` | a non-zero ACCOUNT hit: stop and call the developer. Card self-check below 90 % or not measured: the card list is not acted on (G4) |
| G4. Go / no-go: the new Access has started once on every PC that will run (§3.4, runbook A7); owner accepts the card list (members who will be refused by card until their card is sorted out) -- the survey list is the one the desk used; with a failed card self-check the owner accepts that the losses are unknown, or stops; erase tool present (E1); clock skew within ±10 s or accepted; the go/no-go clock (runbook C) | -- | stop; nothing changed |
| G5. Erase panel 5, then panel 6 (E1 tool) | the tool's AFTER counts `user=0`, `userauthorize=0`, `templatev10=0` | re-run; still not empty → that panel stays on MEMBERSHIP (R8 below) |
| G6. Verify empty: a new export -- `complete: true`, `errors` empty, `counts.user`, `counts.userauthorize`, `counts.templatev10` each exactly 0 (`null` is not 0), `summary.users` 0 -- and a member's card at that door refused | both | back to G5; a `null` count: the panel is not proven empty, call the developer |
| G7. Interlock: panel network cables out (they keep power) | the export from the PC now ends with `CONNECT FAILED` **with the G2 reference `PullLastError`** | another code: something else refused the connection (another PC holding the panel? whether a C3-400 allows two clients is `[UNVERIFIED]`): find it first |
| G8. No install after the erase (§3.4). Start the new Access on each PC (registered at runbook A7) | /access-pcs lists each PC with the new version; each PC's « Pilote / Lecteur » page shows one of the runbook's two expected readings -- no driver set at gym 58 (runbook part H4; a driver reading: runbook C10's STOP) | a start-up that stops: `%TEMP%\MonClubAccess.log`, call the developer; the rollback is the runbook's F row "does not start -- after the erase" |
| G9. Dashboard: the verdict sentence "Tous les PC enregistrés…" (shown only on the add-device form, `gym-devices-view.tsx`; on an existing device a refusal shows as a red message and the confirm dialog names the minimum version); device 5 then 6: "Par personne", tick both boxes, save; reopen each | each reads "Par personne" | refused (409): read `blockingPcs`, revoke retired PCs in /access-pcs |
| G10. On each PC, newest log in `%ProgramData%\MonClub Access\data\logs\`: `[T] PIN_SCHEME_SWITCH device_id=5 previous=MEMBERSHIP scheme=ACCOUNT` (and 6). `cleared_rows` is the old row count here: expected. **Then Quit and restart Access on every running PC** and wait for `getSyncData OK`: a switch that reached a PC through a dashboard fast patch (`app.py::apply_fast_patch_bundle` → `db._insert_device_row`) is recorded and logged, but the running ULTRA workers keep their MEMBERSHIP device copy until a server sync refreshes them (`app.py` sync tick → `refresh_devices`), and the full pass pushes from that copy (`ultra_engine._drain_full_sync_commands`, `self._device`) `[CODE, review 2026-09-26]`. The restart is proven three ways (runbook C13's box): no `MonClubAccess.exe` after the Quit; a new `App started. pid=... version=X.Y.Z` line later than the switch lines; `getSyncData OK` after it -- the log file is cut by hour, not by process (`app/core/logger.py`), so "the new log" alone proves nothing | the lines, then the three restart checks and the page reading (runbook C13's box) | none after a few minutes: `getSyncData OK` in the log? then "Réinitialisation complète"; still none → do NOT plug in, call the developer. A restart check fails, or no expected page reading → do NOT plug in |
| G11. Plug the panel cables back only when every PC that is switched on has shown G10, its proven restart and its page reading; every other PC stays blocked or unplugged (G0, §3.3) -- the cable is the panel's, so it releases every PC that can reach it | -- | -- |
| G12. Push: per panel, a pass ending with `[DeviceSync] Device id=5: device_pins=N desired=N to_sync=0 stale=0` on the pass after the push, N = the people count that pass computed (it can change after midnight: the 00:00:05 date flip asks for a full pass, guide §3.8) | the line for 5 and 6 | `REVOKE_ABORTED` → the panel was not empty: Quit, export, back to G5. `PIN_SCHEME_ACCOUNT_WITHHELD` → "Réinitialisation complète"; persists → call the developer |
| G13. Verify: Quit, export both panels, compare with `--scheme ACCOUNT --access-db <fresh copy>`: `member_owned` = people, `leftover` = 0, the card self-check of this run compared with G3's first run (below 90 % while G3's was at or above, or more than 2 points below G3's: call the developer -- a margin chosen for roster changes, not a measurement), no `cards` loss beyond the G4 list | numbers | members missing → "Réinitialisation complète", redo G12-G13 |
| G14. Doors: 3 members' cards, 1 QR code, 1 expired member (refused), 1 staff card, the reception "Open" button (it needs the PC's connection to the panel: `local_access_api_v2._handle_device_door_open` answers 503 while the panel is unreachable `[CODE]`), on both panels | as expected | the half-state table |
| G15. Re-tick start-with-Windows; only now the watchdog on, and its `NextRunTime` checked (autostart checklist §4). Open | -- | -- |

**Half-states** (per panel): before G5, nothing changed (R1). After G5 and before G10 on some PC:
set "Par abonnement" back if it was saved, reconnect, start Access → the drift re-push refills the panel
under MEMBERSHIP `[CODE]`; done when the G12 line shows `to_sync=0 stale=0` (R2). After G10 (switch
recorded) with a partial push: the push continues at the next pass `[CODE]` (R7); to go back instead:
erase again, cables out, "Par abonnement" (the dashboard asks "J'ai effacé le terminal — basculer"),
start each PC behind the interlock until it logs `previous=ACCOUNT scheme=MEMBERSHIP`, restart it (G10),
then reconnect (R4). Started with the cables in and a failed first sync, a PC works from its stored
"Par personne" row and writes account pins back `[CODE: app.py start-up from the cached devices]`. A panel left for another day stays on MEMBERSHIP, works as today (R8).
The new Access failing to start: before the erase, the previous installer and the pre-A7 data copy
bring the old Access back with nothing changed at the door; after the erase, the same, then the drift
re-push refills under MEMBERSHIP (runbook part F, two rows; the old version on its own copy after a
newer install is `[UNVERIFIED]`, never tried). While a panel is unplugged the reception "Open" button
cannot open it; the opening fallback is the turnstile arm dropped by hand, with a staff member there
`[OWNER, 2026-09-26]` -- how, and by whom, is still to be written down (runbook G).

## 6. Decisions only the owner can take

- **E1 -- the erase tool** (§3.1). Without one, gym 58 cannot be done: then decide explicitly that gym 58
  waits and the night is gym 45 only.
- **E2 -- the QR rescue flag** (§1): which value is right, and who checks it before the night.
- **E3 -- which PCs gym 58 has**, which one drives the panels (runs Access on the night -- not a driver
  set in the dashboard: the night runs without drivers, runbook part H), and whether the others come back
  (gym 45 plan D2). Each one that runs must be upgraded and registered, or never started again.
- **E4 -- the card list** from G3: accept that those members are refused by card until their card is
  entered in MonClub (QR still works for all 1,690), or fix MonClub before the night.
- **E5 -- the survey evening** (runbook A): run G2-G3 on an earlier closed evening, so the card list is
  known and fixed in MonClub before the night. Read-only.
- **E6 -- the 102 cards MonClub cannot write** (§1.1): unchanged by the cutover; a separate question. At
  the desk they are never overwritten, and the 103 starting with `99999` are never touched without the
  owner (runbook A6).
- **E7 -- when the new Access is pre-installed** (§3.4, runbook A7): the survey evening (then it runs
  days on MEMBERSHIP) or the night, after the export. And, before it, the state of protocol 2 and of
  the panels' QR roster check (runbook A7, point 5), and of the server's commands switch -- unchanged
  from A7 until the night is verified, with no driver set at gym 58 (runbook A7 point 7, part H).
- **E8 -- the turnstile arm** (§5 half-states): how it is dropped at doors 1 and 2, who can do it, and
  whether the gym opens with the arms dropped if the refill is not proven.

## 7. Field tests (each needs the real panels)

| ID | What | Check | When |
|---|---|---|---|
| F58-1 | The export reads a C3-400 (parameter names, `user` with `*`, `userauthorize`, `templatev10` fields) | `complete: true`, `errors` empty | G2 |
| F58-2 | Read duration | `timings` in the file | G2 |
| F58-3 | The firewall block stops a PullSDK connection (a PC not upgraded); a pulled cable gives the same `PullLastError` every time | the export before/after; the G2 reference code equals the G7 code | G0, G2, G7 |
| F58-4 | The erase empties the panel (E1 tool) | counts 0 | G5-G6 |
| F58-5 | Full ACCOUNT push time for ~1,690 people on a C3-400 | first to last pass in the log | G12 |
| F58-6 | QR codes open during the push (`ultra_sync_yield_to_rtlog=1`) | someone scans a QR during G12 | G12 |
| F58-7 | `CardNo` read back as written (leading zeros ignored by the comparison) | the card self-check rate at G3 (cards the old Access wrote) and at G13 (the new push) | G3, G13 |
| F58-8 | A member deleted then restored opens the door (guide §7, R6-08) | one member | days after |

## 8. Still unknown after this plan

- What each panel holds (old-system users, cards, fingers): the export answers it.
- How many PCs gym 58 has and their versions.
- The QR rescue flag's real value.
- Every C3-400 duration: export, erase, push.

# Cutover night -- every gym on per-person PINs ("Par personne")

For the owner. Plain steps, in the order of the night. The evidence behind each step is in:
- gym 58 (cards + QR, two C3-400 panels): [`2026-09-26_gym58_cutover_plan.md`](2026-09-26_gym58_cutover_plan.md)
- gym 45 Oxyfit (fingerprints, two MB2000): [`2026-09-19_gym45_cutover_plan.md`](2026-09-19_gym45_cutover_plan.md)
- the PCs starting by themselves: [`2026-09-26_autostart_checklist.md`](2026-09-26_autostart_checklist.md)
- what the release must contain: [`2026-09-26_cutover_release_checklist.md`](2026-09-26_cutover_release_checklist.md)

> **NOT READY -- DO NOT USE ON THE NIGHT YET (master-session review, 2026-09-26).** A read-only review
> found one blocker and four major gaps in this runbook. They must be fixed before any go-ahead:
> 1. **Blocker:** gym 45 dropped the plan's section 5.2 firewall block on the PCs that are not reinstalled. Revoking a PC
>    in /access-pcs does NOT stop an old Access: it syncs with the gym login and would push membership PINs
>    onto the account-keyed terminals. Gym 58's C11 needs the same block, or the PC unplugged from the network.
> 2. The installer re-registers and re-enables the watchdog that C1/D1 disabled, so Access can relaunch by
>    itself about 4 minutes after the install and during every "Quit, then export" step.
> 3. "Ouvrir keeps working" is false while a panel or terminal cable is out: the button needs the device
>    connection. A physical opening fallback is needed.
> 4. The erase happens before the new release has ever started on that PC, and there is no rollback if it fails
>    to start (the installer deletes the old program). Pre-install first, or bring the previous installer and add an F row.
> 5. The card list can only drive desk edits once a card self-check shows the panel returns cards in the form
>    Access wrote them (the C3 read-back format is unverified).
> Minor points: check `cleared_rows` on every running gym 45 PC; prove the restart with a new `App started` line;
> the export tool records failed counts and lists; the export JSON files are personal data and should be git-ignored.

**PLAN ONLY -- nothing has been run.** Written 2026-09-26 on Access `master` `22c9cfc`.

**About the times.** Almost nothing here has ever been timed on the real devices. Where a time is
known it says *measured* and where. Everything else says **not measured**. "Not measured" means:
plan the gym to stay closed until the door tests pass. The survey evening (part A) measures the
reads before the night.

**About the numbers.** Member counts come from a test copy of the 12 September database, not from
today's production. The export on the night gives the real numbers.

---

## The night in 10 lines

1. Days before: a read-only "survey evening" at each gym gives the lists of members who will lose a card or a finger (A).
2. Before leaving home: the release is chosen, the server's minimum version is set, the bag is packed (B).
3. Gym 58 after closing: stop Access on every PC, export both panels, compare, decide go / no-go (C1-C5).
4. Erase panel 5 and panel 6, check they are empty, pull their network cables (C6-C8).
5. Install the new Access on every gym 58 PC, register each one, check the dashboard verdict (C9-C11).
6. Set both panels to "Par personne", wait for the switch line in the log, restart Access, plug the cables back, let it refill (C12-C14).
7. Check the refill, test cards, QR codes and the "Ouvrir" button, re-enable autostart (C15-C17).
8. Gym 45: the same shape with its MB2000 tools, plus the "retire" of each PC's old state (D).
9. Morning: read the logs, watch the first entries, send the listed members to the desk (E).
10. If a refill fails before opening: the rollback of part F; the reception "Ouvrir" button keeps working.

## What blocks the night today (answer these first)

| # | Blocker | Why |
|---|---|---|
| 1 | **No released Access honours "Par personne".** The release must be built and must pass the release checklist | Every tag up to `access_1.4.33` ignores the setting (backend doc `access-account-pin-minimum.md`) |
| 2 | **No tool erases a C3-400 panel** (gym 58). Decide E1 in the gym 58 plan: a small tool in the release (recommended), or the ZKTeco software | Nothing in MonClub Access or its tools clears a panel's user tables on command |
| 3 | **Gym 45: how each PC forgets its old state** ("retire", decision D3 of the gym 45 plan): a button in the release, a technician with SQL, or a fresh data folder (D10 below) | Without it, members who leave are never removed from the gym 45 turnstiles again |
| 4 | **Power on all night** at both gyms (the PCs, the panels, the network) | Most gyms cut the power overnight |
| 5 | **Who is on site and who is on call**: you, a technician who can run the scripts and read a log, the developer on the phone | Most STOP rules end with "call the developer" |

---

## A. Days before -- the survey evening (recommended, read-only)

One evening per gym, with the gym closed. Nothing is written to any device. It gives you the lists
early, so the desk can fix MonClub before the night instead of turning members away the morning after.

| Step | Do | The screen must show | Time | STOP if |
|---|---|---|---|---|
| A1 | On every PC of the gym: Config page, untick **"Ouvrir MonClub Access avec Windows"**; tray icon → **Quit**; if the watchdog exists, disable it (gym 45 plan §3.3) | Task Manager: no `MonClubAccess.exe` | a few minutes | -- |
| A2 | Gym 58: in the folder `tools\c3_panel_scripts`: `.\START_EXPORT.cmd -DeviceIp 192.168.0.202 -Label device5 -Auto`, then `.\START_EXPORT.cmd -DeviceIp 192.168.0.203 -Label device6 -Auto`. **Type each IP in full.** Gym 45: `14_export_terminal_readonly.ps1` as in the gym 45 plan B2-B3 | `[OK] complete - nothing was written to the panel` | not measured -- the file records it | "CONNECT FAILED": check the IP and cable; nothing changed |
| A3 | Copy the whole folder `%ProgramData%\MonClub Access\` of the PC that drives the devices to a USB key. The database is `access\access.db` (every release since 1.0.3); on a PC upgraded from older, check `data\app.db` too -- use whichever holds the members | the copy | -- | -- |
| A4 | Restart Access on every PC (re-tick the box, watchdog on) | Access is back | -- | -- |
| A5 | At home, on the laptop with the tools: `python tools\gym45_cutover\compare_terminal_export.py --gym-id 58 --export 5=<file> --export 6=<file> --access-db <copy>\access.db --detail-csv cards58.csv` (gym 45: `--gym-id 45`, with `-Fingers` exports) | `== cards …` (gym 58) or `== people …` (gym 45) | seconds | -- |
| A6 | The desk fixes MonClub: gym 58, enter the card listed in `member_terminal_only_card` rows on that member; gym 45, re-enrol the fingers listed in `member_terminal_only_finger` rows | -- | depends on the list | -- |

`cards58.csv` and the gym 45 CSV hold names: personal data, keep them private and delete them after.

*Optional at gym 58 only:* install the new Access on its PCs that evening (C9-C10) and let it run on
"Par abonnement" for a few days. Nothing changes at the door, and the night gets shorter. Not at
gym 45: the new build clears fingers that exist only on the terminal (gym 45 plan G9), so gym 45 is
installed only after its survey and re-enrolment.

## B. Before leaving home

| Step | Do | Must show | STOP if |
|---|---|---|---|
| B1 | The release: its checklist is ticked, and the tag passes both `git merge-base --is-ancestor 30c3b93 access_X.Y.Z` and `… 2eafb5f access_X.Y.Z` | exit code 0 twice | either fails: not this release |
| B2 | **Only now** set the server minimum to that exact version, `X.Y.Z` (backend doc `access-account-pin-minimum.md`: a one-line commit + deploy, or the variable `MONCLUB_ACCOUNT_PIN_MIN_ACCESS_VERSION` -- the CI does not pass it today), and restart the backend at a quiet hour | the backend start-up log names the minimum at INFO (a WARN means it was not accepted) | WARN: fix the value |
| B3 | Dashboard, /gym-devices, **"add a device" form** (the verdict sentence shows only there; cancel without saving), with gym 58 then gym 45 | "Au moins un PC enregistré…" or "Aucun PC n'est enregistré…": expected until the PCs are upgraded | "Aucune version publiée…" = the minimum is not set: back to B2 |
| B4 | Download the release installer to two USB keys (the gyms' internet may be slow) | the file, same size on both | -- |
| B5 | Pack the bag (list below) | -- | -- |

**The bag:** two USB keys (installer; `tools\c3_panel_scripts`, `tools\mb2000_scripts` with its `sdk`
folder, `tools\gym45_cutover`); the laptop with Python 3.9+ and this branch, for the comparisons; a
network cable; each PC's Windows password; the gyms' MonClub Access login (you type it -- nobody
else needs it); the list of each gym's PCs with their names in "Postes de réception"; for the door
tests: a card of a current member (a staff member who is also a member is simplest), a phone showing
a current member's QR code, the card of an expired member, a staff card, and at gym 45 three to five
people with fingers enrolled in MonClub; paper to write the time of each step (these are the first
measurements).

## C. Gym 58 after closing

Gym 58's entries run until about 22:00 and restart about 05:00-06:00 (the 12 September copy). The
panels: **device 5 "Door 1" 192.168.0.202** and **device 6 "Door 2" 192.168.0.203**.

| Step | Do | The screen must show | Time | STOP if |
|---|---|---|---|---|
| C1 | Every PC: untick "Ouvrir MonClub Access avec Windows", Quit, watchdog off | no `MonClubAccess.exe` in Task Manager | minutes | -- |
| C2 | Copy each PC's whole `%ProgramData%\MonClub Access\` folder to the USB key | the copies | minutes | -- |
| C3 | Export both panels (A2 commands) | `complete - nothing was written` | not measured (the survey evening measured it) | connect fails: check cable/IP; nothing changed |
| C4 | Compare each export (A5 command), plus once with `--scheme ACCOUNT` | the `cards` list; `account_pins_already_on_terminal` 0 | minutes | the ACCOUNT run shows a number > 0: call the developer |
| C5 | **Go / no-go**: you accept the card list (those members are refused by card until their card is in MonClub; their QR still works); the erase tool is there; the clock skew in the export is within ±10 s | -- | -- | no: re-tick autostart, restart Access. **Nothing has changed** |
| C6 | **Erase** panel 5, then panel 6, with the erase tool of the release (blocker 2) | its AFTER counts: `user=0`, `userauthorize=0`, `templatev10=0` | not measured | not empty after a second run: leave that panel for another day (F, gym 58 row 1) |
| C7 | Check each is empty: a new export shows `users 0`; one member's card at that door is refused | both | minutes | not empty: back to C6 |
| C8 | **Pull the network cable of both panels** (leave them powered) | the export from the PC now ends with `CONNECT FAILED` | minutes | it still connects: find the right cable before going on |
| C9 | On **every** PC that will run Access: run the new installer **over the existing Access -- never uninstall first** (the uninstaller deletes the whole `%ProgramData%\MonClub Access` folder: login, history, the rollback), **untick "Launch MonClub Access" on the last page** (it is ticked by default), keep "Keep MonClub Access running" as the autostart checklist says | the installer ends | not measured | -- |
| C10 | Start Access on each PC. It keeps its login. On "Identité du poste" choose **"C'est un nouveau PC"** and give the name staff use (e.g. "Accueil") | the dashboard page "Postes de réception" lists each PC with the new version | seconds after start (the PC reports at start and right after registering) | Access does not open: `%TEMP%\MonClubAccess.log`, call the developer |
| C11 | Any gym 58 PC that is NOT reinstalled tonight: switch it off and keep it off (it was never registered, so the server cannot see it) | -- | -- | -- |
| C12 | Dashboard, reload. On the "add a device" form (then cancel) the verdict now says **"Tous les PC enregistrés de ce club font tourner au moins la version X.Y.Z…"**. Open device 5: choose **"Par personne"**, tick **both** boxes ("Je confirme que MonClub Access a été mis à jour…", "Je confirme que les utilisateurs de ce terminal ont été effacés"), **"Les deux sont faits — enregistrer"**. Same for device 6. Reopen each | the dialog names version X.Y.Z; after saving, each reads "Par personne" | a minute | refused (red message): it names the PCs in the way; revoke a retired one in "Postes de réception" |
| C13 | On each running PC, newest file in `%ProgramData%\MonClub Access\data\logs\`: search `PIN_SCHEME_SWITCH`. Want `device_id=5 previous=MEMBERSHIP scheme=ACCOUNT` and the same for `device_id=6`. At gym 58 `cleared_rows` is a big number: **normal here** | both lines on every running PC | a few minutes | no line: search `getSyncData OK`; then dashboard page of Access → **"Réinitialisation complète"**; still none: **do not plug in**, call the developer. **Then, on every running PC: Quit Access and start it again**, and wait for `getSyncData OK` in the new log. Why: if the dashboard was open on a gym PC, the switch reached that PC's Access directly and was logged, but its running turnstile workers keep the old "Par abonnement" copy until a server sync refreshes them; plugging in before that would write ~1,690 membership PINs onto the empty panel, and only another erase clears them. A restart builds the workers from the database, which already says "Par personne" |
| C14 | **Plug both panel cables back.** Access refills both panels | log lines `[DeviceSync] Device id=5: device_pins=… desired=… to_sync=… stale=0` | **not measured** for ~1,690 people | `REVOKE_ABORTED` in the log: a panel was not empty -- Quit Access, go to F |
| C15 | Done when a later pass of each panel says `device_pins=N desired=N to_sync=0 stale=0` (N is the people count of that pass; after midnight it can change by itself) | that line for 5 and 6 | not measured; no such line 20 minutes after the push ended: Quit and restart Access (its start-up pass prints it) | `PIN_SCHEME_ACCOUNT_WITHHELD`: "Réinitialisation complète"; persists: call the developer |
| C16 | **Door tests**, each panel: 3 members' cards open; 1 QR code opens; 1 expired card is refused; 1 staff card opens; the reception **"Ouvrir"** button opens. If the QR is refused, open the turnstile page in the dashboard and check the QR rescue setting (gym 58 plan E2) | all as expected | 15 min | a member's card is refused: is that card in MonClub on that member? (the C4 list) |
| C17 | Quit Access, export both panels, compare with `--scheme ACCOUNT` and a fresh copy of `access.db`: `member_owned` = the people count, `leftover` = 0. Restart Access. Re-tick "Ouvrir MonClub Access avec Windows" and the watchdog (autostart checklist) | the numbers | minutes | members missing: "Réinitialisation complète", wait for C15 again |

## D. Gym 45 (Oxyfit), the same night if time allows, otherwise early next morning

The terminals: **device 8 "Sortie" 192.168.1.247** and **device 10 "Entrée" 192.168.1.246** -- type each
IP in full. The three PCs: "Accueil" (LAPTOP-T6KORL9V), "Accuil Oxyfit" (no name recorded),
"Accueil Oxyfit" (DESKTOP-6UCRVSG). Each step cites the gym 45 plan (E1-E14, gates G1-G12), which
holds the exact commands and the evidence. Three things differ from that plan tonight:

- **N1 -- no soak.** The plan installed the new Access two opening days early. Tonight it is installed
  after the erase, behind the interlock, so it runs for the first time on the night. The fingerprint
  version (G3) is still checked BEFORE the erase, from the night's export.
- **N2 -- no rescue before the erase** unless the survey evening happened (A6). Every member in the
  `member_terminal_only_finger` rows cannot enter by finger in the morning until re-enrolled at the desk.
- **N3 -- a go/no-go clock for the erase.** Gym 45 opens at about 08:00 (entries 08:00-23:00 in the
  copy). If the erase (D6) has not started by that time, stop: gym 45 opens on its old Access, unchanged.

| Step | Do | The screen must show | Time | STOP if |
|---|---|---|---|---|
| D1 | All three PCs: untick "Ouvrir MonClub Access avec Windows", Quit, watchdog off; on the driving PC (P1, plan D2) pause Windows Update (plan E1) | no `MonClubAccess.exe` | minutes | -- |
| D2 | Backup + survey, both terminals at once, with templates (plan B3/E2 commands). Copy both files and their `.sha256` to the USB key and the laptop | `complete: true`; each file's IP and serial match its terminal (G5) | **not measured**: the survey evening's `-MaxUsers 50` sample gives `msPerFingerRead`; × 10 × users = the read time | a read fails: retry or stop; nothing changed |
| D3 | Copy each PC's whole `%ProgramData%\MonClub Access\` folder to the USB key | the copies | minutes | -- |
| D4 | Compare on the laptop (`--gym-id 45`, the `access.db` copy of P1): fingerprint version = MonClub's (G3); the fingers-only list (G4); faces 0 (G8); clock skew within ±10 s (G10; a correction is a write, plan E3) | the numbers | minutes | **G3 red: stop gym 45 tonight** (the push would skip every finger of the other version); faces > 0: you decide (G8) |
| D5 | **Go / no-go**: the plan's gates, and the N3 clock | -- | -- | no: re-tick autostart, restart Access. Nothing changed |
| D6 | **Erase** each terminal with script 13: whole users, scope all non-admin, type `CLEAR` (plan E5 has the exact menu path). The warning "UNVERIFIED api" is expected. Removing an admin who is not staff: plan E5b, choice `U` only | its log `DONE ok=… failed=0` | **not measured** (the 2026-09-06 script-13 log, if found, gives the time per user, plan B7) | a user hangs 60 s: plan E5's fail column -- that terminal stays on "Par abonnement" for another day |
| D7 | Check empty, four ways (plan E6): an export, the terminal's own count, a member's finger refused, the comparison's `account_pins_already_on_terminal` = 0 | all four agree | minutes | back to D6 |
| D8 | **Interlock**: network cables out of both terminals (they keep power), or the firewall block proven (plan §5.2) | the export now fails to connect | minutes | it still connects: find the right cable |
| D9 | On every PC that will run Access: the new installer **over the existing Access -- never uninstall first** (the uninstaller deletes the whole `%ProgramData%\MonClub Access` folder: login, history, the rollback). "Launch MonClub Access" unticked | the installer ends | not measured | -- |
| D10 | **The retire**, per PC (blocker 3), before Access starts -- see the box below | (a) the action's counts 0; (b) the plan §5.1 counts 0; (c) the renamed folder exists and `data\app.db` is moved | minutes | a failure: put the D3 copy back, stop (plan R2) |
| D11 | Start Access on P1 (and on each other PC that will run). With a fresh folder (c): log in, and on "Identité du poste" choose **"Ce PC remplace un ancien poste"** and pick that PC's own record | "Postes de réception" shows the new version for it | seconds | Access does not open: `%TEMP%\MonClubAccess.log`, call the developer |
| D12 | "Postes de réception": **revoke** every gym 45 record whose PC is not reinstalled tonight | the verdict on the add-device form: "Tous les PC enregistrés…" | a minute | -- |
| D13 | Devices 8 and 10: "Par personne", tick both boxes, "Les deux sont faits — enregistrer"; reopen each (plan E9) | each reads "Par personne" | a minute | refused: the red message names the PCs in the way |
| D14 | P1's log: `[T] PIN_SCHEME_SWITCH device_id=8 previous=MEMBERSHIP scheme=ACCOUNT cleared_rows=0` and the same for 10 (plan E10). **Here it must be `cleared_rows=0`** | both lines | a few minutes | `cleared_rows` not 0: STOP, do not plug in. No line: plan E10's fail column |
| D15 | **Quit and restart Access** on every running PC; wait for `getSyncData OK` (plan E10b, same reason as C13) | the new log | 1-2 min | -- |
| D16 | **Plug the cables back** (or remove the block). Done per terminal when a pass without `FULL_SYNC_CAPPED` ends with `ZKEM_PUSH_DONE … failed=0 … tpl_failed=0` and `FULL_SYNC_DONE … ok=True`; then Quit and restart: the start-up pass says `all N desired pins already on the terminal -- nothing to push` (plan E11) | those lines | at best about 7 min per terminal, both in parallel -- a floor computed from one field rate (928 users in 419 s, v1.4.26), not a measurement | plan E11's fail column (`PIN_SCHEME_ACCOUNT_WITHHELD`, `CAPACITY_FULL`, `TEMPLATE_VERSION_MISMATCH`, `REVOKE_ABORTED`) |
| D17 | Verify: Quit, `-Fingers` export of both, compare with `--scheme ACCOUNT` and a fresh `access.db` copy: `member_owned` = people, `leftover` = the kept admins (plan E12). Restart Access | the numbers | not measured | members missing: "Réinitialisation complète", redo D16 |
| D18 | **Door tests** (plan E13): 3-5 people with MonClub fingers, one expired member refused, the reception "Ouvrir" button | as expected | 15 min | plan §6 half-state table |
| D19 | P1: re-tick "Ouvrir MonClub Access avec Windows", watchdog on, resume Windows Update. The other PCs as decided (plan D2) | -- | -- | -- |

**The retire (D10), three ways -- your choice:**
- **(a)** the release's own action, if the release checklist item was built (plan D3 (a));
- **(b)** a technician runs the SQL of plan §5.1 with the official SQLite tool, with Access stopped;
- **(c) a fresh data folder**: with Access stopped, rename `%ProgramData%\MonClub Access\access` to
  `access_before_cutover` (keep it), **and** move `%ProgramData%\MonClub Access\data\app.db` (with its
  `-wal` / `-shm` files, if they exist) into that kept folder too -- on its first start Access copies the
  old tables from `data\app.db` into a new database, sync rows included, which would undo the retire (D14
  catches it). (c) needs no new code and no SQL. Its costs: you log in again; `config.json` is rebuilt
  (from the old `data\config.json` if there is one, else defaults: re-check the settings); the PC chooses
  its record again (D11); door history not yet uploaded, offline member creations not yet sent,
  fingerprints kept only on this PC, door presets and the local history the anti-fraud limits count stay
  in the kept folder -- so first check the PC synced a moment ago and has no pending offline work. The
  kept folder is also the rollback.

## E. The morning after (both gyms)

| Step | Do | Must show | If not |
|---|---|---|---|
| E1 | Be there at opening. Watch the first ten entries | members pass | a refused member: are their card / fingers in MonClub? Is the membership valid? Staff open with "Ouvrir" and send them to the desk |
| E2 | The desk has the two lists (gym 58 cards to enter; gym 45 fingers to re-enrol) | -- | -- |
| E3 | Each driving PC, newest log: no `REVOKE_ABORTED`, no `MAINTENANCE_SKIPPED`, no `CAPACITY_FULL`, no `PIN_SCHEME_ACCOUNT_WITHHELD`; **no new `PIN_SCHEME_SWITCH`** after the night (someone changed the setting: call the developer) | clean | call the developer |
| E4 | "Postes de réception": each PC seen in the last minutes, with the new version | yes | a PC off: autostart checklist |
| E5 | The next days: the same log check once a day; delete the exports and CSV files with names or templates once you no longer need them | -- | -- |

## F. Rollback if a refill fails before opening

**The gym can open in two states only:** nothing changed yet, or the door tests passed. In between,
members not yet written back are refused at that device. The reception "Ouvrir" button keeps
working, so staff can let members in by hand while it is fixed.

The new Access handles "Par abonnement" exactly as before, so a rollback never needs the old
version back. Reinstalling an old version over the new database has never been tried.

| Gym | Point reached | Back to a working door |
|---|---|---|
| 58 | Erase started, switch not recorded on any PC | Dashboard still "Par abonnement" (set it back if C12 was saved; if a PC already logged the switch, use the next row). Cables in, start Access: it re-sends every member missing from the panel by itself (the line that does it is in every release checked, 1.4.19 to 1.4.33, and in the new one). Wait for `to_sync=0 stale=0`. If members are still refused: "Réinitialisation complète" |
| 58 | "Par personne" recorded, refill failing | Quit Access on every PC; erase the panel again; **cables out**; set it back to **"Par abonnement"** (the dashboard asks "J'ai effacé le terminal — basculer"); start Access on each PC and wait for `PIN_SCHEME_SWITCH … previous=ACCOUNT scheme=MEMBERSHIP` in its log; Quit and restart each (as C13); cables in; wait for `to_sync=0 stale=0`. Plugging in earlier writes account PINs back onto the panel |
| 58 | Only one panel failed | Treat that panel alone, the other stays on "Par personne" |
| 45 | Every row | Gym 45 plan §6, rows R1-R8, with the C13 restart before every plug-in. A fresh data folder (D10 (c)) counts as "retired": rows R3 and R4 apply to the fresh database as written. Do not rename the old folder back after an erase: it believes every old member is still on the terminal and would push nobody |

## G. Only you can answer

1. Which Access version is the release, and who ticks its checklist (release checklist)?
2. Gym 58's panel erase: a tool in the release, or the ZKTeco software (gym 58 plan E1)?
3. Gym 45's retire: release action, SQL by a technician, or a fresh data folder (D10)?
4. Gym 58's PCs: how many, which one drives the panels, and does each come back tonight (plan E3)?
5. Gym 58's QR rescue setting: on or off? The 12 September copy says off but QR entries were allowed every day (plan E2).
6. Survey evenings before the night: yes / no, and when (A)?
7. Gym 45 without a soak and without re-enrolment beforehand (N1, N2): accepted?
8. The go/no-go clock for gym 45's erase (N3), and how late gym 58 may open if its refill runs late.
9. Power left on all night at both gyms: arranged with whom?
10. The technician on site and the developer on call.
11. The things the gym 45 plan already asks you (D1-D13), especially D5 (terminal admins), D7 (biometric backups), D8 (anyone with the gym login can flip the PIN setting).

# Cutover night -- every gym on per-person PINs ("Par personne")

For the owner. Plain steps, in the order of the night. The evidence behind each step is in:
- gym 58 (cards + QR, two C3-400 panels): [`2026-09-26_gym58_cutover_plan.md`](2026-09-26_gym58_cutover_plan.md)
- gym 45 Oxyfit (fingerprints, two MB2000): [`2026-09-19_gym45_cutover_plan.md`](2026-09-19_gym45_cutover_plan.md)
- the PCs starting by themselves: [`2026-09-26_autostart_checklist.md`](2026-09-26_autostart_checklist.md)
- what the release must contain: [`2026-09-26_cutover_release_checklist.md`](2026-09-26_cutover_release_checklist.md)

> **NOT READY -- DO NOT USE ON THE NIGHT YET.** The review findings of 2026-09-26 (the gym 45 firewall
> block, the watchdog, "Ouvrir" with the cables out, the erase before the first start, the card list)
> are addressed in this second round, which is itself under review.

**PLAN ONLY -- nothing has been run.** Written 2026-09-26 on Access `master` `22c9cfc`; second round
(the review findings of 2026-09-26) on `master` `dbf865f`, branch `claude/cutover-runbook-round2`.

**Grades**, as in the two plans: `[CODE]` (an executable statement, named), `[TEST]`, `[FIELD]` (a dated
measurement), `[COMMENT]` (prose only), `[OWNER]` (the owner said so, dated; nobody has checked it here), `[UNVERIFIED]`,
`[UNKNOWN]`.

**About the times.** Almost nothing here has ever been timed on the real devices. Where a time is
known it says *measured* and where. Everything else says **not measured**. "Not measured" means:
plan the gym to stay closed until the door tests pass. The survey evening (part A) measures the
reads before the night.

**About the numbers.** Member counts come from a test copy of the 12 September database, not from
today's production. The export on the night gives the real numbers.

---

## The night in 10 lines

1. Days before: a read-only "survey evening" at each gym gives the lists of members who will lose a card or a finger; at gym 58 the new Access is then installed and started once, still on "Par abonnement" -- **required before any erase** (A).
2. Before leaving home: the release is chosen, the server's minimum version is set, the bag is packed -- with the **previous** installers and the data copies, for a rollback (B).
3. Gym 58 after closing: stop Access and its watchdog on every PC, block the panels on any PC that will not run the new Access, export both panels, compare, decide go / no-go (C1-C5).
4. Erase panel 5 and panel 6, check they are empty, pull their network cables and prove the cut (C6-C8).
5. Start the new Access on every gym 58 PC and check the dashboard verdict (C9-C11). Nothing is installed after an erase.
6. Set both panels to "Par personne", wait for the switch line in the log, restart Access and **prove** the restart, plug the cables back, let it refill (C12-C14).
7. Check the refill, test cards, QR codes and the "Ouvrir" button, re-enable autostart and the watchdog (C15-C17).
8. Gym 45: the same shape with its MB2000 tools, plus the firewall block on every PC not reinstalled, and the "retire" of each PC's old state (D).
9. Morning: read the logs, watch the first entries, send the listed members to the desk (E).
10. If a refill fails before opening: the rollback of part F. While a panel or terminal is unplugged, the "Ouvrir" button cannot open it: the turnstile arm is dropped by hand and a staff member stays there (F).

## What blocks the night today (answer these first)

| # | Blocker | Why |
|---|---|---|
| 1 | **No released Access honours "Par personne".** The release must be built and must pass the release checklist | Every tag up to `access_1.4.33` ignores the setting (backend doc `access-account-pin-minimum.md`) |
| 2 | **No tool erases a C3-400 panel** (gym 58). Decide E1 in the gym 58 plan: a small tool in the release (recommended), or the ZKTeco software -- or decide that gym 58 waits and the night is gym 45 only | Nothing in MonClub Access or its tools clears a panel's user tables on command |
| 3 | **Gym 45: how each PC forgets its old state** ("retire", decision D3 of the gym 45 plan): a button in the release, a technician with SQL, or a fresh data folder (D10 below) | Without it, members who leave are never removed from the gym 45 turnstiles again |
| 4 | **Power on all night** at both gyms (the PCs, the panels, the network) | Most gyms cut the power overnight |
| 5 | **Who is on site and who is on call**: you, a technician who can run the scripts and read a log, the developer on the phone | Most STOP rules end with "call the developer" |

---

## A. Days before -- the survey evening (recommended, read-only) and the gym 58 pre-install (required)

One evening per gym, with the gym closed. A1-A6 write nothing to any device. They give you the lists
early, so the desk can fix MonClub before the night instead of turning members away the morning
after. A7 (gym 58 only) is required before the erase, whether or not A1-A6 happen.

| Step | Do | The screen must show | Time | STOP if |
|---|---|---|---|---|
| A1 | On every PC of the gym, in this order: Config page, untick **"Ouvrir MonClub Access avec Windows"**; if the watchdog exists, disable it (`Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'`, gym 45 plan §3.3) -- **before** Quit, because the watchdog restarts Access about 2-4 minutes after any Quit (it does not know about the tray Quit: two missed 2-minute checks, then a restart `[CODE: packaging/watchdog/monclub_access_watchdog.ps1, $RequiredConsecutiveMisses = 2]`); tray icon → **Quit**. Write down each PC's name and its Access version (Windows Settings → Apps → "MonClubAccess", or "Postes de réception" for a registered PC) -- it tells which **previous** installer each PC needs for a rollback (B4) | Task Manager: no `MonClubAccess.exe`; `(Get-ScheduledTask -TaskName 'MonClub Access Watchdog' -ErrorAction SilentlyContinue).State` prints `Disabled` or nothing | a few minutes | -- |
| A2 | Gym 58: in the folder `tools\c3_panel_scripts` (run it from the USB key): `.\START_EXPORT.cmd -DeviceIp 192.168.0.202 -Label device5 -Auto`, then `.\START_EXPORT.cmd -DeviceIp 192.168.0.203 -Label device6 -Auto`. **Type each IP in full.** Gym 45: `14_export_terminal_readonly.ps1` as in the gym 45 plan B2-B3 | `[OK] complete - nothing was written to the panel`, and no `error:` line above it | not measured -- the file records it | "CONNECT FAILED": check the IP and cable; nothing changed. `PARTIAL export` or an `error:` line: keep the file, call the developer before any erase |
| A2b | Gym 58, **the reference refusal**: unplug panel 5's network cable **at the panel** (its link light goes off), run its A2 command again, then plug the cable back and run it once more. Same for panel 6. Write both codes on the paper | the unplugged run ends `CONNECT FAILED … (PullLastError=<code>, <n> ms)`; the plugged-back run connects | minutes | the unplugged run connects: that was not the panel's cable |
| A3 | Copy the whole folder `%ProgramData%\MonClub Access\` of **every** PC to a USB key, labelled with the PC's name. The database is `access\access.db` (every release since 1.0.3); on a PC upgraded from older, check `data\app.db` too -- use whichever holds the members. This copy is the rollback of A7 | the copies | -- | -- |
| A4 | Gym 45: restart Access on every PC (re-tick the box, `Enable-ScheduledTask -TaskName 'MonClub Access Watchdog'` where it existed). Gym 58: go to A7 | Access is back | -- | -- |
| A5 | At home, on the laptop with the tools: `python tools\gym45_cutover\compare_terminal_export.py --gym-id 58 --export 5=<file> --export 6=<file> --access-db <copy>\access.db --detail-csv <USB key>\cards58.csv` (gym 45: `--gym-id 45`, with `-Fingers` exports, `--detail-csv <USB key>\fingers45.csv`). Write the CSV to the USB key, not into the repo | `== cards …` and, on the line under it, `card self-check (member pins): …` (gym 58); `== people …` and the `sha self-check` line (gym 45) | seconds | gym 58: the card self-check says **BELOW 90 %** or **NOT MEASURED** -- the card list may only show that the panel returns cards in another form than MonClub writes them: do **not** use it at the desk; call the developer (the night can still happen: the list is then unknown, C5) |
| A6 | The desk fixes MonClub, **only** from a list the self-check passed (A5): **gym 58** -- only the `member_terminal_only_card` rows whose note ends **`no card in MonClub`**: enter that card as the member's card. Every other row names a card MonClub already holds: **never overwrite it** (the note says so), and never touch a MonClub card starting with `99999` -- what that marker means is `[UNVERIFIED]` (`device_sync._normalize_device_card` calls it an "anti-abuse prefix" in a comment only); those members are refused by that panel card after the erase and are sorted out when they come to the desk, with you. **Gym 45** -- re-enrol the fingers listed in `member_terminal_only_finger` rows (gym 45 plan G4 on the `sha self-check`) | -- | depends on the list | -- |
| A7 | **Gym 58 only, required before any erase** (after A1-A3 the same evening, or at the latest on the night at C3c): on every PC that will run Access, the new installer **over** the existing Access -- **never uninstall first** (the uninstaller deletes the whole `%ProgramData%\MonClub Access` folder) -- with **"Launch MonClub Access" unticked** on the last page. "Keep MonClub Access running": as the autostart checklist says on a survey evening (the PC then runs normally for days); **unticked** on the night (C3c). Start Access (the panels connected, still "Par abonnement"): it keeps its login; on "Identité du poste" choose **"C'est un nouveau PC"** and the name staff use | "Postes de réception" lists each PC with version X.Y.Z; newest log in `%ProgramData%\MonClub Access\data\logs\`: `App started. pid=… version=X.Y.Z`, then `getSyncData OK`, then `[DeviceSync] Device id=5: device_pins=…` and the same for 6, with no `REVOKE_ABORTED`. Test one member's card and one QR code at each door | not measured | the installer fails, or Access does not open (`%TEMP%\MonClubAccess.log`): part F, row "the new Access does not start -- before the erase". Gym 58 is not done until the developer has fixed it |

**Why A7 is required.** The installer deletes the old program before copying the new one
(`installer/MonClubAccess.iss::PrepareToInstall` → `DeleteTreeIfExists({app}\current)`) `[CODE]`, and a
first start whose migration fails stops on purpose (`app/core/db.py::init_db`, guide §3.2d) `[CODE]`. If
that first start came after the erase, both panels would be empty with no Access able to refill them.
Before the erase, a failed first start costs nothing at the door: the panels still hold everyone.

**What A7 changes at the door, on "Par abonnement"** (a read of the code on `dbf865f` against the
tags `access_1.4.19` to `access_1.4.33`, review 2026-09-26; never run on a panel):
- **The same as the old Access (1.4.22 to 1.4.33):** the same device pin per member (the membership
  id), the same `user` fields (`Pin`, `Name`, `CardNo`) and the same `userauthorize` rows; no stored
  hash is cleared and no `PIN_SCHEME_SWITCH` is recorded, so the upgrade alone re-writes nobody; no
  fingerprint row is written or deleted (fingerprints are off at gym 58); it removes from a panel a
  subset of what the old Access removes, and refuses a removal step above max(10, 25 % of the roster)
  `[CODE: device_sync.py::derive_member_pin, ::_compute_desired_hash, ::_sync_one_device;
  push_safety.py::check_bulk_removal; db.py::_record_device_pin_scheme_switch]`
  `[TEST: test_pin_scheme_gate.py::test_membership_scheme_is_byte_identical_to_the_pre_account_derivation;
  test_pin_scheme_switch.py::test_a_device_without_pin_scheme_records_nothing]`.
- **What does change:**
  1. From the installer's stop of Access until the new Access has connected, QR codes are not
     rescued by the PC. Cards keep working: the panel decides them `[CODE]`.
  2. If the first start fails, QR rescue stays down until the rollback (part F) `[CODE]`.
  3. A PC on 1.4.19 or 1.4.21 re-writes once the `CardNo` of members whose MonClub card has non-digits,
     leading zeros or more than 10 digits: the new release writes the digits run together
     (`99999+123` → `99999123`) and leaves out a value above 4,294,967,295 `[CODE:
     device_sync.py::_normalize_device_card]`. Any re-push writes MonClub's first card over the
     panel's `CardNo`; the old Access does the same on its own re-pushes and on "Réinitialisation
     complète" `[CODE, same in 1.4.33]`. **So A2 comes before A7**: the survey list shows the panels as
     the old Access left them.
  4. The first sync is a full refresh: any difference between the PC's copy and the server is
     corrected at once (members the server no longer delivers are removed, within the ceiling; new
     ones added) `[CODE]`. Whether there is any difference is `[UNVERIFIED]`.
  5. Two settings would make it stricter, and their production state is `[UNKNOWN]` (G): **protocol 2**
     on the server (`monclub.access.v2.enabled`) -- members outside their dates are removed at the date
     change and QR codes are refused on days not allowed (`access_dates.py::qr_date_verdict`), and a
     later return to the old Access becomes risky; and a device's **QR roster check set to "enforce"**
     (`settings_reader.py::parse_totp_roster_check_mode`, default "trial", which never refuses) -- QR
     codes of members not on the list are refused. With either on, these start at A7, not on the night.
  6. More permissive: a card never seen before is no longer skipped as "in cooldown" right after the
     PC boots, and a renewing member's old pin can stay on the panel longer `[CODE]`.

`cards58.csv`, `fingers45.csv` and every export JSON hold names and card numbers (and, for
`-IncludeTemplates`, fingerprints): **personal data**. Keep them private. They end up in three places,
delete them from all three once the night is verified (E5): the gym PC's copy of the tools folder
(`exports\`), the USB key, and the laptop.

## B. Before leaving home

| Step | Do | Must show | STOP if |
|---|---|---|---|
| B1 | The release: its checklist is ticked, and the tag passes both `git merge-base --is-ancestor 30c3b93 access_X.Y.Z` and `… 2eafb5f access_X.Y.Z` | exit code 0 twice | either fails: not this release |
| B2 | **Only now** set the server minimum to that exact version, `X.Y.Z` (backend doc `access-account-pin-minimum.md`: a one-line commit + deploy, or the variable `MONCLUB_ACCOUNT_PIN_MIN_ACCESS_VERSION` -- the CI does not pass it today), and restart the backend at a quiet hour | the backend start-up log names the minimum at INFO (a WARN means it was not accepted) | WARN: fix the value |
| B3 | Dashboard, /gym-devices, **"add a device" form** (the verdict sentence shows only there; cancel without saving), with gym 58 then gym 45 | "Au moins un PC enregistré…" or "Aucun PC n'est enregistré…": expected until the PCs are upgraded | "Aucune version publiée…" = the minimum is not set: back to B2 |
| B4 | Download to two USB keys: the release installer, **and the previous installer of every PC** (the versions written at A1). The gym 45 PC "Accueil Oxyfit" (DESKTOP-6UCRVSG) runs 1.4.32, a build that was never tagged (gym 45 plan §1): whether its installer exists anywhere is `[UNKNOWN]` (G) | the files, same size on both keys | no previous installer for a PC that is installed tonight: that PC has no rollback (F) -- you decide (G) |
| B5 | Pack the bag (list below) | -- | -- |

**The bag:** two USB keys (the release installer and the previous installers; the A3 data copies;
`tools\c3_panel_scripts`, `tools\mb2000_scripts` with its `sdk` folder, `tools\gym45_cutover`); the
laptop with Python 3.9+ and the branch `claude/cutover-runbook-round2` (or master once it is merged), for the comparisons; a network cable; each PC's Windows
password **and an administrator login on each PC that gets the firewall block** (C1b, D1: adding a
firewall rule needs an administrator PowerShell, and the reception account should not be one --
autostart checklist §2); the gyms' MonClub Access login (you type it -- nobody else needs it); the
list of each gym's PCs with their names in "Postes de réception"; for the door tests: a card of a
current member (a staff member who is also a member is simplest), a phone showing a current member's
QR code, the card of an expired member, a staff card, and at gym 45 three to five people with
fingers enrolled in MonClub; paper to write the time of each step (these are the first measurements)
and the A2b refusal codes.

## C. Gym 58 after closing

Gym 58's entries run until about 22:00 and restart about 05:00-06:00 (the 12 September copy). The
panels: **device 5 "Door 1" 192.168.0.202** and **device 6 "Door 2" 192.168.0.203**.

**Go/no-go clock.** Before C6, write down the latest time the erase may start (G, question 8). It must
leave room before opening for the refill **and**, if the refill fails, for the rollback with the
cables out (part F, gym 58 row 2: erase again, switch back, restart, refill). None of these is
measured on a C3-400. If C6 has not started by that time: stop, nothing has changed.

| Step | Do | The screen must show | Time | STOP if |
|---|---|---|---|---|
| C1 | Every PC, in this order: untick "Ouvrir MonClub Access avec Windows"; `Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'` (if it exists); Quit | no `MonClubAccess.exe` in Task Manager; the watchdog `State` is `Disabled` or absent (A1's command) | minutes | -- |
| C1b | **Every gym 58 PC that will NOT run the new Access tonight** (never pre-installed, A7): the firewall block, with the panels still connected. In an administrator PowerShell: first `.\START_EXPORT.cmd -DeviceIp 192.168.0.202 -Label blocktest -Auto` must **connect**; then `New-NetFirewallRule -DisplayName "MonClub cutover hold TCP" -Direction Outbound -RemoteAddress 192.168.0.202,192.168.0.203 -Protocol TCP -Action Block` and the same with `UDP` and `"MonClub cutover hold UDP"`; then the same export must end with `CONNECT FAILED`. Same proof for .203. Then shut the PC down. **Or** unplug that PC's network cable and keep it off. The rule stays until that PC runs the new Access (A7, on a later day) | the before run connects, the after run fails, for both IPs | minutes each | the after run connects: the block does not work -- unplug that PC from the network instead |
| C2 | Copy each PC's whole `%ProgramData%\MonClub Access\` folder to the USB key, labelled | the copies | minutes | -- |
| C3 | Export both panels (A2 commands) | `complete - nothing was written`, no `error:` line | not measured (the survey evening measured it) | connect fails: check cable/IP; nothing changed. `PARTIAL` or an `error:` line: call the developer before C6 |
| C3b | Only if A2b was not done: the reference refusal (A2b), now | both codes on paper | minutes | as A2b |
| C3c | Only if A7 was not done on an earlier day: **A7 now**, with "Keep MonClub Access running" **unticked**, right after the install `(Get-ScheduledTask -TaskName 'MonClub Access Watchdog' -ErrorAction SilentlyContinue).State` must print `Disabled` or nothing (if `Ready`: `Disable-ScheduledTask …`, check again). When A7's checks pass: C1 again on every PC (Quit, watchdog check) | A7's checks, then C1's | not measured | A7's STOP column (nothing has been erased: part F, "the new Access does not start -- before the erase") |
| C4 | Compare each export (A5 command, with the C2 copy of the PC that drives the panels), plus once with `--scheme ACCOUNT` | the `cards` list; the card self-check line; `account_pins_already_on_terminal` 0 | minutes | the ACCOUNT run shows a number > 0: call the developer. The card self-check is BELOW 90 % or NOT MEASURED: the card list is unknown (C5) |
| C5 | **Go / no-go**: the new Access has started once on every PC that will run tonight (A7 or C3c: "Postes de réception" shows each with X.Y.Z); every other PC is blocked or unplugged (C1b); you accept the card list -- the **survey list (A5)** is the one the desk worked from, tonight's (C4) is a check: a member on tonight's list but not on the survey's is a question for the developer, not a desk edit (those members are refused by card until their card is sorted out; their QR still works). With a failed card self-check you accept that the card losses are **unknown**, or stop; the erase tool is there; the clock skew in the export is within ±10 s; the clock time is not passed | -- | -- | no: re-tick autostart, `Enable-ScheduledTask …`, restart Access. **Nothing has changed** |
| C6 | **Erase** panel 5, then panel 6, with the erase tool of the release (blocker 2) | its AFTER counts: `user=0`, `userauthorize=0`, `templatev10=0` | not measured | not empty after a second run: leave that panel for another day (F, gym 58 row 1) |
| C7 | Check each is empty: a new export (A2 command) says `complete`, no `error:` line, and in the file `counts.user`, `counts.userauthorize` and `counts.templatev10` are each exactly `0` (a `FAILED` or `null` count is **not** 0) and `summary.users` is `0`; one member's card at that door is refused | both | minutes | not empty: back to C6. A count `FAILED`: call the developer -- the panel is not proven empty |
| C8 | **Pull the network cable of both panels** (leave them powered) and run each A2 command | each ends with `CONNECT FAILED` **with the same `PullLastError` code as that panel's A2b reference** | minutes | it still connects: find the right cable before going on. `CONNECT FAILED` with **another** code: STOP -- something other than the pulled cable refused the connection (for example another PC still holding the panel; whether a C3-400 refuses a second client is `[UNVERIFIED]`): find it before C9 |
| C9 | **No installer runs after the erase.** Every PC that will run Access already has the new version (C5) | -- | -- | a PC without it: it stays blocked or unplugged (C1b), off tonight |
| C10 | Start Access on each PC. It keeps its login and its registration (A7) | "Postes de réception" lists each PC with the new version, seen a moment ago | seconds after start (the PC reports at start) | Access does not open (`%TEMP%\MonClubAccess.log`): part F, "the new Access does not start -- after the erase" |
| C11 | Any gym 58 PC that is NOT running the new Access tonight stays blocked (C1b) or unplugged and switched off. **Revoking cannot stop it**: none of these PCs is registered, and a revoke does not stop an old Access anyway (D12) | -- | -- | -- |
| C12 | Dashboard, reload. On the "add a device" form (then cancel) the verdict now says **"Tous les PC enregistrés de ce club font tourner au moins la version X.Y.Z…"**. Open device 5: choose **"Par personne"**, tick **both** boxes ("Je confirme que MonClub Access a été mis à jour…", "Je confirme que les utilisateurs de ce terminal ont été effacés"), **"Les deux sont faits — enregistrer"**. Same for device 6. Reopen each | the dialog names version X.Y.Z; after saving, each reads "Par personne" | a minute | refused (red message): it names the PCs in the way; revoke a retired one in "Postes de réception" |
| C13 | On each running PC, newest file in `%ProgramData%\MonClub Access\data\logs\`: search `PIN_SCHEME_SWITCH`. Want `device_id=5 previous=MEMBERSHIP scheme=ACCOUNT` and the same for `device_id=6`. At gym 58 `cleared_rows` is a big number: **normal here**. **Then, on every running PC, the restart, proven three ways** (box "Proving a restart" below) | both lines on every running PC, then the three restart checks | a few minutes | no line: search `getSyncData OK`; then dashboard page of Access → **"Réinitialisation complète"**; still none: **do not plug in**, call the developer. A restart check fails: **do not plug in** |
| C14 | **Plug both panel cables back.** Access refills both panels | log lines `[DeviceSync] Device id=5: device_pins=… desired=… to_sync=… stale=0` | **not measured** for ~1,690 people | `REVOKE_ABORTED` in the log: a panel was not empty -- Quit Access, go to F |
| C15 | Done when a later pass of each panel says `device_pins=N desired=N to_sync=0 stale=0` (N is the people count of that pass; after midnight it can change by itself) | that line for 5 and 6 | not measured; no such line 20 minutes after the push ended: Quit and restart Access (its start-up pass prints it) | `PIN_SCHEME_ACCOUNT_WITHHELD`: "Réinitialisation complète"; persists: call the developer |
| C16 | **Door tests**, each panel: 3 members' cards open; 1 QR code opens; 1 expired card is refused; 1 staff card opens; the reception **"Ouvrir"** button opens (the panel is connected now; it can still time out during a push chunk). If the QR is refused, open the turnstile page in the dashboard and check the QR rescue setting (gym 58 plan E2) | all as expected | 15 min | a member's card is refused: is that card in MonClub on that member? (the A5 / C4 list) |
| C17 | Quit Access, export both panels, compare with `--scheme ACCOUNT` and a fresh copy of `access.db`: `member_owned` = the people count, `leftover` = 0, the card self-check at or above 90 %. Restart Access. Re-tick "Ouvrir MonClub Access avec Windows"; the watchdog **only now**: `Enable-ScheduledTask -TaskName 'MonClub Access Watchdog'` where it existed (or tick it by the autostart checklist), then `Get-ScheduledTaskInfo 'MonClub Access Watchdog' \| Select NextRunTime` | the numbers; `NextRunTime` a date (empty: autostart checklist §4) | minutes | members missing: "Réinitialisation complète", wait for C15 again |

**Proving a restart (C13, D15, and gym 45 plan E10b).** "Wait for `getSyncData OK` in the new log" proves
nothing: the log file is cut by hour window, not by process (`app-<date>-from-HH-to-HH.log`,
`app/core/logger.py::active_log_name_for`), so an old process that never exited keeps writing
`getSyncData OK (delta)` into the same file; and a second launch while the first still runs exits at
once, saying so only in `%TEMP%\MonClubAccess.log` (`access/main.py`) `[CODE]`. So, on each PC:
1. Tray icon → Quit. Task Manager shows **no `MonClubAccess.exe`** (wait up to a minute; still there:
   call the developer -- do not end it by force before asking).
2. Start Access. The newest log gets a line `App started. pid=<n> version=X.Y.Z …` (`app.py`, written at
   every start) whose time is **later than the `PIN_SCHEME_SWITCH` lines**, and whose `pid` differs from
   the previous `App started` line's.
3. **After** that `App started` line, a `getSyncData OK` line.

Why: if the dashboard was open on a gym PC when you saved "Par personne", the switch reached that
PC's Access directly (a fast patch) and was logged, but its running turnstile workers keep their old
"Par abonnement" copy of the device until a successful server sync refreshes them
(`app.py::apply_fast_patch_bundle`, the sync tick's `refresh_devices`) `[CODE]`. A pass that drains on
that old copy after the cables go in writes membership PINs onto the empty panel, and only another
erase clears them. The restart builds the workers from the database, which already says "Par
personne". (The cables are out until then, and a successful sync also refreshes the workers: the
restart is the check you can see.)

**The watchdog and the installer.** Tonight the watchdog stays disabled from C1 / D1 until C17 / D19,
because it restarts Access after any Quit: it knows nothing of the tray Quit, and after two missed
2-minute checks it starts Access again `[CODE: packaging/watchdog/monclub_access_watchdog.ps1]`. An
install undoes a disable: the installer ticks "Keep MonClub Access running" again when it was chosen
before (`UsePreviousTasks=yes`), and then runs `register_watchdog.ps1`, which deletes the task and
registers a new, **enabled** one (`installer/MonClubAccess.iss` `[Run]` `Tasks: watchdog`;
`register_watchdog.ps1`: `Remove-WatchdogTask`, then `Register-ScheduledTask`) `[CODE]`. With the script
committed on `master` the new task first runs at the next Windows logon; the owner's pending edit adds
a trigger that starts at once, so Access would start by itself a few minutes after the install
(working-tree copy, read 2026-09-26, not committed). Hence: **untick that box at every install tonight
(C3c, D9) and check the task's state right after**. Unticked, the installer leaves an existing task as
it is `[CODE: the [Run] entry runs only when the task is ticked]`. Its log, if you need it:
`%LOCALAPPDATA%\MonClubAccess\logs\watchdog.log`.

## D. Gym 45 (Oxyfit), the same night if time allows, otherwise early next morning

The terminals: **device 8 "Sortie" 192.168.1.247** and **device 10 "Entrée" 192.168.1.246** -- type each
IP in full. The three PCs: "Accueil" (LAPTOP-T6KORL9V), "Accuil Oxyfit" (no name recorded),
"Accueil Oxyfit" (DESKTOP-6UCRVSG). Each step cites the gym 45 plan (E1-E14, gates G1-G12), which
holds the exact commands and the evidence. Three things differ from that plan tonight:

- **N1 -- no soak.** The plan installed the new Access two opening days early. Tonight it is installed
  after the erase, behind the interlock, so it runs for the first time on the night (it cannot be
  pre-installed like gym 58: the new build clears fingers that exist only on the terminal, gym 45
  plan G9). A failed first start is therefore possible after the erase: that is why the bag carries
  the previous installers and the data copies, and part F has a row for it. The fingerprint version
  (G3) is still checked BEFORE the erase, from the night's export.
- **N2 -- no rescue before the erase** unless the survey evening happened (A6). Every member in the
  `member_terminal_only_finger` rows cannot enter by finger in the morning until re-enrolled at the desk.
- **N3 -- a go/no-go clock for the erase.** Gym 45 opens at about 08:00 (entries 08:00-23:00 in the
  copy). The latest erase start leaves room for the refill **and**, if it fails, for the rollback with
  the cables out (plan §6 R2-R4: a full membership re-push, never measured). If the erase (D6) has not
  started by that time, stop: gym 45 opens on its old Access, unchanged.

The PCs that are **not** reinstalled tonight get the plan's §5.2 firewall block at D1 and keep it
(plan §3.3, E1, E14, D2 (a)). That is the plan's own step, not a difference.

| Step | Do | The screen must show | Time | STOP if |
|---|---|---|---|---|
| D1 | All three PCs, in this order: untick "Ouvrir MonClub Access avec Windows", `Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'` (if it exists), Quit; write down each PC's version (A1). On the driving PC (P1, plan D2) pause Windows Update (plan E1). **Every PC that will NOT be reinstalled tonight** (plan: P2, P3), with the terminals still connected: the **plan §5.2 block**, proven -- in an administrator PowerShell, in the script-pack folder: `14_export_terminal_readonly.ps1 -DeviceIp 192.168.1.247 -Label test -Auto` must **connect**; add the two rules of plan §5.2 (`MonClub cutover hold TCP` / `UDP`, remote 192.168.1.246 and .247); the same command must now end with "Connect_Net returned FALSE" (it waits for ENTER); same for .246. Then shut that PC down. The block stays until plan §5.3 is done for that PC (plan D2) | no `MonClubAccess.exe`; the watchdog `Disabled` or absent; on each blocked PC the before run connects and the after run fails, for both IPs | minutes; the before runs are quick exports | an after run connects: the block does not work -- unplug that PC from the network and keep it off (plan §5.2) |
| D2 | Backup + survey, both terminals at once, with templates (plan B3/E2 commands). Copy both files and their `.sha256` to the USB key and the laptop | `complete: true`; each file's IP and serial match its terminal (G5) | **not measured**: the survey evening's `-MaxUsers 50` sample gives `msPerFingerRead`; × 10 × users = the read time | a read fails: retry or stop; nothing changed |
| D3 | Copy each PC's whole `%ProgramData%\MonClub Access\` folder to the USB key, labelled. With the previous installers (B4) this is the rollback if the new Access does not start (F) | the copies | minutes | -- |
| D4 | Compare on the laptop (`--gym-id 45`, the `access.db` copy of P1): fingerprint version = MonClub's (G3); the fingers-only list (G4); faces 0 (G8); clock skew within ±10 s (G10; a correction is a write, plan E3) | the numbers | minutes | **G3 red: stop gym 45 tonight** (the push would skip every finger of the other version); faces > 0: you decide (G8) |
| D5 | **Go / no-go**: the plan's gates, the D1 blocks proven, the previous installer of each PC to be reinstalled is in the bag (B4), and the N3 clock | -- | -- | no: re-tick autostart, `Enable-ScheduledTask …`, restart Access. Nothing changed (the D1 blocks can stay) |
| D6 | **Erase** each terminal with script 13: whole users, scope all non-admin, type `CLEAR` (plan E5 has the exact menu path). The warning "UNVERIFIED api" is expected. Removing an admin who is not staff: plan E5b, choice `U` only | its log `DONE ok=… failed=0` | **not measured** (the 2026-09-06 script-13 log, if found, gives the time per user, plan B7) | a user hangs 60 s: plan E5's fail column -- that terminal stays on "Par abonnement" for another day |
| D7 | Check empty, four ways (plan E6): an export, the terminal's own count, a member's finger refused, the comparison's `account_pins_already_on_terminal` = 0 | all four agree | minutes | back to D6 |
| D8 | **Interlock**: network cables out of both terminals (they keep power), or the firewall block proven on P1 (plan §5.2) | the export now fails to connect | minutes | it still connects: find the right cable |
| D9 | On every PC that will run Access: the new installer **over the existing Access -- never uninstall first** (the uninstaller deletes the whole `%ProgramData%\MonClub Access` folder: login, history, the rollback). On its pages: **untick "Keep MonClub Access running"** (the installer re-ticks your previous choice and would re-register the watchdog as a new, enabled task, which restarts Access by itself before the retire) and **untick "Launch MonClub Access"**. Right after: `(Get-ScheduledTask -TaskName 'MonClub Access Watchdog' -ErrorAction SilentlyContinue).State` | the installer ends; the watchdog `Disabled` or nothing printed; Task Manager: no `MonClubAccess.exe` | not measured | the installer fails: part F, "the new Access does not start -- after the erase". The watchdog reads `Ready` or `Running`: `Disable-ScheduledTask …`, Quit Access if it started, check again -- and if Access ran on that PC before the retire, D14 decides |
| D10 | **The retire**, per PC (blocker 3), before Access starts -- see the box below | (a) the action's counts 0; (b) the plan §5.1 counts 0; (c) the renamed folder exists and `data\app.db` is moved | minutes | a failure: put the D3 copy back, stop (plan R2) |
| D11 | Start Access on P1 (and on each other PC that will run). With a fresh folder (c): log in, and on "Identité du poste" choose **"Ce PC remplace un ancien poste"** and pick that PC's own record | "Postes de réception" shows the new version for it | seconds | Access does not open (`%TEMP%\MonClubAccess.log`): part F, "the new Access does not start -- after the erase" |
| D12 | "Postes de réception": **revoke** every gym 45 record whose PC is not reinstalled tonight -- that is what lets the server accept "Par personne". **A revoke does NOT stop an old Access from syncing or pushing**: 1.4.32/1.4.33 fetch the members with the gym login, and the revoke only stops that PC's heartbeat (`git show access_1.4.33:access/pc_identity.py`, state `revoked`; `…:app/ui/app.py::_sync_tick` calls `get_sync_data` with the gym login token) `[CODE]`; the server's member sync checks no PC status (backend `GymAccessController`, review 2026-09-26). What keeps those PCs off the terminals is the D1 block (or the PC unplugged) -- never the revoke | the verdict on the add-device form: "Tous les PC enregistrés…" | a minute | a PC not reinstalled has no proven block: do not go on until it is blocked or unplugged |
| D13 | Devices 8 and 10: "Par personne", tick both boxes, "Les deux sont faits — enregistrer"; reopen each (plan E9) | each reads "Par personne" | a minute | refused: the red message names the PCs in the way |
| D14 | **Each running PC's** log (every PC started at D11): `[T] PIN_SCHEME_SWITCH device_id=8 previous=MEMBERSHIP scheme=ACCOUNT cleared_rows=0` and the same for 10 (plan E10). **Here it must be `cleared_rows=0` on every one of them** | both lines on every running PC | a few minutes | `cleared_rows` not 0 on a PC: STOP, do not plug in; Quit that PC and keep it Quit (or behind the interlock) until it is retired again (D10) and shows `cleared_rows=0`. No line: plan E10's fail column |
| D15 | **Restart every running PC, proven** ("Proving a restart", part C; plan E10b) | the three checks on each PC | 1-2 min | a check fails: do not plug in |
| D16 | **Plug the cables back** (or remove P1's interlock block -- never the D1 blocks). Done per terminal when a pass without `FULL_SYNC_CAPPED` ends with `ZKEM_PUSH_DONE … failed=0 … tpl_failed=0` and `FULL_SYNC_DONE … ok=True`; then Quit and restart: the start-up pass says `all N desired pins already on the terminal -- nothing to push` (plan E11) | those lines | at best about 7 min per terminal, both in parallel -- a floor computed from one field rate (928 users in 419 s, v1.4.26), not a measurement | plan E11's fail column (`PIN_SCHEME_ACCOUNT_WITHHELD`, `CAPACITY_FULL`, `TEMPLATE_VERSION_MISMATCH`, `REVOKE_ABORTED`) |
| D17 | Verify: Quit, `-Fingers` export of both, compare with `--scheme ACCOUNT` and a fresh `access.db` copy: `member_owned` = people, `leftover` = the kept admins (plan E12). Restart Access | the numbers | not measured | members missing: "Réinitialisation complète", redo D16 |
| D18 | **Door tests** (plan E13): 3-5 people with MonClub fingers, one expired member refused, the reception "Ouvrir" button (the terminals are connected now; it can time out during a push chunk) | as expected | 15 min | plan §6 half-state table |
| D19 | P1 (and every other PC that ran tonight): re-tick "Ouvrir MonClub Access avec Windows", the watchdog **only now** (`Enable-ScheduledTask …`, then the `NextRunTime` check of C17), resume Windows Update. The PCs not reinstalled keep the D1 block (plan D2) | -- | -- | -- |

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
| E1 | Be there at opening. Watch the first ten entries | members pass | a refused member: are their card / fingers in MonClub? Is the membership valid? Staff open with "Ouvrir" (it works while that turnstile is connected; during a push chunk it can time out) and send them to the desk |
| E2 | The desk has the two lists (gym 58: only the `no card in MonClub` rows are entered, A6; gym 45: fingers to re-enrol) | -- | -- |
| E3 | Each driving PC, newest log: no `REVOKE_ABORTED`, no `MAINTENANCE_SKIPPED`, no `CAPACITY_FULL`, no `PIN_SCHEME_ACCOUNT_WITHHELD`; **no new `PIN_SCHEME_SWITCH`** after the night (someone changed the setting: call the developer) | clean | call the developer |
| E4 | "Postes de réception": each PC seen in the last minutes, with the new version. The PCs blocked at C1b / D1 are seen too (the block covers only the devices, their heartbeats still reach the server) | yes | a PC off: autostart checklist |
| E5 | The next days: the same log check once a day. Once the night is verified: delete the export JSON files and the CSV files from the three places they are in -- the gym PC's tools folder (`tools\c3_panel_scripts\exports\`, `tools\mb2000_scripts\exports\`), the USB key, the laptop -- and the biometric backups per gym 45 plan D7 | -- | -- |

## F. Rollback if a refill fails before opening

**The gym can open in two states only:** nothing changed yet, or the door tests passed. In between,
members not yet written back are refused at that device.

**The reception "Ouvrir" button does not help while a device is unplugged.** It opens a door through
the PC's connection to that panel or terminal: with the cable out (or the device blocked) it answers
"device unreachable" or times out (`app/api/local_access_api_v2.py::_handle_device_door_open`, 503) `[CODE]`,
and during a push chunk it can time out too (gym 45 plan §5, E11 note). **The opening fallback** is the
turnstile arm: it can be dropped by hand, so everyone enters freely `[OWNER, 2026-09-26, relayed by the
master session]`. Nothing is then checked and nothing is written to the door history. A staff member
stays at that turnstile until the refill is proven (the door tests) and the arm is raised again. How
the arm is dropped at each turnstile, and who on staff can do it, is not written anywhere yet
`[UNKNOWN]` (G). **At opening time, if the refill is not proven:** keep the gym closed, or open with the
arms dropped and a staff member at each turnstile -- **your call, on the night** (G); it is not a rule
of this runbook.

**The clock.** Each rollback row below takes time with the cables out: an erase again (gym 58, not
measured), the switch back and its restart, then a full re-push under "Par abonnement" (not measured
at either gym). The go/no-go clock (C, N3) must leave that time before opening.

The new Access handles "Par abonnement" exactly as before, so a rollback after the switch never needs
the old version back. Only the "does not start" rows reinstall an old version, which has never been
tried on these PCs `[UNVERIFIED]`; the installer has no downgrade check (`installer/MonClubAccess.iss`,
read 2026-09-26) and deletes the program folder before copying `[CODE]`.

| Gym | Point reached | Back to a working door |
|---|---|---|
| 58 | **The new Access does not start -- before the erase** (A7 / C3c) | Nothing was erased: the panels still hold everyone. Move the failed `%ProgramData%\MonClub Access` folder aside (rename it, keep it for the developer), copy back that PC's A3 (or C2) copy, run that PC's **previous** installer (B4) over it with "Launch" unticked, start Access. It works as before on "Par abonnement". Gym 58 waits until the developer has fixed it (C5 is a no) |
| 58 | **The new Access does not start -- after the erase** (C10) | It started once at A7, so this is a new failure: call the developer first. To go back: keep the cables out; move the failed folder aside; copy back **that PC's A3 copy** (taken before A7, so it is the old version's own database) and run its previous installer (B4); dashboard still "Par abonnement" (C12 not saved; if saved, set it back); cables in, start Access: it re-sends every member missing from the panel by itself (next row). What the new Access recorded since A7 and had not uploaded (door history, offline creations) is only in the moved folder: keep it. Whether the old version runs cleanly again is `[UNVERIFIED]` |
| 58 | Erase started, switch not recorded on any PC | Dashboard still "Par abonnement" (set it back if C12 was saved; if a PC already logged the switch, use the next row). Cables in, start Access: it re-sends every member missing from the panel by itself (the line that does it is in every release checked, 1.4.19 to 1.4.33, and in the new one). Wait for `to_sync=0 stale=0`. If members are still refused: "Réinitialisation complète" |
| 58 | "Par personne" recorded, refill failing | Quit Access on every PC; erase the panel again; **cables out**; set it back to **"Par abonnement"** (the dashboard asks "J'ai effacé le terminal — basculer"); start Access on each PC and wait for `PIN_SCHEME_SWITCH … previous=ACCOUNT scheme=MEMBERSHIP` in its log; restart each and prove it (C13's box); cables in; wait for `to_sync=0 stale=0`. Plugging in earlier writes account PINs back onto the panel |
| 58 | Only one panel failed | Treat that panel alone, the other stays on "Par personne" |
| 45 | **The new Access does not start** (D9 installer fails, or D11) | The terminals are erased; the dashboard is still "Par abonnement" (D13 not reached). Keep the cables out. On that PC: move the failed `%ProgramData%\MonClub Access` folder aside (keep it); copy back its **D3 copy** (the whole folder); run its previous installer (B4), "Launch" unticked. That old database believes every old member is still on the terminal, so a plain start pushes nobody: start Access behind the interlock, wait for `getSyncData OK`, press **"Réinitialisation complète"**, then plug in -- it re-pushes every member under "Par abonnement" (plan §6 R2; 1.4.33 has the button: `git show access_1.4.33:app/api/local_access_api_v2.py::_handle_sync_hard_reset` → `clear_all_device_sync_hashes` `[CODE]`; 1.4.32 was never tagged `[UNVERIFIED]`). Done when the re-push lines end (plan R2). The old system's users are gone for good (the goal). No previous installer for that PC (B4): this row is not possible -- G |
| 45 | Every other row | Gym 45 plan §6, rows R1-R8, with the proven restart (C13's box) before every plug-in. A fresh data folder (D10 (c)) counts as "retired": rows R3 and R4 apply to the fresh database as written. Do not rename the old folder back after an erase and simply start: it believes every old member is still on the terminal and would push nobody -- only the row above, with "Réinitialisation complète", uses the old folder |

## G. Only you can answer

The ten questions of the first round, then the ones this round adds.

1. Which Access version is the release, and who ticks its checklist (release checklist)?
2. Gym 58's panel erase: a tool in the release, or the ZKTeco software (gym 58 plan E1)? Or does gym 58 wait, and the night is gym 45 only?
3. Gym 45's retire: release action, SQL by a technician, or a fresh data folder (D10)?
4. Gym 58's PCs: how many, which one drives the panels, and does each come back tonight (plan E3)? Each one that does not is blocked or unplugged (C1b) until it gets the new Access.
5. Gym 58's QR rescue setting: on or off? The 12 September copy says off but QR entries were allowed every day (plan E2).
6. Survey evenings before the night: yes / no, and when (A)? At gym 58, when is the new Access pre-installed (A7): that evening, so it runs for days on "Par abonnement" (recommended), or on the night (C3c)?
7. Gym 45 without a soak and without re-enrolment beforehand (N1, N2): accepted?
8. The latest erase start at each gym (C, N3), knowing that a failed refill needs the rollback time with the cables out (F), none of it measured; and how late each gym may open.
9. Power left on all night at both gyms: arranged with whom?
10. The technician on site and the developer on call.
11. The things the gym 45 plan already asks you (D1-D13), especially D2 (the PCs not reinstalled: keep the firewall block for good -- their "Ouvrir" button then stops working -- or bring them back later by plan §5.3), D5 (terminal admins), D7 (biometric backups), D8 (anyone with the gym login can flip the PIN setting).
12. **The turnstile arm.** At each turnstile of both gyms (gym 58 doors 1 and 2, gym 45 "Entrée" and "Sortie"): how is the arm dropped (key, lever, a tool?), and which staff members know how? And on the night, if the refill is not proven at opening time: gym closed, or open with the arms dropped and a staff member at each turnstile?
13. **The previous installers** (B4): which version does each PC run today (A1), and where is each installer? "Accueil Oxyfit" (DESKTOP-6UCRVSG) runs 1.4.32, never tagged: without its installer that PC has no rollback if the new Access does not start there.
14. **The cards MonClub already holds** (A6): a member whose panel card differs from the card in MonClub, or whose MonClub card starts with `99999`: the desk does not change MonClub; who decides when that member comes to the desk, and what does `99999` mean in your gyms?
15. **An administrator login** on each PC that gets the firewall block (C1b, D1): who has them, and are they in the bag?
16. **Two server / dashboard settings** that decide whether the gym 58 pre-install (A7) is as harmless as the old Access: is protocol 2 (`monclub.access.v2.enabled`) on in production, and is any gym 58 panel's QR roster check set to "enforce"? (Release checklist §5.)
</content>
</invoke>

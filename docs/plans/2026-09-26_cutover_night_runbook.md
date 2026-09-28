# Cutover night -- every gym on per-person PINs ("Par personne")

For the owner. Plain steps, in the order of the night. The evidence behind each step is in:
- gym 58 (cards + QR, two C3-400 panels): [`2026-09-26_gym58_cutover_plan.md`](2026-09-26_gym58_cutover_plan.md)
- gym 45 Oxyfit (fingerprints, two MB2000): [`2026-09-19_gym45_cutover_plan.md`](2026-09-19_gym45_cutover_plan.md)
- the PCs starting by themselves: [`2026-09-26_autostart_checklist.md`](2026-09-26_autostart_checklist.md)
- what the release must contain: [`2026-09-26_cutover_release_checklist.md`](2026-09-26_cutover_release_checklist.md)

> **NOT READY -- DO NOT USE ON THE NIGHT YET.** Three things still block the night:
> 1. **The release.** No released Access honours "Par personne". It must be built and pass the release
>    checklist, including its MUST items (§3a: the running workers refreshed by a fast patch -- on
>    `master` since `804f4d2`; the installer and the watchdog -- on `master` since `3835ae3` and
>    `aa3445d`; none of it released) and its version and shell gates (§2).
> 2. **The erase** -- **decided 2026-09-27:** the "Erase content" wizard in Access, for C3-400 and MB2000
>    (release checklist §3a). It is on `master` (lanes 1 to 1d, `c89e80d`); lane 1e's fixes are on
>    branch `claude/cutover-final-polish` (code `7c8849a`), merged by the master session. **C6 and D6 below now use it**, in the
>    owner's order (fifth round, 2026-09-27): the wizard switched ON for the gym in the dashboard **on the
>    cutover evening** (it switches itself off 48 h later, lane 3d), erase with "hold until Refill", switch the
>    turnstile to « Par personne », restart, Refill, the wizard switched OFF after the night. **It needs the
>    gym's server switch** (lane 3c, and lane 3d's 48 h end): until that backend route is deployed, every erase
>    START is refused ("le serveur ne propose pas encore…", prerequisite B2c). It has never touched a real
>    C3-400 or MB2000 `[UNVERIFIED]` -- its field tests (release checklist §3a) come before the night.
> 3. **Your answers** in part G (among them the gym 45 retire method -- **decided 2026-09-27**: the wizard's
>    "forget records" option, done inside D6 on the PC that runs the erase, D10 -- power left on, the
>    people on site and on call, the turnstile arm, the previous installers).
>
> The review findings of 2026-09-26 are closed in this second round (independent review, clean on its
> fourth pass, 2026-09-26).

**PLAN ONLY -- nothing has been run.** Written 2026-09-26 on Access `master` `22c9cfc`; second round
(the review findings of 2026-09-26) on `master` `dbf865f`, branch `claude/cutover-runbook-round2`;
third round the same day on `master` `aeeef69`, which holds P3b-2 (driver PCs, readers, the notice
socket, remote commands): every step re-read against it -- **part H**, and notes in A7, C10, C11,
D11, D12, E3 and G. Existing step IDs are unchanged; one step is added, B2b. Fourth round
(2026-09-27, branch `claude/installer-watchdog-fix` after `2f3d5bd`): A1 writes down each PC's Windows
account and watchdog state; A7 leaves "Keep MonClub Access running" unticked on a survey evening too and
turns the watchdog on only when its checks pass; part F turns the watchdog off before any Quit and ends
with **F-end** (autostart given back); **E6** proves one power cycle the next evening; H3 adds the
held-turnstile rule. Steps added: F-end, E6. Fifth round (2026-09-27, branch `claude/erase-wizard-final`, the
Erase wizard's final state): the erase is the wizard's, in the owner's order -- so the new Access runs on
the erasing PC **before** the erase at both gyms (C6, D6), the hold replaces nothing but adds a guard
(the cables still come out, C8, D8), and **Refill** is a step of its own (C13b, D15b); prerequisite B2c
(the gym's server switch) and part F's notes on a held turnstile are added. Steps added: B2c, C13b, D15b, E7.
Sixth round (2026-09-28, branch `claude/cutover-runbook-pass` on `master` `aa015e5`, the master review of
lanes 1c and 3d): the switch's **48 h window** (B2c, A7's rehearsal, C5, D5, E7); E7 reads the switch OFF on
the dashboard, never with a START; **« Remplir » when the server cannot check the password** (C13b, part F);
part F's re-erase row rewritten for the wizard's refusals; a **held P1 that does not start** (part F); D8
proves the cut with P1's Access quit; a stop between P1's start and « Effacer » (C6, D6); gym 45's N3.
No step added; E7 now comes after E6. Seventh round (2026-09-28, branch `claude/cutover-final-polish` on `master` `c89e80d`, the master review of
lanes 1d and 2c): the wizard's switch OFF at every stop before the erase and at F-end, by one procedure
(part B, « Switching the wizard OFF »: an OFF card is never clicked); E7 per gym, and back **before** E6;
no START is used to test anything on the night (B2c); the "before the erase" rollback copies back the
copy taken before A7 (part F); « Échec » with « Remplir » showing (C6, D6, C12, D13, C13b); « Mot de
passe incorrect » and the administrator password in the bag; the clock refusal `TLS_CLOCK`; the
dashboard's member card while P1 is offline (H5). No step added.

**P3b-2 in five lines** (part H has the evidence):
1. The new Access can make one PC the "driver" of a turnstile and every other PC a "reader" that
   never connects to it. That happens only when the server's commands switch is on **and** someone
   set a driver in the dashboard. Neither should be the case in production today: the switch is off
   unless the server was started with it, and the deployment does not set it (part H1); the page
   check below reads the real state on each PC.
2. **Tonight runs without drivers**, at both gyms, from the gym 58 pre-install (A7) until the night
   is verified (E). Then every running PC connects to every turnstile of its gym -- what this
   runbook was written for. Each PC's « Pilote / Lecteur » page shows it (A7, C10, D11).
3. The cables and the firewall blocks stay exactly as they are: a driver setting is not an
   interlock, and a revoke still stops no PC (C11, D12).
4. No step needs either v2 switch on (only the pin-scheme minimum of B2). Keep both v2 switches as they are from A7 to E; if the commands
   switch is on, nobody sends remote commands to these gyms and nobody presses « Confirmer la
   suppression » tonight (E3).
5. Drivers come later, on a quiet day, and each turnstile's driver should be a PC that ran
   tonight's refill (G, question 17). A driver, once set at a gym, cannot be removed from the
   dashboard (H3).

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
2. Before leaving home: the release is chosen, the server's minimum version is set, the server's "no drivers" answer is checked from the laptop (B2b), the Erase wizard is switched ON for both gyms **that evening** and its « Activé jusqu'au … » covers the whole night (B2c), the bag is packed -- with the **previous** installers and the data copies, for a rollback (B).
3. Gym 58 after closing: stop Access and its watchdog on every PC, block the panels on any PC that will not run the new Access, export both panels, compare, decide go / no-go (C1-C5).
4. Start the new Access on the one PC that drives the panels, erase panel 5 then panel 6 with its "Erase content" wizard, **"hold until Refill"**, check they are empty, pull their network cables and prove the cut (C6-C8).
5. Start the new Access on every other gym 58 PC that runs tonight (the cables are out), check that no driver is set on its « Pilote / Lecteur » page and check the dashboard verdict (C9-C11); every other PC stays blocked or unplugged. Nothing is installed after an erase.
6. Set both panels to "Par personne", wait for the switch line in the log, restart Access and **prove** the restart, press **« Remplir »** on the erasing PC, plug the cables back, let it refill (C12-C14).
7. Check the refill, test cards, QR codes and the "Ouvrir" button, re-enable autostart and the watchdog (C15-C17).
8. Gym 45: the same shape -- the new Access installed and started on P1 **before** the erase, the wizard's users erase with "hold" (its forced "forget" is P1's retire), « Par personne », restart, « Remplir » -- plus the firewall block on every PC not reinstalled (D).
9. Morning: read the logs, watch the first entries, send the listed members to the desk (E).
10. If a refill fails before opening: the rollback of part F. While a panel or terminal is unplugged, the "Ouvrir" button cannot open it: the proposed fallback is the turnstile arm dropped by hand with a staff member there -- you confirm it on the night, otherwise the gym stays closed (F, G question 12). **If « Remplir » cannot check the password** (no internet, the MonClub server down): the turnstile stays empty and held -- wait for the connection, or the same arm fallback until « Remplir » works (F, "Held, and « Remplir » cannot check the password").

## What blocks the night today (answer these first)

| # | Blocker | Why |
|---|---|---|
| 1 | **No released Access honours "Par personne".** The release must be built and must pass the release checklist | Every tag up to `access_1.4.33` ignores the setting (backend doc `access-account-pin-minimum.md`) |
| 2 | **The erase** (both gyms). **Decided 2026-09-27:** the "Erase content" wizard in Access (C3-400 and MB2000), on `master` (lanes 1 to 1d, `c89e80d`) with lane 1e's fixes on `claude/cutover-final-polish` (release checklist §3a) -- still a blocker until it is **in the release, its field tests are done** (release checklist §3a), **and the gym's server switch answers** (B2c: lane 3c's backend with lane 3d's 48 h end deployed, the wizard switched ON for gym 58 and gym 45 on the cutover evening) | Before the switch's route is deployed, the wizard refuses every START (`ERASE_SWITCH_MISSING`) `[CODE: app/core/erase_wizard.py::check_erase_switch]` |
| 3 | **Gym 45: how each PC forgets its old state** ("retire", decision D3 of the gym 45 plan). **Decided 2026-09-27:** the wizard's "forget records" option -- forced for an MB2000 users erase, and done inside D6 on the PC that runs it (D10); a PC that runs Access tonight without having run the erase still needs D10 (b) or (c) | Without it, members who leave are never removed from the gym 45 turnstiles again |
| 4 | **Power on all night** at both gyms (the PCs, the panels, the network) | Most gyms cut the power overnight |
| 5 | **Who is on site and who is on call**: you, a technician who can run the scripts and read a log, the developer on the phone | Most STOP rules end with "call the developer" |

---

## A. Days before -- the survey evening (recommended, read-only) and the gym 58 pre-install (required)

One evening per gym, with the gym closed. A1-A6 write nothing to any device. They give you the lists
early, so the desk can fix MonClub before the night instead of turning members away the morning
after. A7 (gym 58 only) is required before the erase, whether or not A1-A6 happen.

| Step | Do | The screen must show | Time | STOP if |
|---|---|---|---|---|
| A1 | On every PC of the gym, in this order: Config page, untick **"Ouvrir MonClub Access avec Windows"**; if the watchdog exists, disable it (`Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'`, gym 45 plan §3.3) -- **before** Quit, because the watchdog restarts Access within minutes of any Quit (it does not know about the tray Quit: two missed checks in a row, then a restart `[CODE: packaging/watchdog/monclub_access_watchdog.ps1, $RequiredConsecutiveMisses = 2]` -- about 2-4 minutes with one 2-minute trigger, possibly sooner with the two of the owner's edit, box below `[UNVERIFIED]`; no sooner than about 90 s with the check script of `2f3d5bd`); tray icon → **Quit**. Write down each PC's name and its Access version (Windows Settings → Apps → "MonClubAccess", or "Postes de réception" for a registered PC) -- it tells which **previous** installer each PC needs for a rollback (B4). **Also write down, per PC:** whether the watchdog task existed before this step and its state then (for the sheet: turning it back on later goes by what exists then, part C, "Turning the watchdog back on"), and the Windows account Access is installed under -- it must be the one that logs on by itself, and every installer of this runbook runs in that account's session (autostart checklist §3a: an install is per Windows user, so under another account it would be a second, separate install) | Task Manager: no `MonClubAccess.exe`; `(Get-ScheduledTask -TaskName 'MonClub Access Watchdog' -ErrorAction SilentlyContinue).State` prints `Disabled` or nothing | a few minutes | Access installed under **two** Windows accounts: no A7 on that PC this evening -- its own day (autostart checklist §3a), with you. Installed under one account that is not the one that logs on by itself: A7 and the night stay in **that** account's session; moving it to the auto-logon account is its own day too (it needs an uninstall, which deletes `%ProgramData%\MonClub Access`) |
| A2 | Gym 58: in the folder `tools\c3_panel_scripts` (run it from the USB key): `.\START_EXPORT.cmd -DeviceIp 192.168.0.202 -Label device5 -Auto`, then `.\START_EXPORT.cmd -DeviceIp 192.168.0.203 -Label device6 -Auto`. **Type each IP in full.** Gym 45: `14_export_terminal_readonly.ps1` as in the gym 45 plan B2-B3 | `[OK] complete - nothing was written to the panel`, and no `error:` line above it | not measured -- the file records it | "CONNECT FAILED": check the IP and cable; nothing changed. `PARTIAL export` or an `error:` line: keep the file, call the developer before any erase |
| A2b | Gym 58, **the reference refusal**: unplug panel 5's network cable **at the panel** (its link light goes off), run its A2 command again, then plug the cable back and run it once more. Same for panel 6. Write both codes on the paper | the unplugged run ends `CONNECT FAILED … (PullLastError=<code>, <n> ms)`; the plugged-back run connects | minutes | the unplugged run connects: that was not the panel's cable |
| A3 | Copy the whole folder `%ProgramData%\MonClub Access\` of **every** PC to a USB key, labelled with the PC's name. The database is `access\access.db` (every release since 1.0.3); on a PC upgraded from older, check `data\app.db` too -- use whichever holds the members. This copy is the rollback of A7 | the copies | -- | -- |
| A4 | Gym 45: restart Access on every PC (re-tick the box; the watchdog back on as part C's box "Turning the watchdog back on" says -- this evening, the task there is the one A1 disabled, if any). Gym 58: go to A7 -- and every gym 58 PC that does **not** get A7 this evening (A7 put off, or the evening stops) gets this same restart of its old Access before you leave | Access is back on every PC that did not get A7 | -- | -- |
| A5 | At home, on the laptop with the tools: `python tools\gym45_cutover\compare_terminal_export.py --gym-id 58 --export 5=<file> --export 6=<file> --access-db <copy>\access.db --detail-csv <USB key>\cards58.csv` (gym 45: `--gym-id 45`, with `-Fingers` exports, `--detail-csv <USB key>\fingers45.csv`). Write the CSV to the USB key, not into the repo | `== cards …` and, on the line under it, `card self-check (member pins): …` (gym 58); `== people …` and the `sha self-check` line (gym 45) | seconds | gym 58: the card self-check says **BELOW 90 %** or **NOT MEASURED** -- the card list may only show that the panel returns cards in another form than MonClub writes them: do **not** use it at the desk; call the developer (the night can still happen: the list is then unknown, C5) |
| A6 | The desk fixes MonClub, **only** from a list the self-check passed (A5): **gym 58** -- only the `member_terminal_only_card` rows whose note ends **`no card in MonClub`**: enter that card as the member's card. Every other row names a card MonClub already holds (as first or as second card), or a panel card MonClub holds on **another** member ("that card is held by another member in MonClub -- do not enter it"): **never overwrite, never enter** (the note says so). The tool checks the other members only among the current members it loaded (the PC's delivered roster): **before entering a card, the desk searches that card number in MonClub**, and does not enter it if anyone holds it (whether MonClub refuses a duplicate card is `[UNVERIFIED]`). Never touch a MonClub card starting with `99999` -- what that marker means is `[UNVERIFIED]` (`device_sync._normalize_device_card` calls it an "anti-abuse prefix" in a comment only); those members are refused by that panel card after the erase and are sorted out when they come to the desk, with you. **Gym 45** -- re-enrol the fingers listed in `member_terminal_only_finger` rows (gym 45 plan G4 on the `sha self-check`) | -- | depends on the list | -- |
| A7 | **Gym 58 only, required before any erase** (after A1-A3 the same evening, or at the latest on the night at C3c). **Only with the release that passed B1** (its checklist ticked) and its installer downloaded as in B4 -- on a survey evening days before the night, do B1 and B4's release-installer part first (B2, the server minimum, can wait until the night). Before A7 on each PC, check that the **previous** installer for the version A1 just recorded is on the key: without it that PC has no rollback -- do A7 on that PC another evening, once it is found, or you accept it (G). On every PC that will run Access, the new installer **over** the existing Access -- **never uninstall first** (the uninstaller deletes the whole `%ProgramData%\MonClub Access` folder) -- with **"Launch MonClub Access" unticked** on the last page, and **"Keep MonClub Access running" unticked -- on a survey evening too** (fourth round, 2026-09-27). Why: gym 58's PCs run tagged builds (≤ `access_1.4.33`), which have no such box (no `access_*` tag contains `a85014c`, the commit that added it) and so no task at A1; ticked, it would register a **new, enabled** task whose time trigger starts at once, and A7's checks, its STOP "Quit" and part F's rollback would run with a watchdog that starts Access again after every Quit. Run the installer in the session of the account Access is installed under (A1). Right after the install: `(Get-ScheduledTask -TaskName 'MonClub Access Watchdog' -ErrorAction SilentlyContinue).State` prints `Disabled` or nothing (`Ready` or `Running`: `Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'`, check again). Start Access (the panels connected, still "Par abonnement"): it keeps its login; on "Identité du poste" choose **"C'est un nouveau PC"** and the name staff use. **On a survey evening, when the checks pass** (the PC then runs normally until the night): re-tick "Ouvrir MonClub Access avec Windows"; turn the watchdog on as part C's box "Turning the watchdog back on" says (a task there: `Enable-ScheduledTask`; none and the PC should have one: `register_watchdog.ps1` by hand, in that same session; then its `State` reads `Ready`). Registered by hand, the task is recorded as unticked by the installer, so later updates leave its definition as it is (they still replace its check script): tick the box at the next update to refresh it. **On the night (C3c):** none of this -- C1 again, as C3c says | "Postes de réception" lists each PC with version X.Y.Z; newest log in `%ProgramData%\MonClub Access\data\logs\`: `App started. pid=… version=X.Y.Z`, then `getSyncData OK`, then `[DeviceSync] Device id=5: device_pins=…` and the same for 6, with no `REVOKE_ABORTED`. After « Identité du poste », the PC's « Pilote / Lecteur » page shows one of part H4's two **expected** readings (press « Actualiser »; a PC registered after its start asks the server again only 2 to 30 min later -- or Quit and start Access again: it asks 12 s after the start, H4). Test one member's card and one QR code at each door | not measured | The « Pilote / Lecteur » page reads « PC pilote », « PC lecteur » or « REVOKED »: a driver is set at gym 58 -- this runbook does not cover it (the way back is the server's commands switch off, H3); on that PC, `Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'` first (if it exists), then Quit Access, and call the developer. No expected reading after a restart of Access: call the developer (H4). The installer fails, Access does not open (`%TEMP%\MonClubAccess.log`), or the log shows `REVOKE_ABORTED`: part F, row "the new Access does not start -- before the erase", and call the developer. A refused card or QR code first gets C16's checks (that card is on that member in MonClub; the member is current; the QR rescue setting, gym 58 plan E2): roll back only when those are right and the call with the developer says so. Gym 58 is not done until the developer has fixed it |

**A7's optional rehearsal (fifth round).** On a survey evening, once A7's checks pass on the PC that
will drive the panels: switch the wizard ON for gym 58 **just before the rehearsal** (B2c's way: the
dashboard's /access-pcs page, then reload the browser tab and read « Activé jusqu'au … »). Then: Devices
page, the bin icon, the administrator password, « Sauvegarde seule (répétition) : rien n'est effacé ». It
proves the server switch answers, shows step 1's list of people the refill would not put back (the desk
can act on it before the night), and measures step 1's read and the backup -- the log's `SDK_CMD
op=erase_… dur_ms=` lines, with a card scan and a desk "Ouvrir" during it. It erases nothing; while it runs
MonClub writes no member to that panel (the hold), and at its end the hold is released and a normal pass
asked `[CODE: erase_wizard.py, backupOnly]`. Its backup file stays on that PC 30 days (personal data, E5).
**Right after the rehearsal, switch the wizard OFF for gym 58** (/access-pcs; reload the tab: the card reads
off, with no « Activé jusqu'au »). Why (sixth round): the switch goes off by itself only 48 h after it was
turned on, and turning it ON while it still reads ON adds no time (lane 3d) `[CODE, backend main
f1482fd1: AccessEraseWizardService.ON_FOR, ::set]` -- a rehearsal one or two evenings before would make the
cutover evening's ON do nothing and end the window in the middle of the night; and left on, anyone with the
administrator password could erase a gym 58 panel until then. The cutover evening turns it ON again (B2c).

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
  7. **Driver PCs (P3b-2): nothing, as long as gym 58 has no driver.** The new Access then connects
     to both panels like the old one, whatever the server's commands switch says; with that switch on
     it also opens a live link to the server and can receive remote commands (part H). From A7 until
     the night is verified, nobody sets a driver for panel 5 or 6 and the commands switch is not
     changed (part H2, H5).

`cards58.csv`, `fingers45.csv` and every export JSON hold names and card numbers (and, for
`-IncludeTemplates`, fingerprints): **personal data** -- the block proofs' `blocktest` / `test` runs
too. Keep them private. Run the C3 export from the USB key (its `exports\` folder is then on the key).
They end up on the gym PCs where a tool ran (the tools' `exports\` folders), the USB key and the
laptop: delete them from all of these once the night is verified (E5).

## B. Before leaving home

| Step | Do | Must show | STOP if |
|---|---|---|---|
| B1 | The release: its checklist is ticked, and the tag passes `git merge-base --is-ancestor <commit> access_X.Y.Z` for `30c3b93` and `2eafb5f`, and for the three MUST rows of release checklist §3a (sixth round): `e70b177` (the running workers refreshed), `7c8849a` (the Erase wizard with lane 1e; `c4ceb63` is lane 1d alone, `7723310` lane 1c alone), `cc50388` (the installer keeps a disabled watchdog disabled) -- if the master session rebased or squashed a lane when merging it, its merged commit instead | exit code 0 five times | any fails: not this release |
| B2 | **Only now** set the server minimum to that exact version, `X.Y.Z` (backend doc `access-account-pin-minimum.md`: a one-line commit + deploy, or the variable `MONCLUB_ACCOUNT_PIN_MIN_ACCESS_VERSION` -- the CI does not pass it today), and restart the backend at a quiet hour | the backend start-up log names the minimum at INFO (a WARN means it was not accepted) | WARN: fix the value |
| B2b | **The server's v2 answer, before any erase** (third round). On the laptop, the evening of the night: open `https://monclubwigo.tn/api/v1/public/access/v2/pc/assignment` in a browser, or `curl.exe -s -i https://monclubwigo.tn/api/v1/public/access/v2/pc/assignment` in PowerShell. No login is needed: the route is public (backend `SecurityConfiguration` `/api/v1/public/**`, the JWT filter skips it) and, with the commands switch off, it is an unmapped route (`GlobalExceptionHandler.handleNoResource`) `[CODE, backend main]`. Never tried against production `[UNVERIFIED]` until this step is done. At gym 58, A7's page check proves the same on its own day; B2b is the only proof before gym 45's erase (N1: no pre-install there) | status **404** and the JSON body has **`"status":false`** and **`"code":"NOT_FOUND"`** -- exactly what the new Access reads as "switched off" (`app/core/v2/api.py::V2ApiError.switched_off`) `[CODE]`, so its page will show expected reading 1 (H4) | a JSON body with `"status":false` and another `code`: **no erase** until the developer has read it. It may be cleared only when it is a 4xx refusal of the missing PC token -- the route exists, so the commands switch is on, and the pages will show expected reading 2 or a driver STOP (H4); which code a token-less request gets there is `[UNVERIFIED]`. A 5xx or 429: repeat B2b later -- a PC would read it as "not reachable" (`app/core/v2/leases.py::LeaseManager.refresh`: only the 404 `NOT_FOUND` is "off", only a 2xx installs roles) `[CODE]`. **An HTML page, another kind of body, or no answer: no erase tonight** -- the new Access would read it as "not reachable" and never give an expected reading (`app/core/v2/api.py`: an answer counts as the backend's only when its JSON has `status` false and a `code`) `[CODE]` |
| B2c | **The Erase wizard's switch** (fifth round; its 48 h window, sixth round). The wizard asks the server at every erase START -- never at step 1, never for « Remplir » -- whether it is on for the gym: `GET /api/v1/manager/gym/access/erase-wizard`, and only a JSON `"enabled": true` lets the erase start `[CODE: app/api/monclub_api.py::get_erase_wizard_switch; app/core/erase_wizard.py::check_erase_switch, called by EraseWizard.start only]`; an erase already started goes on when the switch ends. The route is lane 3c's backend with lane 3d's end time (on backend main: `AccessEraseWizardService.ON_FOR` = 48 h `[CODE, backend main f1482fd1]`; which build production runs is `[UNVERIFIED]`): it answers `{"enabled", "updatedAt", "expiresAt"}`; **an ON ends by itself 48 h after it was turned on**, and turning it ON while it still reads ON adds no time -- to restart the 48 h, turn it OFF, then ON `[COMMENT: lane 3d report, 2026-09-28]`. Deploy order (same report): with the production schema selected (`USE <schema>;`), hand-run `V118` (it lists **5** columns at its end), then the backend, then the dashboard; after the first boot, the check in the backend's `docs/access-v2-switches.md` returns nothing. **Then, on the cutover evening -- not earlier** (A7's rehearsal turned it OFF after itself): **you** switch the wizard ON for gym 58 and for gym 45 on the dashboard's /access-pcs page (the gym login, as the administrator agent). **Reload the browser tab before reading the card**: the page's own refresh reloads the PC list only, never this card `[COMMENT: lane 3d report; master review F14]`. « Activé jusqu'au … » is the server's Tunis time. **From C6 until the last « Remplir » (D15b), nobody deploys or restarts the MonClub backend**: « Remplir » needs it to check the password (part F) | after the reload, each gym's card reads ON with an « Activé jusqu'au … » that **covers the whole night**: later than gym 45's morning (N3) plus the time part F's rows may take. **On site, nothing is started to test the switch** (seventh round, master review F1): the real START of C6 / D6 is the proof -- it checks the switch after the password and before anything is held or read from the turnstile `[CODE: erase_wizard.py::EraseWizard.start -- check_erase_switch runs before the run's thread is spawned; the hold is taken on that thread, _execute_run]`, so a refusal there costs nothing. **No backup-only rehearsal on the night**: on an MB2000 it is a template backup of about 900 commands (not measured), each holding the door service, and it keeps one more biometric backup 30 days. A7's rehearsal is on a survey evening only | the card reads ON but its « Activé jusqu'au » is too early (an ON from an earlier evening still running): OFF, then ON, reload, read again. On site, the wizard's START answers « Le serveur MonClub ne propose pas encore l'activation… » (`ERASE_SWITCH_MISSING`): the backend is not deployed -- **no erase tonight**. « L'effacement n'est pas activé pour cette salle » (`ERASE_NOT_ENABLED`): reload /access-pcs and read the card -- never turned on, or its 48 h ended: ON (or OFF then ON), reload, then read step 1 again. « …n'a pas répondu » (`ERASE_SWITCH_UNREACHABLE`): the internet -- the password check also needs it. « Le serveur MonClub a refusé la connexion sécurisée : la date ou l'heure de ce PC est sans doute fausse… » (`TLS_CLOCK`, seventh round: the server's certificate reads as not yet valid or expired from this PC): correct Windows' date and time on P1, then read step 1 again; already right: call the developer -- no erase meanwhile. « L'activation de l'effacement pour cette salle n'a pas pu être vérifiée : le serveur MonClub a répondu autre chose que prévu » (`ERASE_SWITCH_UNCHECKED`: a server error, a refused gym login, an answer without that boolean -- `check_erase_switch`): retry after a minute; still so: **no erase**, call the developer |
| B3 | Dashboard, /gym-devices, **"add a device" form** (the verdict sentence shows only there; cancel without saving), with gym 58 then gym 45 | "Au moins un PC enregistré…" or "Aucun PC n'est enregistré…": expected until the PCs are upgraded | "Aucune version publiée…" = the minimum is not set: back to B2 |
| B4 | Download to two USB keys: the release installer, **and the previous installer of every PC** (the versions written at A1). The gym 45 PC "Accueil Oxyfit" (DESKTOP-6UCRVSG) runs 1.4.32, a build that was never tagged (gym 45 plan §1): whether its installer exists anywhere is `[UNKNOWN]` (G) | the files, same size on both keys | no previous installer for a PC that is installed tonight: that PC has no rollback (F) -- you decide (G) |
| B5 | Pack the bag (list below) | -- | -- |

**Switching the wizard OFF for one gym** (seventh round, master review of lane 1d, F0 and F4). Every
step that ends a gym's night before its erase (C5 and D5 "no", C6 and D6 stopped before « Effacer »,
D4 G3 red), F-end and E7 point here. On the dashboard's /access-pcs page, **reload the browser tab
first** (the page's own refresh never updates this card, B2c), then read that gym's Erase-wizard card:
1. **It reads ON** (« Activé jusqu'au … »): click it to OFF, reload the tab, and read OFF with no
   « Activé jusqu'au » and no message that the save was not confirmed. Not confirmed: the card's retry
   button, then reload; still ON or unconfirmed: call the developer -- and nobody opens the wizard at
   that gym meanwhile.
2. **It already reads OFF** (its 48 h ran out, or it was turned off): **do not click it.** On an OFF
   card the only click turns it ON, for a new 48 h `[CODE, dashboard main cf24e77e:
   AccessEraseWizardCard.tsx -- checked={current.enabled}, onChange sends the clicked value; backend
   main f1482fd1: AccessEraseWizardService.set starts a new ON_FOR when it reads OFF]`.

OFF never blocks « Remplir » and never strands a held turnstile: the wizard asks the switch at an erase
START only -- never at step 1, never for « Remplir » `[CODE: erase_wizard.py::check_erase_switch,
called by EraseWizard.start only]`. An erase planned later at that gym turns it ON again (B2c).

**The bag:** two USB keys (the release installer and the previous installers; the A3 data copies;
`tools\c3_panel_scripts`, `tools\mb2000_scripts` with its `sdk` folder, `tools\gym45_cutover`); the
laptop with Python 3.9+ and Access `master` at `2f6b96e` or later (the round-2 tools are merged there; the release tag also carries them), for the comparisons; a network cable; each PC's Windows
password **and an administrator login on each PC that gets the firewall block** (C1b, D1: adding a
firewall rule needs an administrator PowerShell, and the reception account should not be one --
autostart checklist §2); the gyms' MonClub Access login (you type it -- nobody else needs it); **each
gym's administrator password** -- the statistics password that the wizard's lock screen, its START and
« Remplir » send to the server; it is not the MonClub Access login -- **and who holds it, reachable on
the night** (without it there is no erase and no « Remplir »; seventh round, master review F5); the
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
cables out (part F, the row that starts '"Par personne" recorded, refill failing': erase again, switch back, restart,
refill). None of these is
measured on a C3-400. If C6's first « Effacer » has not been pressed by that time: stop, nothing is erased
-- C6's STOP column ("The night stops after 1.") says how every PC is given back.

| Step | Do | The screen must show | Time | STOP if |
|---|---|---|---|---|
| C1 | Every PC, in this order: untick "Ouvrir MonClub Access avec Windows"; `Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'` (if it exists); Quit | no `MonClubAccess.exe` in Task Manager; the watchdog `State` is `Disabled` or absent (A1's command) | minutes | -- |
| C1b | **Every gym 58 PC that will not be started at C10 tonight -- whatever its version** (an old Access, or one pre-installed at A7 that stays off tonight: started later with a first sync that fails at boot, it would work from its stored "Par abonnement" row and refill the panel with membership PINs, gym 58 plan §3.2): the firewall block, with the panels still connected. In an administrator PowerShell: first `.\START_EXPORT.cmd -DeviceIp 192.168.0.202 -Label blocktest -Auto` must **connect**; then `New-NetFirewallRule -DisplayName "MonClub cutover hold TCP" -Direction Outbound -RemoteAddress 192.168.0.202,192.168.0.203 -Protocol TCP -Action Block` and the same with `UDP` and `"MonClub cutover hold UDP"`; then the same export must end with `CONNECT FAILED`. Same proof for .203. Then shut the PC down. **Or** unplug that PC's network cable and keep it off. **Bringing it back, on a later day, with the gym closed**, in the order of gym 45 plan §5.3: the block still on, the new Access on it (A7's install if it has an old one, "Keep MonClub Access running" unticked); start it; its log shows `PIN_SCHEME_SWITCH device_id=5 … scheme=ACCOUNT` and the same for 6; the restart proven (C13's box); only then remove the two rules (`Remove-NetFirewallRule -DisplayName "MonClub cutover hold TCP"`, and UDP) -- that PC then re-writes every member once (the switch cleared its stored hashes, `db.py::_clear_device_sync_hashes_on`), hence the gym closed; wait for C15's line; then re-tick "Ouvrir MonClub Access avec Windows" and enable the watchdog (C17) | the before run connects, the after run fails, for both IPs | minutes each | the after run connects: the block does not work -- unplug that PC from the network instead |
| C2 | Copy each PC's whole `%ProgramData%\MonClub Access\` folder to the USB key, labelled | the copies | minutes | -- |
| C3 | Export both panels (A2 commands) | `complete - nothing was written`, no `error:` line | not measured (the survey evening measured it) | connect fails: check cable/IP; nothing changed. `PARTIAL` or an `error:` line: call the developer before C6 |
| C3b | Only if A2b was not done: the reference refusal (A2b), now | both codes on paper | minutes | as A2b |
| C3c | Only if A7 was not done on an earlier day: **A7 now**, with "Keep MonClub Access running" **unticked**, right after the install `(Get-ScheduledTask -TaskName 'MonClub Access Watchdog' -ErrorAction SilentlyContinue).State` must print `Disabled` or nothing (if `Ready`: `Disable-ScheduledTask …`, check again). The untick and this check **stay even with a release that keeps a disabled watchdog disabled** (release checklist §3a, `claude/installer-watchdog-fix`): they are the second guard, and the only one if the release lacks that fix. When A7's checks pass: C1 again on every PC (Quit, watchdog check) | A7's checks, then C1's | not measured | A7's STOP column (nothing has been erased: part F, "the new Access does not start -- before the erase") |
| C4 | Compare each export (A5 command, with the C2 copy of the PC that drives the panels) -- **the cards list and the card self-check come from this run** (the panels still hold "Par abonnement" pins); then once more with `--scheme ACCOUNT`, **only** for `account_pins_already_on_terminal` (its card self-check always reads NOT MEASURED before the switch: the panel holds no account pin yet) | the `cards` list and the card self-check line of the first run; `account_pins_already_on_terminal` 0 in the second | minutes | the ACCOUNT run shows a number > 0: call the developer. The first run's card self-check is BELOW 90 % or NOT MEASURED: the card list is unknown (C5) |
| C5 | **Go / no-go**: B2b answered the backend's 404 `NOT_FOUND` this evening (or the developer cleared another backend JSON answer -- never an HTML page or no answer, B2b); the new Access has started once on every PC that will run tonight (A7 or C3c: "Postes de réception" shows each with X.Y.Z); every other PC is blocked or unplugged (C1b); you accept the card list -- the **survey list (A5)** is the one the desk worked from, tonight's (C4) is a check: a member on tonight's list but not on the survey's is a question for the developer, not a desk edit (those members are refused by card until their card is sorted out; their QR still works). With a failed card self-check you accept that the card losses are **unknown**, or stop; the release carries the Erase wizard and the gym's switch is on, its « Activé jusqu'au … » covering the night (B2c, after a reload of the tab); P1 reaches the internet (the erase and « Remplir » both need the server to check the password -- part F, "Held, and « Remplir » cannot check the password"); the clock skew in the export is within ±10 s; the clock time is not passed | -- | -- | no: re-tick autostart, `Enable-ScheduledTask …`, restart Access; then the wizard's switch OFF for gym 58 (part B, « Switching the wizard OFF »). **Nothing has changed** |
| C6 | **Erase** panel 5, then panel 6, with the release's **« Effacer le contenu »** wizard (fifth round), on the **one** PC that drives the panels (P1, G question 4) -- every other PC stays as C1 / C1b left it. 1. On P1 only: start Access (its login and registration kept, A7); its « Pilote / Lecteur » page shows an **expected** reading (H4); the Devices page shows panels 5 and 6 connected. 2. Devices page, the bin icon on panel 5's row, the administrator password (checked by the server: the internet is needed). **Step 1** reads each table's count and the panel's user list. **Step 2**: tick « Utilisateurs et cartes (user) » -- door rights and fingerprints lock on with it. **Step 3**: « Oui » (forget); **« Attendre que j'appuie sur « Remplir » »**. Read the refill lines: « Le remplissage écrira N membre(s) … (schéma Par abonnement) », « En « Par personne » : N membre(s) » **with nobody « sans numéro de compte »**, and « Liste des membres reçue de MonClub il y a … » within its limit. Read the list « N personne(s) de ce tourniquet ne seront PAS remises par le remplissage » (pin and name: people on the panel that are not in MonClub's list for it). **Step 4**: the address reads `192.168.0.202:4370`; tick « J'ai lu la liste » (when there is a list) and « MonClub Access est fermé sur tous les autres PC… » -- true since C1 / C1b (its "and stays closed until the refill" is kept tonight by the cables, not by the PCs: C10 starts the other PCs before « Remplir », and from C8 to C14 no PC reaches the panels); type the turnstile's name as MonClub has it (« Door 1 »); « Effacer ». 3. When it ends, the same for panel 6 (`192.168.0.203:4370`, « Door 2 »). The wizard backs up the chosen tables to a file and checks it before the first delete, holds the panel (MonClub writes nothing to it until « Remplir »), erases, and counts again `[CODE: app/core/erase_wizard.py]` | each run: « Terminé », « En attente », « Comptage après » `0` for `user`, `userauthorize` and `templatev10`; write down the backup file's path | **not measured** -- each device command logs `SDK_CMD op=erase_… dur_ms=`: write the total | P1's Access does not open at 1. (`%TEMP%\MonClubAccess.log`): nothing is erased -- part F, "The new Access does not start -- before the erase". The wizard refuses (a red line, before anything is erased): read it -- « …ne propose pas encore l'activation » / « …n'est pas activé pour cette salle » / « …n'a pas répondu » / « …n'a pas pu être vérifiée » (B2c's STOP column), « La liste des membres n'est pas récente » (wait for the next sync, read step 1 again), anyone « sans numéro de compte » in « Par personne » (call the developer); « Mot de passe incorrect » -- the server refused the administrator password itself (the bag): check it with the person who holds it; a gym login the server refuses reads « Ce PC n'est pas connecté à MonClub… » with this release instead `[CODE: monclub_api.py::validate_statistics_password tells the backend JWT filter's 401 (code UNAUTHORIZED) from the route's "Wrong password" 401 -- read on backend main f1482fd1; what production runs is UNVERIFIED]`, so if you are sure of the password, P1's newest log must show a recent `getSyncData OK`: none -- handle it as « Ce PC n'est pas connecté à MonClub » (call the developer). Anyone on the not-put-back list who must still get in after tonight (a staff member, a current member MonClub does not list for that door): **do not press « Effacer »** until they are in MonClub and step 1 was read again -- or you accept it (their only copy is the backup, kept for good). « Échec — rien n'a été effacé »: nothing was erased -- read its reason (in French), then **that panel's row on P1's Devices page** (seventh round, master review F3). **No « Remplir » on it:** the hold was released and nothing changed -- deal with the reason and read step 1 again, or stop. **« Remplir » shows on it:** the run kept its hold -- the orange line under « Échec » says why: the pin scheme moved, or could not be read, before any delete (a line that also says it may not last a restart: the same, and above all no restart); do **not** press « Remplir » and do **not** restart Access (C8 comes only after « Terminé »). Reload the dashboard and open that device: **it reads « Par personne »** -- saved too early (C12 comes after C11): set it, and any other gym 58 device already on « Par personne », back to « Par abonnement » -- its « J'ai effacé le terminal — basculer » is right here: nothing was written to that panel since its hold and every other PC is closed, so it holds no per-person PIN -- then wait for P1's log line `PIN_SCHEME_SWITCH device_id=5 previous=ACCOUNT scheme=MEMBERSHIP` (6 for panel 6) and do this step again from 2.: step 1's list must be the one you saw the first time, and the wizard erases a held panel with « Attendre… » (it takes the hold over). **It reads « Par abonnement »** (the scheme did not read): this step again from 2. Until then P1's hold panel says, in red, « Rien n'a été effacé sur ce tourniquet… », and « Remplir » is refused while the scheme is not the one the panel was written under `[CODE: erase_wizard.py::EraseWizard._refill_marked, HELD_SCHEME_MOVED, from the hold row's recorded scheme -- a restart keeps it]`. A panel whose run did not end « Terminé » is never switched at C12 (its STOP). « Incomplet — le tourniquet reste en attente »: run it again with « Attendre… »; still incomplete: that panel waits for another day (part F, row "Erase started, switch not recorded on any PC"). **The night stops after 1. and before the first « Effacer »** (the go/no-go clock passes, a refusal that does not clear, the not-put-back list): nothing is erased, and P1's Devices page shows no « Remplir » (a run that failed before any delete released its hold, the scheme unchanged) `[CODE: erase_wizard.py::_execute_run]`. P1 keeps the new Access (it ran it since A7); start Access again on each PC quit at C1; the C1b blocks can stay; then **F-end** (part F) on every PC that runs Access -- the gyms power off overnight, and a PC left with its box unticked and its watchdog off has no Access at opening -- and F-end's last step, the wizard's switch OFF for gym 58 (part B) |
| C7 | Check each is empty: the wizard's own check -- « Terminé » comes only when every chosen table counts `0` after the erase (`erase_wizard.py::_verify`) `[CODE]`, and « Comptage après » shows it -- and one member's card at that door is refused | both | minutes | a card opens: call the developer -- the panel is not proven empty |
| C8 | **Pull the network cable of both panels, proven with P1's Access quit** (sixth round, as D8). 1. On P1, tray icon → Quit (the watchdog is off since C1); Task Manager shows no `MonClubAccess.exe`. The hold stays in P1's database: after « Terminé » its rows read `erase`, which a start never releases `[CODE: db.py::begin_device_erase, ::release_unstarted_erase_holds]`. 2. Pull both cables (leave the panels powered) and run each A2 command. 3. Start Access on P1 again. Why P1 is quit for the proof: A2b's reference code was taken with no Access running, and a running Access holds its own session to each panel -- whether a C3-400 then refuses the export's second session, and with which code, is `[UNVERIFIED]`. The hold (C6) stops every member write from P1; the cables out are the second guard, for every PC | each ends with `CONNECT FAILED` **with the same `PullLastError` code as that panel's A2b reference**; after 3., P1's Devices page shows panels 5 and 6 on hold, with « Remplir » | minutes | it still connects: find the right cable before going on. `CONNECT FAILED` with **another** code: STOP -- something other than the pulled cable refused the connection (for example another PC still holding the panel; whether a C3-400 refuses a second client is `[UNVERIFIED]`): find it before C9. P1's Devices page no longer shows « Remplir » after 3.: call the developer, do not plug in. P1's Access does not open after 3. (`%TEMP%\MonClubAccess.log`): part F, the note "P1 does not start while a turnstile is held" |
| C9 | **No installer runs after the erase.** Every PC that will run Access already has the new version (C5) | -- | -- | a PC without it: it stays blocked or unplugged (C1b), off tonight |
| C10 | Start Access on each **other** PC that runs tonight (P1 runs since C6, restarted at C8). It keeps its login and its registration (A7). The cables are out (C8): no PC reaches the panels before C14, after the switch and every restart are proven -- which is what the wizard's « fermé sur tous les autres PC » tick protects (the hold binds P1 only) | "Postes de réception" lists each PC with the new version, seen a moment ago; each PC's « Pilote / Lecteur » page shows one of part H4's two **expected** readings (A7) | seconds after start (the PC reports at start) | Access does not open (`%TEMP%\MonClubAccess.log`): part F, "the new Access does not start -- after the erase". The page reads « PC pilote », « PC lecteur » or « REVOKED »: a driver is set at gym 58 -- Quit Access on every PC, call the developer (the way back is the server's commands switch off, H3); nothing is plugged in; if it is not solved within the go/no-go clock, part F |
| C11 | Any gym 58 PC not started at C10 stays blocked (C1b) or unplugged and switched off, whatever its version, until it is brought back as C1b says. **Revoking does not replace the block**: an old one was never registered, and a revoke does not stop an old Access anyway (D12). Nor a new one tonight: the new Access stops driving on a revoke only in a gym that uses drivers (`app/core/v2/leases.py::LeaseManager._drop_leases` returns at once otherwise) `[CODE]`, and gym 58 has none (part H) | -- | -- | -- |
| C12 | Dashboard, reload. On the "add a device" form (then cancel) the verdict now says **"Tous les PC enregistrés de ce club font tourner au moins la version X.Y.Z…"**. Open device 5: choose **"Par personne"**, tick **both** boxes ("Je confirme que MonClub Access a été mis à jour…", "Je confirme que les utilisateurs de ce terminal ont été effacés"), **"Les deux sont faits — enregistrer"**. Same for device 6. Reopen each | the dialog names version X.Y.Z; after saving, each reads "Par personne" | a minute | refused (red message): it names the PCs in the way; revoke a retired one in "Postes de réception". **A panel whose C6 run did not end « Terminé »** (« Échec » or « Incomplet »): do not switch it -- C6's STOP column, and part F, "Only one panel failed" |
| C13 | On each running PC, newest file in `%ProgramData%\MonClub Access\data\logs\`: search `PIN_SCHEME_SWITCH`. Want `device_id=5 previous=MEMBERSHIP scheme=ACCOUNT` and the same for `device_id=6`. `cleared_rows` is **0 on P1** (its C6 « forget » deleted its records of both panels, and the hold let nothing write new ones) and **a big number on the other PCs** (they kept theirs): both normal here `[CODE: db.py::retire_device_records; ::_clear_device_sync_hashes_on counts the device's device_sync_state rows]`. **Then, on every running PC, the restart, proven three ways** (box "Proving a restart" below) **Also (lane B, 2026-09-27): after the restart, no later `PIN_SCHEME_SWITCH ... previous=ACCOUNT scheme=MEMBERSHIP` line on any PC** -- such a line means a sync answer built just before the switch wrote the old scheme back (guide §3.2e residual): stop, do not plug in, call the developer. After P1's restart its Devices page still shows panels 5 and 6 on hold, with « Remplir » (the hold is kept in its database across a restart) `[CODE: app/core/device_hold.py::load]` | both lines on every running PC, then the three restart checks and the page reading (C13's box) | a few minutes | no line: search `getSyncData OK`; then dashboard page of Access → **"Réinitialisation complète"**; still none: **do not plug in**, call the developer. A restart check fails, or no expected page reading: **do not plug in**. P1 no longer shows « Remplir » on a panel before C13b: call the developer, do not plug in |
| C13b | **« Remplir »**, on P1 (fifth round). Devices page, « Remplir » on panel 5's row, the administrator password (online). The hold panel says **« Le remplissage écrira les membres selon le schéma enregistré maintenant : Par personne »**; press « Remplir maintenant ». Same for panel 6. The cables are still out: « Remplir » needs no connection to the panel -- it resets P1's records of it, releases the hold and asks for a full pass, which runs when the cable is back `[CODE: erase_wizard.py::EraseWizard.refill]` | « Remplissage lancé, schéma Par personne. », with **no** « Attention : … » line under it; the row no longer shows « Remplir » | seconds | the panel shows « Par abonnement »: the switch is not on P1 -- do not press, back to C13. **The hold panel says, in red, « Rien n'a été effacé sur ce tourniquet… » and « Remplir maintenant » stays grey** (seventh round, master review C0): that panel was never erased -- its C6 run ended « Échec » and kept its hold, and C12 should not have switched it; « Remplir » is refused while the scheme is not the panel's own `[CODE: erase_wizard.py::EraseWizard._refill_marked]`. Do not plug it in: that panel waits for another day by part F's row '"Par personne" recorded, refill failing -- the cables still out' (switch it back, prove the restarts, then « Remplir », which then reads « Par abonnement » and is accepted). « Attention : N membre(s) n'ont pas de numéro de compte… »: those members are not written tonight -- call the developer (C15's `PIN_SCHEME_ACCOUNT_WITHHELD`). « Attention : … n'est pas récente » or « …pas de liste des membres »: call the developer before C14. **« Remplir » cannot check the password** -- « Pas d'Internet : le serveur MonClub doit vérifier le mot de passe… » (`ADMIN_PASSWORD_UNCHECKABLE`), « Le serveur MonClub n'a pas pu vérifier le mot de passe… » (`ADMIN_PASSWORD_CHECK_FAILED`) or « Ce PC n'est pas connecté à MonClub… » (`PC_NOT_SIGNED_IN`) -- or « Le serveur MonClub a refusé la connexion sécurisée : la date ou l'heure de ce PC… » (`TLS_CLOCK`: correct Windows' date and time on P1 and press again; already right, it is this row) --: the panels stay held and empty, nothing is written and nothing is lost -- **no offline way round it** (owner decision: online only); part F, row "Held, and « Remplir » cannot check the password", says when the cables may go in. **« Mot de passe incorrect »**: the server refused the administrator password itself -- the panels stay held and nothing is lost; check it with the person who holds it (the bag); sure of it: as C6's STOP column says (a recent `getSyncData OK` in P1's newest log, or handle it as « Ce PC n'est pas connecté à MonClub ») |
| C14 | **Plug both panel cables back.** Access refills both panels (P1's pass requested by « Remplir », and the other running PCs' own passes) | log lines `[DeviceSync] Device id=5: device_pins=… desired=… to_sync=… stale=0` | **not measured** for ~1,690 people | `REVOKE_ABORTED` in the log: a panel was not empty -- Quit Access, go to F |
| C15 | Done when a later pass of each panel says `device_pins=N desired=N to_sync=0 stale=0` (N is the people count of that pass; after midnight it can change by itself) | that line for 5 and 6 | not measured; no such line 20 minutes after the push ended: Quit and restart Access (its start-up pass prints it) | `PIN_SCHEME_ACCOUNT_WITHHELD`: "Réinitialisation complète"; persists: call the developer |
| C16 | **Door tests**, each panel: 3 members' cards open; 1 QR code opens; 1 expired card is refused; 1 staff card opens; the reception **"Ouvrir"** button opens (the panel is connected now; it can still time out during a push chunk). If the QR is refused, open the turnstile page in the dashboard and check the QR rescue setting (gym 58 plan E2) | all as expected | 15 min | a member's card is refused: is that card in MonClub on that member? (the A5 / C4 list) |
| C17 | Quit Access, export both panels, compare with `--scheme ACCOUNT` and a fresh copy of `access.db`: `member_owned` = the people count, `leftover` = 0, the card self-check of this `--scheme ACCOUNT` run (the panel now holds account pins) compared with C4's first run -- it measures how the panel returns cards, which the push does not change: call the developer only if it is below 90 % while C4's was at or above 90 %, or more than 2 points below C4's (a margin chosen for roster changes since C4, not a measurement). Restart Access. Re-tick "Ouvrir MonClub Access avec Windows"; the watchdog **only now**, as the box "Turning the watchdog back on" below says (the task registered at A7 exists, disabled at C1: `Enable-ScheduledTask`; `register_watchdog.ps1` only where none exists -- the installer cannot be run again for the same version) | the numbers; the watchdog's `State` `Ready`, `NextRunTime` a date (empty: autostart checklist §4) | minutes | members missing: "Réinitialisation complète", wait for C15 again |

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

Then, before any plug-in, **on a PC running the new Access** (an old Access has no such page and no
driver code, H1 -- a rollback row that restarts an old Access skips this): a minute after the start,
its « Pilote / Lecteur » page shows one of part H4's two **expected** readings (press « Actualiser »).
After this restart the PC has its identity, and it asks the server 12 s after the start (H4). No
expected reading: **do not plug in**, call the developer (H4, the developer's rule).

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
checks in a row it starts Access again `[CODE: packaging/watchdog/monclub_access_watchdog.ps1]`. The
misses are counted per check, not per minute, and the task now has two repeating 2-minute triggers
(the logon one and one that starts at registration, `register_watchdog.ps1`, the owner's edit committed
2026-09-27 as `b30ef60`) `[CODE]`: once both repeat, two checks can come close together, so the restart
after a Quit can come sooner than two full intervals -- how soon is `[UNVERIFIED]`. With the check script
of `2f3d5bd` (on `master` since `aa3445d`) the second miss
counts only 90 s or more after the first, so the restart comes no sooner than about 90 s after the first
check that found Access gone `[CODE, TEST]` -- still a restart. Disable first, then Quit, as every step
says. **An install undid a disable**, as on `master` `d3725fa`: the installer ticks
"Keep MonClub Access running" again when it was chosen before (`UsePreviousTasks=yes`), and then runs
`register_watchdog.ps1`, which deleted the task and registered a new, **enabled** one
(`installer/MonClubAccess.iss` `[Run]` `Tasks: watchdog`) `[CODE]`, and with the trigger that starts at
registration Access would start by itself a few minutes after the install. **Fixed on `master`
(commit `18863bc`, merged by `3835ae3`; not released yet):** a task that was disabled is
registered again disabled, and the script prints `State: Disabled (kept)` (release checklist §3a)
`[CODE, TEST with the Task Scheduler stubbed]`. Only a release that contains it is protected; from
`2f3d5bd` "disabled" is also read from the task's definition, so a disabled task caught while a check
runs stays disabled too, and a registration that cannot keep it disabled leaves the old task or none,
never an enabled one. **Ticking the box never switches a disabled watchdog back on --
`Enable-ScheduledTask` does.** Either way: **untick that box at every install tonight (C3c, D6 -- D9 keeps the reasons) -- and
at A7 on a survey evening too -- and check the task's state right after** -- the second guard. Unticked, the installer leaves an existing task as it is `[CODE: the [Run] entry runs
only when the task is ticked]`. (A PC that never had Access gets the box **ticked** by default from that
release on -- not a case tonight: every install is over an existing Access, which keeps its previous
choice, release checklist §3b.) Its log, if you need it: `%LOCALAPPDATA%\MonClubAccess\logs\watchdog.log`;
from `2f3d5bd`, each install that ran the registration adds one line to `watchdog-register.log` in the
same folder (`OK` and the state, or `FAILED` and the error), and Setup writes its own log to `%TEMP%`.

**Turning the watchdog back on** (A4, A7's ending, C17, D19, F-end, and the gym 45 plan §5.3 and §6
point here). Go by what exists **now**, never by the A1 sheet: a task registered at A7 and disabled at C1
exists, and `register_watchdog.ps1` keeps a disabled task disabled (from `18863bc`) -- running it over a
disabled task leaves the watchdog off.
1. `Get-ScheduledTask -TaskName 'MonClub Access Watchdog' -ErrorAction SilentlyContinue`. **A task:**
   `Enable-ScheduledTask -TaskName 'MonClub Access Watchdog'`. **Nothing**, and the PC should have one
   (autostart checklist §3): `powershell -ExecutionPolicy Bypass -File
   "$env:LOCALAPPDATA\MonClubAccess\watchdog\register_watchdog.ps1"` in the session of the account Access
   is installed under (no admin needed; a new task is registered enabled). A PC still on an old version
   (e.g. a gym 58 PC whose A7 was put off) has no such script if its version predates the watchdog --
   the tagged installers up to `access_1.4.33` ship no `watchdog` folder: it stays without a watchdog
   until it gets the new release.
2. `(Get-ScheduledTask -TaskName 'MonClub Access Watchdog').State` reads **`Ready`** (or `Running` while a
   check runs). `Disabled`: step 1's `Enable-ScheduledTask`, then read it again. `NextRunTime` alone
   cannot tell a disabled task from an enabled one. **Still `Disabled`:** write it on the sheet and call
   the developer -- that PC has no crash recovery until it is fixed.
3. `Get-ScheduledTaskInfo 'MonClub Access Watchdog' | Select NextRunTime`: a date; empty with `Ready`:
   autostart checklist §4.
4. Write the state on the sheet.

## D. Gym 45 (Oxyfit), the same night if time allows, otherwise early next morning

The terminals: **device 8 "Sortie" 192.168.1.247** and **device 10 "Entrée" 192.168.1.246** -- type each
IP in full. The three PCs: "Accueil" (LAPTOP-T6KORL9V), "Accuil Oxyfit" (no name recorded),
"Accueil Oxyfit" (DESKTOP-6UCRVSG). Each step cites the gym 45 plan (E1-E14, gates G1-G12) for its
commands and evidence. **Where this part and the plan differ, this part is the night's order** -- the
plan's own banner lists the differences (sixth round): no Phase D soak; the new Access installed and
started on P1 **before** the erase (D6); the erase and P1's retire are the Erase wizard's (not script 13
at E5, not §5.1 with Access stopped at E8); P1 runs from D6 on (E10's "Start Access on P1" is already
done); « Remplir » (D15b) before the cables go in (E11); part F's rows before plan §6. Three of them in
more detail:

- **N1 -- no soak, but the first start comes before the erase** (fifth round). The plan installed the new
  Access two opening days early. Tonight it is installed on P1 on the night -- and, since the erase is
  the new Access's own wizard, installed and started **before** the erase (D6), still on "Par
  abonnement", the terminals connected. (A pre-install days before, as at gym 58, is the plan's own soak;
  it needs the survey and the re-enrolment first, because the new build clears fingers that exist only
  on the terminal, plan G9 -- tonight D2's backup, with templates, is taken before that first start.) A
  failed first start therefore happens before anything is erased: part F's gym 45 row "The new Access
  does not start". The fingerprint version (G3) is still checked BEFORE the erase, from the night's export.
- **N2 -- no rescue before the erase** unless the survey evening happened (A6). Every member in the
  `member_terminal_only_finger` rows cannot enter by finger in the morning until re-enrolled at the desk.
- **N3 -- a go/no-go clock for the erase.** Gym 45 opens at about 08:00 (entries 08:00-23:00 in the
  copy). The latest erase start leaves room for the refill **and**, if it fails, for the rollback with
  the cables out (plan §6 R2-R4: a full membership re-push, never measured). If the erase (D6, the
  wizard's first « Effacer ») has not started by that time, stop: nothing is erased, and gym 45 opens on
  "Par abonnement", the other PCs on their old Access (D6's STOP column says how every PC is given
  back). **If D6's install was done, P1 now runs the new Access, and at gym 45 that is not "unchanged"**
  (A7's list is gym 58's, where fingerprints are off): the new build's daily finger sweep clears, at
  most 100 members a day per terminal, the finger slots MonClub does not deliver on members it owns
  (plan G9) `[CODE: ultra_engine.py::_drain_finger_sweep, ::_sweep_check, _FINGER_SWEEP_DAILY_CAP]` -- a
  member in the `member_terminal_only_finger` rows who was not re-enrolled (N2) loses that finger at
  the door. Either you keep P1 on the new Access and its log is read every day as plan Phase D2 says
  (`[T] TEMPLATE_VERSION_MISMATCH` → back to the old Access; `[T] FINGER_SWEEP … cleared=` above 0 on a
  pin of the detail CSV → re-enrol that member; `REVOKE_ABORTED`, `CAPACITY_FULL` → the developer), with
  the desk re-enrolling the listed members as they come (E2) -- or P1 gets its old Access back with
  part F's gym 45 row "The new Access does not start -- before the erase" (its D3 copy and previous
  installer). You decide (G question 7).

The PCs that are **not** reinstalled tonight get the plan's §5.2 firewall block at D1 and keep it
(plan §3.3, E1, E14, D2 (a)). That is the plan's own step, not a difference.

| Step | Do | The screen must show | Time | STOP if |
|---|---|---|---|---|
| D1 | All three PCs, in this order: untick "Ouvrir MonClub Access avec Windows", `Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'` (if it exists), Quit; write down each PC's version (A1). On the driving PC (P1, plan D2) pause Windows Update (plan E1). **Every PC that will NOT be reinstalled tonight** (plan: P2, P3), with the terminals still connected: the **plan §5.2 block**, proven -- in an administrator PowerShell, in the script-pack folder: `14_export_terminal_readonly.ps1 -DeviceIp 192.168.1.247 -Label test -Auto` must **connect**; add the two rules of plan §5.2 (`MonClub cutover hold TCP` / `UDP`, remote 192.168.1.246 and .247); the same command must now end with "Connect_Net returned FALSE" (it waits for ENTER); same for .246. Then shut that PC down. The block stays until plan §5.3 is done for that PC (plan D2) | no `MonClubAccess.exe`; the watchdog `Disabled` or absent; on each blocked PC the before run connects and the after run fails, for both IPs | minutes; the before runs read the users only (no `-Fingers`), not measured | an after run connects: the block does not work -- unplug that PC from the network and keep it off (plan §5.2) |
| D2 | Backup + survey, both terminals at once, with templates (plan B3/E2 commands). Copy both files and their `.sha256` to the USB key and the laptop | `complete: true`; each file's IP and serial match its terminal (G5) | **not measured**: the survey evening's `-MaxUsers 50` sample gives `msPerFingerRead`; × 10 × users = the read time | a read fails: retry or stop; nothing changed |
| D3 | Copy each PC's whole `%ProgramData%\MonClub Access\` folder to the USB key, labelled. With the previous installers (B4) this is the rollback if the new Access does not start (F) | the copies | minutes | -- |
| D4 | Compare on the laptop (`--gym-id 45`, the `access.db` copy of P1): fingerprint version = MonClub's (G3); the fingers-only list (G4); faces 0 (G8); clock skew within ±10 s (G10; a correction is a write, plan E3) | the numbers | minutes | **G3 red: stop gym 45 tonight** (the push would skip every finger of the other version): D5's "no", with the wizard's switch OFF for gym 45 (part B); faces > 0: you decide (G8) |
| D5 | **Go / no-go**: B2b answered the backend's 404 `NOT_FOUND` this evening (or the developer cleared another backend JSON answer -- never an HTML page or no answer, B2b); the plan's gates, the D1 blocks proven, the previous installer of each PC to be reinstalled is in the bag (B4), the release carries the Erase wizard and the gym's switch is on, its « Activé jusqu'au … » covering the night (B2c, after a reload of the tab), P1 reaches the internet (the erase and « Remplir » need the server, C5), and the N3 clock | -- | -- | no: re-tick autostart, `Enable-ScheduledTask …`, restart Access; then the wizard's switch OFF for gym 45 (part B, « Switching the wizard OFF » -- no gym 45 PC has the wizard before D6, so this is only the night's closing step). Nothing changed (the D1 blocks can stay) |
| D6 | **Install and start the new Access on P1, then erase** each terminal with its **« Effacer le contenu »** wizard (fifth round; script 13 is no longer the way). 1. On P1, in the session of the account Access is installed under (A1): the new installer **over** the existing Access -- never uninstall first -- with **"Keep MonClub Access running" and "Launch MonClub Access" unticked**; right after, `(Get-ScheduledTask -TaskName 'MonClub Access Watchdog' -ErrorAction SilentlyContinue).State` prints `Disabled` or nothing (D9's reasons). P2 and P3 stay as D1 left them (Quit, blocked). 2. Start Access on P1 (the terminals connected, still "Par abonnement"): `getSyncData OK` in its log; its « Pilote / Lecteur » page shows an **expected** reading (H4). 3. Devices page, the bin icon on device 8 « Sortie », the administrator password (online). **Step 1**: users, administrators, fingerprints and faces each read a number. **Step 2**: « Utilisateurs : cartes, mots de passe, empreintes (sauf administrateurs) ». **Step 3**: « Oui » (forget) is forced for this erase -- it is P1's retire (D10); **« Attendre que j'appuie sur « Remplir » »**; the refill lines as C6 (nobody « sans numéro de compte » in « Par personne »); faces: accept their loss only as D4 / G8 decided; the list « N personne(s) … ne seront PAS remises » holds the old system's users (plan D5 -- deleting them is your written decision) -- anyone else who must keep access: stop, as C6. **Step 4**: `192.168.1.247:4370`, the two ticks, type « Sortie », « Effacer ». 4. Then device 10 « Entrée » (`192.168.1.246:4370`). The administrators (privilege > 0) and their fingers stay on the terminal `[CODE: erase_wizard.py::_erase]` | each run: « Terminé », « En attente »; « Comptage après »: users = the administrators kept, fingerprints = their fingers; the steps list « Enregistrements de MonClub oubliés »; write down the backup file's path | **not measured**: the backup reads every template, 2 users per command (~900 commands for ~1,800 users). Nothing measures it before the night at gym 45 -- no PC there has the wizard before D6 (N1), and A7's rehearsal is gym 58's C3 -- so write down tonight's `SDK_CMD op=erase_read_templates dur_ms=` total, and keep the N3 clock for it | the installer or the first start fails: part F, gym 45 "The new Access does not start -- before the erase" (nothing erased yet). A refusal or « Échec » before any erase: as C6 -- « Échec » with « Remplir » showing included, with gym 45's names: any other gym 45 device already on « Par personne » set back too, the switch line names `device_id=8` or `10`, and the step is done again **from 3.** (the Devices page; never 2., which would restart P1's Access). « Un administrateur du terminal a le même numéro qu'un membre » (`ADMIN_PIN_IN_ROSTER`): change that administrator's number in the terminal's own menu -- the plan has no step for that (plan E5b deletes an administrator with script 7, with Access stopped on P1), and whether this MB2000's menu can change a user's number is `[UNVERIFIED]` -- then read step 1 again; or stop gym 45 tonight. **The night stops after 2. and before the first « Effacer »** (the N3 clock, a refusal that does not clear, the not-put-back list): nothing is erased and P1's Devices page shows no « Remplir » (as C6); P1 keeps the new Access or gets its old one back (N3 says what the new one changes at gym 45); P2 and P3 as D5's "no" (the D1 blocks stay); then **F-end** on P1 -- the box re-ticked, the watchdog back on, Windows Update resumed, and the wizard's switch OFF for gym 45 (part B). « Incomplet »: run it again with « Attendre… »; still incomplete: that terminal waits for another day -- on P1, « Remplir » on it (reading « Par abonnement »: every member is written back), cables in; part F's gym 45 rows (a held terminal takes no push before « Remplir ») |
| D7 | Check empty: the wizard's own check -- « Terminé » comes only when a fresh listing shows no non-administrator user and the terminal's counters equal the administrators kept and their fingers (`erase_wizard.py::_verify`) `[CODE]` -- and a member's finger refused. Plan E6's export is not repeated here (the wizard's own verify is the check): D17's export after the refill shows the terminal's content (`leftover` = the kept administrators) | both | minutes | a member's finger opens: call the developer -- the terminal is not proven empty |
| D8 | **Interlock, proven with P1's Access quit** (sixth round). 1. On P1, tray icon → Quit (the watchdog is off since D1); Task Manager shows no `MonClubAccess.exe`. The hold stays in P1's database: after « Terminé » its row reads `erase`, which a start never releases `[CODE: db.py::begin_device_erase, ::release_unstarted_erase_holds]`. 2. Network cables out of both terminals (they keep power), or the firewall block on P1 (plan §5.2). 3. Run the export of each terminal (`14_export_terminal_readonly.ps1 -DeviceIp <ip> -Label test -Auto`). 4. Start Access on P1 again. Why P1 is quit for the proof: a running Access holds its own session to each terminal, and whether an MB2000 then refuses the export's second session is `[UNVERIFIED]` (plan §8: never tried) -- a wrong cable pulled could still fail the export; gym 45 has no reference refusal code like gym 58's A2b (the export prints only "Connect_Net returned FALSE"). Quit, no session is left but the export's. The hold (D6) stops every member write from P1; the interlock is the second guard, for every PC | each export ends with "Connect_Net returned FALSE" (it waits for ENTER); after 4., P1's Devices page shows devices 8 and 10 on hold, with « Remplir » | minutes | an export connects: find the right cable (or the block does not work: unplug instead). P1's Devices page no longer shows « Remplir » after 4.: call the developer, do not plug in |
| D9 | **No installer runs after the erase** (as C9). P1 got the new Access at D6, before the erase -- where this step's reasons still apply: the installer over the existing Access, **never uninstall first** (the uninstaller deletes the whole `%ProgramData%\MonClub Access` folder: login, history, the rollback -- and, after an erase, the hold and the backups, part F); **"Keep MonClub Access running" unticked** (the installer re-ticks your previous choice; an installer without the fix of release checklist §3a re-registers the watchdog as a new, **enabled** task, which restarts Access by itself -- with the fix, a task disabled at D1 stays disabled, and this untick and the check **stay as the second guard**); "Launch MonClub Access" unticked. P2 and P3 are not reinstalled tonight (D1's block) | -- | -- | a PC other than P1 would run tonight: it gets D6's install and first start **before** the erase, or stays blocked |
| D10 | **The retire.** On P1: **done by D6** -- the wizard's « forget », forced for an MB2000 users erase, deleted P1's records of devices 8 and 10 in one durable write after the erase was verified, the administrators left on the terminal excepted (`erase_wizard.py::_records` → `db.retire_device_records(keep_pins=…)`) `[CODE]`. A PC that runs Access tonight without having run the erase (none in the plan): the box below, (b) or (c), with its Access stopped | each D6 run lists « Enregistrements de MonClub oubliés » | -- | a run without that step (it ended « Incomplet »: nothing is forgotten after an unverified erase): part F |
| D11 | P1 runs since D6. Start Access on each other PC that will run (none in the plan). With a fresh folder (c): log in, and on "Identité du poste" choose **"Ce PC remplace un ancien poste"** and pick that PC's own record | "Postes de réception" shows the new version for it; its « Pilote / Lecteur » page shows one of part H4's two **expected** readings (after "Identité du poste" with (c): H4, a PC registered after its start) | seconds | Access does not open (`%TEMP%\MonClubAccess.log`): part F, "the new Access does not start -- after the erase". The page reads « PC pilote », « PC lecteur » or « REVOKED »: a driver is set at gym 45 -- Quit Access on every PC, call the developer (the way back is the server's commands switch off, H3); nothing is plugged in; if it is not solved within the N3 clock, part F |
| D12 | "Postes de réception": **revoke** every gym 45 record whose PC is not reinstalled tonight -- that is what lets the server accept "Par personne". **A revoke does NOT stop an old Access from syncing or pushing**: 1.4.32/1.4.33 fetch the members with the gym login, and the revoke only stops that PC's heartbeat (`git show access_1.4.33:access/pc_identity.py`, state `revoked`; `…:app/ui/app.py::_sync_tick` calls `get_sync_data` with the gym login token) `[CODE]`; the server's member sync checks no PC status (backend `GymAccessController`, review 2026-09-26). What keeps those PCs off the terminals is the D1 block (or the PC unplugged) -- never the revoke. The new Access too drives on after a revoke tonight: it stops only in a gym that uses drivers (`app/core/v2/leases.py::LeaseManager._drop_leases`) `[CODE]`, and gym 45 has none (part H) | the verdict on the add-device form: "Tous les PC enregistrés…" | a minute | a PC not reinstalled has no proven block: do not go on until it is blocked or unplugged |
| D13 | Devices 8 and 10: "Par personne", tick both boxes, "Les deux sont faits — enregistrer"; reopen each (plan E9) | each reads "Par personne" | a minute | refused: the red message names the PCs in the way. **A terminal whose D6 run did not end « Terminé »**: do not switch it -- D6's STOP column |
| D14 | **Each running PC's** log (every PC started at D11): `[T] PIN_SCHEME_SWITCH device_id=8 previous=MEMBERSHIP scheme=ACCOUNT cleared_rows=0` and the same for 10 (plan E10). After a fresh data folder (D10 (c)) whose first successful sync came only after D13, the line reads `previous=UNKNOWN scheme=ACCOUNT cleared_rows=0 first_sighting=True` instead: also right (`db.py::_record_device_pin_scheme_switch`, first sighting on ACCOUNT) `[CODE]`. **Here it must be `cleared_rows=0` on every one of them -- on P1, at most the `kept` of its D6 « forget » step** (the administrators left on the terminal keep their rows, `db.retire_device_records(keep_pins=…)`, and the switch counts every row left, `db.py::_clear_device_sync_hashes_on`) `[CODE]` | both lines on every running PC | a few minutes | `cleared_rows` above that on a PC (not 0; on P1, above its « forget »'s `kept`): STOP, do not plug in. Quit that PC and keep it Quit; plan E10's fail column (an E6 export: the terminal still empty?). Then retire that PC again (D10, Access stopped). With (a) or (b): the counts for 8 and 10 are 0, and the switch line does not come again -- the switch is already recorded on that PC (`db.py::_record_device_pin_scheme_switch` records nothing when the scheme is unchanged) `[CODE]`. With (c) -- where a non-zero `cleared_rows` most likely means `data\app.db` was not moved: check that first -- a fresh folder again, renamed to `access_before_cutover_2` (never touch the first kept folder: it is a rollback); its first start logs `previous=UNKNOWN scheme=ACCOUNT cleared_rows=0 first_sighting=True` for 8 and 10 -- that is the check. No line: plan E10's fail column |
| D15 | **Restart every running PC, proven** ("Proving a restart", part C; plan E10b) **Also (lane B, 2026-09-27): after the restart, no later `PIN_SCHEME_SWITCH ... previous=ACCOUNT scheme=MEMBERSHIP` line on any PC** -- such a line means a sync answer built just before the switch wrote the old scheme back (guide §3.2e residual): stop, do not plug in, call the developer. | the three checks and the page reading (the box) on each PC; after P1's restart its Devices page still shows devices 8 and 10 on hold, with « Remplir » | 1-2 min | a check fails, or no expected page reading: do not plug in. P1 no longer shows « Remplir » on a terminal before D15b: call the developer, do not plug in |
| D15b | **« Remplir »**, on P1, for device 8 then device 10 -- as C13b (the hold panel reads « …schéma enregistré maintenant : Par personne »; the cables are still out). On an MB2000 « Remplir » also checks the administrators the erase kept, **as the erase's backup lists them** -- it does not read the terminal again (its cables are out): **« D'après la sauvegarde de l'effacement, N administrateur(s) du terminal ont le même numéro qu'un membre en « Par personne » »** means the refill would write that member over the administrator, without administrator rights `[CODE: erase_wizard.py::_refill_recheck, ::_held_run_admins]` | as C13b: « Remplissage lancé, schéma Par personne. », no « Attention : … » line | seconds | as C13b -- « Remplir » cannot check the password: part F, "Held, and « Remplir » cannot check the password" (at gym 45 P1 is the only PC: wait, or the arm fallback). The administrator message: do not tick « Je confirme… » on your own -- call the developer. Changing that administrator's number in the terminal's own menu first (not a plan step; possible on this MB2000 `[UNVERIFIED]`) avoids the overwrite, but the message stays (it reads the backup): tick « Je confirme… » only once the number is changed, or to accept the administrator's replacement |
| D16 | **Plug the cables back** (or remove P1's interlock block -- never the D1 blocks), after D15b. Done per terminal when a pass without `FULL_SYNC_CAPPED` ends with `ZKEM_PUSH_DONE … failed=0 … tpl_failed=0` and `FULL_SYNC_DONE … ok=True`; then Quit and restart: the start-up pass says `all N desired pins already on the terminal -- nothing to push` (plan E11) | those lines | at best about 7 min per terminal, both in parallel -- a floor computed from one field rate (928 users in 419 s, v1.4.26), not a measurement | plan E11's fail column (`PIN_SCHEME_ACCOUNT_WITHHELD`, `CAPACITY_FULL`, `TEMPLATE_VERSION_MISMATCH`, `REVOKE_ABORTED`) |
| D17 | Verify: Quit, `-Fingers` export of both, compare with `--scheme ACCOUNT` and a fresh `access.db` copy: `member_owned` = people, `leftover` = the kept admins (plan E12). Restart Access | the numbers | not measured | members missing: "Réinitialisation complète", redo D16 |
| D18 | **Door tests** (plan E13): 3-5 people with MonClub fingers, one expired member refused, the reception "Ouvrir" button (the terminals are connected now; it can time out during a push chunk) | as expected | 15 min | plan §6 half-state table |
| D19 | P1 (and every other PC that ran tonight): re-tick "Ouvrir MonClub Access avec Windows", the watchdog **only now** (part C, "Turning the watchdog back on": its `State` `Ready`, then `NextRunTime`), resume Windows Update. The PCs not reinstalled keep the D1 block (plan D2) | -- | -- | -- |

**The retire (D10), three ways -- (a) decided 2026-09-27:**
- **(a)** the Erase wizard's « forget », on the PC that runs the erase, inside D6 (release checklist §3b) -- it
  retires that PC only;
- **(b)** a technician runs the SQL of plan §5.1 with the official SQLite tool, with Access stopped;
- **(c) a fresh data folder**: with Access stopped, rename `%ProgramData%\MonClub Access\access` to
  `access_before_cutover` (keep it; a second (c) on the same PC uses `access_before_cutover_2`), **and** move `%ProgramData%\MonClub Access\data\app.db` (with its
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
| E2 | The desk has the two lists (gym 58: only the rows whose note **ends with** `no card in MonClub` are entered, after the desk searched that card number in MonClub, A6; gym 45: fingers to re-enrol) | -- | -- |
| E3 | Each driving PC, newest log: no `REVOKE_ABORTED`, no `MAINTENANCE_SKIPPED`, no `CAPACITY_FULL`, no `PIN_SCHEME_ACCOUNT_WITHHELD`; **no new `PIN_SCHEME_SWITCH`** after the night (someone changed the setting: call the developer). If the server's commands switch is on (part H5): the dashboard may also list these as turnstile problems -- **nobody presses « Confirmer la suppression »** on a list for devices 5, 6, 8 or 10 until the developer has read it; and « Pilote / Lecteur » still shows one of part H4's two **expected** readings on each PC | clean | call the developer |
| E4 | "Postes de réception": each PC that ran tonight seen in the last minutes, with the new version. (The PCs blocked at C1b / D1 were shut down; a revoked one sends no heartbeat, D12) | yes | a PC off: autostart checklist |
| E5 | The next days: the same log check once a day. Once the night is verified: delete the export JSON files and the CSV files from every place they are in -- the `exports\` folder of the tools on **every PC where a tool ran** (the driving PCs, and each PC that got the block proof at C1b / D1: the `blocktest` / `test` runs are full user lists too), the USB key, the laptop -- and the biometric backups per gym 45 plan D7 | -- | -- |
| E7 | **The Erase wizard's switch OFF** (fifth round, the owner's order; sixth round: checked on the dashboard only; seventh round: per gym, and done **before E6** -- the morning after, not the next evening): **for each gym**, once it is verified (E1-E3), or once its night ended through a stop before the erase or a part F row (F-end already did it then, a turnstile left held for another day included) -- it does not wait for the other gym, nor for E6's evening. Switch it OFF as part B's « Switching the wizard OFF » says: reload the tab, read the card; ON → click, reload, read OFF; **already OFF** (its 48 h ran out: it ends by itself 48 h after its ON, B2c) → **do not click**, it would turn it ON for a new 48 h. Not before: part F's rows erase again with it (if its 48 h ran out meanwhile, B2c's ON again). **Never check it by starting the wizard on a gym turnstile**: step 1 alone runs full reads of that turnstile on the worker, during which QR codes, desk "Ouvrir" and staff-card rescues wait (guide §3.2h, "What the wizard does to the door"), and if the OFF did not take, a START goes on to hold and back the turnstile up -- or to erase it `[CODE: erase_wizard.py -- preview() is never gated by the switch; start() checks it after the password]`. Its backups stay on the erasing PCs -- 30 days after « Remplir », and for good when a run removed people the refill does not put back (`keep_not_refilled.txt` in its folder); they are personal and biometric data, like the exports of E5 (gym 45 plan D7) | after the reload, each gym's card reads OFF, with no « Activé jusqu'au » and no message that the save was not confirmed | the card says the save was not confirmed: press the card's retry button (lane 3d report), then reload the tab; still ON or unconfirmed: call the developer -- and nobody opens the wizard at these gyms meanwhile |
| E6 | **The next evening, gym closed** (after C17 / D19, or after a rollback and F-end): on each PC that ran Access that night, **one power cycle** -- the test of the autostart checklist §5 (power off at the wall, back on; t1, t2, t3 on the sheet), never during an erase or a refill. Not on a PC kept blocked or stopped | Windows opens by itself, `App started` in the new log, the "turnstile updated" line, and "Postes de réception" shows the PC seen a moment ago -- nobody touched the PC | autostart checklist §5's STOP rules; until it passes, that PC is not proven to come back after the next power cut: someone switches it on and starts Access at opening |

## F. Rollback if a refill fails before opening

**The gym opens normally in two states only:** nothing changed yet, or the door tests passed. In between,
members not yet written back are refused at that device.

**The reception "Ouvrir" button does not help while a device is unplugged.** It opens a door through
the PC's connection to that panel or terminal: with the cable out (or the device blocked) it answers
"device unreachable" or times out (`app/api/local_access_api_v2.py::_handle_device_door_open`, 503) `[CODE]`,
and during a push chunk it can time out too (gym 45 plan §5, E11 note). **The opening fallback** is the
turnstile arm: it can be dropped by hand, so everyone enters freely `[OWNER, 2026-09-26, relayed by the
master session]`. Nothing is then checked and nothing is written to the door history. A staff member
stays at that turnstile until the refill is proven (the door tests) and the arm is raised again. How
the arm is dropped at each turnstile, and who on staff can do it, is not written anywhere yet
`[UNKNOWN]` (G). **At opening time, if the refill is not proven,** the proposed fallback is to open with
the arms dropped and a staff member at each turnstile -- **you confirm it on the night** (G, question 12);
otherwise the gym stays closed. It is never automatic.

**The clock.** Each rollback row below takes time with the cables out: an erase again (gym 58, not
measured), the switch back and its restart, then a full re-push under "Par abonnement" (not measured
at either gym). The go/no-go clock (C, N3) must leave that time before opening.

The new Access handles "Par abonnement" exactly as before, so a rollback after the switch never needs
the old version back. Only the "does not start" rows reinstall an old version, which has never been
tried on these PCs `[UNVERIFIED]`; the installer has no downgrade check (`installer/MonClubAccess.iss`,
read 2026-09-26) and deletes the program folder before copying `[CODE]`.

**The watchdog during a rollback.** Every row below that quits Access, moves a data folder or reinstalls
starts with **`Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'`** (if the task exists), then
Quit; `(Get-ScheduledTask -TaskName 'MonClub Access Watchdog' -ErrorAction SilentlyContinue).State`
prints `Disabled` or nothing. On the night it is already off (C1, D1), but a task that is on starts
Access again within minutes of a Quit, in the middle of the row. A previous installer (≤ 1.4.33) has
no watchdog box: it leaves the task, and the check script in `%LOCALAPPDATA%\MonClubAccess\watchdog\`,
exactly as they are `[CODE: git show access_1.4.33:installer/MonClubAccess.iss -- no watchdog line]`.
Whichever row ends the night, finish with **F-end** below the table.

**A held turnstile and a rollback** (fifth round, the Erase wizard; sixth round, what a reinstall really
does to it):
- **Where the hold lives.** In the erasing PC's data folder only: a `device_write_hold` row in
  `%ProgramData%\MonClub Access\access\access.db`, beside the erase backups in
  `%ProgramData%\MonClub Access\access\erase_backups\` `[CODE: app/core/utils.py::ACCESS_DATA_DIR,
  ::ACCESS_DB_PATH -- %LOCALAPPDATA%\MonClub Access only when ProgramData cannot be written; db.py
  device_write_hold; erase_wizard.py::_default_backup_root]`. No other PC and no server knows of it
  (guide §3.2h). A hold whose erase started (its row reads `erase`) survives every restart and power
  cut, and **only « Remplir » releases it -- online** (the server checks the password)
  `[CODE: device_hold.release is called only by the run's own end and by EraseWizard.refill; a start
  releases only rows at erase-prep, db.py::release_unstarted_erase_holds]`.
- **What a reinstall does to it.**
  - The **same new version** run over the install replaces only the program folder
    (`%LOCALAPPDATA%\MonClubAccess\current`, `installer/MonClubAccess.iss::PrepareToInstall`) and keeps
    the data folder: the hold, the records and the backups stay, and the same build honours the hold
    `[CODE]`. It answers "already installed … Nothing will be changed" unless `current` is renamed
    first -- the repair of autostart checklist §6, never tried on a gym PC `[UNVERIFIED]`.
  - An **older version** run over the install keeps the same data folder but has no hold code: its
    first pass refills the held turnstile, with membership pins whatever the dashboard says (every tag
    up to 1.4.33 ignores « Par personne »), and whether it even runs on a database the new version
    migrated is `[UNVERIFIED]` (gym 45 plan D2). **Never.**
  - The **uninstaller** deletes the whole data folder: the hold, the records and the backups
    (`installer/MonClubAccess.iss` `[UninstallDelete]`) `[CODE]`. **Never.**
  - The rows below that go back to a previous version **move the whole data folder aside first**
    (renamed, kept) and copy back the copy taken before the new Access (A3, or C2 only when A7 was
    done at C3c; D3): the hold and the
    backups leave with the moved folder, and that old copy holds no hold for the old version to ignore.
    **They may run on the held PC**, as each row says (the dashboard back on « Par abonnement », the
    cables as the row says). Never copy the moved folder back over a running Access.
- **Otherwise, press « Remplir », or finish the scheme switch, before rolling back** to a build without
  lane 1 (the wizard) that keeps the current data folder -- it would ignore the hold.
- **P1 does not start while a turnstile is held** (C8's or D8's restart, C13's or D15's; P1 ran the erase,
  so this is a new failure): call the developer first, with `%TEMP%\MonClubAccess.log` and the newest file
  of `%ProgramData%\MonClub Access\data\logs\`. What would make a start fail after a good run is
  `[UNKNOWN]` here; the developer picks one of:
  1. **the same version repaired** over the install (autostart checklist §6: `current` renamed to
     `current_broken`, the release installer with "Keep MonClub Access running" and "Launch MonClub
     Access" unticked) -- the hold, the records and the backups stay; then the restart proven (C13's
     box -- at C8 / D8, before any switch, its `App started` line only has to be later than the previous
     one) and P1's Devices page still shows « Remplir » on the held turnstiles, as C8 / D8 check; the
     night goes on at the step after the one whose restart failed (C8's: C9; D8's: D9; C13's: C13b; D15's: D15b);
  2. **gym 58, with other PCs started at C10 and their restarts proven at C13:** they are not held
     (the hold binds P1's database only) -- plug the cables in (C14): they refill both panels under
     « Par personne » while P1 stays off; once P1 is fixed, its « Remplir » makes it write every member
     once more (harmless) `[CODE: device_hold; erase_wizard.py::EraseWizard.refill]`;
  3. **the row "does not start -- after the erase"** below (the folder moved aside, the pre-install
     copy, the previous version, the dashboard back on « Par abonnement ») -- at gym 45 the only way
     back while P1 is the only PC.
  Until one of them works, the turnstile stays empty: at opening, the arm fallback above.
- A **held** turnstile is never handed to another PC (H3) -- the night has no drivers anyway.

| Gym | Point reached | Back to a working door |
|---|---|---|
| 58 | **The new Access does not start -- before the erase** (A7 / C3c, or P1 at C6's 1.) | Nothing was erased: the panels still hold everyone. First `Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'` (if it exists) and Quit Access if it runs. **A PC that has run the new Access since a survey-evening A7** (P1 at C6's 1., for one): call the developer first -- it started then, so this is a new failure -- and try the same-version repair of autostart checklist §6 (`%LOCALAPPDATA%\MonClubAccess\current` renamed to `current_broken`, the release installer over the install, "Keep MonClub Access running" and "Launch MonClub Access" unticked): it keeps the data folder; if Access then starts and A7's checks pass, the night can go on (C6 from 1.) within the go/no-go clock. **Otherwise, or at A7 / C3c themselves, back to the old Access:** move the failed `%ProgramData%\MonClub Access` folder aside (rename it, keep it for the developer), copy back **that PC's copy taken before A7** -- **A3** when A7 was done on a survey evening; **C2 only when A7 was done tonight at C3c** (C2 is taken on the night: after a survey-evening A7 it holds the new version's database, and an older version is never run on a database the new one migrated, above) -- run that PC's **previous** installer (B4) over it with "Launch" unticked, start Access. It works as before on "Par abonnement"; what the new Access recorded since A7 and had not uploaded (door history, offline creations) is only in the moved folder: keep it. Gym 58 waits until the developer has fixed it (C5 is a no; at C6's 1., C6's stop: every PC quit at C1 started again, then F-end) |
| 58 | **The new Access does not start -- after the erase** (C10, a PC other than P1; or P1's restart at C8 or C13) | It started once at A7, so this is a new failure: call the developer first. **On P1 while a panel shows « Remplir » (held):** the note above, "P1 does not start while a turnstile is held" -- this row is its option 3 and may run on P1 (it moves the data folder aside with the hold and the backups); the developer picks. To go back: keep the cables out; `Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'` (if it exists) and Quit Access if it runs; move the failed folder aside; copy back **that PC's copy taken before A7** (A3, or C2 when A7 was done at C3c: the old version's own database) and run its previous installer (B4); dashboard still "Par abonnement" (C12 not saved; if saved, set it back -- then every other PC that runs the new Access shows `PIN_SCHEME_SWITCH … previous=ACCOUNT scheme=MEMBERSHIP` and its restart proven (C13's box) before the cables go in, or stays Quit, watchdog disabled first); cables in, start Access: it re-sends every member missing from the panel by itself (next row). What the new Access recorded since A7 and had not uploaded (door history, offline creations) is only in the moved folder: keep it. Whether the old version runs cleanly again is `[UNVERIFIED]` |
| 58 | Erase started, switch not recorded on any PC | Dashboard still "Par abonnement" (set it back if C12 was saved; if a PC already logged the switch, use the next row). On P1: **« Remplir »** on that panel (its hold panel reads « Par abonnement »; a run that ended « Incomplet » kept the hold, and « Remplir » writes every member again). Cables in, start Access on the other PCs: they re-send every member missing from the panel by themselves (the line that does it is in every release checked, 1.4.19 to 1.4.33, and in the new one). Wait for `to_sync=0 stale=0`. If members are still refused: "Réinitialisation complète" |
| 58 | "Par personne" recorded, refill failing -- **the cables still out** (found at C13 / C13b, before C14; sixth round) | Nothing was written to the panels since C6's erase: **no erase again**. Dashboard: that panel back to **"Par abonnement"** (the dashboard asks "J'ai effacé le terminal — basculer": true, the panel is empty since C6). On every running PC wait for `PIN_SCHEME_SWITCH … previous=ACCOUNT scheme=MEMBERSHIP` in its log, then restart it and prove it (C13's box). On P1, a panel that still shows « Remplir »: « Remplir » (it must read « Par abonnement »; it needs the internet -- row "Held, and « Remplir » cannot check the password"). Cables in; wait for `to_sync=0 stale=0` |
| 58 | "Par personne" recorded, refill failing -- **the cables in** (C14 or later: the panel holds account PINs) | The panel is erased again: a « Par abonnement » pass removes account PINs only within the removal ceiling, max(10, 25 % of the roster), and refuses above it (`REVOKE_ABORTED`, guide §3.2g). On every PC but P1: `Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'` (if it exists), then Quit Access; on P1, erase the panel again with the wizard (as C6, « Attendre que j'appuie sur « Remplir » »); **cables out**; set it back to **"Par abonnement"** (the dashboard asks "J'ai effacé le terminal — basculer"); start Access on each PC and wait for `PIN_SCHEME_SWITCH … previous=ACCOUNT scheme=MEMBERSHIP` in its log; restart each and prove it (C13's box); on P1 « Remplir » (it must read « Par abonnement »); cables in; wait for `to_sync=0 stale=0`. Plugging in earlier writes account PINs back onto the panel. **The wizard refuses that erase** when the refill it would need cannot run -- judged under the scheme recorded **now** (« Par personne » here), and for « Attendre… » under « Par personne » as well `[CODE at aa015e5: erase_wizard.py::EraseWizard._refill_check, ::_refill_refusal, called by start() before anything is held]`: « La liste des membres n'est pas récente » -- wait for the next sync, read step 1 again (as C6); anyone « sans numéro de compte » (`REFILL_WITHHELD`) -- the next row; any other refusal: C6's STOP column |
| 58 | ... and the wizard refuses anyone « sans numéro de compte » | They are the members C13b / C15 warned about (`PIN_SCHEME_ACCOUNT_WITHHELD`): the refill wrote everyone else. **Keeping the refill is often better than this row**: those members enter at the desk (« Ouvrir ») until the developer gives them their account number in MonClub, and the next successful sync writes them (gym 45 plan E11's fail column) -- you decide, with the developer. Rolling back anyway, the only order the wizard accepts is **the switch back first, then an erase with « Remplir maintenant »**: under « Par abonnement » nobody is withheld, while « Attendre… » is still checked under « Par personne » and refused for the same rows `[CODE: _refill_refusal]`. Never run on a panel `[UNVERIFIED]`: 1. Cables out. 2. Dashboard: back to « Par abonnement » (its « J'ai effacé le terminal » is confirmed here before the erase, which follows at 5.). 3. On every running PC: the switch line, then its restart proven (C13's box) -- every database now says « Par abonnement ». 4. On every PC but P1: `Disable-ScheduledTask …` (if it exists), Quit. Cables in: P1 alone writes the members' membership PINs beside the account PINs still on the panel -- a full pass, not measured; wait for its `[DeviceSync] Device id=… device_pins=…` line (the wizard's reads wait behind it). A `REVOKE_ABORTED` line for this panel is **expected here** (the account PINs are above the removal ceiling, row above; the pass goes on without removing them) -- not C14's STOP: go on to 5. 5. On P1, the wizard as C6 but with **« Remplir maintenant »**: step 1's list of people the refill will not put back names every member written under « Par personne » (by account number) -- expected here: they come back under their membership number; tick it. That backup is then kept for good although it holds only members MonClub has: tell the developer (E5). 6. « Terminé »: the hold is released and a second full pass asked; wait for `to_sync=0 stale=0`, then start the other PCs |
| 58 | Only one panel failed | Treat that panel alone, the other stays on "Par personne" |
| 45 | **The new Access does not start -- before the erase** (D6's install or first start, fifth round) | Nothing was erased: the terminals still hold everyone. `Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'` (if it exists) and Quit Access if it runs; move the failed `%ProgramData%\MonClub Access` folder aside (keep it for the developer); copy back P1's **D3 copy**; run its previous installer (B4) over it, "Launch" unticked; start Access: it works as before on "Par abonnement". Gym 45 waits until the developer has fixed it |
| 45 | **The new Access does not start -- after the erase** (P1's restart at D8 or D15, or a PC started at D11) | Call the developer first (a new failure: P1 ran the erase). **On P1 while a terminal shows « Remplir » (held):** the note above, "P1 does not start while a turnstile is held" -- this row is its option 3, the only one at gym 45 when the same version cannot be repaired, and it may run on P1: it moves the data folder aside with the hold and the backups. The terminals are erased; the dashboard may still be "Par abonnement" (D13 not reached) -- if D13 saved "Par personne", set it back (the old version ignores it anyway: every tag up to 1.4.33 writes membership PINs). Keep the cables out. On that PC: `Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'` (if it exists) and Quit Access if it runs; move the failed `%ProgramData%\MonClub Access` folder aside (keep it); copy back its **D3 copy** (the whole folder); run its previous installer (B4), "Launch" unticked. That old database believes every old member is still on the terminal, so a plain start pushes nobody: start Access behind the interlock, wait for `getSyncData OK`, press **"Réinitialisation complète"**, then plug in -- it re-pushes every member under "Par abonnement" (plan §6 R2; 1.4.33 has the button: `git show access_1.4.33:app/api/local_access_api_v2.py::_handle_sync_hard_reset` → `clear_all_device_sync_hashes` `[CODE]`; 1.4.32 was never tagged `[UNVERIFIED]`). Done when an export compared with `--scheme MEMBERSHIP` shows every member on the terminal (plan R2's E12 check; the old release's log lines may differ from E11's `[UNVERIFIED]`). The old system's users are gone for good (the goal). No previous installer for that PC (B4): this row is not possible -- G |
| 45 | Every other row | **First, with the wizard (fifth round): on P1 a held terminal takes no push until « Remplir »** -- a « Réinitialisation complète » does not release the hold (`local_access_api_v2.py::_handle_sync_hard_reset` clears hashes and tokens only; guide §3.2h) `[CODE]`. So every plan §6 row that pushes (R2's « Réinitialisation complète », R3's start behind the interlock, R4's re-push) starts -- **when that terminal still shows « Remplir » on P1** (after D15b it does not: the hold is gone) -- with **« Remplir » on that terminal**, reading the scheme the dashboard records now (« Par abonnement » after a switch back); R4's "wipe again (E5-E6)" and R6's "script 13 again" mean the wizard again, with « Attendre que j'appuie sur « Remplir » », then « Remplir » -- **except when the wizard refuses anyone « sans numéro de compte »** while « Par personne » is recorded (sixth round, `REFILL_WITHHELD` at START): then **keep the refill** at gym 45: those members enter at the desk until the developer gives them their account number (gym 58's row "... and the wizard refuses anyone « sans numéro de compte »", its first half). Its switch-back-first erase is **not written for an MB2000**: a second roster written beside the account users can fill the terminal's fingerprint slots (2023 of 3000 used on 2026-09-06, plan §1; what does not fit stays pending with `CAPACITY_FULL`, `ultra_engine._capacity_admit`), the account PINs give `REVOKE_ABORTED`, the log lines differ (`ZKEM_PUSH_DONE`, not `[DeviceSync]`) and the kept backup holds every member's fingerprints for good -- only with the developer on the phone. A « …pas récente » refusal: wait for the next sync, read step 1 again. A D6 that ended « Incomplet » kept the hold and marked every member of P1 to be written again: « Remplir » (reading « Par abonnement ») writes everyone back. Then gym 45 plan §6, rows R1-R8, with the proven restart (C13's box) before every plug-in. A fresh data folder (D10 (c)) counts as "retired": rows R3 and R4 apply to the fresh database as written. Do not rename the old folder back after an erase and simply start: it believes every old member is still on the terminal and would push nobody -- only the row above, with "Réinitialisation complète", uses the old folder |
| 58, 45 | **Held, and « Remplir » cannot check the password** (sixth round; C13b, D15b: « Pas d'Internet : le serveur MonClub doit vérifier le mot de passe… » `ADMIN_PASSWORD_UNCHECKABLE`, « Le serveur MonClub n'a pas pu vérifier le mot de passe… » `ADMIN_PASSWORD_CHECK_FAILED`, « Ce PC n'est pas connecté à MonClub… » `PC_NOT_SIGNED_IN`) | After an erase only « Remplir » releases the hold, and « Remplir » needs the server to check the administrator password -- no offline way (owner decision: online only) `[CODE: erase_wizard.py::EraseWizard.refill → _password_refusal; local_access_api_v2.py::_erase_password_verifier]`. Nothing is lost while you wait: the hold, P1's records and the erase backup stay, across restarts and power cuts. 1. **Wait for the connection, the turnstile left empty** (gym 58: nobody on the panels; gym 45: the terminal's administrators only -- members are refused by card and finger): check P1's internet (open a web page on it) and press « Remplir » again every few minutes. `PC_NOT_SIGNED_IN` (the PC lost its gym login, or the server refused it -- with this release a refused gym login reads this, not « Mot de passe incorrect », seventh round): call the developer. **« Mot de passe incorrect » while you are sure of the password** (the server refused the password; with a production backend that answers a refused gym login otherwise than backend main does, `[UNVERIFIED]`, it could also read so): P1's newest log must show a recent `getSyncData OK` -- none: as `PC_NOT_SIGNED_IN`; one: it is the password -- the person who holds it (the bag). Nobody deploys or restarts the MonClub backend meanwhile (B2c). 2. **Gym 58 only, when other PCs were started at C10 and their restarts proven at C13:** they are not held -- plug the cables in (C14) and they refill both panels under « Par personne »; P1 stays held and writes nothing until its « Remplir » works, then writes every member once more (harmless) `[CODE: the hold is P1's database only]`. 3. **At opening, if « Remplir » still cannot run** (and 2. did not refill): your fallback -- the turnstile arm dropped by hand (free passage), a staff member at each turnstile, until « Remplir » works and the door tests pass (above; G question 12). Never uninstall, reinstall an older version or copy a data folder back to get round it (the note above). Once « Remplir » works: C14 / D16 as written |

**F-end -- whichever row ends the night** (fourth round, 2026-09-27). The rows above end with "start
Access"; none of them gives autostart back. A data folder copied back (A3, C2, D3) was copied **after**
A1 / C1 / D1 unticked "Ouvrir MonClub Access avec Windows", and a fresh one (D10 (c)) starts from the
default -- off (`start_on_system_startup`, default `False`, `app/core/config.py`); and at every start
Access **deletes** its start-up entry while that box is off (`app/ui/app.py::_sync_startup_registration`)
`[CODE]`. Left like that, the first power cut leaves the PC without Access. So, once the doors work, on
**every PC that runs Access at the end of the night**:
1. Re-tick **"Ouvrir MonClub Access avec Windows"** (Config page).
2. The watchdog back on, as part C's box "Turning the watchdog back on" says -- by what exists now: a
   task (the old one, or A7's): `Enable-ScheduledTask`; none and the PC should have one:
   `register_watchdog.ps1`. Its `State` must read `Ready`, then `NextRunTime` a date.
3. Gym 45, P1: **resume Windows Update** (D1 paused it).
4. Write on the sheet (autostart checklist): box ticked, task state, `NextRunTime`.

**And once for the gym** (seventh round, master review F0): **the Erase wizard's switch OFF** (part B,
« Switching the wizard OFF »: reload, read; ON → click, reload, read OFF; already OFF → do not click).
A night that ends here plans no erase at that gym any more -- a turnstile left held for another day is
released by « Remplir », which the switch never blocks, and that day turns the switch ON again (B2c).
Left ON, anyone with the administrator password could erase a live turnstile of that gym until its
48 h run out (A7's reason).

**Not** on a PC that must stay stopped: a PC blocked or unplugged at C1b / D1, or one a row keeps Quit
(D14) -- it keeps the box unticked and the watchdog disabled until it is brought back by its own step
(C1b, gym 45 plan §5.3), which ends with this same step. The next evening, E6 proves one power cycle.

## G. Only you can answer

The ten questions of the first round, then the ones the second and third rounds add. The owner page of
2026-09-26 ("Cutover Night, Round 2") numbers them differently: its 1-10 are 1-10 here; its 11-15 are
12-16 here; its 16-22 split question 11 (gym 45 plan D2, D5, D7, D8, D10, D11, D13). The third round
widens 16 (page 15) and adds 17 (not on the page yet).

1. Which Access version is the release, and who ticks its checklist (release checklist)?
2. Gym 58's panel erase: a tool in the release, or the ZKTeco software (gym 58 plan E1)? Or does gym 58 wait, and the night is gym 45 only? **Answered 2026-09-27:** an "Erase content" wizard in Access, for C3-400 and MB2000 (release checklist §3a; on `master` since lane 1c's merge `aa015e5`, lane 1d merged as `c89e80d`, lane 1e on `claude/cutover-final-polish`), behind a per-gym server switch you turn on (B2c) and off after the night (E7).
3. Gym 45's retire: release action, SQL by a technician, or a fresh data folder (D10)? **Answered 2026-09-27:** the wizard's "forget records" option (release checklist §3b), inside D6 on P1; a PC that did not run the erase and runs tonight: D10 (b) or (c).
4. Gym 58's PCs: how many, which one drives the panels (runs Access tonight -- not a driver set in the dashboard, part H), and does each come back tonight (plan E3)? Each one that does not is blocked or unplugged (C1b), whatever its version, until it is brought back as C1b says.
5. Gym 58's QR rescue setting: on or off? The 12 September copy says off but QR entries were allowed every day (plan E2).
6. Survey evenings before the night: yes / no, and when (A)? At gym 58, when is the new Access pre-installed (A7): that evening, so it runs for days on "Par abonnement" (recommended), or on the night (C3c)?
7. Gym 45 without a soak and without re-enrolment beforehand (N1, N2): accepted?
8. The latest erase start at each gym (C, N3), knowing that a failed refill needs the rollback time with the cables out (F), none of it measured; and how late each gym may open.
9. Power left on all night at both gyms: arranged with whom?
10. The technician on site and the developer on call.
11. The things the gym 45 plan already asks you (D1-D13), especially D2 (the PCs not reinstalled: keep the firewall block for good -- their "Ouvrir" button then stops working -- or bring them back later by plan §5.3), D5 (terminal admins), D7 (biometric backups), D8 (anyone with the gym login can flip the PIN setting).
12. **The turnstile arm.** At each turnstile of both gyms (gym 58 doors 1 and 2, gym 45 "Entrée" and "Sortie"): how is the arm dropped (key, lever, a tool?), and which staff members know how? And on the night, if the refill is not proven at opening time, the proposed fallback is to open with the arms dropped and a staff member at each turnstile: you confirm it then, or the gym stays closed.
13. **The previous installers** (B4): which version does each PC run today (A1), and where is each installer? "Accueil Oxyfit" (DESKTOP-6UCRVSG) runs 1.4.32, never tagged: without its installer that PC has no rollback if the new Access does not start there.
14. **The cards MonClub already holds** (A6): a member whose panel card differs from the card in MonClub, or whose MonClub card starts with `99999`: the desk does not change MonClub; who decides when that member comes to the desk, and what does `99999` mean in your gyms?
15. **An administrator login** on each PC that gets the firewall block (C1b, D1): who has them, and are they in the bag?
16. **The server / dashboard settings** that decide whether the gym 58 pre-install (A7) is as harmless as the old Access: is protocol 2 (`monclub.access.v2.enabled`) on in production, and is any gym 58 panel's QR roster check set to "enforce"? (Release checklist §5.) **And the commands switch** (`MONCLUB_ACCESS_V2_COMMANDS_ENABLED`, part H): do you agree to leave it -- and protocol 2 -- unchanged from A7 until the night is verified, and to keep the commands switch off until then (recommended, H6)? The day you turn them on, both together (release checklist §5a).
17. **Driver PCs after the night** (part H3): no driver is set at gym 45 or gym 58 before the night is verified -- agreed? And when you set them later, each turnstile's driver is a PC that ran tonight's refill (gym 45: P1; gym 58: one of the PCs started at C10), so the members it pushed stay removable when they leave -- agreed, or which PC do you want? Know that the first driver at a gym is one-way: the dashboard cannot take it back, and revoking the driver PC leaves its turnstile with no PC at all (H3).

## H. Driver PCs, readers and the server switches (P3b-2) -- the third round

Read on Access `master` `aeeef69` (P3b-2 merged as `318fb3d`) and backend `main` `919231a8` (read
only), 2026-09-26. Nothing was run on a gym, a device or a production server. In parts A-G, "the PC
that drives the panels" and "P1, the driving PC" mean the PC that runs Access tonight -- never a
driver set in the dashboard.

### H1. Who connects to each turnstile tonight

| The PC runs | It connects to | Evidence |
|---|---|---|
| An old Access (1.4.33 or older, the untagged 1.4.32 included) | every turnstile of its gym, always: it has no driver code | `git ls-tree access_1.4.33 app/core/v2` lists nothing `[CODE]`; 1.4.32 has no tag to read (`git tag -l access_1.4.32` is empty), so for it this is `[UNVERIFIED]` |
| The new Access, the server's commands switch **off** | every turnstile of its gym | every v2 route answers 404 `NOT_FOUND`; the PC reads it as "switched off" and allows every turnstile (`app/core/v2/leases.py::LeaseManager.refresh`, `lease_gate.py` mode `ALL`) `[CODE]` `[TEST: test_v2_runtime.py::test_an_old_server_keeps_everything_dormant]` |
| The new Access, the switch **on**, no driver set at the gym | every turnstile of its gym (« Tous les tourniquets (sans affectation) ») | `lease_gate.snapshot_from_assignment`: `gymUsesAssignments` false → mode `ALL` `[CODE]`; the server makes it true as soon as the gym has one driver row (`AccessAssignmentQueryService.GymSnapshot.usesAssignments`) `[CODE, backend]` |
| The new Access, the switch on, **a driver set for any turnstile of the gym** | only the turnstiles it drives; a PC without a driver lease connects to **none** | `lease_gate.LeaseSnapshot.allows`, checked at every place the PC connects (guide §3.9) `[CODE]` `[TEST: test_v2_lease_gate.py]` |
| The new Access, the server not reachable | what its cached roles say; with no cache, every turnstile | `app/ui/app.py` installs the cache before the first sync tick (`runtime.py::load_cached_roles`); an error keeps what is installed (`LeaseManager.refresh`) `[CODE]` |
| Any PC whose panel / terminal cable is out, or behind the firewall block | nothing | unchanged |

**Production today.** The commands switch is `false` unless the server is started with it
(`application.yml`: `${MONCLUB_ACCESS_V2_COMMANDS_ENABLED:false}`), and the backend's CI passes no
`MONCLUB_ACCESS_*` variable to its `docker run` `[CODE, backend main 919231a8, .gitlab-ci.yml]`. That is
the pipeline, not the running server: which build runs in production, and with what, cannot be
read from anywhere (gym 45 plan §3.2) `[UNVERIFIED]` -- the page check (H4) reads the answer on each PC. A driver cannot be created while the
switch is off (`AccessLeaseService` exists only with it on), and with it on every gym's driver screen
stays locked until `MONCLUB_ACCESS_V2_ASSIGNMENT_MIN_ACCESS_VERSION` is set, every ACTIVE PC of the gym
reports that version, **and** someone pressed « Confirmer qu'aucun poste non enregistré ne tourne ici »
for that gym (`AccessAssignmentLock.evaluate`; dashboard `src/locales/fr/access-assignment.ts`)
`[CODE, backend and dashboard main]`. Once set, a driver is not removed again from the dashboard (H3).

**Tonight**, with no driver set, every running new-Access PC connects to both devices of its gym --
like the old Access, and as every step of parts A-F assumes.

### H2. With drivers or without: without

The night runs **without drivers** at gym 45 and gym 58, from A7 until the night is verified (E):
nobody sets a driver there, and nobody presses « Confirmer qu'aucun poste non enregistré ne tourne
ici » for these two gyms before then. B2b's 404 `NOT_FOUND` proves it at the server from the laptop, and the page check (H4) at A7, C10, D11 and after each proven restart proves it on each PC.
Why, from the code:
1. **A driver is not an interlock.** Only the new Access obeys it, and only from what the server last
   said: a PC with no cached roles connects to every turnstile until the server answers, and the v2
   part starts 12 s after launch (`access/runtime.py::schedule_access_shell_startup`). A fresh data
   folder (D10 (c)) leaves the cached roles and the PC's identity file behind, in the renamed
   folder, so the new one starts with neither (`v2_kv` in `access\access.db`, `access\pc_identity.dat`: `app/core/v2/store.py`,
   `access/pc_identity.py::PcCredentialStore`, `app/core/utils.py::ACCESS_DATA_DIR`) `[CODE]`. The
   cables and the firewall blocks stay the interlock.
2. **A new driver writes "add-only".** Until it has restored the server's ownership record for its
   lease (and, after a forced move, re-read the whole turnstile), it pushes but removes nobody
   (`lease_gate.py`, `leases.py::LeaseManager._not_restored`) `[CODE]`; the restore is refused while
   the server's record is of the other pin scheme (`ownership.py::OwnershipSync.restore`,
   `PIN_SCHEME_MISMATCH`) `[CODE]`; on an MB2000 the re-read is one listing with no door service
   while it runs, never timed on ~1,860 users (guide §3.9) `[UNVERIFIED — FIELD-TEST]`.
3. **None of P3b-2's six field tests has been run** (the live link through production, a reader's
   door request over the internet, the handover on the MB2000 and on a C3, the re-add of a deleted
   member, a power-on without internet -- P3b-2 report); what a C3 panel does with two PC sessions at
   once is `[UNKNOWN]` (guide §3.9).
4. **A reader's « Ouvrir » goes through the server to the driver:** it needs the internet and the
   driver PC on, opens for 3 s whatever the favourite says, and the screen says only that the request
   went to the driver (« Demande envoyée au PC pilote. Son résultat n'est pas visible ici. », or that
   it will expire without opening when the driver is not connected), never that the door opened
   (`local_api_routes.py::_door_request_via_driver`, `v2/handlers.py::CommandHandlers.door_open`,
   `tauri-ui/src/api/realtime.ts::doorRequestedMessage`) `[CODE]`.
   Not something to learn on the night.

### H3. Drivers after the night (G, question 17)

- With the commands switch off, nothing the PCs push tonight reaches the server's ownership record:
  the v2 part uploads nothing unless the server answers "on" (`runtime.py::V2Runtime.tick` stops
  before its extensions) `[CODE]`. Each PC keeps its own proof in its database.
- Once the switch is on, in a gym **still without drivers**, each running new-Access PC uploads its
  record (its first upload sends every fact it has not sent before, then the changes every 5 min;
  state rows older than the device's latest pin-scheme switch are left out), and the server takes it from
  any ACTIVE PC of the gym (`ownership.py::OwnershipSync.tick`, `::_drivable`, `::build_rows`;
  backend `AccessOwnershipService.upload` / `.restore`) `[CODE]`. Never run against production
  `[UNVERIFIED]`.
- A driver set later restores that record and keeps its own proof (`OwnershipSync.restore`: "this
  PC's own proof wins") `[CODE]`. A member its driver did not push, and that no upload holds, is never
  removed by that driver when the member leaves (guide §3.9, residual; P3b-2 report, "Members pushed
  before the gym used drivers") `[CODE]`.
- **A driver cannot be taken back.** Once a gym has one driver row -- even a released one -- the
  server treats it as a gym with drivers for good (`AccessAssignmentQueryService`: every lease row
  of a turnstile the gym still has, whatever its state; `GymSnapshot.usesAssignments` is
  `!leaseByDevice.isEmpty()`), and the dashboard can only move a turnstile to another PC, never back
  to "no driver" (`AccessLeaseService.validateChanges` refuses a change with no PC,
  `CHANGES_INVALID`) `[CODE, backend]`. Revoking the driver PC leaves that turnstile with no PC at
  all (`AccessLeaseService.releaseByRevoke`) `[CODE, backend]`. On the PCs the only way back to
  "every PC connects" is the server's commands switch off -- for every gym, with a backend restart
  (`LeaseManager.refresh` on the 404) `[CODE]`; how long that takes is `[UNVERIFIED]`. The first
  driver at a gym is a one-way step: a quiet day, never the night.
- So: drivers only after the night is verified, after the switch has been on while the PCs that ran
  tonight were running; and each turnstile's driver is a PC that ran tonight's refill (gym 45: P1;
  gym 58: one of the PCs started at C10) -- that covers it even if an upload is missing.
- **A held turnstile moves only after Refill** (fourth round, 2026-09-27; for the days with drivers --
  the night has none). **Rule: press Refill, or finish the scheme switch, BEFORE moving a turnstile that
  is held to another PC. Never force-handover a turnstile held on its PC, and never revoke the PC that
  holds it before Refill** (a revoke ends a pending move too, `releaseByRevoke`; what the server does
  with that turnstile after it was not read here `[UNVERIFIED]`). Why: the Erase wizard's hold
  lives on that one PC only, and a new driver would refill the turnstile under its own recorded scheme;
  so the held PC does not release its lease while the hold is on -- the handover waits for Refill
  (`app/core/v2/ownership.py::OwnershipSync.release` sends no release while `_worker_idle` is false, and
  `_worker_idle` is false for a held turnstile, `device_hold.is_held`) `[CODE, on master since lane 1's
  merge af54f0d; unchanged at e5e3328, aa015e5 and on claude/cutover-runbook-pass]`. The server never
  moves a turnstile on a timer: a pending move waits for the old PC's release, and only the owner's
  force-handover (dashboard) or a revoke ends it earlier (`AccessLeaseService`: `completeForced` is
  reached only from `forceHandover` and a `setDrivers(…, force=true)` owner change, `releaseByRevoke` only
  from the revoke hook; no scheduled job in the v2 access services) `[CODE, backend local main
  63d053b3, read 2026-09-27; what production runs is UNVERIFIED]`. A forced move of a held turnstile
  would hand an erased (or half-erased) turnstile to a PC that knows nothing of the hold.

### H4. The page check (A7, C10, D11, E3, and the restart box of part C)

On each running PC, the new Access's **« Pilote / Lecteur »** page (main menu); press « Actualiser ».
« Rôle de ce PC », and the line under it:

| It reads | Under it | Meaning |
|---|---|---|
| « Inconnu » | « Serveur sans v2 (fonctionnement habituel) » | commands switch off: every turnstile. **Expected reading 1** |
| « Tous les tourniquets (sans affectation) » | « Serveur v2 actif » | switch on, no driver: every turnstile. **Expected reading 2** -- then H5's rules apply |
| « Inconnu », or « Tous les tourniquets (sans affectation) » (an answer cached while the switch was on earlier) | « Pas encore démarré » (the first 12 s) or « Serveur injoignable pour l'instant (rôles du cache local) » | **not yet a proof**: the PC connects to every turnstile for now, but it has not heard the server, and a driver set there would reach it later and stop it in the middle of a refill. It asks 12 s after each start, then 2, 4, 8, 16 and 30 min after each failure; a PC registered after its start (A7, D10 (c)) has no identity at its 12 s question (`runtime.py::V2Runtime.refresh_assignment`, `api.py` `NO_PC_TOKEN`) `[CODE]`. Wait and press « Actualiser », or Quit and start Access again; still this after a restart: call the developer before any plug-in |
| « PC pilote », « PC lecteur », « REVOKED » | anything | **a driver is set at this gym: STOP** (the step's STOP column) |

`[CODE: tauri-ui/src/pages/RealtimePage.tsx AVAILABILITY_FR; tauri-ui/src/api/realtime.ts ROLE_LABEL_FR;
access/v2_routes.py::_handle_v2_status]`. The page exists only in a release whose shell was rebuilt
(release checklist §2). The log says the same, at INFO: `[V2] server v2 availability: UNKNOWN -> OFF`,
or `-> ON` with no `[V2] roles` STOP line after it, is the server's answer that makes a reading
expected (`runtime.py::V2Runtime._set_availability`);
a line containing `[V2] roles` whose part after `->` or after `role=` names `LEASED`, `DRIVER`,
`READER` or `REVOKED` is the STOP (`runtime.py::V2Runtime._on_lease_change`,
`leases.py::LeaseManager.load_cache`) `[CODE]`.

**The developer's rule for « Serveur injoignable » that does not go away.** The PC counts only the
backend's own 404 `NOT_FOUND` as "switched off"; any other answer -- a proxy page, another
envelope -- leaves it at « Serveur injoignable » for good (`api.py::V2ApiError.switched_off`,
`runtime.py::V2Runtime._set_availability` keeps the old state on UNREACHABLE) `[CODE]`. If B2b
answered the backend's 404 `NOT_FOUND` the same evening, the commands switch is off at the server:
no driver can be made (`AccessLeaseService` exists only with the switch on) `[CODE, backend]`. And
the PC in question reads « Inconnu » (or a cached « Tous les tourniquets »): it connects to every
turnstile, and while the switch is off no server answer can give it a driver or reader role --
only a 2xx assignment answer installs one (`LeaseManager.refresh`) `[CODE]` -- as long as nobody
changes the switch before E (H6): the developer may then let that PC plug in, and writes
down why. Without that B2b answer, the PC is not plugged in.

### H5. What the commands switch changes tonight

**Off:** nothing. The v2 part is dormant: no live link, no remote command, nothing uploaded, a new
question to the server every 30 min (guide §3.9) `[CODE]`.

**On, with no driver** (the steps stay the same; these rules are added):
- **A live link** to the server (`wss://…/api/v1/public/access/v2/pc/ws`). Through the production
  web server it has never been tried (P3b-2 field test 1) `[UNVERIFIED — FIELD-TEST]`. The door path
  does not use it (guide §3.9a).
- **Remote commands.** The PC runs the commands the server hands it -- a door open, a card scan, an
  enrolment, a resync, a turnstile reconcile, an audit, a log upload, a confirm removal -- with the
  desk's own code (`app/core/v2/handlers.py::CommandHandlers.table`) `[CODE]`; in a gym without drivers
  the server accepts only a command that names the PC (`LeaseAwareTargetResolver` →
  `ExplicitTargetResolver`, `TARGET_PC_REQUIRED`) `[CODE, backend]`. **Rule: nobody sends remote commands to a gym 45 or
  gym 58 PC from C1 / D1 until E.**
- **Problem reports.** Each running PC reports its turnstiles' problems (`REVOKE_ABORTED` with its
  list, `SKIPPED_NOT_OWNED`, `CAPACITY_FULL`, `TEMPLATE_VERSION_MISMATCH`, `MISSING_OWNED`) once its
  removal step has run (`app/core/v2/reports.py`) `[CODE]`. The dashboard offers « Confirmer la
  suppression » on a `REVOKE_ABORTED` list; pressed, it lets the PC remove that exact list once
  (guide §3.9) `[CODE]`. **Rule: never press it tonight** (E3) -- the list is the developer's to read.
- **Ownership uploads** every 5 min, with no connection to any device (H3). **After an erase, the
  dashboard's member card can be stale while P1 is offline** (seventh round, master review C2): the
  server's record of a turnstile changes generation only when P1 reports the wipe, and until then a
  member's « Sur le tourniquet » there can stay green -- the card has no check that the PC is online
  before that line `[CODE: backend main f1482fd1 AccessMemberOwnershipService reads the current
  generation; dashboard main cf24e77e member-turnstile-truth.ts, today's mode]`. P1 reports the wipe
  first, at its first v2 tick once online, before any upload `[CODE: app/core/v2/ownership.py::
  OwnershipSync.tick calls report_wipes before its uploads]`. So while P1 is offline after an erase (part
  F, "Held, and « Remplir » cannot check the password"), nobody answers a member from that card.
- **More syncs.** A dashboard change to a device -- the "Par personne" save of C12 / D13 included --
  sends the PCs a notice, and each asks for a sync 1-10 s later, at most one such sync a minute
  (`runtime.py::V2Runtime.on_changed`, `::schedule_sync`; backend `AccessNoticeEntityListener`)
  `[CODE]`. A successful sync refreshes the running workers, but the restart after the switch stays
  the proof (C13's box), switch on or off.
- **The missing-member re-add** does nothing to an erased device: a listing that shows none of
  MonClub's pins changes nothing and reports nothing -- on the MB2000
  (`app/core/v2/loss.py::evaluate_listing`) and on a C3 panel (`device_sync.py::_sync_one_device`,
  the report only when `_owned & device_pins`) `[CODE]`.

### H6. Does any step need a switch on or off?

- **No step needs the commands switch on, and none needs it off**: with no driver set, parts A-F read
  the same either way; with it on, H5's two rules are added (no remote commands, no « Confirmer la
  suppression »).
- **Neither switch changes between A7 and E.** A7 is where gym 58 first meets the new Access; the
  night must see the state A7 was checked under. Protocol 2 already follows this rule (A7, point 5);
  the commands switch now does too.
- **Recommended: the commands switch stays off until the night is verified** -- fewer moving parts,
  and the live link through production has never been tried. Turning it on is its own day, both
  switches together, after the backend's CI can pass them at all (release checklist §5a). G, question 16.
- **The interlock and the start-up push are unchanged.** With no driver, every running PC pushes at
  start-up as before (`manual_sync_mode` off: gym 45 plan §1, gym 58 plan §1), and nothing connects
  while the cables are out or the block is on, whatever its role. With drivers, only the driver would
  push -- not tonight.

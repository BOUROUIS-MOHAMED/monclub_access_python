# Release checklist -- the Access build for the cutover night

For the master session, at release time. Tick each box with the command's output, in the release's
own notes. The night ([`2026-09-26_cutover_night_runbook.md`](2026-09-26_cutover_night_runbook.md))
does not start until every **MUST** is ticked and every **DECIDE** has an answer. Second round
2026-09-26 (`dbf865f`): the worker refresh, the C3 erase tool and the watchdog item are MUST (§3a).
Third round 2026-09-26 (`aeeef69`): P3b-2 is on `master` (§1a), the release gates of §2, the server
switches (§5a), and the open items as of `aeeef69` (§3). Fourth round 2026-09-27 (branch
`claude/installer-watchdog-fix` on `master` `d3725fa`): the owner's installer / watchdog edits committed
and the watchdog MUST built on that branch (§2, §3a), the erase wizard and the retire method decided
(§3a, §3b), the merged lanes (§4).

Written 2026-09-26 against `master` `22c9cfc`; updated the same day against `master` `aeeef69`
(P3b-2 merged as `318fb3d`, the db-writer test fix merged as `aeeef69`). `X.Y.Z` below is the release
version. Replace it before running a command. **It cannot be `1.4.34`** (§2, the version gate).

## 1. MUST contain (checked with `git merge-base --is-ancestor <commit> access_X.Y.Z`, exit code 0)

| ✓ | Commit | What it gives the night |
|---|---|---|
| ☐ | `30c3b93` | the per-device `pinScheme` gate (an account pin only on a device set to ACCOUNT) -- backend doc `access-account-pin-minimum.md` names this commit |
| ☐ | `2eafb5f` | the recorded pinScheme switch (`[T] PIN_SCHEME_SWITCH`, the history door events are read by) -- idem |
| ☐ | `ca1e29a` | P3a-2: write-ahead ownership, the one removal ceiling, the MB2000 capacity and template-version checks, 50 pins per pass, the finger-slot sweep (gym 45 plan §3.1) |
| ☐ | `3b28bd2` | P3b-1: protocol 2, power-on date flips, QR days, renewal ordering (merge) |
| ☐ | `d9c86b2` | the one-shot credentials re-send, and a failing migration stops start-up (merge) |
| ☐ | `a94c064` | the R6-01 test fix, so the suite is green on a PC booted less than 83 minutes ago (merge) -- the gym 45 plan's step A2 note is stale once this is in |
| ☐ | `fe8a248` | a never-seen card is not in cooldown right after boot, and `monotonic_s=` on "App started" (merge) -- the autostart test reads it |
| ☐ | `5137ed1` | the test suite never touches the installed Access data (merge) |
| ☐ | `2f6b96e` | the round-2 tools (`tools/c3_panel_scripts/`, `tools/gym45_cutover/`: the card self-check, the per-device card rule, failed counts recorded) and the round-2 runbook -- on `master` since the fast-forward to `2f6b96e` (2026-09-26). Not in the installer: copied by hand (runbook, the bag) |
| ☐ | `318fb3d` | P3b-2 (merge of `claude/p3b2-realtime-leases` `1d0599b`): see §1a. Not needed by the night, but on `master`: the release carries it, dormant or in "every turnstile" mode (§1a, runbook part H) |
| ☐ | `aeeef69` | the db-writer test fix (`52b423d`, test only): `test_db_hot_path_writer.py::test_db_writer_serializes_concurrent_write_jobs` no longer races. **Closes the flaky-test item of the second round** |

Shortcut: all of the above are on `master` at `aeeef69`; `git merge-base --is-ancestor aeeef69
access_X.Y.Z` covers every row, the round-2 tools included (they were on a separate branch in the
second round; they are merged now).

### 1a. P3b-2 in the release -- what it changes for the night

The 20 commits of `claude/p3b2-realtime-leases`, merged by `318fb3d` (guide §3.9, §3.9a; owner
report https://claude.ai/artifact/LwWWoAdgzkF6TKH4P7gvYm):

| Kind | Commits |
|---|---|
| Features | `a3f5996` server clock and the v2 PC HTTP client · `937058c` one lease gate at every place the PC connects to a turnstile · `db4680a` notice socket, WebSocket client, lease manager · `a90dcff` remote command executor and the v2 runtime · `079f38f` ownership backup, add-only leases, problem reports, Confirm removal, loss re-add · `33de04a` the « Pilote / Lecteur » page, reader requests, per-turnstile enrol status |
| Fixes | `505b5f0` · `fd7df88` · `c86fe65` · `36c38a7` · `fe2134a` · `b0e194d` · `e24673a` · `5a9cd73` · `55e8377` · `0f3643a` · `0cbf26d` (review rounds 1-7) |
| Docs | `e266699` · `d705065` · `1d0599b` (guide §3.9, §3.9a) |

For the night, in plain words:

- **With the server's commands switch off -- expected in production** (the backend's CI passes no
  `MONCLUB_ACCESS_*` variable to `docker run`, `.gitlab-ci.yml`, backend `main` `919231a8`
  `[CODE]` -- since lane A, backend `7b383b52`, only those set in GitLab, §4; the running server's state is `[UNVERIFIED]` -- the runbook's page check reads it): every v2 route answers 404 `NOT_FOUND`, the PC reads it as "switched off", allows every
  turnstile, opens no socket, uploads nothing, and asks again every 30 min
  `[CODE: leases.py::LeaseManager.refresh, runtime.py::V2Runtime.refresh_assignment]`
  `[TEST: test_v2_runtime.py::test_an_old_server_keeps_everything_dormant; e2e 5/5 with the switch off, guide §3.9]`.
  Every running PC connects to every turnstile, as the runbook was written.
- **With the commands switch on and no driver set at the gym:** still every turnstile
  (`lease_gate.snapshot_from_assignment`: `gymUsesAssignments` false → mode `ALL`) `[CODE]`. The socket,
  remote commands, ownership uploads and problem reports run (runbook part H says what that means
  on the night).
- **With a driver set for any turnstile of the gym:** a PC without a lease connects to none of them
  `[CODE: lease_gate.LeaseSnapshot.allows]`. The runbook does not cover that: no driver at gym 45 or
  58 from A7 until the night is verified (runbook part H).
- The door path is unchanged in time (scan → decision median 230-232 ms before and after, guide §3.9a)
  `[TEST: measurement, development PC]`. A new start-up step loads cached roles before the first sync
  tick (none cached → every turnstile) and the v2 runtime starts 12 s after launch
  (`app.py` `load_cached_roles`, `access/runtime.py::schedule_access_shell_startup`) `[CODE]`.
- P3b-2 does **not** refresh the running workers on a `pinScheme` fast patch: the restart after the
  switch stays (§3a, runbook C13's box) `[CODE: app/ui/app.py::apply_fast_patch_bundle -- its
  GYM_DEVICE branch calls _request_running_ultra_sync, never refresh_devices; guide §3.2e]`.

## 2. MUST pass on the release commit

| ✓ | Check | Expected |
|---|---|---|
| ☐ | `python -m pytest tests/ -q --ignore=tests/_pydeps` (with `MONCLUB_ACCESS_DATA_ROOT` pointed at an empty temp folder), **on the release commit itself** | 0 failed. Reference: **2914 passed, 0 failed** on `master` `318fb3d` (P3b-2 merged; guide §9). `aeeef69` changes one test only: `52b423d` ran it 50/50 alone and its full suite at 2656 passed on its own base (commit message); the full suite was **not** re-run on `aeeef69` itself |
| ☐ | `python tools/check_sql_arity.py` on the release commit | PASS |
| ☐ | **The version gate.** `X.Y.Z` is higher than any version a production PC has ever reported. `update.json`, `tauri.conf.json`, `Cargo.toml` and `package.json` have said `1.4.34` since `eeae1ed` (2026-09-13, "release: MonClub Access and TV 1.4.34 shells"), and no tag `access_1.4.34` exists `[CODE: git tag]`: every build made from `master` since then reports `1.4.34`. Whether any was installed on a gym PC is `[UNKNOWN]` (untagged builds do reach gyms: "Accueil Oxyfit" runs 1.4.32, never tagged, gym 45 plan §1). Check the version column of "Postes de réception" (/access-pcs) for every gym | no PC anywhere reports `X.Y.Z` or higher. Why: both server minimums (§5a) compare the version the PC reports; an older build reporting the same number would pass the pin-scheme gate and the assignment lock |
| ☐ | The version in the installer, `update.json` and the Tauri files is `X.Y.Z` (`packaging/sync_tauri_version_files.py`, `tests/test_tauri_version_sync.py`) | the three agree |
| ☐ | **The Tauri shell is rebuilt**, not only the Python part. P3b-2 changed `tauri-ui/src-tauri/src/lib.rs` (tray menu, global favourite shortcuts) and the pages bundled into the shell (`RealtimePage.tsx` « Pilote / Lecteur », `DevicesPage.tsx`, `TrayPanelPage.tsx`, `FavoritesOverlayPage.tsx`, `EnrollPage.tsx`) `[CODE: git diff --stat 2f6b96e 318fb3d -- tauri-ui]`. The pages are compiled into the shell (`tauri-ui/src-tauri/tauri.conf.json`: `"frontendDist": "../dist"`), and `build_release.ps1 -SkipTauriBuild` reuses an already staged shell `[CODE]`: a release built that way keeps the old tray and shortcut messages (P3b-2 report) and has no « Pilote / Lecteur » page -- which the runbook's A7 / C10 / D11 check reads | the installed shell shows the « Pilote / Lecteur » menu entry |
| ☐ | The installer is built after the owner's own installer / watchdog edits are committed -- never over them. **Committed 2026-09-27 as `b30ef60`** on branch `claude/installer-watchdog-fix` (his four files, reviewed, unchanged; not merged when this was written). ISCC compiles the files on disk, not the commit (`installer/MonClubAccess.iss` `[Files]` `Source: "..\packaging\watchdog\…"`) `[CODE]`, so the build checkout must hold nothing uncommitted there | `git merge-base --is-ancestor b30ef60 access_X.Y.Z` exits 0, and on the build checkout `git status --short -- installer packaging` prints nothing |
| ☐ | The tag `access_X.Y.Z` exists and is published, so the PCs and the owner's USB key get the same file | the download URL works |
| ☐ | **Only after all of the above:** the server minimum is set to exactly `X.Y.Z` (backend doc: one-line commit + deploy, or `MONCLUB_ACCOUNT_PIN_MIN_ACCESS_VERSION` added to the CI's `docker run`, then a restart); its start-up log shows it at INFO | runbook B2 |

## 3. New code the night needs -- open on `aeeef69`

Written for a later code task. Lane B (`claude/v2-safety-sync`, the only session that changed `app/`) is
**merged into `master` on 2026-09-27**: the first row below is built (tick it on the release commit, as it
says). The watchdog row is built on branch `claude/installer-watchdog-fix` (2026-09-27), not merged, not
released. The erase row is now the "Erase content" wizard, being built by lane 1 -- not merged. Do not tick a
row on anyone's word -- tick it on the merged commit and its test.

### 3a. MUST

| ✓ | Item | Needed for | If not built |
|---|---|---|---|
| ☐ | **BUILT 2026-09-26 on branch `claude/v2-safety-sync`, commit `f23df50` (lane B; merged into master 2026-09-27, not released). Tick with `git merge-base --is-ancestor e70b177 access_X.Y.Z` -- the last commit that changed its code, so the review fixes are in (`87f0995`: no PullSDK removal before the re-check, no device without a worker for the scheduler, a copy refreshed while the lease is away; `e70b177`: the enrolment refresh, the scheduler list kept); a release carrying `f23df50` alone lacks them.** What it does: the workers get the database's device rows before a `GYM_DEVICE` fast patch (or `requiresDeviceRescope`) queues a pass, and right after each sync save that refreshed devices; and every push pass (MB2000 and PullSDK, full and targeted) refuses to write pins of a scheme the database no longer records, at pass start, before the push and between chunks (`[T] PIN_SCHEME_PASS_STOPPED`). Residual: the MB2000 chunk in flight when the switch lands (≤ 10 members), a PullSDK removal step or user batch already started. **Not covered (as on `aeeef69`):** a sync answer the server built just before the switch and saved just after it writes the old scheme back into the database, and the workers follow it (guide §3.2e, review R3-F1) -- the cables-out interlock and the proven restart cover it; proposed for runbook C13: after the restart, no `PIN_SCHEME_SWITCH previous=ACCOUNT scheme=MEMBERSHIP` line follows the switch. Tests: `tests/test_pin_scheme_worker_refresh.py` (16 of its 19 red on `aeeef69`); guide §3.2e. The restart below stays. The original item, as written: **Refresh the running ULTRA workers on an applied `GYM_DEVICE` fast-patch item.** In `app/ui/app.py::apply_fast_patch_bundle`, when a `GYM_DEVICE` item was applied, call `self._ultra_engine.refresh_devices(list_sync_devices_payload())` (`app/core/db.py::list_sync_devices_payload`) **before** `_request_running_ultra_sync` queues the pass. Today the fast patch records and logs the switch (`db._insert_device_row`) but queues a full pass on the workers' old device copy (`_request_running_ultra_sync` only calls `request_sync_now`; the drain copies `self._device` at drain time, `ultra_engine._drain_full_sync_commands`), and that pass survives a disconnect (`ultra_engine.py`, the re-queue while the link is down) `[CODE, review 2026-09-26]`. Test: a `pinScheme` MEMBERSHIP→ACCOUNT fast patch on a running engine never pushes a pin derived under the old scheme, connected or reconnecting. Guide §3.2e updated | both gyms | the three guards of today stay the only ones: the interlock (cables out until the restart), a successful server sync (it refreshes the workers: the device's `updatedAt` changes the `devicesVersion`, review 2026-09-26), and the restart proven three ways (runbook C13, D15, gym 45 plan E10b). Keep the restart even when this is built |
| ☐ | **"Erase content" wizard in Access, for C3-400 panels AND MB2000 terminals** -- **owner decision 2026-09-27** (runbook G question 2), replacing the C3 panel erase tool this row asked for (gym 58 plan §3.1, E1 (a)). Being built by lane 1 on branch `claude/erase-wizard-and-v2-gaps`: **in progress, not merged, not reviewed here** -- how it works is that branch's to say, not this checklist's. Tick it on its merged commit and its test, like every row. For whoever checks it at gym 58, the tool row's requirements, verbatim as written 2026-09-26 for a separate tool (the wizard runs inside Access, so the first point and the "refuses" point do not carry over as written): "32-bit PowerShell next to the export; clears `user`, `userauthorize`, `templatev10`, `template` with `DeleteDeviceData(h, table, "", "")` and nothing else (never `transaction`, `timezone`, `holiday`, parameters); refuses while `MonClubAccess.exe` runs; prints the counts before and after (`GetDeviceDataCount`; a negative answer is an error, never a count, as the export now does); asks for the panel's IP typed in full as confirmation; logs every call; a test against a fake DLL like `tests/test_c3_panel_export_readonly.py`, plus a static check that no other write entry point is declared." The runbook still names "the erase tool of the release" (C6) and script 13 for gym 45 (D6): it is re-read once the wizard is merged | gym 58 (gym 45's MB2000 have script 13 today, runbook D6) | gym 58: the ZKTeco software (untested here, gym 58 plan E1 (b)), or gym 58 waits -- a decision for the night, not a default. Gym 45: script 13 as the runbook says |
| ☐ | **The installer must not switch a disabled watchdog back on.** **BUILT 2026-09-27 on branch `claude/installer-watchdog-fix`, commit `c0391d4` -- not merged, not released.** Tick with `git merge-base --is-ancestor c0391d4 access_X.Y.Z`. The defect, as on `master` `d3725fa`: with the box ticked at the previous install, `UsePreviousTasks=yes` ticks it again and the `[Run]` entry runs `register_watchdog.ps1`, which removed the task and registered a new, **enabled** one `[CODE]`. The fix: the script reads the task's state before removing it; a task that was **disabled** is registered again with the current definition but disabled (`Settings.Enabled = $false`), read back, disabled explicitly if it came back enabled, and the script throws if it still is not; it prints `State: Disabled (kept)`. No task, or an enabled one: registered enabled, as before `[CODE: packaging/watchdog/register_watchdog.ps1]` `[TEST: tests/test_watchdog_script.py::TestRegisterKeepsADisabledTaskDisabled -- the shipped script under Windows PowerShell 5.1, the Task Scheduler stubbed; 3 of its 6 fail on the owner's script before the fix]`. **Not run:** what Windows' Task Scheduler itself does with `Settings.Enabled = $false` `[UNVERIFIED]` -- the read-back covers it, and the runbook's check (C3c, D9) shows it. Also on that commit, the owner's default (2026-09-26): the box is **ticked for a new install**, an existing install keeps its previous choice, and one whose version predates the box gets it unticked (§3b) | both gyms | the runbook's untick and check (C3c, D9) are the only guard. **They stay in the runbook either way**, as the second guard: this commit protects only the installs made with a release that contains it |

### 3b. DECIDE

| ✓ | Item | Needed for | If not built |
|---|---|---|---|
| ☐ | **Gym 45 "retire" method** (gym 45 plan D3) -- **DECIDED by the owner 2026-09-27** (runbook G question 3): the "Erase content" wizard's **"forget records"** option (§3a, lane 1, `claude/erase-wizard-and-v2-gaps`, in progress, not merged) -- the release's own action, i.e. (a) below. Tick it on the merged commit and its test; until then, and if it is not in the release, the runbook's D10 (b) or (c) stay the way. How the option works is that branch's to say; what (a) asked for, as written 2026-09-26, for whoever checks it: (a) an action in the release -- per device, only after a verified wipe, only with the ULTRA engine not started (a command-line mode that exits), refuses a device with push intents or rows written after the last recorded switch; deletes that device's `device_sync_state`, `device_push_intent`, `device_content_mirror` rows; never `device_pin_scheme_switch`, `device_pin_scheme_seen`, `access_history`, `member_account_link`; guide §3.2e updated -- or (b) SQL by a technician, or (c) a fresh data folder. With P3b-2 a fresh folder (c) also leaves the cached driver/reader roles and the PC's identity file behind in the renamed folder (both under `%ProgramData%\MonClub Access\access\`: `v2_kv` in `access.db`, `pc_identity.dat`) `[CODE: app/core/v2/store.py, access/pc_identity.py::PcCredentialStore, app/core/utils.py::ACCESS_DATA_DIR]` -- harmless while gym 45 has no driver (runbook part H) | gym 45 | the runbook's D10 (b) or (c) |
| ☐ | The installer's "Launch MonClub Access" stays ticked by default; the runbook unticks it by hand. **The watchdog default -- DECIDED 2026-09-26, BUILT 2026-09-27** on `claude/installer-watchdog-fix` (`c0391d4`, not merged): "Keep MonClub Access running" is **ticked for a new install** (no Inno uninstall record and no installed files, `MonClubAccess.iss::IsFreshInstall`); an existing install keeps its previous choice (`UsePreviousTasks=yes`); an install whose version predates the box -- every tagged release: no `access_*` tag contains `a85014c`, the commit that added it `[CODE: git tag --contains a85014c]`; untagged builds since 2026-09-11 carry it, and whether one reached a gym is `[UNKNOWN]` (§2) -- gets it **unticked**, so no update, the silent in-app one included, adds a startup entry by itself. Not `checkedonce`: Inno Setup's own code unticks a previously ticked `checkedonce` task (`Setup.WizardForm.pas::CreateTaskButtons`, tag `is-6_5_4`) `[CODE]`. The installer compiles with it (ISCC 6.5.4, `TestInstallerWatchdogTask::test_the_installer_compiles`) `[TEST]`; the task page on a real install is `[UNVERIFIED]`. The runbook still unticks the box at every install of the night (C3c, D9) | -- | -- |

## 4. Other sessions

| ✓ | Item | Check |
|---|---|---|
| ☐ | **P3b-2 is merged** (`318fb3d`). The runbook and both gym plans were re-read against it in the third round (runbook part H): nothing in the night changes as long as no driver is set at gym 45 or 58 and the rules of part H are kept | `git merge-base --is-ancestor 318fb3d access_X.Y.Z`, and runbook part H read by whoever runs the night |
| ☐ | **Lane B** (Access `claude/v2-safety-sync`: the worker refresh of §3a, the safety sync, gating the 45 s probe and the 22:00 job, the missing-member check). **Merged into Access `master` as `804f4d2`** (2026-09-27; branch tip `90e5aca`; its §3a MUST row is ticked with `e70b177`, as that row says). It is in the release: re-read the runbook's restart box (C13), C14-C15 and D16 against its guide changes (§3.2e, §3.6, §3.9) | `git merge-base --is-ancestor 804f4d2 access_X.Y.Z` exits 0, then the diff of `guide_for_agents_and_dev.md` since `aeeef69` |
| ☐ | **Lane A** (backend `claude/v2-ownership-route-and-switches`). **Merged into backend `main`** (merge `73dbf6ba`; `main` at `7b383b52` when this was written, 2026-09-27). Among its commits, `1ef2854f`: the deploy job passes each of the four switches of §5a to `docker run` **only when its GitLab CI/CD variable is set**, refuses a value other than `true`/`false` (switches) or digits and dots (versions) before touching the server, and prints `Access switches passed to the container: …` (`.gitlab-ci.yml`) `[CODE]`. Merged is not deployed: whether a deploy has run since, and which GitLab variables are set, is `[UNVERIFIED]` -- read in the deploy job's log, not here | the last deploy job's log line `Access switches passed to the container:` -- `none, the application.yml defaults apply` means every switch is at its default (§5a) |
| ☐ | Any other branch merged after `aeeef69`: read its guide changes for §3.2 (pins), §3.2g (removal ceiling), §3.4 (push), §3.8 (dates), §3.9 (leases, commands). Merged since: `d31a0e8` (the cutover docs after P3b-2), `804f4d2` (lane B, above), **`d3725fa`** (`claude/ownership-removed-cutoff`: a removal logged before the pin-scheme switch is not uploaded under the new scheme; guide §3.9). Not merged when this was written: `claude/installer-watchdog-fix` (§2, §3a), `claude/erase-wizard-and-v2-gaps` (lane 1, §3a) | `git merge-base --is-ancestor d3725fa access_X.Y.Z` exits 0; the diff of `guide_for_agents_and_dev.md` since `aeeef69` |

## 5. Backend and dashboard in production (the night's STOP rules read them)

| ✓ | Item | How to know |
|---|---|---|
| ☐ | The pin-scheme gate and the minimum-version setting are deployed (backend `main` `c7d4b532` or later) | the turnstile page of the dashboard shows the verdict sentence (runbook B3); a production build number cannot be read from anywhere (gym 45 plan §3.2) |
| ☐ | `pinScheme` and `mainAccountId` reach the PC | gym 45 plan gate G2 on a copy of the PC's `access.db` after the upgrade |
| ☐ | Protocol 2 (`monclub.access.v2.enabled`) | NOT required: with it off the server answers v1 and the PC behaves as before (guide §3.8). A separate decision -- but **know its state before gym 58's pre-install** (runbook A7, point 5): with it on, the new Access removes members outside their dates and refuses QR codes on days not allowed from its first start, and a return to the old Access becomes risky |
| ☐ | The QR roster check of gym 58's panels (`deviceCapabilities.totpRosterCheckMode`) | "trial" (the default: it never refuses). "enforce" refuses the QR codes of members not on the PC's list from the pre-install on (runbook A7, point 5) |
| ☐ | The commands switch and the drivers (§5a) | NOT required by the night. Its state is the same from A7 to the night's verification, and **no turnstile of gym 45 or 58 has a driver** (runbook part H; checked at the server by runbook B2b's 404 `NOT_FOUND` and on each PC at A7, C10, D11) |

### 5a. The server switches (backend `main` `919231a8`, read-only)

Four settings, all blank or `false` by default, none passed by the CI as of backend `main` `919231a8`.
Since lane A was merged (backend `main` `7b383b52`), the CI passes each one only when its GitLab variable is
set; which are set, and whether that build is deployed, is `[UNVERIFIED]` (§4, lane A):

| Environment variable (property) | What it turns on | Default | Grade |
|---|---|---|---|
| `MONCLUB_ACCESS_V2_ENABLED` (`monclub.access.v2.enabled`) | **the dates**: sync protocol 2 (validity windows, off-days, upcoming members) on the member sync; P3b-1 on the PC | `false` | `[CODE: application.yml; GymAccessController @Value]` |
| `MONCLUB_ACCESS_V2_COMMANDS_ENABLED` (`monclub.access.v2.commands.enabled`) | **the socket, remote commands, driver leases, ownership backup, problem reports** -- the P2b/P2c controllers and services are `@ConditionalOnProperty` on it (`AccessV2PcController`, `AccessV2DashboardController`, `AccessLeaseService`, `AccessAssignmentQueryService`, `AccessNoticeEntityListener`, among others); off, every `/access/v2/pc/**` route is unmapped (404 `NOT_FOUND`) | `false` | `[CODE: AccessV2Properties.Commands and those classes' annotations]` |
| `MONCLUB_ACCESS_V2_ASSIGNMENT_MIN_ACCESS_VERSION` (`monclub.access.v2.assignment.min-access-version`) | the **assignment lock**: a gym's driver screen opens only when this is set, the gym has at least one ACTIVE PC, every ACTIVE PC reports this version or later, **and** the owner has confirmed that no unregistered PC runs there. Blank = every gym locked. Read only while the commands switch is on | blank | `[CODE: AccessAssignmentLock.evaluate]` |
| `MONCLUB_ACCOUNT_PIN_MIN_ACCESS_VERSION` (`monclub.access.account-pin.min-version`) | the **pin-scheme gate**: "Par personne" is accepted on a device only when every ACTIVE PC of the gym reports this version or later (revoked PCs are left out). Blank = ACCOUNT refused everywhere. Runbook B2 | blank | `[CODE: AccessPinSchemeGateService]` |

How they combine:
- The two v2 switches are **independent**: either can be on without the other `[TEST: backend
  AccessV2PropertiesBindingTest]`.
- **The sister-gym QR row follows the commands switch only.** The QR credential row created
  (disabled) at sale time for a sister-gym plan is made by `SisterGymCredentialPrecreator`, which is
  `@ConditionalOnProperty(name = "monclub.access.v2.commands.enabled", havingValue = "true")` -- not
  the dates switch `[CODE]`. With the dates on and the commands off, a sister-gym plan sold meanwhile
  gets no pre-created row. So the owner default for the switch-on day is **turn both on together**.
- A driver lease can only be created while the commands switch is on (`AccessLeaseService` is
  conditional on it), and `gymUsesAssignments` is true as soon as the gym has one lease row
  (`AccessAssignmentQueryService.GymSnapshot.usesAssignments`) `[CODE]`. On the PC, that is the moment
  every PC without a lease becomes a reader (runbook part H). **It is one-way:** the gym stays
  "with drivers" whatever state its lease rows are in, a change must name a PC
  (`AccessLeaseService.validateChanges`, `CHANGES_INVALID`), and on the PC only the commands switch
  off brings back "every turnstile" `[CODE]` (runbook H3).
- The two minimum-version settings are separate and both read the version the PC reports -- hence the
  version gate of §2.
- The night needs only `MONCLUB_ACCOUNT_PIN_MIN_ACCESS_VERSION` (runbook B2). The other three are the
  switch-on plan, a separate day (runbook part H, G question 16).

# Release checklist -- the Access build for the cutover night

For the master session, at release time. Tick each box with the command's output, in the release's
own notes. The night ([`2026-09-26_cutover_night_runbook.md`](2026-09-26_cutover_night_runbook.md))
does not start until every **MUST** is ticked and every **DECIDE** has an answer. Second round
2026-09-26 (`dbf865f`): the worker refresh, the C3 erase tool and the watchdog item are MUST (§3a).

Written 2026-09-26 against `master` `22c9cfc`. `X.Y.Z` below is the release version (`update.json`
says `1.4.34` "Mango" today). Replace it before running a command.

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
| ☐ | `tools/c3_panel_scripts/` and `tools/gym45_cutover/` as of `claude/cutover-runbook-round2` (the card self-check, the per-device card rule, failed counts recorded) | the surveys and the night's checks; not in the installer, copied by hand (runbook, the bag) |

Shortcut: all of the above are on `master` at `22c9cfc`; `git merge-base --is-ancestor 22c9cfc access_X.Y.Z`
covers the eight commits (not the round-2 tools, which are on `claude/cutover-runbook-round2`, not merged).

## 2. MUST pass on the release commit

| ✓ | Check | Expected |
|---|---|---|
| ☐ | `python -m pytest tests/ -q --ignore=tests/_pydeps` (with `MONCLUB_ACCESS_DATA_ROOT` pointed at an empty temp folder) | 0 failed (2656 passed on `master` `dbf865f`, 2026-09-26; guide §9) |
| ☐ | `python tools/check_sql_arity.py` | PASS |
| ☐ | The installer is built after the owner's own installer / watchdog edits are committed -- never over them | the owner says so |
| ☐ | The version in the installer, `update.json` and the Tauri files is `X.Y.Z` (`packaging/sync_tauri_version_files.py`, `tests/test_tauri_version_sync.py`) | the three agree |
| ☐ | The tag `access_X.Y.Z` exists and is published, so the PCs and the owner's USB key get the same file | the download URL works |
| ☐ | **Only after all of the above:** the server minimum is set to exactly `X.Y.Z` (backend doc: one-line commit + deploy, or `MONCLUB_ACCOUNT_PIN_MIN_ACCESS_VERSION` added to the CI's `docker run`, then a restart); its start-up log shows it at INFO | runbook B2 |

## 3. New code the night needs (none of it exists on `dbf865f`)

Written for a later code task; nothing below is built on this branch.

### 3a. MUST

| ✓ | Item | Needed for | If not built |
|---|---|---|---|
| ☐ | **Refresh the running ULTRA workers on an applied `GYM_DEVICE` fast-patch item.** In `app/ui/app.py::apply_fast_patch_bundle`, when a `GYM_DEVICE` item was applied, call `self._ultra_engine.refresh_devices(list_sync_devices_payload())` (`app/core/db.py::list_sync_devices_payload`) **before** `_request_running_ultra_sync` queues the pass. Today the fast patch records and logs the switch (`db._insert_device_row`) but queues a full pass on the workers' old device copy (`_request_running_ultra_sync` only calls `request_sync_now`; the drain copies `self._device` at drain time, `ultra_engine._drain_full_sync_commands`), and that pass survives a disconnect (`ultra_engine.py`, the re-queue while the link is down) `[CODE, review 2026-09-26]`. Test: a `pinScheme` MEMBERSHIP→ACCOUNT fast patch on a running engine never pushes a pin derived under the old scheme, connected or reconnecting. Guide §3.2e updated | both gyms | the three guards of today stay the only ones: the interlock (cables out until the restart), a successful server sync (it refreshes the workers: the device's `updatedAt` changes the `devicesVersion`, review 2026-09-26), and the restart proven three ways (runbook C13, D15, gym 45 plan E10b). Keep the restart even when this is built |
| ☐ | **C3 panel erase tool** (gym 58 plan §3.1, E1 (a)): 32-bit PowerShell next to the export; clears `user`, `userauthorize`, `templatev10`, `template` with `DeleteDeviceData(h, table, "", "")` and nothing else (never `transaction`, `timezone`, `holiday`, parameters); refuses while `MonClubAccess.exe` runs; prints the counts before and after (`GetDeviceDataCount`; a negative answer is an error, never a count, as the export now does); asks for the panel's IP typed in full as confirmation; logs every call; a test against a fake DLL like `tests/test_c3_panel_export_readonly.py`, plus a static check that no other write entry point is declared. **Or** the owner decides, explicitly, that gym 58 waits and the night is gym 45 only | gym 58 | the ZKTeco software (untested here, gym 58 plan E1 (b)), or gym 58 waits -- a decision for the night, not a default |
| ☐ | **The installer must not switch a disabled watchdog back on.** Today, with the box ticked at the previous install, `UsePreviousTasks=yes` ticks it again and the `[Run]` entry runs `register_watchdog.ps1`, which removes the task and registers a new, enabled one (`installer/MonClubAccess.iss`; `packaging/watchdog/register_watchdog.ps1`) `[CODE]`. Either the register script keeps a task that exists and is disabled as it is (a test for that), **or** the runbook unticks the box at every install of the night and checks the task's state -- which it now does (C3c, D9). This touches the owner's uncommitted installer / watchdog files: his decision, after his edits are committed | both gyms | the runbook's untick and check (C3c, D9) are the only guard |

### 3b. DECIDE

| ✓ | Item | Needed for | If not built |
|---|---|---|---|
| ☐ | **Gym 45 "retire" method** (gym 45 plan D3): (a) an action in the release -- per device, only after a verified wipe, only with the ULTRA engine not started (a command-line mode that exits), refuses a device with push intents or rows written after the last recorded switch; deletes that device's `device_sync_state`, `device_push_intent`, `device_content_mirror` rows; never `device_pin_scheme_switch`, `device_pin_scheme_seen`, `access_history`, `member_account_link`; guide §3.2e updated -- or (b) SQL by a technician, or (c) a fresh data folder | gym 45 | the runbook's D10 (b) or (c) |
| ☐ | The installer's "Launch MonClub Access" stays ticked by default; the runbook unticks it by hand. The watchdog default changes later (owner decision, after his installer edits) | -- | -- |

## 4. Other sessions

| ✓ | Item | Check |
|---|---|---|
| ☐ | **P3b-2** (`claude/p3b2-realtime-leases`, no commit beyond `master` on 2026-09-26). If it is in the release, re-read the runbook against it before the night: who connects to each turnstile (today every PC connects to every device, `GymAccessController`, `UltraEngine`), the interlock (cables or firewall until each PC has recorded its switch), and the start-up push (`manual_sync_mode` off → Access pushes at start-up) | `git log master..access_X.Y.Z --oneline` lists no P3b-2 commit, or the re-read is done |
| ☐ | Any other branch merged after `22c9cfc`: read its guide changes for §3.2 (pins), §3.2g (removal ceiling), §3.4 (push), §3.8 (dates) | the diff of `guide_for_agents_and_dev.md` since `22c9cfc` |

## 5. Backend and dashboard in production (the night's STOP rules read them)

| ✓ | Item | How to know |
|---|---|---|
| ☐ | The pin-scheme gate and the minimum-version setting are deployed (backend `main` `c7d4b532` or later) | the turnstile page of the dashboard shows the verdict sentence (runbook B3); a production build number cannot be read from anywhere (gym 45 plan §3.2) |
| ☐ | `pinScheme` and `mainAccountId` reach the PC | gym 45 plan gate G2 on a copy of the PC's `access.db` after the upgrade |
| ☐ | Protocol 2 (`monclub.access.v2.enabled`) | NOT required: with it off the server answers v1 and the PC behaves as before (guide §3.8). A separate decision -- but **know its state before gym 58's pre-install** (runbook A7, point 5): with it on, the new Access removes members outside their dates and refuses QR codes on days not allowed from its first start, and a return to the old Access becomes risky |
| ☐ | The QR roster check of gym 58's panels (`deviceCapabilities.totpRosterCheckMode`) | "trial" (the default: it never refuses). "enforce" refuses the QR codes of members not on the PC's list from the pre-install on (runbook A7, point 5) |

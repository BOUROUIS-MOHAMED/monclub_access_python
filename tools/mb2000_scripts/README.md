# MB2000 / zkemkeeper dev scripts

Standalone script folder for developing + testing against ZKTeco **standalone
terminals (MB2000)** and the **ZK9500** desk reader - no `.exe` build needed.
Copy this whole folder to any Windows PC, fix each script alone on real
hardware, then merge the proven calls into MonClub Access
(`app/sdk/zk_standalone.py` - every script header lists the exact SDK
signatures it uses, so a fix here maps 1:1 to the driver).

## Quick start

1. Double-click **`START HERE.cmd`** (or right-click `0_MENU.ps1` -> Run with
   PowerShell). The x86 SDK DLLs are already bundled in `sdk\` - nothing to copy.
2. First time on a PC: run **[1] Register zkemkeeper.dll** (accept the admin
   prompt). It auto-finds the bundled `sdk\zkemkeeper.dll` and verifies the COM
   object can be created.
3. Everything else in any order. Device IP/port/comm key are remembered in
   `config.json` after the first prompt.

> All scripts auto-relaunch themselves in **32-bit PowerShell** (zkemkeeper is
> x86 COM) - you can start them from any console.

## Bundled SDK DLLs (`sdk\`)

Ships the exact x86 DLL set the production MonClub Access install uses, so the
folder is self-contained - no ZKTeco software required on the PC:

- `zkemkeeper.dll` (+ its dep `plcommpro.dll`) - standalone-terminal COM SDK
- `libzkfpcsharp.dll`, `libzkfp.dll`, `fpslib.dll`, `ZKFPCap.dll` - ZK9500 capture

`_common.ps1` prepends `sdk\` to PATH so the COM object and the .NET wrapper's
native deps resolve locally. Script 1 auto-registers the bundled `zkemkeeper.dll`;
script 4 auto-loads the bundled `libzkfpcsharp.dll`. If you move the folder,
re-run **[1]** (registration records the DLL's path).

> Rare: on a PC that never had any ZKTeco software AND lacks
> `C:\Windows\SysWOW64\zkemsdk.dll`, copy that file into `sdk\` too - the verify
> step in **[1]** will tell you if it's missing.

## The scripts

| # | Script | What it does |
|---|--------|--------------|
| 0 | `0_MENU.ps1` | interactive menu + config editor |
| 1 | `1_register_zkemkeeper.ps1` | register the COM DLL (admin, once per PC) + verify |
| 2 | `2_get_member_templates.ps1` | list device users (all/search), read their templates, optional save to the local store |
| 3 | `3_get_device_info.ps1` | firmware/serial/MAC/platform, user+fingerprint+log counts, clock (+optional clock set) |
| 4 | `4_enroll_zk9500.ps1` | capture 3 samples on the ZK9500, merge, **save locally** (`templates\<pin>.json`) - needs `libzkfpcsharp.dll` x86 from the ZKFinger SDK |
| 5 | `5_push_member_to_device.ps1` | push one local member (user+card+fingers) to the device - the app's exact push sequence; a live finger match after = **template-portability PASS** |
| 6 | `6_delete_local_fingerprint.ps1` | remove a finger / member file from the local store |
| 7 | `7_delete_device_fingerprint.ps1` | delete one finger / all fingers / whole user **on the device** |
| 8 | `8_live_monitor.ps1` | live punch table (pin, FINGER/CARD, time) - polls new attendance records |
| 9 | `9_unlock_door.ps1` | ACUnlock relay test (SDK **and** wiring) |
| 10 | `10_backup_restore_device.ps1` | dump ALL users+templates to `backups\*.json` / restore (clone terminals, pre-wipe safety) |
| 11 | `11_portability_test.ps1` | **the decisive gate**: push a ZK9500 desk template then auto-watch the log 90s for a live finger match -> prints **PASS / FAIL** |
| 12 | `12_force_open_door.ps1` | **the door gate**: sustained force-open - ACUnlock repeated N times with a chosen duration/interval, device info before+after, every attempt written to `logs\force_open_*.log`. `-Auto` = no prompts (desk / scripted) |

## Local template store

`templates\<pin>.json` - shared by scripts 2/4/5/6:

```json
{ "pin": "117", "name": "Bob", "card": "8192567",
  "fingers": [ { "fingerId": 6, "template": "<base64>", "size": 1234,
                 "capturedAt": "2026-07-09T10:00:00", "source": "zk9500" } ] }
```

## Run logs

`logs\force_open_<yyyyMMdd_HHmmss>.log` - one file per script-12 run (created on
first use). Plain text, safe to email: device identity/counts, every `ACUnlock`
attempt with its return value and call duration, and the operator's answer about
the physical release.

## Typical workflows

- **Template portability test (do this before enrolling members!):**
  `4` (enroll yourself at the desk) -> `11` (auto push + 90s live-match watch ->
  PASS/FAIL). PASS = desk enrollment works. FAIL = enroll on the terminal instead,
  and the gym's onboarding workflow changes - so decide this BEFORE mass enrollment.
- **Clone terminal A to B/C:** run `10` (Backup) against A, then `10` (Restore)
  against B and C.
- **Verify-method table for the app driver:** run `8`, punch finger then card,
  note the printed verify values.
- **Door force-open / relay gate (GATE 4):** `9` fires one pulse (1 s by default)
  and asks whether the relay clicked; `12` is the one to run when the desk needs
  the door **held** open, or when a single pulse was inconclusive and you want a
  repeated, timed, logged run you can send back. See below.

## Door force-open (script 12) - reading the result

`12_force_open_door.ps1` fires `ACUnlock(machineNumber, delayDeciseconds)` - the same
call script 9 makes and the same one `app/sdk/zk_standalone.py` makes - `-Repeat`
times, `-IntervalSeconds` apart, and writes every attempt (return value, elapsed ms,
device info before and after) to a timestamped file in `logs\`. Send that file back.

| What you see | What it means | What to do |
|---|---|---|
| `ACUnlock -> TRUE` **and** the turnstile releases | **PASS** for the SDK call on this device | send the log - the guides stay `[UNVERIFIED]` on the relay until that report is in |
| `ACUnlock -> TRUE` **and nothing moves** | **wiring problem, not SDK** - the firmware accepted the command | check the relay output -> turnstile input wiring; no software change fixes this |
| `ACUnlock -> FALSE` | the firmware refused the call. This SDK reports **no reason** | send the log, and switch the door command OFF for this device (Devices page, or `MONCLUB_ZK_STANDALONE_OPEN_DOOR=0`) |
| `ACUnlock THREW` | COM/transport error, not a refusal | send the log with the exception text |

Exit codes for `-Auto`: `0` all TRUE, `1` setup/connect failure, `2` some FALSE,
`3` some call threw.

> What the script does **not** know, and does not pretend to: there is **no documented
> SDK maximum** for the delay (the `-MaxDeciseconds` ceiling of 600 is the MonClub
> Access `pulseSeconds 1..60` limit, not an SDK one); whether the delay really holds
> the relay that long; and what a second `ACUnlock` arriving before the first expires
> does. The script header spells each one out. The elapsed ms is the **COM call**, not
> the relay.

> Since 2026-09-04 MonClub Access **issues** this call by default on MB2000-class
> terminals (per-device switch on the Devices page). That is a software decision, not
> proof - this script is still what settles whether the relay releases.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `COM object not registered` | run script 1 (admin); keep the FULL sdk folder together |
| regsvr32 ok but object creation fails | missing companion DLLs beside `zkemkeeper.dll` |
| `Connect_Net FALSE` | wrong IP/port, network, or device COMM key (script menu -> C) |
| Script 4 `Add-Type failed` | wrong-bitness `libzkfpcsharp.dll` - use the **x86** one |
| Template upload returns FALSE | encoding/version mismatch - note it; that finding goes into the app driver (`_push_templates` bias / BASE64 property) |
| A COM call throws "signature" errors | that firmware differs - fix the one call in THAT script (header lists it), then port the fix to `app/sdk/zk_standalone.py` |

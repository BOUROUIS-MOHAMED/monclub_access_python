# gym 45 cutover tooling (read-only)

Two tools for the plan in [`docs/plans/2026-09-19_gym45_cutover_plan.md`](../../docs/plans/2026-09-19_gym45_cutover_plan.md).
Neither writes to a terminal or to a database.

| Tool | Runs on | Reads | Writes |
|---|---|---|---|
| [`tools/mb2000_scripts/14_export_terminal_readonly.ps1`](../mb2000_scripts/14_export_terminal_readonly.ps1) | the gym PC (32-bit PowerShell, COM already registered by the Access install) | ONE MB2000 | a JSON file in `tools/mb2000_scripts/exports/` + its `.sha256` |
| `compare_terminal_export.py` | any PC with Python 3.9+ (and `pymysql` for the backend part) | exports, a COPY of the driver PC's `access.db`, a MySQL copy of the backend | stdout; `--json-out` / `--detail-csv` files only when asked |
| `rehearsal_check.py` | a dev PC with the local `monclub-mysql8` container | the MySQL copy | a temporary synthetic export, deleted at the end |

## 1. The export (on the gym PC)

**Stop MonClub Access on every PC of the gym first** (tray icon > Quit; see the plan for the watchdog).
Whether an MB2000 accepts a second connection while Access holds one has never been tested
(`docs/plans/mb2000_zk_standalone_driver_plan.md` gate G5b) -- so it is never tried.

**Never run `1_register_zkemkeeper.ps1` on the gym PC.** Access already registered its own
`zkemkeeper.dll`; script 1 would re-point the machine-wide registration at the script pack's copy.

```powershell
# fast: users + counters + fingerprint algorithm version
.\14_export_terminal_readonly.ps1 -DeviceIp 192.168.1.247 -Label device8 -Auto
# + every user's finger slots (size and SHA-256 per slot; the slow part)
.\14_export_terminal_readonly.ps1 -DeviceIp 192.168.1.247 -Label device8 -Fingers -Auto
# + the templates themselves: a BACKUP (biometric data - keep private, delete after the cutover)
.\14_export_terminal_readonly.ps1 -DeviceIp 192.168.1.247 -Label device8 -IncludeTemplates -Auto
# time a sample first
.\14_export_terminal_readonly.ps1 -DeviceIp 192.168.1.247 -Label device8 -Fingers -MaxUsers 50 -Auto
```

Run the two terminals in two windows at the same time (each has its own connection).
The file records `timings` (`msPerFingerRead`), which is how long a full `-Fingers` read will take.

**Why it is read-only.** Every COM call it makes is one of: `SetCommPassword` (the PC side of
the COMM key), `Connect_Net`, `Disconnect`, `GetFirmwareVersion`, `GetSerialNumber`,
`GetDeviceMAC`, `GetPlatform`, `GetVendor`, `GetDeviceIP`, `GetDeviceTime`, `GetDeviceStatus`,
`GetSysOption`, `ReadAllUserID`, `SSR_GetAllUserInfo`, `GetStrCardNumber`, `SSR_GetUserTmpStr`
-- the ZKTeco standalone SDK documents all of them as reads or as the connection itself.
`tests/test_mb2000_export_readonly.py` fails the build if any other call, any write method name,
any dynamic COM invocation, or any other dot-sourced file appears in the script or in
`_common.ps1`, and it runs the SHIPPED script against a fake terminal that has only those
methods and logs each call. What the firmware does inside a read is not something a fake can
prove (`[UNVERIFIED]`, guide §7); unlike the Access driver, this script never sends
`EnableDevice`, `RegEvent` or `RefreshData`.

Unlike `10_backup_restore_device.ps1`, it records `privilege`, `enabled` and whether a password
exists (never the password). Its "template version" is the terminal-wide algorithm version
(`~ZKFPVersion`): no read on the allowlist returns a per-template version, so each slot carries its
size and SHA-256 only. The scripts connect with the COMM key saved in `config.json` (`START HERE.cmd`
→ `[C]`); if the terminal has a device password set in /gym-devices, enter it there first. A failed
connection waits for ENTER, even with `-Auto`. An `-IncludeTemplates` file has the shape script 10's Restore reads;
that Restore writes every user back as privilege 0, enabled, without a password.

## 2. The comparison (on a dev PC)

```bash
# a copy of the driver PC's access.db (copied with Access STOPPED: access.db + -wal + -shm)
python tools/gym45_cutover/compare_terminal_export.py \
    --export 8=terminal_device8_....json --export 10=terminal_device10_....json \
    --access-db copy/access.db
# add the backend: a MySQL COPY, never the live server, never wigo-db (refused by name)
# (password in the environment: bash `export MYSQL_PWD=...`, cmd `set MYSQL_PWD=...`, PowerShell `$env:MYSQL_PWD='...'`)
python tools/gym45_cutover/compare_terminal_export.py --export 8=... --export 10=... --access-db copy/access.db \
    --mysql-host 127.0.0.1 --mysql-port 3307 --mysql-db <copy> --mysql-user root --day 2026-09-19
```

The `access.db` is copied again into a temp folder and opened `PRAGMA query_only`; MySQL runs
`SET SESSION TRANSACTION READ ONLY` + `START TRANSACTION READ ONLY`, only `SELECT`s
(anything else raises before it is sent), templates are hashed INSIDE MySQL
(`SHA2(template_bytes, 256)`), and the transaction is rolled back.

What it prints (aggregates only; `--detail-csv` adds per-person rows WITH NAMES):

| Section | Means |
|---|---|
| `sha self-check` | On pins MonClub owns, the share of terminal slots holding exactly MonClub's template bytes. >= 90 % licenses matching fingers by template hash; below that it matches by finger number only (weaker: a re-scanned finger reads as covered). |
| `classes` | `member_owned` (a current member at its MonClub pin, MonClub can prove it wrote it), `member_not_owned` (a current member's pin MonClub cannot prove it wrote), `departed_owned` (MonClub's, no longer on the roster), `intent_only` (a write MonClub started, unconfirmed), `past_membership` (an old membership of the gym), `leftover` (unknown to MonClub). Without `--access-db`, `member` replaces the first two. |
| `leftovers` | How each non-member terminal user ties to a CURRENT member: `template` (a finger with MonClub's exact bytes), `gms_id` (its pin is the old-system card id MonClub imported, `migration_entity_link_gms` PERSON), `card` (same card number), `pin_is_card` (its pin equals a member's card), `name_only` (a hint, never counted as a loss). `links_agree` / `links_conflict` count users with two or more strong links. `pin_is_a_gms_card_id` measures whether the old system used the card id as its terminal pin -- `[UNVERIFIED]` until an export shows it. |
| `people` | `people_with_terminal_only_finger`: current members with a finger on a terminal that MonClub will not push -- they lose it in a wipe. `people_losing_every_finger`: those with no MonClub template at all. `terminal_only_but_template_in_monclub`: the exact template IS in MonClub but not delivered here (disabled at the gym) -- re-enabling it rescues the finger. |
| `ACCOUNT without wipe` | Account pins that would land on a user the terminal already holds (the reason the wipe comes before the switch). |

The SQL roster (used when there is no `--access-db`) replicates the date / status / plan /
permission / freeze filters of the backend; it does NOT apply the photo rule, the unpaid-due rule
or the per-gym fingerprint enrolment gate. On `wigo-demo` for 2026-09-12 it gives 919 memberships
/ 902 people, the same as an independent SQL measurement. `--access-db` is the exact roster.

## 3. The rehearsal

```bash
export MYSQL_PWD=monclub   # cmd: set MYSQL_PWD=monclub
python tools/gym45_cutover/rehearsal_check.py --mysql-host 127.0.0.1 --mysql-port 3307 \
    --mysql-db wigo-demo --mysql-user root --day 2026-09-12
```

Builds a synthetic terminal from the backend copy (every deliverable member at its pin with its
templates, 50 old-system duplicates at their GMS card ids, 40 unknown users, 12 extra fingers,
15 past memberships), runs the comparison and checks each count. Result on 2026-09-19 against
`wigo-demo` (a scrubbed, since-mutated clone of the 2026-09-12 production dump -- NOT production
numbers): all 9 checks OK.

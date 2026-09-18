# MonClub Access — Guide for Agents and Developers

**Purpose.** MonClub Access drives ZKTeco access-control hardware across more than one
SDK family. Most mistakes made in this repo — by humans and by AI agents — are not
logic errors. They are *category* errors: treating one SDK's surface as if it were the
other's, or assuming behaviour that has only ever been proven on one device model.

This file exists to prevent that. It records **only what has been proven**, and marks
what has not. `README.md` at the repo root is **stale** — it describes the original
single-purpose Tkinter tool (PullSDK + ZK9500 only) and predates modes, drivers, the
local API, and the Tauri UI. Do not use it to understand the current system.

**Three files, one source of truth.** This one is the system orientation — modes,
routing, which engine does what. The per-SDK API references are separate:

| File | Covers |
|---|---|
| **`guide_for_agents_and_dev.md`** (this file) | Modes, protocol routing, capability flags, the traps |
| [**`pullsdk_guide.md`**](pullsdk_guide.md) | `plcommpro.dll` — both classes, wire formats, ControlDevice ops, firmware quirks |
| [**`zkemkeeper_guide.md`**](zkemkeeper_guide.md) | zkemkeeper COM — STA rules, every COM call verbatim, the push sequence, the must-not-call |

They share one status-marker system and are meant to agree. **If they disagree, one is
wrong — fix it, don't work around it.**

---

## 0. The maintenance contract

This file is only useful while it is true. If you change any of the following, you
**must** update the named section here in the same change:

| If you change… | Update section |
|---|---|
| `app/sdk/device_driver.py` — protocol enum, aliases, resolution order | §4 Protocol resolution |
| A `supports_*` / capability class attribute on any driver | §5 Capability flags |
| Which engine services which `accessDataMode` | §3 The three modes |
| How a sync request is classified explicit vs automatic (`full_reconcile`) | §3.2c Reconcile reachability |
| `DeviceSyncEngine._normalize_device` allowlist | §6.2 The inert-patch rule |
| How a member becomes a device pin or a pin becomes a member (`pinScheme`, `derive_member_pin`, the collapse, revoke, push report, inbound); the `sync_users.main_account_id` cache and its forced refresh; pinScheme switches; local API handlers carrying a member or pin | §3.2b What a device PIN actually is, §3.2d, §3.2e, §3.2f |
| Anything currently marked `UNVERIFIED` that you actually prove or disprove | §7 Unverified |
| A `[T]` telemetry event name, or the fields it carries | §10 Telemetry events |
| How door-history upload verdicts are persisted, the unresolved retry bound, or its expiry (`device_attendance.py::_sync_pending_history`, `db.py::mark_access_history_unresolved`, `db.py::expire_unresolved_access_history`, `db.py::prune_access_history`) | §3.5 Door-history upload |
| The sync timer — healthy interval, failure-retry schedule, `Retry-After`, the mid-sync re-run, the offline DEVICE-reconcile gate (`app.py::reschedule_sync_timer`, `::_ensure_sync_timer`, `::_sync_base_interval_sec`, `::_on_sync_work_finished`, `::_offline_device_reconcile_due`, `::_defer_ultra_reconnects`, `::request_sync_now`, `::_sync_tick`; `app/core/sync_retry.py`; the startup arming in `access/runtime.py`; the pending-context write in `change_detector.py::_poll_once`) — or the headless loop's pacing (`app.py::mainloop`, `::after`) | §3.6 The sync timer and the headless loop |
| What the optional-content scheduler fetches, stores or sends (`app/core/optional_content_sync.py`) | §3.7 Optional content sync |
| The test / verification commands | §9 Verifying this guide |

**Rules for editing this file:**

1. Every claim carries a status marker (§1) and a way to check it.
2. Never promote a claim to verified because it seems right, because a docstring says
   so, or because a test passes that does not actually exercise it. **A docstring is a
   claim, not evidence.**
3. If you disprove something here, **delete or correct it** — do not leave it standing
   and add a contradiction below.
4. Prefer symbol names (`device_driver.py::_resolve_with_source`) over line numbers.
   Line numbers drift; symbols survive.

---

## 1. Status markers

| Marker | Means |
|---|---|
| `[CODE]` | Traceable to a named symbol in this repo, right now. Check by reading it. |
| `[TEST]` | Pinned by a named test. Check by running it. |
| `[FIELD]` | Observed on real client hardware, in a named version. |
| `[UNVERIFIED]` | Believed, never proven. Do not build on it without proving it. |
| `[UNKNOWN]` | Open question. Stated so nobody assumes an answer exists. |

An unmarked sentence is context or instruction, not a factual claim about behaviour.

---

## 2. Two SDK families, and why they are not interchangeable

MonClub Access talks to ZKTeco hardware through **two completely different SDKs**. They
share a vendor and a default TCP port (4370). They share nothing else.

### ZK_PULLSDK — `plcommpro.dll` `[CODE: app/sdk/pullsdk.py]`

- ZKTeco **access panels**.
- Transport: a native DLL loaded via `ctypes`; one persistent TCP connection per panel.
- Events: **poll-based**. The app asks the panel for new real-time log rows.
- Data model: the panel exposes **tables** (`user`, `userauthorize`, `transaction`,
  `templatev10`, …) read and written as delimited text.

**Models, graded by the evidence that actually exists.** Do not widen this list without
adding evidence. Full grading in [`pullsdk_guide.md`](pullsdk_guide.md) §2.

| Model | Status |
|---|---|
| **C3-200** | `[FIELD]` The only PullSDK panel with a **dated measurement**: 2026-06-24, two production turnstiles 38–74 s behind the PC clock. |
| **C2-400** | **Operator-confirmed in production at v1.4.19** — but in the *source* it appears only in prose, with no measurement and no date. Its support is the operator's report, which lives outside this repo. |
| **C3-400** | `[CODE: comments assert]` 4-door bitmask math and the `fingerprintEnabled=false` path. No dated measurement. |
| ~~C4 / inBio~~ | **Removed.** Named only in the `DeviceProtocol` docstring and one `delete_device_data_batch` docstring citing a vendor manual. Both are author prose. A docstring is a claim, not evidence (§0 rule 2). |

### ZK_STANDALONE — `zkemkeeper` COM `[CODE: app/sdk/zk_standalone.py]`

- ZKTeco **standalone terminals**: MB2000-class multi-bio.
- Transport: a **32-bit COM server**, hosted in-process via `pywin32`.
- Threading: **one STA thread per device owns every COM call.** COM interfaces must not
  be used across apartments, so every public method posts a command onto an internal
  queue and blocks with a deadline. `[CODE: ZKStandaloneDevice._call / _sta_main]`
- Events: **push-based** via `RegEvent` + a COM sink, drained by `poll_rtlog_once()`
  and normalized into the exact dict shape PullSDK emits — so the ULTRA worker's loop,
  dedupe, cooldown, popup and history plumbing run unchanged.
- **There is no transaction table.** Events exist only as they arrive.
- Deployed: the MB2000 gym — fingerprint + RFID. Under active test.

### Consequences you must respect

- **PullSDK cannot talk to an MB2000.** Handing one a `plcommpro.dll` socket does not
  fail fast — it burns the full connect timeout and looks exactly like a cabling
  fault. `[FIELD: connect_ms=5110 against a healthy terminal, 2026-08-27]`
- **zkemkeeper has no call timeout.** A terminal that stops answering wedges the STA
  thread forever, and a blocked COM call cannot be interrupted. The driver's only
  recovery is to abandon the thread and build a fresh one behind a generation fence.
  `[CODE: ZKStandaloneDevice._abandon_sta_thread, self._sta_gen]`
- **Never branch on device *model*.** Branch on protocol (a closed set of ~3–5) or on a
  capability flag (§5). Models number in the hundreds; SDK families do not.

---

## 3. The three modes (`accessDataMode`)

`accessDataMode` is **per device**, not per gym. Anything not exactly `AGENT` or
`ULTRA` normalizes to `DEVICE`. `[CODE: settings_reader.py::normalize_access_data_mode]`

### DEVICE — the PC feeds and harvests the terminal

- The PC pushes the roster: `DeviceSyncEngine` syncs **only** devices whose
  `accessDataMode == "DEVICE"`. `[CODE: device_sync.py — "Skip device … (not DEVICE)"]`
- The PC harvests attendance from the device's own transaction table:
  `DeviceAttendance._list_device_candidates` skips any device whose
  `access_data_mode != "DEVICE"`. `[CODE]`
- **No PC component makes an automatic access decision for a DEVICE-mode device.** The
  two automatic open-door paths in the app both belong to other modes — see the
  call-site table below. Manual operator opens are a separate path and *do* apply here.
- The device firmware is therefore what grants or denies a live scan.
  `[UNVERIFIED]` — this follows from the absence of any PC decision path, not from a
  read of the firmware configuration. It has never been confirmed against the panel's
  own settings.

### AGENT — the PC decides and opens the door

- `AgentRealtimeEngine.refresh_devices` builds workers **only** for devices that are
  `active` **and** `accessDevice` **and** `accessDataMode == "AGENT"`. `[CODE]`
- `DecisionService` consumes events and issues the open itself, via
  `DeviceCommandBus.open_door(...)`. `[CODE: realtime_agent.py::DecisionService]`
- `DeviceSyncEngine` does **not** sync AGENT devices. `[CODE]`
- Whether the firmware *also* holds a roster and decides independently in this mode is
  a device-configuration question. `[UNKNOWN]` — not answerable from this repo.

### ULTRA — the terminal decides; the PC observes and rescues

- The firmware decides RFID/fingerprint and opens the door on its own. On an **allow**,
  the PC only *enriches* the event for popup and history — it does not open anything.
  `[CODE: ultra_engine.py::_handle_allow — "Device already opened door."]`
- On a **denied** event the PC may override:
  - card matches the TOTP/QR format → `_handle_totp_rescue` → `_open_door_with_retry`
  - denied RFID belonging to a valid **STAFF** member → `_handle_rfid_rescue` →
    `_open_door_with_retry` (staff skip the device's re-entry interval)
  - every other denial stands — including the device's punch-interval block.
  `[CODE: ultra_engine.py::_process_event]`
- ULTRA is the **only** mode that can drive a ZK_STANDALONE terminal. See §3.2.

### 3.1 Every door-open call site in the app

Exhaustive, so the mode descriptions above can be checked rather than believed.
Regenerate with `grep -rn "\.open_door(" app/ --include=*.py`. `[CODE]`

| Call site | Trigger | Applies to |
|---|---|---|
| `realtime_agent.py::DecisionService` (→ `DeviceCommandBus.open_door`) | **Automatic** — the AGENT access decision | AGENT only (workers are only built for AGENT devices) |
| `ultra_engine.py::_open_door_with_retry` | **Automatic** — ULTRA TOTP/QR and staff-RFID rescues only | ULTRA only |
| `ultra_engine.py` command-queue handler | Queued door command executed on the ULTRA worker's connection | ULTRA only |
| `realtime_agent.py::DeviceCommandBus` / `DeviceWorker.open_door` | Plumbing beneath the two above | — |
| `device_actor_runtime.py::_handle_message` (`OPEN_DOOR`) | Actor-message plumbing | — |
| `local_access_api_v2.py::_handle_device_door_open` | **Manual operator action** from the UI | **All modes** — tries the AGENT engine, then the ULTRA worker, then falls back to a direct PullSDK connect for "DEVICE-mode or unmanaged devices" `[CODE: that comment marks the fallback]` |

The last row is why "the PC is not in the live path" is **false** as a blanket statement
about DEVICE mode. It is true only of *automatic* decisions.

### 3.2 The roster rule — the most operationally important fact in this file

> **A `ZK_STANDALONE` device in `DEVICE` mode receives nothing. No engine pushes to it.**

- The standalone roster push is `ZKStandaloneDevice.push_roster`, and its **only**
  callers in the entire app are inside `app/core/ultra_engine.py`.
  `[CODE: verify with the grep in §9 — note it must match calls (\.push_roster\(), not
  the bare word, which also appears in comments elsewhere]`
- `PullSDKDevice` has no `push_roster` at all. `[CODE]`
- `DeviceSyncEngine._sync_one_device` therefore refuses any non-PullSDK protocol with a
  **loud ERROR**, never a silent skip — a quiet `return` would look like a successful
  sync while the terminal got nothing. `[CODE]`
  `[TEST: test_device_sync_protocol_guard.py::TestSyncOneDeviceRefusesNonPullSDK]`

**So: an MB2000 must be `accessDataMode=ULTRA`.** In `DEVICE` mode it is silent and
empty, and every surface will still report success.

### 3.2b What a device PIN actually is — and why it changed

> **The PIN is a per-device choice: `pinScheme` = `MEMBERSHIP` (the default) or `ACCOUNT`.**
> Nothing switches a device implicitly — not a client upgrade, not the backend starting
> to send `mainAccountId`, and not a device payload that omits `pinScheme` or carries a token
> this client does not recognise (§3.2e: those keep the last known scheme).

Derivation happens in exactly ONE function, `device_sync.derive_member_pin(user, scheme)`,
applied by `DeviceSyncEngine._filter_users_for_device` under the device's
`device_sync.device_pin_scheme(device)`. Both the PullSDK path and the standalone path route
through that filter.

| `pinScheme` | pin | several memberships of one person | row lacking the field |
|---|---|---|---|
| `MEMBERSHIP` — the stored value, or none stored for a device with no `ACCOUNT` history | `activeMembershipId`, else `userId` | stay separate rows (last row wins a pin; a `userId` pin never displaces a membership pin) | n/a |
| `ACCOUNT` | `mainAccountId` **only** | collapsed into one row (below) | **withheld** — never emitted under its membership pin |

`[CODE: app/core/device_sync.py::derive_member_pin, ::device_pin_scheme, ::_filter_users_for_device]`
`[TEST: tests/test_pin_scheme_gate.py::test_membership_scheme_is_byte_identical_to_the_pre_account_derivation]`
— MEMBERSHIP is checked against a verbatim copy of the loop as it was at `c13d1c2^`, over
randomised rosters that carry `mainAccountId`: same pins, same order, same row objects.

**Why a gate, not a fallback chain.** `c13d1c2` derived `mainAccountId → activeMembershipId →
userId` unconditionally. On the 2026-09-12 production data **110 `main_account.id` values
equal an existing `active_membership.id`, and 99 of those are a DIFFERENT person** (0 the same
person). The first client to see `mainAccountId` would have pushed account pins onto terminals
that still hold membership pins: on a PRESERVE device, pin X for person A overwrites device user
X that belongs to person B — wrong fingerprint and card on the wrong person — and the old rows
are never removed. So a device is switched deliberately, after a manual wipe (§3.2c), and never
mixes schemes. That is also why ACCOUNT does not fall back: a withheld row's membership id may
be another person's account pin on that terminal.

**Why ACCOUNT exists.** `active_membership.id` churns — delete and recreate a membership and the
pin changes, which on a preserve-policy device orphans the old row with its fingerprints and
card still resident. `main_account.id` never changes. It also matches the data model now that a
fingerprint template belongs to the account: a membership-keyed pin pushes one template under N
pins and burns N device slots for one finger.

**Where `pinScheme` comes from — the same path as `rosterPushingPolicy`.** Backend
`GymDeviceDto.pinScheme` → `getSyncData` `devices[]` (and fast-patch `GYM_DEVICE` upserts) →
`db._insert_device_row` → `sync_devices.pin_scheme` (`ACCOUNT`/`MEMBERSHIP` when the payload
states one of them; otherwise the last recorded scheme, `NULL` when there is none) → the
device payload projection's `"pinScheme"` → `list_sync_devices_payload` /
`get_sync_device_payload` / `load_sync_cache().devices` → the ULTRA worker's raw
`self._device`, and `DeviceSyncEngine._normalize_device`, whose allowlist now carries the key
(§6.2). `[CODE]`
`[TEST: test_pin_scheme_gate.py::test_pin_scheme_survives_ingest_to_the_engine,
::test_pin_scheme_survives_the_delta_device_refresh]`

**A withheld row makes the device's roster INCOMPLETE.** Under ACCOUNT a deliverable row
without `mainAccountId` (for example a cache row written before `sync_users` stored `mainAccountId`) is counted in
`stats_out["withheld_missing_account"]`, logged at WARNING and emitted as
`[T] PIN_SCHEME_ACCOUNT_WITHHELD`. Its account pin cannot be named, so it cannot be kept: any
caller that REMOVES pins absent from the filter's result must not remove on an incomplete
roster. `[CODE]` `[TEST: test_pin_scheme_gate.py::test_account_scheme_withholds_a_row_without_main_account_id_and_reports_it]`
**Offline projections are not withheld.** `load_sync_cache().users` also carries one synthetic row
per queued offline creation (`db.list_projected_offline_users`, `offlinePending: True`, negative
synthetic ids, never a `mainAccountId`). No roster refresh can fill it — it is not a `sync_users`
row — and a `blocked_auth` item waits on an operator, so counting it froze every removal on every
ACCOUNT device for as long as the item stayed queued (review #12). Under ACCOUNT such a row is
skipped: not emitted under any pin, counted only in `stats_out["skipped_offline_projections"]`.
Under MEMBERSHIP its negative pin already fails the digit check, so neither scheme pushes an
unconfirmed offline sale. `[CODE: device_sync.py::_filter_users_for_device]`
`[TEST: test_account_pin_device_sites.py::test_a_queued_offline_creation_does_not_freeze_removals]`

**The roster hash.** `build_device_sync_fingerprint` adds `pinScheme=ACCOUNT` to its header only
for ACCOUNT, so a MEMBERSHIP device's hash is unchanged by the upgrade.
`[TEST: test_pin_scheme_gate.py::test_a_membership_device_keeps_its_roster_hash_and_an_account_device_does_not]`

**The collapse (ACCOUNT only).** One person holding several memberships at one gym is ONE
device row, and a row carries one validity window, one name and — on the terminal — one card.
`_merge_same_pin_entries` resolves it:

- **validity** — the furthest-reaching membership wins, *among those this device accepts*, since
  `allowedMemberships` and the validity filter both run BEFORE the collision is possible. An
  absent `validTo` counts as furthest: that is how "no end date" is expressed, and treating an
  unknown as expired would revoke members we cannot date. **Ties go to the larger
  `activeMembershipId`**: both the push and `furthest_reach` rank by the one total order
  `device_sync.pin_row_rank`. Before that key was shared, the push kept the FIRST row on a tie
  and the inbound resolver the LARGER id. `[CODE]`
  `[TEST: test_pin_scheme_gate.py::test_equal_reach_is_broken_by_the_larger_membership_id_on_both_sides]`
- **fingerprints** — UNIONED, never the winner's alone. `_collect_templates_for_pin` treats
  `user['fingerprints']` as the whole answer and the backend attaches each template to the
  membership it was enrolled under, so taking only the winner's list silently deletes every
  finger scanned on the losing plan. De-duped by template id. The union is **sorted**
  (`fingerId`, `templateVersion`, template id, data): `_collect_templates_for_pin` keeps the last
  template per finger, so before the sort a finger enrolled under two memberships got whichever
  template the row order put last, and its desired hash moved with payload order (review #7). Now
  the largest template id wins that finger in any order. `[CODE]`
  `[TEST: test_fingerprints_are_unioned_not_taken_from_the_winner,
  test_pin_scheme_gate.py::test_the_template_pushed_for_a_finger_does_not_depend_on_row_order]`
- **cards** — the winner's, with an empty slot filled from the loser. **Only `firstCardId` reaches
  the terminal**: every PullSDK user write sends one `CardNo` from it (targeted push and full-sync
  writes) and the standalone `push_roster` entry carries one `card` from it (one
  `SetStrCardNumber`); `secondCardId` is never pushed. So when a person's accepted memberships carry
  different cards, the reach winner's card is on the device and **the others are dropped there** —
  under MEMBERSHIP each was on its own device user. The PC-side rescue opens only for STAFF, and a
  ZK_STANDALONE terminal decides alone, so a dropped card is refused. `_filter_users_for_device`
  counts them in `stats_out["dropped_cards"]` and logs one WARNING per roster build with a sample of
  the memberships whose card was dropped (review #5). The rank that picks the card is the validity
  rank (`pin_row_rank`), which must stay shared with the inbound resolver, so it is not a "best
  card" choice. Whether a device user record could hold a second card (e.g. a C3 multi-card table,
  a second MB2000 card) is `[UNVERIFIED — HARDWARE-GATED]`; nothing here writes one.
  `[CODE]` `[TEST: test_pin_scheme_gate.py::test_a_collapse_that_drops_a_card_reports_it]`

**Every site that turns a membership into a device pin goes through the device's scheme.**
Sync requests, delta `changed_ids`, fast-patch impacts and revocations all name MEMBERSHIPS
(`activeMembershipId`). Under ACCOUNT each site translates before touching a pin — a membership
number used as a pin names, for the 110 colliding ids, ANOTHER person's device user. The
translation is `device_sync.device_pins_for_members` (MEMBERSHIP: `str(int(id))`, unchanged;
ACCOUNT: `account_pins_for_memberships` — the roster in hand, then `member_account_link` (§3.2d),
which still answers after a revocation deleted the row; an unmappable membership is ABSENT, never
replaced by its own number). `[CODE]`

| Site | MEMBERSHIP (unchanged) | ACCOUNT |
|---|---|---|
| `DeviceSyncEngine.sync_member_on_connected_sdk` (PullSDK targeted push / revoke) | `pin = member_id`; rows of that membership | `pin` = the person's account pin; rows = EVERY row of the person (`person_rows_for_membership`), so the collapse is complete; unmappable → nothing pushed or deleted; `revocation=True` with the person still deliverable → the collapsed row is re-pushed even when its hash is unchanged, and that push is the return value |
| `DeviceSyncEngine._sync_one_device` `known_server_pins` | `activeMembershipId` of every user | account pin of every user |
| `_sync_one_device` delta pruning / drift check (`int(pin) in changed_ids`) | verbatim | `pin in` the account pins of `changed_ids` |
| `UltraDeviceWorker._build_standalone_roster(only_member_ids)` | `wanted = {str(int(m))}` | the account pins of those memberships |
| `UltraDeviceWorker._load_member_roster` | that membership's row | every row of the person |
| `UltraDeviceWorker._defer_member_sync` | flags `str(member_id)` | flags the person's pin; none when unmappable |
| `UltraDeviceWorker._run_standalone_member_revoke` | removes `str(member_id)` (ownership-checked) | see below |
| `_run_standalone_full_sync` explicit-revocation ownership check + `required_pins` | `str(member_id)` | the person's pin, and only when it LEFT the desired roster |
| `UltraDeviceWorker._handle_allow` fingerprint-scan pin → member (`_user_for_device_pin`) | `users_by_am[int(pin)]` | the collapsed row `_filter_users_for_device` builds for this device |
| `ZKStandaloneDevice._refresh_pin_card_map` (pin → card on standalone events) | `active_membership_id or user_id` | the collapsed rows for this device, scheme read from the stored device row |

`[TEST: tests/test_account_pin_device_sites.py]` — 18 of its 23 cases fail against the code
before this conversion (2eafb5f); the 5 that pass there pin MEMBERSHIP behaviour or refusals that
were already safe.

**Revoking one membership of a person (ACCOUNT).** `_account_member_revoke` names the person's pin,
reads the person's remaining rows and builds this device's roster from them. If the person is
still deliverable, the collapsed row is RE-PUSHED (the revoked plan's validity and finger slots
leave with it; `MEMBER_REVOKE_DONE mode=repushed`) and nothing is deleted. Only when nothing of the
person remains is the pin removed, through the same ownership-checked `_remove_standalone_pins`.
An unmappable membership removes nothing (`MEMBER_REVOKE_PIN_UNKNOWN`) and defers to a full sync.
The full sync's explicit-revocation check likewise requires removal only of person pins that left
the roster; otherwise a person holding another membership would fail every full sync. A
revocation whose membership was never seen with a `mainAccountId` names no pin; that membership
can never have been pushed under ACCOUNT (the push reads `mainAccountId` from the same rows the
link is refreshed from), so there is nothing of it to remove. `[CODE]`
`[TEST: ::test_revoking_one_of_two_memberships_repushes_and_keeps_the_pin,
::test_revoking_the_last_membership_removes_the_account_pin,
::test_revoking_sonias_membership_5_removes_sonia_not_ali,
::test_a_revoked_membership_whose_person_remains_does_not_fail_the_sync]`

**The PullSDK path (review #11).** Both ULTRA PullSDK consumers read
`sync_member_on_connected_sdk`'s bool as "revocation done": the targeted drain finalises the
revoke, and the full sync's `_mark_member_revoke_confirmed` decides whether the sync reports
"authoritative revocation unconfirmed". The per-pin hash carries no validity window, so when a
person keeps another plan the collapsed row's hash does not move, and the "unchanged" skip
returned False on every run — every full sync failed forever. Both call sites now pass
`revocation=True`; under ACCOUNT with the person still deliverable the collapsed row is re-pushed
regardless of the hash and that push's result is returned. A non-revocation sync still skips an
unchanged row. `[CODE: device_sync.py::sync_member_on_connected_sdk; ultra_engine.py call sites]`
`[TEST: test_account_pin_device_sites.py::test_revoking_one_of_two_memberships_is_confirmed_by_the_repush,
::test_an_unchanged_non_revocation_sync_still_skips]` — the call sites passing the flag are `[CODE]`
only; no worker-level test drives them. **Still open:** an UNMAPPABLE membership's revocation
returns False on this path (nothing to name), so it stays unconfirmed and re-queues a full sync on
every run, whereas the standalone full sync treats it as nothing to remove.

**No removal on an incomplete ACCOUNT roster.** When `_filter_users_for_device` withheld rows
(no `mainAccountId`), their people's pins are missing from `desired_pins` and would read as
departed. So, under ACCOUNT with withheld rows: the standalone full sync skips
`_maybe_mirror_reconcile`, `_neutralise_revoked_pins` AND `prune_device_sync_state`
(`safe_to_prune=False`, `[T] REVOKE_SKIP_INCOMPLETE_ROSTER`); the PullSDK full sync skips the
stale-pin delete, the nuke and both prunes; and the two TARGETED removals
(`sync_member_on_connected_sdk`, `_account_member_revoke`) first check
`device_sync.account_roster_withheld_for_device` over `db.list_sync_users_missing_main_account`,
because a person's other membership row may be the one without the field. This neither mixes
schemes (nothing is pushed under a membership pin) nor revokes a row already on the device, and it
keeps the ownership evidence §3.2c depends on. The cost is that, while such rows exist,
revocations on that device are not carried out — the forced refresh of §3.2d is what ends the
window. `[CODE]` `[TEST: ::test_an_incomplete_roster_skips_the_revoke_pass_and_the_prune,
::test_an_incomplete_account_roster_removes_and_prunes_nothing,
::test_no_delete_while_a_deliverable_row_has_no_main_account_id,
::test_no_removal_while_a_deliverable_row_has_no_main_account_id]`

**The PullSDK nuke heuristic is off for any device that has switched scheme.** INCREMENTAL clears
every table when stale pins outnumber desired ones. Right after a switch the old scheme's pins ARE
that majority, so the heuristic would wipe the terminal automatically — other systems' users
included. The procedure is a manual wipe (§3.2e), so `_sync_one_device` suppresses the heuristic
when `device_pin_scheme_switch` has a row for the device; stale pins are still removed one by one.
An explicit `FULL_REPLACE` policy is left as configured. `[CODE]`

**The fingerprint push report names the id the pin IS.** `report_fingerprint_push_result` posted
every pin as `activeMembershipId`; the backend then runs
`findByActiveMembershipIdAndFingerId(<that number>, fingerId)`, so under ACCOUNT a report for
account pin 5 would write — or clear — a push error on the fingerprint of the person whose
MEMBERSHIP is 5. The digits cannot say which scheme minted them, so the push records it:
`_filter_users_for_device` exposes `stats_out["pin_sources"]`, every `_push_templates` caller
(targeted push, full-sync phase C, the per-pin path, and the admin raw push, which records the
device's scheme — or `UNKNOWN` when the device row cannot be read, which the report never sends,
review #10) passes `pin_source`, and `fingerprint_push_status.pin_source` stores it
(`NULL` = written before the column = MEMBERSHIP: every pin was membership-derived then, and a
userId-keyed member cannot own a UserFingerprint). `get_pending_fingerprint_push_reports`
aggregates per `(pin_source, pin, finger)` — pin 5 under two schemes is two people — and the
"last reported" record moved to `fingerprint_push_reported_v2`, keyed the same way (v1 rows copied
once as MEMBERSHIP, so no transition is re-sent after the upgrade). The report then sends:

| `pin_source` | item key |
|---|---|
| `ACCOUNT` | `mainAccountId` — the backend resolves it through the reporting gym's enabled enrolment of that finger |
| `MEMBERSHIP`, or absent | `activeMembershipId` |
| `USER` | nothing (skipped) |

An older backend ignores `mainAccountId` (Jackson `FAIL_ON_UNKNOWN_PROPERTIES` is not enabled)
and skips an item without `activeMembershipId`. `[CODE: app/api/monclub_api.py::report_fingerprint_push_result,
db.py::get_pending_fingerprint_push_reports]`
`[TEST: tests/test_push_report_pin_scheme.py]`
**Scope:** only the PullSDK push (`DeviceSyncEngine._push_templates`) records per-finger outcomes;
the ZK_STANDALONE `push_roster` path records none, so gym 45's MB2000s emit no push reports at
all — before or after this change. `[CODE: upsert_fingerprint_push_status has one caller]`

**Inbound: a pin is read under the scheme its DEVICE ran when the event happened.** A device
reports a pin, and on the 2026-09-12 production data **110 `main_account.id` values numerically
equal an existing `active_membership.id`**, for **99** of them DIFFERENT people (**0** the same
person). Nothing in the event says which scheme minted the pin — but the device runs one scheme at
a time and every change is recorded with its time (§3.2e). `device_attendance.HistoryPinResolver`
uses that:

- **scheme at event time** — `db.list_device_pin_scheme_switches` read by `pin_scheme.scheme_at`
  at the row's `event_time`. No row → MEMBERSHIP: this database has only seen the device on
  MEMBERSHIP. A row at or before the event → its scheme. Before the first row → that row's
  `previous_scheme`: MEMBERSHIP for a recorded switch, **unknown** for a first sighting
  (`previous_scheme='UNKNOWN'`, §3.2e) — a database that first sees a device already on ACCOUNT
  does not know when it switched, so it does not invent a MEMBERSHIP window ending at PC-now.
- **MEMBERSHIP** → the membership index only. **ACCOUNT** → the collapsed row
  `_filter_users_for_device` builds for THAT device (its `allowedMemberships` / validity policy,
  `pin_row_rank`), so an event names the membership the device row represents; a device no longer
  in the cache falls back to the unfiltered by-account index, ranked the same way. A known scheme
  never consults the other index.
- **unknown** (a device with history whose `event_time` does not parse, an event before a first
  sighting on ACCOUNT, or a legacy caller of
  `_resolve_history_user` without `pin_scheme`) → the old rule: the unambiguous reading, and a pin
  that is both prefers MEMBERSHIP, with a WARNING. c13d1c2's "account index first" inverted
  correctness on devices still holding membership pins; that is why the fallback prefers
  membership.

Used by the backend uploader (`_sync_pending_history` → `_serialize_row_for_backend(resolver=…)`)
and the dashboard feed (`_dash_user_indexes` / `_dash_history_resolver`). When the dashboard cannot
build the resolver (switch history unreadable), it names a member **by card only** — the old
fallback was a membership-only pin lookup that showed a stranger for an account pin on an ACCOUNT
device, for the 60 s the cache lives (review #3). Display only. The 60 s cache also means events
just after a switch can be shown under the old scheme for up to a minute `[CODE]`, not fixed.
`[TEST: test_account_pin_inbound_by_scheme.py::test_the_dashboard_feed_uses_the_same_resolution]`
The upload item for an
**unresolved** pin: MEMBERSHIP → `activeMembership` = pin (unchanged); ACCOUNT → `mainAccountId` =
pin and **no** `activeMembership` (the backend's history ingest resolves `userId`, then
`mainAccountId`, gym-scoped, and reads `activeMembership` only when neither is sent); unknown →
neither. If the switch history cannot be read, the batch is not uploaded that tick and the rows stay
pending. **Cost of "unknown → neither" (review #9):** an item with no identifier is, per the
reviewer's read of `GymAccessController` (`anyIdentifier` false → `unidentified`, token in
`terminalFailedIds`) `[UNVERIFIED — not re-read here]`, terminal on the backend, and the client
then marks the row terminal, so that door event never reaches attendance history even after the
roster catches up. Deliberately not changed: naming either id would be a guess, and retrying never
makes the scheme knowable. Since the first-sighting rule (§3.2e), this also covers unresolved pins
in the backlog before a device was first seen on ACCOUNT. `[CODE: app/core/device_attendance.py::HistoryPinResolver, ::_resolve_history_user,
::DeviceAttendanceMaintenanceEngine._serialize_row_for_backend]`
`[TEST: tests/test_account_pin_inbound_by_scheme.py;
test_account_pin_derivation.py::test_an_ambiguous_pin_resolves_as_a_membership_the_pre_cutover_reality]`

`[UNVERIFIED]` **the event clock.** `event_time` is the terminal's clock and `switched_at` the PC's.
C3-200 panels were measured 38–74 s behind the PC (§2) and `UltraDeviceWorker._device_tz_offset_sec`
exists because a device clock can differ further. An event within that offset of a switch can be
read under the wrong scheme. Across that window an unwiped terminal holds both schemes anyway, which
is why the procedure wipes BEFORE switching.

**Cutover is a WIPE, not a re-key.** Because of those 110 collisions, re-keying a device in place
can graft one member's fingerprints onto another member's row. Existing terminals must be cleared
and re-pushed. `[UNVERIFIED — the wipe path itself has not been exercised on hardware]`
**And the wipe must be MANUAL** — neither automatic removal path can do it. §3.2c says why.

### 3.2c Neither automatic path can clear an old-scheme PIN (2026-09-12)

> **The pin-scheme cutover is a MANUAL wipe. This is settled, not a preference.**

Two mechanisms could in principle remove a stale pin from a `ZK_STANDALONE` terminal. On the
installed fleet neither can, for independent reasons. Establish this before promising an
operator that "mirror mode will clean it up".

**1. MIRROR reconcile — blocked three times over, and the third survives the repair.**

`_maybe_mirror_reconcile` gates policy FIRST: `rosterPushingPolicy != "MIRROR"` returns before
anything else. Gym 45's two turnstiles (device 8 "Sortie", device 10 "Entrée") are
`device_protocol=ZK_STANDALONE`, `roster_pushing_policy=PRESERVE`, `access_data_mode=ULTRA`,
both active. `[FIELD: restored production DB, 2026-09-12 — gym_device joined to
gym_infrastructure/gym_agent on gym 45]` PRESERVE is the default every gym runs, so **no code
change in this repo makes MIRROR run there**; it needs the backend to change
`gym_device.roster_pushing_policy`.

Independently, the trigger gate was unsatisfiable. It read
`reason in ("user-sync", "daily-forced-sync", "hard-reset")`, but `reason` carries a
*trigger_source* token — `app.py` passes `trigger_context.trigger_source`, whose vocabulary is
`API_MANUAL`, `CHANGE_DETECTOR`, `FAST_PATCH_BUNDLE`, `FINGERPRINT_ENROLLED`, `MANUAL`,
`MANUAL_EVALUATE`, `STARTUP`, `SYNC_NOW_API`, `TIMER`, plus the scheduler's `startup`/`timer`
and the worker's `revoke-*`. **No producer ever emitted those three literals**: every
occurrence in the repo's history is a test hand-passing the literal into the gate.
`[CODE + git archaeology: a -S search over all history for those assignments returns only
test hunks]`

Two of the three were not even spelled correctly for the field they belonged to: the real
`trigger_hint` markers are `user-sync` and **`daily-auto-sync`** (never `daily-forced-sync`),
and a hard reset is `run_type="HARD_RESET"` / `hint["hardReset"]`, not a reason at all.

*Fixed 2026-09-12 by carrying the answer, not re-deriving it.*
`sync_observability.is_explicit_user_sync` already folds those three cases into one predicate
and already gates `_should_push` in manual-sync mode. The app layer evaluates it once and a
`full_reconcile: bool` travels with the request — `_request_running_ultra_sync` →
`UltraEngine.request_sync_now` → `UltraSyncScheduler.request_sync_now` → pending merge/drain →
`_sync_all` → `UltraDeviceWorker.request_full_sync` → `_run_standalone_full_sync` → the gate.
It merges by OR, never assignment, so coalescing a timer tick into a queued operator reconcile
cannot downgrade it. `[CODE: the named symbols]`
`[TEST: tests/test_mirror_reconcile_reachability.py]`

Two further skips had to move or the repaired flag would have been dead again — both are
`[TEST]`-pinned in that file:

- `_sync_all` skips a device whose desired-roster fingerprint is unchanged. A reconcile targets
  rows the TERMINAL holds and the roster does not, which never moves that hash.
- `UltraEngine.request_sync_now` routes targeted member syncs whenever `changed_ids` is not
  `None`. A delta-mode explicit sync would never have requested a full sync.
- `UltraSyncScheduler._sync_all` had the same branch on the **scheduler-fallback** route (a
  dead or refusing worker hands the request to the scheduler, which drains it into
  `_sync_all`): it tested only `normalized_changed_ids is not None`, so the reconcile was lost
  there even after the engine route was fixed, and with no usable worker `_sync_device` was
  handed the delta's `changed_ids`. Both now honour `full_reconcile`.
  `[TEST: test_mirror_reconcile_reachability.py::test_the_scheduler_fallback_honours_full_reconcile_with_delta_changed_ids,
  ::test_the_whole_fallback_chain_delivers_the_reconcile,
  ::test_a_reconcile_without_a_usable_worker_is_not_narrowed_to_changed_ids]`

**Cost note.** Because an explicit sync now bypasses the roster-hash skip, every "Sync data"
click drives a full sync on each ULTRA device. On a PRESERVE device the per-pin diff keeps
`to_push` empty, so it stays cheap. On a MIRROR device each click additionally enumerates the
whole terminal (`list_device_users`) over the STA thread. `[CODE]`

**One condition remains, by design.** `_request_running_ultra_sync` returns early unless the
sync actually returned a roster refresh (`refresh["members"]` or `refresh["devices"]`), so a
"Sync data" click on a gym with no changes dispatches nothing to reconcile. A **hard reset**
always qualifies: it clears the version tokens, so the next `getSyncData` runs in FULL mode.
Use hard reset when the point is the reconcile rather than the changes.
`[CODE: app.py::_request_running_ultra_sync, local_access_api_v2.py::_handle_sync_hard_reset]`

**Even on a MIRROR device, a cutover-sized diff never reaches the plan.** Gate 8 — the 25 %
floor, `if len(extras) > roster_count * _MIRROR_MAX_DELETE_FRACTION` — precedes gate 9, which
is what calls `mirror_reconcile_record_plan`. At cutover every device pin is absent from the
new roster, so `extras` is essentially the whole roster and the pass returns on
`MIRROR_ABORT_FLOOR` **before any plan is written**. `/mirror-plan` keeps returning
`lastPlanCount: null` and the dashboard's arm button stays disabled — the same symptom the
trigger repair removes for *ordinary* churn. Unlike the revoke pass, MIRROR's floor is purely
fractional: there is no `_REVOKE_ABSOLUTE_FLOOR` equivalent, so a full re-key is refused at any
roster size. `[CODE: ultra_engine.py::_maybe_mirror_reconcile, gate order]`
`[TEST: test_mirror_reconcile_reachability.py::
test_a_cutover_sized_diff_aborts_mirror_before_any_plan_is_recorded]`

> So **flipping `roster_pushing_policy` to MIRROR does not buy a cutover.** The repaired
> trigger restores the dry-run → `/mirror-plan` → arm chain for everyday departures, which is
> what it is for. It does not, and cannot, re-key a terminal.

**2. The revoke pass — aborts on its own floor, and that abort is protective.**

`_neutralise_revoked_pins` is trigger-independent: it runs on every successful standalone full
sync, and it is the only removal path a PRESERVE device has. Its candidate set is `owned` (pins
with `ownership_confirmed=1` in `device_sync_state`) minus `keep` (the desired roster) minus the
grace/allowlist. It refuses a bulk strip above
`ceiling = max(_REVOKE_ABSOLUTE_FLOOR=10, roster_count * _MIRROR_MAX_DELETE_FRACTION=0.25)`.

After a pin-scheme change `owned` holds old membership pins and `keep` holds new account pins,
so the difference is essentially the whole roster. Gym 45 has **1080 ACTIVE memberships across
1061 distinct accounts**, counted across all five of its `gym_agent` rows (8, 49, 50, 51, 52 —
counting only agent 8 gives 990/988 and is a lower bound).
`[FIELD: restored production DB, 2026-09-12]` The ceiling is therefore of order 250 against a
candidate set of order 1000 → `REVOKE_ABORT_FLOOR`, nothing removed, and it never self-resolves
because nothing shrinks between runs.

Treat that ceiling as an **estimate, not a measurement**: `roster_count` is the *device* roster
after `shouldExposeMembership`, the validity window and `allowedMemberships`, not the
ACTIVE-membership count. The order of magnitude is the point — the candidate set is the whole
roster and the ceiling is a quarter of it.

**Do not raise the floor to "unblock" a cutover.** Nothing inside that function can tell a
pin-scheme change from a truncated or half-built roster — they are informationally identical
there — and the second is the case the floor exists to refuse.

**The abort is accidentally load-bearing.** It returns `safe_to_prune=False`, which skips
`prune_device_sync_state(keep_pins=desired_pins)`. Post-cutover that prune would delete the
`device_sync_state` row — and with it the `ownership_confirmed` bit — for every old-scheme pin.
`owned` would then be empty, the revoke pass could never target those pins again, and they would
be stranded on the turnstile permanently and invisibly. **Any change that makes `safe_to_prune`
true without actually removing the pins is worse than the current behaviour.**
`[CODE: ultra_engine.py::_neutralise_revoked_pins, ::_run_standalone_full_sync]`

The abort fails the sync (`sync_ok=False`, `"authoritative revocation unconfirmed"`) **only when
that sync also carried explicit authoritative revocations** — `if unconfirmed_revoked_ids and
not safe_to_prune`, where `unconfirmed_revoked_ids` comes from the request's own `revoked_ids`,
not from the roster diff. An ordinary post-cutover sync therefore aborts the revoke pass, skips
the prune, logs `REVOKE_ABORT_FLOOR`, and still reports success. `[CODE]`

**Hard reset does NOT strand ownership evidence.** `clear_all_device_sync_hashes` and
`clear_device_sync_hashes` set only `desired_hash=NULL, last_ok=0, last_error='forced resync'`;
`UltraSyncScheduler.force_resync` clears in-memory hashes only. `ownership_confirmed` and
`pushed_finger_ids` survive both, so a hard reset is safe to reach for and a later pass can
still reconcile. `[CODE: db.py::clear_all_device_sync_hashes, ::clear_device_sync_hashes;
ultra_engine.py::UltraSyncScheduler.force_resync]`

**EnableDevice bracketing stays OFF — deliberately reversing plan decision D6.**

D6 said the explicit/nightly reconcile would re-push every pin inside an `EnableDevice(False)`
bracket. It never once executed, because its condition was the same dead reason-string test.
Meanwhile the driver changed underneath it: `push_roster` collapses a bracketed roster into ONE
command (`chunks = [users]`) with `timeout_sec` as the whole budget, bypassing the per-chunk
timeout and wedge recovery that exist because a single-command ~950-member push meant "the gym
never got more than the first 10 members". Bracketing also holds the terminal — the gym's sole
verifier — locked for the entire push. So `bracket` is now an explicit `False`, and an explicit
reconcile stays incremental and unbracketed. Turning it on is a separate, hardware-gated
decision, not a side effect of repairing the MIRROR trigger.
`[CODE: ultra_engine.py::_run_standalone_full_sync; zk_standalone.py::push_roster]`
`[TEST: test_zk_standalone_driver.py::TestStandaloneFullSyncBranch::
test_an_explicit_reconcile_does_not_bracket_enable_device]`

**What this means operationally.** "Use mirror mode first, wipe manually only if it has a
problem" is not available on the installed fleet, and no setting change makes it available: on
a PRESERVE device mirror mode is a no-op regardless of trigger; on a MIRROR device a
cutover-sized diff aborts on the 25 % floor before it records a plan, so the arm button never
becomes clickable; and the revoke pass refuses a roster-sized strip by design. **The PIN
cutover must be a manual wipe of each terminal, followed by a re-push.** The wipe path itself is
still `[UNVERIFIED — HARDWARE-GATED]` (§3.2b).

### 3.2d The member cache carries the person — and the upgrade trap (2026-09-12)

**Until this change `mainAccountId` never survived `sync_users`.** No writer stored it and
`_coerce_user_row_to_payload` never read it back, so every roster the engines saw had no
`mainAccountId`: the account pin, the collapse and the account index of §3.2b were inert on
every installed client while their raw-dict tests passed. `[CODE: git show 0f0a445:app/core/db.py]`

Now `sync_users.main_account_id INTEGER` is written by **every** sync_users writer — found by
grepping `INSERT INTO sync_users` / `INSERT OR REPLACE INTO sync_users` / `UPDATE sync_users`,
not from memory:

| Writer | Path |
|---|---|
| `save_sync_cache` | full replace |
| `save_sync_cache_delta` → `_apply_full_users_refresh` (INSERT **and** UPDATE) | FULL member refresh, per-row diff |
| `save_sync_cache_delta` delta branch | DELTA member refresh |
| `upsert_delta_users` | delta helper |
| `_upsert_sync_user_row` ← `apply_fast_patch_bundle` | fast-patch `ACTIVE_MEMBERSHIP` upsert |
| `_rebuild_sync_users_without_legacy_fingerprint` | legacy-schema migration |

and read back as `"mainAccountId"`. `main_account_id` is part of `_SYNC_USER_COLUMNS`, the
tuple the full-refresh diff compares: a row whose **only** change is a newly-arrived
`mainAccountId` must compare unequal or it would stay NULL. `[CODE]`
`[TEST: tests/test_account_pin_sqlite_roundtrip.py::test_every_writer_round_trips_main_account_id_into_the_pin,
::test_the_full_refresh_diff_updates_a_row_whose_only_change_is_main_account_id]`

**Migration order is load-bearing.** The legacy rebuild re-creates `sync_users` from a
hardcoded column list, so every `sync_users` `_ensure_column` now runs **after** it. They used
to run before, which is how `birthday`, `image_source`, `user_image_status` and
`user_profile_image` were added and then silently dropped on a legacy database (the next write
naming them failed); the rebuild's list now names them and `main_account_id` too. `[CODE]`
`[TEST: test_account_pin_sqlite_roundtrip.py::test_a_legacy_database_is_rebuilt_without_losing_a_column]`

**The upgrade trap, and the one forced refresh.** Once the column exists every cached row is
NULL until the members section is re-fetched — and nothing re-fetches it: the backend's
`membersVersion` does not change because a client upgraded, so each sync answers
`refreshMembers=false` or a delta naming only members that happened to change. Under
`pinScheme=ACCOUNT` those rows are withheld indefinitely. So when `init_db` finds the column
**absent** (measured before the legacy rebuild, which re-creates the table with an empty
column), `_ensure_main_account_id_column` deletes `membersVersion` and `membersUpdatedAfter` —
the house mechanism behind hard reset and `strip_all_member_version_tokens` — and keeps every
other section's token. The next `getSyncData` carries neither (`MonClubApi.get_sync_data`
sends the stored tokens as request params), the backend answers in FULL member mode, and the
per-row diff fills the column. `[CODE: db.py::_ensure_main_account_id_column, init_db]`
`[TEST: ::test_an_old_database_gains_the_column_and_forces_one_full_member_refresh,
::test_the_forced_refresh_actually_reaches_the_backend_request_in_full_mode,
::test_the_refresh_is_forced_once_not_on_every_start]`

It is **atomic**: the token DELETE runs before the ALTER, so both sit in the single transaction
`init_db` commits at its end; a crash in between rolls both back and the next start detects the
missing column again. `[TEST: ::test_the_column_and_the_token_drop_commit_together]`
**The same trap on the device side (review #13).** `sync_devices.pin_scheme` also arrives NULL,
and `devicesVersion` survives the upgrade, so the backend answers `refreshDevices=false`: a device
set to ACCOUNT while the PC still ran the old client would read as MEMBERSHIP (no switch, no hash
clear) until an unrelated device edit moved the token, and then switch with no wipe in between.
`_ensure_pin_scheme_column` therefore, when a sync_devices table that existed before `init_db`
lacks the column (measured before the `CREATE TABLE`, so a fresh install is not an upgrade),
deletes `devicesVersion` — the device section's only progress token — and records every device
already in the table as seen on MEMBERSHIP (the old client had no other scheme, so the ACCOUNT
value the refresh brings is a real switch, §3.2e). Same one-shot, DELETE-before-ALTER atomicity
as the members helper. The backend half (`refreshDevices = clientDevicesVersion == null || …`) was
read in `GymAccessController`, not run. `[CODE: db.py::_ensure_pin_scheme_column, init_db]`
`[TEST: test_pin_scheme_switch.py::test_an_old_database_gains_pin_scheme_and_forces_one_device_refresh]`

If the backend in use does not emit `mainAccountId`, the refresh still runs once and the column
stays NULL: MEMBERSHIP devices are unaffected, ACCOUNT devices withhold everyone (§3.2b).

**`member_account_link` — membership → person, durable.** `_refresh_member_account_links` runs at
the end of every sync_users write transaction and records each cached `(active_membership_id,
main_account_id)` pair; rows are never deleted with the member. A revocation deletes the
member's `sync_users` row (and its `member_shadow` row) **before** the device worker acts on
it, and under ACCOUNT that worker must still name the person's pin.
`db.get_main_account_ids_for_memberships` reads it; `db.list_sync_users_by_main_account_ids`
reads every cached row of a person. `[CODE]`
`[TEST: ::test_the_link_survives_the_member_row_being_deleted]`

**`member_shadow.pin` is not a device pin, and nothing reads it.** It holds the
`activeMembershipId`. Every `FROM member_shadow` reader selects `active_membership_id` /
`card_id` or compares card, name, `fp_hash`, dates and `membership_id` (grep, 2026-09-12), so no
revoke or diff path looks a device row up through it; the table is unchanged and rows written by
deployed versions diff exactly as before. The shadow diff deliberately does **not** compare
`main_account_id`: the forced refresh above would flag every member (1 080 at gym 45) as
modified and dispatch that many targeted member syncs to MEMBERSHIP devices on which nothing
changed. A device reaches ACCOUNT only through an operator switch, and a withheld row that
becomes deliverable moves that device's roster hash, which the scheduler's full sync acts on.
`[CODE: ultra_engine.py::UltraSyncScheduler._sync_all]` In a manual-sync-mode gym that full
sync waits for the operator's "Sync data". `[CODE: UltraSyncScheduler loop — timer pushes are
skipped when _manual_sync_mode()]`

### 3.2e Switching a device's pin scheme (2026-09-12)

**Detection.** Every device write — `save_sync_cache`, the `save_sync_cache_delta` device section
and a fast-patch `GYM_DEVICE` upsert — goes through `db._insert_device_row`, which calls
`_record_device_pin_scheme_switch` in the same transaction. The current scheme is the latest
`device_pin_scheme_switch` row for the device, MEMBERSHIP when there is none; a payload whose
`pinScheme` is **explicitly** `ACCOUNT` or `MEMBERSHIP` (case/space-insensitive,
`pin_scheme.recognized_pin_scheme`) and differs is a switch. An absent key (an older backend, a
partial payload), `null`, `""` or an unknown token is **not** a switch: nothing is recorded, no
hash is cleared, and `sync_devices.pin_scheme` is written with the last recorded scheme, so the
push keeps deriving that scheme's pins (WARNING logged). This matches the backend's own rule for
the field ("old clients don't send it — keep the current value"). A current backend always sends
it. `[CODE: app/core/db.py::_insert_device_row, ::_record_device_pin_scheme_switch]`
`[TEST: tests/test_pin_scheme_switch.py::test_every_device_write_path_sees_the_switch_exactly_once,
::test_a_payload_without_a_recognised_pin_scheme_keeps_the_last_known_scheme,
::test_an_explicit_membership_after_account_is_still_a_switch]`

**What a switch does — and does not do.**

- Clears that device's per-pin hashes with the **same UPDATE** `clear_device_sync_hashes` and hard
  reset use (`_clear_device_sync_hashes_on`: `desired_hash=NULL, last_ok=0`). It never DELETEs:
  `ownership_confirmed` and `pushed_finger_ids` survive. `[TEST: ::test_switching_to_account_records_once_and_clears_hashes_without_deleting]`
- Records `(device_id, previous_scheme, scheme, switched_at, cleared_rows)` in
  `device_pin_scheme_switch`. `switched_at` is `now_iso()` — local PC time, the clock and shape of
  `access_history.created_at`. Kept **outside** `sync_devices`, which every device-section refresh
  DELETEs and re-inserts. `[TEST: ::test_the_switch_time_survives_a_device_section_refresh]`
- Logs CRITICAL and emits `[T] PIN_SCHEME_SWITCH`.
- The roster hash moves (`pinScheme=ACCOUNT` joins its header, §3.2b), so the scheduler does not
  skip the device's next full sync.
- It does **not** touch the terminal. Nothing in this repo wipes a device automatically.

**A first sighting is not a switch** (a new or reinstalled PC, a lost SQLite file, or a device
added after the upgrade). `device_pin_scheme_seen` records each device the database has seen with
an explicit scheme. A device with neither a seen row nor a switch row is a first sighting: on
MEMBERSHIP only the seen row is written; already on ACCOUNT, a row `('UNKNOWN' → 'ACCOUNT', now)`
is written, so events stamped before it resolve under the unknown-scheme rule (§3.2b inbound) —
not as MEMBERSHIP. Hashes are still cleared (idempotent UPDATE). It logs WARNING when there was
nothing to clear; CRITICAL (wipe) only when this PC already held sync state for the device, since
those pins were pushed before any scheme was recorded, i.e. as membership pins. The row counts as
history for the nuke suppression below. `[CODE: db.py::_record_device_pin_scheme_switch]`
`[TEST: test_pin_scheme_switch.py::test_a_first_sighting_on_account_is_not_a_switch_and_earlier_events_are_unknown,
::test_a_device_seen_on_membership_then_account_is_a_real_switch]`

*Decision for review #14 (a PC with no history).* A first sighting on **MEMBERSHIP** is read as
MEMBERSHIP for earlier events too, not unknown. Reason: treating it as unknown would degrade every
new install at a MEMBERSHIP gym — a backlog pin not in the cache would go up with no identifier
(dropped by the backend), and a membership pin that equals a cached account id would name the
account holder. The residual `[UNVERIFIED — not observed]`: a device that ran ACCOUNT and was
switched back to MEMBERSHIP before this database first saw it has its ACCOUNT-period backlog read
as MEMBERSHIP.

> **Operator procedure.** Wipe the terminal's users, then switch `pinScheme` on the device.
> Until the wipe, a PRESERVE terminal holds the old scheme's users next to the new ones, and on
> the 110 colliding ids (99 different people) the new push overwrites a stranger's device user.
> `[UNVERIFIED — HARDWARE-GATED]`: the wipe itself has not been exercised on an MB2000.

**Known consequence after a switch: the revoke pass stays aborted.** The old scheme's
`device_sync_state` rows remain `ownership_confirmed=1` (deliberately, §3.2c). The revoke pass's
candidates are `owned − keep`, i.e. essentially every old-scheme pin, which exceeds the floor, so it
returns `REVOKE_ABORT_FLOOR` / `safe_to_prune=False` on every full sync; a full sync that also
carries explicit revocations reports "authoritative revocation unconfirmed". Targeted member
revokes (§3.2b) are unaffected. Retiring the old-scheme rows after a confirmed wipe needs an
explicit operator-confirmed action that does not exist yet. `[CODE: ultra_engine.py::_neutralise_revoked_pins]`
`[UNKNOWN — not built; needs a decision]`

**Reading the history.** `db.list_device_pin_scheme_switches` and
`pin_scheme.scheme_at(switches, when)`, items `(scheme, switched_at, previous_scheme)`: no row →
MEMBERSHIP (only ever seen on MEMBERSHIP — see the #14 decision above for what that does not
cover); before the first row → its `previous_scheme`, `None` when that is `UNKNOWN`; a row
stamped at or before `when` is in force; an unparseable `when` on a device with rows → `None`; a
row with an unparseable time → `None` until the next parseable row at or before `when`.
`[TEST: ::test_switching_back_is_a_second_switch_and_each_window_resolves, ::test_scheme_at_rules,
::test_scheme_at_reads_the_scheme_before_the_first_row_from_that_row]`

### 3.2f Local API handlers that carry a member or a pin (2026-09-12)

Every localhost handler that accepts a membership id or a device pin, or turns a device pin into a
member, with its request fields and how the pin scheme reaches it. Routes are in
`access/local_api_routes.py`; handlers in `app/api/local_access_api_v2.py`. The dashboard calls
were confirmed by a read-only sweep of the dashboard branch `claude/fingerprints-quick-wins`; the
Access desktop UI (`tauri-ui/src`) was grepped in this repo. `[CODE]`

| Route → handler | Request fields | Member/pin handling | Scheme |
|---|---|---|---|
| `POST /api/v2/enroll/start` → `_handle_enroll_start` (dashboard fingerprint dialog, `tauri-ui` UsersPage) | `type`/`target`, `userId`, **`activeMembershipId`** (optional, preferred), `fingerId`, `fullName`, `device` | Backend `createUserFingerprint(activeMembershipId)` (a backend id, not a device pin), then `_request_running_ultra_sync(changed_ids={activeMembershipId})` | The targeted member sync converts: ACCOUNT → the person's pin, every row of the person, collapsed (§3.2b table). No handler change needed. |
| `GET /api/v1/access/enroll` → `_handle_v1_enroll` (deprecated) | `id`/`userId`, `fingerId`, `fullName`, `device` | Same path, membership resolved from `userId` | Same as above |
| `POST /api/v2/sync/now` → `_handle_sync_now` (dashboard) | optional hint `{entityType, entityId, operation, priority}`; `entityId` is an `activeMembershipId` when `entityType=ACTIVE_MEMBERSHIP` (the dashboard rewrites FINGERPRINT changes into that) | The hint only strips `membersVersion` (`sync_scope.apply_trigger_hint_to_version_tokens`); the resulting delta's membership ids flow into `_request_running_ultra_sync` | Converted downstream: targeted syncs, `changed_ids` pruning and revokes all translate membership → person pin (§3.2b) |
| `POST /api/v2/sync/fast-patch-bundle` → `_handle_sync_fast_patch_bundle` (dashboard) | the backend patch bundle verbatim; member items are `ActiveMemberUserDto` carrying `mainAccountId`; device items carry `pinScheme` | `db.apply_fast_patch_bundle` stores `main_account_id` and the membership→person link (§3.2d) and a `GYM_DEVICE` upsert records a pinScheme switch (§3.2e); impact membership ids go to `_request_running_ultra_sync` | Converted downstream, as above |
| `POST /api/v2/devices/{deviceId}/users/push` → `_handle_device_users_push` (PullSDK only) | `pin`, `name`, `cardNo`, `doorIds`, `templates` | RAW pin, written as given — no derivation exists | The caller must send the pin under the device's scheme. The per-finger push outcome is recorded with the device's scheme, so the upstream report names `mainAccountId` on an ACCOUNT device (§3.2b push report); if the device row cannot be read it is recorded `UNKNOWN` and not reported `[TEST: test_push_report_pin_scheme.py::test_an_unreadable_device_scheme_is_never_reported_as_a_membership]` |
| `POST /api/v2/devices/{deviceId}/users/delete` → `_handle_device_users_delete` (PullSDK only) | `pin` | RAW pin deleted as given | Caller's responsibility; no local state touched |
| `GET /api/v2/devices/{deviceId}/users` → `_handle_device_users_list` | — | Lists the terminal's raw pins | Display only |
| `GET /api/v2/dashboard/overview` → `_handle_dashboard_overview` (tauri-ui DashboardPage) | `limit` | Door-history pin → member for the feed | `HistoryPinResolver`: scheme of the event's device at the event's time (§3.2b inbound) |
| `GET /api/v2/push-history/{batchId}/pins`, `GET /api/v2/devices/{deviceId}/mirror-plan`, `GET /api/v2/db/access-history`, `GET /api/v2/popup/poll` | — | Raw pins / stored rows / engine-enriched notifications, no pin → member mapping in the handler (`popup/poll` payloads are enriched by `_handle_allow`, which is converted) | Display only |
| `POST /api/v2/members/photo`, `POST /api/v2/members/mutation`, `POST /api/v2/enroll/retry-push` | `activeMembershipId` / `targetId` | Backend-side membership ids; no device pin | n/a |
| `GET /api/v2/sync/cache/users`, `GET /api/v2/members` (`_handle_members_roster`) | paging/filter | Cached rows; they now also carry `mainAccountId` | n/a |
| `POST /api/v2/devices/{deviceId}/force-resync` | — | `clear_device_sync_hashes` (UPDATE) + scheduler `force_resync` | n/a |

`[UNVERIFIED]` Whether any dashboard or UI screen calls `users/push` or `users/delete` with a pin: the
dashboard sweep found those routes only in code comments, and `tauri-ui/src` has no caller.

### 3.3 How ULTRA pushes to a *PullSDK* device (non-obvious)

For PullSDK devices, ULTRA has no push implementation of its own. It copies the device
payload, **overwrites `accessDataMode` to `"DEVICE"`**, and hands that copy to a private
`DeviceSyncEngine` instance so the existing push path can be reused.
`[CODE: ultra_engine.py, two sites — device_copy["accessDataMode"] = "DEVICE"]`

If you are ever tracing why a device is being synced in a mode it is not in, this is
why. The protocol guard still fires inside that reused engine — which is exactly why
the standalone path uses `_run_standalone_full_sync` → `push_roster` instead.

### 3.4 ULTRA authoritative revocation — source of truth and delivery semantics

An **authoritative revocation** is not an ordinary member change. It travels as a
separate `revoked_ids` set from the accepted backend change through `MainApp`,
`UltraEngine`, `UltraSyncScheduler`, and the worker; where the same ID is also changed,
revocation wins. `[CODE: app/ui/app.py::_member_sync_dispatch_ids,
::apply_fast_patch_bundle; app/core/ultra_engine.py::request_sync_now]`
`[TEST: test_fast_patch_runtime.py::test_request_running_ultra_sync_gives_revocation_precedence;
test_authoritative_revocation_pipeline.py::test_revocation_takes_precedence_over_incoming_changed_id]`

There are only two authoritative sources:

- A fast-patch `ACTIVE_MEMBERSHIP` `ENTITY_DELETE`, but only when its item index is in
  the patch result actually committed by the local DB transaction. Rejected stale
  deletes, duplicate bundles, and rolled-back items cannot reach a device. Ambiguous
  result accounting schedules reconciliation rather than guessing which item applied.
  `[CODE: db.py::apply_fast_patch_bundle; app.py::apply_fast_patch_bundle]`
  `[TEST: test_fast_patch_db.py::test_apply_fast_patch_bundle_reports_only_transactionally_applied_item_indexes,
  ::test_apply_fast_patch_bundle_rolls_back_earlier_items_when_later_item_fails;
  test_fast_patch_runtime.py::test_runtime_stale_membership_delete_does_not_revoke_newer_local_member,
  ::test_runtime_mixed_bundle_routes_only_transactionally_applied_item]`
- A successful delta/full roster response whose authoritative member IDs prove that a
  previously shadowed member is absent. Cache deletion and shadow diff consume the
  **same validated authoritative-ID outcome**. Malformed authority, an inconsistent
  delta, or the H-006 empty-roster guard refuses cache/shadow deletion and physical
  revocation, then clears `membersVersion` and `membersUpdatedAfter` so the next request
  retries with a full member refresh. Safe, validated upserts may still be applied.
  `[CODE: db.py::_resolve_authoritative_member_ids, ::save_sync_cache_delta;
  app.py::_apply_member_shadow_sync, ::_run_sync_once]`
  `[TEST: test_authoritative_revocation_pipeline.py::test_cache_and_shadow_share_one_authoritative_id_contract,
  ::test_full_h006_cache_refusal_preserves_shadow_and_emits_no_revocations,
  ::test_main_sync_h006_refusal_dispatches_no_revocations_and_clears_member_tokens,
  ::test_main_sync_inconsistent_delta_dispatches_only_accepted_safe_upsert]`

For a connected, usable `ZK_STANDALONE` ULTRA worker, an accepted targeted request is
put on the worker queue immediately after the sync/fast-patch DB work succeeds. When
the worker drains it, an owned PIN is deleted first. If whole-user delete is unsupported,
fails, or is not affirmatively confirmed, the worker neutralises the user with
`enabled=false`, blank card and name, and confirmed removal of every fingerprint slot
tracked in `device_sync_state`. Ambiguous or contradictory SDK results confirm nothing.
Only confirmed deletion or complete neutralisation atomically clears that PIN's
`device_sync_state` and `device_content_mirror` rows; failure retains both for retry.
`[CODE: ultra_engine.py::_run_standalone_member_revoke,
::_remove_standalone_pins; db.py::clear_device_revocation_state]`
`[TEST: test_standalone_revoked_pin_removal.py::TestImmediateAuthoritativeRevoke,
::TestRemovalResultContract; test_db_standalone_revocation_state.py;
test_zk_standalone_template_removal.py]`

Ownership is a safety boundary. A `device_sync_state` row alone is **not** ownership
proof: ownership requires the durable `ownership_confirmed=1` bit, set only after an
affirmatively successful MonClub push and sticky across later failed updates. On
installed databases, `last_ok=1` or a recorded `pushed_finger_ids` set is conservative
migration evidence; ambiguous legacy rows remain unconfirmed. A failed first push
therefore cannot authorize deletion or neutralisation of a colliding manually managed
user on a shared MB2000. Without this affirmative proof, the worker makes **no
destructive SDK call**, writes a critical log for `MEMBER_REVOKE_OWNERSHIP_MISSING`,
emits warning-level telemetry with the same event name, and schedules full
reconciliation. Full reconciliation also fails closed before ordinary roster I/O when
an explicit revoke has a recorded but unconfirmed attempt. Such an unowned PIN is
intentionally left untouched for alert/reconciliation investigation.
Force-resync commands invalidate content hashes and retry status without deleting
ownership or pushed-finger evidence, so a later full pass can still reconcile stale
revoked credentials.
`[CODE: ultra_engine.py::_run_standalone_member_revoke]`
`[TEST: test_standalone_revoked_pin_removal.py::
TestImmediateAuthoritativeRevoke::test_unowned_pin_is_not_touched_and_requests_full_reconciliation]`

Full reconciliation is the recovery route, not the primary revoke route. Separate
physical-revocation and roster-exclusion ownership, with lock-guarded `ACTIVE` and
`RETRY` phases, keeps a revoked member out of stale roster snapshots while avoiding
duplicate deletion and preserving work across targeted/full-sync and dead-worker races.
A compound full-refresh-plus-revocation request is one worker full-sync command; a
revoke-only change remains an immediate targeted command. PullSDK and standalone paths
retain authoritative revocation ownership across missing, dead, disconnected, or
otherwise unusable workers until physical removal is confirmed.
`[CODE: UltraDeviceWorker.request_member_revoke, ::request_full_sync,
::_drain_pending_full_sync; UltraEngine.request_sync_now;
UltraSyncScheduler._sync_all]`
`[TEST: test_ultra_sync_scheduler.py::test_ultra_engine_full_refresh_routes_revocation_as_one_full_command,
::test_ultra_engine_revoke_only_still_routes_immediate_member_command,
::test_failed_dependent_full_retains_exclusion_until_eventual_success,
::test_ultra_sync_scheduler_no_worker_additive_pull_device_keeps_revocation_pending,
::test_ultra_sync_scheduler_preserves_standalone_revocation_until_worker_replacement,
::test_disconnected_standalone_revoke_is_requeued_with_revoke_intent]`

**Latency and acknowledgement boundary.** A local HTTP/IPC dispatch acknowledgement
confirms only that dispatch was accepted/queued; it does **not** mean the turnstile has
already mutated. Physical latency depends on worker wake-up, SDK/device round trips,
delete-to-neutralise fallback, retries, and network/serial conditions. No production
SLA is established. Disconnected/unusable devices retain retry ownership for recovery.
`[CODE: app.py::apply_fast_patch_bundle; UltraEngine.request_sync_now;
UltraDeviceWorker._run_standalone_member_revoke]`
`[TEST: test_fast_patch_runtime.py::test_runtime_applied_membership_delete_routes_revocation;
test_ultra_sync_scheduler.py::test_disconnected_standalone_revoke_is_requeued_with_revoke_intent]`

The command and retry path is proven in source and automated tests, but physical delete,
neutralisation, retry timing, and end-to-end latency have not been exercised on Gym T's
installed MB2000/standalone firmware and wiring. They remain
`[UNVERIFIED — HARDWARE-GATED]`; there is deliberately **no `[FIELD]` claim** until that
site validation is recorded.

### 3.5 Door-history upload — verdicts, the unresolved retry bound, and expiry (2026-09-12)

**Where it runs.** On every sync tick that starts — logged in, no previous tick still running;
`_sync_tick` returns early otherwise — and in every mode, the tick's `work()` calls
`DeviceAttendanceMaintenanceEngine.run_blocking`, which uploads **one** batch — the
`UPLOAD_BATCH_SIZE` (200) oldest due rows (`list_pending_access_history_for_sync`, `ORDER BY
id`) — then expires, then prunes. The tick interval is the backend's
`agentSyncBackendRefreshMin` (default 30 min), else local `sync_interval_sec` (default 60 s),
with the fast failure-retry schedule of §3.6 after a failed `getSyncData`. A retry tick also
runs this: the upload returns at once while offline, but the expire and prune passes run on
every started tick. `[CODE: app.py::reschedule_sync_timer, ::_sync_tick;
device_attendance.py::run_blocking, ::_sync_pending_history]`

**How each outcome is persisted.** `_parse_upload_response` is unchanged in behaviour; only what
happens to its retryable list is new.

| Outcome | Row becomes | Counts toward expiry |
|---|---|---|
| Named in `successIds` (or no lists, `ok` true, `failedCount` 0 — e.g. an old backend's bare `"DONE"`) | `SYNCED` | — |
| Named in `failedIds` (any `_RETRY_TOKEN_KEYS` key) | `FAILED_RETRYABLE` via `mark_access_history_unresolved`: `backend_unresolved_count` +1, delay `300 s × 2^(n−1)` capped at `UNRESOLVED_RETRY_MAX_SECONDS` (24 h) | **yes** |
| Retryable but **not named** (`ok` false with no lists; rows left over when `failedCount` > 0) | `FAILED_RETRYABLE`, fixed 300 s | no |
| Named in `terminalFailedIds` | `FAILED_TERMINAL` | — |
| HTTP 400 | per-row isolation, then the rows above apply per row | as above |
| 5xx, timeout, network | `FAILED_RETRYABLE`, fixed 300 s | **no** |

`[CODE: device_attendance.py::_mark_retryable, ::_named_retry_row_ids;
db.py::mark_access_history_unresolved]`
`[TEST: test_access_history_unresolved_bound.py]`

`backend_unresolved_count` is a separate column because `backend_attempt_count` and
`backend_failure_count` both rise on outages too — a bound on either would expire real events
during a long backend outage. `[CODE: db.py::init_db, the _ensure_column for it]`

**What the backend puts in each list** (monclub_backend `GymAccessController`
`bulkSaveGymAccessHistory`, branch `claude/door-event-terminal`). Terminal: the row carries no
identifier, or **every** person id it carries (`userId`, `mainAccountId`) is a positive id naming
no row — user and account ids come from forward-only sequences, so a deleted one never returns.
Retryable: a person who exists but does not resolve on the gym's own-plan roster (lapsed with
the membership deleted, or on a family-shared plan), a non-positive id (this client's synthetic
offline-pending ids, `db.py::_synthetic_negative_id`), and every PIN-only row. `[CODE: backend]`

**Expiry.** `expire_unresolved_access_history` moves a row to `FAILED_TERMINAL` only when it is
`FAILED_RETRYABLE` **and** has ≥ `UNRESOLVED_MIN_VERDICTS_TO_EXPIRE` (3) explicit verdicts **and**
is older than `history_retention_days` (default 30). The reason is written to
`backend_last_error`. `prune_access_history` is unchanged: its `COALESCE(backend_synced_at,
created_at)` ages an expired row on `created_at`, so an expired row is deleted **in the same
pass** — the same lifetime a `SYNCED` row gets. A row that only ever failed on outages is never
expired or pruned. Expiry runs **only** in `run_blocking`, deliberately: `realtime_agent.py`
also calls `prune_access_history` every 200 history writes, but that call only deletes what is
already `SYNCED`/`FAILED_TERMINAL`, and the tick — which reaches expiry on every started tick in
every mode — is enough to bound the queue. `[CODE: realtime_agent.py, the `_writes % 200` prune]`
Both functions compare `julianday('now')` (UTC) with a local-time
`created_at`, so ages read low by the UTC offset; they agree with each other. `[CODE]`
`[TEST: ::test_expiry_needs_the_verdict_floor_and_the_retention_age_together,
::test_a_row_the_backend_keeps_rejecting_is_expired_and_pruned_end_to_end]`

**Wire compatibility.** `_parse_upload_response`, `_coerce_id_values` and `_safe_int` are
source-identical (`ast.get_source_segment`) in `access_1.4.30`, `access_1.4.31`,
`access_1.4.33` and `master` 7e2c2d3, and every one of those `prune_access_history` deletes
`FAILED_TERMINAL`. Installed clients therefore stop retrying — and later prune — a backend
terminal verdict with no release. They do **not** get the bound: an installed client still
retries a backend-retryable row every tick, indefinitely. `[CODE]`
`[TEST: ::test_deployed_client_routes_every_verdict_class_of_the_new_backend,
::test_old_done_backend_acks_every_row_and_never_counts_a_verdict]`

`[UNVERIFIED]` The two constants (24 h cap, 3-verdict floor) are policy, not measurements. No
gym's client database has been observed holding `FAILED_RETRYABLE` rows: the three gym-45
`access.db` copies measured on 2026-09-12 hold none, and the gym-58 backlog reported in review
was inferred from backend history (804 rows / 18 users whose memberships were since deleted),
not read from a client queue.


### 3.6 The sync timer and the headless loop (2026-09-18)

**The headless loop.** `MainApp.mainloop` runs every `after()` callback on the process main
thread (`run_app` / `access.bootstrap.run_access_app`). While nothing is due it waits on a
`threading.Condition` (`_sched_lock`) until the earliest deadline, asking for at most
`_SCHED_MAX_SLEEP_SEC` (50 ms); `after()`, `quit()` and `destroy()` notify it, so work posted from
another thread and a stop are picked up in well under a millisecond, not at the bound. When a
callback is already due — typically one a callback just posted with `after(0, …)`, whose notify
nobody was waiting for — it yields with `time.sleep(_SCHED_MIN_SLEEP_SEC)` instead. On this
Windows build a `Condition.wait` rounds up to the ~15.6 ms timer tick (`wait(0.001)` measured
median 15.5 ms, `wait(0.05)` ~62 ms) while `time.sleep(0.001)` sleeps ~1.6 ms (CPython ≥ 3.11
uses a high-resolution timer); `time.monotonic` itself is `GetTickCount64`, 15.6 ms resolution,
so a timed callback can run up to about one tick late, as before. The sleep floor caps a callback
that re-schedules itself with `after(0, …)` at a few hundred passes/s — no busy spin. Callbacks due in the same pass still run in
insertion order, outside the lock; a raising callback is logged and skipped. Deadlines use
`time.monotonic()`, so wall-clock jumps do not move them (the daily 22:00 check,
`_daily_sync_check`, reads the wall clock itself, once a minute). `[CODE: app.py::mainloop,
::after, ::_init_scheduler, ::_wake_scheduler]` `[TEST: test_mainloop_scheduler.py, incl.
::test_after_zero_from_inside_a_callback_runs_within_a_few_ms]`

Before 2026-09-18 the loop's only wait sat after its `while`, so it re-scanned continuously:
~97–99 % of one core when idle, and — through the GIL — another Python thread's 1 ms sleep woke
~14.5 ms late and its pure-Python work ran ~2× slower. After: 0–0.9 % of a core, 0.6–0.7 ms.
Those figures come from a one-off harness (not in the repo) on the development PC, 32-bit
Python 3.11, 3 runs × 5 s; the repo pins only the bound. `[TEST:
test_mainloop_scheduler.py::test_idle_loop_does_not_spin — < 0.2 s CPU per 1 s idle]`
`[UNVERIFIED]` The effect on real door threads on a gym PC has not been measured.

**The periodic sync timer.** One timer, `_sync_after_id`. Every `_sync_tick` first re-arms it to
the healthy interval (`_sync_base_interval_sec`: `agentSyncBackendRefreshMin` × 60, else
`sync_interval_sec`, floor 10 s). The worker's `finally` posts `_on_sync_work_finished` to the
loop thread, which decides the rest `[CODE: app.py::_sync_tick, ::_on_sync_work_finished]`.
Startup arms it through `_ensure_sync_timer` (`access/runtime.py`, 500 ms), which only arms when
nothing is armed: a plain re-arm there used to replace the ~15 s retry of a startup tick that had
already failed fast (no network yet at boot) with a full 30 min wait.
`[TEST: ::test_the_startup_rearm_does_not_replace_a_fast_failure_retry]`

`_sync_fail_count` counts consecutive failed sync *attempts*: `getSyncData` itself, **or** any
step after it inside the same fetch-and-apply `try` in `work()` (`save_sync_cache_delta`, the
member shadow sync, `save_version_tokens`, `_request_running_ultra_sync` …). A post-fetch local
error therefore also runs the fast schedule. Such a retry re-sends the un-advanced version
tokens and re-asks the running ULTRA workers for a sync, which skip each device while its roster
fingerprint is unchanged (`ultra_engine.py` `_sync_all`, "fingerprint unchanged") — local CPU,
no device I/O. `[CODE]` The table below says "failed" in that sense:

| Outcome of the finished sync | Timer | Re-run |
|---|---|---|
| the attempt failed (`_sync_fail_count` > 0) | re-armed to `sync_retry_delay_sec` | none now; the pending request rides the retry tick |
| succeeded | the healthy timer armed at the tick's start stands | once, if a request arrived mid-sync — after the ULTRA reconnect deferral, below |
| a newer sync already started before the callback ran | untouched | untouched |

**Failure-retry schedule** (`app/core/sync_retry.py`): after 1, 2, 3, 4, ≥ 5 consecutive failures
the next attempt comes after 15, 30, 60, 120, 300 s, each ±20 % jitter, never above 300 s and
never above the healthy interval. With a 30 min interval that is ~12.6 attempts/h per PC during
an outage, against ~6/h before (1800 s once, then `min(base·2ⁿ, 600)` + 0–10 s, because the
timer was re-armed at tick start from the *previous* tick's count). `[CODE]`
`[TEST: test_sync_retry_and_rerun.py::test_retry_timeline_over_consecutive_failures,
::test_first_retry_after_a_failure_is_about_15s_not_a_full_interval,
::test_without_the_backend_setting_the_base_is_sync_interval_sec]`

**429 / `Retry-After`.** `get_sync_data` raises `MonClubApiHttpError` (a `MonClubApiError`, same
message) with `status_code`, and for 429/503 `retry_after_sec` parsed as delta-seconds (the
HTTP-date form is ignored). The backend's `RateLimitFilter` sends 429 with integer
`Retry-After` (per-account bucket, 200 requests / 60 s by default). A `Retry-After` longer than
the scheduled step wins, up to the healthy interval. Only ASCII digits are accepted (`str.isdigit`
also passes `²`, which `int()` rejects); 10+ digits count as "very long" and clamp to the
healthy interval, so a malformed header can never replace the HTTP error with a `ValueError`. `[CODE: monclub_api.py::get_sync_data;
backend RateLimitFilter.write429]` `[TEST: ::test_get_sync_data_429_carries_status_and_retry_after,
::test_a_429_retry_after_stretches_the_retry]`

**A sync requested mid-sync re-runs once.** A tick that finds `_sync_work_running` with a
pending request context (sync now, change detector, daily 22:00, fast patch, auth login, hard
reset) sets `_sync_rerun_requested`; the context stays in `_pending_sync_context` and the one
re-run consumes it — the latest request wins, exactly as `request_sync_now`'s preserve rule
already decided. A plain timer tick sets nothing. Never two workers. `[CODE]`
The re-run does not start inside the previous sync's ULTRA reconnect deferral: a successful
`SYNC_NOW_API` / `CHANGE_DETECTOR` / `FAST_PATCH_BUNDLE` sync defers a *disconnected* ULTRA
worker's reconnect by 20 s (`_defer_ultra_reconnects`), and back-to-back re-runs during a stream
of dashboard edits would re-defer it for the whole stream — no PC-side RTLog or QR/TOTP rescue at
that terminal meanwhile. So an *automatic* re-run waits until `_ultra_defer_until_mono` +
`_RERUN_AFTER_ULTRA_DEFER_MARGIN_SEC` (5 s; the worker re-checks its connect deadline at least
once a second). An explicit one (`is_explicit_user_sync`: Sync data, hard reset, daily) runs at
once — those do not come in streams. A request arriving during the wait starts a sync at once
with the latest context, and the waiting re-run tick (`_sync_rerun_after_id`) is cancelled as
soon as any tick starts a sync, so it cannot fire later as a stray TIMER sync.

**A waiting explicit sync is never replaced by an automatic request.** `_pending_sync_context`
is one slot; `request_sync_now` and the change detector (`change_detector.py::_poll_once`, which
writes the slot from its own thread) keep a pending explicit context when the new request is
automatic — otherwise a per-edit dispatch landing after a "Sync data" click would silently turn
the click's full sync (which also pushes in manual-sync mode) into an automatic one. Among
automatic requests, and among explicit ones, the latest still wins. `[TEST:
::test_an_automatic_request_does_not_replace_a_waiting_explicit_one,
::test_a_request_during_the_rerun_wait_leaves_no_stale_tick,
::test_an_explicit_rerun_is_not_delayed_by_the_ultra_deferral;
test_change_detector.py::test_a_waiting_explicit_sync_is_not_replaced]` `[TEST: ::test_a_rerun_waits_for_the_previous_syncs_ultra_reconnect_deferral,
::test_a_rerun_after_an_expired_deferral_starts_at_once]` `[UNVERIFIED]` Field delta-sync
durations and edit rates; the starvation regime was shown with a simulation, not on hardware.
`[TEST: ::test_a_request_during_a_running_sync_reruns_when_it_finishes,
::test_many_rapid_requests_coalesce_into_one_rerun, ::test_a_rerun_after_a_failed_sync_waits_for_the_retry]`

**Offline DEVICE-mode reconcile gate.** A tick whose `getSyncData` failed still reconciles
DEVICE-mode panels from the cached roster (`DeviceSyncEngine.run_blocking(changed_ids=None)`):
per PullSDK panel a connect, a full Pin read and `SetDeviceParam` writes; a FULL_REPLACE panel is
wiped and re-pushed. So the fast retries must not each do it: an *automatic* failed tick
dispatches it only if the tick that last dispatched it **started** at least
`_OFFLINE_RECONCILE_INTERVAL_SEC` = 600 s ago (`_last_tick_device_reconcile_mono`) — the old
outage cadence, whatever the healthy interval. A healthy timer tick starts at least one interval
after the previous tick, so with the 30 min default a failure on it still reconciles exactly as
before. Explicit syncs (`is_explicit_user_sync`) and every successful tick are unchanged.
AGENT and ULTRA devices, ZK_STANDALONE terminals, RTLog and QR/TOTP rescue get no device I/O from
a failed tick. `[CODE: app.py::_offline_device_reconcile_due and its call in _sync_tick's work()]`
`[TEST: ::test_retry_ticks_during_an_outage_do_not_repeat_the_device_reconcile,
::test_the_first_failed_healthy_tick_after_a_reconcile_still_reconciles,
::test_at_30_min_an_outage_still_reconciles_every_600s_as_before,
::test_a_short_healthy_interval_does_not_raise_the_outage_reconcile_rate,
::test_an_explicit_sync_still_reconciles_while_the_backend_is_down]`

Simulated 6 h outage (virtual clock, the real `sync_retry_delay_sec`, 2 s per failed tick; old =
the fecae45 formula), failed ticks/h and DEVICE reconciles/h:

| `agentSyncBackendRefreshMin` | old ticks = reconciles | new ticks | new reconciles |
|---|---|---|---|
| 1 | 6.5/h | 58.3/h | 5.8/h |
| 2 | 6.3/h | 30.0/h | 6.0/h |
| 5–15 | 6.0–6.2/h | 13.2/h | 4.7/h |
| 30 (all four gyms) | 5.7/h (4 in hour 1) | 13.2/h (16 in hour 1) | 4.7/h (5 in hour 1) |

So panels see no more outage reconciles than before, at any setting. `[TEST: simulation, not in
the repo; UNVERIFIED on hardware]`

**Backend traffic during an outage, per PC:** one `getSyncData` per failed tick, plus one
`POST /public/account/refresh` whenever the refresh deadline has passed (a failed refresh does
not advance it, so every retry then pays both). The retry delay never exceeds the healthy
interval, so retries are never *slower* than healthy polling — and at 30 min they are faster:
~16 attempts in the first outage hour, then ~12.6/h, against 4 and ~6/h before (at 1 min, ~60/h
as when healthy, against ~6.5/h before). A revoked session (401) retries on the same schedule
indefinitely, as it did at ~600 s before. `[CODE]`

Against the backend's limits: the per-account `RateLimitFilter` bucket is 200 requests / 60 s
(`application.yml` defaults), and the Hikari pool is 25 connections (`DB_HIKARI_MAX_POOL`
default). The fleet is 5 devices on a handful of PCs (`[UNVERIFIED]` exact count). The busiest
retry minute is the first one: ≤ 2 requests (sync + refresh) per PC at ~15 s, i.e. a gym with 3
PCs sends ≤ 6 requests in that window — ~3 % of its bucket; steady state is ≤ 2 requests per PC
per ~300 s. Each request holds a pool connection only while the backend handles it, so even if
every PC of every gym retried at the same instant after a backend restart, that is ≤ 2 × the PC
count concurrent connections, far below 25; the ±20 % jitter spreads the first retry over
12–18 s. `[CODE: backend RateLimitProperties, application.yml; client sync_retry.py]`

**A worker thread that cannot start** (`RuntimeError: can't start new thread` at the 32-bit
ceiling) no longer leaves `_sync_work_running` True forever: the flag is cleared, the request
context restored and a retry armed. `[TEST: ::test_a_worker_that_cannot_start_does_not_wedge_the_sync]`

`[UNVERIFIED]` The worker has no overall deadline. `requests`' `timeout` (60 s for
`getSyncData`) bounds each socket wait, not the whole call, and a device or database call inside
the worker that never returns would keep `_sync_work_running` True — with every later sync
skipped and its request left pending. Not observed; not guarded.

### 3.7 Optional content sync (2026-09-18)

`OptionalContentSyncScheduler` (daemon thread, started 10 s after launch by
`access/runtime.py`, first cycle 30 s later, then every `optional_data_sync_delay_minutes`,
floor 60 min) POSTs version markers to `/api/v1/manager/gym/access/v1/content/sync` and stores
the gym's upcoming events, products and active deals in `optional_upcoming_events`,
`optional_products`, `optional_deals` (image **URLs** only — nothing is downloaded), with the
markers in `optional_sync_state`. `[CODE: optional_content_sync.py, db.py::replace_optional_*]`

Until 2026-09-18 it had never authenticated: it sent `Bearer <AuthTokenState repr>` — the
email, access token and refresh token in clear — and its marker read and write used names the
database functions do not have, so it would have re-downloaded every section every cycle. It now
sends `auth.token`, reads and saves the markers, and advances a section's marker only once its
rows are stored. `[TEST: test_optional_content_sync_auth.py]`

**Nothing reads those tables** — no local API route, no TV code, no Tauri UI references them.
`[CODE: grep of app/, access/, tv/, shared/, tauri-ui/src for the table and list_* names]` The
scheduler has no token refresh of its own and is never `stop()`ped (it is a daemon thread).
`[CODE]`

---

## 4. Protocol resolution — how a device gets its driver

Single construction point: **`device_driver.py::get_driver(device_payload)`**. Engines
call this instead of constructing a driver class directly. `[CODE]`

Resolution order `[CODE: device_driver.py::_resolve_with_source]`:

1. **Local override map** — the `MONCLUB_DEVICE_PROTOCOL_OVERRIDES` env var, JSON like
   `{"12": "ZK_STANDALONE"}`, or `set_protocol_override(device_id, protocol)`. This is
   the on-site bring-up path and the kill-switch: it works without a backend deploy and
   reverts instantly. Source reported as `override`.
2. **Backend payload** — `deviceProtocol` (camelCase) or `device_protocol`. Source
   reported as `payload`.
3. **Default** — absent, empty, or unrecognised ⇒ `ZK_PULLSDK`. Source `default` or
   `unrecognised:<value>`.

Standalone is matched against an alias set, not one literal: `ZK_STANDALONE`,
`STANDALONE`, `ZKEMKEEPER`, `ZKEM`, `PUSH`, `ADMS`, `MB2000`.
`[CODE: _STANDALONE_ALIASES]`

### Why the fallback is PullSDK, and why the *source* matters

Defaulting to PullSDK means no gym onboarded before `deviceProtocol` existed can
regress. But it also means a misconfigured MB2000 is silently routed to a DLL that
cannot talk to it, and the only symptom is a generic connect failure.

So `get_driver` logs the resolved protocol **and which input chose it**, once per device
and again on any change; and when the payload's `model` looks like an MB2000 but the
protocol resolved via `default`/`unrecognised`, it emits an explicit warning.
`[CODE: _log_driver_choice]`

> An explicitly-supplied, recognised `ZK_PULLSDK` is `payload`, **not** a fallback.
> Reporting it as a misconfiguration would alarm every healthy PullSDK gym. `[CODE]`

A protocol with no driver raises `UnsupportedDeviceProtocolError` rather than falling
back — a standalone terminal must never be silently driven down the PullSDK path.
`[CODE]`

---

## 5. Capability flags — the extension mechanism

Do not branch on model. Where a capability flag exists, do not branch on protocol in
feature code either. Gate on the **flag**, so a future driver only has to declare
itself:

| Flag | `PullSDKDevice` | `ZKStandaloneDevice` | Meaning |
|---|---|---|---|
| `supports_transaction_table` | `True` `[CODE]` | `False` `[CODE]` | Device has a readable/pruneable transaction table. When `False`, `read_transaction_rows` / `get_table_count` / `delete_all_transaction_rows` are **inert** — callers must skip the device, not act on their return values. |
| `supports_open_door` | absent ⇒ callers default `True` | **per-device switch**, family default `True` `[CODE]` | Whether the driver may issue a door-open. On the standalone family it is resolved per instance: env `MONCLUB_ZK_STANDALONE_OPEN_DOOR` > persisted local switch (`db.device_local_settings`, projected as `openDoorEnabled`) > family default. See §5.1 and §7. |
| `owns_event_source` | — | `True` `[CODE]` | Driver owns its own event delivery (push) rather than being polled. |
| `supports_device_params` | — | `False` `[CODE]` | `get_device_param` / `set_device_param` are meaningful. |

Callers read these as `getattr(drv, "flag", True)` so a driver predating a flag keeps
the old behaviour. `[CODE: device_attendance.py, ultra_engine.py,
local_access_api_v2.py]`
`[TEST: test_device_sync_protocol_guard.py::TestTransactionTableCapability]`

**A flag being `False` does not mean "unimplemented".** `ZKStandaloneDevice._do_open_door`
implements the real `ACUnlock` call; `supports_open_door` only decides whether the app
is *allowed* to make it. See §7.

### 5.1 The standalone door switch — how `supports_open_door` is set (2026-09-04)

`[CODE: zk_standalone.py::resolve_open_door_switch, ::apply_open_door_switch]`
`[TEST: test_mb2000_force_open.py::TestOpenDoorSwitchResolution]`

| Priority | Source | Value | Where it comes from |
|---|---|---|---|
| 1 | `env` | `MONCLUB_ZK_STANDALONE_OPEN_DOOR` | `1/true/yes/on/all` ⇒ ON for every standalone terminal; `0/false/no/off/none` ⇒ OFF for every one; a device-id list (`8,12`) ⇒ ON for those ids, OFF for the rest. Blank ⇒ no override. Anything else is **logged and ignored**, never read as ON or OFF. Parsed per call. |
| 2 | `local` | `db.device_local_settings.open_door_enabled` | The operator's per-device switch: Devices page → control panel → « Commande d'ouverture », or `GET/POST /api/v2/devices/{id}/open-door-switch` (`{enabled: true|false|null}`, null clears). Persisted **outside** the `sync_*` tables, so it survives every sync replace and logout. Projected into the device payload as `openDoorEnabled` by `db.list_sync_devices_payload` / `get_sync_device_payload`, which is how it reaches `get_driver(device_payload)`. |
| 3 | `default` | `_OPEN_DOOR_FAMILY_DEFAULT = True` | **Operator decision 2026-09-04**: ON for the whole standalone family. Before this the flag shipped OFF and the desk was refused on every press `[FIELD: 2026-08-30, 13× DOOR_OPEN result=409_unsupported + 8× 429_cooldown in ten seconds]`. |

- The effective value is resolved at driver construction — i.e. at every worker
  connect — and announced as `[T] DOOR_OPEN_SWITCH worker=ZKEM:<id> enabled=… source=…`.
  `[CODE: ZKStandaloneDevice.__init__ → apply_open_door_switch]`
- The POST endpoint applies the new value to the **running** driver without a
  reconnect and stamps the worker's device snapshot, so a reconnect before the next
  sync refresh re-resolves the same value. `[CODE: local_access_api_v2.py::
  _handle_device_open_door_switch_set]` `[TEST: TestLocalApiOpenDoorSwitch]`
- Both endpoints refuse non-standalone protocols with `409 + unsupported: true` — the
  PullSDK family has no such flag and always opens. The switch endpoints are the one
  place that branches on protocol; every consumer of the *result* still gates on the
  flag. `[CODE]`
- The worker snapshot exposes `supports_open_door` **and** `open_door_source`
  (`env|local|default`, `None` on drivers without the switch). `[CODE: get_snapshot]`
- The switch says nothing about hardware: `ACUnlock` releasing the MB2000 turnstile is
  still **`[UNVERIFIED]`** — see §7.

---

### 5.x `deviceCapabilities.fingerprintTemplateVersion` — live since 2026-09-11

The dashboard dropdown (Device settings → **Fingerprint template** → AUTO / ZKFinger 9
/ ZKFinger 10) writes `{"fingerprintTemplateVersion": 9|10}` into the device's opaque
`deviceCapabilities` JSON.

**It was inert from the day it shipped**, for two compounding reasons `[CODE]`:

1. the per-pin desired hash hashed the RECORD's `templateVersion`, never the effective
   one — so flipping the dropdown moved no pin's stored hash, `device_sync` reported
   `sync skip: fingerprint unchanged`, and **nothing was pushed at all**;
2. even when a push did happen, the warm L1 firmware-profile cache reused its learned
   `(template_table, body_index)` combo without consulting the override — and that
   cached table is precisely what the setting is meant to choose.

Both are fixed:

- `DeviceSyncEngine._resolve_template_version_override` is the **single** source, used
  by the push path and by BOTH desired-hash paths. They must agree: a divergence at any
  one site makes the stored hash permanently disagree with what the push produced, and
  the pin is then re-pushed every cycle forever. `[TEST:
  test_template_version_override_activation.py::TestTheResolverIsTheSingleSource]`
- the effective version enters `_compute_desired_hash`, which propagates into the
  device checksum automatically. **The checksum HEADER was deliberately NOT widened** —
  doing both would force a full roster re-push on every device carrying the setting,
  including ones where no member's effective version changed. `[TEST:
  ...::test_the_header_itself_was_not_widened]`
- a CHANGE of bias drops the cached combo **once** (`reset_firmware_template_combo`),
  and the winning combo is persisted with the bias it was learned under, so this
  cannot re-probe on every sync. `[TEST: ...::test_bias_re_probe_happens_only_once]`

The probe fallback is unchanged: it still tries both tables, so a wrong setting costs
one extra SDK call, never a member who cannot badge in.

> **Release gate.** This retroactively activates a setting that has been inert since it
> shipped, so every stored value in the field is configuration nobody has ever seen take
> effect on real hardware. Before rollout: inventory which devices carry a non-null
> value and what it is, then pilot ONE device and verify with a REAL FINGER at a door.
> SDK success is not evidence the finger will match. `[UNVERIFIED]`

> **Expected on first sync after upgrade:** members on a device whose dropdown disagrees
> with their stored `templateVersion` get one re-push, logged by `FP_DELTA` as
> `field_change_counts={'tvo': N}`. Devices set to AUTO are untouched.

---

## 6. Two traps that have each cost a production release

### 6.1 The two-layer trap — `PullSDK` is not `PullSDKDevice`

`app/sdk/pullsdk.py` defines **two** classes. They are not interchangeable:

- **`PullSDK`** — the low-level `plcommpro.dll` wrapper (`get_device_data_rows`,
  `set_device_data`, `delete_device_data`). **No other driver implements this surface.**
  Constructed directly by `device_sync.py` and `local_access_api_v2.py`. `[CODE]`
- **`PullSDKDevice`** — the `DeviceDriver` implementation. Portable. This is what
  `get_driver()` returns.

Anything written against the low-level `PullSDK` class is **PullSDK-only by
construction**, and cannot be made portable by swapping in `get_driver()`. For those
handlers the correct answer is to **refuse, not route**:
`local_access_api_v2.py::_unsupported_for_protocol` returns **409 + `unsupported: true`**
— not 500, which told the operator the server had broken on a perfectly healthy
terminal. `[CODE]`

When a task says "add MB2000 support to X", first determine which layer X is written
against. If it is the low-level one, the work is a refusal or a genuine second
implementation — never a substitution.

### 6.2 The inert-patch rule — check the allowlist first

`DeviceSyncEngine._normalize_device` returns a **fixed allowlist dict**, and every
caller normalizes *before* `_sync_one_device` sees the payload. `[CODE]`

While that allowlist omitted `deviceProtocol`, `resolve_device_protocol()` answered
`ZK_PULLSDK`/`default` for an MB2000 — so a protocol guard placed downstream **could
never fire, while appearing to be correctly in place.**

> **Rule:** before adding a guard that reads a payload key, prove the key survives every
> normalization layer between the source and the guard. A guard on a stripped key is not
> a weak guard; it is no guard.

Both halves are pinned — the key survives normalization **and** the guard refuses
without ever constructing a PullSDK object.
`[TEST: test_device_sync_protocol_guard.py::TestNormalizationCarriesProtocol
and ::TestSyncOneDeviceRefusesNonPullSDK]`

`pinScheme` is on the allowlist for the same reason (2026-09-12). `_sync_one_device`, the
targeted `sync_member_on_connected_sdk` and `build_device_sync_fingerprint` all hand the
NORMALIZED dict to `_filter_users_for_device`, while the standalone roster passes the worker's
raw `self._device`. Without the key, an ACCOUNT device would have received MEMBERSHIP pins on
the PullSDK paths and ACCOUNT pins on the standalone path — the mixing §3.2b exists to prevent.
`[TEST: test_pin_scheme_gate.py::test_pin_scheme_survives_ingest_to_the_engine]`

---

## 7. Unverified and hardware-gated — do not treat these as known

Recorded so nobody assumes an answer exists. Proving one is a real result; update this
section when you do.

### `ACUnlock` on the MB2000 — the command is issued, the relay is `[UNVERIFIED — HARDWARE-GATED]`

`ACUnlock` is documented SDK-wide but has **never been confirmed on MB2000 hardware**:
no PASS of script 9 or 12 has been reported from the site. Since 2026-09-04 the command
is nevertheless **issued** — the switch is ON for the family by operator decision (§5.1)
— because a refused desk button with no way to turn it on was the worse failure
`[FIELD: 2026-08-30, 13× 409_unsupported in ten seconds]`. What replaces "ships off" is
*loudness*: `[CODE]` `[TEST: test_mb2000_force_open.py::TestDriverDoorCommand,
::TestLocalApiDoorOpenChain]`

- every attempt logs and emits `[T] DOOR_OPEN worker=ZKEM:<id> result=… delay_ds=… dur_ms=…`
  with `result ∈ {ok, false, exception, timeout, unsupported}` (`clamped=True` when the
  pulse was clamped, `source=` which switch level decided);
- a `False` from the terminal reaches the desk as HTTP 500 with a French message naming
  the FALSE return (`detail` keeps the raw string) — never as a silent success;
- the local API additionally logs `DOOR_OPEN result ∈ {200_ok, 409_unsupported,
  429_cooldown, 503_timeout, 500_failed}` keyed by `device_id`, so one grep shows the
  press, the refusal or the SDK answer;
- the door command goes through the driver's `_call()` like every other STA command, so
  the generation fence and wedge recovery are not bypassed — a hung `ACUnlock` is
  abandoned at the deadline (`result=timeout`, `ZKEM_STA_WEDGED`) and the next connect
  rebuilds the thread. `[TEST: ::test_wedged_acunlock_times_out_abandons_sta_and_reports_timeout]`

Verify with the script pack: `tools/mb2000_scripts/9_unlock_door.ps1` (minimal
one-shot) or `12_force_open_door.ps1` (sustained: repeat/interval, device info
before/after, `-Auto`, and a `logs/force_open_*.log` the operator can send back). Both
fire the identical `ACUnlock(mn, ds)` call. Listen for the relay **and** confirm the
turnstile physically releases: `ACUnlock` returning `True` with no release is a wiring
fault, not an SDK one.

**What stays unproven until the operator reports script 12 (or 9) PASS on site:**
whether `ACUnlock(1, ds)` returning `True` makes *this* turnstile release. This section
stays `[UNVERIFIED]` until then. Do **not** promote it on the strength of a `result=ok`
line in the app log — that proves the COM call returned `True`, nothing more. See
`zkemkeeper_guide.md` §8 for what script 12 does and does **not** establish (no
documented SDK maximum for the delay, no reason available on a `False` return, elapsed
ms is the COM call).

The pulse is converted `ms → deciseconds` and clamped to **1…600 ds (0.1…60 s)** — the
app's own ceiling, identical to the local API's `pulseSeconds` 1–60 and the PullSDK
driver's 1–60 s. The **firmware's true maximum is `[UNKNOWN]`**; no vendor document in
this repo states one, so none is claimed. `[CODE: _pulse_ms_to_delay_ds]`

### Which `verifyMethod` integer means what on MB2000 `[UNKNOWN]`

The value space **shifts** between the terminal's normal mode (`0`=password,
`1`=fingerprint, `2`=card) and multi-verify modes (`0`=FP, `1`=PIN, `2`=PW, `3`=RF), so
`0` is genuinely ambiguous. The driver maps both tables defensively and **always keeps
the raw value** in `rawRow`. `[CODE: _VERIFY_METHOD_SCAN_MODE]`

Do not write logic that depends on a specific integer until the mapping is confirmed on
the actual terminal.

### Other MB2000 unknowns `[UNVERIFIED — HARDWARE-GATED]`

Declared in `zk_standalone.py`'s own module docstring: in-process COM viability, event
field semantics, template portability, and the card-number space.

### Why fingerprint templates were refused `[UNKNOWN]`

Two candidate causes, **neither proven**:

1. The terminal's fingerprint store is full of enrolments carried over from the gym's
   previous software (they were never deleted).
2. Algorithm-version mismatch — a ZK9500 desk capture is v10.

The driver now reports `deviceFpVersion`, `templateVersion` and `fpStore=used/capacity`
on the connect line and on every refusal, which distinguishes the two.
`[CODE: _read_fp_version, _read_device_status, _warn_if_device_full]`

Until a connect line settles it, **do not state either as the cause.**

---

## 8. Deployment facts that are not code facts

- **32-bit Python is a hard requirement**, enforced at package time: `build_release.ps1`
  throws when `Requires32BitPython` is set and the interpreter is not 32-bit. Both
  `plcommpro.dll` and `zkemkeeper` are 32-bit.
  `[CODE: build_release.ps1, app/core/arch.py::require_32bit_python_for_32bit_dll]`
- **`zkemkeeper` is a COM server — shipping the DLL is not enough.** It must be
  **registered** (`regsvr32`, elevated, 32-bit) along with its dependencies.
  `[FIELD: an unregistered COM server was one of the two root causes of the MB2000
  outage; registering it on the client PC was part of the remedy]`
- **Backend base URL** is a single constant, `app/core/app_const.py::MONCLUB_BASE_URL`.
  Not runtime-configurable and not editable from the UI. `[CODE]`
- **On-site script pack**: `tools/mb2000_scripts/` (`0_MENU.ps1` plus 12 scripts — COM
  registration, device info, ZK9500 enrol, push, live monitor, unlock, backup/restore,
  portability test, force-open). Use these to establish ground truth on hardware
  **before** changing driver code. `[CODE]`

---

## 9. Verifying this guide

These are runnable, so "is this still true" is a command rather than a judgement.
Run them after completing the README development/test setup (`pip install -r
requirements-dev.txt`) and activating the project `.venv`; the system Python is not
expected to carry the application's test dependencies.
The snippets below use PowerShell/bash quoting; replace single quotes with double
quotes when running them from cmd.exe.

```bash
python -m pytest tests/ -q --ignore=tests/_pydeps --ignore-glob='**/pytest_tmp_*' --ignore-glob='**/.tmp_pytest*' -W error::pytest.PytestUnhandledThreadExceptionWarning
```

`--ignore=tests/_pydeps` is **required** — that directory holds vendored third-party
packages whose own tests break collection. There is no `pytest.ini`, so the flag is not
applied for you. The two `--ignore-glob` flags skip the `tests/pytest_tmp_*` /
`tests/.tmp_pytest*` scratch directories that stale permission-denied temp folders leave
under `tests/` in some working copies; they are not part of the suite. Unhandled
background-thread exceptions are promoted to failures. Last run: **1847 passed** (2026-09-18,
branch `claude/access-loop-retry-fixes`: §3.6 loop and sync timer, §3.7 optional content; with
the CLAUDE.md command `python -m pytest tests/ -q --ignore=tests/_pydeps`, 32-bit `.venv`
Python 3.11, `MONCLUB_ACCESS_DATA_ROOT` set to an empty scratch folder; exit code 0). `[TEST]`

> **Run the suite with `MONCLUB_ACCESS_DATA_ROOT` pointing at an empty scratch folder.** It
> moves the whole data root (`app/core/utils.py::_candidate_data_roots`), so a test that forgets
> the `_DB_PATH` override below cannot reach the installed gym database. Measured this way,
> master `fecae45` gave **1764 passed, 7 failed**, not the 1771 recorded on 2026-09-13: the seven
> tests in `test_access_history_unresolved_bound.py` left `list_device_pin_scheme_switches`
> unpatched and passed only against an already-migrated — the installed — database, and
> `test_sync_handlers_schedule_expected_trigger_metadata` ran `DELETE FROM sync_version_tokens`
> on whatever database was active. Both are patched now (commit a87830b).
>
> **Many other test files still reach the default database.** Run one file at a time, each from
> a fresh empty `MONCLUB_ACCESS_DATA_ROOT` (2026-09-18, branch `claude/access-loop-retry-fixes`),
> 33 of the 121 `tests/test_*.py` files created `access/access.db` under that root — i.e. without
> the variable they open the installed database. Among them: `test_authoritative_revocation_pipeline`,
> `test_sync_observability` (`::test_main_app_initializes_scheduler_before_first_after`),
> `test_fast_patch_runtime`, `test_pin_scheme_gate`, `test_ultra_engine`,
> `test_ultra_sync_scheduler`, `test_zk_standalone_driver`, `test_device_sync_protocol_guard`,
> `test_standalone_*`, `test_account_pin_*`. All 121 pass alone. Whether each one only reads, or
> also writes, has not been established per test. `[TEST: the sweep; UNVERIFIED per-test writes]`

> **Any test that drives a full sync must use the documented `_DB_PATH` temp-database
> override.** Without it the run writes per-pin state into the developer's *installed*
> database, and a leftover `ownership_confirmed` row there then looks like a departed
> member to the next suite's revoke pass — which adds neutralise pushes and fails
> assertions far away from the cause. `_make_sync_worker` in
> `test_zk_standalone_driver.py` now also stubs `list_confirmed_device_sync_pins`, so a
> polluted database can no longer reach it; `get_conn()` does **not** commit ad-hoc
> writes, so clean up through `_run_db_write_sync` if you ever need to.

```bash
python tools/check_sql_arity.py
```

Release gate. Statically compares every literal `INSERT`'s column list against its
`VALUES` **terms** — not its `?` count, because `VALUES (?, 0, ?, datetime('now'))` is
valid and must not be flagged. It exists because a 59-column / 57-value `INSERT` shipped
in v1.4.20 and v1.4.21 and silently killed **every device sync, for every gym, on both
protocols**. `[CODE]`

Targeted checks for the rules in this guide:

```bash
python -m pytest tests/test_device_sync_protocol_guard.py tests/test_device_driver_factory.py tests/test_zk_standalone_driver.py tests/test_mb2000_force_open.py -q
```

To confirm §3.2 (the roster rule) still holds:

```bash
grep -rn "\.push_roster(" app/ --include=*.py
```

**Expected:** every match inside `app/core/ultra_engine.py` — currently four real calls
(`_run_standalone_full_sync`, `_run_standalone_member_sync`, the neutralise fallback in
`_remove_standalone_pins`, and the ACCOUNT revoke re-push in `_account_member_revoke`, §3.2b)
plus one docstring mention (`_build_standalone_roster`). A match in any other file means the rule has changed and
this guide is out of date.

Match on `\.push_roster(`, not the bare word: `push_roster` also appears in an
explanatory comment in `local_access_api_v2.py`, and a looser grep makes an intact rule
look broken.

To confirm §3.2c (the reconcile trigger is a flag, not a reason string):

```bash
grep -rnE "_MIRROR_RECONCILE_REASONS|bracket = reason" app/ --include=*.py
```

**Expected: no matches.** Any hit means the gate has been reverted to a reason-string
test that no producer can satisfy. Match on the *symbol* and the *assignment*, not on the
literals `user-sync` / `daily-forced-sync`: those still appear in the explanatory comment
above `_MIRROR_MAX_DELETE_FRACTION`, and a looser grep makes an intact rule look broken.

```bash
python -m pytest tests/test_mirror_reconcile_reachability.py tests/test_mirror_pushing_policy.py -q
```

To regenerate the door-open table in §3.1:

```bash
grep -rn "\.open_door(" app/ --include=*.py
```

---

## 10. Telemetry events (`[T]`)

`app/core/telemetry.py` emits one grepable line per event on the `zkapp.telemetry`
logger: `… | INFO | [T] NAME k=v k=v`. The field guide for an operator is
[`docs/field/fingerprint_telemetry_cheatsheet.md`](docs/field/fingerprint_telemetry_cheatsheet.md)
— **update it in the same change as this table.**

There is **no runtime registry** of event names: no `EVENT_NAMES` symbol, no test over
the whole set. This table is the only index, so an event missing from it is invisible.

### 10.1 Correlation keys — there is no single global one

A grep on the wrong key finds nothing. `[CODE]`

| Layer | Key |
|---|---|
| Enrolment (UI + ZK9500 capture) | `enroll_id=` |
| Backend API | `am_id=` + `finger_id=` (shared surface — no `enroll_id`) |
| Member / sync | `am_id=`, `pin=` |
| `ZKStandaloneDevice` | `worker=ZKEM:<device id>` |
| `UltraDeviceWorker` | `worker=ULTRA:<device id>` |
| Local API | `device_id=` |

`DOOR_OPEN` is emitted at **two** layers with **two different `result` vocabularies**
(§7). Grep only one key and you see half the presses.

### 10.2 The fingerprint chain (added 2026-09-04)

`[TEST: tests/test_fingerprint_telemetry.py, tests/test_fingerprint_telemetry_enrol.py]`

| Event | Where | Carries |
|---|---|---|
| `ENROLL_START` | `app/ui/app.py` | `user_id finger_id device am_id am_source candidates candidate_ids` |
| `ENROLL_SCANNER` | `zkfinger.py` (`phase=init`), `app.py` (`phase=open`) | `rc ok dll_path dll_dir` / `ok err dur_ms` |
| `ENROLL_SAMPLE` | `zkfinger.py` | `sample result size` (+ `score` when `result=rejected`) |
| `ENROLL_MERGE` | `zkfinger.py` | `ok size samples dur_ms` |
| `ENROLL_BACKEND_REQ` | `app.py` | `am_id finger_id template_version encoding tpl_chars tpl_sha1` |
| `ENROLL_BACKEND` | `monclub_api.py` | `am_id finger_id status result body dur_ms` |
| `ENROLL_BACKEND_ERR` | `app.py` | `am_id finger_id err dur_ms` |
| `ENROLL_MEMBER_SYNC` | `app.py` | `am_id requested ok err` |
| `ENROLL_DONE` | `app.py` | `outcome user_id finger_id am_id total_ms` + per-phase `*_ms` |
| `FP_ARRIVED` | `db.py` | `delta_mode incoming_users members_with_tpl templates am_ids ids_omitted` |
| `ZKEM_PUSH_CHUNK` | `zk_standalone.py` | `chunk chunks members first_pin last_pin pushed failed tpl_attempted tpl_ok op del_attempted del_ok dur_ms ok` |
| `MEMBER_SYNC_DEFERRED` | `ultra_engine.py` | `member_id reason in_db` |
| `MEMBER_REVOKE_REQUESTED` | `ultra_engine.py` | `member_id pin` |
| `MEMBER_REVOKE_DONE` | `ultra_engine.py` | `member_id pin mode ok` (`mode=deleted|neutralised|repushed`; `repushed` = ACCOUNT pin kept, collapsed row re-pushed, §3.2b) |
| `MEMBER_REVOKE_FAILED` | `ultra_engine.py` | `member_id pin` |
| `MEMBER_REVOKE_OWNERSHIP_MISSING` | `ultra_engine.py` | `member_id pin` |
| `MEMBER_REVOKE_PIN_UNKNOWN` | `ultra_engine.py` | `member_id` (warn; pinScheme=ACCOUNT, the person's pin cannot be named — nothing removed, §3.2b) |
| `MIRROR_SKIP_NOT_FULL_RECONCILE` | `ultra_engine.py` | `worker` (was `MIRROR_SKIP_REASON`; see §3.2c) |
| `MIRROR_SKIP_NO_CAPABILITY` | `ultra_engine.py` | `worker` |
| `MIRROR_SKIP_EMPTY_ROSTER` | `ultra_engine.py` | `worker` (warn) |
| `MIRROR_SKIP_LIST_FAILED` | `ultra_engine.py` | `worker err` (warn) |
| `MIRROR_NOOP` | `ultra_engine.py` | `worker device roster` |
| `MIRROR_ABORT_FLOOR` | `ultra_engine.py` | `worker extras roster max_frac` (warn) |
| `MIRROR_PLAN` | `ultra_engine.py` | `worker would_delete sample armed` |
| `REVOKE_DONE` | `ultra_engine.py` | `pins deleted neutralised slots ok` (confirmed outcomes only) |
| `REVOKE_ABORT_FLOOR` | `ultra_engine.py` | `revoked roster ceiling max_frac abs_floor` |
| `REVOKE_SKIP_EMPTY_ROSTER` | `ultra_engine.py` | (no fields) |
| `REVOKE_SKIP_INCOMPLETE_ROSTER` | `ultra_engine.py` | `withheld` (warn; ACCOUNT rows without `mainAccountId` — MIRROR, revoke pass and prune skipped, §3.2b) |
| `ZKEM_PUSH_FAILED_PINS` | `zk_standalone.py` | `count by_reason pins truncated` |
| `ZKEM_PUSH_TPL_REFUSED` | `zk_standalone.py` | `pin finger size template_version device_fp_version fp_used fp_capacity` |
| `ZKEM_TPL_VERSION_MISMATCH` | `zk_standalone.py` | `pin finger template_version device_fp_version` |
| `PULLSDK_PUSH_TPL_REFUSED` | `device_sync.py` | `device_id pin fingers errs` |
| `SYNC_RETRY_BACKOFF` | `device_sync.py`, `ultra_engine.py` | `device_id pins` |
| `PIN_SCHEME_ACCOUNT_WITHHELD` | `device_sync.py` | `device_id withheld` (warn; §3.2b — ACCOUNT rows with no `mainAccountId`) |
| `PIN_SCHEME_SWITCH` | `db.py` | `device_id previous scheme cleared_rows` (warn; §3.2e — the terminal must be wiped) |
| `ZKEM_PUSH_WEDGED` | `zk_standalone.py` | `chunk chunks members consecutive pushed_before err` |
| `ZKEM_PUSH_RECONNECT` | `zk_standalone.py` | `chunk ok err` |
| `ZKEM_PUSH_ABANDONED` | `zk_standalone.py` | `consecutive chunk chunks pushed` |
| `ZKEM_DEVICE_LEFT_LOCKED` | `zk_standalone.py` | `worker err` |
| `FP_DELTA` | `ultra_engine.py` | `device_id reason header_changed added removed changed fields` |
| `ZKEM_DEVICE_COUNTERS` | `zk_standalone.py` | `device_fp_version label_source c_<name>=<value>` |
| `ZKEM_VERIFY_OK` | `ultra_engine.py` | `pin verify_method scan_mode_hint age_s event_id` |
| `ZKEM_VERIFY_INVALID` | `ultra_engine.py` | the same, plus `att_state` |

`ENROLL_DONE outcome` is a closed set: `ok`, `ok_deferred_offline`, `capture_failed`,
`backend_rejected`, `sync_failed` (the **pre-flight** sync, not the targeted one),
`no_membership`, `restricted`, `not_logged_in`, `cancelled`, `no_pending_record`,
`error`. Every exit path reaches it. `[CODE: _remote_enroll_worker's finally]`

`ZKEM_PUSH_FAILED_PINS` reasons: `set_user_info_false`, `template_refused_f<N>`,
`finger_remove_false_f<N>`, `finger_remove_exception_f<N>`, `exception:<Type>`,
`chunk_wedged_or_unconfirmed`. `[CODE: _do_push_roster]`

### 10.3 Three rules this instrumentation follows — keep them

1. **Never log template bytes.** Sizes, `sha1[:8]`, `templateVersion`, encoding only.
   Pinned by a test per layer (`test_never_logs_template_bytes`).
2. **No per-item event inside the STA push loop.** The STA loop services one command
   with **no COM pump for its duration** (`zkemkeeper_guide.md` §2), and the log handler
   writes synchronously inline, so a line per member on a 928-member push widens that
   window — a behaviour change, not instrumentation. Per-pin detail is accumulated in
   memory and emitted at **chunk** boundaries. The rare failure paths may write inline.
   The same reasoning caps `FP_ARRIVED` at one line per sync rather than one per member:
   it runs inside the sync DB write, where a plain 934-row `SELECT` has taken 6.8 s on
   the gym PC. `[FIELD]`
3. **`ZKEM_VERIFY_INVALID` names the branch, not the cause.** The driver stamps the
   literal `eventType="zkem_invalid"` whenever `IsInValid` is non-zero — that routing is
   `[CODE]`. What any `IsInValid`, `AttState` or `verifyMethod` value *means* on the
   MB2000 is `[UNVERIFIED]`/`[UNKNOWN]` (§7). The raw values are logged **side by side**
   and must never be collapsed into a single decoded "reason".

### 10.4 Two traps when adding an event

- **Do not put `SSR_DeleteEnrollData`, `zk.SSR_DelUserTmpExt`, `.push_roster(` or
  `.open_door(` into an event name, message or field *value*.** §9 and
  `zkemkeeper_guide.md` §11 mandate greps with **expected match counts**; a literal in a
  log string inflates them and raises a false MUST-NOT-CALL alarm for the next agent.
  Use a non-matching spelling such as `op=del_user_tmp_ext`.
- **Do not add a third spelling of the STA timeout text.** The existing two differ only
  by a leading `zkemkeeper ` and that difference is load-bearing for log matching
  (`zkemkeeper_guide.md` §2). Reuse one.

To list every event name actually emitted (and check §10.2 against it):

```bash
python tools/list_telemetry_events.py
```

`--where` adds the `file:line` of every emit site. **Do not use a plain
`grep '_tel.event("NAME"'` for this** — it silently misses most events, because a
call with more than about three fields is wrapped onto the next line, and because
`zkfinger.py` emits through the `_enroll_tel(...)` helper that stamps `enroll_id`.
A single-line grep finds 63 of the 134 names. `[CODE]`

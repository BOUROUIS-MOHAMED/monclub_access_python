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
| The ULTRA re-scan cooldown — its window, its default for a never-seen card, the staff exemption (`ultra_engine.py::_process_event`'s cooldown block, `::_effective_card_cooldown_sec`) | §3 ULTRA |
| How a sync request is classified explicit vs automatic (`full_reconcile`) | §3.2c Reconcile reachability |
| `DeviceSyncEngine._normalize_device` allowlist | §6.2 The inert-patch rule |
| How a member becomes a device pin or a pin becomes a member (`pinScheme`, `derive_member_pin`, the collapse, revoke, push report, inbound); the `sync_users.main_account_id` cache and its forced refresh; pinScheme switches, the worker refresh on a device change and the push passes' scheme re-check (`app.py::_refresh_running_ultra_devices`, `device_sync.py::pin_scheme_superseded`, `ultra_engine.py::_pass_scheme_stopped`); local API handlers carrying a member or pin | §3.2b What a device PIN actually is, §3.2d, §3.2e, §3.2f |
| Anything currently marked `UNVERIFIED` that you actually prove or disprove | §7 Unverified |
| A `[T]` telemetry event name, or the fields it carries | §10 Telemetry events |
| How door-history upload verdicts are persisted, the unresolved retry bound, or its expiry (`device_attendance.py::_sync_pending_history`, `db.py::mark_access_history_unresolved`, `db.py::expire_unresolved_access_history`, `db.py::prune_access_history`) | §3.5 Door-history upload |
| The sync timer — healthy interval, failure-retry schedule, `Retry-After`, the mid-sync re-run, the offline DEVICE-reconcile gate (`app.py::reschedule_sync_timer`, `::_ensure_sync_timer`, `::_sync_base_interval_sec`, `::_on_sync_work_finished`, `::_offline_device_reconcile_due`, `::_defer_ultra_reconnects`, `::request_sync_now`, `::_sync_tick`; `app/core/sync_retry.py`; the startup arming in `access/runtime.py`; the pending-context write in `change_detector.py::_poll_once`) — the v2 safety sync and what it switches off (`app/core/sync_cadence.py`, `app.py::_v2_safety_sync`, `::_tighten_sync_timer`, `::_safety_tick_device_reconcile_due`, `::change_detection_gated`, `::_daily_sync_gated`, `::_daily_sync_check`, `change_detector.py::_poll_once`'s gate, `v2/runtime.py::_post_cadence_check`) — or the headless loop's pacing (`app.py::mainloop`, `::after`) | §3.6 The sync timer and the headless loop |
| The missing-member check — what it compares, when it asks a refresh or a probe, its suppression (`app.py::_check_missing_members`, `::_missing_member_action`, `::_request_member_refresh`; `sync_scope.py::member_id_set_digest`, `::token_id_set_digest`, the `forceMemberRefresh` / `probeMemberSet` hints in `::apply_trigger_hint_to_version_tokens`; `db.py::list_local_member_ids`, `::list_member_window_ids`) | §3.6 "The missing-member check" |
| What the optional-content scheduler fetches, stores or sends (`app/core/optional_content_sync.py`) | §3.7 Optional content sync |
| The removal ceiling or any path that removes device users in bulk (`app/core/push_safety.py`, `device_sync.py::_sync_one_device` stale/clear step, `ultra_engine.py::_neutralise_revoked_pins`) | §3.2g |
| The finger-slot sweep — who qualifies, the daily batch, `finger_slots_swept` (`ultra_engine.py::_finger_sweep_plan`, `::_sweep_pin`, `::_drain_finger_sweep`; `zk_standalone.py::sweep_finger_slots`, `::_clear_finger_slot`) | §3.4c, and zkemkeeper_guide §5/§11 |
| The write-ahead push intent — when it is written, what resolves it, the read-back promotion, the daily maintenance slot (`db.py::record_push_intents` and siblings, `_run_db_write_sync(durable=)`, `ultra_engine.py::_record_push_intents`, `::_push_with_chunk_recording`, `::_promote_intents_by_readback`, `::_drain_daily_maintenance`, `device_sync.py::_settle_pullsdk_intents`, `::_prove_pullsdk_intent`) | §3.4a |
| The ULTRA operator queues — door-open and control-panel SDK calls — their deadline or their claim (`ultra_engine.py::request_door_open`, `::_drain_commands`, `::request_run_sdk`, `::_drain_sdk_commands`, `::_CommandClaim`; the `sent, no answer` text in `local_access_api_v2.py::_door_open_error_fr` and its `500_sent_no_answer` branch in `::_handle_device_door_open`; `zk_standalone.py::last_open_door_result`; the 503 group in `local_access_api_v2.py::_run_on_device_sdk`) | §3.1a, §7 (`ACUnlock` on the MB2000), §10.2a, field cheatsheet §6, and zkemkeeper_guide §4 (Door) |
| What runs between the chunks of a standalone push, the per-pass cap, superseded pins (`ultra_engine.py::_standalone_push_yield`, `::_note_push_superseded`, `::_prioritise_for_cap`, `_FULL_SYNC_MAX_PINS_PER_PASS`; `zk_standalone.py::push_roster(between_chunks=)` and the `push_roster` STA op's event pump) | §3.4e, and zkemkeeper_guide §5 |
| The QR roster check — its verdicts, where it runs, its switch, its counts (`access_verification.py::verify_totp`'s roster step, `::record_totp_roster_check`, `::maybe_log_totp_roster_summary`; `settings_reader.py::parse_totp_roster_check_mode`; `ultra_engine.py::_handle_totp_rescue`'s member-list choice; the heartbeat's `qrRosterCheck`, `pc_identity.py::_qr_roster_check_report`) | §3.1b, §10.2a |
| What the credential diff compares, or how it compares grants (`db.py::_sync_gym_access_credentials_rows`, `::_sync_credential_grants_changed`) | §3.1b |
| Sync protocol 2 on the PC — what the request sends, what the save stores (`db.py::_apply_protocol2_save`, `_reconcile_held_rows`, `_create_protocol2_tables`), the flip and the gym date/clock rules (`db.py::apply_local_date_flips`, `::gym_date_status`, `app/core/access_dates.py`), or when the flip runs (`app.py::_apply_date_flips` and its triggers, `pc_identity.py::_heartbeat_payload_after_date_check`) | §3.8, §10.2b |
| The QR allowed-days step (`access_verification.py::verify_totp`'s date step, `::current_access_days`, `access_dates.py::qr_date_verdict`, `::effective_credentials`) | §3.1b "Allowed days" |
| Renewal ordering — which old pins are held, when they are removed (`ultra_engine.py::_neutralise_revoked_pins`, `::_remove_released_holds`, `device_sync.py::_sync_one_device` holds) | §3.4f, §3.2g |
| The one-shot credentials re-send at startup — what it drops, its marker table, its place and catch in `init_db` (`db.py::_force_one_credentials_resend`, `::_run_one_shot_credentials_resend`, `local_one_shot_steps`; `tools/bench_credential_resend.py`) | §3.1b "The upgrade window" |
| What happens when an `init_db` step fails — the four schema migrations that stop startup, the steps that log and go on, a `try` or an `import logging` added inside `init_db` (`db.py::init_db`, `::_relax_firmware_profiles_not_null`, `::_rebuild_sync_users_without_legacy_fingerprint`, `::_ensure_main_account_id_column`, `::_ensure_pin_scheme_column`, `::_run_one_shot_credentials_resend`) | §3.2d "A failing migration stops startup", §3.1b "The upgrade window" |
| Anything in `app/core/v2/` (the server clock, the v2 client, the notice socket, leases, commands, ownership backup, problem reports, loss re-add), `access/v2_routes.py`, or a lease-gate call site (`ultra_engine.py::_v2_writes_blocked` and the `_lease_gate` calls, `device_sync.py`, `realtime_agent.py`, `device_attendance.py`, `app.py::ultra_devices_for_this_pc`, `access/local_api_routes.py::LEASE_GATED_HANDLERS` / `SCANNER_GATED_HANDLERS`) | §3.9 |
| What `push_safety.check_bulk_removal` defers (`add_only`, `handover_release`) or lets through (a Confirm-removal approval) | §3.2g, §3.9 |
| The removal log (`db.py::_log_v2_removal` in `clear_device_revocation_state` / `delete_device_sync_state`) | §3.4a, §3.9 |
| The Erase-content wizard or the write hold (`app/core/erase_wizard.py` — incl. `::refill_roster`, `::held_waiting_count`, `EraseWizard._refill_check`, and since lane 1c `::_sync_staleness` / `::_sync_max_age_sec` with `app.py`'s `_last_sync_ok_mono` stamp, `::terminal_people` / `::not_refilled` / `::_bind_not_refilled` / `KEEP_MARK`, `::_refill_recheck`, `::_prune_now` / `::_folder_times`, `::_no_answer`, `local_access_api_v2.py::_handle_auth_verify_admin_password`'s codes —, `app/core/device_hold.py` — incl. `load(release_unstarted=)` and the `erase-prep`/`erase` phases —, `db.py::set_device_write_hold` / `::clear_device_write_hold` / `::list_device_write_holds`, `::begin_device_erase`, `::release_unstarted_erase_holds`, `erase_wizard.py::check_erase_switch` / `monclub_api.py::get_erase_wizard_switch` (the gym's server switch), `erase_wizard.py::prune_erase_backups` (30-day retention), `::retire_device_records`, `::invalidate_device_records`, `device_sync.py::_filter_users_for_device(quiet=)`, `PullSDKDevice.ERASABLE_TABLES`, `local_access_api_v2.py::_handle_auth_verify_admin_password`'s offline answer, the hold in `ultra_engine.py::_v2_writes_blocked`, the worker's `_connected_addr` (`::_connect` / `::_disconnect`), `device_sync.py`'s three hold checks, `v2/handlers.py::device_reconcile`, `app.py`'s start-up `device_hold.load()` and `_sync_tick`'s `device_hold.ensure_loaded()`, `ownership.py::OwnershipSync._worker_idle`, the `erase` routes and handlers, `local_access_api_v2.py::_refuse_held_or_frozen`, `PullSDKDevice.count_table_strict` / `::read_table_strict` / `::erase_table`, `ZKStandaloneDevice.read_device_status` / `::read_user_templates` and the listing's `privilege`, `tauri-ui/src/components/EraseWizardDialog.tsx`) | §3.2h, pullsdk_guide §5, zkemkeeper_guide §4 |
| What a turnstile's heartbeat line reports as waiting (`device_sync.py::count_waiting_pins`, `ultra_engine.py::_count_waiting_pins` and the snapshot's `failed_pins`, `_sync_one_device`'s `_last_waiting_pins`, `realtime_agent.py::get_status_snapshot`'s `failedPins`, `pc_identity.py::build_heartbeat_payload`, `::_report_held_turnstiles` and its `held` key, `erase_wizard.py::held_waiting_count`, the wizard's `_set_waiting`) | §3.10 |
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
- **The PC's re-scan cooldown runs before all of the above.** A card/QR scanned again
  inside its window returns early: no popup, no history, no rescue.
  - The window is `_effective_card_cooldown_sec`: a 3 s debounce, or
    `anti_fraude_duration` when anti-fraud is on for that scan kind. The duration is
    clamped to 5–300 s by `settings_reader.py::normalize_device_settings`.
  - A staff RFID card past the debounce still goes through to the rescue.
    `[CODE: ultra_engine.py::_process_event — the cooldown block]`
  - A card never seen by this worker is **not** in cooldown. Up to master `3b28bd2`
    it defaulted to `last_seen = 0.0`, as in every tagged release checked (`access_1.4.24`,
    `.25`, `.26`, `.30`, `.31`, `.33`; 1.4.27–1.4.29 and 1.4.32 have no tag).
    `time.monotonic()` counts from boot, so while the PC's uptime was below the window,
    every first scan was skipped. A first allowed card lost its popup and history, and
    a first QR was never rescued (the terminal refuses a QR it cannot know). It is now
    `float("-inf")`.
    `[TEST: test_ultra_engine.py::TestCardCooldown::test_a_never_seen_scan_is_not_in_cooldown_right_after_boot]`
  - The field logs from gyms 44 and 45 on hand (1.4.24–1.4.33, 2026-08-27 to 09-10,
    24 app starts) show no such skip. All 97 cooldown skips had `elapsed` below the
    app's own age, and only 3 s and 30 s windows appear. `[FIELD]`
  - After a start, the MB2000s at gym 45 delivered scans made while the app was not
    running, up to 5684 s old (`ZKEM_VERIFY_* age_s`). The PC processed them from about 11–18 s after the app started
    (most starts). So a boot window also covers that backlog. `[FIELD]`
  - How soon after power-on a gym PC starts the app is not measured: none of those 24
    starts came from the Run key (`startup_arg=False`). Nor is it known whether a Fast
    Startup power-on resets the monotonic clock. `[UNVERIFIED]` The "App started" log
    line now carries `monotonic_s=`. Read against the known power-on time, a future
    field log answers both questions.
    `[CODE: app/ui/app.py]`
- ULTRA is the **only** mode that can drive a ZK_STANDALONE terminal. See §3.2.

### 3.1 Every door-open call site in the app

Exhaustive, so the mode descriptions above can be checked rather than believed.
Regenerate with `grep -rn "\.open_door(" app/ --include=*.py`. `[CODE]`

| Call site | Trigger | Applies to |
|---|---|---|
| `realtime_agent.py::DecisionService` (→ `DeviceCommandBus.open_door`) | **Automatic** — the AGENT access decision | AGENT only (workers are only built for AGENT devices) |
| `ultra_engine.py::_open_door_with_retry` | **Automatic** — ULTRA TOTP/QR and staff-RFID rescues only | ULTRA only |
| `ultra_engine.py::_drain_commands` (command queue, fed only by `request_door_open`) | Queued **operator** door command executed on the ULTRA worker's connection; skipped once its caller has given up or its deadline has passed (§3.1a) | ULTRA only |
| `realtime_agent.py::DeviceCommandBus` / `DeviceWorker.open_door` | Plumbing beneath the two above | — |
| `device_actor_runtime.py::_handle_message` (`OPEN_DOOR`) | Actor-message plumbing | — |
| `local_access_api_v2.py::_handle_device_door_open` | **Manual operator action** from the UI | **All modes** — tries the AGENT engine, then the ULTRA worker, then falls back to a direct PullSDK connect for "DEVICE-mode or unmanaged devices" `[CODE: that comment marks the fallback]` |
| `app/core/v2/handlers.py::CommandHandlers.door_open` (→ the lease-gated `_handle_device_door_open` above) | **Remote operator action**: a DOOR_OPEN command from the dashboard or a reader PC, claimed by this PC (P3b-2, §3.9) | Only a turnstile this PC drives; otherwise exactly the row above |

The last row is why "the PC is not in the live path" is **false** as a blanket statement
about DEVICE mode. It is true only of *automatic* decisions.

### 3.1a A queued operator door-open has a deadline (2026-09-18)

`UltraDeviceWorker.request_door_open` is the **only** producer of `_cmd_queue`, and its only
caller is `_handle_device_door_open` (route `POST /api/v2/devices/{id}/door/open`, used by the
Tauri pages, the tray and the favourite shortcuts), which waits 2.0 s and answers 503
"device unreachable (command timed out)" on timeout. `[CODE]` The dashboard's door button
calls `/api/v1/service/openDoor` on 127.0.0.1, a route this app does not serve (404) — it
reaches no queue. `[CODE: mon_club_dashboard layout.tsx, LocalAccessService.ts;
access/local_api_routes.py]`

Each queued entry carries `deadline = time.monotonic() + timeout` — the caller's own wait — and
a `_CommandClaim` (below). `_drain_commands` (also reached mid-push through
`_sync_yield_to_doors`) skips an entry whose caller has given up or whose deadline has passed:
no SDK call, result `expired (not executed)`, a `CMD door_open EXPIRED` log line (with
`reason=caller_gave_up` or `reason=deadline`) and `[T] DOOR_CMD_EXPIRED`. Before, nothing
removed an abandoned entry except a newer press or a drain, and the worker drains only while
connected — so an open pressed during an outage or a sync hand-off (`pause_for_sync`, which has
no door yield) pulsed the relay on the next reconnect, however late. `request_door_open` also
returns a **copy** of the result box, and the worker writes `ok`/`error` in one `dict.update`,
so the handler can no longer read a half-written pair. Mid-push, `[T] SYNC_DOOR_YIELD` carries
`opened` (entries the worker took and did not skip: handed to the driver whatever it answered, or
answered `not connected` without a call — as before) and `expired` (skipped) separately.
`[CODE: ultra_engine.py::request_door_open, ::_drain_commands, ::_sync_yield_to_doors]`
`[TEST: test_door_open_deadline.py]`

**Exactly one side decides an entry — the worker or its caller (2026-09-19).** The deadline
alone did not keep the promise above. `Event.wait(timeout)` is not timed by `time.monotonic`
and can return while `monotonic()` is still ≤ `deadline`; the caller then answered "timeout"
and a drain in that gap still opened the door. `[TEST]` The scenario of
`::test_a_door_open_the_caller_gave_up_on_is_never_executed_later` (`timeout=0.05`, then an
immediate `_drain_commands`), looped 300 times with the 32-bit `.venv` Python 3.11 on the dev
PC, opened the door 23/300 times, then 15, 8 and 15 /300 in three reruns on `d09f88f`; 0/300 in
three runs with this change. It also failed once in a full-suite run. Re-measured on master
`ca1e29a` (P3a-2, 2026-09-19): 26, 51 and 50 /300, and 0/300 in three runs with the claim ported
onto it. A stress probe with a real concurrent drainer — `_drain_commands`, `_sync_yield_to_doors`
(the mid-push path) and the SDK queue below — sent 189 of 11,404 commands on master after their
caller had answered "timeout", and 0 of 11,404 with the claim (same seeds, interleaved runs).
`[TEST: scratch probes, not committed]` A competing fix (branches `claude/p3a1-door-deadline-race`
and `claude/p3a1-sdk-cmd-abandoned`: the caller sets an `abandoned` flag once its wait has run
out, the worker reads the flag at dequeue) was not kept. The worker can read the flag while it is
still clear, the caller then sets it and answers "timeout", and the command is still sent; a
forced interleaving reproduced it. The claim makes that decision under a lock. `[CODE]`

Now each entry carries a `_CommandClaim` (named `_DoorOpenClaim` until the SDK queue below
started using it too), a lock and an owner, taken once. The worker takes it
before any SDK call and skips the entry if the caller already has it. The caller, when its wait
runs out, takes it before answering "timeout". Whoever comes second is refused:

- **The caller took it** → the worker never sends that open; the caller answers `timeout`
  (local API: 503 "device unreachable (command timed out)").
- **The worker took it first** → the open is being sent, so the caller does **not** answer
  "timeout". It waits up to `_DOOR_OPEN_IN_FLIGHT_WAIT_SEC` more (the 4 s `timeout_ms` the worker
  passes to the driver, plus 1 s — a chosen bound) and returns the worker's own answer, `ok=True`
  on success. (If the worker finds itself disconnected after taking it, nothing is sent and
  the answer is `not connected` → 500 "appareil non connecté", the answer any drain on a
  disconnected worker already gave; only a caller whose wait ran out before that answer used to
  say `timeout` → 503.) If the extra wait also runs out it returns `sent, no answer`, never
  `timeout`; the local API answers 500 whose `error` is "commande envoyée à l'appareil, sans
  réponse à temps — vérifier si la porte s'est ouverte", not the generic "échec…".
  What the operator sees `[CODE]`: the Tauri pages' `post` throws that `error` as the
  `ApiError` message, and the pages print it behind their own failure framing. That is
  "Ouverture échouée: ApiError: …" on `DevicesPage`, "ApiError: …" on `FavoritesOverlayPage`, and
  a "Door open failed" notice on `TrayPanelPage`. A favourite global shortcut reports only the
  HTTP status (`lib.rs`, "HTTP 500 …"). The native tray item prints the `error` to stderr only
  (`lib.rs::post_open_door`). Not changed here.
  The local API logs this answer as `ULTRA door open SENT, NO ANSWER` and emits
  `[T] DOOR_OPEN result=500_sent_no_answer` (same 500, same French text), so a log reader does
  not take it for a refusal. `[CODE: local_access_api_v2.py::_handle_device_door_open]`
- **A timed-out call is "sent, no answer", not a refusal (review, 2026-09-25).** A driver's
  `open_door` answers `False` both when the terminal refuses and when the driver stops waiting.
  On the standalone driver the extra wait always outlasts the call: `open_door` gives up after
  `max(2 s, timeout_ms)` = 4 s, abandons its STA thread (`ZKEM_STA_WEDGED`) and answers `False`,
  so a wedged `ACUnlock` read as the terminal's refusal ("vérifier le relais et le câblage") —
  on master the same press answered 503 at 2 s. The driver now records each outcome in
  `last_open_door_result` (a `_DOOR_OPEN_RESULTS` value, written by `_door_open_event` on every
  path), and `_drain_commands` answers `sent, no answer` when it is `timeout`: the command was
  queued to the driver's STA thread and may or may not have reached `ACUnlock` (that thread can be
  stuck in another COM call), so the relay may still fire. A real `False` still reads as the
  refusal. `PullSDKDevice.open_door` keeps no `last_open_door_result` and answers `False` for
  "not connected" and for any exception from `door_pulse_open` alike, so on a panel both still read
  as the refusal, as on master. That answer is a label, not proof the door stayed shut. `[CODE: zk_standalone.py::open_door, ::_door_open_event; ultra_engine.py::_drain_commands;
  pullsdk.py::PullSDKDevice.open_door; the not-reached case: zk_standalone.py::_call (its deadline
  includes the time in the queue), ::_sta_main, ::_pump_events_once]`
  `[TEST: test_mb2000_force_open.py::TestLocalApiDoorOpenChain::
  test_a_wedged_acunlock_is_sent_no_answer_not_a_refusal, test_door_open_deadline.py::
  test_a_timed_out_open_reads_sent_no_answer_a_refusal_reads_false]`

`[CODE: ultra_engine.py::_CommandClaim, ::request_door_open, ::_drain_commands;
local_access_api_v2.py::_door_open_error_fr]` `[TEST: test_door_open_deadline.py::
test_a_wait_that_ends_before_the_deadline_still_never_opens_later,
::test_an_open_the_worker_took_first_is_answered_with_its_result_not_timeout,
::test_an_open_still_being_sent_after_the_in_flight_wait_is_not_called_a_timeout,
::test_a_queued_door_open_is_decided_once_by_its_worker_or_its_caller,
::test_the_desk_is_told_an_unanswered_open_was_sent]` — these drive the order through a
scripted `Event.wait` on the caller's result event, not through sleeps or the clock.

On a standalone (MB2000) full sync the queue is drained between push chunks too since P3a-2
(§3.4e), by the same `_drain_commands`, so the claim decides there as well. A press early in a
chunk still waits for the rest of that chunk — up to ~4.1 s at the field write rate, longer than
the handler's 2.0 s. `[TEST: measured on a fake terminal, §3.4e]` If the caller's wait runs out
first it takes the claim and answers 503, and the yield skips the entry afterwards; if the yield
takes it first, the caller waits for the device's answer as above. `[CODE]`

The deadline check stays, as a second reason to skip only. The worker's clock can pass the
deadline while the caller's wait is still running, and mark the entry expired just before the
caller copies the box; `request_door_open` reports that as its own `timeout` (nothing was
sent), which keeps the local API on its 503 instead of a generic 500.

What it does **not** change: the check is at dequeue, so an open taken inside the deadline still
runs and its waiter gets the device's answer. The cost is time. When the worker takes an open
at the very end of the caller's 2 s wait, `_handle_device_door_open` can take up to
2 s + 5 s. That holds only its own request thread: the local API server is a
`ThreadingHTTPServer` `[CODE: local_access_api_v2.py::_AppHTTPServerV2]`. The Tauri pages'
`post` aborts after 15 s `[CODE: tauri-ui/src/api/client.ts::post]`;
the tray and favourite-shortcut calls set no timeout of their own
`[CODE: tauri-ui/src-tauri/src/lib.rs::post_open_door, the shortcut handler's reqwest call]`.
How long the SDK call itself can take is driver-specific. The standalone driver gives up after
`max(2 s, timeout_ms)` and abandons its STA thread `[CODE: zk_standalone.py::open_door, ::_call]`.
`PullSDKDevice.open_door` ignores `timeout_ms` and may reconnect inside the call
(`ensure_connected`), so its duration is bounded only by the DLL. `[UNKNOWN]` That bound has
never been measured. When it is exceeded the desk reads "sent, no answer" and the door may still
pulse. The expiry applies to operator opens only.
QR/TOTP and staff-RFID rescue opens call `self._sdk.open_door` directly on the worker thread
(`_open_door_with_retry`) and never touch this queue, so no rescue is delayed or dropped by it.
`[TEST: ::test_rescue_opens_do_not_use_the_queue]` Member syncs and revocations live in other
structures (`_pending_member_syncs`, the revoke-id sets, `_pending_full_sync_request`) and are
deliberately re-queued — they have no deadline and must not get one (§3.4).

**The control panel's SDK-call queue is decided the same way (2026-09-19).**
`UltraDeviceWorker.request_run_sdk` is the only producer of `_sdk_cmd_queue`, and its only
caller is `local_access_api_v2.py::_run_on_device_sdk`, used by the DevicesPage control panel:
`GET /api/v2/devices/{id}/settings` (budget 15 s), `POST …/reentry` (5 s: `SetDeviceParam`
`Door{n}Intertime`, then a read-back), `GET …/clock` (15 s) and `POST …/clock/sync` (25 s).
`[CODE: access/local_api_routes.py; the four handlers]` `_drain_sdk_commands` skipped an
abandoned entry only by `time.monotonic() > deadline`, the check the door queue outgrew.
`[TEST: scratch probe, not committed]` 300 runs of `request_run_sdk(timeout=0.05)` followed at
once by `_drain_sdk_commands`, with the 32-bit `.venv` Python 3.11 on the dev PC, ran the queued
function after its caller had been answered "timeout" 25, 31 and 29 /300 times on `f1812e7`
(branch `claude/p3a1-door-open-claim`; integrated as `f8fe2a0`);
0/300 in three runs with this change.

Each entry now carries the same `_CommandClaim`, taken by the worker before `fn` runs and by
the caller before it answers "timeout":

- **The caller took it** → `fn` never runs; the caller answers `timeout` (503).
- **The worker took it first** → `fn` is running and a write may be landing, so the caller
  waits up to its own `timeout` again and returns the worker's answer. That bound is chosen,
  not measured. It is the budget each handler already sized for its call (`clock_sync`'s
  25 s covers the standalone driver's two 10 s STA waits, `zk_standalone.py::_call`,
  `_DEFAULT_CMD_TIMEOUT_SEC`), so a call that fits its own budget gets its answer. How long a
  PullSDK call can take is bounded only by the DLL. `[UNKNOWN]` If the extra wait also runs
  out, the answer is `sent, no answer`, never `timeout`. `_run_on_device_sdk` returns it as
  500, outside its 503 group (`timeout`, `device not connected`, `expired (not executed)`:
  nothing was sent). This path has no French mapper: DevicesPage prints the raw `error` as
  `ApiError: sent, no answer` (`String(e)`), as it already does for the other English
  strings here. A worker that took the entry and finds itself disconnected answers
  `device not connected` (503, as before).
- **The worker's clock passes the deadline while the caller still waits** → the worker skips
  the entry and the caller reads `expired (not executed)`. `_run_on_device_sdk` already
  answers 503 for that string, so unlike the door queue it is not remapped to `timeout`.

`request_run_sdk` returns a copy of the box (or a fresh dict for `timeout` and
`sent, no answer`), and the worker writes each outcome in one `dict.update`; before, it used
two or three item assignments. A skipped entry now logs `SDK_CMD op=… EXPIRED (not executed):
reason=caller_gave_up|deadline late_by_ms=…`. `[T] SDK_CMD` still carries
`ok=False expired=True` and is otherwise unchanged. The cost is time: a handler can hold its
own request thread for twice its budget — 30 s for the settings and clock reads, 10 s for
reentry, 50 s for a clock sync. Unlike the door queue, this queue has **no mid-push yield**:
`_drain_sdk_commands` has one call site, once per connected poll-loop iteration, after the
inline member and full syncs. It is not reached during a `pause_for_sync` hand-off, while
disconnected, or inside a push (`_sync_yield_to_doors` drains only `_cmd_queue`). A
control-panel call issued then waits; if its caller's wait runs out first, the caller takes
the claim and the call is skipped, never run late. `[CODE: ultra_engine.py::run (its one
_drain_sdk_commands call), ::_sync_yield_to_doors]`
`[CODE: ultra_engine.py::request_run_sdk, ::_drain_sdk_commands;
local_access_api_v2.py::_run_on_device_sdk]` `[TEST: test_sdk_cmd_deadline.py::
test_an_sdk_call_the_caller_gave_up_on_is_never_run_later,
::test_an_sdk_call_the_worker_took_first_is_answered_with_its_result_not_timeout,
::test_an_sdk_call_still_running_after_the_in_flight_wait_is_not_called_a_timeout,
::test_the_worker_writes_each_outcome_in_one_update,
::test_the_control_panel_does_not_call_an_unanswered_call_unreachable]` — the ordering tests
script the caller's `Event.wait`, as the door tests do.

**The door path, before vs after the integration (2026-09-25).** The decision code —
`_process_event`, `_handle_totp_rescue`, `_handle_rfid_rescue`, `_open_door_with_retry`,
`_poll_with_watchdog`, `run`, `access_verification.py::verify_totp` and `::verify_card`, the standalone
driver's `open_door` and `poll_rtlog_once` — is identical to master `ca1e29a` (compared as syntax trees,
comments aside). `[CODE]` Measured with a copy of §3.4e's harness (its queue entries adapted to the
claim), master and this branch interleaved. On the real `UltraDeviceWorker.run()` loop over a fake
terminal, three runs each of 150 scans and 150 desk presses: scan to decision median 267 / 255 / 273
ms on master and 247 / 265 / 266 ms here, p95 472–481 and 451–490 ms (set by the STA loop's 250 ms
idle wait plus the worker's own empty-poll wait, up to 300 ms, `empty_backoff_max_ms`, which no scan
wakes; neither changes here), no scan lost; desk-open round trip median 0.4–0.5 ms and 0.4–0.9 ms,
every press answered ok. One run here had a p95 of 4.0 ms and a worst press of 112 ms. On the
400-press probe the first run here had 21 presses of 41–93 ms, all within one 20 s stretch. A stack
sample the probe takes at least 20 ms after each press starts (its time is not recorded) found the
worker in `_wait_for_work` (13) or in `_poll_with_watchdog`'s `t.start()` (8); why, the probe does not
show `[UNVERIFIED]`. Two re-runs of both trees had none, medians 0.6–0.8 ms, worst 3.7–27.6 ms. During a 100-member push — §3.4e's push
harness, which calls the pass and the loop's own drain steps in order on one thread, not `run()` — a
scan, a desk press and a member update waited the same on both: median 5, at most 9 member writes.
`[TEST: fake terminal; harness kept out of the repo, §3.4e]`

Found while tracing this, **not changed** `[CODE]`:
- AGENT has no queue — `DecisionService` and the local API call `DeviceWorker.open_door`
  synchronously — but `PullSDKDevice.open_door` waits on `_sdk_lock` with no timeout and
  ignores `timeout_ms`, so a caller blocked behind a wedged poll can still pulse late.
- A rescue has no event-age gate: `verify_totp_resilient` accepts a scan time up to
  `EVENT_TIME_SANITY_BOUND_SEC` (3600 s) from the PC clock, so a QR scan observed late (RTLog
  backlog after an outage) can still be rescued late.
- `_handle_device_door_open` falls through from a failed AGENT open to a direct PullSDK
  connect for a device with no ULTRA worker; if the AGENT pulse was sent but reported False,
  the door can pulse twice.
- `POST …/clock/sync` gives the worker 25 s, but the Tauri pages' `post` aborts after 15 s
  (`tauri-ui/src/api/client.ts::post`, `timeoutMs = 15_000`; `hooks.ts` `syncClock` passes
  none). A clock sync slower than 15 s therefore shows the page's own abort, not the server's
  answer, and the write may still land. This was true before the SDK-queue claim and still is.
  The `GET`s set no abort.
- `[T] SDK_CMD` (`_drain_sdk_commands`) is not in the §10 table, so by §10's own rule it is
  invisible to anyone reading only the table.
- A newer press supersedes every queued door-open of the device, whatever its door:
  `request_door_open` drains the whole queue before adding its own. On a two-door panel a
  press on door 2 while a door-1 press still waits (a busy worker, a push chunk) answers the
  door-1 caller `superseded`, and door 1 is not opened. Unchanged since before the claim.
  `[CODE: ultra_engine.py::request_door_open]`
- A standalone clock write that outlasts the driver's 10 s STA wait and then lands is reported
  as "device refused the clock write": `zk_standalone.py::set_device_time` answers `False` on
  any exception, timeout included, and the 25 s handler budget receives that answer.
  Unchanged since before the claim. `[CODE: zk_standalone.py::set_device_time;
  local_access_api_v2.py::_sync_device_clock]`

### 3.1b The QR/TOTP roster check — trial first, then enforce (2026-09-18)

**The gap it closes.** A QR code opens the door through the PC: the ULTRA rescue
(`_handle_totp_rescue`) or the AGENT decision (`DecisionService`), both via
`verify_totp_resilient` → `verify_totp`. Until 2026-09-18 a code that matched a credential was
allowed even when **none** of that credential's `grantedActiveMembershipIds` was a key of
`users_by_am` — the PC's member list; it fell back to the first grant id with `user=None`. The
eligibility filter (`_iter_eligible_totp_creds`) checks only `enabled`, the ids, the secret and a
non-empty grant list. So a member dropped from the member list kept opening the door by QR
until the credentials themselves were refreshed. `[CODE: 62773a3 access_verification.py::verify_totp]`
`[TEST: test_totp_roster_check.py::test_trial_is_the_default_and_still_allows — the old allow, now
trial-mode behaviour; test_access_verification.py::test_totp_no_matching_user_in_users_by_am
passes an EMPTY member list, so it now pins `roster_empty`, not this case]`

**Where the check is.** In `verify_totp`'s final ALLOW step, after the hits are resolved — so
the TOTP speed index and the full loop reach it with the same `grants` and the same
`users_by_am`. **Never** in `_iter_eligible_totp_creds`: `build_totp_index` shares that filter,
and a roster condition there would drop credentials from the index and break the
index-equals-loop contract. Every matched QR result now carries `rosterCheck` and
`rosterCheckMode`: `[CODE: access_verification.py::verify_totp]`

| `rosterCheck` | Means | trial | enforce |
|---|---|---|---|
| `in_roster` | a granted membership is on the member list | allow | allow |
| `in_roster_by_account` | no grant is listed, but a listed row carries the credential's `accountId` as `mainAccountId` | allow (counted) | allow (counted) |
| `not_in_roster` | neither | allow (counted) | **deny** `DENY_NOT_IN_LOCAL_ROSTER`, `user=None` |
| `roster_empty` | the member list is empty | allow (counted) | allow (counted) |
| `roster_behind` | not listed, but the shared credential index matched and the list checked is older than it (ULTRA only) | allow (counted) | allow (counted) |

Only the new fields change on an allow: `activeMembershipId` and `user` are resolved exactly as
before. `roster_empty` exists because an empty list cannot be told apart from a failed read:
`load_local_state` turns a failed users query into `[]`, and `_get_cached_local_state` falls back
to `({}, {}, {})` on a bad load. Enforcing then would refuse every QR code at every door. `[CODE]`

`in_roster_by_account` exists because the PC's cached grants can go stale. The backend
recomputes `grantedActiveMembershipIds` on every request and never stores it on the credential
row, so a renewal (a new `ActiveMembership`, a new id) changes **only** the grants of a
credential that stays. Until 2026-09-18 the client dropped that change even when it arrived:
`db.py::_sync_gym_access_credentials_rows` compared only `id gym_id account_id secret_hex
enabled rotated_at created_at updated_at`, so the member kept the old id in the local
credential, passed only through this second chance, and door history carried the old
`activeMembershipId`. The diff now also reads `granted_active_membership_ids_json` in the same
full-table scan and compares the grants **as a set** (`_sync_credential_grants_changed`) — the
way backend `main`'s credentials token digests them (sorted, distinct). Neither grant query
(`findAllValidForAccessByGymId` / `…ByGymFamilyName` for the main sync, `findAllValidNowByUserId`
for the fast patch) has an `ORDER BY`, so an order-only difference is not written; a raw-string
compare would rewrite every multi-grant row whenever the order moved. What is stored is the list
as the backend sent it when the row was last written — an order-only difference leaves that
order in place — and it is never re-sorted: `verify_totp` walks it in order. A value that does not
parse counts as changed. `[CODE: db.py::_sync_gym_access_credentials_rows,
::_sync_credential_grants_changed; backend main GymAccessController::computeCredentialsVersion,
ActiveMembershipRepository]` `[TEST: test_credential_grants_diff.py::test_a_grant_only_change_is_written,
::test_a_grant_only_change_is_written_on_the_fast_patch_merge_path,
::test_the_same_grants_in_another_order_write_nothing, ::test_grants_compare_as_a_set_and_write_when_in_doubt,
::test_a_renewed_member_scans_in_on_the_new_membership_after_the_next_sync]`

The cost, measured on the development PC with 2,000 credentials (old function against new,
interleaved, 101 runs, paired median; 32-bit `.venv` Python 3.11 and Python 3.13): **+1 to +3 ms**
per sync for fetch + diff when nothing or 5 % of the grants changed; the worst case, every row's
grants reordered with 20 grants each (4,000 parses), +41 to +46 ms. `[TEST: re-run with
tools/bench_credential_diff.py — a measurement, not a pass/fail test; the 1–3 grants per
credential mix it assumes is not measured on a gym]` P6's ~21 s (`[COMMENT]`
in the function) came from the old OR-of-AND predicate's plan, not from reading the column: the
scan is a plain `SCAN sync_gym_access_credentials` with or without the grants column (no index
covers it), and SQLite stores a row's columns together unless the row outgrows its page
(kilobytes; a grant list is tens of bytes), so the same pages are read — on a slow disk only
the CPU time above is added. `[UNVERIFIED]` on a gym PC.

Where grants can **still** be stale: on backend `main` a renewal reaches the PC with its new
grants on both paths — the main sync builds `users[]` and the credentials from one list, and the
client writes both sections in one `save_sync_cache_delta` transaction; the membership fast
patch sends the member and a `CREDENTIALS` `UPSERT_ONLY` section in one bundle
(`AccessPatchBundleService.buildMembershipBundle`). `[CODE: backend main; client db.py]` A
backend whose credentials token does not digest the grants never sets `refreshCredentials` for
a grant-only change, so the main sync does not re-send it (`[UNVERIFIED]` whether the gyms run
backend `main`). So once a PC runs this build, an `in_roster_by_account` count that keeps
growing points to grant changes not arriving — once the one forced re-send below has landed (the
first successful sync after the upgrade), the only cause traced here; check which backend serves
that gym before reading it any other way.

**The upgrade window — closed by one forced re-send (2026-09-25).** Rows the previous build left
stale are rewritten only when the backend re-sends the credentials, and it re-sends them only when
the client's token is absent or differs from its own: `refreshCredentials = clientCredsVersion ==
null || !clientCredsVersion.equals(currentCredsVersion)`; otherwise the section goes out as
`gymAccessCredentials: []`. `[CODE: backend main a98bf154 GymAccessController, read not run; the
same null check at fcfc850c, whose token is only count:maxUpdated with no grant digest]` Upgrading
the client does not move that token, the §3.2d migrations drop only member and device tokens, and
backend `main`'s daily safety net forces members only. So `init_db` drops the stored
`credentialsVersion` **once**, at the first start of a build with the grant-aware diff
(`_force_one_credentials_resend`, run through `_run_one_shot_credentials_resend` right after
`sync_version_tokens` is created). The next `getSyncData` carries every other token and no
`credentialsVersion`; the backend answers with every credential, and the diff rewrites only the
rows that differ — a renewed member's stale grant is written, an order-only difference is not.
The drop deletes no credential row: an offline PC keeps its QR credentials, and keeps asking for
the full list, until a sync succeeds — tokens are saved only after a successful cache write.
`[CODE: db.py::_force_one_credentials_resend, ::init_db; app.py sync tick, "Save new version
tokens ONLY after successful cache write"; MonClubApi.get_sync_data]`
`[TEST: test_credentials_token_one_shot.py::test_the_token_is_dropped_exactly_once_across_two_starts,
::test_every_other_token_is_kept, ::test_the_marker_is_never_sent_to_the_backend,
::test_the_full_resend_rewrites_only_the_stale_rows]`

*Where "once" is recorded.* There is no column to key it on, so a row in `local_one_shot_steps
(name, done_at)` — name `credentials_resend_for_grant_diff` — records that the step ran. Not in
`sync_version_tokens`: `load_version_tokens` returns every row, the sync tick sends them all as
`getSyncData` params, and a logout clears the table. Not in `sync_meta`: one row (`CHECK id=1`,
`contract_status NOT NULL`) whose presence is what tells `load_sync_cache` and
`load_sync_contract_meta` that a sync has run, so a marker there would invent a contract snapshot
on a fresh install. `PRAGMA user_version` is one unnamed integer for the whole file; a named row
says what ran. `[CODE: db.py::load_version_tokens, ::_fetch_sync_cache_snapshot,
::load_sync_contract_meta; app.py sync tick]` A fresh install runs the step too: the DELETE finds
nothing, the marker is written, and no later start touches its tokens.
`[TEST: ::test_a_fresh_install_gets_the_marker_and_nothing_else]`

*Atomic, and never lost.* The DELETE runs before the marker INSERT, both inside the one transaction
`init_db` already has open by then and commits at its end. The statement that opens it comes
earlier than the `UPDATE access_history` backfill this paragraph used to name. On every start it is
the unconditional F-015 `DELETE FROM sync_devices` de-duplication at the latest. A migration that
writes rows opens it sooner, for example the members helper's token DELETE on a first start. `init_db`
has one `conn.commit()`, at the end of its `with` block. `[CODE: db.py::init_db; checked with an
in_transaction probe on a fresh and an existing database, 2026-09-26]` A crash between them rolls
both back and the next start acts again.
`[TEST: ::test_a_crash_between_the_delete_and_the_marker_rolls_both_back — it checks, at the cut,
that the DELETE had already run inside the open transaction]` An ordinary error at the INSERT is
logged and startup goes on: the DELETE commits without the marker, so the next start drops the
token again — a second full re-send, never a lost one; the other order could commit the marker
without the drop. `[TEST: ::test_a_failed_marker_write_repeats_the_drop_never_loses_it]` That catch
is deliberate and sits in `_run_one_shot_credentials_resend`. The schema migrations earlier in
`init_db` have no catch and stop startup on a failure. Before that was made the rule it happened by
accident: their inline catches raised `UnboundLocalError` and never logged. §3.2d "A failing
migration stops startup" says why it is now the rule.

*The one-time cost.* One sync carries the whole credentials list and writes it through the diff.
`tools/bench_credential_resend.py` times that write end to end (`save_sync_cache_delta` with only
credentials refreshed, through the writer thread, commit included) against the write the same
sync does without the drop (every section skipped), paired, 21 runs, on the development PC:

| Credentials | Rows that differ | 32-bit `.venv` Python 3.11 | Python 3.13 |
|---|---|---|---|
| 1,500 | none / 5 % / all | +25 / +27 / +45 ms | +15 / +17 / +34 ms |
| 3,000 | none / 5 % / all | +73 / +80 / +93 ms | +46 / +46 / +69 ms |

The response carries about 394 KiB (1,500) or 790 KiB (3,000) of credentials JSON, uncompressed,
in the probe's row shape: the DTO's ten fields, a 40-hex secret (`randomSecretHex(20)`), one grant.
The write bumps the local-state generation, so ULTRA reloads its caches once — what every member
refresh, the daily one included, already does. `[CODE: db.py::save_sync_cache_delta,
::bump_local_state_generation]` "All rows" is a real ceiling: under the previous build a row's
grants were rewritten only when one of its scalar columns changed, so every renewal since then
stayed stale. `[TEST: re-run the tool — a measurement, not a pass/fail test]` `[UNVERIFIED]` the
stale share on a real gym, the timing on a gym PC's disk, and the backend's time to build and send
the list.

*What it does not cover.* A PC that goes back to a build without the grant-aware diff and then
upgrades again keeps its marker, so it is not re-sent: rows left stale in that stretch wait for a
credential change, a forced refresh or a logout. A backend whose token does not digest the grants
(fcfc850c) re-sends on the dropped token too — the null check does not depend on the digest —
but does not move its token for later grant-only changes (above).

The second chance is sound because the stale id and the listed one are the same person: the
credential's `accountId` is the `MainAccountModel` id found by the member's email,
the row's `mainAccountId` is `user.account.id`, and `UserModel.account` is unique (one user per
account). `[CODE: backend main GymAccessController.getGymAccessUsers, ::computeCredentialsVersion;
UserModel.account; client db.py]` A row with no `mainAccountId` never matches. The account ids
are gathered only when no grant is listed, into a set cached per member-list object
(`_roster_account_ids`): ULTRA reuses one object between refreshes, so it is built once
(~0.45 ms for 1,800 rows on the development PC); AGENT's `_load_local_state` hands a fresh copy
per scan and rebuilds it on each such scan. `[TEST: ::test_a_renewed_member_with_stale_grants_passes_by_account,
::test_the_account_second_chance_needs_the_same_account]`

**Shared plans and staff.** In the main sync the backend derives `users[]` and every
credential's grants from the **same** filtered list (`scoped`: dates, status, freezes, gym
permission, unpaid-due and photo rules), so each granted id there is a listed row by
construction. "Family/shared plan" in this codebase is one person's own membership honoured at
the sister gyms of a chain (`gymFamilyAccess` + `sharedGyms`) — each person keeps their own
`ActiveMembership` id; there is no owner/beneficiary split. Staff and coach plans are ordinary
rows. A credential passes as soon as **any** of its grants is listed. `[CODE: backend main
GymAccessController.getGymAccessUsers; MembershipModel.permitsGym]`
`[TEST: ::test_a_shared_plan_credential_passes_when_any_grant_is_listed,
::test_an_empty_member_list_is_unevaluable_and_never_refuses,
::test_index_and_loop_reach_the_same_roster_verdict, ::test_the_index_itself_is_not_filtered_by_the_roster]`

**One verification per refusal.** `verify_totp_resilient` returns a `DENY_NOT_IN_LOCAL_ROSTER`
at once instead of re-running the full check against the wall clock: that retry exists for clock
skew (no match, expired), and on the no-index path it would double the worker's time. It could
only differ if another credential produced the same code in the other time window. The other
way round — the scan-clock pass finds nothing (device clock skewed), the wall-clock retry matches
and refuses on the roster — the retry's `DENY_NOT_IN_LOCAL_ROSTER` is what is reported and
counted. `[TEST: ::test_an_enforced_roster_refusal_does_not_rerun_the_verification,
::test_a_roster_refusal_found_on_the_wall_clock_retry_is_the_reported_verdict]`

**The switch.** Per device, in the device's opaque `deviceCapabilities` JSON:
`{"totpRosterCheckMode": "enforce"}`. `settings_reader.py::parse_totp_roster_check_mode` reads it
into `normalize_device_settings()["totp_roster_check_mode"]`, which both engines use; anything
else — absent, malformed, another value — is `trial`. It survives storage
(`sync_devices.device_capabilities`) to the engine. `[TEST: ::test_the_mode_arrives_from_the_device_payload,
::test_the_mode_survives_device_ingest_to_the_engine_settings]` The backend stores
`deviceCapabilities` as free JSON and the dashboard's device form keeps unrelated keys on save
(`deviceCapabilitiesRaw`). `[CODE: backend main GymDeviceDto; dashboard gym-devices-view.tsx]` On
dashboard `main` no input edits the key — it can only be set by an API call on the device. Dashboard
branch `claude/qr-roster-check-mode` (caa3c2f0) adds a per-device **"Contrôle QR de la liste des
membres"** select, Essai / Appliquer, in the Reader group: Enforce writes lowercase `"enforce"`,
Trial **removes** the key (as AUTO does for `fingerprintTemplateVersion`), unrelated keys survive,
and a saved value is read as this parser reads it (trimmed, case-insensitive `enforce`), so a device
set to `"ENFORCE"` by API loads as Enforce and an unrelated save does not switch it off.
`[CODE: dashboard claude/qr-roster-check-mode gym-devices-capabilities.ts]`
`[TEST: dashboard tests/gym-devices-capabilities.test.ts]` `[UNVERIFIED]` merged or deployed — the
branch was not pushed. An Access build without this section's code ignores the key: it has no
roster check at all.

**Newer index, older member list.** A worker uses the shared index when its generation is `>=`
the worker's own, so the index can carry a credential for a member added after that worker's
member list was loaded. `_handle_totp_rescue` then checks against the process-wide member list
(`_get_shared_local_state`) when it is at least as new as the index — it is published by the
refresh that the index is later built from. Without it, a brand-new member would read as
`not_in_roster`: a false count in trial, a refusal in enforce. The shared list is published
**monotonically**, like the index: a refresh whose slow load straddled a sync commit cannot put
an older complete list back over a newer one (`_set_shared_local_state` ignores a lower
generation; a clear is always allowed). A snapshot with **no members** is not newer information
— `load_local_state` returns `(creds, {}, {})` when its users read fails — so an older complete
list may replace it, it never replaces a complete list at the **same** generation (at a higher
one it does: a gym that really drops to zero members comes with a generation bump), the rescue
never adopts it, and a cold worker that adopts one in
`_get_cached_local_state` starts its own refresh at once (at the current generation nothing else
would reload it before the 300 s TTL). When no non-empty list at least as new as the index
exists, the rescue checks the worker's own (older) list and passes `roster_current=False`; if the
**index** is what matched, a "not listed" code is then `roster_behind` — counted, **never
refused** — because the member may simply be newer than the list. If `verify_totp` fell back to
the loop (the index did not cover the scan's window), the worker's own credentials matched,
from the same load as its list, and the verdict stands. The worker's own list and its generation
are written by the refresh thread without a lock (list first, then generation), so the rescue
reads the generation before and after taking the list and keeps the **lower**: a list is never
labelled newer than it is; a refresh landing mid-read can only make it look older (one scan of
`roster_behind`, no refusal). `[CODE: ultra_engine.py::_handle_totp_rescue,
::_set_shared_local_state, ::_get_cached_local_state; access_verification.py::verify_totp]`
`[TEST: ::test_ultra_checks_a_newer_index_against_a_member_list_at_least_as_new,
::test_ultra_never_adopts_an_empty_shared_member_list,
::test_the_shared_member_list_never_goes_back_a_generation,
::test_an_empty_member_list_is_not_newer_information,
::test_a_cold_worker_that_adopts_an_empty_list_refreshes_itself,
::test_a_list_older_than_the_index_that_matched_never_refuses,
::test_roster_current_only_qualifies_an_index_match, ::test_ultra_loop_fallback_keeps_a_trustworthy_refusal,
::test_a_refresh_landing_mid_read_never_makes_an_old_list_look_current]`

**Counting.** `verify_totp` stays pure — `verify_totp_resilient` calls it twice on the denial
path (scan clock, then wall clock) and tests call it freely. Each engine records the **final**
result once: `record_totp_roster_check` in `_handle_totp_rescue` and in `DecisionService.run`.
It adds one to an in-process counter and, for every verdict other than `in_roster`, logs
`[T] QR_ROSTER_CHECK source=… verdict=… mode=… allowed=…` — no member id, name or credential.
`totp_roster_check_counts()` returns the counts since the process started (they restart with the
app). `maybe_log_totp_roster_summary` logs `[T] QR_ROSTER_SUMMARY` with the running totals at most
once an hour, from each recorded scan and from the ULTRA background refresh loop; the first line
comes an hour after start, and on a PC with no ULTRA worker it comes only with a scan. `[CODE]`
`[TEST: ::test_verify_totp_itself_counts_nothing, ::test_record_counts_one_scan_and_logs_no_member_identity,
::test_the_summary_line_is_logged_at_most_once_per_interval,
::test_ultra_rescue_of_a_removed_member, ::test_agent_decision_for_a_removed_member]`

**How the counts leave the PC — the log upload, and the heartbeat.** Every `[T]` line is in the
app log, and `log_uploader.py` uploads each log window when it closes; the dashboard's "Sync logs
now" button (fast path to 127.0.0.1, else a backend request the PC's `LogSyncRequestPoller` picks
up within ~10 min) uploads the open window on demand. No backend change is needed. **In the
dashboard, only a MonClub admin can open the files:** its Access logs page is in the ADMIN-only
menu and calls the ADMIN-only `/protected/access/logs`; a gym account's dashboard shows upload
status only. The backend also serves each gym its own files at `/api/v1/gym/access/logs` and
`…/download-url` (GYM role, gym taken from the token), but no dashboard page calls them yet.
`[CODE: backend main AccessLogAdminController, AccessLogGymController.resolveScopedGym,
SecurityConfiguration; dashboard config-nav-dashboard.tsx, sync-logs-header-button.tsx]`

The PC heartbeat (`pc_identity.py::build_heartbeat_payload` → `/public/access/v1/pc/heartbeat`,
every 300 s) also carries them, as `qrRosterCheck`: `{since, inRoster, inRosterByAccount,
notInRoster, rosterEmpty, rosterBehind, refused}` from `totp_roster_check_counts()`, with `since`
converted to UTC `…Z` — the shape `lastSyncAt` has always had. Verdict counts only; a counter
that cannot be read, a bad `since`, or any non-integer count leaves the key out whole and the
rest of the heartbeat unchanged. The counts are **per PC** (process-wide, every device and both
modes together), not per device, and restart with the app. `[CODE: pc_identity.py::_qr_roster_check_report]`
`[TEST: test_pc_identity.py::test_heartbeat_payload_uses_existing_version_sync_and_worker_snapshots,
::test_heartbeat_qr_roster_report_is_verdict_counts_only, ::test_heartbeat_qr_roster_since_is_sent_as_utc,
::test_heartbeat_reads_the_real_roster_counters, ::test_heartbeat_without_readable_roster_counts_leaves_the_key_out]`
A backend without the field ignores the key. On backend `main` (e40f8648, 2026-09-19; the same at
a98bf154, 2026-09-25, whose `GymAccessPcService` changes touch only adopt and revoke)
`HeartbeatRequest` declares four fields (`appVersion lastSyncAt lastSyncOk turnstiles`):
`GymAccessPcService.heartbeat` reads the first three and counts `turnstiles`, and since R0 (d9d82d68)
`AccessDeviceStatusService.storeTurnstiles` stores `turnstiles[]` — nothing reads another key. Nothing
enables `FAIL_ON_UNKNOWN_PROPERTIES`: the only `spring.jackson` property is `time-zone`
(`application.yml` Africa/Tunis, `application-local.yml` UTC), there is no `ObjectMapper` bean, and
`JacksonConfig` registers a `Hibernate6Module` and a lenient `LocalDateTime` deserializer, neither of
which sets it — so Spring Boot's default applies and Jackson drops the key; the pre-R0 heartbeat
(d10ba08b, da4a6d18) has the same DTO and the same `JacksonConfig`. `[CODE: backend main
GymAccessPcDtos, GymAccessPcController.heartbeat, GymAccessPcService.heartbeat,
AccessDeviceStatusService.storeTurnstiles, JacksonConfig, application*.yml]` `[UNVERIFIED]` by a live
request, and no backend test pins it (`GymAccessPcAdditiveContractTest` covers paths and JWT, not unknown
keys): a backend that enabled `FAIL_ON_UNKNOWN_PROPERTIES` would answer 400 to every heartbeat of this
build. That is a visibility loss, not a door one: `PcIdentityService.heartbeat_once` changes state only
on `ACCESS_PC_REVOKED`, `ACCESS_PC_INVALID_CREDENTIALS`, `ACCESS_PC_TOKEN_INVALID` and 429; any other
rejection is logged and retried at the next beat. `[CODE: pc_identity.py::heartbeat_once]` Backend branch `claude/qr-roster-heartbeat` adds
`HeartbeatRequest.qrRosterCheck` (`since` bound as text, so an unreadable one cannot 400 the
heartbeat), keeps the latest report per PC in eight nullable `gym_access_pc.qr_roster_*` columns
through a compare-and-set update after the liveness write (a heartbeat without the key leaves the
last report; adoption clears it; hand-run `V112__add_gym_access_pc_qr_roster_check.sql`), and
returns it as `PcSummary.qrRosterCheck`. Backend `main` has since taken `V112`
(`V112__add_access_pc_command.sql`) and `V114`, so that file needs a free number — `V115` or later —
before the branch is merged. `[CODE: backend main a98bf154 src/main/resources/db/migration]`
Dashboard branch `claude/access-pcs-qr-roster-counts` shows it on `/access-pcs` as a caption under
the state chip, with the breakdown in a tooltip. `[TEST: backend GymAccessPcServiceHeartbeatTest,
GymAccessPcHeartbeatJsonBindingTest, GymAccessPcHeartbeatUpdateJpaTest, GymAccessPcServiceAdoptTest;
dashboard tests/gym-access-pc-qr-roster.test.ts, tests/gym-access-pc-model.test.ts]` `[UNVERIFIED]`
none of the three branches is merged or deployed, and no PC has yet been seen sending the key to a
backend that stores it.

**What does not change.** Card checks (`verify_card`), the staff-RFID rescue, and the staff QR
re-entry exemption: the exemption reads `user["membershipId"]`, and `user` was already `None`
for a code whose grants are not listed, so a staff member off the list got no exemption before
either. The deny reason is free text on the backend (`GymAccessDoorHistoryDto.reason`,
`GymAccessDoorHistory.reason`: plain `String`, no enum) and the uploaded row's type still comes
from `scanMode`, so an enforce-mode refusal uploads as a QR row with that reason. `[CODE:
backend main]` The Tauri popup shows it as « Aucun abonnement actif trouvé pour ce code ».
`[CODE: tauri-ui/src/pages/PopupWindow.tsx]`

**What it cannot do.** The check compares against the member list this PC last received. Without
trusted protocol-2 windows (a v1 server, the switch off, §3.8) an **offline** PC's list does not
change, so a member whose membership ends during an internet outage keeps opening by QR until the PC
is back online and syncs. With trusted windows the date flip (§3.8) takes that member off the list
and the allowed-days step below refuses the code. `[CODE]`

**Allowed days (P3b-1, 2026-09-19).** After the roster check and the enforce-mode roster refusal,
before the ALLOW return, `verify_totp(..., access_days=)` asks
`access_dates.qr_date_verdict` about the matched credential's grants and the same member list —
never in `_iter_eligible_totp_creds` / `build_totp_index`, so the index and the loop decide alike.
Every matched QR result carries `dateCheck`:

| `dateCheck` | Means | Result |
|---|---|---|
| `ok` | a grant is deliverable on the applied gym date by its window; or a grant is on the list with no window (a fast patch, a v1 row); or `rosterCheck` is `in_roster_by_account` (a renewal whose grants are stale); or a grant's person (`member_person_link` userId) has a row on the list (another current plan, review round 4) | allowed as before |
| `not_today` | every grant is provably not deliverable today BY ITS WINDOW | **refused `DENY_NOT_ALLOWED_TODAY`, in BOTH roster modes** |
| `unchecked` | no trusted windows (`access_days` None, `trusted=0`, no applied date), or a grant with no stored window and no row on the list — the PC knows no date for it; whether it opens is the roster check's question (trial counts it, enforce refuses it) | allowed as before |

The first version also called a grant with no window and no row on a current list `not_today`: that
turned trial mode into enforce for exactly the members the trial counts — e.g. a renewal whose stored
credential grants are stale and whose row has no `mainAccountId` (review round 2, reproduced against
base: base allowed, the branch refused). `[TEST: test_access_dates.py::TestQrDateVerdict,
test_qr_allowed_days.py::test_a_code_in_neither_the_windows_nor_the_list_is_the_roster_checks_question]`

So with trusted windows, trial mode no longer allows every `not_in_roster` code: a code whose
memberships are all out of their windows is refused. `[TEST: test_qr_allowed_days.py]` The popup
says « Abonnement non valable aujourd'hui ». A date refusal is final in `verify_totp_resilient`
(no wall-clock re-run; a wall-clock pass that produces it is the reported verdict).
`[TEST: ::test_a_date_refusal_does_not_rerun_the_verification,
::test_a_date_refusal_found_on_the_wall_clock_retry_is_the_reported_verdict]`

*The credentials of the gym date.* `load_local_state` passes the stored credentials through
`access_dates.effective_credentials` (the loop AND the speed index use that list): an upcoming
credential is added, enabled, on the first day one of its grants is deliverable (unless the account
already has an enabled one); a main credential gains the upcoming memberships whose `qrAccountId` is
its account and that start today (a renewal). Nothing stored changes; a failed read keeps the stored
list. `[TEST: ::test_an_upcoming_only_credential_opens_on_its_first_day,
::test_a_renewal_adds_the_starting_membership_to_the_existing_credential]` The server enables an
upcoming-only account's credential row only at 00:16 Tunis on the first day
(`DailyScheduleService.nightlySyncGymAccessCredentialEnabledStatus`, cron `0 16 0 * * *`); a sync
between 00:00 and 00:16 lists it `enabled=false` and no longer as upcoming, so that member's QR
waits for the next sync (the wiring arms one at 00:17, §3.8). `[CODE: backend]`
`[TEST: local e2e S6]`

*Which snapshot.* `access_verification.current_access_days(max_generation=)` keeps the snapshots of
the last few local-state generations. The ULTRA rescue passes the generation of the data the scan is
matched against — its own list's as `access_days`, and the shared TOTP index's as
`access_days_index`, which `verify_totp` uses only when the match came through the index (it uses
the index only while that index covers the scan's counter window; a late RTLog event falls back to
the loop over the worker's own credentials, review round 2) — and the AGENT decision the older of its two cached halves, so a list loaded before a flip
is checked against the day it was loaded on: checking it against the newer day refused a renewing
member whose old plan ended yesterday until the worker's refresh landed (found in review of part D),
and checking a newer list against the older day refused a starter and, in trial, admitted an
ex-member at the second door after a flip (review round 1). The ULTRA worker keeps
`(state, generation)` as ONE attribute (`_cached_pair`) written by every writer after the two
separate fields, so the rescue reads the exact generation of the list it got — including a list
`_get_cached_local_state` just adopted from the shared snapshot after a cache reset, which the older
"generation read before the call" labelled pre-flip. No snapshot old enough → `unchecked` for that
scan. `[TEST: tests/test_p3b1_review_r1.py — the ULTRA rescue tests]` A snapshot is labelled with the generation read before its load
and reloaded when the generation moved during the load, so none is labelled newer than its data.
`[TEST: tests/test_p3b1_integration_fixes.py]` Residual: a flip commits, then bumps; a load that
reads the new rows and finishes inside that gap is labelled one generation too old (the transient
false refusal, for that one generation's lists). Same class: an ULTRA background refresh whose load
straddles a row-moving flip installs post-flip rows labelled with the pre-flip generation, so until
the next refresh (the next scan sees the generation moved and triggers it) that list is checked
against the pre-flip day — in trial an ex-member held that night is admitted, which base also did
(no date check). Reported in review round 2; not changed. `[CODE]` A reload on the scan path (the first scan
after a bump, before the refresh warms it) cost 35 ms median on the development PC with 1,860
synthetic windows; a cached call 1.2 µs. Re-measured 2026-09-26 with the snapshot's person map
(1,860 windows and 1,860 `member_person_link` rows): 16–17 ms median, max 38 ms; cached 1 µs.
`[measured, dev PC; gym PC UNKNOWN]` *The person second chance.* The PC's credential diff does not
see a server-side change of a credential's grants, so stored grants can name only an expired plan
of a member whose other plan is current; with that plan's expired window still stored, the date
check refused the member in trial mode offline (base: allowed). The snapshot carries the
`member_person_link` userIds of its windowed memberships, and a grant not deliverable today is `ok`
when the same person has a row on the list. `[TEST: tests/test_p3b1_review_r4.py — the QR tests]`

*Counting.* `record_totp_roster_check` also counts `not_today` and logs
`[T] QR_DATE_CHECK source verdict=not_today` (no member identity). `refused` keeps its meaning (the
roster check's own refusals); the counters are not exclusive. `QR_ROSTER_SUMMARY` gains `not_today`.
`[TEST: ::test_a_date_refusal_is_counted_and_logged_without_member_identity]` Card checks
(`verify_card`) have no date input: a held member's card is refused because the flip took the row
off the list the card index is built from. `[CODE]`

**Before switching a device to enforce** — known ways a valid member could still read as
`not_in_roster` `[CODE]`, which is what the trial counts are for:
- A renewal whose new membership sits on a row **without** `mainAccountId` (a user with no linked
  main account) fails both the stale grant and the account second chance — only while its grants
  are stale (above); once a credentials sync writes the new grant it passes as `in_roster`.
- The fast-patch path builds credentials with `AccessPatchBundleService.shouldExposeMembership`,
  which omits the photo (`blockAccessForUnphotographedMembers`) and unpaid-due
  (`allowEntryPastDueDate`) rules the main sync applies — so a fast-patch credential can grant a
  membership the member list deliberately leaves out. Enforce refuses that member, which matches
  the main sync's intent, but trial counts will include them. Since 2026-09-18 such grants are
  written even when they are a credential's only change, and they stay: the main sync re-sends
  credentials only when the credentials token moves (`GymAccessController.computeCredentialsVersion`
  digests the main sync's own list, which the patch does not change), and a membership trigger
  strips only `membersVersion` (`sync_scope.py::apply_trigger_hint_to_version_tokens`). So the
  patch's grant list lasts until another credential change, a forced refresh or a logout moves
  the token. That allows nothing the member list does not: a grant allows only when it is listed,
  and the account second chance does not read grants. `[CODE: access_verification.py::verify_totp;
  sync_scope.py; backend main GymAccessController, AccessPatchBundleService]`
- Removed members still count as `not_in_roster` only until their credential is removed by a
  sync; the counts measure the gap, not a steady state.
`[UNVERIFIED]` How often any of these happens on a real gym — that is the trial's job.

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
  `allowedMemberships` runs BEFORE the collision is possible (the roster has no date filter, §3.8). An
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
| `DeviceSyncEngine.sync_member_on_connected_sdk` (PullSDK targeted push / revoke) | `pin = member_id`; rows of that membership | `pin` = the person's account pin; rows = EVERY row of the person (`person_rows_for_membership`), so the collapse is complete; unmappable → nothing pushed or deleted; `revocation=True` with the person still deliverable → the collapsed row is re-pushed even when its hash is unchanged, and that push is the return value. Both schemes: a pin that is no longer deliverable is deleted ONLY when owned (P3a-2, §3.4) |
| `DeviceSyncEngine._sync_one_device` `known_server_pins` | `activeMembershipId` of every user | account pin of every user |
| `_sync_one_device` delta pruning / drift check (`int(pin) in changed_ids`) | verbatim | `pin in` the account pins of `changed_ids` |
| `UltraDeviceWorker._build_standalone_roster(only_member_ids)` | `wanted = {str(int(m))}` | the account pins of those memberships |
| `UltraDeviceWorker._load_member_roster` | that membership's row | every row of the person |
| `UltraDeviceWorker._defer_member_sync` | flags `str(member_id)` | flags the person's pin; none when unmappable |
| `UltraDeviceWorker._run_standalone_member_revoke` | removes `str(member_id)` (ownership-checked; not owned → `SKIPPED_NOT_OWNED`, final, §3.4) | see below |
| `_run_standalone_full_sync` explicit-revocation ownership check + `required_pins` | `str(member_id)`; a revoked pin that is not owned is dropped from the pass as `SKIPPED_NOT_OWNED` (§3.4) | the person's pin, and only when it LEFT the desired roster (a still-desired person pin is re-pushed, never skipped) |
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
stale-pin delete, the FULL_REPLACE table clear and both prunes; and the two TARGETED removals
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

**The PullSDK nuke heuristic no longer exists (P3a-2, §3.2g).** INCREMENTAL used to clear every
table when stale pins outnumbered desired ones; it was suppressed only for a device with a
`device_pin_scheme_switch` row, which gym 58's C3-400s (pinScheme '') never have. Right after a
switch the old scheme's pins ARE that majority, and the stale step now goes through the one
removal ceiling, which refuses it (`REVOKE_ABORTED`, rows kept) instead of removing them one by
one — the cutover stays a manual wipe (§3.2e). An explicit `FULL_REPLACE` clears only a panel
whose rows fit under the same ceiling. `[CODE: device_sync.py::_sync_one_device]`
`[TEST: test_account_pin_device_sites.py::test_a_device_with_scheme_history_is_never_nuked_by_the_heuristic,
::test_the_nuke_heuristic_no_longer_fires_without_scheme_history]`

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

`_neutralise_revoked_pins` is trigger-independent: it runs on every standalone full sync — since
P3a-2 BEFORE the push and whatever the push then does (§3.4b) — and it is the only removal path a
PRESERVE device has. Its candidate set is `owned` (pins
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
| `_reconcile_held_rows` (P3b-1) | a held row restored at a save — a column-for-column copy from `sync_users_held` |
| `apply_local_date_flips` (P3b-1) | the date flip: restore (column copy) and promote (`_upsert_sync_user_row` of the stored upcoming row) |

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
missing column again. `[TEST: ::test_the_column_and_the_token_drop_commit_together]` An *error*
in between does the same, because `init_db` does not catch it (see "A failing migration stops
startup" below). `[TEST: test_init_db_migration_failures.py::test_a_main_account_column_that_fails_after_the_token_drop_rolls_the_drop_back]`
**The same trap on the device side (review #13).** `sync_devices.pin_scheme` also arrives NULL,
and `devicesVersion` survives the upgrade, so the backend answers `refreshDevices=false`: a device
set to ACCOUNT while the PC still ran the old client would read as MEMBERSHIP (no switch, no hash
clear) until an unrelated device edit moved the token, and then switch with no wipe in between.
`_ensure_pin_scheme_column` therefore, when a sync_devices table that existed before `init_db`
lacks the column (measured before the `CREATE TABLE`, so a fresh install is not an upgrade),
deletes `devicesVersion` — the device section's only progress token — and records every device
already in the table as seen on MEMBERSHIP (the old client had no other scheme, so the ACCOUNT
value the refresh brings is a real switch, §3.2e). Same one-shot, DELETE-before-ALTER atomicity
as the members helper, for a crash and for an error. The backend half (`refreshDevices =
clientDevicesVersion == null || …`) was read in `GymAccessController`, not run.
`[CODE: db.py::_ensure_pin_scheme_column, init_db]`
`[TEST: test_pin_scheme_switch.py::test_an_old_database_gains_pin_scheme_and_forces_one_device_refresh,
test_init_db_migration_failures.py::test_a_pin_scheme_column_that_fails_after_the_token_drop_rolls_the_drop_back]`

If the backend in use does not emit `mainAccountId`, the refresh still runs once and the column
stays NULL: MEMBERSHIP devices are unaffected, ACCOUNT devices withhold everyone (§3.2b).

**A failing migration stops startup — on purpose (owner's decision, 2026-09-25).** `init_db` calls
`_relax_firmware_profiles_not_null`, `_rebuild_sync_users_without_legacy_fingerprint`,
`_ensure_main_account_id_column` and `_ensure_pin_scheme_column` with no `try`. When one of them
fails, its own exception leaves `init_db` and `get_conn` closes the connection uncommitted. Neither
`access/store.py::init_db` nor `MainApp.__init__` catches it, and neither does `access/main.py::main`
or `app.py::run_app`, so the process exits. The traceback goes to stderr, which is
`%TEMP%\MonClubAccess.log` when the process has no console (`access/main.py::_ensure_console_streams`;
`app/main.py` redirects to the same file; no `sys.excepthook` is installed anywhere in the repo,
grep 2026-09-26). The next start runs the migration again. `[CODE: db.py::init_db;
access/store.py::init_db; app.py::MainApp.__init__, ::run_app; access/main.py::main]`

What rolls back is the transaction, and Python's `sqlite3` opens it at the first INSERT, UPDATE or
DELETE, not at DDL. A `CREATE`, `DROP` or `ALTER` that ran before that is already committed. So a
failed first start keeps the tables it had created, and a failed `_relax…` leaves an empty
`sync_firmware_profiles__new`, which the retry drops first. `[TEST: test_init_db_migration_failures.py
— each of the four made to fail at its entry, and each failed between two of its statements through
a connection proxy, followed by a clean start: ::test_a_failing_migration_raises_its_own_error_and_the_next_start_completes,
::test_a_legacy_rebuild_that_fails_midway_leaves_no_copy_behind,
::test_a_firmware_profile_rebuild_that_fails_midway_keeps_the_cached_profile, and the two token
tests above]`

*Why not log and go on.* The four used to sit in `except …: logging.getLogger(…).error(…)` wrappers
written to do exactly that, and `_ensure_pin_scheme_column`'s also added the column with
`_ensure_column`. But `init_db` imported `logging` in its own body (the stale-lock resets after its
`with` block). A name bound anywhere in a function is local to all of it, so every one of those
`except` branches raised `UnboundLocalError` instead of logging: a failing migration already
stopped startup, by accident. `[TEST: ::test_init_db_binds_no_local_logging — the local imports are
gone]`

Making the wrappers work was measured and is worse. The run was on 2026-09-25, from scratch scripts
that are not in the repo: the four imports removed, the wrappers kept, a failure injected between
two statements, then clean starts.
`[CODE: git show 832af74:app/core/db.py, init_db's four wrappers; Python's sqlite3 opens a
transaction only at DML]`
No test pins this. To check: on 832af74, delete the four `import logging` lines in `init_db`, then
run `tests/test_init_db_migration_failures.py::test_a_legacy_rebuild_that_fails_midway_leaves_no_copy_behind`.
It fails with `DID NOT RAISE`, after `[DB] schema migration _rebuild_sync_users failed` is logged:
the first start completed with the copy committed. Calling `init_db()` twice more after the same
`_fail_once` cut fails both times with `UNIQUE constraint failed: sync_users.user_id,
sync_users.active_membership_id`. Checked this way on 2026-09-26.

What the run showed:
- **Legacy `sync_users` rebuild failing at `DROP TABLE sync_users`:** a full `sync_users_new` was
  committed. The next start copied the rows into it again, and it and every later start failed on
  `uq_sync_users_uid_amid`.
- **Firmware-profile rebuild failing at its RENAME:** the DROP of the old table was committed, a
  later `CREATE TABLE IF NOT EXISTS` made an empty one, and the cached profile stayed in the orphan
  copy.
- **`pin_scheme` failing at its `devicesVersion` DELETE:** the fallback added the column, so the
  forced device refresh never ran.
- **`_ensure_main_account_id_column`:** it cannot go on at all. The unguarded
  `idx_sync_users_main_account` index fails without the column, and every `sync_users` writer names
  it.

With no catch, each of these rolls back and the next clean start completes (the tests above).

The cost: a fault that persists (a corrupt file, a full disk) stops the app on every start until it
is cleared, as it already did. Not everything in `init_db` stops startup:
- the plain `_ensure_column` adds swallow their own `ALTER` error, silently (`db.py::_ensure_column`);
- the one-shot credentials drop logs and goes on (§3.1b "The upgrade window");
- the stale-lock resets after the commit log and go on. `[TEST: ::test_the_stale_lock_resets_still_log_through_the_module_logging]`

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
history for the scheme-aware readers (§3.2b inbound). `[CODE: db.py::_record_device_pin_scheme_switch]`
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
>
> A full procedure for gym 45 -- survey, wipe, the manual retire of the old-scheme rows, the switch, an
> interlocked re-push and the rollback rows -- is planned (not executed) in
> [`docs/plans/2026-09-19_gym45_cutover_plan.md`](docs/plans/2026-09-19_gym45_cutover_plan.md).
> Gym 58's two C3-400 panels (PullSDK) are planned in
> [`docs/plans/2026-09-26_gym58_cutover_plan.md`](docs/plans/2026-09-26_gym58_cutover_plan.md), and the
> night that does both in [`docs/plans/2026-09-26_cutover_night_runbook.md`](docs/plans/2026-09-26_cutover_night_runbook.md).
> **On a PullSDK panel the retire is not needed**: the stale set there is built from the pins READ from
> the panel, so after a verified erase it is empty, and the first clean ACCOUNT pass prunes the old
> rows (`device_sync.py::_sync_one_device`, `db.prune_device_sync_state`) `[CODE]`. The erase itself
> is the Erase-content wizard since lane 1 (2026-09-27, §3.2h), for both SDK families; before it,
> `clear_device_table`'s only caller was the ceiling-gated `FULL_REPLACE` clear (§3.2g) `[CODE]`.

**A switch reaches the running workers before any pass is queued (release MUST, lane B, 2026-09-26).**
Until this change a dashboard `GYM_DEVICE` fast patch recorded the switch and logged
`[T] PIN_SCHEME_SWITCH` (`app.py::apply_fast_patch_bundle` → `db._insert_device_row`) and then queued
a full pass (`_request_running_ultra_sync`), but a running `UltraDeviceWorker` kept its own device copy
until the next successful sync's device refresh, and the pass pushed from that copy
(`ultra_engine.py::_drain_full_sync_commands`) — MEMBERSHIP pins onto a terminal just wiped for
ACCOUNT, including a pass queued while the link was down and one already pushing. A server sync had
the same gap: it saved the device section, then refreshed the workers only near the end of its tick,
after the DeviceSync run, the fingerprint report and the attendance upload. `[TEST: red on aeeef69]`
Now `[CODE]`:
- **The copies follow the database first.** `MainApp._refresh_running_ultra_devices` (under
  `_ultra_lock`, only while the engine runs) hands `UltraEngine.refresh_devices` the ULTRA rows of
  `db.list_sync_devices_payload()` that already have a worker. `refresh_devices` updates those workers'
  copies whatever their lease state, and gives the ULTRA scheduler only the lease-filtered list (review
  R1-F5: a copy left stale while a lease was away made the guard below stop every pass once it came
  back). Devices without a worker are left out on purpose: `refresh_devices` also replaces the
  scheduler's list, and the scheduler pushes a device with no worker over its own session (R1-F2); a
  device added or switched to ULTRA gets its worker when the next tick restarts the engine, as before.
  The scheduler's list itself is replaced only when every worker is driven — the end-of-tick refresh's
  own condition — so a lease away during a refresh cannot empty it for good (review R2-4).
  `apply_fast_patch_bundle` calls it when any item of the bundle is `GYM_DEVICE` or carries
  `requiresDeviceRescope` — applied or not, the database is the truth — right after the database apply
  and before its date flip (which may queue a pass itself, R1-F6) and both dispatch branches; the sync
  tick calls it right after each `save_sync_cache_delta` whenever `refresh["devices"]`, before that
  save's date flip (the refresh near the end of the tick stays), and so does the enrolment fallback
  after its full `save_sync_cache` (review R2-3). In the fast patch a failed refresh is logged,
  schedules the full reconcile, and still dispatches: the guard below refuses the old scheme's pins,
  and the bundle's revocations are not held back. In the tick and the enrolment fallback it is only
  logged (R2-2): the guard stops that device's passes until a later refresh — the end-of-tick one when
  that tick's final answer still carries the devices section (not after the device-scope follow-up,
  whose flags replace the first answer's, review R3-F2), the next device section, or an engine
  restart.
- **Every push pass re-checks the recorded scheme.** `device_sync.pin_scheme_superseded` compares the
  scheme a pass derived its pins under with `sync_devices.pin_scheme` (`db.get_device_pin_scheme`, one
  primary-key read). MB2000: the full sync at its start (the device copy — nothing removed, nothing
  pushed), before the push (`_push_with_chunk_recording`, the roster's own scheme) and between chunks
  (`_standalone_push_yield`); the targeted member push; the ACCOUNT revoke re-push. PullSDK: the ULTRA
  worker's pass at its start, `DeviceSyncEngine._sync_one_device` at its start (before any session)
  and again after its panel read, before the removal steps (the stale delete, a `FULL_REPLACE` clear —
  R1-F3), and before its user batch (`PinSchemeSwitchedError`, so every caller reads a failed pass,
  never an in-sync panel), and `sync_member_on_connected_sdk` (`DEFERRED`). A stop at a pass's start
  sends nothing; a later stop sends nothing more — what that pass already did stays done (see "What is
  left" for the steps that run without a re-check of their own). No stop stamps a roster hash; its revocations stay pending;
  `[T] PIN_SCHEME_PASS_STOPPED`. The next pass is the one the app queues after the refresh.
- **What is left.** On the MB2000 the chunk already in flight when the switch lands (at most
  `_PUSH_CHUNK_MEMBERS` = 10 members, handed over before the switch existed); on PullSDK a removal step
  or a user batch already started (no abort inside either); on the MB2000 the removal step
  (`_neutralise_revoked_pins`), which runs between the pass-start check and the push check with no
  re-check of its own — with one pass per worker only old-scheme pins can be owned then, so what it
  removes is a correct old-scheme removal (review R4-3); and the post-push release of a renewal
  hold (§3.4f) — it deletes only MonClub's own old pin of a renewing member, a pin being written under
  the new scheme is never among them on the MB2000 (`_remove_released_holds` skips pins touched
  mid-push), and one worker drives each PullSDK panel (review R2-1). A worker the watchdog rebuilds
  from a dead worker's copy at the very moment a refresh lands may keep the old copy until the next
  refresh; its passes are stopped meanwhile `[UNVERIFIED — not reproduced]`.
  **Not covered, as on base (review R3-F1):** a sync answer the server built just BEFORE the switch
  and saved just after the fast patch writes the old scheme back — the database records it again
  (`PIN_SCHEME_SWITCH previous=ACCOUNT scheme=MEMBERSHIP`), the workers follow the database, and the
  guard, which compares with the database, lets the pass push the old scheme; the next sync switches
  back (the stale answer stored its stale devicesVersion). `save_sync_cache_delta`'s device section
  never consults the fast-patch revisions, for any device field. `[TEST: review round 3 probe, scratch;
  the same revert on aeeef69]` Timing `[UNVERIFIED]`. The cutover's cables-out interlock and proven
  restart cover it; a check that no `previous=ACCOUNT` switch line follows the switch would make the
  restart proof catch it (runbook C13 — lane D's file, not edited here). A targeted revoke drained between the save and the refresh
  names its pin under the previous scheme — what an unwiped terminal holds. A device row that cannot be
  read is not re-checked (logged): a broken database already stops every write at its write-ahead
  intent (§3.4a). `[CODE]`
`[TEST: test_pin_scheme_worker_refresh.py — the real fast patch on a temp database driving a real
worker over a fake MB2000 (pin 5 is Alice's membership and Bob's account), a pass queued while the link
was down, a switch mid-push and before the push, a pass drained before the refresh, the four PullSDK
sites, the tick order, the refresh helper, and the review-round-1 cases (no device without a worker for
the scheduler, a copy refreshed while the lease is away, the refresh before the flip, no removal after a
switch during a panel read); 16 of its 19 tests fail on aeeef69 (two controls pass, and the no-worker
case, which guards this change itself) — two of the panel ones only at the import of
`PinSchemeSwitchedError`, where a scratch probe showed aeeef69 writing the MEMBERSHIP pins 5 and 6, and
the three helper ones because the helper is new;
test_fast_patch_runtime.py::test_apply_fast_patch_bundle_requests_device_rescope_sync pins the order
refresh → dispatch]`
The cutover procedures still restart Access after the switch, before a terminal is reconnected
(runbook C13, D15, gym 45 plan E10b): a second guard, not replaced by this one.

**Known consequence after a switch: the revoke pass stays aborted.** The old scheme's
`device_sync_state` rows remain `ownership_confirmed=1` (deliberately, §3.2c). The revoke pass's
candidates are `owned − keep`, i.e. essentially every old-scheme pin, which exceeds the floor, so it
returns `REVOKE_ABORT_FLOOR` / `safe_to_prune=False` on every full sync; a full sync that also
carries explicit revocations reports "authoritative revocation unconfirmed". Targeted member
revokes (§3.2b) are unaffected. `[CODE: ultra_engine.py::_neutralise_revoked_pins]` Retiring the
old-scheme rows after a confirmed wipe is the Erase-content wizard's "Forget MonClub's records" option
(lane 1, 2026-09-27, §3.2h): an operator-confirmed action, run only after the wizard itself verified
the users erase. `[CODE]` `[TEST: test_erase_wizard.py]` Never exercised on hardware `[UNVERIFIED]`.

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

### 3.2g One removal ceiling, no automatic wipe (P3a-2, 2026-09-18)

**The rule.** Every bulk removal from a terminal goes through ONE function,
`push_safety.check_bulk_removal`: the MB2000 revoke pass (`path=standalone_revoke`), the PullSDK
stale-pin delete (`path=stale`) and the PullSDK `FULL_REPLACE` table clear (`path=table_clear`,
counted as every row on the panel, because `DeleteDeviceData(table, "", "")` deletes them all,
foreign users included). The ceiling is the standalone revoke pass's own rule,
`max(REVOKE_ABSOLUTE_FLOOR=10, desired_roster × MAX_DELETE_FRACTION=0.25)`, strictly greater is
refused; an empty desired roster refuses any removal. `[CODE: app/core/push_safety.py]`
`[TEST: test_push_safety_foundation.py::TestRemovalCeiling]`

**Refused = `REVOKE_ABORTED`, retryable, never final.** Nothing is removed, the per-pin state is
kept (the prune is skipped on both paths, so the kept pins stay reachable — the §3.2c invariant),
`[T] REVOKE_ABORTED device_id protocol path count roster ceiling reason sample` is emitted and the
push-batch row carries `REVOKE_ABORTED=n (...)` in `error_message` (`/api/v2/push-history`). The
rest of the pass — the push of new/changed members, the door-parameter writes — still runs and
the pass is not failed by it. An explicit revocation that needed the refused step stays
unconfirmed (retried), exactly as before. It is deliberately NOT `SKIPPED_NOT_OWNED` (final): an
abort that finalised a revocation would silently drop it. `[TEST: test_removal_ceiling_pullsdk.py]`

**Why the INCREMENTAL wipe is simply gone.** Its trigger `stale > desired and stale > 10` is always
above the ceiling: desired ≤ 40 → ceiling 10 < stale; desired > 40 → 0.25 × desired < desired <
stale. So passing it through the ceiling could only ever refuse it; the code is removed.
`[TEST: ::TestRemovalCeiling::test_the_old_nuke_trigger_is_always_above_the_ceiling]` It was armed on
gym 58: `pushing_to_device_policy=1` resolves to INCREMENTAL (`_resolve_push_policy` has no integer
mapping), and pinScheme '' writes no switch row, so its only suppression never applied. The ULTRA
worker relabels the device `accessDataMode=DEVICE` before handing it to `DeviceSyncEngine` (§3.3), so
no ULTRA-only branch is used: the rule is one code path, DEVICE mode included (no fleet device is
DEVICE-mode). `[TEST: ::TestTheProductionUltraPath]` — both the worker full sync and the scheduler
fallback relabel path. `[UNVERIFIED]` whether the wipe ever actually fired on gym 58: FIELD-TEST —
grep that PC's logs for `NUKE-AND-REPAVE` / `ClearDeviceTable(table=`.

**A failed delete keeps its row (PullSDK).** The stale step used to erase `device_sync_state` and
the mirror for every attempted pin "regardless of SDK outcome", so a delete the panel refused left
no trace: once the member had left the roster nothing ever tried again. Now only confirmed deletions
are forgotten (`clear_device_revocation_state`: state, mirror and push intent in one transaction);
a failed one keeps its row and ownership bit, the prune keeps it too, and the push-batch note says
`REMOVAL_FAILED=n`. `[TEST: ::test_a_failed_stale_delete_keeps_its_state_for_the_retry]` The prune also
keeps the row of every pin still on the panel: under `ADDITIVE_ONLY` (no stale removal) it used to drop
it, and the member's later explicit revocation then found no ownership and was skipped for good
(review R3-06). `[TEST: test_review_round3.py]`

**Accepted consequence: an above-ceiling departure is not removed, and says so once** (review round 1,
R1-04/05/13 — this is the rule working as specified, not a defect). A step refused by the ceiling stays
refused on every later pass until the count falls under the ceiling or the roster grows; the pass
itself is `ok`, so the scheduler stamps the roster hash and the refusal is re-reported only when the
roster changes. Triggers seen by the reviewers: 11 members of a 40-member door removed at once
(`allowedMemberships` edited to drop a plan — they stay active members, so no revocation is sent);
more than 25 % of a C3 panel's roster leaving between two passes (e.g. the PC off during a closure);
a pinScheme cutover without the manual wipe (§3.2e: before P3a-2 the PullSDK stale step removed the
old-scheme pins one by one; now the ceiling refuses them). Those members keep their cards on that door
until an operator acts. The operator-confirmed override this needs does not exist
(`[UNKNOWN — not built; needs a decision]`, as §3.2e already records for the MB2000).
**Two more consequences:** a `FULL_REPLACE` panel's clear counts every panel row, so on an established
panel it is refused on every pass (and the prune skipped) — no deployed gym is known to use
`FULL_REPLACE`; and the PullSDK ULTRA full sync's **explicit-revocation pre-pass** removes each revoked
member through the ownership-gated targeted path with no ceiling (unchanged from base; the MB2000 routes
the same revocations through its ceiling-gated revoke pass) — so "every bulk removal goes through one
ceiling" does not cover explicit PullSDK revocations. `[CODE: ultra_engine.py::_drain_full_sync_commands]`

**Renewal holds (P3b-1, §3.4f).** The removals-first step's ceiling judges what that step removes
— the real leavers; the holds are set aside first. The released holds are removed after the push only
while (pins removed first this pass + released holds) stays within the same ceiling, else they are
all kept for a later pass (`REVOKE_ABORTED path=renewal_release`). So a pass never removes more than
the ceiling allows, as when the old pins were removed first. The first version counted the holds in
the step's ceiling; a renewal whose new pin kept failing then stayed in the count on later passes and
could push a later day's leavers over it — `REVOKE_ABORTED`, the ex-members left on the turnstile —
where base, having removed the old pin on the first day, removed them (review round 1, reproduced on
both SDKs). `[TEST: test_renewal_ordering.py::TestStandaloneCeilingAndFailures::test_the_ceiling_judges_the_leavers_and_a_release_beyond_it_waits,
::test_a_kept_hold_does_not_push_the_next_days_leavers_over_the_ceiling, and the same two in
::TestPullSdkRenewal]`

**Driver leases and Confirm removal (P3b-2, 2026-09-26).** Before the ceiling, a turnstile this PC is
handing over or runs add-only (§3.9) refuses the step with reason `handover_release` / `add_only`: retryable
like a ceiling refusal, reported as `[T] REMOVAL_DEFERRED`, never as `REVOKE_ABORTED` and never recorded as a
problem. Above the ceiling, a `REMOVAL_CONFIRM` approval for EXACTLY the refused pin set (count and canonical
hash, not expired) lets that one `standalone_revoke` or `stale` step through once (`[T] REMOVAL_CONFIRMED`);
never a `table_clear`, a `renewal_release` or an empty roster. Every refusal of those two steps is recorded, all
its pins, for the turnstile problem report. `[CODE: push_safety.py]` `[TEST: test_v2_add_only.py, test_v2_problems.py]`

**What stays different.** MIRROR keeps its own stricter, purely fractional floor (§3.2c) — merging it
into the shared ceiling would RELAX it below 40 members. Single-pin removals (a targeted revoke)
are count 1, always under the ceiling; they are gated by ownership instead (§3.4). The PullSDK
stale set is still NOT ownership-gated (it is `known_server_pins ∪ device_sync_state rows`, §3.3);
the ceiling is that path's rail.

**Deliberate test inversions.** `test_batch_device_push.py::test_stale_exceeding_desired_never_clears_the_tables`
and `::test_a_refused_stale_step_deletes_no_stale_pin_individually` (were: the nuke fires / the nuke
avoids individual deletes), and `test_account_pin_device_sites.py`'s two scheme-history tests (were:
12 stale pins against a roster of 2 are removed one by one / the nuke fires without history).

### 3.2h The Erase-content wizard — the manual wipe, as an Access feature (lane 1, 2026-09-27)

**Where.** Devices page → the bin icon on a turnstile's row → five steps: the tables with their counts
(read-only), the choice, the options, the confirmation, the run. Owner's design, 2026-09-27. Server
`app/core/erase_wizard.py`; routes `GET /api/v2/devices/{id}/erase/preview`, `POST
/api/v2/devices/{id}/erase`, `POST /api/v2/devices/{id}/erase/refill`, `GET /api/v2/erase/status`, `GET
/api/v2/erase/holds` (the first two lease-gated). Page `tauri-ui/src/components/EraseWizardDialog.tsx`, in
French and English — the rest of the Access UI is French only, so it carries its own dictionary
(`src/lib/eraseWizardText.ts`). `[CODE]`

**The tables — by protocol, never by model (§2).** `[CODE: erase_wizard.C3_TABLES, ::MB_TABLES]`

| Protocol | Erasable | How | Shown, never erasable |
|---|---|---|---|
| `ZK_PULLSDK` (C3-400) | `user`, `userauthorize`, `templatev10`, `template` | `DeleteDeviceData(h, table, "", "")` (`PullSDKDevice.erase_table` → `clear_device_table`), one table per command, fingerprints and door rights before the user rows | `transaction` |
| `ZK_STANDALONE` (MB2000) | `users` (every NON-admin user row: card, password, fingers), `fingerprints` (non-admin users' slots) | `delete_users` → `SSR_DeleteEnrollData(1, pin, 12)` (backup number 12, `[FIELD]` 2026-09-06, zkemkeeper guide §3), 20 pins per command; `sweep_finger_slots` → `SSR_DelUserTmpExt`, ≤ 3 slots per command | the attendance log |

Never a parameter, timezone or holiday table (not in the list), never the finger-index delete that hangs
the MB2000. Administrators (privilege > 0) and their fingers are kept, as script 13 keeps them. A table
whose count does not read is shown `—` and cannot be chosen. `[TEST: test_erase_wizard.py::TestPreview,
::TestMb2000::test_fingerprints_only_keep_the_users_and_the_admins_fingers]`

**Door logs are not erasable — why.** The owner's rule is "send every event not yet uploaded, then
erase". This PC cannot say which panel rows it already sent: the server de-duplicates on `(deviceId,
eventId)` (backend `DoorHistoryDedupeKey`, read not run), a live-captured row's id is the RTLog one
(`time|card|event|…`) and a panel row read later would get another (the DEVICE harvester's SHA-1 of the
row), so re-sending would store every event twice; `_device_row_to_history` has no key for a C3
`transaction` time field, and no real C3 transaction row nor any MB2000 attendance-log read has ever been
made by this app `[UNVERIFIED]`. There is no documented MB2000 log clear either (`ClearGLog` is only in
script 13, marked unverified there). So both logs are counted and refused (`DOOR_LOG_NOT_SUPPORTED`).
`[TEST: ::TestTheRightDeviceOnly::test_a_door_log_or_an_unreadable_table_cannot_be_chosen]` The cutover
does not need them.

**Before anything runs** (`EraseWizard.start`), all of: a preview of THIS turnstile younger than 15
min, whose id, name, address, port and protocol have not changed; the typed name equal to the
turnstile's name (trimmed, exact); tables that the preview showed erasable; for "forget", the users
table among them; **on a C3, `user` only together with every rights and fingerprint table the preview
could read** (`USER_NEEDS_RIGHTS_AND_FINGERS`, with or without "forget": left behind, an old pin's door
rights and fingers would pass to whoever gets the same pin next — ACCOUNT pins reuse membership numbers,
§3.2e); **on an MB2000, the users erase only with "forget"** (`USERS_ERASE_NEEDS_FORGET`, see the
residuals); on an MB2000 with the users table chosen, the faces' loss accepted when status 21 reports
faces (`FACES_PRESENT`) **or does not answer** (`FACES_UNKNOWN`: an unreadable count is not zero, and no
face backup exists); this PC drives the turnstile, it is not being handed over and not add-only (§3.9); a
running, connected ULTRA worker drives it — every call goes through its connection (`request_run_sdk`),
never a second session; **that worker is connected to the address MonClub records** (`ADDRESS_CHANGED` /
`ADDRESS_UNKNOWN`, below); the erase holds were read at start-up (`HOLDS_UNKNOWN`); no Refill of that turnstile
is in progress (`REFILL_IN_PROGRESS`); the pin scheme reads (the run records it; `PIN_SCHEME_UNREADABLE`
otherwise); no other run; and **the admin password, checked by the server** (`validate_statistics_password`, the Local DB
page's call) — the page's own lock is a screen, and offline the password cannot be checked, so nothing is
erased (503 `ADMIN_PASSWORD_UNCHECKABLE`, lane 1b: never read as a wrong password). The refusal's code
(`erase_wizard._password_refusal`, start and Refill): a 401 is `ADMIN_PASSWORD` (a wrong password —
`validate_statistics_password` answers False on a 401 alone; whether the backend also answers 401 for a rejected gym
token is `[UNVERIFIED]`); 503 `ADMIN_PASSWORD_UNCHECKABLE` (offline), or `PC_NOT_SIGNED_IN` when this PC has no gym
token (the verifier answered 401 "Not authenticated" for that before review round 1); 400 `ADMIN_PASSWORD_REQUIRED`;
any other status (a proxy's 502/504, a 5xx) `ADMIN_PASSWORD_CHECK_FAILED`, shown with the server's words. `[TEST: test_erase_wizard_gaps.py::TestTheRefillRoute]` The page ticks and locks the C3
rights and fingerprint tables when `user` is ticked, fixes "forget" to yes for an MB2000 users erase, and asks the face
confirmation for an unknown count too. `[TEST: ::TestNothingIsErasedWithout, ::TestTheRightDeviceOnly, ::TestLocalApi,
::TestC3UsersNeedsRightsAndFingers, ::TestMb2000UsersEraseForgets, ::TestUnknownFaces,
::TestNoRunWhileTheHoldsAreUnknown; test_erase_wizard_gaps.py::TestTheRefusalGates — every gate above, ADD_ONLY at
start and inside a write, the 15-min preview and its single use, BUSY; ::TestTheMb2000RefusalGates; ::TestTheRefillRoute]`

Since lane 1b (2026-09-27, the master review), an erase (not a backup-only rehearsal) also needs `[CODE]`:
- **`otherPcsClosed: true`** (`OTHER_PCS_NOT_CONFIRMED`, 400) — the page's required tick box "MonClub Access is closed on
  every other PC of this gym — on each: 'Ouvrir MonClub Access avec Windows' unticked, the watchdog switched off
  (`Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'`), then Quit — and stays closed until the refill" (FR/EN;
  lane 1c, review C1: quitting is not enough — `register_watchdog.ps1` registers that task at logon and every 2 min and
  `monclub_access_watchdog.ps1` starts Access again after two misses at least 90 s apart, and the Run-key autostart brings
  it back at the next logon; the order is runbook C1 / D1's) `[CODE]` `[TEST: test_erase_wizard_lane1c.py::
  TestTheOtherPcsTickNamesTheWatchdog]`. Why the box (review C0, verified): the hold is this PC's
  `device_write_hold` and in-memory set only; with no driver assignments (v2 off, or `gymUsesAssignments=false`)
  `LeaseSnapshot.allows()` answers True for every turnstile and `app.py::ultra_devices_for_this_pc` starts a worker for
  every ULTRA turnstile — so every Access PC of the gym writes to this turnstile during the erase and refills it right
  after, under ITS records. **No local check can see another PC**: with v2 off this PC keeps no list of its gym's PCs;
  the verify only catches rows another PC wrote back before the counts after (`INCOMPLETE`). The box covers every use;
  on the cutover night its "stays closed until the refill" is kept by the cables instead: runbook C10 starts the other
  gym 58 PCs before « Remplir », and from C8 to C14 (D8 to D16 at gym 45) no PC reaches the turnstiles. `[TEST: test_erase_wizard_lane1b.py::TestEveryOtherPcMustBeClosed]`
- **A refill that can refill** (review C1, `EraseWizard._refill_check`): what the refill pass would write, from THE SAME
  source and filter both passes use (`erase_wizard.refill_roster`: the sync cache's rows through
  `DeviceSyncEngine._filter_users_for_device(quiet=True)`, on a copy of the device row — no withheld WARNING, no
  `[T] PIN_SCHEME_ACCOUNT_WITHHELD`: this only measures). Refused (409, nothing held, nothing read beyond step 1):
  `REFILL_SOURCE_MISSING` (no cache, or unreadable), `REFILL_SOURCE_STALE` (`EraseWizard._sync_staleness`, with its
  reason `staleWhy`: `LAST_SYNC_FAILED` — the app's `_last_sync_ok` is not True, the heartbeat's own `lastSyncOk`;
  `NO_SYNC_YET` — no successful getSyncData recorded since Access started; `TOO_OLD` — **the owner's age limit (decision
  2026-09-27, lane 1c): the last SUCCESSFUL getSyncData is older than max(3 × the effective sync interval, 10 min)**. The
  interval is the app's own `MainApp._sync_base_interval_sec` — the server's `agentSyncBackendRefreshMin` if any, else
  `cfg.sync_interval_sec` — the one the sync timer uses; unreadable, the 10-min floor. The age is read on the monotonic
  clock `app.py` stamps with the success (`_last_sync_ok_mono`, next to `_last_sync_ok = True`), so a PC clock change
  cannot make an old list look recent; a getSyncData that hangs records no failure, only its age tells it. The preview
  and the 409 carry `staleWhy`, `lastSyncAgeSec` and `syncMaxAgeSec`; the page shows the list's age in the refill line.
  `[TEST: test_erase_wizard_lane1c.py::TestTheMemberListMustBeRecent — fresh, an old success, a hung sync, 5 min → 15
  min, the floor, the app's own interval]`), `REFILL_SOURCE_EMPTY` (no member for this turnstile), `REFILL_WITHHELD` (ACCOUNT rows with no
  `mainAccountId`: never written, and "N waiting" cannot count them, §3.10). For **hold** the scheme at Refill is not
  known yet, so the roster is checked under the scheme now AND under ACCOUNT (the cutover's "erase under MEMBERSHIP,
  switch, Refill" — under MEMBERSHIP no row is ever withheld, so a current-scheme check alone never fires there); for
  now/auto, under the scheme now (a scheme that moves during the run keeps the hold, step 6). Every erasable table is
  gated, not only the users: rights, fingers and users all come back only from the refill. The count is before the
  pass's own exclusions (an explicit revocation, the recently-removed guard), so it can only be higher than what is
  written. The preview returns it (`refill {scheme, members, withheld, ifAccount, lastSyncOk, cacheUpdatedAt, problem,
  accountProblem}`) and the page shows "the refill will write N members" in the Options and Confirm steps.
  `[TEST: ::TestTheRefillMustBeAbleToRefill]`
- **No now/auto on a turnstile already held** (`HELD_USE_REFILL`, 409; review F2): only the Refill button — which shows
  and checks the pin scheme — releases an earlier "hold until Refill"; the page greys those options out. The run keeps
  an earlier hold whatever it was asked (`_refill(held_before=True)`, note `HELD_BEFORE`), as a backstop.
  `[TEST: ::TestAnEarlierHoldIsReleasedOnlyByRefill]`

Since lane 1c (2026-09-27, the master review of lane 1b, critic C0 verified here), an erase also needs `[CODE]`:
- **The people the refill will NOT put back, named and accepted.** An erase removes more than MonClub's members: the
  MB2000 users erase deletes every privilege-0 user of its backup (`_erase`: `members` = privilege ≤ 0), the C3 erase is
  `DeleteDeviceData` on the whole table — staff or cleaners enrolled on the terminal, another system's users (gym 45's
  shared terminals), a member no longer in this PC's roster — and the refill writes only its roster. Their only copy
  was the backup, deleted after 30 days. Now step 1 (`preview`) also reads the terminal's user list — C3: the `user`
  table (`read_table_strict`, the whole table, as the backup reads it); MB2000: the listing (`list_device_users`) — and
  lists by pin and name every non-administrator whose pin is not in the refill roster under the scheme recorded now
  (`erase_wizard.terminal_people`, `::not_refilled`). Steps 3 and 4 show "N people on this turnstile will NOT be put
  back by the refill" with that list; an erase needs `acceptNotRefilled: true` when N > 0 (`NOT_REFILLED_UNCONFIRMED`,
  409), and a list that did not read refuses it (`NOT_REFILLED_UNKNOWN`, 409; a backup-only rehearsal needs neither).
  A pin is a person under the scheme it was written with — the scheme recorded now until the cutover's switch — so a
  turnstile switched BEFORE its erase lists everyone (every old pin differs from the new ones): conservative, and
  visible. Names reach the page only (never the log, telemetry, `run.json` or the mark: review F29).
  `[TEST: test_erase_wizard_lane1c.py::TestPeopleTheRefillWillNotPutBack]`

**The gym's server switch** (owner decision 2026-09-27, NEW 2): every START — a backup-only rehearsal too; never the
preview, never Refill (a held turnstile must always be refillable) — asks the server, right after the password check
(so a wrong password still reads as one), whether the wizard is on for this gym: `GET {base}/manager/gym/access/erase-wizard`,
`base` exactly as `validate_statistics_password` builds it (`{scheme}://{host}/api/v1`, `monclub_api.py::
get_erase_wizard_switch`), the same gym bearer token, 15 s. Only a 200 whose JSON `enabled` is the boolean `true`
enables (`erase_wizard.check_erase_switch`); `false` refuses 403 `ERASE_NOT_ENABLED` ("L'effacement n'est pas activé
pour cette salle — le propriétaire peut l'activer dans le tableau de bord (page PC d'accès)"). The other refusals (503)
say why (lane 1c, review F4 — before it every one read "…n'a pas pu être vérifiée. Réessayez (Internet requis)", which a
technician with working internet could not act on): a 404 or 405 is `ERASE_SWITCH_MISSING` — a backend without the
route; retrying cannot help until the server is updated; no answer at all — `requests`' ConnectionError or Timeout, or a
socket error (`erase_wizard._no_answer`; `requests`' other errors, a body that is not JSON included, derive from OSError
but got an answer) — is `ERASE_SWITCH_UNREACHABLE` ("vérifiez Internet"), a proxy that does not answer (`ProxyError`)
included; a TLS failure (`requests`' SSLError, a ConnectionError, or `ssl.SSLError`) is not "no answer" since lane 1d
(review nit: something answered with a certificate that does not check out; `erase_wizard.is_tls_failure`) and reads
`ERASE_SWITCH_UNCHECKED` with its text as the detail line -- and the erase / Refill password check
(`local_access_api_v2._erase_password_verifier`) answers a TLS failure 502, `ADMIN_PASSWORD_CHECK_FAILED`, not 503 « Pas
d'Internet » (review round 1) `[TEST: test_erase_wizard_lane1d.py::TestTheNits]`; anything else — no token, 401/403, 5xx, a
body that is not JSON, `"true"` as a string — stays `ERASE_SWITCH_UNCHECKED` ("réponse inattendue du serveur", the
server's words as a detail line). The switch is OFF by default on the server: until lane 3c's backend route
(`GET /api/v1/manager/gym/access/erase-wizard`) is deployed EVERY start is refused `ERASE_SWITCH_MISSING` (today's
production backend's 404), and once it is, the owner switches the wizard on per gym on /access-pcs. `[CODE]` `[TEST:
test_erase_wizard_lane1b.py::TestTheGymsServerSwitch]` The route shape was given by the master session; the backend is
`[UNVERIFIED]` here (not in this repo).
**The 48 h window (lane 3d, 2026-09-28)** `[COMMENT: lane 3d report and the master review of lanes 1c/3d -- backend and
dashboard branch `claude/erase-wizard-switch-expiry`, not in this repo]`: the route answers `{"enabled", "updatedAt",
"expiresAt"}`; an ON reads `false` from 48 h after it was turned on (computed at every read, nothing scheduled); asking for
ON while it still reads ON changes nothing and keeps its end -- to restart the 48 h, OFF then ON; the /access-pcs card shows
« Activé jusqu'au … » (the server's Tunis time) and is re-read only when the page is reloaded (its page's own refresh does
not reach it). Access reads `enabled` only and ignores the other fields `[CODE: check_erase_switch]`, and asks at START
only, so an erase already started goes on past the end. Operator rules (runbook B2c, A7, E7): ON on the cutover evening,
not earlier; check that « Activé jusqu'au » covers the whole night, else OFF then ON; OFF after a survey-evening
rehearsal and after the night -- checked on the card after a reload, never with a START on a live turnstile (step 1 alone
runs full reads on the worker, "What the wizard does to the door"). The page's start timeout is 60 s, and after a start
that got no answer it watches `/erase/status` for another minute: `requests`' `timeout=15` applies to the connect and to
each read, so the password check and the switch check can each take about 30 s or more.

**Erase backups are kept 30 days** (owner decision 2026-09-27, NEW 1; `erase_wizard.prune_erase_backups`, at start-up on
its own thread after the holds are loaded -- through `prune_erase_backups_at_startup`, which first waits for the server
clock, lane 1d below -- and after every run). A run folder goes 30 days after the LATEST of its run's
start (the run id's local time) and the last write of any file in it — the run's end, and `refilled_at.txt`, which
Refill writes into every run folder of the turnstile BEFORE it releases it (`_mark_refilled`; after, a prune in between
found the folder neither held nor marked — review round 3): a turnstile held longer than 30 days keeps its backups 30
days after Refill (review round 2). A mark that cannot be written is logged at ERROR and reported in Refill's answer
(`backupsMarked: false`, which the page shows as a warning); Refill still releases — a held turnstile must always be refillable. The mark also restarts the
30 days of that turnstile's older runs. Never: a held turnstile's runs (while the holds cannot be
read every turnstile reads held, so nothing goes); the run in progress; a folder whose name is not a run's; a run id
before `20260901` (`_NO_RUN_BEFORE`: no run predates the wizard, so that is a PC clock that was wrong — its age cannot
be told). A run whose `run.json` is unreadable or still `RUNNING` goes once old enough and not held: no run of this
process is that old, so a power cut or a crash ended it, and its biometric copy is not kept forever (review round 2).
Logged as `[ERASE] backup of run … (turnstile N, STATE) deleted` and `[T] ERASE_STEP step=backup_deleted` —
run id, turnstile and state only, never a name, card or template. `[CODE]` `[TEST: test_erase_wizard_lane1b.py::
TestBackupsAreKeptThirtyDays]`

Since lane 1c `[CODE]`:
- **Never a backup holding people the refill does not put back** (review C0): a run whose erase removes any of them writes
  `keep_not_refilled.txt` (`KEEP_MARK`: their count and pins, never a name) into its folder, durably, BEFORE its first
  delete — no mark written, no erase (`KEEP_MARK_NOT_WRITTEN`, `FAILED`) — and the prune never deletes a marked folder,
  whatever its `run.json` says. A run that fails before any delete removes its mark (nobody was erased), and since
  lane 1d so does the start-up release of a run a power cut or a kill stopped before its erase record (below, "A run
  stopped before any delete leaves no hold"). `[TEST: test_erase_wizard_lane1c.py::TestTheirBackupIsNeverPruned]`
- **The PC clock is not trusted blindly** (review F2): with no `now` given (every production call), the prune takes the
  server-corrected time when this process has a measurement of the server's clock (`server_clock.get_default()` with a
  sample), and prunes NOTHING while that measurement puts the PC clock more than a day off (`PRUNE_MAX_CLOCK_OFFSET_SEC`,
  the owner's "> 1 day"). Runs are dated on the same corrected clock: `run.json` records `startedAtEpoch` (and
  `clockCorrected`) and every write's `writtenAtEpoch`; Refill's `refilled_at.txt` records `at` (JSON). A folder is dated by
  those — never by its files' mtimes — and one written before lane 1c by its run id and mtimes, as before. A folder dated
  more than a day after "now" (`PRUNE_FUTURE_TOLERANCE_SEC`: a clock ahead then, or this one behind) is kept and logged
  (`dated … in the future`), the others pruned as usual. The hold is read before the times and again before the delete
  (review nit). `[TEST: ::TestThePruneAndTheClock]`
- **The start-up prune waits for the server clock** (lane 1d, master review F1): it used to run before the v2 runtime
  sets its clock (about 12 s after launch, `access/runtime.py`), so the prune every morning after the power comes back
  used the PC clock alone, on v2 PCs too. `app.py` now starts `prune_erase_backups_at_startup` on its thread: it polls
  (`STARTUP_PRUNE_POLL_SEC` = 5 s) until `server_clock.get_default()` has a sample, at most
  `STARTUP_PRUNE_CLOCK_WAIT_SEC` = 180 s (chosen, not measured), then runs the same `prune_erase_backups` -- the same
  `_prune_now` guard as after a run. A PC clock jumped weeks ahead loses the persisted offset (its 12-h age check reads
  the wrong wall clock, `ServerClock.__init__`), so only a LIVE sample catches it: the first 2xx answer of a v2 route,
  which carries `serverTime` (`app/core/v2/api.py::_sample`) -- with the commands switch on (§3.9; protocol 2's
  `syncMeta.serverTime` does not feed this clock). With no sample by then it prunes on the PC clock, as the prune after a
  run does; skipping instead would keep biometric
  backups past the owner's 30 days at every gym today. `[TEST: test_erase_wizard_lane1d.py::
  TestTheStartUpPruneWaitsForTheServerClock]`
- **Residual** `[CODE]`: with v2 off — every gym today — no server time ever reaches the PC (samples come only from the v2
  routes and socket, `app/core/v2/api.py`, `runtime.py`), so the start-up prune, after its wait, uses the PC clock alone,
  as before. A PC clock set forward by 30 days or more then deletes the backups of unheld, unmarked turnstiles; a clock
  wrong by days, then corrected, shortens or lengthens the 30 days by that much. With a measurement too, a PC clock stepped forward after the last sample goes unseen until the next one:
  `offset()` is the median of samples taken before the step (so it stays small) and `now()` follows the stepped wall clock
  — `server_clock` detects such steps (`_age_of`, `STEP_TOLERANCE_SEC`) for its report only (lane 1c review round 1; not
  changed: v2 is off at every gym today).

**Owner decisions, 2026-09-27** (the lane 1 report's section 07, answered through the master session): door logs are
never erasable; the erase and Refill stay online-only (the server checks the password); an MB2000 users erase forces
"forget"; typing the name is enough, with the IP and port shown in step 4; a held turnstile keeps blocking every member
write until Refill, and stays VISIBLE (the red Devices page, and the heartbeat's `held` line, §3.10); backups are
deleted after 30 days (above); the wizard is behind a per-gym server switch, off by default (above). Lane 1b's two
questions, answered the same day: the "hold" erase keeps its check under ACCOUNT too (kept as built); "stale" gains the
age limit max(3 × the sync interval, 10 min), on the monotonic clock, never enforced mid-run (lane 1c, above).

The page (lane 1b): the lock screen says the erase and Refill need the internet; step 4 shows the address and SDK the
run is tied to (`ip:port`, review F28); the Options and Confirm steps say plainly that a users (or a C3's door-rights)
erase keeps every card and finger member out — until Refill with "hold", until the refill ends otherwise (F26); every
refusal code and run error is translated FR/EN with the server's text as a detail line, the progress phases too (F27);
a start or Refill that got no answer in time reads `/erase/status` or the holds before reporting an error, and the
dialog cannot be closed while a start is out (C6). `[CODE: EraseWizardDialog.tsx, eraseWizardText.ts]` No UI test
(the type check only, same two pre-existing errors as 337f1bb, and the dev mock `erase-mock.html`).
Lane 1c adds, FR/EN: the list's age in the refill line and why it is stale; the people not put back in steps 3 and 4,
their tick gating Erase; the watchdog tick; Refill's warnings and the administrator-overwrite confirmation; the finish
note of a run that kept its hold (`HELD_BEFORE`, `PIN_SCHEME_CHANGED`, `PIN_SCHEME_UNREADABLE`); a lockout line for a
fingerprints-only erase; `noAnswer()` never reads an HTTP answer (`ApiError`) as "no answer". The lock screen's route
(`/auth/verify-admin-password`) now answers every refusal with a code — `ADMIN_PASSWORD_REQUIRED`, `PC_NOT_SIGNED_IN`,
`ADMIN_PASSWORD`, `ADMIN_PASSWORD_CHECK_FAILED` (its generic 500 too since lane 1d), statuses and texts unchanged for the
Local DB page (review F6) — so the English page no longer shows "Mot de passe incorrect" raw.
Lane 1d (review nits), FR/EN: the not-put-back title says what the chosen tables take from those people -- the user
(a users erase), or only their door rights and / or fingerprints, their user and card staying
(`NotRefilledWhat`); the tick and the finish line say "what the erase takes from them"; the kept-hold notes
(`HELD_SCHEME_MOVED` / `_UNREADABLE`) say the hold stays even after a restart. Step 1 looks its worker up once (one that
leaves the engine mid-read no longer gives a raw 500: `NO_WORKER`, or a device error) and reads any failure of its
user-list read as "unread" (`NOT_REFILLED_UNKNOWN` at START) `[TEST: ::TestTheNits]`. Type check: the same
pre-existing errors in `AccessFeedbackProvider.tsx` and `PopupWindow.tsx` as at `aa015e5`, none in the wizard's files. `[TEST: test_erase_wizard_lane1c.py::
TestRegressionGuards::test_the_lock_screens_route_answers_with_a_code]` The pages were checked on the dev mock in a
browser (steps 3 and 4, Erase disabled until both ticks, the Refill warning); no UI test.

**The right turnstile, by its live connection (review round 2).** The identity checks above compare the
database with the database; the worker's socket is another matter. `UltraDeviceWorker.update_device` swaps the
payload without reconnecting, and the connection is refreshed only every 30 min, so after an IP edit — two
turnstiles' addresses swapped to fix a mislabel — the worker stays connected to the OLD address, which may be
the other turnstile. The worker now records the address its driver actually connected to (`_connected_addr`,
the driver's `ip`/`port`, cleared on every disconnect and failed connect); the wizard refuses a worker whose
address is unknown or differs from the recorded one (both drivers default the port to 4370) at step 1, at the
start, again after the idle wait (`FAILED`, nothing erased) and inside every erase command's closure on the
worker thread (a reconnect mid-run: `INCOMPLETE`). `[CODE: ultra_engine.py::_connect, erase_wizard.py::_address_refusal]`
`[TEST: ::TestTheWorkerMustBeOnTheRecordedAddress]` The same stale socket serves the ordinary roster pushes
for up to 30 min after an IP edit; that is outside the wizard and not changed here.

**What the wizard may call on a device** is pinned by an AST allowlist (lane 1b, review F17 — before it the
check only looked at calls on a name spelled `drv` and could be bypassed by an alias, a `getattr`, another
parameter name or `drv._sdk._dll.X`): every function handed to the worker (`_call` / `_write_call`) may use its
device parameter — whatever its name — ONLY as `param.<allowed>(...)`, the allowed set being exactly the strict C3
count and read, the one-table erase, the MB2000 status read, listing and template read, the whole-user delete and the
finger-slot clear; no alias, no `getattr`, no nested attribute, no passing it on (`_guarded` hands it to the checked
`fn` only); `request_run_sdk` is called in `_call` alone; no forbidden name appears in the code (docstrings do not
count). `erase_table` is called once, in the loop over `C3_ERASE_ORDER`, with that loop's table; and the driver itself
refuses any table outside `PullSDKDevice.ERASABLE_TABLES` (`user`, `userauthorize`, `templatev10`, `template`) before
connecting. `[TEST: ::test_the_wizard_calls_only_these_driver_methods, ::test_the_table_erase_takes_its_table_from_the_erase_order_only,
::test_the_driver_refuses_any_other_table_before_connecting; mutations checked: getattr, alias, nested attribute,
pass-on, another parameter name, a literal door-log table — each fails]` What it does NOT cover: another module calling
the driver directly (the table allowlist in the driver is the rail there).

**The run** (its own thread; each step logged `[ERASE] run=… step=…`, `[T] ERASE_STEP`, and written to the
run folder's `run.json`):

1. **hold** — `device_hold.hold`: a durable row, then the in-memory gate (below). From here MonClub writes
   no member to the turnstile; the door, the scans and the rescues go on (`[TEST: test_erase_wizard_gaps.py::TestTheDoorRunsWhileHeld]`:
   a desk door open, a queued SDK command and a rescue open run while held, and only `_v2_writes_blocked` reads the
   hold in the worker). The row's phase is `erase-prep` (lane 1b, review F1): reads and the backup only, no delete yet.
   On a turnstile already held for a real erase the row keeps `erase` (the upsert never downgrades it) and its
   `created_at` (held since then); a backup-only rehearsal there leaves the row untouched — it keeps naming the run
   that may have erased — while a real erase takes the run id over (its `begin_device_erase` needs it).
   `[TEST: ::TestReviewRound1]`
2. **idle** — waits (≤ 120 s) for a pass already running to end; a push stops at its next chunk (the gate).
3. **counts before**, then **the backup**: C3 — every row of each chosen table, the count read in the same
   command, rows read must equal it; the `user` table's password values are emptied (the key kept, any
   case) and counted in `redacted` — MonClub's refill never needs one, and the MB2000 backup leaves them out
   too; MB2000 — the user listing (must equal status 2, every pin numeric ≤ 9 digits, every privilege an
   integer, the admins listed must equal status 1: a wrong out-param order would back up — and target —
   garbage), then every template of every user, admins included, 2 users (20 `SSR_GetUserTmpStr`) per
   command, whose total must equal status 3. Written to
   `<data root>\access\erase_backups\<run>_device<id>\backup.json` (+ `.sha256`), fsynced, renamed, read
   back and hash-checked. **Any failure here: nothing erased, the hold released** (kept if the turnstile was
   already on hold), state `FAILED`. The file holds names, cards and fingerprint templates: biometric data,
   on the gym PC only. `[TEST: ::test_a_verified_backup, ::test_the_backup_is_written_and_checked_before_the_first_erase,
   ::TestMb2000::test_a_listing_whose_admin_count_disagrees_is_not_trusted, ::test_a_template_count_that_disagrees_stops_before_any_erase,
   ::TestBackupRedactsPasswords]`
   Each MB2000 command carries the driver's own `timeout_sec` (status 20 s, listing 60 s, templates 90 s,
   delete 90 s, sweep 30 s), below the wizard's `request_run_sdk` budgets (30 / 120 / 120 s), so the
   driver's timeout fires first — a `request_run_sdk` timeout abandons the STA thread (§3.1a). Chosen, not
   measured `[UNVERIFIED on hardware]`. `[TEST: ::TestMb2000Commands; test_erase_wizard_gaps.py::TestTheSmallerClaims
   — the fingerprints-only path too]`
3b. **Before the first delete** (lane 1b):
   - *The refill is checked again* (lane 1b review round 1): the MB2000 backup can be long, and a SUCCESSFUL sync in
     between can empty the member list or bring withheld ACCOUNT rows. From the counts (not `problem`, where a STALE
     would mask them): no cache, no member, or withheld rows — under the scheme now, and under ACCOUNT for "hold" —
     refuse the run (`REFILL_SOURCE_MISSING` / `_EMPTY` / `REFILL_WITHHELD`, `FAILED`, nothing erased). A sync that
     merely FAILED meanwhile leaves the list as it was and does not stop the run. `[TEST: ::TestReviewRound1]`
   - *MB2000 administrators vs the refill* (review C4, verified): the push writes `SSR_SetUserInfo(1, pin, name, "", 0,
     enabled)` — privilege 0, password emptied (`zk_standalone.py`, the roster push) — so a kept administrator whose pin
     is also a member pin of the refill roster would be demoted and renamed to that member. A kept admin pin found in
     the roster under the scheme now — and, for "hold", under ACCOUNT — refuses the run: `ADMIN_PIN_IN_ROSTER`,
     `FAILED`, nothing erased (a users or a fingerprints erase: both reset every record). Change that admin's pin on the
     terminal first. `[TEST: test_erase_wizard_lane1b.py::TestAnAdminPinTheRefillWouldOverwrite]`
   - *The people the refill does not put back, bound to the backup* (lane 1c, review C0; `_bind_not_refilled`): from the
     BACKUP — what is really erased — against the roster now: the MB2000 backup's users, the C3 backup's `user` rows, or,
     for a C3 erase without the `user` table (its backup holds no user rows), the list read once more here. Only the pins
     accepted at step 1 may be among them — or a member step 1 saw in the roster who left it since (a right that ended at
     the midnight date flip during a long MB2000 backup: a normal pass would remove them too; lane 1c review round 1; the
     step-1 roster's pins are kept with the run, `EraseWizard._run_step1_roster`, not in its record). Anyone else — a user
     enrolled on the terminal since step 1 — ends the run `NOT_REFILLED_CHANGED`, `FAILED`, nothing erased (the operator
     reads step 1 again). That roster excuses its pins only under the scheme it was read with: a pin-scheme switch saved
     since step 1 (during the backup) ends the run `PIN_SCHEME_CHANGED`, `FAILED`, nothing erased — every old pin would
     otherwise read "not put back" (lane 1c review round 2).
   - *A stop before the first delete once the scheme moved keeps the hold* (lane 1c review rounds 3-4,
     `EraseWizard._scheme_moved_note`): any `FAILED` run — that one, or a now/auto re-check finding withheld rows under the
     new scheme — whose turnstile's scheme differs from the run's start keeps the hold and asks no pass, note
     `HELD_SCHEME_MOVED` (a scheme that does not read: the same, note `HELD_SCHEME_UNREADABLE`, "check the scheme, then
     Refill"): the terminal still holds every pin of the old scheme, and a released pass would write the new scheme's pins
     beside them. The run's start scheme is step 1's: `start()` refuses a switch saved between step 1 and START (409
     `PIN_SCHEME_CHANGED`, nothing held, the page reads step 1 again; a backup-only rehearsal is not refused). The operator erases again with "hold" (step 1 then lists every old pin as not put
     back), or sets the scheme back, before « Remplir » — `_refill`'s own end-of-run rule. **Since lane 1d (master review
     F0) the kept hold survives a restart**: that run's row moves, durably, from `erase-prep` to `erase-scheme-moved`
     (`db.keep_erase_hold_after_scheme_move`: that run's own `erase-prep` row only, never an `erase` row nor another
     run's), which no start releases — only « Remplir », or a later run's erase record (`begin_device_erase` moves it on
     to `erase`; the upsert of a later run's hold keeps it, `set_device_write_hold`). Before, the row stayed `erase-prep`
     and the next start released it: the protection covered the running session only, and the gyms power off every
     night. A write that fails keeps the hold for the session only and says so under its own finish-note code,
     `HELD_SCHEME_MOVED_SESSION` / `HELD_SCHEME_UNREADABLE_SESSION` (`… -- NOT kept across a restart of Access …`; lane 1d
     review round 1: the page's line for the plain code promises a hold that outlives a restart). So does a turnstile
     whose row is gone (deleted in MonClub: its scheme reads None, `EraseWizard._device_gone`) -- no « Remplir » could be
     pressed for it; a row that does not READ is not gone, and keeps the durable hold (fail closed). Residual `[CODE]`: like any hold, it blocks every member write, revocations included,
     across restarts until « Remplir » — the page's note says so. `[TEST: test_erase_wizard_lane1d.py::
     TestAHoldKeptAfterASchemeMoveSurvivesARestart — both notes reloaded with release_unstarted=True, the unchanged-scheme
     control, the row rules, Refill releases it, a failed write]` With the scheme unchanged a `FAILED` run releases as
     before. `[TEST:
     test_erase_wizard_lane1c.py::TestPeopleTheRefillWillNotPutBack::test_a_scheme_switched_since_step_1_stops_the_run_before_any_delete,
     ::test_any_failure_before_the_first_delete_after_a_switch_keeps_the_hold, ::test_a_failure_with_the_scheme_unchanged_still_releases]` Then the run records `notRefilled {count, pins}` — those who left the roster included — and,
     when there are any, writes the keep mark (above) before `begin_device_erase`. `[TEST: ::TestPeopleTheRefillWillNotPutBack]`
   - *The erase is recorded* (`db.begin_device_erase`, one durable transaction, review F12 + F1): the run's hold row
     moves to `erase` (a delete may run from here), and the last push result (§3.9) of every pin MonClub recorded for
     this turnstile — sync state, intent or result rows, the MB2000 admins kept excepted — becomes UNKNOWN, stamped with
     this moment on the corrected clock: an erase is an attempt start for all of them. Before it, no erase path touched
     `device_push_result` but forget's delete, so an `INCOMPLETE` run, a crash, "keep", or a C3 rights-only erase left
     `lastPushOk=true` standing and a deleted member could read ON_TURNSTILE (contract §4); the next upload now carries
     `lastPushOk: null` dated at the erase. Done here, not at the hold: a backup-only rehearsal or a `FAILED` run resets
     nothing (an unchanged pin gets no new result, so a reset there would leave "not known" standing). A write that
     fails, or no hold row of this run, means `RESULTS_NOT_RESET`, `FAILED`, nothing erased — the admin `users/push`
     route's rule (§3.9). `[TEST: ::TestTheEraseMakesEveryResultUnknown — INCOMPLETE, the upload row, a rights-only
     keep, durable before the first delete, no reset no erase, a rehearsal, the kept admin]`
4. **erase**, then **counts after** and **verify**: C3 — every chosen table counts 0; MB2000 — a fresh listing
   shows no non-admin user and status 2 equals the admins kept, and status 3 equals the admins' templates.
   A C3 table the run's own counts before read as 0 gets no `DeleteDeviceData` (step `erase_<table>` with
   `skipped=empty`; lane 1b, review C5): the FULL_REPLACE clear treats a template-table refusal as "table may not exist"
   (`device_sync.py::_sync_one_device`, `clear %s skipped`), and whether a C3 without the v9 `template` table counts it
   0 or refuses the count is `[UNVERIFIED]` — sent a delete it may refuse, it would end the run `INCOMPLETE` after
   `templatev10` is gone; the verify still requires 0 after. `[TEST: ::TestAnEmptyTableGetsNoDelete]` An MB2000 erase
   that answered ok but left a row fails the verify: `INCOMPLETE`, nothing forgotten, no REMOVED fact (review F15).
   `[TEST: test_erase_wizard_gaps.py::TestAnUnconfirmedMb2000EraseForgetsNothing]`
   **Every erase command is lease-checked twice** (`EraseWizard._write_call`): on the wizard thread before
   it is queued, and on the worker thread just before it runs — the command waits in the worker's queue and
   the lease can move meanwhile. A refusal (`NOT_DRIVER`, `HANDOVER_IN_PROGRESS`, `ADD_ONLY`) stops the run.
   The worker's connected address is checked in the same closure (above). An MB2000 delete command that did
   not fully go stops the erase there, marked uncertain (a timeout
   reports every pin failed although some may be gone). **Any of these, or a row left, or a command that got
   no answer (`sent, no answer`), is `INCOMPLETE`: the hold is kept, nothing is forgotten, and every recorded
   pin of the turnstile is made "not in sync"** (`_invalidate` → `db.invalidate_device_records(
   fingers_erased=False)`: the hard-reset UPDATE, durable; ownership and the recorded finger sets kept —
   whether the fingers went is not known — **and the retry backoff cleared**, `fail_streak=0`,
   `last_attempt_hash=NULL`: a pin refused repeatedly on the same content, a refused template for one, would
   otherwise be held back by both selectors for up to `_SYNC_RETRY_MAX_SEC` (6 h) after the refill, review round
   2), so the refill writes every pin again. A crash after the first
   erase command does the same. Before review round 1 an INCOMPLETE left every record "in sync" and Refill
   put back nothing the erase had removed (a C3 pass only notices a missing `user` row; an MB2000 pin whose
   record matches is skipped). `[TEST: ::TestC3Run::test_an_erase_that_leaves_rows_keeps_the_hold_and_forgets_nothing,
   ::test_an_unanswered_erase_is_never_read_as_done, ::TestIncompleteRefillsEverything,
   ::TestTheLeaseIsCheckedAtEveryWrite, ::TestMb2000Commands::test_a_failed_delete_chunk_stops_the_erase,
   ::TestTheResetsClearTheRetryBackoff]`
5. **records** — the lease is checked again first (a refusal: `INCOMPLETE`, above). *forget*:
   `db.retire_device_records`, one durable transaction: a `v2_removal_log` row for every pin with a state or
   intent row (the ownership backup's REMOVED fact, §3.9), then the turnstile's `device_sync_state`,
   `device_push_intent`, `device_content_mirror`, `v2_readd` and `device_push_result` rows go; the pin-scheme
   history stays. **The MB2000 administrators the erase left on the terminal (`keep_pins`, from the backup)
   keep every row and are never logged REMOVED** — before review round 1 an admin pin with a MonClub record
   was retired and reported removed while it stayed on the terminal. *keep*: `db.invalidate_device_records`
   — the hard-reset UPDATE (hashes cleared, `last_ok=0`, ownership kept, §3.2c), and on an MB2000 whose
   fingers went, `pushed_finger_ids=''` (known empty) and `finger_slots_swept=1` — the kept admins excepted —
   so the refill never clears an already-empty slot that answers False (§7 R1-20). A users erase is also
   reported to the server (`ownership.note_wipe`, the report a PullSDK table clear makes). The worker's "N waiting"
   figure (§3.10) becomes the whole refill roster (`_set_waiting`, lane 1b, review F0) — it used to become None,
   which the heartbeat sends as 0; a refill pass that never runs keeps it.
   `[TEST: ::test_forget_retires_the_records_through_the_removal_log_and_reports_the_wipe,
   ::test_keep_records_invalidates_every_pin_and_keeps_ownership, ::TestForgetKeepsWhatStaysOnTheTerminal;
   test_erase_wizard_lane1b.py::TestTheHeartbeatOfAHeldTurnstile::test_the_run_leaves_the_roster_waiting_not_none]`
6. **refill** — a turnstile that was held BEFORE this run keeps its hold whatever was chosen (note `HELD_BEFORE`,
   lane 1b; `start()` refuses now/auto there anyway). *now* / *next sync*: the pin scheme is read again first; if it is not the one the run
   started under (a switch recorded during the run, or a stale answer reverting one, §3.2e) or does not
   read, the run ends `DONE` **with the hold kept** (note `PIN_SCHEME_CHANGED` / `PIN_SCHEME_UNREADABLE`):
   the operator presses Refill. Otherwise the hold is released, the scheduler's roster hash dropped
   (`force_resync`) and, for *now*, a full pass requested (`request_full_sync(reason="erase-refill")`);
   *next sync* relies on `force_resync` — without it the scheduler skips the unchanged roster; a manual-sync
   gym waits for "Synchroniser". *hold*: kept, durably, until the **Refill** button. An MB2000 refill is
   capped at `_FULL_SYNC_MAX_PINS_PER_PASS` = 50 pins a pass (§3.4e): several passes. `[TEST: ::test_refill_now,
   ::test_refill_at_the_next_sync, ::TestRefillPinScheme::test_a_scheme_switched_during_the_run_keeps_the_hold]`

**The Refill button** (`/erase/refill`, `EraseWizard.refill`). The page reads the pin scheme from
`/erase/holds` (never the run's start value), shows it, and sends it back as `expectedPinScheme`; the server
refuses a missing one (400 `PIN_SCHEME_REQUIRED`), one that moved since (409 `PIN_SCHEME_CHANGED` with the
scheme now — the page re-reads and shows it) and an unreadable one (503). Then the admin password, checked
by the server: **Refill needs the internet** — offline it answers 503 and the turnstile stays held (owner decision
2026-09-27: online only; it is the only release of a hold whose erase started -- `device_hold.release` has no other
caller for it and a start releases only `erase-prep` rows; what the night does meanwhile: runbook part F, "Held, and
« Remplir » cannot check the password"). Then it **always resets the turnstile's records first**
(`invalidate_device_records(fingers_erased=False)`, durable) — a hold can come from an `INCOMPLETE` run or
from a restart mid-run, which leaves no run record — and only then releases the hold, drops the scheduler's
roster hash, sets the worker's "N waiting" to the refill roster (lane 1b) and requests a full pass. A reset that fails
answers 500 `RECORDS_NOT_RESET` and keeps the hold. Offline: 503 `ADMIN_PASSWORD_UNCHECKABLE` (lane 1b).
**Refill checks again before it resets and releases** (lane 1c, review F1; `EraseWizard._refill_recheck`): the erase was
checked under the scheme of its start, and the switch's own sync — or a switch landing during a now/auto run, which then
keeps the hold (step 6) — can change the roster since. Under the scheme it verified and pushes, Refill computes the refill
roster (members, withheld, `REFILL_SOURCE_MISSING` / `_STALE` / `_EMPTY`, `REFILL_WITHHELD`, the list's age) and returns it
as `refill`: reported, never refused — refusing leaves the turnstile empty anyway; the page shows each as a warning. On an
MB2000 it reads the administrators the hold's run kept from that run's verified `backup.json` (Refill needs no
connection; a held turnstile's backups are never pruned) and intersects them with that roster: a clash answers 409
`ADMIN_PIN_IN_ROSTER` with the pins — nothing reset, marked or released — until the operator confirms exactly those pins
(`confirmAdminPins`; review C4 at Refill: the push writes `SSR_SetUserInfo(…, privilege 0)` over the admin). `adminCheck`:
`CHECKED`, `NOT_APPLICABLE` (a C3 has no administrators — also read from the backup's protocol when the device row is
gone), `UNREADABLE` (no backup or no roster: a warning, not a refusal). The administrators are the backup's, never the
terminal's: an administrator whose number was changed on the terminal since still reads as a clash (the page says so:
confirm once the number is changed), and one enrolled after the erase is not checked. `[TEST:
test_erase_wizard_lane1c.py::TestRefillChecksAgain]`
It needs no connection to the turnstile (the cables may be out); the refill pushes the scheme the database
records, since the workers follow the database (§3.2e). **Refill and a run never overlap** (review round 2): the
password is a network call, and a run started meanwhile used to have its hold released and a pass requested under
it. Refill now marks the turnstile (`_refilling`) from its first check to its return, and `start()` refuses a
marked turnstile (`REFILL_IN_PROGRESS`); after the password it looks again for a run on that turnstile
(`RUN_IN_PROGRESS`) and requires the hold row it saw — same run id — to be still there (`HOLD_CHANGED`).
`[TEST: ::TestRefillAndARunNeverOverlap]` `[TEST: ::test_hold_until_refill_survives_a_restart_and_refill_needs_the_password,
::test_the_refill_names_the_scheme_recorded_now, ::TestRefillPinScheme,
::TestIncompleteRefillsEverything::test_a_hold_left_by_a_restart_mid_run_refills_every_pin,
::test_refill_keeps_the_hold_when_the_records_cannot_be_reset]`

**Every release of a hold by the wizard** (a `FAILED` run, a backup-only run, a refill) also drops the
scheduler's roster hash (`force_resync`): a pass the hold cut short may have reported success with its
roster stamp (the PullSDK engine returns early on a held panel) and the scheduler would skip the turnstile
until the roster changes. `[TEST: ::TestEveryReleaseForcesTheScheduler]` A `FAILED` or backup-only release also asks
that pass again at once (`request_full_sync(reason="erase-released")`, best effort; lane 1b, review F8): dropping the
stamp alone left it to the scheduler's next timer — up to 15 min, and never on a manual-sync gym. A turnstile whose
earlier hold the run kept asks nothing, and neither does a run that failed because the worker is connected to another
address (`ADDRESS_CHANGED` / `ADDRESS_UNKNOWN`: no pass through it; the scheduler's own timer still applies, review
round 1). `[TEST: test_erase_wizard_lane1b.py::TestAReleaseAsksThePassAgain, ::TestReviewRound1]`

A "backup only" run (the rehearsal) does steps 1–3 and releases the hold. `[TEST: ::test_backup_only_erases_nothing]`

**A run stopped before any delete leaves no hold** (lane 1b, review F1). In process, a `FAILED` run and a backup-only
run always released the hold (unless it was held before). A power cut, a crash or a kill during the reads or the
backup — an MB2000 template backup of ~1,800 users is long `[UNVERIFIED]`, and gyms cut the power at night — left the
row, and every member write, revocations included, stayed blocked until someone pressed Refill online. Now the row
records its phase: `erase-prep` from the hold, moved to `erase` durably by `db.begin_device_erase` BEFORE the first
delete command is queued (step 3b), so a row still at `erase-prep` proves no delete of that run was issued. The
start-up load (`device_hold.load(release_unstarted=True)`, from `MainApp.__init__` and from the `ensure_loaded`
retry — `start()` refuses while the holds are unknown, so no run of this process can be preparing then) deletes those
rows first (`db.release_unstarted_erase_holds`), logs `[HOLD] turnstile N released at start-up`, and emits
`[T] ERASE_STEP step=released_at_start`. A row at `erase`, or written before this rule (reason `erase`), is kept: a
delete may have run. So is a row at `erase-scheme-moved` (lane 1d, above: nothing erased, but the scheme moved). The
upsert never downgrades `erase` or `erase-scheme-moved` to `erase-prep` (a second run on a turnstile an earlier run may
have emptied). A failure to release is logged and the rows stay held (fail closed). `[TEST:
test_erase_wizard_lane1b.py::TestAHoldThatNeverErased]`
**The keep mark of a released run goes too** (lane 1d, master review F3): `_bind_not_refilled` writes `KEEP_MARK`
durably before `_begin_erase`, and only the in-process failure handlers dropped it -- a power cut or a kill between the
two left a biometric backup the prune never deletes, for a run that erased nobody. The start-up release is the one proof
that no delete ran (the row was still `erase-prep`; never `run.json`, whose writes are best effort), so
`device_hold.load` hands its `{device: run}` to `erase_wizard.drop_keep_marks_of_unstarted_runs`, which removes that
run folder's mark (logged `[ERASE] run … stopped before any delete: its keep mark is removed`); the 30 days then apply
as to any run. A run killed after its erase record keeps both the hold and the mark. `[TEST:
test_erase_wizard_lane1d.py::TestAKeepMarkOfARunThatNeverErasedIsDroppedAtStartUp]`

**An uninstall deletes the hold and the backups** (lane 1b, review C2, verified): `installer/MonClubAccess.iss`
`[UninstallDelete]` removes `{commonappdata}\MonClub Access` (and the LocalAppData / AppData copies), which is the data
root (`app/core/utils.py::_candidate_data_roots`: `%ProgramData%\MonClub Access`, else `%LOCALAPPDATA%\MonClub
Access`) holding `access.db` — the `device_write_hold` row — and `access\erase_backups\`. An Access installed after an
uninstall has no hold: its first pass refills the turnstile under whatever scheme the server then sends, and the only
backup of the erased content is gone. **Never uninstall Access while a turnstile is held**: press Refill first (or
finish the switch). Runbook A7 already says "never uninstall first" for another reason. `[CODE]`
An installer run OVER the install is another matter (the master review of lane 1c, F5; runbook part F): it replaces only
the program folder (`PrepareToInstall` → `DeleteTreeIfExists({app}\current)`) and keeps the data root `[CODE]` -- the
SAME version then honours the hold (the repair of the autostart checklist §6, never tried on a gym PC `[UNVERIFIED]`); an
OLDER version has no hold code and refills the turnstile at its first pass (every tag up to 1.4.33 with membership pins),
so never over a held turnstile's data root. The runbook's rollback rows that go back to an older version move the whole
data root aside first -- the hold and the backups leave with it -- and restore a copy taken before the new Access, which
holds no hold: they may run on the held PC.

**What the wizard does to the door** (lane 1b, review F9/F10; the module docstring's "short commands" was wrong for the
whole-table ones). Every wizard device call runs as ONE `request_run_sdk` command on the worker thread, and
`_drain_sdk_commands` runs `fn(sdk)` to its end: for that whole time the worker polls no RTLog, runs no desk or remote
door open (they wait in their queue and expire at their deadline, §3.1a) and makes no QR/TOTP or staff-RFID rescue
open (made on this same thread). Card and finger decisions the terminal makes itself go on. `[CODE:
ultra_engine.py::_drain_sdk_commands, ::request_run_sdk]` The wizard's own budget (`T_READ` / `T_ERASE` 120 s, then as
long again once taken) only decides when the WIZARD stops waiting — it does not interrupt a C3 call. Per command:
- C3 (PullSDK): `count + read` of a whole chosen table (the backup, `GetDeviceData` up to the 8 MB ladder), one
  `DeleteDeviceData` per chosen table, one count of all five tables (steps 1 and 4, and before/after), and — since
  lane 1c — one read of the whole `user` table at step 1 (`erase_read_user_list`: who the refill will not put back),
  read once more before the first delete by an erase that does not include `user`. On a C3 with
  ~1,800 users the duration of each is **unmeasured** `[UNVERIFIED]`; nothing in this repo bounds a `GetDeviceData` or a
  `DeleteDeviceData` but the DLL itself.
- MB2000 (zkemkeeper, STA): the driver's own `timeout_sec` ends the wait (and abandons the STA thread) — status ≤ 20 s,
  the listing ≤ 60 s (three times since lane 1c: step 1 `erase_list_users_step1`, the backup and the verify, ~1,860
  users in one command), 2 users' templates (20 reads) ≤ 90 s,
  20 whole-user deletes ≤ 90 s, 3 slot clears ≤ 30 s; so the worker regains the door after at most that. Real
  durations `[UNVERIFIED]`.
- Each command's duration is logged: `SDK_CMD op=erase_<label> ok=… dur_ms=…` (`[T] SDK_CMD`) — the field tests read it
  there. Run the wizard with the gym closed, or accept that QR members and desk opens wait during the backup and erase.
The PullSDK authorize fallback (`device_sync.py::_sync_one_device` Phase B, no cached pattern: up to 4 `SetDeviceData`
per pin) now serves the door and the scans between pins (`_maybe_yield_doors` / `_maybe_yield_rtlog`, lane 1b, review
F9); it ran the whole roster door-blind before, and its retry passes since lane 1 repeat it (per-pin backoff: 3 free
attempts, then 15 min doubling to 6 h). The retry semantics are unchanged. `[TEST: test_v2_last_push.py::
TestTrueNeedsTheDoorRights::test_the_fallback_serves_the_door_between_pins]`

**The hold** (`app/core/device_hold.py`, table `device_write_hold`). Loaded in `MainApp.__init__`, after the
cached roles, before the first sync tick can start a worker — the cutover restarts Access between the erase
and the refill. It closes the gates a handover's write freeze closes: `ultra_engine._v2_writes_blocked`
(member drain, full-sync drain — a queued pass waits, it is not dropped —, the chunk yield, the pre-push
check, the member push, the maintenance slot), `DeviceSyncEngine._sync_one_device` at its start (no session:
the scheduler fallback lands there) and before its batch, `sync_member_on_connected_sdk` (deferred), the
remote `DEVICE_RECONCILE` (`FAILED DEVICE_ON_HOLD`), and the local API's direct PullSDK user writes
(`users/push`, `users/delete`: 409 `DEVICE_ON_HOLD`, or `HANDOVER_IN_PROGRESS` during a handover, before any
connect — no page calls them). One immutable-set lookup, no lock, no database. The door, the clock and the
re-entry settings are not member writes and are not held. `[TEST: test_device_hold.py,
test_erase_wizard.py::TestDirectWritesRefuseAHeldTurnstile]` **A failed load at start-up holds EVERY
turnstile** (fail closed, review round 1: `is_held` answers True for any id while `load_failed()`), logged
at ERROR; `MainApp._sync_tick` retries it every tick through `device_hold.ensure_loaded()`, which reads
nothing once the holds are loaded; meanwhile Refill answers 503 `HOLDS_UNKNOWN` and `/erase/holds` reports
`loadFailed`; `start()` answers 503 `HOLDS_UNKNOWN` too (every turnstile reading held, a run would take its own
hold for an earlier one and never release it). `load()`, `hold()` and `release()` hold the module lock across
their database work and the in-memory install, so a hold landing during a load's read is not overwritten by the
stale read (review round 2); `is_held` stays lock-free. `[TEST: test_device_hold.py — the four fail-closed tests,
::test_a_load_racing_a_hold_keeps_the_in_memory_gate; test_erase_wizard.py::TestRefillWhileTheHoldsAreUnknown,
::TestNoRunWhileTheHoldsAreUnknown]`

**A handover waits for a run, and for Refill.** `OwnershipSync._worker_idle` answers False while
`EraseWizard.running_device()` is that turnstile, so the release's final upload comes after the run and
carries an `INCOMPLETE` reset (a reset row uploads `pushedHash: null`, and a restore adopts it as such, so
the new driver writes the pin). It also answers False while the turnstile is **held** (review round 2, R2-3):
the hold lives in this PC's `device_write_hold` only — no upload, release or restore carries it — so a new
driver would refill the erased turnstile at once under ITS recorded scheme, before the switch the old one.
The release therefore waits for Refill; the hold panel says so. `[TEST: ::test_a_handover_release_waits_while_an_erase_runs,
::TestAHeldTurnstileIsNotHandedOver]` The server never moves a turnstile on a timer: a pending move stays
`RELEASING` until the outgoing PC releases it (after its final upload); it ends otherwise only by an explicit owner
action — "force handover", a move saved again with force, or a revoke of either PC — and every forced path leaves the
new driver add-only, which still ADDS members, so a forced move of a held turnstile refills it under the new PC's
scheme `[COMMENT: the architecture session's reading of backend main 63d053b3, AccessLeaseService.java
setDrivers/forceHandover/acknowledgeRelease, 2026-09-27; not read in this repo]`. Runbook rule: press Refill (or
finish the scheme switch) BEFORE moving a held turnstile; never force-handover a turnstile held on its PC. The
cutover night runs with no driver PCs (no leases), so this matters once drivers are assigned. Since lane 1b the
heartbeat's `turnstiles[]` line of a held turnstile carries `held: true` and its whole refill roster as `failedPins`
(§3.10); backend `47f35a96` ignores `held` and stores `failedPins`, and neither the backend nor the dashboard shows
"held on PC X until Refill" yet (not built, not in this repo).

**Not the removal ceiling.** The wizard's erase is the operator's manual wipe (§3.2c: the cutover must be
one); it does not go through `push_safety.check_bulk_removal`. Its rails are the password, the typed name,
the verified backup and the verified erase. `[CODE]`

**Residuals** `[CODE]` unless marked:
- Never run against a C3-400 or an MB2000 `[UNVERIFIED]`: every test drives a fake panel or the fake COM
  terminal. Field tests are in the lane reports; each must MEASURE the door impact above from the log's
  `SDK_CMD op=erase_… dur_ms=` lines, with a card scan, a QR scan and a desk door open during each phase:
  - C3-400 (~1,800 users): step 1's counts (`erase_count`), the backup read of `user` / `userauthorize` /
    `templatev10` (`erase_read_<table>`), each `DeleteDeviceData` (`erase_erase_<table>`), and what step 1 shows for
    `template` (a count, 0, or "—": a 0 is now skipped, a "—" is not chosen);
  - MB2000 (~1,860 users): the status read (`erase_status`), the listing (`erase_list_users`, and
    `erase_list_users_after` for the verify), one template command (`erase_read_templates`, 2 users) × ~900, one
    delete command (`erase_delete_users`, 20 users), one slot clear (`erase_clear_fingers`);
  - the other-PCs rule: with a second PC's Access open, the erase refills itself (or ends `INCOMPLETE`) — then close it;
    and a second PC whose watchdog is on comes back by itself within minutes of a Quit (lane 1c: the tick says to
    disable it first);
  - a power cut during a backup-only rehearsal: after the restart the turnstile is NOT held (log `released at start-up`);
  - the heartbeat of a held turnstile on the dashboard: "N waiting" = the refill roster;
  - lane 1c: step 1's user-list read (`erase_read_user_list` on a C3, `erase_list_users_step1` on an MB2000) — its
    duration, with a card scan and a desk door open during it; a staff card enrolled on the panel by hand (not a MonClub
    member) appears in steps 3 and 4 by pin and name, Erase stays disabled until its tick, and after the erase its run
    folder holds `keep_not_refilled.txt`; the refill line's list age matches the last successful sync in the log;
  - the server switch before lane 3c's backend is deployed: START answers `ERASE_SWITCH_MISSING` ("le serveur … ne propose
    pas encore"), never "Internet requis"; after the deploy and the owner's switch on /access-pcs, the erase starts.
- The MB2000 template read (`SSR_GetUserTmpStr`) is new in the app driver; its return shape through win32com
  is handled as `(ok, template, length)` like the other ByRef reads, and an unexpected shape fails the whole
  backup. Its duration is unmeasured: ~1,800 users × 10 reads `[UNVERIFIED]` (script 14's own
  `msPerFingerRead`, when run, gives it).
- A C3 table larger than the read ladder's last step (8 MB) cannot be backed up, so it cannot be erased.
- A C3 rights or fingerprint table that did not read at step 1 is not required with `user`: if it failed
  only that once, its rows stay. Read again (step 1) before erasing.
- A **forced** lease move (no release, so no final upload): between the server moving the lease and this
  PC's next check — at most one erase command, a C3 table or 20 MB2000 users — that command still runs, and
  the new driver may restore the old hashes before this PC uploads its `INCOMPLETE` reset (the lost-turnstile
  upload sends it later, changes only, §3.9).
- A handover waits for a running backup to end: the reads are not lease-checked (the first erase command
  then refuses). An MB2000 template backup's duration is unmeasured `[UNVERIFIED]`.
- "Keep records" after an MB2000 users erase is refused (`USERS_ERASE_NEEDS_FORGET`): the departed members'
  owned rows would stay, so the next pass's removal step would delete pins that are no longer there; what
  `SSR_DeleteEnrollData(…, 12)` answers for a missing pin is `[UNVERIFIED]`, and a False sends the pin to the
  neutralise fallback, which writes a blank disabled user (§3.4). An MB2000 **`INCOMPLETE`** users erase
  keeps the records (nothing may be forgotten after an unverified erase), so it keeps this risk for the pins
  it did delete.
- While a held turnstile's release waits for Refill, its periodic ownership upload waits too (a turnstile with a
  pending release is left out of the upload tick): facts written since the last upload — a forget's REMOVED rows, an
  `INCOMPLETE` reset — stay on this PC until Refill lets the final upload go. Only an explicit force-handover or a
  revoke could move the turnstile meanwhile; the new PC would then restore the older rows (review round 3).
- A run thread that cannot start (the 32-bit build's "can't start new thread") answers 503 `RUN_NOT_STARTED` and
  leaves nothing running and nothing held (review round 3). `[TEST: ::test_a_run_thread_that_cannot_start_leaves_no_run_behind]`
- A hold stops every member write, **revocations included**: a member revoked while the turnstile is held
  keeps what is still on it (after a fingerprints-only erase, an `INCOMPLETE` run, or "hold") until Refill. There
  is no timeout on a hold; the Devices page shows "Remplir" on its row, and since lane 1b the heartbeat says `held`.
  A hold from a run that never deleted is released at the next start (above). Owner question, lane report.
- `users/push` and `users/delete` check the hold before a PullSDK connect of a few seconds; a hold set in
  between is not seen. No page calls them.
- `fingerprint_push_status` rows (the PullSDK per-finger push outcomes) are not touched by "forget".
- While held, the heartbeat line says `held: true` and counts the whole refill roster waiting (§3.10); after the
  release the worker's figure is that roster until the refill pass counts again.
- Lane 1b, judged and left (review items, `[CODE]` unless marked):
  - *F3 — the physical device.* The run binds to MonClub's record and the live socket address, never to a serial
    number; a record whose IP points at the neighbouring turnstile passes every check, and a second ULTRA record on the
    same address is not held. A serial read at step 1 would not catch the first case (the neighbour's serial is read
    every time). Operator rail: step 4 now shows `ip:port`; compare it with the panel. How often either occurs in the
    fleet `[UNVERIFIED]`.
  - *F4 — an abandoned MB2000 delete chunk.* A delete command that times out abandons its STA thread, which may finish
    the rest of its chunk (≤ 19 pins) later; a Refill pressed at once could rewrite a pin that thread then deletes. The
    run ends `INCOMPLETE`; the repo's field notes say a wedged zkemkeeper call does not come back, and Refill needs a
    network password round trip first. Not changed `[UNVERIFIED on hardware]`.
  - *F5 — the MB2000 template backup is long and holds.* ~900 commands of 20 reads for ~1,800 users, the turnstile held
    throughout (revocations wait), each command door-blind (above). Measure it on the rehearsal (field test); a power cut
    during it no longer leaves a hold (F1).
  - *F6 — holds that cannot be read hold every turnstile.* Kept fail-closed; the retry runs at the top of every sync
    tick (`app.py::_sync_tick`, before its early returns): the healthy interval, or any sync request — a change the
    members-version probe sees (`change_detector.py`, `poll_interval` default 45 s) included. The heartbeat now shows
    every line `held` while the load has failed (§3.10), so it is visible off the PC.
  - *F11 — one more DB round trip per push chunk* (`record_push_results`, not durable), on the v1 path too. Its door
    impact is inside the §3.9a noise; a push under load was not measured separately `[UNVERIFIED]`.
  - *F18 — the PullSDK batch "true only with a positive set" guard* is an equivalent mutant today (every reachable pin
    is either confirmed or given a code before Phase D); no test can tell `elif` from `else`, and the proposed test
    would fail on correct code. Not tested, on purpose.
  - Backup durability: the file is fsynced and renamed; the directory entry is not flushed (no `FlushFileBuffers` on
    the folder). A power cut right after the rename could lose the rename — the `.tmp` file then holds the backup.
- Lane 1c (the master review of lane 1b), judged and left `[CODE]` unless marked:
  - *C0 (b) and (c)* — a roster member whose card on the terminal differs from the one MonClub writes, and fingerprint
    templates of roster members that MonClub does not hold, are not counted: the refill writes MonClub's card and
    templates, and the terminal-only ones are lost with no figure on the page. They are in the backup, which goes after 30
    days unless the run also removed people outside the roster (the keep mark). How many there are at gym 45 or 58
    `[UNVERIFIED]` — the runbook's desk rescue (A5/A6) and the gym 45 tools count them before a wipe.
  - *F3* — a held line reports the whole refill roster as `failedPins` during a run's reads and backup too (phase
    `erase-prep`, nothing deleted yet), and on every line while the holds cannot be read: a figure only, for at most one
    heartbeat interval during a run; not changed.
  - *F0* — the backend still drops `held: true` (§3.10): a backend and dashboard follow-up, not in this repo.
  - Review nits not done: a parity test between `refill_roster` and the passes' own rosters; renaming
    `test_it_survives_a_restart`; a failing re-erase of a held turnstile rewrites the hold row's `run_id`; the START's two
    network calls against the page's 60 s (the page already watches `/erase/status` a minute more); the AST allowlist does
    not see a device reached through a captured object; the server-side proof that the F12 null overrides a stored `true`.

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
proof: ownership requires the durable `ownership_confirmed=1` bit, sticky across later failed
updates and never cleared (only a removal deletes the row). It is set by an affirmatively
successful MonClub push, by the read-back promotion (§3.4a), and — **since P3a-2 review round 1
(R1-14/R1-26), on the MB2000 — by a user row the terminal ACCEPTED** (`SSR_SetUserInfo` → True,
reported by the driver as `user_written`) even when a finger of that push then failed. On
installed databases, `last_ok=1` or a recorded `pushed_finger_ids` set is conservative
migration evidence; ambiguous legacy rows remain unconfirmed. A push whose user row was NOT
accepted (refused, a wedged chunk, a member never sent) confers nothing. Without this
affirmative proof, the worker makes **no destructive SDK call** — on either protocol.

*The inversion, and what it costs (review round 1).* This sentence used to read "a failed first
push cannot authorize deletion of a colliding manually managed user". But a member whose card
landed and whose finger was refused — or whose template `TEMPLATE_VERSION_MISMATCH` skips on every
push (§3.4d) — can badge in, and on departure was `SKIPPED_NOT_OWNED` until the next day's
read-back, or for good if the read-back did not match. `SSR_SetUserInfo` creates AND overwrites, so
the bit proves MonClub wrote AT the pin, not that the pin was free: **residual** — at a pin where a
MonClub membership id collides with another system's user id on a shared terminal, that user is now
owned at the first write whose user row lands (before: at the first fully confirmed push, or the
read-back), and a departure deletes it whole, its fingers included. The read-back's "anything else →
never deleted" branch does not guard such a pin, and nothing re-checks the terminal's identity before
that delete — a pin the other system later rewrote back is deleted too. Base had the same exposure
for every confirmed push. Precondition to check before trusting a shared terminal: FIELD-TEST on
gym 45 — compare MonClub's membership-id range with the other system's user ids on devices 8/10 (§7).
`[TEST: test_user_row_ownership.py]` Such a pin also gets the 10-min enrolment grace a clean targeted
push gets (a removals-first pass built from a cache that does not list the member yet would delete it,
review R2-24), and the prune keeps every pin inside that grace window (R2-09) — the very set the
removal step spared, even when the window expires between the two (R3-11). The ACCOUNT revoke re-push
gets the same grace (R3-13).
Force-resync commands invalidate content hashes and retry status without deleting
ownership or pushed-finger evidence, so a later full pass can still reconcile stale
revoked credentials.

**P3b-2: an add-only turnstile is checked BEFORE ownership (§3.9).** On a turnstile this PC drives under a
lease whose ownership backup it has not restored, or whose lease says `handoverForced`, "not owned" proves
nothing (the previous driver may have written the pin), so every row of the table below defers instead —
the targeted revokes return "retry", the full sync does not finalise, the PullSDK path answers `DEFERRED`.
`[TEST: test_v2_add_only.py]`

**Not owned is FINAL: `SKIPPED_NOT_OWNED` (P3a-2, 2026-09-18).** Until P3a-2 an unowned pin
escalated into a full reconciliation that refused before any roster I/O (a recorded but
unconfirmed attempt) or pushed and then aborted its whole revoke pass (no row at all) — and
every later full sync of that device failed the same way, for the life of the process, while
the other departed members MonClub did own were never removed either. Now the three places
that decide it treat "provably not owned" as a finished outcome and "cannot read ownership"
as a retry:

| Site | Not owned (row absent or `ownership_confirmed=0`) | Ownership unreadable |
|---|---|---|
| `ultra_engine.py::_run_standalone_member_revoke` (targeted, MB2000) | nothing deleted, `[T] MEMBER_REVOKE_SKIPPED_NOT_OWNED`, returns True (revocation finished), no full sync | False + `request_full_sync(revoke-failed)` (unchanged) |
| `ultra_engine.py::_run_standalone_full_sync` (explicit revocations, MB2000) | once the desired roster is known, a revoked pin that LEFT it and is not owned is dropped from the pass (`_skip_unowned_revocations`): its physical-revoke phase is finalised, it is removed from the required pins, the rest of the roster is pushed and the other departed owned pins are removed; the pass is not failed and the id is never sent back to the scheduler. ACCOUNT: a person pin still desired is re-pushed, not skipped | the pass is refused before device I/O (unchanged) |
| `device_sync.py::sync_member_on_connected_sdk` (PullSDK, targeted and the ULTRA full sync's revoke pre-pass) | nothing deleted, `engine._last_member_sync_outcome="SKIPPED_NOT_OWNED"`, returns False (never a false success); both ULTRA callers read the marker and treat it as finished (`_revoke_skipped_not_owned`) | `OWNERSHIP_UNREADABLE`, False, retried as before — also when the write-ahead intent proof (§3.4a) cannot be read: the intent row or the panel read failed, or the matched card's promotion could not be written (review R1-12, R2-18: those were reported as the FINAL skip) |

`[CODE: those symbols; db.py::get_device_sync_ownership_for_pin]` `[TEST: test_revoke_ownership_skip.py]`
The PullSDK gate is **scheme-independent**: before P3a-2 that path deleted with no check at all,
under both schemes (and erased the state row even when the SDK delete failed, so every retry then
read "not owned" — it now keeps the row). Under MEMBERSHIP the pin is the revoked membership's own
number, so the old delete could only hit a non-MonClub user at that number; under ACCOUNT it hit
the 110 colliding ids (§3.2b). The gate does not protect an UNWIPED terminal after a scheme switch:
the old scheme's rows keep `ownership_confirmed=1` (§3.2c), so only the manual wipe does.
**What a gym sees:** a revoked member whose device user MonClub cannot prove it wrote stays on the
terminal and is reported (`MEMBER_REVOKE_SKIPPED_NOT_OWNED`, push-history note
`SKIPPED_NOT_OWNED=n (...)`) instead of blocking every later sync. On gym 58 the pins this PC pushed
have owned rows (the boot migration also promotes `last_ok=1` rows); `[UNVERIFIED]` how many panel
pins lack one — FIELD-TEST: compare `GET /api/v2/devices/{id}/users` with
`SELECT pin FROM device_sync_state WHERE device_id IN (5,6) AND ownership_confirmed=1`.
**Contrast `REVOKE_ABORTED` (§3.2g):** above the removal ceiling the step is refused but the
revocation stays PENDING and the scheduler re-queues it; a skip is never used for that.
`[TEST: test_revoke_ownership_skip.py::test_an_above_ceiling_abort_still_leaves_the_revocation_pending]`

Full reconciliation is the recovery route, not the primary revoke route. Separate
physical-revocation and roster-exclusion ownership, with lock-guarded `ACTIVE` and
`RETRY` phases, keeps a revoked member out of stale roster snapshots while avoiding
duplicate deletion and preserving work across targeted/full-sync and dead-worker races.
A compound full-refresh-plus-revocation request is one worker full-sync command; a
revoke-only change remains an immediate targeted command. PullSDK and standalone paths
retain authoritative revocation ownership across missing, dead, disconnected, or
otherwise unusable workers until physical removal is confirmed.
`[CODE: UltraDeviceWorker.request_member_revoke, ::request_full_sync,
::_drain_full_sync_commands; UltraEngine.request_sync_now;
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

### 3.4a Write-ahead ownership — the push intent (P3a-2, 2026-09-18)

**The defect.** `ownership_confirmed` is set only after a push is confirmed, and it used to be
written once per roster, after `push_roster` returned (MB2000), or in Phase D after phases A–C
(PullSDK). A crash or power cut in between — most gyms cut the power overnight and the PC boots
while members arrive — left members on the terminal with no row; once one of them left the roster
nothing could ever remove it (the revoke pass removes only owned pins; §3.4). The same happened
with no crash at all when a user row landed and its finger was refused (the pin is "failed", so not
owned). `[TEST: test_push_write_ahead.py — red on bea2978, green after]`

**The intent.** Table `device_push_intent(device_id, pin, intent_name, intent_card, intent_hash,
protocol, created_at, updated_at, readback_misses)`, one row per pin MonClub is ABOUT to write,
with the name and card exactly as the wire carries them (MB2000: name cut at 24, card digits —
`ultra_engine._standalone_wire_identity`; PullSDK: the `Name`/`CardNo` values). Kept OUT of
`device_sync_state` on purpose: `last_ok` defaults to 1 there and the every-start migration promotes
`last_ok=1` rows to owned, and the prune deletes rows — either would turn an unconfirmed write into
ownership or erase it. `[CODE: db.py::init_db, ::record_push_intents …]`

**Order and durability.** The intents of a push are committed in ONE durable job BEFORE its first
device write: `_run_standalone_full_sync`, `_run_standalone_member_sync` and the ACCOUNT re-push on
the MB2000 (`_record_push_intents`); before Phase A and before a single-pin push on PullSDK. If the
intent cannot be recorded, nothing is written that pass (`[T] PUSH_INTENT_FAILED` on MB2000; the
PullSDK pass fails before any write). The same transaction makes each of those pins' last push result
unknown (lane 1, 2026-09-27, §3.9 "The last push result"). The job runs with `PRAGMA synchronous=FULL`
(`_run_db_write_sync(durable=True)`): every connection here is WAL + `synchronous=NORMAL`, under
which a commit is not fsynced and can roll back after a power loss; FULL syncs the WAL on commit.
SQLite refuses to change the level inside a transaction (measured on the bundled 3.38.4: "Safety
level may not be changed inside a transaction"), so the writer sets it before `BEGIN IMMEDIATE`
and restores NORMAL after; only intents use it (one extra fsync per push call). Whether the gym PC's
disk honours the flush is `[UNVERIFIED]` — FIELD-TEST: commit an intent and cut power within 1–5 s.

**The removal log (P3b-2).** `clear_device_revocation_state` and `delete_device_sync_state` (the two writers of
a CONFIRMED device removal) also record `(device, pin, time)` in `v2_removal_log`, in the same transaction, at
the server-corrected time when measured. It is the only source of an uploaded `REMOVED` fact (§3.9): a row
that just vanished — a prune — proves no removal. `[CODE: db.py::_log_v2_removal]`

**Resolution.** A state write that sets `ownership_confirmed` (a confirmed push, or — MB2000, review
R1-14/R1-26 — a user row the terminal accepted, §3.4) deletes the pin's intent in the same
transaction; so does a removal (`clear_device_revocation_state`,
`delete_device_sync_state`). Nothing else prunes the table. On the MB2000 each chunk's result is
recorded as soon as the chunk returns (`push_roster(on_chunk=…)` → `_push_with_chunk_recording`),
so a crash loses at most the chunk in flight — which its intent covers. `[TEST:
::test_every_member_on_the_terminal_is_owned_or_intended]` (power cut after chunk 2 of 5: chunk 1
owned, chunk 2 intent-only, a foreign user untouched).

**Read-back promotion — never a foreign user.** An intent pin that LEFT the desired roster is
settled by reading the terminal:

| Found at the pin | Result |
|---|---|
| exactly the name + card MonClub wrote (PullSDK: the card; an empty intent card proves nothing) | promoted: `ownership_confirmed=1, last_ok=0`, intent deleted — the next removal step removes it (through the ceiling, §3.2g) |
| nothing (a successful listing) | intent dropped: the write never landed — only on a NON-EMPTY listing: an empty one (an empty terminal, or a read that returned nothing) drops nothing, on the MB2000 (review R2-06) as on PullSDK, where an empty one-pin answer on a targeted revoke drops nothing either (R1-30) |
| anything else | intent kept, `readback_misses+1`, never deleted |
| listing failed | nothing changes |
| a listing that shows NONE of the pins MonClub owns on that terminal (MB2000; e.g. a wrong out-param order putting names in the pin field) | not trusted: nothing changes, `PUSH_INTENT_READBACK ok=False reason=no_owned_pin_listed` (review R3-20); the same when MonClub's ownership state cannot be read (R4-04) |
| a listing that misses ANY pin MonClub owns (MB2000; e.g. an enumeration cut short, which the driver cannot tell from its end) | promotions and misses still count, but nothing is DROPPED: absence from an incomplete listing is not proof the write never landed (review R4-06); the missing owned pins are REPORTED only (`missing_owned=`, a WARNING log line), nothing changes — round 5 flagged them for a re-push, which after a cut-short listing re-pushed most of the roster and reset the retry clock of pins in backoff (R6-02, R6-03), and re-adding members another system removed is loss detection, outside P3a-2 (§7, R5-01). Residual: a listing cut off after the last owned pin, or one on a terminal where MonClub owns no pin, still reads as complete (R5-02) |

MB2000 (`_promote_intents_by_readback`): one `list_device_users` (a whole-terminal enumeration in ONE
STA command — no RTLog pump, no door service for its duration; ~1,860 users on gym 45, duration
`[UNVERIFIED]` — FIELD-TEST, 60 s timeout). So it runs only in the **daily maintenance slot**
(`_drain_daily_maintenance`): once per local day, after that day's first full sync has pushed and run
its removal step ("after the morning removals" — the PC is usually off at night, so there is no fixed
hour), only while no door command, member update or full sync is waiting, never during a push, and
only when intents of departed members exist. A promotion requests a full sync so the removal follows
at once. PullSDK (`_settle_pullsdk_intents`): inside every full sync, one extra `Pin\tCardNo` read of
the user table, only when such an intent is on the panel; a targeted revoke of an intent-only pin
reads that one pin (`_prove_pullsdk_intent`) and deletes it only if the card matches.
`[TEST: ::TestReadBackPromotion, ::TestPullSdkWriteAhead]` `[UNVERIFIED]` how the C3-400 returns
`CardNo` (padding, leading zeros are ignored in the comparison) and the MB2000's
`SSR_GetAllUserInfo` tuple order (§7): a wrong order makes every comparison mismatch, which fails
safe (nothing promoted) but leaves such pins unprovable.

### 3.4b Removals first, and retried fast (P3a-2, 2026-09-18)

**Order within a pass.** PullSDK already deleted stale pins before Phase A. The MB2000 full sync
did the opposite: `push_roster` first, and the revoke pass only `if sync_ok` — so one unrelated
member's refused finger meant no departed member was removed that pass. The revoke pass has no data
dependency on the push (its candidates are owned pins NOT in the desired roster; a pin being pushed
is desired by construction), so it now runs first; MIRROR still runs only after a successful push,
and the prune last. An explicit revocation whose pin that step removed is confirmed at once and is
not re-queued even if the push then fails. `[CODE: ultra_engine.py::_run_standalone_full_sync]`
`[TEST: test_removals_first_and_retry.py::TestRemovalsFirst]` — deliberate inversion:
`test_standalone_revoked_pin_removal.py::test_a_failed_push_no_longer_blocks_revocation`.
**Qualified by P3b-1 (§3.4f):** on MEMBERSHIP pins, the old pin of a person whose new pin is not yet
on the device (a renewal) is removed AFTER the push, not first; everyone else still goes first.

**Retry of a FAILED removal (≤ 300 s).** The claim "delete and upsert retries both back off to 24 h"
held for upserts only. A failed removal had no timer at all: the pass still reported success, the
scheduler stamped the roster hash and skipped the device as "unchanged" until the roster changed; a
refused PullSDK stale delete even erased its own state row, so it was never retried (§3.2g). Now a
removal the device refused — the MB2000 revoke pass's `failed` set, a PullSDK stale delete, or an
explicit PullSDK revocation still pending after its pass — arms the worker's own retry
(`_update_removal_retry`): 30 s, doubling, capped at `_REMOVAL_RETRY_MAX_SEC` = 300 s; the run loop
(`_maybe_request_removal_retry`) then requests a full sync `reason=removal-retry` whatever the
roster hash says, and only while connected. A pass with no failed removal clears it. A refusal by the
ceiling (`REVOKE_ABORTED`, §3.2g) is NOT a failure and is not fast-retried: nothing shrinks between
passes. `[T] REMOVAL_RETRY_SCHEDULED worker pins delay_s streak`. Load: each retry is one pass — a
roster build and state read, no device I/O for unchanged members — plus the failed removals only
(`SSR_DeleteEnrollData(…, 12)` per pin, then the neutralise fallback; ≤ the ceiling): at the cap ≤ 12
passes an hour, only while a removal keeps failing. `[TEST: ::TestFailedRemovalIsRetriedFast]`
Targeted revocations were already re-queued at once (`request_full_sync(revoke-failed)`); unchanged.

*Review round 1 (R1-06/07/08/22) — the retry follows what the removal step actually did.* Each pass
reports once (`_update_removal_retry` marks it): a step that RAN clears or re-arms from its own
failure list; a step SKIPPED because the roster is incomplete (`roster_withheld`, an empty roster)
leaves the retry as it is (it used to re-arm from the previous pass's list — a useless pass every
300 s for as long as the roster stayed incomplete); a step that could not be evaluated (ownership
state unreadable) re-arms. A pass that never reported — it raised, returned early, or (PullSDK)
stopped before its removal report, `_last_removal_report["complete"]` False — keeps a pending retry
armed (`_keep_pending_removal_retry`, run after every drained pass); it used to clear it, and the
roster hash already stamped then stranded the failed removal. The delay's exponent is clamped:
`30.0 * 2 ** 1024` raised `OverflowError` after ~85 h of one failing removal, before the streak was
stored, so every later MB2000 pass raised before its push. `[TEST: ::TestRetryReviewRoundOne]`

*Review round 2 — a removal that could not be attempted is PARKED* (`_REMOVAL_RETRY_PARKED_SEC` =
30 min, streak unchanged, `[T] REMOVAL_RETRY_SCHEDULED … parked=True`). Round 1 left the retry "as it
is" on a skipped step — but when the skipped pass was the retry pass itself its timer was already
spent, and the failed removal waited for an unrelated roster change (R2-17). Skipped now also covers
the MB2000 revoke pass's guards (explicit pins not owned, still desired, or inside the enrolment
grace) — they used to mark the step "ran" and clear another pin's retry (R2-20). On PullSDK the
pre-pass tells a revocation a fast retry can change (`DELETE_FAILED`, `OWNERSHIP_UNREADABLE`) from
one it cannot (`DEFERRED`: an incomplete ACCOUNT roster, an unnameable pin — it re-armed the 300 s
retry forever, R2-23); the latter parks. And the stale step's failed deletes are published as soon as
the step ends (`_last_removal_report`, `complete=False` until the end of the pass), so a later step
that raises no longer loses them (R2-21). ≤ 48 parked re-checks a day, only while such a removal is
pending. `[TEST: test_review_round2.py]` `[CODE: device_sync.MEMBER_SYNC_DEFERRED]`
*Round 3:* parking never postpones a sooner retry (R3-16); a PullSDK pass that left no removal report
at all (it stopped before `_sync_one_device`) is not "complete" and does not clear a pending retry
(R3-04); an MB2000 revocation whose pin the removal step removed is released at once even when the
rest of the pass fails — left ACTIVE, it excluded the member from every later roster until a restart,
even after a restored membership (R3-14). Its roster exclusion is released with it: keeping it at RETRY
(round 4) refused a membership restored meanwhile, and the next successful pass then left that paying
member off the terminal while reporting the roster in sync (R5-03). What the exclusion protected against —
a capped continuation built from a stale cache pushing the departed member back (R4-11) — is covered by a
database guard instead: for `_REMOVED_MEMBER_GUARD_SEC` = 10 min after MonClub finished a revocation — the
removal step removed the pin, or the targeted revoke (the usual route, R6-05) returned done: deleted or
neutralised the pin, re-pushed the person's other plans (ACCOUNT), or skipped a pin MonClub does not own —
every pass excludes that membership's rows if they are gone from the database, and a restored membership is
pushed normally. The check is ONE query per pass for
all guarded members (R6-07): a scan of `sync_users`, whose indexes cannot serve `active_membership_id` alone
(`EXPLAIN QUERY PLAN`: `SCAN sync_users`). Measured on this development PC, synthetic 2,000-row table:
median 0.2–0.5 ms for 1–10 guarded members, 3.3 ms (rows without fingers/photo) to 16 ms (2 fingers + a
22 KB photo per row) for 225, the removal ceiling on a 900-member roster; `[UNVERIFIED]` on the gym PCs.
Nothing is measured before P3a-2: the guard is new. If the read fails, the pass does nothing and fails, so
the scheduler retries it: excluding on doubt could DELETE a restored member (the removal step takes owned
pins missing from the roster) and report the roster in sync; trusting the cache could re-enrol a departed
one (R6-06). `[TEST: test_review_round6.py]` A pass re-queued because the link is dead
reports nothing to the removal retry (R5-04). `[TEST: test_review_round5.py]` `[TEST: test_review_round3.py]` Load note: on PullSDK every
retry pass also re-writes the door parameters (`DoorNDrivertime`, `DoorNIntertime`/anti-passback), like
any full pass (R3-09).

**Upsert retry cap 24 h → 6 h.** `device_sync._SYNC_RETRY_MAX_SEC = 21600` (both SDKs share
`DeviceSyncEngine._retry_due`; free attempts and the 15-min doubling unchanged). The PC is on about
06:00–23:00 and off overnight (door history, 2026-09-12 study), so a 24 h cap could leave a refused
member with no retry for two operating days; at 6 h a permanently refused pin costs ≤ 4 retries a
day (≈0.45 s per MB2000 member write, field 928/419 s; on PullSDK a firmware-cache clear plus a ≤10-call
probe per finger). New content still bypasses the backoff. `[TEST: ::TestUpsertBackoffCap]`

### 3.4c A deleted finger does not stay on the MB2000 — the slot sweep (P3a-2, 2026-09-18)

**The gap.** The vacated-slot removal (2026-09-05) clears only slots it KNOWS a pin held
(`device_sync_state.pushed_finger_ids`). An unknown set (NULL, or no row) yielded no removal at all
(`ultra_engine._standalone_removals`). Worse, a "known" set can be wrong: the backfill
(`_backfill_pushed_fingers`) and every successful push record the DESIRED set without clearing
anything, so a finger deleted while the mirror was write-only (before 2026-09-05) can still be
resident under a recorded set that omits it. `[CODE]` How many gym-45 pins are affected is
`[UNVERIFIED]` — FIELD-TEST (read-only): `SELECT device_id, COUNT(*), SUM(pushed_finger_ids IS
NULL) FROM device_sync_state WHERE device_id IN (8,10) AND ownership_confirmed=1 GROUP BY device_id`.

**The flag.** `device_sync_state.finger_slots_swept` (0 for every existing row) marks an owned pin
whose unused slots 0–9 were cleared once. Candidates are `ownership_confirmed=1 AND
finger_slots_swept=0` — both the NULL and the possibly-wrong recorded sets.

**The sweep.** `ZKStandaloneDevice.sweep_finger_slots(pin, slots)`: `SSR_DelUserTmpExt` per slot
through the one helper `_clear_finger_slot` (never the finger-index `SSR_DeleteEnrollData`, §3 of
the zkemkeeper guide), then `RefreshData`. An empty slot answers `False` (field-measured), so a
`False` is counted, not a failure; only an exception or a wedge fails the sweep. It never goes
through `remove_fingers_by_pin`, whose `False` means a refusal. ≤ `_SWEEP_SLOTS_PER_COMMAND` = 3
slots per STA command: 3 × 71–171 ms ≈ ≤ 0.5 s without event pump or door, and the worker serves
queued events (rescues) and operator opens between commands (`_yield_during_device_work`).

| When | Which pins | Recorded |
|---|---|---|
| right after a **targeted** member push (`_run_standalone_member_sync`) | that pin, if MonClub owned it BEFORE the push and never swept it (`_finger_sweep_plan`); slots = 0–9 minus the member's fingers | swept=1; an UNKNOWN set is recorded (the desired set) only after the sweep succeeded — the push itself leaves it NULL |
| the **daily batch** (`_drain_finger_sweep`), one command per run-loop iteration | owned, unswept, still-desired pins; ≤ `_FINGER_SWEEP_DAILY_CAP` = 100 pins a day | same |

The daily batch runs in the daily maintenance slot (§3.4a): after the local day's first full sync
has pushed and run its removal step ("after the morning removals" — the PC is usually off at 03:30),
only while no door command, member update or full sync waits, and never during a push. It never
clears a slot that is desired in the last full sync's snapshot OR recorded now (a targeted push may
have added a finger since), and it skips a pin pushed in the last 10 min (the MIRROR grace window).
Budget: ≤ 100 × 10 calls × 171 ms ≈ 171 s of terminal time a day, in ≤ 0.5 s slices; a fully
unswept 928-pin terminal is done in ~10 days. `[T] FINGER_SWEEP worker pin source ok cleared empty
raised dur_ms` (`abandoned=True` when a plan was dropped mid-way, below).

*Review round 1 (R1-18/R1-19/R1-27).* A pin's plan was built once and resumed across run-loop
iterations: a targeted push or a full sync served between two of its commands could write a finger
into a slot the plan still meant to clear, and the batch cleared it while the state said it was there
(never re-pushed). And the snapshot the batch reads was rewritten by every pass, including one with an
incomplete roster, so a member missing from it had EVERY slot cleared and `''` recorded. Now
`_sweep_check` runs before every command: the pin must be in the last COMPLETE roster's snapshot
(`_last_desired_*`, written only when the roster was not withheld and the removal step ran without a
ceiling refusal), owned, unswept, outside the 10-min grace window, and confirmed (`last_ok=1`) with
exactly that snapshot's hash (`db.get_pin_sync_status`) — i.e. the terminal is known to hold exactly
those desired fingers. If anything moved, the plan is dropped, not marked swept; the pin is tried again
another day (or swept by its next targeted push). A failed push is therefore never swept by the
batch, and the snapshot is only recorded for a pin whose last push confirmed it.
`[TEST: test_finger_slot_sweep.py::TestDailyBatchReviewRoundOne]`

*Review round 2.* The maintenance slot opens after every pass that pushed, whatever its roster — the
batch and the read-back read the last complete snapshot, re-checked per pin — so a gym whose roster is
always incomplete (a latched ceiling, ACCOUNT rows without `mainAccountId`) no longer loses them
silently; with no complete roster since the worker started, `[T] MAINTENANCE_SKIPPED
reason=no_complete_roster` once a day (R2-05). It never runs on a link the driver reports dead (R2-16).
The targeted sweep reads the outcome as RECORDED, so a pin whose fingers capacity withheld is not swept
and its withheld finger is never recorded as resident (R2-02). `[TEST: test_review_round2.py]`

**Never a pin MonClub did not own before the push.** A first push (no row) or an unowned row is
never swept: on gym 45's shared terminals that pin may hold another system's user, whose fingerprints
are not MonClub's to delete. Residual `[UNVERIFIED]`: a MonClub pin that collided with a foreign
user at its FIRST push keeps that user's fingers until the daily batch reaches it (it is owned after
the push); whether any MonClub pin collides with a foreign pin on devices 8/10 is FIELD-TEST
(enumerate the terminal read-only and compare).

`[UNVERIFIED — HARDWARE-GATED]`: that a `False` from an OCCUPIED slot never happens (every field
observation of `False` was an empty slot; 943/943 occupied clears returned `True`, §3), and whether
`RefreshData` is needed for the matcher to drop a cleared template. FIELD-TEST on a bench MB2000:
enrol fingers 0 and 3 on a test pin, mark it owned/unswept, sweep 1–9 → expect `True` only for 3,
then confirm at the terminal that finger 3 no longer verifies and finger 0 still does.
`[TEST: test_finger_slot_sweep.py]`

**Also fixed here:** the backfill received every desired pin not pushed — including one held back
by the retry backoff — and wrote it `ok=True`, so a refused member silently became "in sync" and
was never retried. Backoff-held pins are now excluded.
`[TEST: ::test_a_pin_in_retry_backoff_is_not_backfilled_as_ok]`

### 3.4d Capacity and template-version checks (MB2000, P3a-2, 2026-09-18)

**Before.** `_read_device_status` / `_read_fp_version` ran at connect only, as diagnostics
(`_warn_if_device_full` logs); `push_roster` wrote every user and template unconditionally, and a
version disagreement was noticed only after the terminal REFUSED a template — never when it
accepted an unusable one. `[CODE]`

**Capacity (`CAPACITY_FULL`).** Capability-gated (`supports_capacity_check`). Before a full-sync or
targeted push that needs a NEW slot, `read_capacity()` re-reads `GetDeviceStatus` 11 (`users_free`)
and 10 (`fingerprints_free`) — 3–6 COM calls in one STA command — because a connect-time value can
be hours old on a terminal another system enrols on. `UltraDeviceWorker._capacity_admit` refuses
only the write that has no slot, never more:

- **A member certainly not on the terminal** (no state row AND no push intent — a row or an intent
  means it may already be there, and an update needs no new user slot) is refused whole when no
  user slot is free: not pushed, no state row, it stays pending. A targeted push of it is deferred.
- **A finger** that needs a new fingerprint slot (a recorded finger rewritten is a replacement and
  needs none; an owned pin with an unknown recorded set counts none) is withheld when none is free.
  The member itself IS pushed — user row, card, replacements, and the clear of its vacated slots,
  which count as free from that pin on (they are cleared before its templates are written). The pin
  is recorded NOT in sync, so the withheld finger is retried.

The free counts are a budget in push order. Reported as `[T] CAPACITY_FULL worker users_free
fingerprints_free need_users need_fingers skipped withheld_fingers withheld_pins` + push-history note
`CAPACITY_FULL=n (…)`. The pass is `ok` but withholds the roster hash, so the scheduler retries it.
Updates and every removal are never refused. An unreadable status gates nothing. The admission runs
before the targeted push's intent, so a refused push never rewrites what the intent records.

*Review round 1 (R1-10/11/17/29):* the first version refused the whole member when fingerprint slots
were short — a new member got no card at all (base wrote the card and let the terminal refuse the
templates), and an owned member's deleted finger was never cleared; an intent-only pin (a crash after
the write) counted as a new user. All four are covered by tests.
`[TEST: test_capacity_and_template_version.py::TestFingerLevelRefusal]` *Round 2 (R2-01):* marking the
withheld pins failed turned a WEDGED chunk's result (which names no pin: nothing confirmed) into one
naming only them, so every other member of that chunk was recorded written and owned; the marking now
applies only to a result that lists its failed pins. `[TEST: test_review_round2.py]` *Round 3:* such a
pin's state write is "not in sync", which keeps its previous `pushed_finger_ids` — but its vacated slots
WERE cleared and its other fingers written, so every retry cleared an already-empty slot, read the
`False` as a refusal and failed for good; what is resident is now recorded
(`db.set_device_pushed_fingers`, R3-12 — on the full sync per chunk and on the targeted push). A
targeted push (≤ 10 pins) admits — and reads its pins' finger state (R4-05) — with primary-key reads, not
three whole-device tables (R3-24). `[TEST: test_review_round3.py]`
`[UNVERIFIED]` that index 11 is `users_free` on the MB2000 beyond the 2026-09-06 arithmetic
(`1838 + 1162 = 3000`), and that `SSR_SetUserInfo` on an existing pin consumes no new user slot.

**Template version (`TEMPLATE_VERSION_MISMATCH`).** In `_do_push_roster`, a template whose
`templateVersion` and the terminal's `~ZKFPVersion` BOTH parse to integers and differ is not uploaded:
no delete-before-write, no write (whatever the slot held stays), the pin is failed with reason
`template_version_mismatch_f<N>` (so it is retried under the upsert backoff, §3.4b) and one
`[T] TEMPLATE_VERSION_MISMATCH worker skipped device_fp_version` per push (never per finger inside the
STA loop, §10.3). An unreadable or non-numeric device version gates nothing. `templateVersion`
defaults to 10 when the backend omits it (`_collect_templates_for_pin`), so a template really of v9
but unlabelled would read as 10 — `[UNVERIFIED]`. FIELD-TEST before relying on it at gym 45: read the
connect line `deviceFpVersion=` of devices 8 and 10 (the v1.4.26 run had no disagreement), and after
deploy grep `TEMPLATE_VERSION_MISMATCH`: any hit names fingers that were never usable on that
terminal. Whether a mismatched template can in fact never match is itself `[UNVERIFIED —
HARDWARE-GATED]` ("template portability", module docstring).

### 3.4e The door does not wait behind a push; one pass is capped (MB2000, P3a-2, 2026-09-19)

**Before.** A standalone full sync ran `push_roster` to its end on the worker thread. Each chunk
(`_PUSH_CHUNK_MEMBERS` = 10 members, one STA command) returned to the worker, but nothing ran
between chunks: a scan the terminal reported during the push waited in the driver's event queue,
a desk open in `_cmd_queue`, an enrolment's targeted push in the member queue — until the whole
push ended (419 s for 928 members, field v1.4.26). And one pass pushed every pin that needed it.
`[CODE]` `[TEST: test_push_yield_and_cap.py — 14 of its 15 tests fail on c42e589]` The PullSDK
path is unchanged: it already yields between `SetDeviceData` chunks (`_door_yield_cb`, and
`_rtlog_yield_cb` behind the gym flag `ultra_sync_yield_to_rtlog`, default OFF).

**Between two chunks** (`push_roster(between_chunks=…)` → `UltraDeviceWorker._standalone_push_yield`),
on the worker, while the STA thread is idle:

1. The events the terminal buffered during the chunk are already queued: the `push_roster` STA op
   runs `_pump_events_once` itself before releasing the caller, and the loop's own step-2 pump is
   skipped for that iteration — the same COM calls, earlier. On a pump error step 2 runs and
   handles it exactly as before (a dying pump is a disconnect). `[CODE: _sta_main]`
2. `_yield_during_device_work`: every queued event is decided (`_process_event` — a QR/TOTP or
   staff-RFID rescue opens the door here) and queued desk opens run (`_sync_yield_to_doors`).
3. At most ONE pending member update or revoke is served (`_drain_member_sync_commands(limit=1)`),
   never twice for the same member in one pass (a failing revoke re-queues itself). The pins it
   handled — named by `_note_push_superseded` from the member-sync, deferral and revoke paths,
   whatever their outcome — are dropped from the chunks not yet sent and returned in the result's
   `superseded_pins`: neither pushed, nor failed, nor `not_attempted`. The pass then leaves them
   out of its own state write (`_push_with_chunk_recording`'s tail) and its success check
   (`_standalone_failed_pins_from_result` sees only the pins actually sent), and adds every pin it
   handled to the prune's keep set and to MIRROR's roster. Without that a member revoked mid-push
   is re-enrolled from the pass's older snapshot, a renamed one is overwritten and stamped with the
   old hash (the 2026-09-06 stale-snapshot bug), and a member enrolled mid-push loses the row that
   proves MonClub wrote it.
4. The worker state goes `push_yield` → `full_sync`, so `WORKER_STALL` (25 s in one state) now
   measures one chunk, not the whole push — the worker is no longer frozen between chunks.

Never in bracket mode, never before the first or after the last chunk, never after the loop
stopped; an exception in the yield is logged and the push carries on. `[CODE]`
`[TEST: test_push_yield_and_cap.py]`

**Measured** on a fake terminal (harness `measure_door_wait.py`, kept out of the repo; waits
counted in member writes, which do not depend on machine speed, projected with the field
419 s / 928): a scan, a desk open or a member update queued during a 100-member push waited up to
**99 writes before** (the rest of the push, median 67; 44.7 s projected — on a 928-member re-push
up to 927 writes ≈ 418 s) and at most **9 writes after** (the rest of its chunk, median 5; 4.1 s
projected). `[TEST: fake terminal]` `[UNVERIFIED — HARDWARE-GATED]`: that the MB2000 hands over, at
the chunk's end, the events of scans made during the chunk (`ReadRTLog`/`GetRTLog` after a write
loop), and that the terminal's own card and fingerprint decisions — which the PC does not make — are
unaffected by a concurrent push.

**The bound is within ONE pass** (review R1-23). Each pass also has a setup — roster build, state
reads, the capacity read, the removal step — with no yield, and the cap multiplies passes (19 for 928
members). Measured on the fake: a desk open queued at the end of a capped pass waited 0.35 s (the next
pass's setup), and setup alone is 17 ms median with the local fingerprint index stubbed. On the gym
PC it is `[UNVERIFIED]` — FIELD-TEST: compare each `FULL_SYNC_START` with that pass's first
`ZKEM_PUSH_CHUNK`. A pass that served an update mid-push withholds the roster hash (review R1-24: that
update may itself have failed or been deferred), so the scheduler runs the next pass that re-checks it.

**A dead link is rebuilt** (review R1-21). A COM call past its deadline — a door open, a sweep
command, the daily read-back's enumeration — makes the driver abandon its STA thread and clear
`is_connected`; the worker never looked (its only reconnect trigger is a poll returning None, and this
driver's poll never fails), so nothing pumped events or opened the door until an unrelated push or the
30-min refresh. `UltraDeviceWorker._push_link_lost` now checks once per loop iteration and reconnects:
`[T] WORKER_LINK_LOST`. `[TEST: test_worker_link_recovery.py]` *Rounds 2–4:* the scans the driver had
already queued are decided before it is torn down, so none is lost (history, popup; R2-13) — a rescue
among them cannot open the door on the dead link, exactly as before P3a-2, and the member re-scans after
the reconnect (accepted, R3-19). Carrying them over the reconnect was tried in round 3 and withdrawn in
round 4: aged from the wrong clock it could open the door a minute after the scan, and its age bound
dropped terminal-decided scans from the history (R4-01/07/08/09). EVERY queued scan is decided, not only
the first 64 (R5-06), and so are the scans queued when the 30-min connection refresh or a sync hand-off
tears the driver down (`_decide_queued_events`, R5-07 — those teardowns used to drop them undecided,
before P3a-2 too), including the ones the STA thread's last event pump queues while it stops:
`disconnect()` sets its stop flag and joins it, and the thread pumps once more before it looks at the flag
(`_close_link_deciding_scans`, R6-01). Those get their history row and popup, but the connection is closed
by then: a rescue among them is recorded `DOOR_CMD_FAILED`, as on a link loss, and the member re-scans
(deciding it after the reconnect could open the door long after the scan, R4-01). Not on a link loss: a
thread abandoned inside a COM call is not joined, and a scan it pumps when that call finally returns lands in
the discarded queue — no history row, no popup, as before P3a-2 (residual). A full-sync pass is not run on a link the driver reports dead — it waits, queued, for
the reconnect (R4-10). The first loss reconnects at once; a loss within `_LINK_STABLE_SEC` = 60 s
after the reconnect that followed the PREVIOUS loss waits 2, 4, 8 … s up to the connect backoff cap, so
a flapping terminal is not a connect loop (R2-12) — measured from that loss, so a routine 30-min refresh
never inherits an old streak (R3-01) — and such a wait starts the outage clock, so the desk's Open
answers "device unreachable" at once instead of timing out (R3-02). Neither the push yield nor the run
loop's member drain spends a member update on a link the driver reports dead (R2-14, R3-03). (`CONN_DISCONNECT` timing stays on
`_disconnect` — the round-1 insertion had moved the decorator onto the new method, R2-11.) It does not shorten the command itself:
while the read-back's single enumeration runs (duration on 1,860 users `[UNVERIFIED]`), no scan is
decided and no door opens.

**The desk's Open button can still time out during a push** (§3.1a): 4.1 s > the handler's 2.0 s.
A press the yield has not reached when the caller's 2.0 s run out answers 503, and the claim keeps
the yield from sending it afterwards; a press the yield takes first gets the device's answer, the
handler waiting up to 2 s + 5 s for it. `[CODE: ultra_engine.py::request_door_open,
::_drain_commands]` `[TEST: test_door_open_deadline.py::test_the_mid_push_yield_event_counts_expired_opens_apart]`
On a scratch probe that held the drain for 1.9 s (a stand-in for a chunk, not the real push
yield), master answered 503 at 2.0 s while the relay fired at 1.9 s; with the claim the answer was
200 at 2.4 s. `[TEST: scratch probe, not committed]`
Rescue opens have no such deadline and do go through. A `_PUSH_CHUNK_MEMBERS` of about 4 would bring
the worst case under 2 s, but every chunk also costs a `RefreshData(1)` whose duration on the MB2000
is `[UNKNOWN]`, so it is not changed without that number.

**The cap.** `_FULL_SYNC_MAX_PINS_PER_PASS = 50` pins pushed per pass; removals (they run first,
§3.4b) are not counted. It is not what protects the door (the yield does, every 10 members): it
bounds how long anything that needs a NEW pass waits — an expiry the scheduler found, the 30–300 s
removal retry of §3.4b, a revoke that fell back to a full sync. 50 × 0.45 s (the field per-member
rate) = 22.6 s, under the 30 s first removal retry; before, such a pass waited for the whole push.
There is no opening-hours data in this app, so the cap applies at every hour. When more pins need a
push, they go in this order (`_prioritise_for_cap`, stable): a vacated finger slot to clear first,
then new members, then retries of unconfirmed pushes, then plain changes — sorted BEFORE capacity
admission and sliced AFTER it, never before the backfill (a pin cut there would be backfilled as in
sync). A pin left for later gets no state row. The capped pass reports `ok` with the roster hash
withheld, skips MIRROR (its last continuation runs it), writes the push-history note
`PUSH_CAPPED=n (50 per pass; the rest next pass)`, emits `[T] FULL_SYNC_CAPPED`, and — only when it
wrote at least one member — queues its own continuation (`request_full_sync(reason="push-capped")`,
carrying the roster hash and `full_reconcile`). A pass that wrote nothing queues none, so a terminal
refusing everything cannot loop; the withheld hash makes the scheduler retry it. `[CODE]`
`[TEST: test_push_yield_and_cap.py::TestOnePassIsCapped]` Measured on the fake: 928 members → 19
passes; each pass's setup before its first write (roster build, state reads) median 17 ms with the
local fingerprint index stubbed. `[UNVERIFIED]` on the gym PC — FIELD-TEST: compare each
`FULL_SYNC_START` with that pass's first `ZKEM_PUSH_CHUNK`.

**Still one command: removals.** The removal step deletes every departed pin in ONE STA command
(`delete_users`, at most the §3.2g ceiling), with no event pump and no door for its duration. Its
duration is now on `[T] ZKEM_DELETE_DONE dur_ms`; the per-delete time on the MB2000 is `[UNKNOWN]`.

**Idle door path, before vs after** (base `d09f88f` vs this branch; the real
`UltraDeviceWorker.run()` loop over a fake terminal; 3 runs x 150 scans and 150 desk opens each,
plus 400 desk opens with a stack probe). The decision code — `_poll_with_watchdog`,
`_process_event`, `_handle_totp_rescue`, `_open_door_with_retry` — and the driver's `open_door`,
`poll_rtlog_once` and `_on_att_event` are byte-identical to the base. `[CODE: git diff d09f88f]` The
run loop gained idle calls (`_maybe_request_removal_retry`, `_drain_daily_maintenance`, and after review
round 1 `_push_link_lost`): +2.9 to 4.5 µs per iteration. Re-measured after round 1 (2 runs each):
scan-to-decision median 238 / 256 ms base vs 266 / 305 ms branch, desk-open median 0.4 ms on both, max
1.2 ms on both, no scan lost. Scan to decision, median 256 / 305 / 304 ms on the base and 288 / 270 /
275 ms on the branch (p95 460-494 vs 462-493 ms; set by the STA loop's 250 ms idle wait plus the
worker's own empty-poll wait, up to 300 ms, which no scan wakes — neither version changes them); no
scan lost. Desk-open round trip, median 0.6-0.8 ms on both. Two branch
runs had one slow open each (148 and 230 ms of 150); the 400-open probe then gave base max 54 ms
(worker asleep: thread scheduling) and branch max 29 ms — no systematic difference.
`[TEST: fake terminal]` Not measured here: while the once-a-day intent read-back (one terminal
enumeration, §3.4a) or a sweep command (at most 0.5 s, §3.4c) runs, the loop waits for it; their
MB2000 durations are field items.

### 3.4f Renewal ordering — the new pin first, then the old one (P3b-1, 2026-09-19)

**What a renewal is, pin-wise.** The backend's **renew** action updates the SAME `ActiveMembership`
(new start and end dates, same id — the same MEMBERSHIP pin); nothing leaves the turnstile.
`[CODE: backend ActiveMembershipService.renewActiveMembership — findById(dto.getActiveMembershipId()),
setStartDate/setEndDate, save]` A NEW id for the same person comes from selling ANOTHER plan
(`startMembership` refuses the same plan twice with 409 and gives the new row the same `user`, i.e.
the same `userId`). `[CODE: backend ActiveMembershipService.startMembership]` P3b-1's date flip
produces exactly that case: at 00:00:05 or at power-on, the old plan's row is held out and the new
plan's upcoming row promoted in ONE flip, so one full-sync pass sees the old pin leave and the new
pin arrive. With removals first (§3.4b) the old pin went before the new one was written, and if
that write failed the person had neither until a later pass (§7 R3-21).

**The rule.** A **hold** is an owned pin that left the desired roster, is NOT an explicit revocation
of the pass (nor an excluded or recently-removed id), and whose PERSON
(`member_person_link.user_id`, §3.8) still has a desired pin not confirmed on the device at the start
of the pass (it needs a push — new, changed, failed — or is held back by the retry backoff).
MEMBERSHIP scheme only; under ACCOUNT a renewal keeps the account pin and nothing is held. No person
link (a membership never cached on this database, a read failure) → no hold: removed first, as before.

- The holds are set aside first; the removal ceiling (§3.2g) judges the leavers this step removes,
  and a refusal removes none of them (the holds stay held).
- Leavers are removed first, exactly as before.
- After the push, a hold whose person's desired pins are ALL confirmed now (sent, not failed, not
  superseded, not capped out, not capacity-refused) is removed by the same ownership-checked code
  (MB2000: `_remove_departed_pins`, ownership re-read first; PullSDK: `_bulk_delete_pins` +
  `clear_device_revocation_state`) — only while the leavers removed first plus these still fit the
  ceiling; otherwise all of them are kept for a later pass (`REVOKE_ABORTED path=renewal_release`).
  A failed post-push removal is a normal removal failure (fast retry, `REMOVAL_FAILED`).
- The rest are KEPT: never removed that pass, state rows kept (prune keep set), MIRROR treats them as
  roster; not a failure, not a ceiling refusal. The person keeps entering through the old pin until
  the new one lands (a retry, the next capped pass) — or until the server's own revocation of the
  old plan arrives with the next sync, which removes it first (below, "Not covered").
- **No hold on a full terminal** (MB2000): a hold keeps the old pin's user and finger slots, and
  capacity admission (§3.4d) refused the new pin on every pass while they were taken — it never
  landed (review round 2, reproduced against base). When there are holds, the full sync dry-runs the
  same admission first (`_capacity_admit(report=False, unconfirmed_is_new=True)`, a live capacity
  read) over every pending new pin — to push now or parked by the retry backoff. Holds are allowed
  only when EVERY pending new pin fits without the held slots; otherwise nobody is held and every
  old pin goes first, as before P3b-1. A new pin not confirmed on the terminal counts as needing a
  slot even when an earlier attempt left a state row or a push intent (review round 3). The earlier
  per-person rule ("hold the people whose own pin fits") still let a hold take the slot another
  pending pin needed — a first-day starter refused, or a renewal not held and so left with neither
  pin (review round 4). So on a terminal near capacity a renewal falls back to base behaviour
  (old pin first; the R3-21 gap for that pass) rather than costing someone else their slot.
  `[TEST: tests/test_p3b1_review_r2.py::test_a_renewal_on_a_full_terminal_removes_the_old_pin_first_and_the_new_one_lands,
  tests/test_p3b1_review_r3.py::test_a_known_new_pin_on_a_full_terminal_does_not_keep_the_person_held,
  tests/test_p3b1_review_r4.py — the slot tests]`
- One removal-retry report per pass: with holds, the removal step's own result and the post-push
  failures are reported together after the push (the exception handler reports if the pass raises
  in between). One `[T] RENEWAL_HOLD worker|device_id held removed_after_push kept` per pass that
  had holds; `REVOKE_DONE pins` now counts only what the removal step removed first.

`[CODE: ultra_engine.py::_run_standalone_full_sync, ::_neutralise_revoked_pins,
::_remove_released_holds, ::_remove_departed_pins; device_sync.py::renewal_holds,
::renewal_released_holds, ::DeviceSyncEngine._sync_one_device]` `[TEST: tests/test_renewal_ordering.py
— 34 tests, both SDKs; red on the base]` `[TEST: local e2e S3d — on the synced rows, the fake MB2000
saw the two leavers deleted before any write and the renewal's new pin written before its old pin
was deleted]`

On the MB2000 `_standalone_pins_needing_push` now runs once, BEFORE the removal step (it reads the
state of desired pins only; the removal step clears only non-desired pins), so `SYNC_RETRY_BACKOFF`
now appears before `REVOKE_DONE` in the log. On PullSDK "unconfirmed at the start" is the pins that
needed a push in the hash loop (before backoff and delta pruning) plus `pins_to_sync` — on a delta
pass it errs toward keeping the old pin. The ULTRA PullSDK full sync hands the engine the
memberships its revoke pre-pass handled (`engine._full_sync_revoked_pins`, set in
`_drain_full_sync_commands` after the unchanged pre-pass) so an explicit revocation is never held.

**Not covered.** A server revocation of the old plan served by the TARGETED path
(`_run_standalone_member_revoke`, `sync_member_on_connected_sdk`) still removes it first, whatever
the new pin's state — outside "the same pass"; so does the full pass for a pin the server
revoked explicitly (required, never held). The date-driven case is served by the flip's full sync
before any server revocation arrives — when the new pin lands in that pass. When it does not (the
hold is kept), the next successful sync brings the server's revocation of the old plan (the flip
never touches `member_shadow`, so the diff names it) and the old pin is removed first while the new
one is still refused: the member then has neither pin until the new one lands, as in base. The hold
protects a kept renewal only while the PC is offline (review round 2). A new pin superseded mid-push
counts as unconfirmed for that pass. `[CODE]` `[UNVERIFIED — HARDWARE-GATED]` whether an MB2000 or a C3-400 accepts a second
user carrying a card number another user on the device holds: the backend keeps cards unique across
a gym's memberships (`cardInUseInGym`, no status filter), but an old pin's device row can still carry
a card later moved to the new membership. If the terminal refuses the duplicate, the new pin fails
every pass and the hold is kept (the person still enters with the old pin, but the new plan's
fingerprints never land). FIELD-TEST on a bench MB2000 and C3-400: write user A with card X, then
user B with card X, and check whether B lands.

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
| HTTP 400 or 409 (`_ROW_VERDICT_HTTP_STATUSES`) | per-row isolation: each row is posted alone; a row that gets 400 or 409 alone is `FAILED_TERMINAL`, with the real status in `backend_last_error`; the other rows as above | as above |
| any other status (401, 403, 422, 5xx), timeout, network | `FAILED_RETRYABLE`, fixed 300 s | **no** |

`[CODE: device_attendance.py::_mark_retryable, ::_named_retry_row_ids, ::_isolate_rejected_rows;
db.py::mark_access_history_unresolved]`
`[TEST: test_access_history_unresolved_bound.py; test_access_history_400_isolation.py]`

**Why 409 is isolated like 400 (2026-09-18).** Both are one verdict on a whole batch for a
fault in one row. 400: the backend's Jackson mapping of the array fails on one element
(`GymAccessController.normalizeBulkSaveGymAccessHistoryPayload`). 409: the backend's
`GlobalExceptionHandler.handleDataIntegrity` maps a `DataIntegrityViolationException` to
`409 CONFLICT`, and one bad row in `bulkSaveGymAccessHistory`'s `saveAll` rolls back the whole
batch. Before this, a 409 fell into the whole-batch retry and the same 200 rows were re-sent
every tick forever. Isolation is unchanged otherwise: sequential, at most one request per row of
the batch (≤ `UPLOAD_BATCH_SIZE`), and it stops at the first row that fails any other way
(that row and the rest stay retryable). A single-row batch is quarantined without a second
request. `[CODE: backend GlobalExceptionHandler.handleDataIntegrity, identical on backend
`main` and `claude/r0-turnstile-status`]` `[TEST: test_access_history_400_isolation.py::
test_http_409_isolates_the_poison_row_like_400, ::test_single_row_409_is_quarantined_without_a_second_request,
::test_a_row_409d_alone_during_a_400_isolation_is_quarantined_and_isolation_continues,
::test_http_422_still_keeps_the_whole_batch_retryable]` `[UNVERIFIED]` No 409 from this endpoint
has been observed in a field log. The backend's own unit test
(`GymAccessHistoryIdentityResolutionTest::saveAllFailurePropagatesRatherThanReportingSuccess`)
calls the controller directly, without Spring's dispatcher, so its comment "the client sees a
5xx" is not evidence; the handler mapping above says 409. The P1b backend change (duplicates
always succeed) removes the most likely cause; this client rule covers old/new server mismatches.

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
per PullSDK panel a connect, a full Pin read and `SetDeviceParam` writes; a FULL_REPLACE panel whose
rows fit under the removal ceiling (§3.2g) is
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

**The v2 safety sync (lane B, 2026-09-26).** Before it, `syncMeta.reconcileSec` (600 s: the server's
"how often an idle v2 PC should compare its list with mine", `GymAccessController.accessV2ReconcileSeconds`)
was stored in `access_v2_state.reconcile_sec` and read nowhere; a v2 PC synced data on the healthy
interval (30 min) and polled only pending COMMANDS every 120 s while its socket was down (§3.9). The
server leaves some changes un-notified and counts on that poll ("the PC's safety poll covers it",
backend plan P2b). `[CODE: db.py::_apply_protocol2_save; backend GymAccessController, read not run]`
Now `[CODE]`:
- **One predicate**, `MainApp._v2_safety_sync`: the v2 runtime's `availability` is `ON` (the commands
  switch), `access_v2_state.trusted` (the dates switch and a members section applied) and
  `reconcile_sec` a positive integer → `{reconcile_sec, socket_connected}` (`notice.connected`);
  anything else — no runtime yet, `UNKNOWN`/`OFF`, an untrusted or unreadable state — is None, today's
  behaviour.
- **The healthy timer** (`reschedule_sync_timer`, `sync_cadence.healthy_sync_delay_sec`): None → the
  healthy interval exactly, as before. Socket connected → `max(60, reconcileSec)`; socket down → 120 s;
  never longer than the healthy interval, and a shorter cadence is spread by × uniform(0.8, 1.0) so the
  PCs of a gym whose sockets dropped together (a redeploy) do not sync in step — the spread only brings
  a sync forward. The timer is armed at each tick's start, so a notice-driven sync restarts the count.
- **The failure-retry schedule and the `Retry-After` clamp are unchanged**: they keep the healthy
  interval as their cap, so an outage is still retried at 15/30/60/120/300 s and a 429 still waits its
  `Retry-After` (up to 30 min), never the 120 s cadence.
- **Tighten only** (`_tighten_sync_timer`, loop thread): when v2 comes on (`V2Runtime._set_availability`
  → `ON`), when a socket session ends (`on_disconnected`; a handshake that never succeeds leaves
  `connected` False, so the cadence is already the 120 s one) — both posted to the loop through
  `app.after(0, …)` by `runtime.py::_post_cadence_check` — and after each successful sync, called
  directly by `_on_sync_work_finished` on the loop thread (trust may have just arrived with that save,
  review R3-F4). It brings the armed timer forward when it is due later than the
  new target, never pushes it back, and never touches a failure retry. A socket that comes back is
  followed by its `welcome` sync, whose tick arms the longer cadence.
- **DEVICE-mode panels keep their cadence**: a successful `TIMER` tick that refreshed neither members
  nor devices reconciles them only when it started at least one healthy interval after the last
  reconcile it dispatched (`_safety_tick_device_reconcile_due`; outside safety mode every such tick
  does, as before). No fleet device is DEVICE-mode (§3.2g). ULTRA workers are asked for nothing by a
  tick that refreshed nothing (unchanged). `TIMER` is not in `_should_defer_ultra_reconnects`, so a
  safety tick defers no reconnect.
- **No success sound on a safety tick that brought nothing** (review R1-F1, R2-5):
  `_maybe_emit_sync_success_feedback` publishes no `sync_completed_success` for a `TIMER` sync in safety
  mode whose answer refreshed no section — the desk's sound and confetti (`tauri-ui`
  `AccessFeedbackProvider`, both on by default) would otherwise play up to every ~2 min. A safety tick
  that brought a change plays them, as the probe's sync for that change did; every other successful
  sync, and every `TIMER` sync outside safety mode, plays them as before. Each tick
  still writes its `sync_run_history` row (kept 30 days, `prune_sync_run_history`): up to ~560 a day
  with the socket down all day (37.5/h over a ~15 h day), ~110 with it up, against ~30 today; the row
  size is not measured `[UNVERIFIED]`.
- **A lost notice now waits for the safety sync** (review R1-F8): with the probe off, a change whose
  notice never arrives is picked up by the next safety sync — within `reconcileSec` (600 s) while the
  socket is up, 120 s while it is down — where the 45 s probe caught one within ~45 s. The backend's
  `AccessNoticeCoalescer` javadoc speaks of a "120 s safety poll"; its `syncMeta.reconcileSec` default
  (600, `GymAccessController`) is what this PC follows. `[CODE: backend main 919231a8, read not run]`
- **Power-on and offline**: the runtime starts 12 s after launch in `UNKNOWN` (§3.9a), so a PC boots on
  today's cadence and the probe runs until the server answers `ON`; offline the syncs fail and the
  failure schedule decides, as before (`UNREACHABLE` keeps `ON`, which only matters once a sync
  succeeds). An old server (`OFF`, or a v1 answer → `trusted=0`) is today's behaviour exactly.
`[TEST: test_v2_safety_sync.py — the cadence, the predicate (every "not v2" case), the timer on the
§3.6 harness, the failure schedule and a 429 in safety mode, tighten/never-lengthen, the runtime
hooks, the DEVICE-mode gate]` On aeeef69 nothing reads `reconcile_sec` (grep, 2026-09-26). `[CODE]`

*Load, per gym with 3 v2 PCs* (they share the gym account's `RateLimitFilter` bucket, 200 requests /
60 s, for `getSyncData`, the probe and the door-history upload; the command poll goes to the separate
`access-pc:<ip>` bucket, 3000 / 60 s, `RateLimitFilter.ACCESS_PC_PATTERNS`). Counted from the code, not
measured `[CODE]`:

| per hour, 3 PCs | before (v2 on) | socket up | socket down |
|---|---|---|---|
| members-version probe (2 `MAX(updated_at)` queries each; off in safety mode, below) | 240 | 0 | 0 |
| `getSyncData` on the timer | 6 | 18–22.5 | 90–112.5 |
| door-history upload (only when rows are pending, review R4-2) | ≤ 6 | ≤ 18–22.5 | ≤ 90–112.5 |
| pending-command poll (P3b-2, unchanged; PC bucket) | 0 up / 90 down | 0 | 90 |

Plus, unchanged: the notice-driven syncs (≤ 1 a minute per PC, §3.9), one heartbeat per PC every
300 s, and the first sync of each Tunis day carrying the full member list. Every successful tick also
runs the door-history upload (`DeviceAttendanceMaintenanceEngine.run_blocking` → `_sync_pending_history`):
one `bulk_save_gym_access_history` POST whenever door events are pending — the same rows in total,
spread over more, smaller requests. The busiest case on the gym account's bucket — socket down, doors
busy — is ≤ 112.5 + 112.5 = 225 requests an hour for the gym, ≤ 3.75 a minute, under 2 % of the bucket;
the command poll's 90 an hour are on the PC bucket. The weight is
per request, not per count: a no-change `getSyncData` still loads the gym's whole deliverable scope
(`findAllValidForAccessByGymId`/`…ByGymFamilyName` + freezes), builds the credentials, computes the four
version tokens (`computeMembersVersion` counts fingerprints and enrolments and digests the id set) and,
on protocol 2, `buildSyncV2` — against the probe's two aggregate reads `[CODE: backend main 919231a8
GymAccessController.getGymAccessUsers, ::getMembersVersion, read not run]`. So socket down means up to
~19× as many scope builds as before for that gym, in exchange for 240 fewer probes; socket up, 3–3.75×.
The server time of a no-change `getSyncData` for gym 58 (~1,690 deliverable rows) is `[UNVERIFIED]` —
FIELD-TEST: the backend's `[PERF] scope+freeze+filter` log line. Socket down should be the exception
since the nginx WebSocket block was added (2026-09-26, §3.9 `[UNVERIFIED — FIELD-TEST]`); a gym whose
sockets never connect runs at the socket-down rate for as long as that lasts.

*The ULTRA scheduler's own timer is separate and unchanged*: `UltraSyncScheduler._run` passes every
`min(15 min, the shortest ultra_sync_interval_minutes)` — the 15-min seed caps the per-device default of
30 min, which `/api/v2/ultra/status` reports as `sync_interval_minutes` all the same. Local work only (a
device whose roster hash is unchanged is skipped); left as it is and now commented so (lane B). `[CODE]`

**The 45 s probe and the 22:00 job are off in safety mode — and only then (lane B, 2026-09-26).** Both read
the same `_v2_safety_sync`, so the probe can never be off while the cadence is the 30-min one: a v2 PC
whose socket drops goes from ~45 s change detection to ≤ 120 s, not to 30 min. `[CODE]`
- `ChangeDetectorService._poll_once` asks `app.change_detection_gated()` first and makes no request
  while it answers exactly `True` (logged once per change of state); a gate that raises or answers
  anything else leaves the probe on. The thread keeps running, so the probe resumes at its next turn
  when the safety sync stops; its first poll then compares with the baseline it had, and a change made
  meanwhile starts one sync. `[TEST: test_v2_safety_sync.py — the probe tests]`
- `_daily_sync_check` does not fire the 22:00 job while `_daily_sync_gated()` — safety mode AND not
  `manual_sync_mode` — and does not mark the day as run, so if the safety sync stops later that evening
  the job still fires. In a manual-sync gym it stays: it is that gym's only automatic push of the day
  (a safety sync is a `TIMER` sync, which manual mode never pushes). What an auto-sync gym gives up with
  it (review R1-F7): `report_daily_sync`, and — only on a day whose 22:00 answer carried a members or
  devices section, since `_request_running_ultra_sync` returns early without one — one explicit
  `full_reconcile` pass (the roster-hash skip bypassed, MIRROR's reconcile — no gym runs MIRROR, §3.2c).
  The dashboard shows a banner only on a report with `lastDailySyncOk === false`, so no report shows
  none; a failure reported before the gate stays shown until someone dismisses it. Offline in safety
  mode (`UNREACHABLE` keeps `ON`) the job is skipped as well — its sync would have failed anyway. `[CODE: dashboard layouts/dashboard/layout.tsx::refreshPendingSync; backend
  GymAccessController.reportGymAccessDailySync]` `[TEST: test_v2_safety_sync.py — the daily-job tests]`
- An old server, a switch off, a PC not yet `ON` (power-on) or offline from start: both run as before.

**The missing-member check (lane B, 2026-09-26).** A member the server lists and this PC lacks now asks an
immediate full member refresh. Before, the only detector was the member-cache self-heal
(`sync_scope.member_cache_is_stale`, kept): it fires below 50 % of the token's member count, so a PC missing a
handful — a row lost to a stale fast-patch delete (the 2026-09-06 shape), an entrant the server counts as
delivered but never sent (the collision `GymAccessController`'s javadoc describes) — stayed so until an
unrelated change moved the token: a delta's `validMemberIds` never re-sends a member, and nothing compared
them with the PC's rows. `[TEST: scratch probe on aeeef69 — after a delta naming member 7 the next request
still carried both member tokens and 7 stayed missing]` Now, after each successful sync (after the save, its
date flip and the tokens), `MainApp._check_missing_members` compares the server's set with the PC's —
`sync_users` + `sync_users_held` (`db.list_local_member_ids`: a held member is still in the server's list):
- **a members section applied with a valid authority** → its validated ids
  (`save_sync_cache_delta`'s `authoritative_member_ids`: a delta's `validMemberIds`, a full answer's
  `users[]`). A gap after a FULL section is a row this PC could not store: another full refresh cannot fix
  it, so it is reported once and remembered (`_missing_member_action`, in memory) — never refreshed for again
  while it stays missing; a member that arrives or leaves the server's list is forgotten. A refused section
  (H-006, a malformed authority) is skipped: its refusal already drops the member tokens (§3.4).
- **no members section, protocol-2 windows trusted** → `member_access_window` (`db.list_member_window_ids`):
  the server's set of the day, replaced whole by every members section; a fast patch drops its membership's
  window (`_forget_protocol2_membership`) and a hold keeps the row in `sync_users_held`, so neither reads as
  missing; a promoted starter is an extra row, never missing.
- **no members section, not trusted, a P1a token** → the token's last component, the id-set digest
  (`sync_scope.token_id_set_digest`: 16 lowercase hex characters after the LAST colon — the timestamps hold
  colons), against the digest of the local set (`member_id_set_digest`: ids sorted numerically, distinct,
  joined by `,`, SHA-256, first 8 bytes hex — pinned against vectors the backend's own Java produced). A
  digest cannot tell a missing member from an extra row, so a mismatch asks ONE delta answer per token value
  (`probeMemberSet`: `membersVersion` dropped, `membersUpdatedAfter` kept — the backend then serves a delta
  whose `validMemberIds` is exactly the list its digest hashes `[CODE: backend main GymAccessController,
  read not run]`), and the first rule decides on it. The probe counts as asked for that token only
  once a sync that CARRIED it has completed (review R1-F4): a pending request can be replaced by a later
  automatic one before it runs.
A missing member → `request_sync_now(trigger_source="MISSING_MEMBERS", trigger_hint={forceMemberRefresh})`,
posted to the loop; `sync_scope.apply_trigger_hint_to_version_tokens` drops both member tokens for it, so the
next `getSyncData` serves the full list. `[T] MEMBERS_MISSING source action count sample`. `[CODE]`
**Removal safety.** The check only reads: it deletes no row and names no revocation. The refresh it asks for is
the ordinary full member refresh (hard reset and the self-heal use the same one), with its H-006 empty-roster
refusal, its per-row diff and the previous-day guards of §3.8; the probe is an ordinary delta. What either
removes, the next member change would have removed through the same authority — only sooner. It is
automatic, so in manual sync mode the refreshed members reach the turnstiles with the admin's next "Sync data",
as every automatic sync. Side effects accepted (review R1-F9/F10): the local API already accepted
`forceMemberRefresh` in a `POST /api/v2/sync/now` body (`local_access_api_v2.py::_sync_trigger_hint_from_body`
lists it) and nothing read it; it now forces a full member refresh — nothing in the Tauri UI, the dashboard
or the backend sends it (grep, 2026-09-27); `probeMemberSet` is not accepted there. And a fast-patch delete
landing between the check's two reads can cost one needless full refresh. `[TEST: test_missing_member_check.py — the digest vectors, the token parsing, both
hints, the decision and its suppression, and on the §3.6 harness with a real temp database: a delta naming a
member the PC lacks, a held member, a matching and a disagreeing digest, the probe once per token, the
protocol-2 windows, a promoted starter and a held member after a midnight flip (nothing asked, nothing moved),
and that the check deletes nothing]` Cost: one indexed union read of two local tables per sync, plus the
window read or a SHA-256 over the id list (~1,860 ids) when no members section came; on the server, only the
refresh or probe a mismatch asks.

**Date flips (P3b-1).** `work()` runs the date precheck before the fetch and a date flip after
each save; a separate 60 s timer (`_date_flip_tick`) and a 00:00:05 one-shot run the same check
on their own. None of them touches `_sync_after_id` or the retry schedule, and a flip never
requests a backend sync (only the one 00:17 first-day sync does). See §3.8 "When the flip runs".

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

### 3.8 Sync protocol 2 on the PC — validity windows, power-on date flips, the clock (P3b-1, 2026-09-19)

**Why.** Most gyms cut the PC and the electricity overnight (§3.4a), and a `ZK_STANDALONE` turnstile
decides alone. Before P3b-1 nothing on the PC ever removed a member whose plan ended while the PC
was offline or off: the member list is the server's answer of the last sync, and the default
device roster has **no date filter**. `[CODE: device_sync.py::_filter_users_for_device]` It used to
compare `validFrom/validTo` under `pushingToDevicePolicy == "VALID_ONLY"`, a value no backend version
has ever sent: the backend enum `AccessSoftwareInDeviceDataModePushingPolicy` never had it (`git log -S
VALID_ONLY` over the backend and dashboard histories finds only comments), so the filter never ran; lane B
removed it (2026-09-26). `[TEST: test_pin_scheme_gate.py::test_no_pushing_policy_filters_by_date — its
two VALID_ONLY cases fail on aeeef69, every real enum value passes on both;
::test_membership_scheme_is_byte_identical_to_the_pre_account_derivation no longer draws VALID_ONLY, the
one input whose oracle branch is now unreachable — a deliberate change]`
Sync protocol 2 sends each membership's days so the PC can apply them itself.

**The contract** (backend `main` `2b75ddb3`, read-only here: `ActiveMemberResponseV2`,
`ActiveMemberUserV2Dto`, `AccessWindowDto`, `AccessSyncMetaDto`, `UpcomingGymAccessCredentialDto`,
`AccessDeliverability`, `GymAccessController.getGymAccessUsers`). The PC always sends `protocol=2`
and its stored `windowsVersion`; the server answers v2 only while `monclub.access.v2.enabled` is on
(env `MONCLUB_ACCESS_V2_ENABLED`), otherwise plain v1 — an old server ignores the parameter. A v2
answer adds `syncMeta` (server `today`, `horizonEnd` = today + 7, `serverTime` with the Tunis
offset), `currentWindowsVersion`, a window on every `users[]` row plus `memberWindows` for today's
rows not sent (together exactly today's set), and — in every full section, and in a delta only when
it changed — `upcoming[]` (memberships deliverable on some day up to `horizonEnd` but not today)
with `upcomingIds` and `upcomingCredentials` (existing QR credentials of upcoming-only accounts,
sent `enabled=false`). A day D is deliverable when `accessFrom <= D <= accessUntil` and D is not in
`offDays`. `[CODE: backend]` `[TEST: local e2e on a scratch copy of wigo-demo, 2026-09-19 — the
answers for gym 59 and gym 58 (1,602 rows, 11 upcoming, 2.5 s) had exactly these fields]`

**Pure logic** — `app/core/access_dates.py` (no clock, no database): `parse_v2_payload` validates
the v2 part WHOLE (a malformed `syncMeta`, a malformed `memberWindows` entry, `upcoming` without a
matching `upcomingIds`… rejects it; a `users[]` row without a usable window is kept as
*windowless*); `window_status` (`ok` / `grace` / `expired` / `not_started` / `frozen`);
`evaluate_gym_date` and `clock_at_sync` (below); `plan_flip`; `qr_date_verdict`;
`effective_credentials`. `[TEST: tests/test_access_dates.py]` The 32-bit Python the gyms run has
no `tzdata`, so `zoneinfo.ZoneInfo('Africa/Tunis')` raises; the Tunis offset is taken from
`syncMeta.serverTime`. `[measured 2026-09-19 on the .venv]`

**Storage** (`db.py::_create_protocol2_tables`, one `init_db` transaction):

| Table | Holds |
|---|---|
| `access_v2_state` (one row) | the last `syncMeta`, `trusted`, the clock (`server_epoch`, `utc_offset_sec`, `skew_sec`, `floor_date`, `max_pc_epoch`, `clock_suspect`, `clock_reason`), `applied_date`, `grace_days`. NOT cleared by `clear_version_tokens` |
| `member_access_window` | the window of every membership of today's set; replaced whole by each members section |
| `sync_upcoming_users`, `sync_upcoming_credentials` | `upcoming[]` / `upcomingCredentials` exactly as last sent (the row's JSON; credentials stored disabled) |
| `sync_users_held` | rows of today's set taken off the roster for a later gym date; the same 20 columns as `sync_users` (`_SYNC_USER_COLUMNS`) + reason/date |
| `member_person_link` | membership → `userId` (+ `mainAccountId`), never deleted; written with `member_account_link` by every `sync_users` writer (no `mainAccountId` filter), back-filled at `init_db` — used by §3.4f |

`windowsVersion` lives in `sync_version_tokens` (so logout and hard reset drop it and the request
sends it back) but is written or deleted only inside the save transaction.
`[TEST: tests/test_protocol2_foundation.py]`

**The save** (`db.py::_apply_protocol2_save`, called inside `save_sync_cache_delta`'s single
`BEGIN IMMEDIATE` transaction after all v1 sections, and inside `save_sync_cache`'s transaction —
the enrolment fallback's tokenless sync is answered v2 too). A failure there rolls the whole save
back: the windows, the upcoming lists and the token never part from the rows they describe.
`[TEST: tests/test_protocol2_save_and_flip.py::test_a_failure_inside_the_v2_step_rolls_back_the_whole_save]`

| Answer | Effect |
|---|---|
| v1 (no `syncMeta`) or a malformed v2 part | `trusted=0`, `windowsVersion` deleted, lists kept but unused; the next flip puts every held row back (a v1 PC's roster is the server's last list); `[T] SYNC_V2_REJECTED reason` for a malformed one |
| v2, members section applied with a valid authority (delta: `validMemberIds` present, valid, not H-006-refused; full: not refused) | state + clock stored, `floor_date` reset to the server's day, windows replaced, upcoming lists replaced when sent, token stored, `trusted=1` |
| v2, members section present but not applied | `trusted=0`, token dropped (the refusal already clears the member tokens, §3.4) |
| v2, members section skipped | lists and trust kept (the server skips it only when the PC's `windowsVersion` is current) |

**Held rows at a save** (`_reconcile_held_rows`, any protocol, only when the members section was
applied with a valid authority): a delta restores, column for column, every held row still in
`validMemberIds`, not in `users[]` and not already back on `sync_users` — the server counts it as
delivered and will never resend it — and drops the rest; a full section drops them all. The flip
that follows the save holds again whatever its date says. `delete_users_by_am_ids` also deletes
the held copy, or the next flip would restore a revoked member. **A fast patch of a membership**
(`ACTIVE_MEMBERSHIP` `ENTITY_UPSERT` or `ENTITY_DELETE`) is newer than its stored protocol-2 data —
the backend sends an upsert only for a membership deliverable today
(`AccessPatchBundleService.shouldExposeMembership`) — so `_forget_protocol2_membership` drops that
membership's stored window, upcoming row and held copy, and `windowsVersion` when a stored list
changed (the next sync then serves the members section), and the local-state generation moves. The
first version kept them: the flip held a pre-sale the desk moved to today, a same-id end-date change
the next morning offline, and a freeze cancelled at the desk, and re-promoted a deleted pre-sale
(review round 1). `[TEST: tests/test_p3b1_review_r1.py — the fast-patch tests]` H-006's empty-roster guards count held rows (they are still in the
server's list), and so does the member-cache self-heal (`count_member_cache_rows`).
`[TEST: tests/test_protocol2_save_and_flip.py — the held-row, H-006 and fast-patch tests]`

**The flip** — `db.py::apply_local_date_flips(pc_now_epoch, grace_days, source)`: ONE write job,
idempotent, recomputed from the stored state. It evaluates the gym date (below), persists the clock
verdict and `applied_date`. With `trusted=0` it moves nothing by date and puts every held row back
into `sync_users` (a held id already back — a fast patch — keeps that fresher row): untrusted means
a v1 PC's behaviour, whose roster is the server's last list. The first version returned before
that, so a trust drop (a v1 or malformed answer, a refused members section) left members held
while trusted — e.g. a one-day freeze — locked out offline until the next online first-of-day sync,
which base never did (review round 5). `[TEST: tests/test_p3b1_review_r5.py]` Only with `trusted=1`
does it run `access_dates.plan_flip`:

- a `sync_users` row whose window is not deliverable on the gym date → **held** (column-for-column
  copy into `sync_users_held`, then deleted from `sync_users`);
- a held row deliverable again (a freeze day passed) → **restored**; a held row with no window stays
  held (nothing proves it may come back);
- an upcoming row deliverable on the day, not on the roster nor held → **promoted** (its row replayed
  through `_upsert_sync_user_row`, and its `member_shadow` row written in the same job); the stored
  upcoming list is never changed;
- a row with no window (one a fast patch wrote — the patch drops its stored window — or a v1
  period) is never moved.

Because the rows really leave `sync_users`, every reader — the device roster, the targeted member
sync, the ACCOUNT collapse, `load_local_state` (cards and QR), the Access UI members list — sees the
day's roster with no reader-side filter. `member_shadow` is NOT touched for held rows: the server's
own revocation still arrives with the next sync and finds the pin already gone (the known false
`SKIPPED_NOT_OWNED` of §7 R3-15). A **promotion** does write the promoted row's `member_shadow` row
(`_upsert_member_shadow_row`, the same write the sync uses; the row is server data from
`upcoming[]`): a pre-sale promoted offline and dropped by the next sync (cancelled or re-dated
meanwhile) is then a normal revocation. Without it that sync produced no revoked id and the
turnstile kept the pin until an unrelated full pass (review round 3).
`[TEST: tests/test_p3b1_review_r3.py::test_a_promoted_pre_sale_the_next_sync_drops_is_revoked]`
Both shadow diffs (`apply_member_shadow_delta`, `diff_member_shadow`) now call a shadow row missing
from the server's valid ids a revocation only when the membership also left `sync_users`
(`_on_roster_ids`) — always true before P3b-1 at that point, since the save runs first. An answer
still carrying the previous server day, saved just after the midnight flip, otherwise revoked the
starter the flip after the save had put back (review round 4). The H-006 decision is taken before
that filter, unchanged. `[TEST: tests/test_p3b1_review_r4.py — the previous-day answer tests]` The flip bumps the local-state generation when rows move, and also
when the applied day moves while trusted, and expires the sync cache when rows move.
`[CODE: db.py::apply_local_date_flips]` `[TEST: tests/test_protocol2_save_and_flip.py,
tests/test_p3b1_integration_fixes.py]`

Beyond `horizonEnd` the server promises `accessFrom`/`accessUntil` but no off days; a membership
flagged `offDaysBeyondHorizon` is **kept inside its window** there (the end date still applies).
This is a PC policy — the server states no default — and an **owner decision**; memberships
starting or unfreezing after `horizonEnd` are in no list and wait for a sync.
`[CODE: access_dates.py::window_status]` **Offline grace** (`offline_revoke_grace_days`, Access
config, default 0; capped at `access_dates.GRACE_DAYS_MAX` = 36500 days by the config normaliser,
the flip and the config page, and compared as a day count — a date sum overflowed past ~2.9 million
days (review round 2) and the SQLite write past 2**63-1 (review round 3)): on a day AFTER the last server day only, a membership past its `accessUntil`
stays that many days (never a freeze day or a future start). `[TEST: ::TestWindows]`

**The gym date and the clock** (`access_dates.evaluate_gym_date`). P = the PC's date in Tunis time
(PC epoch + the offset from `serverTime`); S = the last server day; A = `floor_date`, the highest
day applied since the last v2 sync (reset to S by every v2 save).

- **Never earlier than S or A**: a clock that falls back (a flat CMOS battery, a wrong manual
  change) re-admits no one.
- **CLOCK_SUSPECT** when the PC clock reads more than 300 s behind the latest trustworthy time it has
  seen (the last `serverTime`, or the highest PC time seen since — policy tolerance
  `CLOCK_BEHIND_TOLERANCE_SEC`), or when it was more than a day ahead of the server at the last sync
  (`clock_at_sync`, skew = PC − server). A suspect clock applies exactly max(S, A): dates advance only
  as far as already known. Otherwise the day is max(P, S, A).
- A clock ahead by less than a day is NOT suspect: it flips up to that many hours early (task rule).
- **Owner decision — a clock set forward by mistake while offline.** Offline, a forward jump cannot be
  told from a long closure (the skew is measured only at a sync), so it is applied: e.g. a flat
  battery, then a hand-set date with day and month swapped (10/09 → 9 October), holds everyone whose
  plan ends before that date. Setting the right date then reads as a clock falling back (behind the
  highest time seen) → `CLOCK_SUSPECT`, and the day stays at the wrong, later floor until the next
  successful protocol-2 sync resets it; the « Horloge du PC suspecte » pill appears only after the
  correction. The alternative — trust a clock that falls back to a moment after the last sync —
  would undo this, but also let a clock set back by mistake re-admit members whose plan ended in
  between. Current behaviour is the fail-closed one. `[TEST: review round 1 reproduction, not in the
  repo; both verifiers confirmed it]`

`[TEST: tests/test_access_dates.py::TestGymDate;
tests/test_protocol2_save_and_flip.py::test_a_flat_battery_after_a_day_was_applied_neither_rewinds_nor_restores]`
The verdict is on `/api/v2/status` (`session.clockSuspectWarning`, `clockSuspectReason`, `gymDate`,
`accessDatesTrusted`) and the Access UI shows an amber « Horloge du PC suspecte » pill; the log
gets `[T] CLOCK_SUSPECT` / `[T] CLOCK_OK` when the verdict changes (§10.2b).
`[TEST: tests/test_p3b1_setting_and_status.py]` The heartbeat payload carries nothing new for this (P3b-2 later added `clockOffset`, §3.9): the
backend's `HeartbeatRequest` has no field for it (§3.1b), and a parallel branch edits
`build_heartbeat_payload`.

**When the flip runs** (`app.py`, `MainApp._apply_date_flips` and its triggers). Every trigger
goes through `_apply_date_flips(source)`, serialised by `_date_flip_lock` and never raising (a
failure logs `[T] DATE_FLIP_FAILED` and returns None). A failure may still commit later —
`_run_db_write_sync` stops waiting after 60 s but the job stays queued — so it sets
`_date_flip_recover`: the next trigger runs a flip whatever the precheck says (it queues behind the
late one) and, even when that run moves nothing, bumps the generation and wakes the caches and
ULTRA as if it had (review round 5). `[TEST: tests/test_p3b1_review_r5.py]`

| Trigger (`source`) | How |
|---|---|
| start-up (`startup`) | synchronously in `MainApp.__init__`, after the engines are constructed and before `after(250, _sync_tick)` is even scheduled. Every ULTRA / AGENT / DEVICE worker is started from a sync tick's `work()`, so none starts before it. `[TEST: tests/test_p3b1_app_wiring.py::test_init_applies_the_startup_flip_before_the_first_sync_tick]` |
| every 60 s (`tick`) | `_date_flip_tick` on the loop thread runs the read-only precheck `db.gym_date_status`; only when it says `needs_flip` does a daemon thread run the flip — never two such threads. Catches sleep/hibernate, a clock change, a missed one-shot |
| 00:00:05 gym time (`midnight`) | a one-shot (`_arm_midnight_date_flip`, armed at start-up or by the first tick once the gym offset is known), precheck + flip on a daemon thread, re-armed for the next day |
| every sync (`sync-tick`, `save`) | `work()` runs the precheck **before** the fetch (so an offline tick still applies a new day) and a flip after **each** `save_sync_cache_delta` (the main one and the forced member follow-up) |
| enrolment fallback (`save`) | after its tokenless `save_sync_cache` |
| fast patch (`fast-patch`) | after a non-duplicate `db.apply_fast_patch_bundle`, before anything is dispatched — an upsert can put a held membership back on `sync_users` |
| heartbeat (`heartbeat`) | `pc_identity.py::_heartbeat_payload_after_date_check` runs the precheck (and a flip if needed) before building each payload; a failure there never costs the heartbeat |

A flip that moved rows drops the cached sync snapshot (`invalidate_sync_cache(clear_cached=True)`),
resets the AGENT and ULTRA fast-patch caches (in every mode — the PC's own decisions move) and,
unless manual sync mode is on (§3.6, the turnstiles change only when the admin syncs), asks a
*running* ULTRA engine for a full pass (`request_sync_now(changed_ids=None, reason="date-flip")`,
removals first per §3.4b). Dropping, not just expiring, the snapshot matters: `load_sync_cache`
serves an expired snapshot while its reload runs, and the full pass pushed the pre-flip roster when
it drained inside that window (review round 1). The cache still loads ONE at a time (as in base);
every `invalidate_sync_cache` bumps an epoch that each load carries: a load that finishes at the
current epoch is installed fresh; one that finishes after a plain invalidation is installed expired
(newer than what it replaces) and one follow-up load starts; one that started before a clearing
invalidation (the flip's) is never installed, and readers wait for the follow-up — nothing blocks
the flip's own thread. The first version released the in-flight marker on every invalidation, which
started one concurrent full load per invalidation during a burst (review round 3: 20 loads, 4 at
once over 3 s, against 5 and 1 in base). `[TEST: tests/test_p3b1_review_r3.py — the sync-cache
tests]` It never asks the
backend for a sync, so a flip cannot start a sync loop. The precheck (`db.gym_date_status`) also
reports the offline grace the last flip applied, and the app flips when the configured value differs
(`_date_flip_needed`) — a config PATCH writes `self.cfg` only, so a grace change used to wait for the
next day. `[TEST: tests/test_p3b1_app_wiring.py, tests/test_p3b1_review_r1.py]`

**The first-day sync at 00:17.** A new membership's QR credential is enabled by the server's 00:16
job (backend `DailyScheduleService`, cron `0 16 0 * * *`); until then the PC holds it disabled
(`upcomingCredentials`). When a flip reports `starters` (upcoming memberships starting on the
applied day) before 00:17:00 gym time, it arms ONE `request_sync_now(trigger_source="DATE_FLIP",
trigger_hint={"reason": "first-day-credentials"})` at 00:17:00 on the server's clock — the PC time
plus the PC-ahead skew measured at the last sync (a PC two minutes fast fired it before the 00:16
job and brought nothing, review round 2); a later flip replaces it, so there are never two. From 00:17 on nothing is armed: the next ordinary sync brings the credential. The
hint strips no version token (`sync_scope.apply_trigger_hint_to_version_tokens` acts only on
`entityType` / `forceDeviceRefresh`). `[TEST: tests/test_p3b1_app_wiring.py — the 00:17 tests]`
Why it is needed although the PC enables a stored upcoming credential itself on its first day
(`access_dates.effective_credentials`): a sync between 00:00 and 00:16 already answers with the
new day, so the starter is in today's set, no longer in `upcomingCredentials`, and its credential
is still disabled on the server — its QR is refused until a sync after 00:16. Without network at
00:17 it waits for the next successful sync; the card and the fingerprint are not affected (the
row itself was promoted). `[CODE: access_dates.py::effective_credentials; plan §9]`
`[TEST: local e2e 2026-09-19 — "a new member's QR came back disabled from the sync before the
00:16 job and opened after it"]`

**QR codes** — see §3.1b "Allowed days". **Renewals** on MEMBERSHIP-pin turnstiles — see §3.4f.

**End to end** (2026-09-19, backend `main` `2b75ddb3` on port 5091 with
`MONCLUB_ACCESS_V2_ENABLED=true`, a scratch copy of `wigo-demo`, gym 59, the branch's real save/flip/QR
code and the suite's fake MB2000 fed with the synced rows; the backend clock cannot be moved, so
"the server date moved" was emulated by moving the scenario's dates one day earlier): an evening
sync, then a power-on at D+1 07:30 with no network held the expired member, the freeze-day member
and a renewing member's old plan, promoted the pre-sold starter, the freeze-ended member and the
renewal; their QR codes and cards followed; on the fake MB2000 the two leavers were removed before
any write and the renewing member's new pin was written before the old one was removed; a
flat-battery clock (2000-01-01) re-admitted no one; the next morning's server list matched what the
PC had applied offline; a new member's QR came back disabled from the sync before the "00:16 job"
and opened after it; a cancelled pre-sale left the upcoming list; a v1 answer dropped trust; a clock
two days ahead was CLOCK_SUSPECT and held the server day. `[TEST: e2e harness kept out of the repo,
the report lists every check]` Re-run on the branch with the app wiring (HEAD `e667396`): the
real `MonClubApi` sent `protocol=2` and its `windowsVersion` itself and stamped
`_clientReceivedAtEpoch`; every flip went through `MainApp._apply_date_flips` (a `MainApp` built
without `__init__`, a recording ULTRA engine); the midnight path (`_maybe_apply_date_flips` at
00:00:05 D+1) logged one `DATE_FLIP source=midnight` (held 3, promoted 3), asked ULTRA once and
armed ONE 00:17 sync (16 min 55 s), re-armed to 12 min by a 00:05 flip; the 07:30 power-on armed
none; the flat battery logged `CLOCK_SUSPECT reason=behind` and the fix `CLOCK_OK`. 58 checks, 0
failed. `[TEST: same harness, 2026-09-19]` Re-run on the final branch head `5094150` after six
review rounds (2026-09-26): 58 checks, 0 failed. `[TEST: same harness]`

### 3.9 Driver leases, remote commands, the notice socket (P3b-2, 2026-09-26)

**The contract** is backend `main` `c7d4b532` (read-only here; plans `docs/plans/2026-09-18-p2b-realtime-commands.md`,
`2026-09-19-p2c1-leases-assignment.md`, `2026-09-26-p2c2-ownership-reports.md`): PC routes under
`/api/v1/public/access/v2/pc/**` with the v1 PC token (`/public/access/v1/pc/token`). Everything is in
`app/core/v2/` and is **dormant** unless the server answers those routes. `[CODE]`

**Dormant on an old server — the one rule.** With `monclub.access.v2.commands.enabled` off every v2 PC route
answers the backend's unmapped-route 404, `{"status":false,"code":"NOT_FOUND",...}`. Only that answer (a 404
whose body is the backend envelope with `code == "NOT_FOUND"`, `api.py::V2ApiError.switched_off`) means
"switched off": the runtime goes `OFF`, the cached roles are deleted, every turnstile is allowed (exactly the
pre-P3b-2 behaviour), no socket is opened, nothing is polled or uploaded, and the assignment is re-probed every
30 min. A proxy's HTML 404, a 5xx, a TLS/network error or no PC token is `UNREACHABLE`: whatever was known is
kept (re-probed after 2 min, doubling to 30 min). Reading those as "off" would turn a reader into a driver of
every turnstile. `[CODE: api.py, leases.py::LeaseManager.refresh, runtime.py::V2Runtime.tick]`
`[TEST: test_v2_clock_and_api.py::test_a_backend_404_not_found_is_the_switch_being_off,
::test_anything_else_is_never_read_as_switched_off; test_v2_runtime.py::test_an_old_server_keeps_everything_dormant;
test_v2_review0.py::test_unreachable_probes_back_off_to_half_an_hour]`
`[TEST: e2e 2026-09-26, local backend c7d4b532 with the commands switch off (the dates switch on): every v2
route and the socket handshake answered 404 NOT_FOUND; a cached reader went back to every turnstile — 5/5 checks]`
Production (`origin/main` `fcfc850c`) maps an unmapped route to the same envelope
(`GlobalExceptionHandler` `NoResourceFoundException` → `NOT_FOUND`) `[CODE, read, not run against production]`.

**The server clock (owner decision 5a).** `server_clock.py::ServerClock`: a sample is `serverTime −
midpoint(send, receive)`, a round trip over 5 s is no sample, the offset is the median of the last 7; sources:
the socket `welcome`, every REST `serverTime` (Tunis local — placed with the gym offset learnt from `welcome`
or `access_v2_state.utc_offset_sec`), and a 409 `CLOCK_SKEW`'s `details.serverTime` — or, while no gym offset is known (no `welcome` yet: e.g. a
proxy that does not pass WebSockets), its `details.skewSeconds` (server now − our `sentAt`, offset-free); any
backend error's `details.timestamp` that carries an offset also teaches the gym offset (review R4). `now()` = PC time +
offset and never lower than the last value it returned in this process (it slews at 10 % of real time until
the estimate catches up). **One deliberate exception:** a `CLOCK_SKEW` refusal restarts the sample window and
drops that floor — the server refused every write stamped with the wrong estimate (> 5 min off), so nothing it
stored can be out of order, while keeping the floor kept every retry refused (found in the end-to-end run). The
offset is persisted (`v2_kv` `server_clock`) and reused after a restart only while younger than 12 h. Every
`sentAt` is stamped per attempt from `now()`; every `observedAt`/`wipedAt` in the same body is capped at that
attempt's `sentAt` and the capped value is what the ownership upload records (P2c-2's "write the clamped time
back"). The heartbeat gains `clockOffset {offsetSec, samples, source}` (server − PC, s) once measured; backend
`c7d4b532`'s `HeartbeatRequest` has no such field and Jackson's default drops it (§3.1b) `[UNVERIFIED by a live
request]`. Since lane 1 (2026-09-27, backend contract `docs/plans/2026-09-27-ownership-last-push-contract.md` §5.1 on
branch `claude/v2-last-push-and-clock`) it also carries `ageSec`. **The block is a heartbeat-only VIEW over the
samples taken in the last 30 minutes on the PC's own clock** (`RECENT_SEC`, inclusive; master correction 3,
2026-09-27, before contract revision 4): `offsetSec` = their median, `samples` = their count, `ageSec` = the age
of the OLDEST of them. Why: with the socket up the guaranteed samples are the 600 s assignment refreshes, so the
window of 7 spanned about an hour and its oldest sample never met the dashboard's freshness rule (measured ≥ last
seen − 30 min). No sample in the last 30 minutes: the window's own median as `offsetSec`, `samples` **0** (it
always counts the view, contract revision 4.1 §5.1) and **no** `ageSec`. The
window of 7 that drives `offset()` (every `sentAt` / `observedAt`) is untouched. Each recent sample is kept, and
persisted (`recent` in the `server_clock` kv row), with its own time, so after a restart a remembered offset counts
its age from the original measurement; a row persisted before this change has no `recent`, so `ageSec` is left
out. An authoritative `CLOCK_SKEW` sample restarts both the window and the view. A sample of this process also keeps
the monotonic time it was taken: its age is measured on that clock, and once the PC's wall clock has been stepped
since — wall minus monotonic moved by more than `STEP_TOLERANCE_SEC` (2 s), either way — it leaves the view for good,
whether or not a sample lands before the clock catches up (review rounds 3-4; the window of 7 keeps it, as before).
A sample loaded from disk is pinned to the new process's monotonic clock at load (its age then = wall now minus
its time), so a step after the restart retires it too; one stamped later than now is dropped at load; a step
between the save and the restart is not detected (review round 5). `[CODE: server_clock.py::report, ::_recent_locked, ::_age_of]`
`[TEST: test_v2_last_push.py — the clock tests, incl. ::test_one_sample_every_ten_minutes_keeps_the_age_within_30_minutes,
::test_no_sample_in_the_last_30_minutes_sends_no_age, ::test_a_pre_step_sample_leaves_the_view_even_with_no_sample_before_the_catch_up,
::test_a_forward_step_also_retires_the_samples_before_it, ::test_a_loaded_sample_is_retired_by_a_step_after_the_restart; test_v2_runtime.py::test_the_heartbeat_carries_the_measured_offset_only_once_measured]` `[CODE: server_clock.py, api.py::_cap_fact_times, access/pc_identity.py::_clock_offset_report]`
`[TEST: test_v2_clock_and_api.py — incl. ::test_a_clock_skew_refusal_outvotes_earlier_wrong_samples,
::test_fact_times_are_capped_at_the_sent_at_of_each_attempt; test_v2_runtime.py::test_the_heartbeat_carries_the_measured_offset_only_once_measured]`
Parsing is lenient (`timefmt.py`): the socket sends 0–3 fraction digits with an offset, REST `LocalDateTime`s
0–6 digits without one, `CLOCK_SKEW` may drop the seconds; the PC always sends UTC `…Z` with microseconds.

**Transport.** `ws_client.py` is a standard-library RFC 6455 client (no WebSocket package is installed in the
32-bit build; no new dependency): TLS with certifi + SNI, system proxies (`urllib.request.getproxies()`:
environment and the Windows Internet Settings registry; `proxy_bypass` honoured) through `CONNECT`, **no
`Origin` header** (the backend answers any with 403), auto-pong (also between fragments), close handshake, a
refused handshake's JSON `code` and `Retry-After` read from a Content-Length, **chunked** (Tomcat's own error
answers) or close-delimited body. `notice.py::NoticeLoop` (thread `v2-notice`): `welcome` → a clock sample, a
pending-command poll, a sync 0–5 s later and a roles refresh; `changed` → one sync 1–10 s later, at most one
notice-driven sync a minute (`assignment` scope → a roles refresh only); `rollover` → a sync within
`spreadSec`; `command` → the executor; every numbered notice acked. A socket silent for `readIdle + 15` s is
dropped as half-open; a wall-clock jump of more than 30 s against the monotonic clock (sleep/resume) rebuilds
it; after a session a random 0–60 s wait, repeated handshake failures back off to 15 min, `Retry-After`
wins; close 4001 → a new token (`PcIdentityService.invalidate_token`), 4003 → 30 min, 4009 → 5 min. While the
socket is down pending commands are polled every `pollIntervalSec` (120 s) — and, on a trusted v2 PC, the
data sync runs every 120 s too, and at least every `reconcileSec` while it is up; the 45 s members-version
probe and (outside manual sync mode) the 22:00 job are then off (§3.6 "The v2 safety sync", lane B
2026-09-26). No notice handler touches a device,
a DB write job or an engine lock; syncs go through `app.after(0, request_sync_now)`. `[CODE]`
`[TEST: test_v2_ws_client.py, test_v2_notice_and_leases.py, test_v2_runtime.py]`
`[TEST: e2e — the handshake with the real Tomcat backend answered 101 + welcome in 41–134 ms; a bad token was
refused 401 before any 101]` `[UNVERIFIED — FIELD-TEST]` `wss://` through the production nginx: from a gym PC,
one handshake must answer 101, or a JSON refusal (401/404) — never an nginx page.

**Driver leases (owner decisions 1, 4).** `lease_gate.py` is ONE immutable snapshot read lock-free by every
site that connects to a turnstile: mode `ALL` (no lease information, v2 off, or `gymUsesAssignments=false`)
allows everything as before; mode `LEASED` allows only `drive[]` entries in state `DRIVE` plus `release[]`
entries (the outgoing PC keeps serving the door until its release is acknowledged; the incoming PC does not
connect while `WAIT_FOR_RELEASE`). A reader is allowed nothing. The filter sits at: the ULTRA device list
(`app.py::ultra_devices_for_this_pc`), `UltraEngine.start`/`refresh_devices`, the worker's `_connect` (last
line of defence), `AgentRealtimeEngine.refresh_devices`, `DeviceSyncEngine._sync_all_devices`,
`_run_single_device_sync` (the ULTRA scheduler's PullSDK fallback) and `_sync_one_device`,
`DeviceAttendanceMaintenanceEngine._list_device_candidates`, the local API's device-session handlers
(`access/local_api_routes.py::LEASE_GATED_HANDLERS` → 409 `notDriver`), the desk card scanner
(`SCANNER_GATED_HANDLERS`: a scanner set on the address of a turnstile this PC does not drive → 409; `mode`
and `ip` read with the handlers' own expression, so `"USB"` or an empty `mode` — a network scan in
`card_scanner` — cannot pass, review round 5) and the
network discovery (those addresses are skipped). `[CODE]`
`[TEST: test_v2_lease_gate.py — every driver constructor made to raise under a READER snapshot while each site
runs; test_v2_review0.py — the scanner and discovery]`
The roles are fetched at start, on an `assignment` notice and every 10 min, and cached in `v2_kv`
(`assignment_cache`, tied to the installation's `pcUuid`); `MainApp.__init__` installs the cache
synchronously **before the first sync tick** (`runtime.py::load_cached_roles`), so a reader stays a reader at a
power-on without internet (owner decision 8). A roles change asks for a sync (`LEASE_CHANGE`), whose `work()`
starts/stops the workers; until then a worker for a turnstile this PC no longer drives writes nothing
(`ultra_engine.py::_v2_writes_blocked` gates the member drain, the full-sync drain and the maintenance slot;
DeviceSync skips the device) and does not reconnect. A pass already running re-reads the gate before it
writes: the MB2000 push (`_push_with_chunk_recording`: nothing sent, every pin "superseded", no roster hash
stamped), between two push chunks (`_standalone_push_yield` drops the rest), the member push, and
`_sync_one_device` before its batch push; a removal refused as `not_leased` is a deferral like `add_only`,
never a ceiling abort. `[CODE]` `[TEST: test_v2_review0.py::test_a_lost_lease_stops_every_write_at_once,
test_v2_review1.py::test_r11_*, test_v2_runtime.py::test_a_reader_is_a_reader_at_a_cold_start_before_any_worker]`
A PC the server calls `ACCESS_PC_REVOKED`/`ACCESS_PC_ADOPTED`, or whose identity is `revoked` /
`invalid_credentials` / `invalid_token` (no token can be minted), drives nothing any more when its gym uses
leases (role `REVOKED`, cached too, so a cold start keeps it); in a gym without leases nothing changes; a PC
merely offline keeps its cached roles. `[CODE: leases.py::LeaseManager._revoked, ::_drop_leases]`
`[TEST: test_v2_review1.py::test_r2_*]` Residual `[CODE]`: a PC that is revoked or loses its lease while it is
**off** acts on its cached roles at the next power-on until the server answers (usually the first minute
online); offline it has no way to learn it. An AGENT-mode worker (`realtime_agent.py::DeviceWorker.run`) re-reads the
gate at every loop turn (one lock-free snapshot read): when the lease or the release it was finishing ends it
drops its session at that turn and does not poll again, instead of holding it until the next sync tick
(review round 5). `[CODE]` `[TEST: test_v2_review1.py::test_round5_an_agent_worker_drops_its_session_once_the_lease_ends]`
`[UNVERIFIED]` Not a hard "never two sessions": a door open the `DecisionService` already decided goes through
the command bus, whose `PullSDKDevice.open_door` reconnects, until the worker is removed at the next sync tick
(≤ ~1 s of session, then this check drops it again); and if the assignment refresh after an acknowledged
release fails, the `release[]` entry — and the session — stays until the next successful refresh (review
round 6). What two concurrent PullSDK sessions do on a C3 is unknown.

**Add-only and the handover (P2c-1/P2c-2).** A `DRIVE` turnstile is add-only while its lease says
`handoverForced` or while this PC has not restored the ownership backup for the lease generation it holds; a
`release[]` turnstile has its writes frozen. Both refuse **every** removal before any ownership check:
`push_safety.check_bulk_removal` answers `add_only`/`handover_release` (`[T] REMOVAL_DEFERRED`, retryable, state
kept, prune skipped — never `REVOKE_ABORTED`, never recorded as a problem), and so do the targeted revokes
(`_run_standalone_member_revoke` → a full-sync request; `sync_member_on_connected_sdk` → `DEFERRED`), the full
sync's "not owned → SKIPPED" finalisation, MIRROR (`[T] MIRROR_SKIP_REMOVALS_DEFERRED`), the vacated-slot
clears, the finger sweep. The reason: a new driver has no local proof, so a departed member the previous driver
pushed would read "not owned" and be finalised `SKIPPED_NOT_OWNED` — left on the turnstile for good. Pushes still
run. `[CODE]` `[TEST: test_v2_add_only.py]`
Restore (`ownership.py::OwnershipSync.restore`): every page of the current generation; an `APPLIED` row this PC
has no confirmed state for becomes `device_sync_state(ownership_confirmed=1, desired_hash=pushedHash, last_ok=1,
pushed_finger_ids=pushedFingerIds, finger_slots_swept=1)` — the engine's own hash comparison then skips a member
already in sync (no whole-roster re-push after a handover) and pushes one that is not; the adopted row is also
recorded as already uploaded (`v2_ownership_uploaded`, the server's state, hash, fingers and `observedAt`), so
it is never re-sent unchanged and a final upload re-sends it at the server's own time — the server keeps each
member's original writer and "since" time instead of the handover's (peer review 2026-09-26); local proof is
never lowered; `REMOVED`/absent rows prove nothing (the server's ~10-minute clock-ordering window, P2c-2 report).
Read-back (a forced lease, once restored): one listing through the worker, then `POST …/assignment/read-back` —
the only way the flag clears. Release: writes frozen at once, the door kept; once no pass is writing the
turnstile — the ULTRA worker's full sync and its private DeviceSync engine, the ULTRA scheduler's PullSDK
fallback pass, and the DEVICE-mode DeviceSync engine (`OwnershipSync._worker_idle`) — (+2 s grace) the WHOLE record is uploaded with `finalPage=true`, then `POST …/assignment/release`. `[CODE]`
`[TEST: test_v2_ownership.py]` `[TEST: e2e — a release without the final upload was refused
OWNERSHIP_NOT_UPLOADED; with it the server handed turnstile 8 to the other PC, which restored 24 owned pins
with their hashes and without the removed one]`
`[UNVERIFIED — FIELD-TEST]` the listing a read-back needs on an MB2000 is one STA command with no door service
for its duration (§3.4a); on ~1,860 users its length is unmeasured.

**Ownership upload.** From `device_sync_state` (`ownership_confirmed=1` → `APPLIED`, `0` → `FAILED`),
`device_push_intent` (`INTENT`) and `v2_removal_log` (`REMOVED`, written in `clear_device_revocation_state`'s
and `delete_device_sync_state`'s own transaction, at the corrected time). A row that merely vanished (a prune) is
never `REMOVED`; a logged removal older than a state already uploaded for that pin is not sent again. Rows
older than the device's latest pin-scheme switch are not uploaded — all three kinds, see "The pin-scheme cutoff"
below. Only what changed, every 5 min, for the
turnstiles this PC drives (restored) — and, in a gym with leases, for every other turnstile it holds facts for
AND uploaded before (a lease lost without a release): under the scheme and generation of its own last upload,
since the server's `GET /ownership` answers only the lease holder (409 `NOT_DEVICE_DRIVER`) while the upload
POST is open to any ACTIVE PC; local record only, no wipe report, no device connection, the server keeps the
newer fact per pin; a `STALE_OWNERSHIP_GENERATION` whose `details.pinScheme` is still ours is re-posted once
under `details.currentGeneration` (this PC's own wipe report bumped it, and the server refuses facts older
than the wipe); `CLOCK_SKEW`, 429 and network errors are retried; any other refusal is not retried until a
restart or until this PC drives it again (`_lost_with_facts`, reviews R7 and round 2). Residual `[CODE]`: pins a PC pushed only
before its gym used leases, on a turnstile it never uploaded for, are never uploaded (no generation to post
under) — the new driver's restore does not see them — pages of 1,000; `observedAt` = the row's `updated_at` (PC local) +
offset, strictly newer than this PC's last upload of that pin when the state changed. A PullSDK table clear
posts `/ownership/wiped`. `[CODE]` `[TEST: test_v2_ownership.py, test_v2_review0.py::test_an_older_removal_never_resurfaces_after_a_later_upload]`
`[TEST: e2e — 25 pins stored, an unchanged record sent nothing, a removal stored REMOVED]`

*The last push result (lane 1, 2026-09-27).* APPLIED is sticky — `ownership_confirmed` never goes back to 0 — so
the server could not tell "the member is there" from "MonClub once put the member there and the last push failed".
Backend contract `docs/plans/2026-09-27-ownership-last-push-contract.md` (branch `claude/v2-last-push-and-clock`,
revision 3.1, §1): every uploaded state row now carries `lastPushOk` (`true`/`false`/`null`), `lastPushAt` (server
clock, `…Z`, or `null`) and `lastPushError` (a short code `^[A-Z0-9_]{1,32}$`, only with `false`, else `null`).
Stored in `device_push_result` (`db.py::record_push_results`, `::list_push_results`). `[CODE]`
- **Only a real write produces a result**, recorded where its outcome is decided: MB2000 —
  `ultra_engine.py::_record_standalone_pin_state` (every chunk of a full sync, its tail, the targeted member
  push, the ACCOUNT revoke re-push) through `::_record_push_results`, the driver's per-pin reason mapped to a code
  (`set_user_info_false` → `USER_WRITE_FAILED`, `template_refused_f…` → `TEMPLATE_REFUSED`,
  `template_version_mismatch_f…`, `finger_remove_…` → `FINGER_CLEAR_FAILED`, a capacity-withheld finger →
  `CAPACITY_FULL`, a wedged chunk → `TIMEOUT`; a chunk never sent, `not_attempted`, gets none). PullSDK — the
  per-pin path (≤ 5 pins) and the targeted push (`_push_pin_to_connected_sdk`, live through
  `sync_member_on_connected_sdk`) per pin; the batch path in Phase D. **`true` is a positive set** on every
  PullSDK path: the user row written (or its force-retry succeeded), the door authorization answered with NO
  error, no template error. `_push_userauthorize` answers `(1, None)` or `(0, error)` and never raises: the
  per-pin and targeted paths used to count an error as complete when `ok_count == len(door_ids)` — any error is
  now `false AUTHORIZE_FAILED` (master correction 2, 2026-09-27); in Phase D a pin whose outcome is FAILED
  without a code is `false OTHER`, and a pin with no recorded answer stays `null`, never the state's "no
  error = ok". MB2000: `true` only for a pin not in the driver's `failed_pins`, which include a refused vacated
  finger slot (`finger_remove_…` → `FINGER_CLEAR_FAILED`). The unchanged-pin backfill, a restore, a read-back
  promotion, a hash clear and a deferral write no result. `[CODE]`
- **An attempt that starts makes the result unknown**, in `record_push_intents`' own durable transaction, before
  the device write — so it covers every intent caller of both SDKs: an interrupted attempt never leaves the
  previous `true` standing, and a failed intent write rolls the reset back with it. **The reset keeps the attempt's
  START time** (`corrected_now()`, taken before the transaction), and the upload stamps the reset row's
  `observedAt` no earlier than it — never "previous upload + 1 ms", which lost to another PC's later `true` in
  today's multi-writer mode (master correction 4). The start time is part of the change key, so every new attempt
  re-sends the row. **A restore** (this PC acquiring the turnstile, once per lease generation) makes every result
  of that turnstile unknown first, with no time (members stay "not known" until their next push: accepted,
  master note 5). **Forget** (§3.2h) deletes them. **An erase** makes every result of that turnstile unknown before
  its first delete, stamped with that moment (`db.begin_device_erase`, the MB2000 admins it keeps excepted; lane 1b,
  review F12): an `INCOMPLETE` run, a crash, "keep" or a C3 rights-only erase used to leave `true` standing for members
  it may have deleted. `[CODE]` `[TEST: test_erase_wizard_lane1b.py::TestTheEraseMakesEveryResultUnknown]`
- **A fifth writer, outside the sync (contract revision 4.1 §1.1): the local admin route `users/push`**
  (`local_access_api_v2.py::_handle_device_users_push`) writes a user row, door rights and templates for any pin
  from the request body, with no intent and no sync state. It is not a MonClub attempt and never produces
  `true`; but it changes what the turnstile holds, so right before its first device write it makes that pin's
  result unknown, durably, stamped with the moment (`db.py::reset_push_results_for_pins`) — a reset that cannot be
  recorded means no write (500). A held or handed-over turnstile is refused before any connect (§3.2h). `[CODE]`
  `[TEST: test_v2_last_push.py::TestTheAdminUsersPushRoute]`
- **Upload.** The three fields are part of "has this row changed": `v2_ownership_uploaded` gains
  `last_push_ok / last_push_src_at / last_push_error / last_push_sent_at`, the change key being the LOCAL record
  (ok, its own time, code) so a moving clock offset does not re-send rows; a changed row gets an `observedAt`
  no earlier than its last push event (a result, or a reset's start) and strictly newer than what it uploaded
  before; a re-send keeps the `lastPushAt` it sent. `lastPushAt` goes on the server's
  clock (the record's corrected time, or its PC time plus the offset at upload) and `api.py::_cap_fact_times` caps
  it at `sentAt` like `observedAt`. A REMOVED fact carries `null`. Rows uploaded before the upgrade compare as
  `(null, null, null)`, so nothing is re-sent in bulk. An older backend ignores the keys (Jackson's default, §3.1b).
  `[CODE]`
- **Found and fixed on the way (the contract's "lane 1 checks both").** Templates: every Phase C failure does
  set `error_message` `[CODE]`. Door rights: on the batch path `_push_userauthorize` never raises — it answers
  `(0, error)` — and both the pattern-discovery push of the first pin and the per-pin fallback ignored that
  answer, so a pin whose door rights the panel refused was recorded in sync and never retried. Both now record
  it FAILED (`AUTHORIZE_FAILED`), so it is retried like any refused pin. `[CODE: device_sync.py::_sync_one_device,
  Phase B]` Never seen on a C3-400 `[UNVERIFIED]`.
`[TEST: test_v2_last_push.py — the reset in the intent transaction and its rollback, the code filter, the MB2000
outcomes (a refused user row, a refused template, the backfill, an interrupted attempt, a wedged and an unsent
chunk), the PullSDK batch, per-pin and targeted paths, the restore reset, the upload fields and types, a flip and a
reset re-uploaded strictly newer, no bulk re-send after the upgrade, the cap, a full re-send, a REMOVED row;
::TestTrueNeedsTheDoorRights (an authorize error in the discovery AND in the fallback of one batch pass, and an error
with a matching count on the per-pin and targeted paths), ::TestStandaloneTrueNeedsTheVacatedSlotsCleared,
::TestAResetRowIsANewerFact]`
Not done (the master's optional note 5): reporting an MB2000 `pushedFingerIds` of `''` as known only once
`finger_slots_swept=1`. An MB2000 pin the driver skips as invalid (not digits, or more than 9) is never written and
gets NO result (`UltraDeviceWorker._STANDALONE_MAX_PIN_DIGITS` = the driver's `_MAX_PIN_DIGITS`; unreachable below
member/account id 1,000,000,000). **Does not prove** (review round 3, predates lane 1): on the PullSDK BATCH path
(> 5 pins, the default upsert strategy) a finger the member no longer has is not deleted from the panel, yet the pin
is `true` — the per-pin and targeted paths clear the pin first; whether a C3 `templatev10` write of other fingers
leaves the old one in place is `[UNVERIFIED on hardware]`. Listed as "does not prove" (master note 5, nothing built): a turnstile the server labels
PullSDK but a local protocol override (`device_driver.py`, `MONCLUB_DEVICE_PROTOCOL_OVERRIDES`) drives as
standalone.

*The pin-scheme cutoff (2026-09-27).* `ownership.py::local_facts` reads the device's latest
`device_pin_scheme_switch.switched_at` (PC local time) and leaves out every fact from before it: `device_sync_state`
and `device_push_intent` rows by `updated_at`, and `v2_removal_log` rows by `removed_at`. A corrected
`removed_at` is on the server's clock, so it is first moved back by the offset `build_rows` uses for this upload.
`[CODE]` `[TEST: test_v2_ownership.py::test_rows_older_than_the_last_pin_scheme_switch_are_not_uploaded,
::test_a_removal_logged_before_the_switch_is_not_uploaded_under_the_new_scheme,
::test_a_corrected_removal_is_compared_with_the_switch_on_the_pcs_clock,
::test_a_corrected_removal_after_the_switch_is_still_uploaded]`
Until this change the removal rows had no such check. After a MEMBERSHIP → ACCOUNT switch, the first upload under
the new generation sent, as an ACCOUNT fact, every membership-era removal that no later state row of the same pin
number had superseded. `[TEST: ::test_a_removal_logged_before_the_switch_is_not_uploaded_under_the_new_scheme fails
on aeeef69: build_rows under (ACCOUNT, 5) returns membership id 300 as REMOVED, logged an hour before the recorded
switch]` A scratch probe of `upload()` on aeeef69 (not in the repo) showed that row in the POST body.
The server does not drop such a fact. Its "outdated" fence (`ignoredOutdated`) applies only to a `DEVICE_WIPED`
generation: a `PIN_SCHEME_CHANGED` bump is lazy (the first request after the switch) and clears `wipedAt`. Its
tombstones are looked up per scheme, too. So the fact is stored as `REMOVED` in the ACCOUNT generation, and after
30 days `pruneRemoved` turns it into an ACCOUNT tombstone. `[CODE: backend 919231a8, read with git show, not run —
AccessOwnershipService::upload, ::lockedCurrentEpoch, ::pruneRemoved; AccessDeviceOwnershipEpoch::bump;
AccessDeviceOwnershipTombstoneRepository::findForPins; the same in c7d4b532]`
Nothing acts on such a row beyond that:
- The server reads stored rows only in `upload` (newest fact per pin wins; a tombstone refuses an older fact for a
  pin with no row), `restore` and `pruneRemoved`.
- The PC's `restore` adopts `APPLIED` rows only, and `meta` reads the page header only.

This PC's own account-era facts are all later than a removal it logged before its switch, so the false fact never
displaced them. For one PC, the gap was a false record, not a wrong decision. `[CODE]` Two PCs uploading for the
same turnstile (a gym without drivers, `_drivable`) are a different case: there the newest fact wins across PCs,
whatever the scheme era it came from. That case was not analysed. `[UNVERIFIED]`
Residuals `[CODE]`:
- **It is a time rule, not a scheme rule.** MonClub may remove an old-scheme pin *after* this PC recorded the
  switch: a pass or a targeted revoke still working from the device copy it held before the switch (§3.2e). That
  removal is logged after the switch and still goes up as `REMOVED` under the new scheme.
- **The manual retire writes no removal log.** It is the plain `DELETE`s of the gym 45 plan §5.1, and
  `db.py::_log_v2_removal` is the table's only writer, so the retire produces no `REMOVED` fact. The
  Erase-content wizard's "forget" (§3.2h) is not that retire: `db.py::retire_device_records` logs a
  removal for every pin it forgets, in its own transaction, and the wizard reports the wipe
  (`ownership.note_wipe`). An erase done before the switch is logged before it, so the cutoff above
  keeps those removals out of the new scheme's upload.
- **The offset is the one at upload,** not the one in force when the removal was logged.
- **`switched_at` has one-second resolution,** so a removal logged within the switch's own second is kept.

**Remote commands (P2b; payloads P2c-2 §5).** `commands.py::CommandExecutor` (thread `v2-commands`): a
journal row (`v2_command_journal`) with a fresh claim token BEFORE the claim (a lost answer is re-claimed with
the same token); 404/409 on the claim = nothing runs; the row turns `STARTED` in a durable write
(`synchronous=FULL`) BEFORE the command acts; a row found `STARTED` without an outcome after a restart is never
run again (`FAILED INTERRUPTED`) — a command started by this process is never read so, and its outcome is
journaled before it leaves the running set (a duplicate offer in between once reported an opened door as
INTERRUPTED, review R1); the deadline is the claim answer's `finishBy − serverTime` (both the server's
local clock) from the answer's arrival; below a per-type margin (door 10 s — the desk handler it reuses may
wait 2 s + 5 s on the ULTRA queue, or 4 s on the AGENT bus and then connect; card 5 s, enrolment 30 s) the
command is not started (`FAILED EXPIRED`); the result is re-posted until acknowledged (≤ 1 h). A claim that fails for a transient reason (timeout, 5xx,
the local 429 backoff) is tried again after 2, 4, 8, 16, 30, 30 s with the same token (kept in memory too, so a `SEEN` write that timed out but commits later cannot split it, review round 4) — the server notifies a
command once, so with the socket up nothing else would re-offer it (review round 3); after that the pending
poll is the backstop. Handlers run on
their own thread. `handlers.py` reuses the desk's code: DOOR_OPEN → the lease-gated `_handle_device_door_open`
(so §3.1a's claim and deadline apply; `SENT_NO_ANSWER` when the driver answered "sent, no answer"); CARD_SCAN →
`_handle_scan_quick`; ENROLL_START → `_handle_enroll_start` with the payload as its body (outcome from
`MainApp._last_enroll_outcome`; its progress is `{enrollId, scansDone, scansNeeded: 3}` from the
scanner's structured phase, `handlers.py::enroll_progress` — waiting for or retrying sample n is n-1
done, `processing` is 3 — and never the desk's free-text step line, which carries mojibake; the phase
object seen before the start is ignored, because the new worker resets the globals only when its thread
runs, lane 1 2026-09-27 `[TEST: test_v2_enroll_progress.py]`); ENROLL_CANCEL cancels only the enrolment its command started;
MEMBERS_RESYNC → a sync (explicit for `{reason:"user-sync"}`); DEVICE_RECONCILE → an explicit full reconcile of
that turnstile; DEVICE_AUDIT → one read-only listing vs owned pins; LOGS_FLUSH → `flush_now()`;
REMOVAL_CONFIRM below. `[CODE]` `[TEST: test_v2_commands.py, test_v2_handlers.py]`
`[TEST: e2e — ten reader-filed DOOR_OPENs routed by the server to the driver, each run once (request → driver
handler median 81–108 ms, max 175–311 ms, local backend); an expired one never ran; a restart reported
FAILED INTERRUPTED]` Residual `[CODE]`: on an AGENT turnstile the door open has no claim/deadline (§3.1a "not
changed"); the 10 s start margin keeps the pulse inside the command's window unless the fallback's direct
PullSDK connect itself takes longer (bounded by the SDK's own connect timeout, not by this code).
**The task said "DEVICE_RECONCILE (confirm removal)"; the server's contract has a separate `REMOVAL_CONFIRM`
type (payload `{expectedCount, pinSetHash}`) — that is the one implemented as "confirm removal";
DEVICE_RECONCILE is a plain explicit reconcile (the ceiling still applies).**

**Problem reports and Confirm removal (P2c-2 §2-3, owner decision 7).** `problems.py::registry` is fed where
each signal already exists: `check_bulk_removal` records every refused pin of the standalone revoke pass and the
PullSDK stale step (never a table clear or a renewal release; a step that runs with nothing refused resolves
it); `_capacity_admit` sets/clears `CAPACITY_FULL`; every push adds/removes `TEMPLATE_VERSION_MISMATCH` pins
(from the driver's new aggregate `failed_reasons`); the targeted and full-sync skips add `SKIPPED_NOT_OWNED`
(7-day expiry); a trusted listing sets `MISSING_OWNED`. `reports.py::ProblemReporter` posts one snapshot per
driven turnstile when it changes and hourly while it has problems, only after that turnstile's removal step
(the standalone revoke pass or the PullSDK stale step) ran in this process — a `CAPACITY_FULL` clear, a table
clear or a targeted skip alone does not count (review R9) — so a restart never sends a snapshot that hides a
stored `REVOKE_ABORTED` list. The pin-set
hash is the server's (`AccessPinSets.canonicalHash`). REMOVAL_CONFIRM recomputes the CURRENT refused list; a
different count or hash is `FAILED REMOVAL_LIST_CHANGED`; otherwise a one-shot approval bound to (turnstile,
hash, count), expiring with the command, lets `check_bulk_removal` pass that exact pin set once, on the
standalone revoke pass or the PullSDK stale step only (never an empty roster, never an add-only turnstile).
`[CODE]` `[TEST: test_v2_problems.py, test_v2_add_only.py]` `[TEST: e2e — the server stored the report and
computed the same pin-set hash; REMOVAL_CONFIRM for the bound list ran, for another list was refused]`

**Loss re-add (owner decision 6).** Only where the server has v2 — seen ON in this process, or roles
cached from it (`loss.set_enabled`); against an old server the PC behaves exactly as before (review R5).
`loss.py`: owned pins absent from a TRUSTED listing — successful, showing
at least one owned pin, missing no more than `max(10, 25 % of owned)` — are reported (`MISSING_OWNED`) and the
still-desired ones marked in `v2_readd`; the next pass pushes a marked pin that its state calls in sync, at most
50 a pass, 3 attempts; a confirmed push clears the mark. It never clears `desired_hash`/`last_ok` (R6-03), never
touches a pin in retry backoff, and a listing that loses more than the ceiling is not believed (R6-02). The
listings: the MB2000 daily read-back when it runs, and an extra one when the user count read at connect
dropped by more than MonClub's own removals since the previous connect (compared on the v2 control thread,
`loss.LossWatch`, not on the worker). The PullSDK path already re-pushes a desired pin missing from its
per-pass PIN read (the existing F-011 drift check, `device_sync.py`); only its `MISSING_OWNED` report is new.
`[CODE]` `[TEST: test_v2_loss.py, test_v2_review0.py]` Residuals: MonClub's own additions between two connects
can hide a loss of the same size (the daily read-back stays the backstop); on a day with no departed intent and
no count drop the MB2000 is not listed. `[UNVERIFIED — FIELD-TEST]` gym 45: delete one MonClub member on the
terminal's menu, reconnect the worker, check `[V2] turnstile N: user count dropped` and the member re-pushed
after that day's first pass.

**Reader screens (owner decisions 2, 3).** Local routes `access/v2_routes.py` (`/api/v2/realtime/…`): the
role and turnstiles; the reader door history from the server (`/pc/reader/door-history`, the server picks the
turnstiles); a reader's door or resync request FILED on the server (`POST /pc/commands`, no target: the server
routes it to the turnstile's driver). The local door route itself does it for a turnstile this PC does not
drive while v2 is ON (`local_api_routes.py::_door_request_via_driver`: the desk's 1 s cooldown, then 202
`{ok, requested, notDriver, targetConnected}`), so every caller — the Devices page, the favourites overlay, the
tray panel, the tray menu and the global favourite shortcuts (`src-tauri/src/lib.rs`) — reaches the driver
(review round 5: before, only the Devices page did); every caller shows it as "demandé au PC pilote", never
as an opened door (review round 6: `lib.rs` shortcut → red flash with that text, tray menu → log line, overlay
→ red flash, tray panel → info/destructive notice); a request filed by the local route itself (a remote command
run in process, `LocalCtx.in_process`) is never re-filed. The server's DOOR_OPEN payload is `{doorNumber}`
only (`AccessPcCommandPayloads.doorOpen`), so a favourite's own pulse time is lost: the driver pulses 3 s
(`handlers.py::door_open`) — a contract limit (P3c-2). With v2 not ON it answers 409 `notDriver` as before;
after an enrolment, each turnstile with the PC that pushes the finger. No PC route returns a command's outcome
or a driver's per-turnstile push state, so the reader shows "demande envoyée" / "en attente du PC pilote",
never "fait" — a contract gap (report). Tauri page « Pilote / Lecteur » (`RealtimePage.tsx`), French only like
the rest of the UI. `[CODE]` `[TEST: test_v2_local_routes.py]`

**Door path and start-up.** The decision code is untouched; the ULTRA worker gained lock-free snapshot reads
(`device_allowed`, `writes_frozen`) at each drain and at connect, and an in-memory note of the connect-time user
count. Measurements: §3.9a below.

#### 3.9a Measured before and after (development PC, 2026-09-26)

Scratch harnesses (not in the repo), base `22c9cfc` and this branch interleaved, 32-bit `.venv` Python 3.11,
the PC at 85–96 % memory load. `[TEST: measurement, not pass/fail]`

| What | Base `22c9cfc` | Branch, no leases | Branch, DRIVER lease installed |
|---|---|---|---|
| Scan → decision on the real `UltraDeviceWorker.run()` loop over the fake MB2000, 150 scans × 3 runs | median 230.1–232.4 ms, p95 541.8–546.8 ms, 0 lost (6 runs) | median 231.0–233.2 ms, p95 542.5–546.4 ms, 0 lost | median 231.4–232.4 ms, p95 531.9–544.6 ms, 0 lost |
| Desk door open (`request_door_open`) round trip, 150 × 3 | median 0.49–0.76 ms, max ≤ 4.5 ms | median 0.47–0.90 ms, max ≤ 4.1 ms | median 0.56–0.81 ms, max ≤ 4.7 ms |
| `create_access_app()` (MainApp `__init__`), warm data root, network blocked | 480–505 ms (3 runs) | 488–701 ms (3 runs; the 701 ms run also took 215 ms to import — disk noise) | — |

Re-measured on the final branch (after the seven review rounds), same harnesses and interpreter, base and
branch interleaved, 3 runs each: scan → decision base median 230.7–232.2 ms (p95 543.5–544.1), branch no
leases 230.2–230.9 ms (p95 542.0–545.2), branch DRIVER 230.4–231.3 ms (p95 541.5–543.6), 0 lost in every run;
desk door open median 0.47–0.72 ms on all three; `create_access_app()` base 545–636 ms, branch 558–709 ms
(overlapping ranges; branch middle run 590 vs base 565 ms). The AGENT worker's per-turn lease read (review
round 5) is not on these harnesses: unmeasured. `[TEST: measurement, not pass/fail]`

The v2 runtime starts 12 s after launch (after the PC identity); offline and unregistered it reads
`availability=UNKNOWN`, `mode=ALL`, reason `NO_PC_TOKEN`, and changes nothing. `[TEST: same harness]`
Remote door open, reader request → driver's door handler, local backend: median 81–108 ms, max 175–311 ms
(two runs of 10). `[TEST: e2e]` On a gym PC and through the internet: `[UNVERIFIED — FIELD-TEST]`.
Final end-to-end run on `0cbf26d` against backend `c7d4b532` (scratch copy of `wigo-demo`, dropped after):
**46/46** with both switches on — the 37 earlier checks plus: the clock corrected by a refusal with no gym
offset known; a turnstile lost by a forced move whose new fact goes up by POST without the holder-only GET;
a reader's own local door route answering 202 `requested`, 429 on a second press within 1 s, the driver
running it once (SUCCEEDED/OPENED); a PC revoked on the server driving nothing, also after a cold start —
and **5/5** with the commands switch off. Reader request → driver handler in that run: median 145 ms, max
562 ms (one run of 10, the backend freshly started). `[TEST: e2e]`

**Lane B (`claude/v2-safety-sync` at `591ca69`, 2026-09-27), same harnesses and interpreter**, base `aeeef69`
(`git archive`) and the branch interleaved, run alone, 3 runs each `[TEST: measurement, not pass/fail]`:
scan → decision base median 231.5–231.8 ms (p95 536.9–545.0, max ≤ 550.9), branch 231.6–232.3 ms (p95
542.3–545.0, max ≤ 550.7), 0 lost in every run; desk door open median base 0.47 ms (max ≤ 1.4), branch
0.44–0.45 ms (max ≤ 1.5); `create_access_app()` on a warm data root, network blocked, after one warm-up
run each (base 612 ms, branch 421 ms, not counted): base 381–384 ms, branch 362–374 ms, import 34–38 ms on
both, the 20 s loop exiting cleanly. The door path runs none of lane B's code (the scheme re-checks are in
the push passes); offline the v2 runtime stays `UNKNOWN`, so this start-up is the power-on path with the
safety sync off — a start-up in safety mode is not on these harnesses: unmeasured.

**Lane 1 (`claude/erase-wizard-and-v2-gaps` at `97ed4d5`, 2026-09-27)**, the same two harnesses rebuilt after
this section's description (scratch, not in the repo: the real `UltraDeviceWorker.run()` over the fake MB2000,
and `create_access_app()` on a warm data root with the network blocked), base `d3725fa` (an export of master)
and the branch interleaved, same interpreter `[TEST: measurement, not pass/fail]`: scan → decision base median
231.5–231.7 ms (p95 486.5–543.4, max ≤ 571.9), branch 230.6–231.7 ms (p95 542.2–546.2, max ≤ 560.9), 0 lost
of 150 in every run (3 runs each); desk door open median base 0.75–0.91 ms (max ≤ 7.6), branch 0.57–0.89 ms
(max ≤ 5.8), 150/150 opened in every run; `create_access_app()` after one warm-up run each (base 1022 ms,
branch 777 ms, not counted), 5 runs each: base 578–740 ms, branch 549–747 ms — overlapping ranges, no
difference this noise can show. The worker loop reads `device_hold.is_held` (a set lookup and one boolean)
in its write gates (`_v2_writes_blocked`), not in the scan decision; the start-up adds the hold load. An
earlier run at `954763b`, before the round-1 fixes, gave the same picture (scan median base 230.5–231.0 ms,
branch 230.6–230.9 ms; start-up base 552–805 ms, branch 577–676 ms, 3 runs each). **Re-measured at the final
`1f363e1`** (after review rounds 2–5: the worker's `_connected_addr`, the hold lock), same harnesses, the PC busier
(other sessions running): scan → decision base median 231.2–233.0 ms (p95 539.9–552.1, max ≤ 607.5), branch
231.0–231.9 ms (p95 542.1–542.5, max ≤ 806.3, one outlier), 0 lost in every run; desk door open median base
0.75–1.17 ms (max ≤ 46.8), branch 0.83–1.17 ms (max ≤ 67.8), 150/150 in every run; `create_access_app()` after a
warm-up each, 5 runs: base 665–1528 ms, branch 602–1297 ms — overlapping, dominated by the load, no difference shown.

**Lane 1b (`claude/erase-wizard-and-v2-gaps`, measured at `ac8be91`, 2026-09-27)** — the same two scratch harnesses
(lane 1's, reused unchanged), base `337f1bb` (a detached worktree) and the branch interleaved, same interpreter, the PC
shared with other sessions `[TEST: measurement, not pass/fail]`: scan → decision base median 232.5–233.1 ms (p95
541.4–544.7, max ≤ 588.0), branch 232.1–232.7 ms (p95 530.4–545.8, max ≤ 578.1), 0 lost of 150 in every run (3 runs
each); desk door open median base 0.88–1.26 ms (max ≤ 13.9), branch 0.95–1.14 ms (max ≤ 16.4), 150/150 in every run;
`create_access_app()` after one warm-up each (base 1884 ms, branch 1686 ms, not counted), 5 runs: base 693–1090 ms,
branch 694–1285 ms — overlapping ranges, no difference this noise can show. The worker loop runs none of lane 1b's
code (its hold gate is unchanged); the start-up adds one read of `device_write_hold` for `erase-prep` rows (a durable
write only when there is one to release) and starts the backup-prune thread. The later commits (`699080e`, review round
1) touch neither path. Not measured: the heartbeat of a held turnstile (it filters the roster once per held line every
5 min) and the PullSDK authorize fallback's new yields (they only add door service between pins).

**Lane 1c (`claude/erase-wizard-final`, measured at `e6c0ac8`, 2026-09-28)** — the same two scratch harnesses (lane
1b's, reused unchanged), base `e5e3328` (a `git archive` export) and the branch interleaved, same interpreter, the PC
shared with other sessions `[TEST: measurement, not pass/fail]`: scan → decision base median 231.3–234.2 ms (p95
542.3–546.0, max ≤ 589.9), branch 231.6–231.7 ms (p95 542.3–545.7, max ≤ 558.2), 0 lost of 150 in every run (3 runs
each); desk door open median base 0.39–0.64 ms (max ≤ 2.65), branch 0.46–0.76 ms (max ≤ 6.67), 150/150 in every run;
`create_access_app()` after one warm-up each (base 871 ms, branch 830 ms, not counted), 5 runs: base 553–955 ms, branch
567–791 ms — overlapping ranges, no difference this noise can show. The worker loop runs none of lane 1c's code; the
start-up adds one attribute (`_last_sync_ok_mono`). Not measured: the wizard's new step-1 user-list read — a device
command, door-blind for its length (§3.2h, field test). The later commits, up to `7723310` (review rounds 1-5), change
only `app/core/erase_wizard.py`'s start, run and Refill paths, its tests and the page's texts
(`git diff --stat e6c0ac8..7723310`): neither the worker loop nor `create_access_app()`.

### 3.10 The heartbeat's turnstile line — "N waiting" (lane 1, 2026-09-27)

`pc_identity.py::build_heartbeat_payload` sends one `turnstiles[]` line per device, `{gymDeviceId,
reachable, failedPins, mode}`: from the sync cache (`failedPins` from the cached device row), then the
AGENT snapshot (`failedPins`), then the ULTRA worker snapshot (`failedPins` or `failed_pins`), the last
one found winning. `[CODE]` Until this change no engine put the key in either snapshot and no device
row carries it, so every line said 0 and the dashboard's "not reachable since 14:02, 3 waiting"
(`mon_club_dashboard` `gym-access-pcs-turnstiles-presentation.ts::waitingLineForm`, "the PINs the PC
could not write and keeps for its next try") never appeared. `[CODE]`

- **ULTRA** — each full pass counts, when it ends, the pins of ITS desired roster that the per-pin
  state does not show confirmed with the desired content: no `device_sync_state` row, `last_ok=0`, or
  another hash (`device_sync.py::count_waiting_pins`, the predicate the next pass pushes on, backoff
  aside). So a pin the terminal refused, one held by the retry backoff, one left by the per-pass cap
  or by `CAPACITY_FULL` counts; a pin outside the roster never does — after a pinScheme switch the old
  scheme's rows stay `last_ok=0` for good (§3.2c: the revoke pass aborts, no prune), and a raw
  `last_ok=0` count would read ~1,000 waiting at gym 45 forever. MB2000: `_run_standalone_full_sync`
  (after its try, so a pass that raised part-way counts what it left unwritten); PullSDK:
  `DeviceSyncEngine._sync_one_device`'s `finally` sets `_last_waiting_pins`, which the worker's PullSDK
  drain copies. The worker snapshot's `failed_pins` is None until a pass has counted (the heartbeat
  sends 0 then, as before), and a pass that stops before building its roster (no cache, unreadable
  ownership or guard, a scheme stop, a lease refusal) keeps the previous figure. `[CODE]`
  `[TEST: test_waiting_pins_report.py — refused, backoff-held and capped-out pins counted, a clean
  pass 0, 12 old-scheme rows at last_ok=0 not counted, an early return keeping the figure, both SDKs,
  the worker's PullSDK copy, the heartbeat line]`
- **Limits `[CODE]`.** The figure is as of the last full pass. No pass runs while the terminal is
  unreachable, so the line "not reachable since …, N waiting" shows what that last pass left, not the
  members changed since; a targeted member push does not move it until the next pass (which the
  scheduler runs after every roster change). ACCOUNT rows withheld for a missing `mainAccountId` are
  not counted: their pin cannot be named (§3.2b, `PIN_SCHEME_ACCOUNT_WITHHELD` reports them).
- **AGENT** — `failedPins: 0` in the snapshot, stated, not defaulted: no engine writes a PIN to an
  AGENT device (§3). **DEVICE** mode keeps the cache row's value, which no writer fills (no fleet device
  is DEVICE-mode, §3.2g). `[CODE]`
- **A held turnstile** (lane 1b, review F0/F7/F14/F26; §3.2h). No pass runs while it is held, so no pass
  counts, and the worker's figure used to read 0 (the run set it to None) for an emptied turnstile —
  "reachable, nothing waiting" off the PC for the whole "hold until Refill". Now, after the three sources
  above, `pc_identity.py::_report_held_turnstiles` adds `held: true` to the line of every turnstile
  `device_hold.is_held` answers True for — the durable hold loaded at start-up, so it survives a restart;
  EVERY line while the holds could not be read — and sets `failedPins` to the members its refill would
  write (`erase_wizard.held_waiting_count`: `refill_roster` over the sync cache ALREADY in memory,
  `peek_sync_cache`, never a cache load), recomputed at each heartbeat. When
  that cannot be told (no cache in memory, no device row) the figure is left as it was, `held` still
  set. Only held lines carry the key, and never an AGENT line (no engine writes a pin to it; review round 1). The
  count is made from the cache already in memory, but building the filter's `DeviceSyncEngine` reads the backend
  settings (`get_backend_global_settings`, its own 30 s cache) — one small database read per held line and heartbeat,
  inside the heartbeat's try. The cache's device row is the DB row (snake_case), coerced to the payload shape the
  passes filter (`db._coerce_device_row_to_payload`; `allowedMemberships` was missed before review). The first heartbeat
  after a start is sent at once: if the sync cache is not in memory yet, a held line has `held` and the worker's figure
  until the next beat, 5 min later. `[CODE]` `[TEST: test_erase_wizard_lane1b.py::TestTheHeartbeatOfAHeldTurnstile,
  ::TestReviewRound1::test_an_agent_line_is_never_reported_held]` The call in `build_heartbeat_payload` has its own
  `try` since lane 1c (review F7), like the three blocks before it: whatever the held-turnstile code raises — `is_held`,
  `refill_roster`, `peek_sync_cache`, the helper itself — every line still goes, since a payload that raises sends no
  heartbeat and the PC would look silent. `[TEST: test_erase_wizard_lane1c.py::TestRegressionGuards::
  test_the_heartbeat_builds_when_the_held_count_raises]`
  The backend: `GymAccessPcDtos.TurnstileReport` is a 4-component record `{gymDeviceId, reachable,
  failedPins, mode}` and the application's mapper leaves `FAIL_ON_UNKNOWN_PROPERTIES` off
  (`GymAccessPcHeartbeatJsonBindingTest` binds unknown keys at the top level and inside a nested record,
  not inside a `turnstiles[]` element) — so backend `47f35a96` drops `held` and stores `failedPins`
  (`AccessDeviceStatusService.cleanFailedPins`: any value ≥ 0) `[CODE: backend read with git show, not
  run]`. The dashboard therefore sees "N waiting", not "held"; a held flag there is not built.

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
| `supports_capacity_check` | absent ⇒ callers default `False` | `True` `[CODE]` | `read_capacity()` reports free user/fingerprint slots and the algorithm version; the engine refuses writes needing a new slot when none is free (P3a-2, §3.4d). PullSDK has no such signal in this repo, so it is never gated. |

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
  the FALSE return (`detail` keeps the raw string) — never as a silent success; an open the
  driver stopped waiting on (`result=timeout`: its command may or may not have reached `ACUnlock`)
  reaches it as "sent, no answer" instead (§3.1a), because the relay may still fire;
- the local API additionally logs `DOOR_OPEN result ∈ {200_ok, 409_unsupported,
  429_cooldown, 503_timeout, 500_sent_no_answer, 500_failed}` keyed by `device_id`, so one grep
  shows the press, the refusal or the SDK answer;
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

Residuals the first review round accepted rather than changed (pre-existing mechanisms or paths no
deployed gym uses): a pin whose first push failed BEFORE this branch has no intent and no ownership, so
its revocation is `SKIPPED_NOT_OWNED` (base never removed it either, but kept the revocation pending)
(R1-03); a vacated finger slot that is already empty answers `False`, which the removal step reads as a
refusal, so such a pin fails on every retry — reachable after a lost state commit or a finger removed on
the terminal by other means (R1-20/R1-28; telling "refused" from "empty" needs a template read,
`[UNVERIFIED]` on this firmware); a PullSDK intent with no card is never proven or dropped (R1-16; the
gym 58 C3-400s are card-only); a door open that times out inside the push yield abandons the STA thread,
so the next outer chunk is recorded as wedged and its members as failed, then retried (R1-25).
Round 2 added: a pin owned through an accepted user row whose recorded finger set is unknown bypasses
the fingerprint-slot gate on later passes (every template is sent and the terminal refuses what does
not fit — base behaviour, R2-03); a removal retry armed on a worker the watchdog then replaces is lost
with that worker, while the scheduler keeps the stamped roster hash (the thread rarely dies — the loop
catches `Exception` — R2-08); an intent re-recorded with a new name/card before its new write lands
replaces the identity of an earlier write that did land, so the read-back can never match it (R2-10).

Round 3 added: **a plan switch under pinScheme=MEMBERSHIP could lock the member out until the next
pass** (R3-21). Corrected by P3b-1: the backend's *renew* keeps the same membership id (same pin); a
new id for the same person comes from selling another plan (§3.4f). Removals ran first (§3.4b), so the
old pin was deleted before the new one was written. **Closed for full-sync passes by §3.4f** (the old
pin is held until the new one is confirmed); still open on the targeted revoke path (§3.4f "Not
covered"). FIELD-TEST: at gym 45, watch `RENEWAL_HOLD` with `kept>0` next to failed new pins. The
finger-slot sweep clears fingers enrolled DIRECTLY on the MB2000 for a MonClub member (base never touched
unrecorded slots, R3-25) — enrol through MonClub. A PullSDK revocation of a pin MonClub has no record of
(never pushed to that panel, or already removed) is reported `SKIPPED_NOT_OWNED` at CRITICAL like a
foreign user (R3-05); a scheduler replay of a revocation the fast retry already completed logs a false
`SKIPPED_NOT_OWNED` (R3-15). A PullSDK revocation that failed for a reason other than a failed delete or
unreadable ownership (e.g. a failed ACCOUNT re-push) is parked, not fast-retried (R3-07); an exception in
the PullSDK revoke pre-pass loses the fast retry of the revocations it had tried (the scheduler still
re-queues them, R3-08). When a revoke-pass guard trips, the pass stores no roster snapshot, so that day's
read-back uses the previous one (R3-10). The `push_roster` STA op's event pump runs inside the chunk's
deadline, so a hung `ReadRTLog` turns a written chunk into a wedged one (its members are retried, R3-23).

A MonClub membership id that collides with another system's user id on a shared MB2000 (gym 45):
MonClub's write overwrites that user's name and card, and since review round 1 the pin is MonClub's
as soon as that user row lands (§3.4), so a departure deletes the whole user; the finger-slot sweep
(§3.4c) likewise clears its unused slots. Whether any id collides is `[UNVERIFIED]` — FIELD-TEST:
list devices 8/10's users (`GET /api/v2/devices/{id}/users`) and compare the other system's pins
with MonClub's membership ids before relying on removals there.

**P3b-2 (2026-09-26) — see §3.9 for each:** `wss://` through the production nginx (never exercised: the
end-to-end run used the local backend over `ws://`); a PC revoked or moved while it was off acts on its cached
roles until the server answers; a remote DOOR_OPEN on an AGENT turnstile has no claim/deadline; the MB2000
listing a read-back, an audit or a loss check needs is one door-blind STA command of unmeasured length; MonClub's
own additions can hide an equal loss between two connects; no PC route reports a command's outcome or a
driver's per-turnstile push, so a reader shows requests and enrolments as pending, never done.

Round 6 left two things as they are. **A MonClub member deleted from a shared MB2000 by another system
stays off it** — MonClub still believes the pin is its own and in sync, so no pass pushes it; base behaved
the same. The daily read-back REPORTS such pins (`PUSH_INTENT_READBACK missing_owned=N`, a WARNING
line) — but only on the days it runs, i.e. while departed-member intents exist (§3.4a); no line does NOT
mean nothing is missing. Re-adding them is loss detection, outside P3a-2 (round 5 flagged them for a
re-push; withdrawn, R6-02/03/04). While one exists the listing never looks complete, so no departed intent
is dropped and the read-back runs every day for as long as those intents remain — one whole-terminal listing, a single STA command during which no door command is served, of
`[UNVERIFIED]` duration (R5-01; FIELD-TEST at gym 45: `grep -F "[T] PUSH_INTENT_READBACK"` — `dur_ms` is the
door-blind time, `missing_owned` the members to check on the terminal). **On a C3-400 (gym 58)** a
revoked member deleted by a full pass that then fails keeps a RETRY roster exclusion until a pass succeeds,
so a membership restored meanwhile is refused by the targeted sync and left out of that pass (R6-08). This
is base behaviour on the PullSDK path, unchanged by P3a-2 (the MB2000 path releases it, R5-03); not
reproduced here — the step not traced is what the scheduler's `_sync_device` fallback pushes for that
member meanwhile. FIELD-TEST at gym 58: after a restored membership, check the member opens the door.

From P3a-2 (§3.4e), measured only on a fake terminal: whether the MB2000 hands over at a chunk's
end the events of scans made during it; the duration of `RefreshData(1)` (what a smaller chunk
would cost); the per-pin duration of the whole-user delete (`ZKEM_DELETE_DONE dur_ms`); the gym
PC's setup time per capped pass.

### ~~Why fingerprint templates were refused~~ — RESOLVED (see zkemkeeper_guide §8)

This section used to list two unproven causes (a full store, an algorithm-version mismatch).
`zkemkeeper_guide.md` §8 records the answer: a clean field run at v1.4.26 pushed 928 users and 853
template sets with `templates_failed=0`, so neither was the cause; the refusals were a downstream
symptom of the `SSR_DeleteEnrollData` hang. `[FIELD]` Kept consistent here so the two guides agree.

Since P3a-2 both are checked BEFORE writing (§3.4d) — as a new rail for the shared-terminal
scenario (a store another system fills), not as a re-diagnosis of that incident.

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
- **On-site script pack**: `tools/mb2000_scripts/` (`0_MENU.ps1` plus 14 scripts — COM
  registration, device info, ZK9500 enrol, push, live monitor, unlock, backup/restore,
  portability test, force-open, inspect-and-clear, and the read-only export of script 14,
  whose read-only property is pinned by `tests/test_mb2000_export_readonly.py`). Use these to
  establish ground truth on hardware
  **before** changing driver code. `[CODE]`
- **PullSDK panels**: `tools/c3_panel_scripts/export_c3_panel_readonly.ps1` reads one panel
  (parameters, clock, table counts, `user`, `userauthorize`, `templatev10` finger ids) into a file,
  through a helper that declares only `Connect`, `Disconnect`, `GetDeviceData`, `GetDeviceDataCount`,
  `GetDeviceParam`, `PullLastError` `[TEST: tests/test_c3_panel_export_readonly.py]`; a negative
  `GetDeviceDataCount` is recorded in `errors` and written as `null`, and a failed `user` /
  `userauthorize` / `templatev10` count makes the export partial `[TEST: same file]`. Its output is
  compared by `tools/gym45_cutover/compare_terminal_export.py`, whose `cards` section is licensed by a
  card self-check (own pins whose device card equals the card MonClub writes, ≥ 90 %), the card rule
  chosen per export (`_normalize_device_card` for a panel, the raw digits for an MB2000)
  `[TEST: tests/test_gym45_compare_terminal_export.py::TestPanelCards]`. Never run against a real panel
  yet `[UNVERIFIED]`. There is no PullSDK write or erase script: erasing a panel is the Access
  Erase-content wizard (§3.2h). `[CODE]`

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
background-thread exceptions are promoted to failures. Last run: **3489 passed, 0 failed** (2026-09-28, branch `claude/cutover-runbook-pass` at `5327275`, code commit `3bc9c31` -- lane 1d, the master review of lanes 1c and 3d: a kept hold survives a restart, the start-up prune waits for the server clock, a keep mark of a run that never erased goes at start-up, review nits, and the cutover runbook's sixth round -- the command above plus `-p no:cacheprovider`, `MONCLUB_ACCESS_DATA_ROOT` pointed at an empty temp folder, the 32-bit `.venv` Python 3.11; the lighter `python -m pytest tests/ -q --ignore=tests/_pydeps -p no:cacheprovider` gave the same 3489; its base master `aa015e5` counts 3466 (the master session's figure, not re-run here), and the branch adds the 23 tests of `tests/test_erase_wizard_lane1d.py`; `tools/check_sql_arity.py` PASS, 73 files, 398 literal statements). Before it: **3466 passed, 0 failed** (2026-09-28, branch `claude/erase-wizard-final` at `c09d917`, last code commit `7723310` -- lane 1c, the Erase wizard's last review fixes and the owner's age limit, after six review rounds -- the command above plus `-p no:cacheprovider`, `MONCLUB_ACCESS_DATA_ROOT` pointed at an empty temp folder, the 32-bit `.venv` Python 3.11; its base master `e5e3328` gave **3386** on the same PC the same day; `tools/check_sql_arity.py` PASS, 73 files, 396 literal statements). Before it: **3343 passed, 0 failed** (2026-09-27, branch `claude/erase-wizard-and-v2-gaps` at `4ff85aa` -- lane 1b, the Erase wizard's review fixes and the owner's two decisions -- the command above plus `-p no:cacheprovider`, `MONCLUB_ACCESS_DATA_ROOT` pointed at an empty temp folder, the 32-bit `.venv` Python 3.11; its base `337f1bb` gave 3203; `tools/check_sql_arity.py` PASS, 73 files, 396 literal statements). Before it: **3023 passed, 0 failed** (2026-09-27, branch `claude/v2-safety-sync` — lane B, the v2 safety sync — on the guide as of its final measurement note, code as of `591ca69`; the command above plus `-p no:cacheprovider`, `MONCLUB_ACCESS_DATA_ROOT` pointed at an empty temp folder, the 32-bit `.venv` Python 3.11; its base master `aeeef69` gave 2914; `tools/check_sql_arity.py` PASS, 71 files — `device_worker.py` removed). Before it on master: **2914 passed, 0 failed** (2026-09-26, master after merging `claude/p3b2-realtime-leases` onto the cutover-runbook round-2 master `2f6b96e`; same command and data-root rule; `tools/check_sql_arity.py` PASS). The branches alone: P3b-2 -- **2876 passed, 0 failed** (2026-09-26, branch `claude/p3b2-realtime-leases`, P3b-2 final, after review round 7 and the restore-dating fix; after round 6, 2875; `cargo check` of `tauri-ui/src-tauri` clean; before that 2874, 2873; after round 4, 2865; after round 3, 2864; after round 2, 2861; one earlier run of the same commit failed `test_worker_link_recovery.py::test_an_abandoned_sta_thread_is_rebuilt_by_the_worker` once on its 10 s wait under full-suite load -- 3/3 alone and the rerun passed; `tools/check_sql_arity.py` PASS). Branch `claude/cutover-runbook-round2` (2026-09-26; `python -m pytest tests/ -q --ignore=tests/_pydeps -p no:cacheprovider` with `MONCLUB_ACCESS_DATA_ROOT` pointed at an empty temp folder -- a lighter command than this one): `master` `dbf865f` **2656 passed**; the branch **2672 passed, 0 failed**. One earlier full run of the branch had **1 failed, 2671 passed**: `test_db_hot_path_writer.py::test_db_writer_serializes_concurrent_write_jobs`, which asserts the order of two threads' `results.append` after the writer released them -- a race in the test (15/15 passes alone, passed on the rerun; the branch changes no app code); `tools/check_sql_arity.py` PASS. Last run on master: **2634 passed, 0 failed** (2026-09-26, master after also merging `claude/card-cooldown-boot` and `claude/test-dataroot-files`; before those, **2633 passed** after merging `claude/heuristic-dirac-3b96e7` and `claude/init-db-logging-fix`, same command and data-root rule; `tools/check_sql_arity.py` PASS). Before those two: **2616 passed, 0 failed**
(2026-09-26, master after merging `claude/p3b1-power-on-dates` `5094150` onto master `84bcfb7`, which
already held the access integration (QR grants diff, heartbeat `qrRosterCheck`, operator-queue claim)
and the gym 45 cutover tools; the CLAUDE.md command, 32-bit `.venv` Python 3.11, `MONCLUB_ACCESS_DATA_ROOT`
an empty scratch folder; `tools/check_sql_arity.py` PASS). The two branches alone: P3b-1 at `5094150`
gave **2522 passed** (six adversarial review rounds; base `ca1e29a` 2109 passed); the integration at
`f2f1a90` gave **2148 passed** with both commands, twice each. The door-timing flake below is
discussed with its own measured rates. `[TEST]`
`tests/test_door_open_deadline.py::test_a_door_open_the_caller_gave_up_on_is_never_executed_later`
was timing-flaky up to master `ca1e29a`: runs of that file alone failed 13/52 on `d09f88f` and 16/60
on P3a-2. The race behind it: `Event.wait(timeout)` can return while `time.monotonic()` has not passed
the entry's deadline, so a drain right after the caller's `timeout` still sent the open; in isolation
that scenario opened the door in 23 of 300 repetitions (2026-09-18, development PC, commit 75f2c7d on
branch `claude/confident-williamson-07839d`, integrated as 079bb02). The claim (§3.1a) closes it.
Re-measured on 2026-09-25, master and this branch interleaved, a new empty data root per process:
the file alone failed 19/60 on master and 0/60 here; the test's original body alone, 18/60 and 0/60;
an in-process loop of that scenario opened the door 24, 33 and 36 times per 300 on master and 0 here.
In the four full runs of each tree that day it passed every time, on master too. `[TEST]`
`tests/test_review_round6.py::test_r6_01_a_scan_from_the_sta_threads_last_pump_is_decided`
depended on machine uptime up to master `3b28bd2` (a test defect, not a product one). It set
`_connected_since_mono = time.monotonic() - 5000.0`. `time.monotonic()` counts from boot
(`GetTickCount64()` on the 32-bit Python 3.11 `.venv`), so that value is negative on a PC up for
less than 5000 s, and `_maybe_refresh_connection` reads a non-positive value as "never
connected". It failed after reboots on 2026-09-19 and 2026-09-25, and on 2026-09-26 at uptime
1047 s. The test now sets `ultra_connection_refresh_sec = 1.0` in the worker's settings and
back-dates the connect by 5 s, clamped positive. It does not patch the clock, because the real
STA thread shares the `time` module. It passed at uptime 1134 s on 2026-09-26 (branch
`claude/heuristic-dirac-3b96e7`). The full suite on that branch gave **2616 passed, 0 failed**
between uptime 1298 s and 1481 s: the CLAUDE.md command, `MONCLUB_ACCESS_DATA_ROOT` an empty
scratch folder, `tools/check_sql_arity.py` PASS. `[TEST]`
In `ultra_engine.py`, three fields have guards that read `0.0` as unset: `_connected_since_mono`
(`> 0.0`), `_connect_down_since_mono` and `_last_down_error_log_mono` (`== 0.0`). No other test
back-dates any of them from the real clock. The other writes (round-2, round-3 and round-5 link
tests, `test_ultra_engine.py`) are `0.0`, or positive values under a patched `ue.time.monotonic`
(fake clocks at 1000.0 and up).
`[CODE: grep -rnE "_connected_since_mono|_connect_down_since_mono|_last_down_error_log_mono" tests/]`
`tests/test_authoritative_revocation_pipeline.py::test_shadow_sync_never_truncates_or_accepts_noncanonical_valid_ids[0]`
failed once in a full run of `d09f88f` and passed 20/20 alone. `[UNVERIFIED]` cause (test-order).
`tests/test_zk_standalone_com_teardown.py::test_unexpected_exception_exit_still_unadvises_first`
failed once in a reviewer's `-x` run on P3a-2 and passed alone and in every full run.
`[UNVERIFIED]` whether it is timing-flaky.

> **Run the suite with `MONCLUB_ACCESS_DATA_ROOT` pointing at an empty scratch folder.** It
> moves the whole data root (`app/core/utils.py::_candidate_data_roots`), so a test that forgets
> the `_DB_PATH` override below cannot reach the installed gym database. Measured this way,
> master `fecae45` gave **1764 passed, 7 failed**, not the 1771 recorded on 2026-09-13: the seven
> tests in `test_access_history_unresolved_bound.py` left `list_device_pin_scheme_switches`
> unpatched and passed only against an already-migrated — the installed — database, and
> `test_sync_handlers_schedule_expected_trigger_metadata` ran `DELETE FROM sync_version_tokens`
> on whatever database was active. Both are patched now (commit a87830b).
>
> **`tests/conftest.py` now keeps the whole suite off the installed database** (merged 2026-09-26 from
> `claude/test-dataroot-files`): session-scoped guards point `app.core.db._DB_PATH` at one temp file
> (re-applied around every test, because some fixtures reload `app.core.db`), repoint the split-config
> paths, and repoint the popup image cache with a `requests` stub that refuses, so no test writes the
> installed app's config or fetches from the production backend. Before it, a per-file sweep
> (2026-09-18) found 33-34 test files reaching the installed database. Setting
> `MONCLUB_ACCESS_DATA_ROOT` to an empty folder is still recommended as a second guard. `[CODE: tests/conftest.py]`

> **Any test that drives a full sync must use the documented `_DB_PATH` temp-database
> override.** Without it the run writes per-pin state into the developer's *installed*
> database, and a leftover `ownership_confirmed` row there then looks like a departed
> member to the next suite's revoke pass — which adds neutralise pushes and fails
> assertions far away from the cause. `_make_sync_worker` in
> `test_zk_standalone_driver.py` now also stubs `list_confirmed_device_sync_pins`, so a
> polluted database can no longer reach it; `get_conn()` does **not** commit ad-hoc
> writes, so clean up through `_run_db_write_sync` if you ever need to.

> **No test reaches the default database any more — `tests/conftest.py` enforces it.**
> The default data root is `C:\ProgramData\MonClub Access` (`_candidate_data_roots` in
> `app/core/utils.py`), so with `_DB_PATH` left at `None` a test run on a gym or dev PC opens
> the *installed* `access.db`. A per-file sweep on master (2026-09-18: each `tests/test_*.py`
> run alone with `MONCLUB_ACCESS_DATA_ROOT` set to a fresh empty folder) found **34 of 118**
> files creating `access/access.db` under that root. `[TEST]` The main path was a read:
> engine and sync code reaching `get_backend_global_settings` →
> `load_sync_access_software_settings` unpatched. A second sweep with an `sqlite3` authorizer
> (root pre-seeded with a migrated DB, one sweep, 2026-09-18) showed which ones **write**:
> `test_access_history_user_id`, `test_daily_counter` and `test_anti_fraud_daily_limit_integration`
> INSERT/UPDATE/DELETE `access_history` (the committed inserts advance its `AUTOINCREMENT`
> counter even after cleanup; cleanup runs only if the test passes), and `test_db_anti_fraud_columns`
> INSERTs/DELETEs `sync_devices`. `test_device_sync_protocol_guard::test_pullsdk_device_is_not_refused`
> and `test_zk_standalone_driver::…::test_full_sync_pushes_roster_and_terminates` leave rows in
> `push_batch_history`. `test_sync_observability::test_main_app_initializes_scheduler_before_first_after`
> runs `cleanup_stale_in_progress_sync_runs`, which commits `UPDATE sync_run_history SET
> status='INTERRUPTED' WHERE status='IN_PROGRESS'` and would mark a running app's live sync as
> interrupted. Those first four files also run `init_db()` from a module-scoped fixture, so they
> applied schema migrations (DDL) to the installed database. `[TEST]` That sweep ran against an
> *empty* migrated schema. A populated installed database could send the same tests down
> further write paths. `[UNVERIFIED]`
>
> `tests/conftest.py` now points `_DB_PATH` at one empty temp file for the whole session.
> It never calls `init_db()` itself. So a file run alone still fails on an unpatched read of a
> missing table, the failure that the 7 tests in `test_access_history_unresolved_bound.py`
> hid until commit 86be8ea (cherry-picked from a87830b). **A full-suite run does not catch
> this.** Four files (above) call `init_db()` from a module-scoped fixture without their own
> override, which migrates the shared session file early in the run. After a full run it held
> 41 tables. `[TEST]` Only the per-file sweep below keeps such reads detectable. Two details
> are load-bearing. `[CODE]` **Session scope:**
> module-scoped `init_db()` fixtures run before any function-scoped override, and the db
> writer, sync-cache loader and popup prefetch threads outlive single tests, so the path is
> never reverted to `None`. **Re-applied around every test:** seven fixtures call
> `importlib.reload(app.core.db)`, which re-executes `_DB_PATH = None`. Their `monkeypatch`
> then restores that `None` at teardown, which made every later test open the default
> database again. Tests that need a schema still patch `_DB_PATH` to their own `tmp_path` and
> call `init_db()`. The conftest is a safety net, not a substitute for that. After the change
> the same sweep finds **0 of 118** files creating a database, and all 118 pass alone. `[TEST]`
>
> **Nor config files, the popup image cache, or the backend.** With the database guarded, the
> sweep still found three files writing *outside* `data/` under the root (2026-09-18, traced
> with a Python audit hook on file opens, renames and mkdirs, plus `socket.connect`). `[TEST]`
> - `test_feedback_api` and `test_scan_session_api` wrote `access/config.json`, `tv/config.json`
>   and `shared/install.json`. The first config read in a process (`serialize_access_config`,
>   `load_access_app_config`) runs `shared.config.migrate_split_config_if_needed`. That calls
>   `ensure_dirs()` and writes default component configs and `install.json` wherever they are
>   missing. On a gym PC that is the installed app's folder.
> - `test_ultra_engine` made a **real HTTPS request to the production backend**
>   (`monclubwigo.tn:443`). An allow event carrying a member image (`"alice.jpg"`) reaches
>   `popup_image_cache.prefetch`, whose pool thread runs `requests.get` on the URL joined to
>   `MONCLUB_BASE_URL`. The server answered with a 950-byte HTML page, which was cached as
>   `access/cache/images/<sha1>.jpg`. `fetch_and_cache` attaches `Authorization: Bearer` with
>   whatever `load_auth_token()` returns `[CODE]`. Before the database guard, that token came
>   from the installed database. Whether any past run actually sent a real gym token is
>   `[UNVERIFIED]`.
> - `test_popup_image_negcache::test_cache_dir_resolves_under_images_when_unmemoized` created
>   the empty folders `access/cache/images` through the real
>   `current_access_runtime_db_path()`.
>
> The fixes are two more session-scoped, never-reverted guards in `tests/conftest.py`. `[CODE]`
> - **Config paths:** it repoints the `shared.desktop_paths` config-path globals, which
>   `get_desktop_path_layout()` reads at call time, to a temp root. It stubs `ensure_dirs` inside
>   `shared.config` (`save_json` creates the parents it needs). The migration still runs, from
>   the first test that reads config, and writes its defaults into the temp root. `[TEST]` The
>   conftest also resets `_MIGRATION_DONE` to `False`. That is defensive only: it is already
>   `False` after the whole suite is collected. `[TEST]`
> - **Popup images:** it points `popup_image_cache._cache_dir_cached` at a temp folder and
>   replaces its `requests` with a stub that raises. `fetch_and_cache` handles that like any
>   fetch error, so a blocked prefetch also lands in the module's negative cache. Tests of the
>   fetch still `patch.object(pic, "requests")` and clear that cache.
>   **This stub covers `popup_image_cache` only.** Any other code that fetches over the network
>   is not blocked, and a network call leaves no file under the root for the sweep to find.
> - **The negcache test:** now points `access.storage.current_access_runtime_db_path` at
>   `tmp_path` and asserts the exact resolved folder.
>
> After the change, no file among the 118 creates anything outside `data/` under the root:
> no file, no folder. The same audit hook over the per-file runs *and* over one full-suite run
> (1771 passed) records no writes there and only one `socket.connect`:
> `test_network_discovery` to `127.0.0.1`. `data/` itself is
> created at import by `_pick_data_root` and stayed empty in every per-file run. The full suite
> left nothing outside `data/` either. `[TEST]` To re-run the sweep (expected output: nothing):
>
> ```bash
> for f in tests/test_*.py; do r=$(mktemp -d); MONCLUB_ACCESS_DATA_ROOT="$r" python -m pytest "$f" -q -p no:cacheprovider >/dev/null 2>&1; find "$r" -mindepth 1 -not -path "$r/data" -not -path "$r/data/*" | sed "s|^|$f: |"; rm -rf "$r"; done
> ```
>
> The conftest guards only what is collected under `tests/`. A bare `pytest` from the repo
> root also collects `totp_file_test.py`, which imports `app.core.db` and gets no guard. Always
> run the suite with `MONCLUB_ACCESS_DATA_ROOT` set to a scratch folder. `[TEST]` / `[CODE]`

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
| `CAPACITY_FULL` | `ultra_engine.py::_capacity_admit` | `worker users_free fingerprints_free need_users need_fingers skipped withheld_fingers withheld_pins` (warn; `skipped` = new members not pushed, no user slot; `withheld_*` = fingers not written, no fingerprint slot — the member itself was pushed; §3.4d) |
| `TEMPLATE_VERSION_MISMATCH` | `zk_standalone.py::push_roster` | `worker skipped device_fp_version` (warn; templates of another algorithm version not uploaded, once per push, §3.4d) |
| `PUSH_YIELD` | `ultra_engine.py::_standalone_push_yield` | `worker member_updates pins dur_ms` — a member update or revoke served between two push chunks; `pins` = pins it handled, dropped from the rest of the push. Emitted only when one was served (§3.4e) |
| `WORKER_LINK_LOST` | `ultra_engine.py::_push_link_lost` | `worker streak delay_s` (warn; a push driver reported its link down — an abandoned STA thread or a dead event pump — and the worker reconnects after `delay_s`, absent on the first loss; `streak` counts consecutive losses, each within 60 s after the reconnect that followed the previous one; review R1-21/R2-12/R3-01, §3.4e) |
| `MAINTENANCE_SKIPPED` | `ultra_engine.py::_drain_daily_maintenance` | `worker reason` (warn, once a day; `reason=no_complete_roster`: no complete roster since the worker started, so no finger sweep and no intent read-back; review R2-05, §3.4c) |
| `FULL_SYNC_CAPPED` | `ultra_engine.py::_run_standalone_full_sync` | `worker cap pushing left` — this pass pushes `pushing` pins and leaves `left` for its continuation (§3.4e) |
| `ZKEM_PUSH_DONE` | `zk_standalone.py::push_roster` | `pushed failed skipped_pin ok chunks tpl_attempted tpl_ok tpl_failed op del_attempted del_ok not_attempted superseded` — `superseded` (2026-09-19) = pins the between-chunks caller handled itself and dropped (§3.4e) |
| `ZKEM_DELETE_DONE` | `zk_standalone.py::_do_delete_users` | `deleted failed ok dur_ms` — `dur_ms` (2026-09-19) is the one STA command's duration: no door, no event pump during it (§3.4e) |
| `FINGER_SWEEP` | `ultra_engine.py` | `worker pin source ok op cleared empty raised dur_ms` (`source` ∈ `targeted`, `daily`; `cleared` = slots that held a template, `empty` = already empty; §3.4c) |
| `REMOVAL_RETRY_SCHEDULED` | `ultra_engine.py` | `worker pins delay_s streak errored parked` (warn; a removal failed — the worker re-requests a pass after `delay_s` ≤ 300; `parked=True`: a pending removal this pass could not attempt, re-checked after 1800 s, §3.4b) |
| `PUSH_INTENT_FAILED` | `ultra_engine.py` | `worker pins err` (warn; the write-ahead intent could not be recorded — nothing was written that pass, §3.4a) |
| `PUSH_INTENT_READBACK` | `ultra_engine.py`, `device_sync.py` | `worker`/`device_id protocol ok candidates listed promoted dropped mismatched dur_ms reason missing_owned` (§3.4a; `missing_owned` = owned pins absent from the listing, reported only — nothing is re-pushed (R6-02); `ok=False` = the listing failed or was not trusted, nothing changed; `reason=no_owned_pin_listed` when it showed none of MonClub's pins) |
| `MEMBER_REVOKE_SKIPPED_NOT_OWNED` | `ultra_engine.py`, `device_sync.py` | `worker`/`device_id member_id pin protocol` (+ `row` on the full sync, `pin_scheme source` on PullSDK) (warn; P3a-2 — FINAL: MonClub cannot prove it wrote that pin, nothing deleted, revocation finished, §3.4). Replaces `MEMBER_REVOKE_OWNERSHIP_MISSING`, which is no longer emitted |
| `MEMBER_REVOKE_PIN_UNKNOWN` | `ultra_engine.py` | `member_id` (warn; pinScheme=ACCOUNT, the person's pin cannot be named — nothing removed, §3.2b) |
| `MIRROR_SKIP_NOT_FULL_RECONCILE` | `ultra_engine.py` | `worker` (was `MIRROR_SKIP_REASON`; see §3.2c) |
| `MIRROR_SKIP_NO_CAPABILITY` | `ultra_engine.py` | `worker` |
| `MIRROR_SKIP_EMPTY_ROSTER` | `ultra_engine.py` | `worker` (warn) |
| `MIRROR_SKIP_LIST_FAILED` | `ultra_engine.py` | `worker err` (warn) |
| `MIRROR_NOOP` | `ultra_engine.py` | `worker device roster` |
| `MIRROR_ABORT_FLOOR` | `ultra_engine.py` | `worker extras roster max_frac` (warn) |
| `MIRROR_PLAN` | `ultra_engine.py` | `worker would_delete sample armed` |
| `REVOKE_DONE` | `ultra_engine.py` | `pins deleted neutralised slots ok` (confirmed outcomes only) |
| `REVOKE_ABORT_FLOOR` | `ultra_engine.py` | `revoked roster ceiling max_frac abs_floor` (kept next to `REVOKE_ABORTED` for existing greps) |
| `REVOKE_ABORTED` | `push_safety.py::check_bulk_removal` | `worker device_id protocol path count roster ceiling max_frac abs_floor reason sample` (warn; P3a-2 — one removal step refused by the shared ceiling, nothing removed, state kept; `path` ∈ `standalone_revoke`, `stale`, `table_clear`; `reason` ∈ `above_ceiling`, `empty_roster`; §3.2g) |
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

Since P3b-2 a cancel that interrupts the capture itself reports `cancelled` (it used to read
`capture_failed`, so a remote ENROLL_CANCEL looked like a scanner fault). `[CODE: app.py::_remote_enroll_worker]`

`ENROLL_DONE outcome` is a closed set: `ok`, `ok_deferred_offline`, `capture_failed`,
`backend_rejected`, `sync_failed` (the **pre-flight** sync, not the targeted one),
`no_membership`, `restricted`, `not_logged_in`, `cancelled`, `no_pending_record`,
`error`. Every exit path reaches it. `[CODE: _remote_enroll_worker's finally]`

`ZKEM_PUSH_FAILED_PINS` reasons: `set_user_info_false`, `template_refused_f<N>`,
`finger_remove_false_f<N>`, `finger_remove_exception_f<N>`, `exception:<Type>`,
`chunk_wedged_or_unconfirmed`, `not_attempted` (a chunk never sent because the loop
stopped early, added 2026-09-18) and `template_version_mismatch_f<N>` (a template not uploaded
because its algorithm version differs from the terminal's, §3.4d). `[CODE: _do_push_roster, push_roster]`

### 10.2a Door queue and QR roster check (added 2026-09-18)

| Event | Where | Carries |
|---|---|---|
| `DOOR_CMD_EXPIRED` | `ultra_engine.py::_drain_commands` | `worker door` — an operator door-open dequeued after its caller gave up or its deadline passed, **not executed** (§3.1a). Which of the two is only in the log line's `reason=` |
| `SYNC_DOOR_YIELD` | `ultra_engine.py::_sync_yield_to_doors` | `worker opened expired` — operator opens drained between push chunks; `opened` = taken and not skipped: handed to the driver whatever it answered (on an MB2000 a `timeout` one may never have reached `ACUnlock`, §3.1a), or answered `not connected` without a call, `expired` = skipped. `expired` added 2026-09-18; before, `opened` counted every queued entry (§3.1a) |
| `QR_ROSTER_CHECK` | `access_verification.py::record_totp_roster_check` | `source verdict mode allowed` — one per QR scan whose verdict is not `in_roster`; no member id, name or credential (§3.1b) |
| `QR_ROSTER_SUMMARY` | `access_verification.py::maybe_log_totp_roster_summary` | `since in_roster in_roster_by_account not_in_roster roster_empty roster_behind refused` — running totals since the process started, at most once an hour (§3.1b) |

`[TEST: test_door_open_deadline.py::test_an_expired_open_is_reported_expired_and_releases_its_waiter;
test_totp_roster_check.py::test_record_counts_one_scan_and_logs_no_member_identity,
::test_the_summary_line_is_logged_at_most_once_per_interval]`

### 10.2b Date flips, the clock, QR days and renewals (P3b-1, added 2026-09-19)

| Event | Where | Carries |
|---|---|---|
| `DATE_FLIP` | `app.py::_apply_date_flips` | `source gym_date applied_before held restored promoted moved starters reasons trusted skipped ultra dur_ms` — one per flip that moved rows, and always one at start-up (with `skipped=no_state|untrusted|no_gym_date` when nothing could move). `reasons` = `hold reason:count,…`; `ultra` = a running ULTRA engine was asked for a full pass (§3.8) |
| `DATE_FLIP_FAILED` (warn) | `app.py::_apply_date_flips` | `source err` — the flip raised; nothing was applied, the next trigger retries |
| `CLOCK_SUSPECT` (warn) | `app.py::_apply_date_flips` | `reason gym_date pc_date` — the clock verdict turned suspect (`reason=behind|ahead`, §3.8) |
| `CLOCK_OK` | `app.py::_apply_date_flips` | `gym_date` — the verdict turned back to normal |
| `SYNC_V2_REJECTED` (warn) | `db.py::_apply_protocol2_save` | `reason` — a malformed protocol-2 part; the windows stop being trusted until the next good v2 answer (§3.8) |
| `QR_DATE_CHECK` | `access_verification.py::record_totp_roster_check` | `source verdict=not_today` — a QR refused for its days (§3.1b "Allowed days"); no member identity. `QR_ROSTER_SUMMARY` gains `not_today` |
| `RENEWAL_HOLD` | `ultra_engine.py` (`worker=`), `device_sync.py` (`device_id=`) | `held removed_after_push kept` — one per pass that held a renewing member's old pin until the new one was written (§3.4f). `kept>0` = old pins left for a later pass: the new pin was not confirmed, or removing them with the leavers removed first would exceed the removal ceiling (then also `REVOKE_ABORTED path=renewal_release`, §3.2g) |

### 10.2c Driver leases and Confirm removal (P3b-2, added 2026-09-26)

| Event | Where | Carries |
|---|---|---|
| `REMOVAL_DEFERRED` (warn) | `push_safety.py::check_bulk_removal`, `ultra_engine.py::_run_standalone_member_revoke` | `worker device_id protocol path count reason member_id` — a removal refused because the turnstile is add-only (`reason=add_only`) or being handed over (`handover_release`); retryable, state kept, NOT a `REVOKE_ABORTED` (§3.9) |
| `REMOVAL_CONFIRMED` (warn) | `push_safety.py::check_bulk_removal` | `worker device_id protocol path count roster ceiling` — an above-ceiling step let through once by a Confirm-removal approval for exactly that pin set (§3.2g) |
| `MIRROR_SKIP_REMOVALS_DEFERRED` | `ultra_engine.py::_maybe_mirror_reconcile` | `worker` — MIRROR skipped on an add-only / handed-over turnstile |
| `MEMBERS_MISSING` (warn) | `app.py::_report_missing_members` | `source action count sample` — members the server lists and this PC lacks (§3.6 "The missing-member check", lane B 2026-09-26). `source` ∈ `delta`, `full`, `windows`, `digest`; `action` ∈ `full_refresh` (a full member refresh asked), `probe` (a digest mismatch: one delta answer asked; `count`/`sample` empty), `suppressed` (a full answer's rows this PC could not store — reported once, never refreshed again); `sample` = up to 20 membership ids |
| `PIN_SCHEME_PASS_STOPPED` (warn) | `ultra_engine.py::_pass_scheme_stopped` (`worker=ULTRA:<id>`, any ULTRA worker), `device_sync.py::_raise_if_pin_scheme_switched` (`device_id=`, the DeviceSync engine) | `path scheme` — a push pass wrote nothing (more) because its pins were derived under `scheme` and the database records another pinScheme now (§3.2e, lane B 2026-09-26). With `worker=`: `full_sync` (pass start — MB2000 or a PullSDK panel in ULTRA), `push`, `between_chunks`, `member_sync`, `account_revoke` (MB2000); with `device_id=`: `sync`, `removal`, `batch`, `member_sync` (PullSDK, review R4-1). The app refreshes the worker copies and queues the next pass; one of these right after a `PIN_SCHEME_SWITCH` is expected |

The v2 runtime logs on `zkapp.v2*` loggers with a `[V2]` prefix (roles changed, availability, commands,
releases, restores, read-backs, loss checks); none is a `[T]` event.

### 10.2d The Erase-content wizard (lane 1, added 2026-09-27)

| Event | Where | Carries |
|---|---|---|
| `ERASE_STEP` | `erase_wizard.py::EraseWizard._step`, `::refill` | `run device_id step ok` + the step's own scalar fields: `n_<table>` counts (before/after; `-1` = unreadable), `path sha256 rows` (backup), `code error uncertain` (a failed erase), `verified why`, `state holdKept note` (`finish`; `note` `PIN_SCHEME_CHANGED…` when a refill was held back, and since lane 1c `HELD_SCHEME_MOVED…` / `HELD_SCHEME_UNREADABLE…` when a run that stopped before its first delete kept the hold after the scheme moved or did not read -- since lane 1d that hold row reads `erase-scheme-moved` and survives a restart, and when that durable write failed, or the turnstile's row is gone, the note's code is `HELD_SCHEME_MOVED_SESSION` / `HELD_SCHEME_UNREADABLE_SESSION` and it ends `-- NOT kept across a restart of Access (…)`; the `error` codes of a `FAILED` run gain `NOT_REFILLED_UNKNOWN`, `NOT_REFILLED_CHANGED`, `KEEP_MARK_NOT_WRITTEN` and `PIN_SCHEME_CHANGED`), `mode pinScheme` (refill), `state/intents/mirror/readd/results/removals_logged/kept` (forget), `invalidated kept` (keep_records), `invalidated` (records_invalidated, after an `INCOMPLETE`), `resultsReset kept` (`erase_recorded`, lane 1b), `skipped=empty` (an `erase_<table>` that counted 0, lane 1b), `count` (`not_refilled`, lane 1c: the people the erase removes and the refill does not put back — a count, never a pin or a name). `step` ∈ `hold`, `idle`, `counts_before`, `backup`, `not_refilled`, `erase_recorded`, `erase_<table>`, `erase_users`, `erase_fingerprints`, `erase`, `counts_after`, `forget`, `keep_records`, `records_invalidated`, `wipe_reported`, `refill`, `finish` (`note` also `HELD_BEFORE…`), `refill_pressed` (`run=refill`, the Refill button: `pin_scheme requested invalidated`), `released_at_start` (`device_hold.load`, lane 1b: `run` = the run that stopped before any delete), and `backup_deleted` (`prune_erase_backups`, owner decision 2026-09-27: `run` = the run whose folder went, `state`). One line per step; the same step is written to the run folder's `run.json` (§3.2h) — except `released_at_start` and `backup_deleted`, which have no run in this process. No member name, card or template. The `error` / `why` texts may carry up to 5 member pins (`ERASE_FAILED`, `NOT_VERIFIED`, `NOT_REFILLED_CHANGED` since lane 1c, `ADMIN_PIN_IN_ROSTER` up to 3 admin pins) — never a listed value that failed the pin check: `BACKUP_UNTRUSTED` carries a count only since lane 1b (a wrong out-param order lists names as pins; review F29). |

`REVOKE_DONE pins` now counts only what the removal step removed first; held old pins removed after
the push are in `RENEWAL_HOLD removed_after_push` (§3.4f). `REVOKE_ABORTED` has a new `path`,
`renewal_release`: released holds kept because, with the pins removed first, they would exceed the
ceiling (§3.2g).
`[TEST: tests/test_p3b1_app_wiring.py, tests/test_qr_allowed_days.py, tests/test_renewal_ordering.py,
tests/test_protocol2_save_and_flip.py]`

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

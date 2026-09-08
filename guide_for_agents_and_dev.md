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
| `DeviceSyncEngine._normalize_device` allowlist | §6.2 The inert-patch rule |
| Anything currently marked `UNVERIFIED` that you actually prove or disprove | §7 Unverified |
| A `[T]` telemetry event name, or the fields it carries | §10 Telemetry events |
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

### 3.3 How ULTRA pushes to a *PullSDK* device (non-obvious)

For PullSDK devices, ULTRA has no push implementation of its own. It copies the device
payload, **overwrites `accessDataMode` to `"DEVICE"`**, and hands that copy to a private
`DeviceSyncEngine` instance so the existing push path can be reused.
`[CODE: ultra_engine.py, two sites — device_copy["accessDataMode"] = "DEVICE"]`

If you are ever tracing why a device is being synced in a mode it is not in, this is
why. The protocol guard still fires inside that reused engine — which is exactly why
the standalone path uses `_run_standalone_full_sync` → `push_roster` instead.

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

```bash
python -m pytest tests/ -q --ignore=tests/_pydeps --ignore-glob='**/pytest_tmp_*' --ignore-glob='**/.tmp_pytest*'
```

`--ignore=tests/_pydeps` is **required** — that directory holds vendored third-party
packages whose own tests break collection. There is no `pytest.ini`, so the flag is not
applied for you. The two `--ignore-glob` flags skip the `tests/pytest_tmp_*` /
`tests/.tmp_pytest*` scratch directories that stale permission-denied temp folders leave
under `tests/` in some working copies; they are not part of the suite. Last run:
**1074 passed** (2026-09-05, after the Phase C progress/yield fix). `[TEST]`

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

**Expected:** every match inside `app/core/ultra_engine.py` — currently two real calls
plus one docstring mention. A match in any other file means the rule has changed and
this guide is out of date.

Match on `\.push_roster(`, not the bare word: `push_roster` also appears in an
explanatory comment in `local_access_api_v2.py`, and a looser grep makes an intact rule
look broken.

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
| `MEMBER_REVOKE_DONE` | `ultra_engine.py` | `member_id pin mode ok` (`mode=deleted|neutralised`) |
| `MEMBER_REVOKE_FAILED` | `ultra_engine.py` | `member_id pin` |
| `MEMBER_REVOKE_OWNERSHIP_MISSING` | `ultra_engine.py` | `member_id pin` |
| `REVOKE_DONE` | `ultra_engine.py` | `pins deleted neutralised slots ok` (confirmed outcomes only) |
| `REVOKE_ABORT_FLOOR` | `ultra_engine.py` | `revoked roster ceiling max_frac abs_floor` |
| `REVOKE_SKIP_EMPTY_ROSTER` | `ultra_engine.py` | (no fields) |
| `ZKEM_PUSH_FAILED_PINS` | `zk_standalone.py` | `count by_reason pins truncated` |
| `ZKEM_PUSH_TPL_REFUSED` | `zk_standalone.py` | `pin finger size template_version device_fp_version fp_used fp_capacity` |
| `ZKEM_TPL_VERSION_MISMATCH` | `zk_standalone.py` | `pin finger template_version device_fp_version` |
| `ZKEM_PUSH_WEDGED` | `zk_standalone.py` | `chunk chunks members consecutive pushed_before err` |
| `ZKEM_PUSH_RECONNECT` | `zk_standalone.py` | `chunk ok err` |
| `ZKEM_PUSH_ABANDONED` | `zk_standalone.py` | `consecutive chunk chunks pushed` |
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

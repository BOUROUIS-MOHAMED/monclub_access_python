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
| `supports_open_door` | absent ⇒ callers default `True` | `False` `[CODE]` | Whether the driver may issue a door-open. See §7. |
| `owns_event_source` | — | `True` `[CODE]` | Driver owns its own event delivery (push) rather than being polled. |
| `supports_device_params` | — | `False` `[CODE]` | `get_device_param` / `set_device_param` are meaningful. |

Callers read these as `getattr(drv, "flag", True)` so a driver predating a flag keeps
the old behaviour. `[CODE: device_attendance.py, ultra_engine.py,
local_access_api_v2.py]`
`[TEST: test_device_sync_protocol_guard.py::TestTransactionTableCapability]`

**A flag being `False` does not mean "unimplemented".** `ZKStandaloneDevice._do_open_door`
implements the real `ACUnlock` call; `supports_open_door = False` only decides whether
the app is *allowed* to make it. See §7.

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

### `supports_open_door = False` on ZK_STANDALONE `[UNVERIFIED — HARDWARE-GATED]`

`ACUnlock` is documented SDK-wide but has never been confirmed on MB2000 hardware. It
ships **off**: a door command that silently does nothing is worse than one that reports
it cannot. `[CODE]`

Enable per-machine without a rebuild via **`MONCLUB_ZK_STANDALONE_OPEN_DOOR`** — but
verify first with `tools/mb2000_scripts/9_unlock_door.ps1`, which fires the identical
`ACUnlock(1, ds)` call. Listen for the relay **and** confirm the turnstile physically
releases: `ACUnlock` returning `True` with no release is a wiring fault, not an SDK one.
Enabling it logs a loud warning, deliberately. `[CODE: _open_door_override]`

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
- **On-site script pack**: `tools/mb2000_scripts/` (`0_MENU.ps1` plus 11 scripts — COM
  registration, device info, ZK9500 enrol, push, live monitor, unlock, backup/restore,
  portability test). Use these to establish ground truth on hardware **before** changing
  driver code. `[CODE]`

---

## 9. Verifying this guide

These are runnable, so "is this still true" is a command rather than a judgement.

```bash
python -m pytest tests/ -q --ignore=tests/_pydeps
```

`--ignore=tests/_pydeps` is **required** — that directory holds vendored third-party
packages whose own tests break collection. There is no `pytest.ini`, so the flag is not
applied for you. Last run: **833 passed** (2026-08-29). `[TEST]`

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
python -m pytest tests/test_device_sync_protocol_guard.py tests/test_device_driver_factory.py tests/test_zk_standalone_driver.py -q
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

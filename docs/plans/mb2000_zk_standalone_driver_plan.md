# MB2000 ZK_STANDALONE Driver — Implementation Plan (Step 2)

> **Audience:** an implementing AI agent (or developer) executing largely unsupervised.
> Follow phases IN ORDER. Every claim below is evidence-grounded (file:line or cited URL).
> Line numbers may drift — always locate by the quoted symbol/string first, line second.
>
> **Status of prerequisites:** Step 1 (driver factory) is DONE, committed `ee1eb43`:
> `app/sdk/device_driver.py` has `DeviceProtocol{ZK_PULLSDK, ZK_STANDALONE}`,
> `resolve_device_protocol()`, `get_driver()` (ZK_STANDALONE currently raises
> `UnsupportedDeviceProtocolError`), and a `runtime_checkable DeviceDriver` Protocol.

---

## 0. Context — the target gym and hardware

- New gym: **3 turnstiles**, each with its own **ZKTeco MB2000** multi-bio terminal, each = **1 door**.
  **2 turnstiles = ENTRY, 1 = EXIT.** Members verify by **FINGERPRINT + RFID card** on the terminal.
- Fingerprints are enrolled at the desk on a **ZK9500 USB reader** (already working:
  `app/sdk/zkfinger.py` → `enroll_3_samples()` ~line 813, posts to backend via
  `create_user_fingerprint`, `app/api/monclub_api.py` ~460).
- MB2000 facts (datasheet https://amcoegypt.net/wp-content/uploads/2021/03/MB2000.pdf +
  https://www.zkteco.eg/MB_Series/MB2000): ZKFinger **VX10.0** + ZKFace 7.0; 3,000 FP / 3,000 cards /
  100,000 logs; TCP/IP (port 4370); **9-digit user ID**; lock/door-sensor/exit-button contacts;
  **NO QR reader**; ADMS/push optional; ID/Mifare card reader is a factory option.
- SDK: ZKTeco **Standalone SDK** = `zkemkeeper.dll` COM, **32-bit only**
  (https://github.com/ZKTeco/Standalone-SDK, "Communication Protocol SDK 32bit Ver 6.2.4.11").
  Protocol reference: https://github.com/adrobinoga/zk-protocol.
- **The production Access process is 32-bit Python by hard build gate**
  (`packaging/desktop_components.ps1:28` `Requires32BitPython = $true`;
  `build_release.ps1` ~171–179 aborts unless `struct.calcsize('P')*8 == 32`), and
  **pywin32 + comtypes already ship** (`requirements.txt` lines ~8–9, `MonClubAccess.spec` ~60–61).
  → in-process COM is possible; no sidecar is mandatory.
- Existing PoC: `app/core/zkemkeeper_scanner.py` — ONE-SHOT card read via a 32-bit PowerShell
  subprocess (stdout line protocol `READY`/`CARD:`/`ERROR:*`, pump threads + hang deadline,
  ~lines 42–108 and 199–289). Reusable as the **fallback sidecar pattern**, not as the driver.

### Repos
- ACCESS (desktop): `C:\Users\mohaa\Desktop\monclub_access_python`
- DASHBOARD: `C:\Users\mohaa\Desktop\mon_club_dashboard`
- BACKEND: `D:\projects\MonClub\monclub_backend`
- MOBILE: `C:\Users\mohaa\Desktop\wigo` (needs **no changes**; it already reads `direction`
  from door history — `lib/data/models/gym_door_access_history.dart:19,75,90`)

### THE FROZEN INVARIANT
**The existing C3-200 gym (PullSDK/ULTRA) must not change behavior.** Every change here is
additive behind `get_driver()`; `resolve_device_protocol()` defaults everything unrecognised
to `ZK_PULLSDK`. Never modify the PullSDK runtime path, `device_sync.py` PullSDK table writes,
or `_poll_with_watchdog` semantics for poll drivers.

---

## 1. DECISIONS ALREADY MADE — implement these, do not re-litigate

| # | Decision | Rationale (evidence) |
|---|----------|----------------------|
| D1 | **Transport = zkemkeeper COM in-process** (32-bit prod process + pywin32/comtypes already shipped). The 32-bit PowerShell **sidecar is the designed fallback**, selected only if on-site GATE 1 fails. **pyzk is FORBIDDEN in the shipped app** (GPL-2.0 license contamination); it may be used on-site only as a throwaway diagnostic from a separate venv. | build gate + deps cited above; pyzk GPL |
| D2 | **Event acquisition = `ReadRTLog`/`GetRTLog` POLLING with a registered COM sink** (`RegEvent(1, 1)` → `OnAttTransactionEx`) on a dedicated STA thread, keeping `pythoncom.PumpWaitingMessages()` in the loop as belt-and-braces. Polling mode fires the sink synchronously from `GetRTLog`, removing the Windows-message-pump dependency that silently kills naive service integrations. | TFT SDK manual (usermanual.wiki/Pdf/TFTSDKManual.1477075900); STA requirement http://styjun.blogspot.com/2019/07/how-to-fix-issue-of-zkemkeeperdll.html |
| D3 | **Event delivery shape:** the driver owns one STA event thread per device filling an internal `queue.Queue`; it exposes `start()`/`stop()` lifecycle AND implements **`poll_rtlog_once()` as a non-blocking drain of that queue**. This preserves "driver owns its event source" while reusing `UltraDeviceWorker`'s loop, `_poll_with_watchdog`, dedupe, cooldown, popup/history queues, and `note_poll` telemetry **unchanged**. Added latency ≤ ~300ms = the C3 idle poll cadence. | resolves the Protocol contradiction; worker loop at `ultra_engine.py` run() ~399–540 |
| D4 | **Identity mapping:** device user **PIN = backend user id** (numeric; MB2000 max 9 digits — add an explicit guard). The driver maintains a **pin→card map** built at `push_roster` time (persisted locally) and **emits `cardNo` = RFID card number** on every event, so ALL downstream (cooldown keyed on cardNo `ultra_engine.py` ~1416/1439, staff-card check, member resolution, history, uploader, popup photo) stays byte-compatible with C3 events. Unknown-pin events emit `cardNo="ZKPIN:<pin>"` + a telemetry warn, never dropped silently. | OnAttTransactionEx carries EnrollNumber=PIN for both FP and card verifies |
| D5 | **COM call funneling:** ALL zkemkeeper calls (connect, GetRTLog loop, ACUnlock, user/template writes, time get/set) execute **on the driver's single STA thread**. Public driver methods are blocking wrappers that post a command (with deadline) to a driver-internal command queue. Calling a non-marshaled COM interface cross-thread raises "interface marshalled for a different thread" — the worker calls `open_door` from ITS thread (`ultra_engine.py` `_drain_commands` ~844–869), so the funnel is mandatory. | COM apartment rules; PoC proved zkemkeeper can hang → deadline for free |
| D6 | **Push/sync seam:** branch `_drain_full_sync_commands` **by protocol BEFORE** the raw-sdk extraction (`raw_sdk = getattr(self._sdk, "_sdk", None)` — `ultra_engine.py` ~1079). ZK_STANDALONE calls `driver.push_roster(users, templates_by_pin)` consuming `DeviceSyncEngine._collect_templates_for_pin` output verbatim (`device_sync.py` ~1252–1301, protocol-neutral). **NEVER** route an MB2000 into `run_one_device_on_connected_sdk` or the `templatev10`/`userauthorize` writers. Per-member sequence: `SetStrCardNumber` → `SSR_SetUserInfo` → per finger (`SSR_DeleteEnrollData(pin, fingerIdx)` if occupied → `SetUserTmpExStr(pin, fingerIdx, Flag=1, base64Tmp)`). **Delta pushes during opening hours WITHOUT `EnableDevice`; `EnableDevice(false/true)`-bracketed full reconcile only via the 22:00 forced sync / manual sync.** MB2000 is the sole verifier at this gym — a UI-locked terminal means members physically cannot enter. | SDK manual; ZKTeco FAQ: template upload requires the finger slot to be EMPTY (delete-before-reupload) |
| D7 | **Direction:** authoritative source = **per-device door preset** (dashboard: ENTRY-1=IN, ENTRY-2=IN, EXIT=OUT). `AttState` is telemetry cross-check ONLY. The backend model already exists end-to-end (`GymDeviceDoorPreset.direction`, V53; `GymAccessDoorHistory.direction`; dashboard editor + history column all shipped) — only mappers/keying/projections are broken (Phase 2/3 fixes). The driver stamps `raw["direction"]` so the existing uploader (`device_attendance.py` `_direction_from_raw` ~182–200 picks up a `direction` key first; `_serialize_row_for_backend` ~705) needs **zero changes**. | direction investigation, all cited below |
| D8 | **Capability surface:** driver-level flags now: `owns_event_source=True`, `supports_device_params=False`, `supports_open_door` (bool, set after GATE 4). All PullSDK-shaped Protocol methods on the MB2000 driver return **inert values (None/0/[]), never raise** — the shipped /devices control panel calls `get_device_param`/`set_device_param` via the worker SDK queue and must render "unsupported", not crash. | control-panel Slice 1 exists; Protocol members at `device_driver.py:72–85` |
| D9 | **Backend V88 scope = one PR:** `deviceProtocol` + `deviceCapabilities` columns AND all **three** device mappers updated together (`GymDeviceController.toDto`/`applyDtoToEntity`, `AccessPatchBundleService`, `GymAccessController.toDeviceDto` — the known-lossy one). The membersType incident was exactly one missed mapper. | mapper list verified; GymAccessController.toDeviceDto already omits ultra* fields |
| D10 | **Local protocol override:** desktop config map `device_id → protocol` consulted by `resolve_device_protocol` BEFORE the payload key. Decouples hardware bring-up from the backend deploy; instant kill-switch. | sequencing safety |

---

## 2. PHASE 1 — BACKEND (deploy FIRST, before any desktop build that reads new fields)

### 2.1 Flyway V88 — protocol + capabilities
File: `src/main/resources/db/migration/V88__add_device_protocol_and_capabilities.sql`
- `ALTER TABLE gym_device ADD COLUMN device_protocol VARCHAR(30) NOT NULL DEFAULT 'ZK_PULLSDK';`
- `ALTER TABLE gym_device ADD COLUMN device_capabilities TEXT NULL;` (JSON as TEXT — verify prod
  MySQL-vs-MariaDB first; if MySQL 8 use `JSON`. Check the JDBC URL / `SELECT VERSION()`.)
- Use the idempotent `information_schema.COLUMNS` guard pattern from
  `V83__add_manual_sync_and_pending.sql` (VARCHAR from birth — the V17 ENUM-widening wall:
  `V17__widen_gym_device_access_data_mode.sql`).
- Check Flyway config for the duplicate prefixes V56/V60 before assuming V88 validates.

### 2.2 Entity + DTO
- `Models/GymDevice.java`: add `deviceProtocol` (String, default `"ZK_PULLSDK"`),
  `deviceCapabilities` (String/JSON, nullable). GymDevice **already has**
  `totpEnabled`(~:179) `rfidEnabled`(~:182) `fingerprintEnabled`(~:185) `faceIdEnabled`(~:188) — do not duplicate.
- `Models/DTO/GymDeviceDto.java`: add the same two fields.

### 2.3 ALL THREE device mappers (same PR — D9)
1. `Controllers/GymDeviceController.java` — `toDto` (~264–338) and `applyDtoToEntity` (~345–419).
2. `Services/AccessPatchBundleService.java` — device DTO builder (~884–943).
3. `Controllers/GymAccessController.java` — `toDeviceDto` (~261–334). **This mapper is known-lossy**
   (already omits `ultraSyncIntervalMinutes`/`ultraTotpRescueEnabled`/`ultraRtlogEnabled`/
   `monthlyPassLimit`/`antiFraudeDailyPassLimit`) — add the new fields AND fix the pre-existing omissions.

### 2.4 Direction fixes (required for 3-device correctness — D7)
1. **Bulk-save keying bug:** `GymAccessController.bulkSaveGymAccessHistory` (~741–804) builds
   `doorDirectionMap` keyed by **doorNumber only** (~768–775, comment "if two devices share a door
   number, first wins"). With 3 MB2000s each having doorNumber=1 and one being OUT, **stored direction
   is wrong** → silently corrupts every analytics consumer that reads the stored column
   (`AccessComputeService` tailgating/inOutBalance/dwell/peak-occupancy, `FactTableComputeService`
   in_count/out_count, `DailyListComputeService`, 3 PDF reports, and the `directionLike` filter
   `GymAccessDoorHistorySpecifications.java:99–102`). FIX: key by `deviceId + ":" + doorNumber`
   (same keying the READ path already uses at ~993–1006), lookup via
   `element.getDeviceId() + ":" + element.getDoorId()`, fallback `element.getDirection()`.
2. **Preset mapper omissions (1 line each):** add `.direction(p.getDirection())` to
   `GymAccessController.toPresetDto` (~247–259) and `AccessPatchBundleService.toPresetDto` (~828–839).
   `GymDeviceDoorPresetDto` already has the field (~:32, default "IN").
3. **Optional consistency fix (noticed in passing):** `AccessComputeService.computePerInfrastructureCapacity`
   ~line 449 looks up a device-keyed map with `e.getDoorId()` where `e.getDeviceId()` is meant —
   events at the new gym would be misattributed for capacity stats.

### 2.5 Backend acceptance
- `mvn compile` clean; a round-trip test (or manual REST check) that a device created with
  `deviceProtocol="ZK_STANDALONE"` returns it from ALL THREE endpoints (CRUD get, patch bundle,
  active-member/get_gym_users response).

---

## 3. PHASE 2 — ACCESS local plumbing (NO hardware needed)

### 3.1 `sync_devices` protocol column — the 5-hop chain (every hop silently defaults!)
The chain: backend column → mappers (Phase 1) → **ACCESS ingest INSERT** → **sync_devices column**
→ **`_coerce_device_row_to_payload` projection** (fixed key list, drops unknown keys — `app/core/db.py`
~4312–4357) → `resolve_device_protocol`. Missing ANY hop = the MB2000s silently route to PullSDK
(safe connect-fail backoff, but the gym is dead). Implement each hop + its test:
1. `_ensure_column(conn, "sync_devices", "device_protocol", "device_protocol TEXT")` next to the
   existing sync_devices ensures (~db.py:972–1017 region), and add to the CREATE TABLE.
2. Persist `d.get("deviceProtocol")` in the devices ingest INSERT (find the sync_devices upsert).
3. Add `"deviceProtocol": row["device_protocol"]` to `_coerce_device_row_to_payload`.
4. **TEST (mandatory):** synthetic backend device dict with `deviceProtocol="ZK_STANDALONE"` survives
   ingest → `list_sync_devices_payload()` → `resolve_device_protocol()` returns ZK_STANDALONE.

### 3.2 Local protocol override (D10)
In `resolve_device_protocol` (`app/sdk/device_driver.py`): before reading the payload key, consult a
config override map (e.g. `cfg`/env/local JSON: `{device_id: "ZK_STANDALONE"}`). Keep the default-safe
behavior otherwise. TEST: override wins over payload; absent override falls through.

### 3.3 Door-preset direction threading (D7)
1. `_ensure_column(conn, "sync_device_door_presets", "direction", "direction TEXT")`
   (next to the favorite_* ensures, `db.py` ~1129–1131).
2. Persist `p.get("direction")` in the doorPresets ingest INSERT (`db.py` ~2764–2783).
3. Include `direction` in BOTH projections: `_build_synced_door_presets_index_from_rows` (~db.py:4207)
   and `list_sync_device_door_presets_payload` (~db.py:4231; also check ~5538–5551 — verified to
   currently OMIT direction).
4. `settings_reader.normalize_device_settings` needs NO change (forwards `door_presets` verbatim ~496–498).
5. TEST: preset with direction=OUT survives ingest → device settings → readable by the worker.

---

## 4. PHASE 3 — the driver (`app/sdk/zk_standalone.py`) + engine seams (fake-testable, NO hardware)

### 4.1 Driver skeleton — `class ZKStandaloneDevice`
Must satisfy the `DeviceDriver` Protocol (`app/sdk/device_driver.py:57–85`). Shape:

```python
class ZKStandaloneDevice:
    # capability flags (D8)
    owns_event_source = True
    supports_device_params = False
    supports_open_door = False   # flipped to True only after GATE 4 passes

    def __init__(self, device_payload, logger=None): ...
    # lifecycle
    def connect(self) -> bool: ...          # posts CONNECT cmd to STA thread, waits w/ deadline
    def disconnect(self) -> None: ...       # posts STOP; joins STA thread with timeout
    @property
    def is_connected(self) -> bool: ...
    def ensure_connected(self) -> bool: ...
    def start(self) -> None: ...            # starts the STA event thread (idempotent)
    def stop(self) -> None: ...             # alias of disconnect for the event source
    # event source (D3): non-blocking drain of the internal queue
    def poll_rtlog_once(self) -> list[dict]: ...
    # commands (all funneled through the STA thread — D5)
    def open_door(self, *, door_id: int, pulse_time_ms: int, timeout_ms: int = 4000) -> bool: ...
    def get_device_time(self) -> float | None: ...     # zkemkeeper GetDeviceTime — verify in SDK CHM;
    def set_device_time(self, epoch: float) -> bool: ...#  if absent, return None/False (clock discipline no-ops)
    # roster push (D6)
    def push_roster(self, users: list[dict], templates_by_pin: dict[str, list[dict]],
                    *, bracket_enable_device: bool = False) -> dict: ...
    # PullSDK-shaped members — INERT, never raise (D8)
    def get_device_param(self, *, items, initial_size=None): return None
    def set_device_param(self, *, items): return 0
    def get_table_count(self, *, table, filter_expr="", options=""): return 0
    def delete_table_rows(self, *, table, data="", options=""): return 0
    def read_transaction_rows(self, *, options="new record", initial_size=None): return []
```

**STA thread body** (the ONLY place COM is touched):
```
pythoncom.CoInitialize()
zk = win32com.client.DispatchWithEvents("zkemkeeper.ZKEM", _SinkClass)   # try ZKEM then CZKEM ProgID
ok = zk.Connect_Net(ip, port)          # SetCommPassword(commkey) FIRST if configured
zk.RegEvent(1, 1)                      # bit 1 = OnAttTransactionEx (add 2048 OnHIDNum only if needed)
loop:
    drain command queue (open_door→ACUnlock(1, delay_ds); push cmds; time cmds)
    zk.ReadRTLog(1)
    while zk.GetRTLog(1): pass         # fires the sink synchronously
    pythoncom.PumpWaitingMessages()    # belt-and-braces
    sleep(0.3)
on stop: Disconnect(); pythoncom.CoUninitialize()  # ON THIS THREAD ONLY
```
Every public method = post `(cmd, args, result_event, result_box)` + wait with deadline
(mirror the worker's own `_cmd_queue` pattern, `ultra_engine.py` ~760–789). `connect()` itself is a
command with a hard deadline — the PoC proved `Connect_Net` can hang (`zkemkeeper_scanner.py` deadline
pattern ~199–289). Reconnect: exponential backoff; a died pump thread emits telemetry
`ZKEM_EVT_SINK_DOWN` and flips `is_connected` False so the worker's normal reconnect logic drives recovery.

### 4.2 Event normalization (in the driver, NEVER the engine)
`OnAttTransactionEx(EnrollNumber, IsInValid, AttState, VerifyMethod, Y, M, D, H, Mi, S, WorkCode)`
(signature: TFT SDK manual, usermanual.wiki/Pdf/TFTSDKManual.1477075900) → NormalizedEvent dict,
shape identical to `PullSDKDevice.poll_rtlog_once` (`app/sdk/pullsdk.py` ~1168–1230):
```python
{
  "eventId":  f"{Y:04d}-{M:02d}-{D:02d} {H:02d}:{Mi:02d}:{S:02d}|{cardNo}|{evtype}|1|{pin}|zkem|{seq}",
  "doorId":   1,                        # one door per MB2000
  "eventType": "0" if IsInValid == 0 else "zkem_invalid",   # "0" == ALLOW for _process_event (~1484)
  "cardNo":   card_from_pin_map(EnrollNumber) or f"ZKPIN:{EnrollNumber}",   # D4
  "eventTime": f"{Y:04d}-{M:02d}-{D:02d} {H:02d}:{Mi:02d}:{S:02d}",         # match PullSDK format
  "table":    "zkem",
  "rawRow":   {"pin": EnrollNumber, "attState": AttState, "verifyMethod": VerifyMethod,
               "workCode": WorkCode, "direction": preset_direction,          # D7 — from synced door preset
               "scan_mode_hint": verify_method_to_scan_mode(VerifyMethod)},
}
```
`verify_method_to_scan_mode` must map **BOTH value spaces** (they shift under multi-verify mode):
normal: 0=password, 1=**fingerprint**, 2=**card**; multi-verify: 0=FP, 3=RF(card), 1=PIN, 2=PW …
(full tables in the TFT manual). Map defensively: {1: FP, 2: CARD, 3: CARD, 0: PASSWORD}, log raw value.
`AttState` (0=in,1=out…) goes to telemetry cross-check ONLY — direction comes from the preset (D7).
`eventTime` is device-local; tz offset comes from the device payload like the C3
(`timezoneOffsetSeconds`, `ultra_engine.py` ~185–192) so `parse_event_time_to_epoch` works unchanged.

### 4.3 Factory wiring
`app/sdk/device_driver.py` `get_driver()`: replace the `UnsupportedDeviceProtocolError` raise for
ZK_STANDALONE with a lazy import + `return ZKStandaloneDevice(device_payload, logger=logger)`.
Update `tests/test_device_driver_factory.py`: standalone no longer raises; returns the new driver;
`isinstance(drv, DeviceDriver)` holds; PullSDK default path unchanged.

### 4.4 Worker integration (`app/core/ultra_engine.py`) — minimal seam
1. After a successful `_connect()` (~661), if `getattr(self._sdk, "owns_event_source", False)`:
   call `self._sdk.start()`. In `_disconnect()`: call `stop()` if present.
2. The main loop needs NO structural change: `_poll_with_watchdog` → `poll_rtlog_once()` now drains
   the driver's internal queue (fast, non-blocking) → `_process_event` per event → popups/history/
   cooldown/telemetry all reused verbatim (D3). While waiting, the worker sits in telemetry states
   in `_idle_states` (`telemetry.py` ~488) — no false WORKER_STALL.
3. **Full-sync protocol branch (kills a verified LIVELOCK):** in `_drain_full_sync_commands`, the
   current code does `raw_sdk = getattr(self._sdk, "_sdk", None)` (~1079) and on None it
   **re-queues `request_full_sync` forever** — `_mark_full_sync_finished` never fires and manual-sync
   pending counters never ack. Branch BEFORE that line:
   ```python
   if getattr(self._sdk, "owns_event_source", False):      # ZK_STANDALONE
       users, templates = _build_standalone_roster(filtered_cache, device_copy)  # reuse
       result = self._sdk.push_roster(users, templates)     # _collect_templates_for_pin output
       ok = bool(result.get("ok")); ...
       self._mark_full_sync_finished(...); self._notify_full_sync_finished(...)  # ALWAYS, both outcomes
       continue
   ```
   Template collection reuses `DeviceSyncEngine._collect_templates_for_pin` (`device_sync.py`
   ~1252–1301 — pure data assembly, `[{fingerId, templateVersion, templateData, templateSize}]`).
4. `push_roster` internals (in the driver, on the STA thread — D6): per member
   `SetStrCardNumber(card)` → `SSR_SetUserInfo(1, pin, name, "", 0, True)` → per finger:
   if occupied `SSR_DeleteEnrollData(1, pin, 1, fingerIdx)` → `SetUserTmpExStr(1, pin, fingerIdx, 1, b64)`.
   PIN guard: reject/telemetry any pin > 9 digits (MB2000 limit). Full reconcile path additionally
   brackets with `EnableDevice(1, False)` / `EnableDevice(1, True)` and stale-deletes pins not in the
   roster via `SSR_DeleteEnrollData(pin, 12)` — but ONLY when `bracket_enable_device=True`
   (22:00/manual sync). Daytime delta pushes never bracket (D6).
5. TOTP: assert-with-test that `totp_enabled=False` leaves `_handle_totp_rescue` inert
   (gates at `ultra_engine.py` ~1643–1648) — this gym has no QR.

### 4.5 Tests (all fake-driver, no COM/hardware — extend `tests/test_ultra_engine.py` + new files)
- Fake standalone driver whose internal queue is pre-loaded with canned NormalizedEvents →
  worker `_process_event` produces expected popup_q + history_q contents (incl. `raw["direction"]`).
- Full-sync branch: fake driver records `push_roster` call; `_mark_full_sync_finished` fires on
  success AND failure; **a ZK_STANDALONE device can NEVER reach `run_one_device_on_connected_sdk`**
  (assert via monkeypatched sentinel).
- `poll_rtlog_once` drains and returns []; never blocks.
- Command funnel: `open_door` from a non-STA thread returns within deadline; unsupported
  `get_device_param` returns None (never raises).
- pin→card map: known pin → cardNo mapped; unknown pin → `ZKPIN:` prefix + telemetry warn.
- VerifyMethod mapping table: both value spaces.
- Factory: updated expectations (4.3).

### 4.6 Sidecar fallback — SPEC ONLY (write the doc, build only if GATE 1 fails)
Long-lived 32-bit PowerShell (or 32-bit python) process per device; line protocol on stdio:
`READY` / `EVENT:{json NormalizedEvent}` / `PONG` (reply to `PING\n`) / `RESULT:{json}` (reply to
`CMD:{json}` for open_door/push/time); supervision = pump threads + hang deadline + restart with
backoff (pattern: `zkemkeeper_scanner.py` ~199–289). The driver class above keeps the same public
surface; only the transport under the command funnel changes.

---

## 5. PHASE 4 — dashboard/config prep (before on-site day)

1. Create the 3 GymDevice rows: names **"Entrée 1", "Entrée 2", "Sortie"** (popup shows
   `e.deviceName`), IPs, port 4370, `accessDataMode='ULTRA'`, `deviceProtocol='ZK_STANDALONE'`,
   `fingerprintEnabled=true`, `rfidEnabled=true`, `totpEnabled=false`, `faceIdEnabled=false`.
2. One door preset each (doorNumber=1) via the existing dashboard dialog
   (`GymDeviceDoorPresetsDialog.tsx` — direction toggle already shipped): IN / IN / OUT.
3. `popupLanes=3` (settings; clamp 1..5, default 3 — no code change).
4. **Keep the devices inactive or the gym desktop un-upgraded until on-site day** — a live desktop
   with protocol-less rows would PullSDK-hammer the terminals in connect-fail loops.
5. Dashboard code changes: none required for v1 (protocol field can be set via API/DB if no UI;
   optional: add a protocol select in the device form later).

---

## 6. PHASE 5 — ON-SITE DAY: hardware gates (STOP points, in order)

> Bring: 32-bit `zkemkeeper.dll` (from github.com/ZKTeco/Standalone-SDK, register with 32-bit
> `regsvr32`), the ZK9500 + libzkfp, a test card, gate scripts prepared in advance.

| Gate | What | Procedure | On FAIL |
|------|------|-----------|---------|
| **G1** | In-process COM viability (decides transport, D1) | On the gym PC: register DLL → from the installed 32-bit runtime run the gate script: STA thread + `DispatchWithEvents` + `Connect_Net` (check device COMM>Security for a comm key first; `SetCommPassword` if set) + `RegEvent(1,1)` + ReadRTLog/GetRTLog loop. Present finger + card; confirm `OnAttTransactionEx` fires with sane args, no stale-'0' reads. | Switch to the pre-specified sidecar (4.6); driver above the transport seam unchanged. |
| **G2** | Event fidelity table (fills the mapping constants) | Record raw `(EnrollNumber, IsInValid, AttState, VerifyMethod, ts)` for: FP-allow, card-allow, unknown card, unenrolled finger, punch on ENTRY vs EXIT unit, punches under the configured verify mode. | If DENY events don't exist → deny popups/history stay out of scope v1 (allow-only). Unrecognised eventTypes already land on the DENY branch = fail-safe. |
| **G3** | **Template portability (RUN BEFORE ANY MASS ENROLLMENT)** | Desk-enroll ONE test user (`enroll_3_samples`) → `SSR_SetUserInfo` + `SetUserTmpExStr(Flag=1, b64)` → live finger on terminal must match. Also enroll ON the terminal, download, compare blob. | Activate terminal-enrollment fallback (`StartEnrollEx`) and change the desk workflow BEFORE members are enrolled. This gate changes the gym's operating procedure, not code. |
| **G4** | ACUnlock + wiring | `ACUnlock(1, 10)`; listen for relay; confirm each turnstile is wired to its MB2000 lock contacts. | `supports_open_door=False`; remote/desk-open descoped; access is 100% on-device verification (already the design). |
| **G5** | Concurrency + leak soak | One process holds all 3 connections ≥1h punching both methods — watch PROC_HB `private_mb`/handles (32-bit space is the known scarce resource). Second process `Connect_Net` to a held terminal — record kick/fail/coexist. Keypad responsiveness while connected and during `EnableDevice(false)`. | Leak → scheduled recycle policy or sidecar isolation. Second-connect-kicks → hard rule: no other tooling may ever connect directly. |
| **G6** | Card number space + reader type | Scan a gym card: live-event value vs `GetStrCardNumber` vs the desk capture value for the SAME card; identify EM vs Mifare option. | Mismatch → normalization layer in the driver; re-verify before roster push. |
| **G7** | Push timing + UI blocking | Push ~200 users × 2 templates with and without `EnableDevice`; time per-user; observe whether the terminal keeps verifying during un-bracketed writes. | Calibrates the delta-vs-batch policy (D6). |
| **G8** | Device-side config | (a) punch-state pinning menu (fixed AttState per unit — cross-check only); (b) on-device re-entry interval analog of Door{N}Intertime — if absent, the ULTRA software cooldown is the only re-entry layer; (c) Get/SetDeviceTime support (pre-check the SDK CHM on the dev machine — no hardware needed for API existence); (d) ADMS/Cloud menu presence (future push transport, note only). | Adjust settings/expectations accordingly. |

---

## 7. PHASE 6 — canary rollout

1. Bring up **ONE entry terminal** in ULTRA observe-only; soak ≥30 min with both verify methods;
   watch `WORKER_HB` (polls/events advancing), `PROC_HB` (flat memory/handles), `POPUP_ENQUEUE`,
   history rows reaching the backend with correct `direction`.
2. Add the second entry terminal; re-soak. Then the EXIT terminal; verify `/door-history` shows
   Exit rows AND (critical) the **stored** direction is OUT (the read-time override can mask the
   bulk-save bug — query the DB/analytics, not just the page).
3. Enroll the member base at the desk (only after G3 passed).
4. Leave FP_DELTA-style telemetry watching for a week; the C3 gym diff (before/after RTLog +
   access_history) must show zero change.

---

## 8. Telemetry contract for the new path (parity checklist)

- Free via shared heartbeat once the worker calls `_tel.set_state(wid, …)` + `_tel.note_poll(wid, events=n)`:
  `WORKER_HB`, `WORKER_STALL`, `PROC_HB` (`telemetry.py` ~478–592).
- Reuse verbatim by reusing worker plumbing: `POPUP_ENQUEUE`/`POPUP_QUEUE_FULL`, history timings.
- Emit explicitly in the driver/worker seams: `CONN_CONNECT`/`CONN_DISCONNECT` (@_tel.timed),
  `FULL_SYNC_START`/`FULL_SYNC_DONE` around `push_roster`, `RUN_LOOP_EXCEPTION`,
  `thread_spawn_failure` on STA-thread creation, and NEW: `ZKEM_EVT_SINK_DOWN` (pump death),
  `ZKEM_PIN_UNMAPPED` (unknown pin → ZKPIN: fallback), `ZKEM_PUSH_USER_FAIL`.

## 9. Explicitly OUT OF SCOPE for v1

- Face (ZKFace 7.0): no push path exists anywhere in ACCESS; templates not portable. On-device only, later.
- Push/ADMS transport; pyzk in shipped code (GPL); deny-event popups (pending G2); accessDataMode
  collapse / pcVerifiesCard (separate plan); any change to the C3 gym.

## 10. Known risks the executor must keep in view

- 32-bit address space is the scarce resource that already caused a daily lockup
  (`ultra_engine.py` ~484–496) — watch `private_mb` from day one; sidecar is the isolation valve.
- The PoC's stale-'0' diagnosis (cross-bitness marshaling) was never re-tested at matching bitness — G1 decides.
- Engine restart on device-set change (`app/ui/app.py` ~2614–2625) tears down all 3 COM pumps at once —
  `stop()` must join the STA thread with timeout and never call COM from the caller's thread.
- The worker watchdog rebuilds workers while a previous connection may be half-open
  (`ultra_engine.py` ~3579–3623) — reconnect-while-half-open behavior is G5.
- Every device-menu instruction is provisional until the units are unboxed (2014 datasheet, newer firmware).

# ULTRA Mode — Access Control Hybrid Architecture

**Date:** 2026-04-01
**Status:** Approved
**Scope:** Backend (Java/Spring), Access Client (Python/Tauri), Dashboard (React/TypeScript)

---

## Problem

Current access control modes force a trade-off:

- **DEVICE mode:** Instant RFID/fingerprint access, offline-capable, handles peak time — but no TOTP support, no popup notifications, no real-time visibility into who entered.
- **AGENT mode:** Full TOTP support, popup notifications, real-time history — but the PC is a single point of failure, adds 100-400ms latency to every scan, and nothing works if the PC crashes.

Gyms that need both RFID speed and TOTP support (with offline resilience and peak-time handling) have no good option.

## Solution

**ULTRA mode** — a per-device hybrid that combines device-firmware RFID/fingerprint processing with PC-side RTLog observation and TOTP rescue.

### Decision Authority

| Authentication | Who decides | Who opens door |
|---------------|------------|----------------|
| RFID card | Device firmware | Device firmware |
| Fingerprint | Device firmware | Device firmware |
| TOTP (QR code) | PC (Access app) | PC sends `ControlDevice(open_door)` |

The PC never overrides device decisions for RFID/fingerprint. It only acts on denied events matching the TOTP format.

---

## Architecture

### Three Layers Per Device

```
Layer 1: Device Sync
  - Pushes user data (PINs, cards, fingerprints) to controller
  - Runs on configurable timer (default: 15 minutes)
  - Reuses existing DeviceSyncEngine push logic
  - Hash-based change detection: skip push if data unchanged

Layer 2: RTLog Observer
  - Polls RTLog continuously (50-100ms intervals)
  - Classifies each event into 3 paths (see Event Classification)
  - Generates popup notifications and history records for ALL events
  - Runs in dedicated UltraDeviceWorker thread per device

Layer 3: TOTP Rescue
  - Triggered only by denied events matching TOTP format
  - Verifies TOTP locally (HMAC-SHA1, cached secrets, no internet needed)
  - Sends open_door command if valid
  - Runs inline in UltraDeviceWorker thread (no queue hop)
```

### Event Classification

```
RTLog Event from Device
  |
  +-- ALLOW (device recognized card/fingerprint)
  |     -> Passive: enrich with user data -> popup -> history
  |        PC sends NO command (door already opened by device)
  |
  +-- DENY + scanned code matches TOTP format (prefix + N digits)
  |     -> TOTP Rescue: verify locally
  |        -> valid: open_door command -> popup (allowed) -> history
  |        -> invalid: popup (denied) -> history
  |        PC sends open_door ONLY if TOTP verification passes
  |
  +-- DENY + scanned code does NOT match TOTP format
        -> Deny: popup (denied, reason=DEVICE_DENIED) -> history
           PC sends NO command (respects device decision)
```

### TOTP Rescue Timing Budget (target < 300ms)

| Step | Time |
|------|------|
| RTLog poll catches event | 50-100ms |
| TOTP verification (HMAC-SHA1) | < 1ms |
| ControlDevice(open_door) via TCP | 50-100ms |
| **Total** | **~100-200ms** |

The TOTP rescue runs inline in the worker thread with no queue hop, eliminating the DecisionWorker queue latency that AGENT mode has.

---

## Device Sync Strategy

**Push frequency:** Configurable per-device via `ultraSyncIntervalMinutes` (default: 15 minutes).

**Hash-based change detection:**
1. PC calls backend `get_gym_users` on the sync timer
2. PC computes hash of user payload (sorted PINs + cards + fingerprint hashes)
3. If hash matches previous push -> skip device write
4. If hash changed -> push to device via SetDeviceData

**Pushing policy:** Reuses the existing `pushingToDevicePolicy` per-device enum. No change needed.

**New member between syncs:**
- RFID: won't work until next sync (max 15 min wait)
- TOTP: works immediately (PC has fresh cache from backend)
- Natural fallback: "Use QR code now, card activates in a few minutes"

---

## Degradation Behavior

| Scenario | RFID/FP | TOTP | Popup | History |
|----------|---------|------|-------|---------|
| Everything normal | Instant (device) | ~200ms (PC) | Yes | Yes (backend) |
| Internet down | Instant (device has data) | ~200ms (local cache) | Yes | Queued locally |
| PC crashes | **Instant** (device autonomous) | **Dead** | No | No |
| PC + internet down | **Instant** (device autonomous) | **Dead** | No | No |
| Device unreachable | Dead | Dead | No | No |

Critical advantage over AGENT mode: when the PC crashes, RFID/fingerprint users can still enter. Only TOTP stops.

---

## Supported Devices

All ZKTeco PullSDK-compatible controllers:
- C3 series: 100, 100 Plus, 200, 200 Plus, 100 Pro Plus, 200 Pro Plus, 400 Pro Plus
- C2 series: same variants
- C4 series: same variants
- InBio, InBio Pro Plus

All use the same PullSDK protocol: SetDeviceData, GetRTLog, ControlDevice.

**Deny feedback:** On most ZKTeco setups, the reader beeps on card read (always, regardless of allow/deny). The controller silently decides. No separate "deny beep" from the controller. TOTP users experience: reader beep -> brief pause (~200ms) -> door opens.

---

## Changes Per Codebase

### Backend (Java/Spring) — monclub_backend

**1. Enum: `AccessSoftwareDataMode.java`**
Add `ULTRA` value alongside existing `DEVICE` and `AGENT`.

**2. Model: `GymDevice.java`**
Add fields:
- `ultraSyncIntervalMinutes` (Integer, default 15) — how often to push data to device
- `ultraTotpRescueEnabled` (Boolean, default true) — enable/disable TOTP rescue
- `ultraRtlogEnabled` (Boolean, default true) — enable/disable RTLog observation

**3. DTO: `GymDeviceDto.java`**
Add corresponding fields to the DTO so the Access client receives them.

**4. No new endpoints needed.** ULTRA reuses:
- `get_gym_users` for data sync
- Existing credential system for TOTP secrets
- Existing `bulk_save_gym_access_history` for history push

### Access Client (Python/Tauri) — monclub_access_python

**1. Config: `app/core/config.py`**
Add `"ULTRA"` recognition to `_normalize_data_mode()`:
- Accepts: "ULTRA", "ULTRA_MODE", "3" -> "ULTRA"

**2. New file: `app/core/ultra_engine.py`**
Contains:
- `UltraEngine` — main orchestrator, manages workers + sync
- `UltraDeviceWorker` — per-device thread: RTLog poll + event classification + TOTP rescue + popup/history enqueue
- `UltraSyncScheduler` — wraps existing DeviceSyncEngine push logic on configurable timer

Reuses from existing code:
- `_verify_totp()` from realtime_agent.py (extracted or imported)
- `_verify_card()` from realtime_agent.py (for enriching ALLOW events)
- `PullSDKDevice.poll_rtlog_once()` for RTLog polling
- `PullSDKDevice.open_door()` for TOTP rescue door command
- `NotificationRequest` dataclass for popup queue
- `HistoryRecord` for history queue
- Event dedup: LRU deque (10,000 per device) + DB atomic INSERT OR IGNORE
- Connection watchdog (15s timeout)
- Adaptive sleep tuning (per-device settings)

**3. App wiring: `app/ui/app.py`**
- Update `get_access_mode_summary()` to count ULTRA devices
- Start `UltraEngine` for ULTRA-mode devices during startup
- Add ULTRA to the sync timer logic

**4. Settings: `app/core/settings_reader.py`**
Read new ULTRA fields from device settings:
- `ultra_sync_interval_minutes` (default 15)
- `ultra_totp_rescue_enabled` (default true)
- `ultra_rtlog_enabled` (default true)

**5. Local API: `app/api/local_access_api_v2.py`**
- Add `/api/v2/ultra/status` endpoint for ULTRA engine status
- Include ULTRA engine state in `/api/v2/status` unified endpoint
- ULTRA popup events use the same SSE channel `/api/v2/agent/events`

### Dashboard (React/TypeScript) — mon_club_dashboard

**1. Device mode selector**
Add `ULTRA` option to the accessDataMode dropdown (alongside DEVICE/AGENT).

**2. ULTRA-specific settings panel**
When ULTRA is selected, show:
- Sync interval (minutes, default 15, min 5)
- TOTP rescue enabled (toggle, default on)
- RTLog observation enabled (toggle, default on)

**3. TypeScript types**
Update `GymDeviceDto` interface with new ULTRA fields.

---

## Component Reuse Map

| Component | Source | Reused in ULTRA |
|-----------|--------|-----------------|
| DeviceSyncEngine push logic | DEVICE mode | UltraSyncScheduler |
| poll_rtlog_once() | AGENT DeviceWorker | UltraDeviceWorker |
| _verify_totp() | AGENT DecisionWorker | UltraDeviceWorker (inline) |
| _verify_card() | AGENT DecisionWorker | UltraDeviceWorker (for enrichment) |
| PullSDKDevice.open_door() | AGENT DeviceCommandBus | UltraDeviceWorker (direct call) |
| NotificationRequest + popup queue | AGENT mode | Same queues, same SSE |
| HistoryRecord + history queue | AGENT mode | Same queues, same sync |
| Event dedup (LRU + DB atomic) | AGENT mode | Same logic |
| Adaptive sleep tuning | AGENT mode | Same per-device settings |
| Connection watchdog (15s) | AGENT mode | Same logic |

Approximately 70% reused code, 30% new wiring and event classification.

---

## Peak Time Analysis

Scenario: 60 members in 10 minutes (morning rush)

- 48 RFID users (80%): Device firmware handles ALL at hardware speed. Zero PC involvement in decisions. PC reads RTLog passively for popup — this is non-blocking and can fall behind without affecting access.
- 12 TOTP users (20%): PC processes sequentially at ~200ms each = 2.4 seconds total spread across 10 minutes. Zero bottleneck.

If PullSDK hangs (15s watchdog timeout): Only TOTP stops for that device. RFID continues unaffected (device is autonomous).

---

## Security Considerations

- TOTP verification uses the same proven HMAC-SHA1 implementation as AGENT mode
- Replay protection via event ID dedup (LRU + DB atomic)
- TOTP collision detection (reject if 2+ credentials match same code)
- TOTP age validation (reject expired/future-skewed codes)
- PC never overrides device RFID/FP decisions — cannot be used to bypass device-level deny
- Stale data window (max 15 min) mitigated by TOTP fallback for new members
- Local TOTP secrets encrypted at rest in SQLite (same as AGENT mode)

---

## Out of Scope

- No changes to the mobile app (TOTP QR generation unchanged)
- No changes to the AGENT mode or DEVICE mode behavior
- No new backend API endpoints
- No changes to fingerprint enrollment flow
- No changes to PullSDK wrapper

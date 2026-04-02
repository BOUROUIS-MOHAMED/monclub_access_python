# MonClub Access Performance Review
# Round 6 — 2026-04-02

---

## Summary

Performance is not a launch blocker. The changes from Round 6 fixes (ULTRA double-sync prevention, sync flag race fix) improve reliability without any performance regression. Key risks are bounded by the clamped settings system and the adaptive sleep mechanism.

---

## Hot paths

### 1. AGENT DecisionService inner loop

**Path**: `DecisionService.run()` — `event_queue.get()` → `access_history_exists()` → `_load_local_state()` → `verify_totp()` → `insert_access_history()` → `open_door()`

**Timing budget**: 100–300ms typical for a human-perceptible "fast" gate

| Step | Typical cost | Notes |
|------|-------------|-------|
| `access_history_exists()` | <1ms | Indexed read on UNIQUE(event_id) |
| `_load_local_state()` | <1ms (cached) | 2s TTL; full query only on cache miss |
| `verify_totp()` | 1–5ms | HMAC inner loop over all credentials |
| `insert_access_history()` | 1–5ms | WAL write + commit |
| `open_door()` | 50–200ms | PullSDK TCP call; cmd_ema tracked |

Total: ~60–220ms. Well within budget.

**Bottleneck risk**: A single DecisionService thread processes events for all AGENT devices. If N devices fire simultaneously, events queue up. With N=5 devices each firing 2 events simultaneously, total delay is ~N×decision_time. For typical gyms (1–3 devices), this is negligible.

### 2. ULTRA UltraDeviceWorker poll loop

**Path**: `run()` → `_poll_with_watchdog()` → `_process_event()` → classify → `verify_totp()` / passive enrich → `insert_access_history()`

Similar timing profile as AGENT. Additional overhead: each ULTRA device runs its own thread (no shared queue), so events are parallelized per-device. More scalable than AGENT for multi-device setups.

**TOTP rescue timing**: `verify_totp() + _open_door_with_retry()`. Typical 60–220ms. The firmware's decision is already final when the ULTRA worker processes the denial event; the rescue command is sent on the next event arrival. This is acceptable because ZKTeco firmware typically holds the result for a brief window.

### 3. DeviceSyncEngine per-device sync

**Path**: `connect()` → `get_device_data_rows("user")` → `set_device_data()` × N pins

| Step | Typical cost | Notes |
|------|-------------|-------|
| PullSDK connect | 500–2000ms | TCP handshake to device |
| `get_device_data_rows("user")` | 200–5000ms | Proportional to number of users on device |
| `set_device_data()` per user/FP | 50–500ms each | Firmware write |

For 1000 users, a full push takes ~5–15 minutes. Hash-based change detection means normal sync only pushes changed pins (typically 0–20 per cycle). Fast path: ~0.5–3 seconds per device for a stable deployment.

**Post-Round-6 improvement**: Preventing ULTRA double-sync eliminates a redundant full-sync pass that would run every 60s in mixed-mode deployments.

### 4. History upload batch

**Path**: `list_pending_access_history_for_sync(limit=200)` → serialize 200 rows → HTTP POST to backend → mark synced

- Batch size = 200 rows max per upload cycle
- At 200 events/upload and 60s sync interval, this supports ~3 events/second sustained throughput to the backend
- At a typical gym (50–500 events/day), this is more than sufficient

**Risk**: Fixed 300s retry delay with no jitter. Under backend outage, all sites retry at the same time. Does not affect local access control — history is written locally first.

---

## DB hot paths

### SQLite schema design

```
access_history: UNIQUE(event_id), indexed on device_id+event_time, created_at, backend_sync_state
sync_users: UNIQUE(user_id, active_membership_id), indexed on first_card_id, second_card_id
sync_devices: UNIQUE(id)
sync_device_door_presets: UNIQUE(remote_id), indexed on device_id
device_sync_state: indexed on device_id+pin
agent_rtlog_state: indexed on device_id
```

- WAL mode: readers don't block writers; multiple threads share same connection
- `synchronous=NORMAL`: safe for normal operation; trades some durability for speed
- `wal_autocheckpoint=1000`: auto-checkpoint after 1000 WAL pages

### Potentially expensive queries

| Query | Frequency | Concern |
|-------|-----------|---------|
| `list_sync_users()` (for card index) | Every 2s (AGENT) or 5s (ULTRA) on TTL miss | Full table scan; mitigated by index on first_card_id |
| `list_pending_access_history_for_sync(limit=200)` | Every sync_tick | Index on backend_sync_state + next_retry_at; efficient |
| `get_recent_access_history(limit=200)` | On restart (ULTRA/AGENT pre-populate) | Index on created_at; fast |
| `prune_access_history(retention_days)` | Every 200 history writes | DELETE WHERE created_at < threshold; index-friendly |

---

## Threading risks

### 1. Python GIL constraint

All Python threads share the GIL. CPU-bound work (HMAC in verify_totp) releases GIL only briefly. For typical credential counts (< 500 TOTP credentials), HMAC loop takes < 5ms and does not cause starvation.

### 2. PullSDK thread safety

PullSDK wraps a native 32-bit DLL. Each `PullSDKDevice` instance holds its own connection handle. `DeviceSyncEngine` uses `ThreadPoolExecutor(max_workers=4)` — up to 4 concurrent connections to different devices. Multiple connections to the SAME device (previously possible with ULTRA+DEVICE mix) are avoided after Round 6 fix.

### 3. SQLite concurrency

`get_conn()` creates a thread-local connection using `check_same_thread=False`. WAL mode allows concurrent reads and a single writer. Multiple threads writing simultaneously are serialized by the WAL journal. 30s timeout prevents indefinite blocking.

### 4. Event queue blocking

`DeviceWorker.event_queue.put(AccessEvent)` (AGENT) has no timeout — blocks if queue is full. At 5000 max queue size and ~1 event/second typical rate, overflow would require 5000 seconds (83 minutes) of a non-responsive DecisionService. This is a theoretical risk only.

Post-launch improvement: use `put_nowait()` with drop counting.

---

## Scaling risks

| Scenario | Current capacity | Risk threshold | Notes |
|----------|-----------------|----------------|-------|
| Number of users | 10,000+ practical | >50,000 cards may slow index rebuild | DB index on first_card_id helps |
| Number of DEVICE devices | 50+ (parallel sync) | >50 may exceed 4-worker pool | Increase ThreadPoolExecutor workers |
| Number of AGENT devices | 10+ workers | Memory and GIL contention | Each worker adds ~1MB + 1 thread |
| Number of ULTRA devices | 10+ workers | Same as AGENT | Each worker adds polling thread |
| Events per second | 10/s safe | >100/s may overflow event_queue | Increase queue size or add workers |
| History upload queue depth | Bounded at 200/batch | Grows if backend offline | Local DB keeps all PENDING rows |

---

## What must be fixed before launch

| Item | Priority | Impact if deferred |
|------|----------|-------------------|
| M-NEW-001: ULTRA double-sync | Required | Concurrent connections to ULTRA device cause sync failures |
| M-NEW-002: New ULTRA device ignored | Required | Mode switch at runtime requires app restart |
| M-NEW-003: `_sync_work_running` race | Required | Two concurrent sync threads under unusual conditions |

## Safe post-launch improvements

| Item | Effort | Benefit |
|------|--------|---------|
| History retry jitter | 1 line | Prevents retry storms after backend outage |
| Event queue `put_nowait` + drop count | 5 lines | Prevents DeviceWorker thread blocking under burst |
| Per-device DecisionService workers | Refactor | Isolates slow verifications per device |
| ULTRA local state TTL configurable | 2 lines | Match AGENT mode (already configurable) |
| `pushingToDevicePolicy` enforcement | Design work | Document or implement the policy |

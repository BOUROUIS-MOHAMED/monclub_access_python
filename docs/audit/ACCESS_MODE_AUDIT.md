# MonClub Access Mode-by-Mode Audit
# Round 6 — 2026-04-02

---

## DEVICE Mode

### Intended behavior (from code)

Periodically pushes users, fingerprint templates, and door-authorization records to ZKTeco controllers via PullSDK. The controller firmware makes all access decisions autonomously. The PC role is data management and history collection only.

### Actual behavior found

Confirmed. `DeviceSyncEngine.run_blocking()` is called from `sync_tick()` only when DEVICE-mode devices exist (`summary.get("DEVICE", 0) > 0`). The engine applies per-pin SHA1 hash-based change detection, fingerprint/user push, stale-pin deletion, and per-device sync state persistence.

Mode isolation is clean: the check `accessDataMode != "DEVICE"` in `_sync_all_devices()` skips AGENT-mode devices. **However**, the normalization in `_normalize_device()` maps "ULTRA" to "DEVICE", causing ULTRA devices to be synced in this path as well when DEVICE devices co-exist.

`DeviceAttendanceMaintenanceEngine` reads transaction logs from all devices and uploads them to the backend via a 200-row batch. Retry is fixed at 300s.

### Strengths

- Hash-based change detection prevents redundant PullSDK operations
- Drift detection: re-syncs pins found missing on device despite stored hash
- Stale-pin deletion correctly scoped to known-server pins only
- `_delete_pin_if_exists` handles firmware that doesn't support DeleteDeviceData gracefully
- Template push has multi-table, multi-field-name fallback for firmware diversity
- Parallel sync across devices (ThreadPoolExecutor, max 4)
- `pushingToDevicePolicy` is read into device payload (though not enforced in push engine)

### Weaknesses

1. **ULTRA devices also processed**: `_normalize_device()` maps "ULTRA" → "DEVICE", causing ULTRA devices to be synced concurrently with `UltraSyncScheduler`. Concurrent PullSDK connects to the same device may fail.
2. **`pushingToDevicePolicy` is read but never enforced**: `device_sync.py:216-232` reads the value but nothing in `_sync_one_device` acts on it. If the policy is supposed to limit what data gets pushed, it's silently ignored.
3. **Fixed history retry interval**: `UPLOAD_FAILURE_RETRY_SECONDS = 300` with no jitter. Under prolonged backend outage, all sites will retry simultaneously.
4. **No per-device sync concurrency guard**: If two sync ticks fire close together (e.g., during app startup) and both get past the `_running` lock, behavior is safe (inner lock blocks second run) but logging is noisy.

### Failure risks

- **Device offline during sync**: PullSDK connect fails. Saved hash stays at previous value. Next sync tick reattempts. Safe.
- **Partial push** (user wrote, template failed): `save_device_sync_state(ok=False)` keeps desired_hash NULL so next run retries. Safe.
- **Backend returns empty user list** (outage / bug): `save_sync_cache()` refuses to wipe if old_count > 10. Previous users remain on device. Safe.
- **Card change not detected by UltraSyncScheduler**: FIXED — M-004 includes `firstCardId` / `secondCardId` / `fingerprintsHash` in payload hash.

### Performance concerns

- `get_device_data_rows("user")` initial read on every sync (not just on hash change) is O(n users on device). Mitigated by `sdk_read_initial_bytes` knob.
- ThreadPoolExecutor with max 4 workers: reasonable for < 50 devices; may queue for large deployments.

### Security concerns

None specific to DEVICE mode beyond what's covered in the security review (local API auth, loopback bind — both fixed).

### Production readiness verdict

**DEVICE mode: GO with one targeted fix** (prevent ULTRA double-sync — M-NEW-001).

---

## AGENT Mode

### Intended behavior (from code)

PC polls ZKTeco RTLog in real time. All access decisions are made by the PC using the locally synced credential cache. The device firmware sees unknown cards and fires "deny" events that the PC intercepts to run TOTP/RFID verification locally, then issues door-open commands.

### Actual behavior found

Confirmed and clean. `AgentRealtimeEngine` starts one `DeviceWorker` thread per AGENT-mode device. Each worker polls RTLog via a 15-second watchdog-guarded thread. New events are pushed to a shared `event_queue`. The single `DecisionService` thread dequeues events, verifies credentials, claims history via `INSERT OR IGNORE`, and opens the door only if it claimed the event (rowcount==1).

`refresh_devices()` allows the engine to add/remove devices at runtime without full restart.

### Strengths

- **Fail-closed on DB failure**: `_history_claimed = 0` on exception → door does not open
- **Atomic dedup**: `INSERT OR IGNORE` on `UNIQUE(event_id)` prevents double door-open across DecisionService workers
- **Pre-populated seen deque**: avoids replaying up to 200 recent events after restart
- **Cursor-based old-event filtering**: `_is_old_by_cursor()` skips events older than the saved cursor epoch
- **15s watchdog**: prevents polling loop from hanging indefinitely on SDK hang
- **Exponential backoff on reconnect**: 0.25s → 30s cap
- **Local state TTL cache**: 2s TTL prevents a DB read on every event under burst
- **NotificationGate**: per-minute rate limit + dedupe window (both backend-controlled)
- **H-002**: HistoryService not started in AGENT mode (DecisionService writes history directly)

### Weaknesses

1. **Single DecisionService thread**: AGENT mode processes all events sequentially. Under burst (multiple devices firing events simultaneously), the event_queue may back up. With queue maxsize=5000 and 200ms sleep between polls, this is unlikely to overflow but creates latency.
2. **No per-device decision isolation**: A single slow verification (e.g., TOTP with many credentials) blocks decisions for other devices. Post-launch optimization: per-device decision workers.
3. **Door ID fallback**: if `ev.door_id` is None (RTLog didn't populate it), uses `settings.get("door_entry_id", 1)`. If that setting is misconfigured, wrong door may open.
4. **RTLog cursor clock drift**: `_parse_event_time_to_epoch()` uses device local time minus `tz_offset_sec`. If device clock drifts, cursor comparison can skip valid events or replay old ones.
5. **No RFID card expiry check in AGENT mode**: `verify_card()` checks only card format and card index membership; it does not enforce `validFrom/validTo`. Membership expiry is filtered at device-sync time (DEVICE mode) but not re-checked per-event in AGENT mode. A user whose membership expired after last sync could still access. This is a known design trade-off (same as ULTRA), documented here for completeness.

### Failure risks

- **Event queue overflow**: If `decision_q` fills (5000 events), `DeviceWorker.event_queue.put()` with no timeout would block the polling thread. Looking at the code, `event_queue.put(AccessEvent)` is called with no timeout — this would block the DeviceWorker thread when the queue is full. The worker has no `put_nowait` with a drop path. This is a latent risk under sustained burst.
  - Fix: use `put_nowait` with drop logging, or add per-device queues.
- **Backend outage → stale cache**: AGENT mode continues authorizing from local SQLite indefinitely. No staleness threshold. Post-launch work item.

### Performance concerns

- `load_local_state()` rebuilds card index on cache miss (every 2s). For 10,000 users, this is a full SQLite query. Under normal load (2s TTL, ~1 event/s), this is fine.
- `access_history_exists()` is called before every decision — one read per event. WAL mode makes this fast.

### Security concerns

- RFID fallback in `verify_totp()`: a card number that accidentally matches TOTP format (starts with prefix, correct length) passes through TOTP verification and falls back to RFID check. The RFID check would correctly identify it as a card. Risk is cosmetic (wrong scanMode logged) rather than security.
- TOTP replay within same counter window (30s): not blocked. A valid code captured and replayed within the same 30-second window would succeed. This is by design for TOTP systems.

### Production readiness verdict

**AGENT mode: GO** — all critical issues from previous rounds are fixed. The weaknesses above are performance/UX concerns, not safety blockers.

---

## ULTRA Mode

### Intended behavior (from code)

Hybrid mode. Device firmware handles RFID and fingerprint verification autonomously (same as DEVICE mode). The PC observes RTLog passively for enrichment. When the device denies a code that looks like a TOTP token, the PC intercepts, verifies locally, and opens the door if valid. Users/templates are periodically pushed to the device like DEVICE mode.

### Actual behavior found

Confirmed and functionally correct after Round 4/5 fixes. The ALLOW/TOTP/DENY classification in `_process_event()` is sound. TOTP rescue opens the event door (not just the configured default). ULTRA history rows are stored with `history_source="ULTRA"`. Sync is scoped to the target ULTRA device with a filtered cache copy.

New issues found in this round:

1. **ULTRA devices also processed by DeviceSyncEngine** (M-NEW-001): same issue as DEVICE mode description above.
2. **New ULTRA device not picked up if engine running** (M-NEW-002): `UltraEngine.start()` exits early if `self._running`. A device switching to ULTRA while the engine runs for another device is silently ignored.

### Strengths

- `_is_totp_format()` guards prevent non-TOTP denials from entering rescue path
- TOTP verification is pure and testable (no class dependencies)
- Per-event dedup via `_seen` deque (maxlen=10000) + pre-populated from DB on restart
- `INSERT OR IGNORE` with `history_source="ULTRA"` before enqueuing
- `inserted = False` on DB exception — prevents bypass of dedup gate
- `_open_door_with_retry()` retries once with 100ms delay
- Event door preference: `door_id > 0 ? event_door : configured_default`
- Configurable poll timeout via `rtlog_poll_timeout_sec` setting
- Coarse payload hash includes card numbers and fingerprint hash (M-004)
- Per-device sync state tracked in `_last_sync_at` / `_next_sync_at`
- `UltraEngine.get_status()` feeds `/api/v2/ultra/status` endpoint

### Weaknesses

1. **M-NEW-001**: ULTRA devices double-synced by DeviceSyncEngine. See Architecture Map.
2. **M-NEW-002**: New ULTRA device not picked up without full engine restart.
3. **ULTRA ALLOW events not validated**: `_handle_allow()` only enriches, does not validate. If the device's pushed user data is stale or corrupted, the PC cannot prevent a door from opening. This is a known ULTRA design trade-off (firmware-first), documented in previous audit docs.
4. **UltraSyncScheduler uses shortest interval across all devices**: `min_interval = min(all device intervals)`. If one device is configured to 1-minute sync, all devices wake up every minute.
5. **HistoryService for ULTRA does redundant inserts**: see Architecture Map note. The first insert (by UltraDeviceWorker) has `history_source="ULTRA"`. If the insert fails and HistoryService succeeds, the event is recorded as history_source=NULL (default "AGENT"). Low probability but architecturally incorrect.
6. **ULTRA does not check `validFrom`/`validTo` on ALLOW path**: same as AGENT mode. Expired memberships allowed if device firmware decides ALLOW. Intentional by design.

### Failure risks

- **TOTP rescue timing budget**: verify_totp + open_door must complete before firmware considers the denial final. In practice ~100-200ms is available. The 15s poll cycle means the rescue fires on the next event, not in real-time relative to the denial timestamp. This is acceptable because the rescue is triggered by the denial event itself.
- **Multiple ULTRA devices, same TOTP code**: same TOTP code valid at both devices simultaneously would open both. This is correct behavior (credential is valid for both).
- **ULTRA sync concurrent with DeviceSyncEngine** (when M-NEW-001 is unfixed): PullSDK connections to the same device from two threads. One connection will fail; the other will succeed. No data corruption, but sync may be incomplete.

### Performance concerns

- Each ULTRA device runs its own polling thread — O(N) threads per N devices
- UltraSyncScheduler runs DeviceSyncEngine inline in its own thread — if sync is slow, next interval is delayed (fine)
- Local state cache TTL is 5s (hardcoded in UltraDeviceWorker), vs 2s configurable in DecisionService

### Security concerns

- TOTP rescue is the only active door-open path in ULTRA mode. It is gated by HMAC-SHA1 + counter window + age check. The verification is the same code as AGENT mode.
- History source is preserved and queryable for audit.

### Production readiness verdict

**ULTRA mode: GO WITH FIXES** — functionally correct but requires M-NEW-001 and M-NEW-002 fixes before deploying in mixed DEVICE+ULTRA environments or multi-device ULTRA environments where devices may switch modes at runtime.

---

## Cross-mode concerns

| Concern | DEVICE | AGENT | ULTRA | Status |
|---------|--------|-------|-------|--------|
| Mode resolution per device | Clean | Clean | Bug: DeviceSyncEngine also processes ULTRA | Fix needed |
| Runtime mode switch (device adds to mode) | N/A | refresh_devices() handles it | Engine ignores new device | Fix needed |
| History source tracking | "DEVICE" | "AGENT" | "ULTRA" | Correct |
| Backend history upload | DeviceAttendance | DeviceAttendance | DeviceAttendance | Shared — OK |
| Local state stale auth risk | N/A | No max-age | No max-age | Post-launch |
| Door-open safety (fail-closed) | N/A (firmware) | INSERT OR IGNORE gate | INSERT OR IGNORE gate | Correct |
| Notification/popup enrichment | N/A | NotificationService | UltraDeviceWorker direct | Correct |

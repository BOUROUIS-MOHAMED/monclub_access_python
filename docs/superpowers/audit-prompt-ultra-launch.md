# Pre-Launch Audit Prompt — MonClub Access (All 3 Modes)

Copy everything below and give it to a fresh AI agent session.

---

## Your Mission

You are a senior software auditor performing a **pre-production launch audit** of the MonClub Access system. This is a gym access control application that manages ZKTeco controllers (C2/C3/C4/InBio series) via PullSDK over TCP.

The system has 3 access modes per device:
- **DEVICE** — Push user data to controller, firmware handles RFID/fingerprint. PC only syncs data periodically.
- **AGENT** — PC intercepts every scan in real-time, decides allow/deny, sends door command. Full TOTP + popup + history.
- **ULTRA** (NEW) — Hybrid: device firmware handles RFID/FP instantly + PC observes RTLog passively for popups/history + PC rescues TOTP codes (denied QR → verify locally → open door).

We are about to deploy ULTRA mode to production. **Your job is to find every bug, race condition, logic error, failure scenario, and performance concern** before we launch.

## Codebase Location

```
C:\Users\mohaa\Desktop\monclub_access_python
```

## Files to Audit (read ALL of these)

### Core Engine Files (READ EVERY LINE)
- `app/core/ultra_engine.py` — UltraDeviceWorker, UltraSyncScheduler, UltraEngine
- `app/core/realtime_agent.py` — AgentRealtimeEngine, DeviceWorker, DecisionService, HistoryService
- `app/core/device_sync.py` — DeviceSyncEngine (pushes data to DEVICE-mode controllers)
- `app/core/access_verification.py` — Shared verify_totp, verify_card, load_local_state
- `app/core/access_types.py` — Shared dataclasses: AccessEvent, NotificationRequest, HistoryRecord

### Configuration & Normalization
- `app/core/config.py` — _normalize_data_mode() — must handle DEVICE, AGENT, ULTRA
- `app/core/settings_reader.py` — normalize_device_settings(), normalize_access_data_mode()
- `app/core/db.py` — SQLite storage, sync cache, access history, mode validation

### App Wiring & API
- `app/ui/app.py` — Main app: engine initialization, _sync_tick, mode switching, get_access_mode_summary, destroy
- `app/api/local_access_api_v2.py` — REST API: /api/v2/status, /api/v2/ultra/status, SSE events
- `access/local_api_routes.py` — Route registration

### Hardware SDK
- `app/sdk/pullsdk.py` — PullSDK ctypes wrapper + PullSDKDevice high-level API

### Tests
- `tests/test_access_verification.py` — 64 tests for shared verification
- `tests/test_ultra_engine.py` — 73 tests for ULTRA engine

### Spec & Plan (for intent verification)
- `docs/superpowers/specs/2026-04-01-ultra-mode-design.md` — What ULTRA should do
- `docs/superpowers/plans/2026-04-01-ultra-mode.md` — Implementation plan

## Audit Checklist

### A. ULTRA Mode — Logic Correctness

1. **Event Classification**: Read `UltraDeviceWorker._process_event()`. Verify:
   - EventType 0 → ALLOW path (passive enrichment only, NO verify_card call)
   - EventType non-0 + TOTP format match → TOTP rescue path
   - EventType non-0 + no TOTP match → DENY path (passive logging)
   - What happens if EventType is missing or None?
   - What happens if CardNo is empty?

2. **TOTP Rescue Flow**: Read `_handle_totp_rescue()`. Verify:
   - verify_totp is called with correct arguments (keyword-only: scanned, settings, creds_payload, users_by_am, users_by_card)
   - Door opens ONLY if verify_totp returns allowed=True
   - open_door_with_retry: max 2 attempts, 100ms between
   - DOOR_CMD_FAILED: both attempts fail → allowed flipped to False, reason="DOOR_CMD_FAILED"
   - User gets message "Valid code but door did not open — try again or use card"
   - Counters updated correctly (totp_rescues, totp_failures, door_cmd_failures)

3. **TOTP Format Detection**: Read `_is_totp_format()`. Verify:
   - Checks totp_enabled AND ultra_totp_rescue_enabled (both must be true)
   - Prefix + digits length check is correct
   - Edge cases: empty string, pure digits without prefix, code with letters

4. **ALLOW Enrichment**: Read `_handle_allow()`. Verify:
   - Does NOT call verify_card (spec says passive lookup only)
   - Looks up user by card number in users_by_card
   - Handles case where users_by_card returns a list vs a dict
   - Handles missing user gracefully (unknown card)
   - Membership ID correctly parsed to int (NotificationRequest expects Optional[int])

5. **Event Dedup**: Read `_is_seen()` and `_pre_populate_seen()`. Verify:
   - deque maxlen=10,000 prevents unbounded memory growth
   - Pre-populate loads from DB on startup (prevents reprocessing after restart)
   - Event ID format: uses eventId from RTLog, falls back to f"{device_id}:{event_time}:{card_no}"
   - DB-level dedup: _enqueue_history uses insert_access_history (INSERT OR IGNORE)
   - Only enqueues to history_q if DB insert returned rowcount=1

6. **Local State Caching**: Read `_get_cached_local_state()`. Verify:
   - 5-second TTL prevents stale data from persisting too long
   - Cache is per-worker-instance (not shared across devices)
   - What happens if load_local_state() throws? Does the cache return stale data or crash?

7. **Connection Management**: Read `_connect()`, `_disconnect()`, `_poll_with_watchdog()`. Verify:
   - PullSDKDevice created with device_payload dict and logger
   - 15-second poll watchdog kills hung polls
   - After watchdog timeout: disconnect and reconnect on next loop
   - 5-second wait on failed connect before retry
   - Clean disconnect on stop

### B. ULTRA Mode — Concurrency & Thread Safety

8. **Thread Model**: Verify:
   - One UltraDeviceWorker thread per device (daemon=True)
   - One UltraSyncScheduler thread shared across all ULTRA devices
   - popup_q and history_q are queue.Queue (thread-safe) with maxsize=5000
   - Queue full → put_nowait drops with warning (no crash)
   - stop_event is threading.Event shared between engine and workers

9. **PullSDK Thread Safety**: Verify:
   - Each worker has its own PullSDKDevice instance (no shared connections)
   - poll_rtlog_once and open_door are called only from the owning worker thread
   - The watchdog thread only reads result[0] / error[0], doesn't call SDK
   - PullSDKDevice internally uses _sdk_lock — verify no deadlock with watchdog pattern

10. **SQLite Concurrency**: Verify:
    - insert_access_history: uses get_conn() context manager with WAL mode
    - load_local_state: uses get_conn() — safe for concurrent reads under WAL
    - Multiple workers inserting history simultaneously — is there contention?
    - UltraSyncScheduler writes sync cache while workers read — WAL isolation OK?

### C. ULTRA Mode — Sync Scheduler

11. **UltraSyncScheduler**: Read the full class. Verify:
    - Hash-based change detection: what fields are included in the hash?
    - Is the hash sufficient? (Only checks activeMembershipId — misses card number changes, fingerprint changes?)
    - DeviceSyncEngine.run_blocking() — does it filter by accessDataMode? Will it skip ULTRA devices?
    - Immediate first sync on start
    - Per-device interval configuration
    - Stop signal respected (no infinite blocking)

### D. AGENT Mode — Regression Check

12. **Shared Module Extraction**: Verify that AGENT mode still works after extraction:
    - realtime_agent.py imports AccessEvent, NotificationRequest, HistoryRecord from access_types.py
    - realtime_agent.py imports verify_totp, verify_card, load_local_state from access_verification.py
    - DecisionService methods are thin wrappers calling shared functions
    - No behavior change for existing AGENT mode logic

13. **AgentRealtimeEngine**: Quick scan for any unintended changes:
    - Still filters for AGENT-mode devices only
    - Still uses its own popup_q, history_q (separate from ULTRA)
    - refresh_devices() called in _sync_tick after agent engine start

### E. DEVICE Mode — Regression Check

14. **DeviceSyncEngine**: Verify:
    - Still filters by `mode != "DEVICE"` → skips non-DEVICE devices
    - ULTRA devices are correctly skipped (not double-pushed by both DeviceSyncEngine and UltraSyncScheduler)
    - No changes to push logic

### F. Mode Switching

15. **DEVICE → ULTRA**: Verify in app.py _sync_tick:
    - UltraEngine starts for ULTRA devices
    - DeviceSyncEngine naturally skips ULTRA devices (filter check)
    - UltraSyncScheduler does immediate first push
    - No data loss (device already has user data)

16. **AGENT → ULTRA**: Verify:
    - Agent engine drops ULTRA devices on next refresh_devices() cycle
    - No event queue leak (agent pending events for that device)
    - ULTRA engine starts and begins polling

17. **ULTRA → DEVICE or AGENT**: Verify:
    - ULTRA engine stops when ultra_count == 0
    - History consumer stops
    - Appropriate engine picks up the device

18. **Mixed modes**: Can a gym have devices in all 3 modes simultaneously?
    - Verify no shared state conflicts between engines
    - Verify mode summary counts are accurate

### G. App Wiring

19. **Startup Flow**: Read app.py. Verify:
    - UltraEngine initialized in constructor
    - _sync_tick checks mode summary and starts/stops ULTRA engine
    - HistoryService wired with correct arguments (logger, history_q, global_settings callable)
    - global_settings passed as get_backend_global_settings function reference

20. **Shutdown Flow**: Read destroy(). Verify:
    - ULTRA engine stopped
    - History consumer stopped
    - Worker threads joined with timeout (no hang on exit)
    - Agent engine also stopped (existing behavior)

### H. API & SSE

21. **GET /api/v2/ultra/status**: Verify:
    - Returns {"running": false, "devices": {}} when engine not running
    - Returns full device snapshots when running
    - Route registered in local_api_routes.py

22. **GET /api/v2/status**: Verify:
    - Mode summary includes ULTRA count
    - Response includes "ultra" key with engine status
    - Backward compatible (existing "agent" key still present)

23. **SSE /api/v2/agent/events**: Verify:
    - ULTRA popup events are drained from ultra_engine.popup_q
    - Uses same SSE event format as agent popups
    - Non-blocking drain (get_nowait with queue.Empty catch)
    - Limited to 10 events per SSE tick (prevents starvation)

### I. Performance Analysis

24. **TOTP Rescue Latency Budget**: Verify the claim of ~200ms:
    - RTLog poll interval (adaptive sleep: 0-2000ms depending on activity)
    - verify_totp computation time (HMAC-SHA1 — should be <1ms)
    - open_door TCP command time (~50-100ms)
    - Is the 200ms claim realistic? What's the worst case?

25. **Peak Time**: 60 members in 10 minutes:
    - 48 RFID: device handles, PC only reads RTLog passively
    - 12 TOTP: ~200ms each = 2.4s total
    - Can the polling keep up? What if RTLog buffers 10 events?

26. **Memory**: Check for leaks:
    - deque maxlen=10,000 bounded
    - Queue maxsize=5000 bounded
    - _cached_state refreshed every 5s (old state garbage collected?)
    - PullSDKDevice ctypes handles — properly freed on disconnect?

### J. Error Handling & Edge Cases

27. **Device unreachable after connect**:
    - Mid-session disconnect: poll_with_watchdog returns None → reconnect
    - What if the device IP changes? (DHCP)
    - What if PullSDK DLL is missing? (access client installed without SDK)

28. **Empty sync cache**:
    - UltraSyncScheduler: what if load_sync_cache() returns None?
    - Workers: what if load_local_state() returns empty lists?
    - TOTP verification with empty creds: always denies?

29. **Backend unreachable**:
    - Access client uses cached data — ULTRA still works
    - History queue fills up — what happens at 5000 limit?
    - Sync scheduler uses cached sync data — hash comparison still works?

30. **Corrupt SQLite database**:
    - WAL mode: what if WAL file is corrupt?
    - insert_access_history failure: still tries to enqueue (fail-open)
    - pre_populate_seen failure: logs warning and continues (OK)

### K. Security

31. **TOTP Replay Protection**: Verify:
    - Event ID dedup prevents same event from being processed twice
    - TOTP code collision: reject if 2+ credentials match same code?
    - TOTP age validation: reject expired/future-skewed codes?
    - Does verify_totp handle all these? Read the actual implementation.

32. **PC cannot override device decisions**: Verify:
    - ALLOW events: PC sends NO door command (enrichment only)
    - DENY events (non-TOTP): PC sends NO door command
    - Only TOTP rescue sends open_door — and only after cryptographic verification

### L. Test Coverage Gaps

33. **Review test files**: Identify what's NOT tested:
    - UltraSyncScheduler hash detection
    - Mode switching scenarios
    - SSE popup drain
    - PullSDKDevice connection/disconnect lifecycle
    - Full _process_event end-to-end with mocked SDK
    - HistoryService consumer integration
    - Concurrent access from multiple workers

## Output Format

For each item, report:

```
### [Item Number] — [Title]
**Status:** ✅ PASS | ⚠️ CONCERN | ❌ FAIL | 🔍 NEEDS MANUAL TEST
**Finding:** [What you found]
**Risk:** [HIGH / MEDIUM / LOW / NONE]
**Fix Required:** [Yes/No — if yes, describe the fix]
**File:Line:** [exact location]
```

At the end, provide:

1. **LAUNCH BLOCKERS** — Issues that MUST be fixed before production
2. **LAUNCH WARNINGS** — Issues to monitor but not blocking
3. **POST-LAUNCH TODO** — Improvements for after launch
4. **OVERALL VERDICT** — SAFE TO LAUNCH / LAUNCH WITH CONDITIONS / DO NOT LAUNCH

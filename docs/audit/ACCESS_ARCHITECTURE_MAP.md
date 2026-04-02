# MonClub Access — Runtime Architecture Map
# Round 6 — 2026-04-02

## Runtime component overview

```
┌──────────────────────────────────────────────────────────────────────┐
│  Windows process: MonClubAccess.exe  (32-bit Python, PyInstaller)    │
│                                                                      │
│  MainApp (app/ui/app.py)                                             │
│  ├─ sync_tick() — 60s timer, daemon thread (_work_guarded)           │
│  │   ├─ MonClubApi.get_sync_data() ──► backend (cloud)              │
│  │   ├─ save_sync_cache(data) ──► SQLite (with anti-wipe guard)     │
│  │   ├─ DeviceSyncEngine.run_blocking() [DEVICE mode devices only]  │
│  │   │   ● BUG: also processes ULTRA devices (normalize ULTRA→DEVICE)│
│  │   ├─ DeviceAttendanceMaintenanceEngine.run_blocking()             │
│  │   │   ├─ PullSDK → read device attendance log                    │
│  │   │   └─ MonClubApi.sync_access_history() ──► backend            │
│  │   ├─ AgentRealtimeEngine.refresh_devices() [AGENT mode]           │
│  │   └─ UltraEngine start/stop management [ULTRA mode]               │
│  │       ● BUG: new ULTRA device ignored if engine already running  │
│  │                                                                   │
│  ├─ LocalAccessApiServerV2  127.0.0.1:8788  (ThreadingHTTPServer)   │
│  │   └─ 88 endpoints — auth-gated by X-Local-Token (per-session)    │
│  │                                                                   │
│  ├─ AgentRealtimeEngine (app/core/realtime_agent.py)                 │
│  │   ├─ DeviceWorker × N  (one per AGENT-mode device, daemon thread) │
│  │   │   └─ PullSDK → poll_rtlog_once() every 200–2000ms            │
│  │   ├─ DecisionService  (1 thread, consumes event_q)                │
│  │   │   ├─ verify_totp / verify_card ──► SQLite cache               │
│  │   │   ├─ insert_access_history (INSERT OR IGNORE) ──► SQLite     │
│  │   │   └─ DeviceCommandBus.open_door() ──► PullSDK                │
│  │   └─ NotificationService (Windows toast, daemon thread)           │
│  │                                                                   │
│  ├─ UltraEngine (app/core/ultra_engine.py)                           │
│  │   ├─ UltraDeviceWorker × N (one per ULTRA device, daemon thread)  │
│  │   │   ├─ PullSDK → poll_rtlog_once() via 15s watchdog thread      │
│  │   │   ├─ classify: ALLOW (passive) / TOTP_RESCUE (active) / DENY │
│  │   │   ├─ verify_totp ──► SQLite cache (5s TTL)                   │
│  │   │   ├─ insert_access_history(history_source="ULTRA") ──► SQLite│
│  │   │   └─ PullSDK.open_door() (TOTP rescue only)                  │
│  │   ├─ UltraSyncScheduler (1 thread, 15-min interval)               │
│  │   │   └─ DeviceSyncEngine.run_blocking() [DEVICE copy of device] │
│  │   └─ HistoryService (1 thread, history_q consumer) [pruning only]│
│  │                                                                   │
│  └─ Tauri UI process (monclub-access-ui.exe, child process)          │
│      ├─ React + WebView frontend                                     │
│      ├─ HTTP to LocalAccessApiServerV2 with X-Local-Token header     │
│      └─ SSE popup stream with ?token= query param                    │
└──────────────────────────────────────────────────────────────────────┘
         │                          │
         ▼                          ▼
    SQLite WAL DB              MonClub Backend (cloud)
  (AppData/access.db)        (Spring REST API)
```

---

## Module responsibilities

| Module | Role |
|--------|------|
| `app/ui/app.py` — `MainApp` | Orchestrator: owns all engines, sync timer, local API, Tauri launcher, ULTRA lock |
| `app/core/realtime_agent.py` — `AgentRealtimeEngine` | AGENT mode: RTLog polling, PC-side decisions, door commands, notifications |
| `app/core/ultra_engine.py` — `UltraEngine` | ULTRA mode: firmware observe + TOTP rescue; UltraSyncScheduler |
| `app/core/device_sync.py` — `DeviceSyncEngine` | DEVICE mode push: users / FP templates / userauthorize to ZKTeco |
| `app/core/device_attendance.py` — `DeviceAttendanceMaintenanceEngine` | Read ZK attendance log; upload to backend; prune old rows |
| `app/core/access_verification.py` | Shared TOTP + RFID verify logic (pure functions) |
| `app/core/db.py` | SQLite abstraction: schema, WAL, migrations, all CRUD |
| `app/core/settings_reader.py` | Normalize backend-synced settings to snake_case; fallback chain |
| `app/api/local_access_api_v2.py` | 88-endpoint local HTTP API; per-session token auth middleware |
| `app/sdk/pullsdk.py` | ZKTeco PullSDK wrapper (plcommpro.dll, 32-bit) |
| `app/sdk/zkfinger.py` | ZKTeco fingerprint SDK wrapper (fail-closed on OSError) |
| `shared/auth_state.py` | DPAPI-protected auth token encrypt/decrypt |
| `access/store.py` | Offline creation queue, SQLite init, auth token read/write |
| `access/config.py` | App config loader, API endpoint builder |
| `tv/` | TV component (separate runtime, mostly isolated from access) |

---

## End-to-end flow: DEVICE mode

```
[Backend sync — every sync_interval_sec, default 60s]
  MainApp.sync_tick()
    MonClubApi.get_sync_data(token)
    save_sync_cache(data)
      → writes sync_users, sync_devices, sync_access_software_settings
      → anti-wipe guard: refuses to clear if backend returns 0 users and local has >10

[Device push — if DEVICE-mode devices exist]
  DeviceSyncEngine.run_blocking(cache, source="timer")
    _sync_all_devices(cache):
      for each active device where accessDataMode == "DEVICE":
        _normalize_device(d)
        _filter_users_for_device() — validFrom/validTo, allowedMemberships filter
        _collect_templates_for_pin() — fingerprint templates from cache or local DB
        _compute_desired_hash() — sha1(pin+name+card+doors+tz+templates)
        compare with stored hash in sync_device_state
        if hash changed OR pin missing on device:
          PullSDK.connect(ip, port, timeout_ms, password)
          get_device_data_rows("user") → current pins on device
          delete stale pins (known-from-server, no longer desired)
          for changed pins:
            set_device_data("user")
            set_device_data("userauthorize")
            set_device_data("template"/"templatev10")
          save_device_sync_state(pin, desired_hash, ok=True)
        PullSDK.disconnect()

[Attendance upload — every sync_tick]
  DeviceAttendanceMaintenanceEngine.run_blocking()
    for each DEVICE-mode device:
      read attendance via PullSDK get_device_data_rows("AttLog")
      insert_access_history_batch() — INSERT OR IGNORE
    list_pending_access_history_for_sync(limit=200)
    MonClubApi.sync_access_history(items)
    mark_access_history_synced(row_ids)
    fixed retry delay: 300s on failure (no backoff)
```

---

## End-to-end flow: AGENT mode

```
[AgentRealtimeEngine.start()]
  read global settings from SQLite
  for each AGENT-mode device: DeviceWorker.start()  — daemon thread
  DecisionService.start() — daemon thread
  NotificationService.start() — daemon thread

[Per-device polling loop — DeviceWorker.run()]
  PullSDK.ensure_connected()  (exponential backoff on failure: 0.25s → 30s)
  poll_rtlog_once() via 15s watchdog thread
  for each event not in _seen deque (maxlen=10000):
    if not _is_old_by_cursor():  (epoch comparison + last_event_id check)
      event_queue.put(AccessEvent)
      update cursor state (device_id, last_event_at, last_event_id) → SQLite every 1s

[Decision loop — DecisionService.run()]
  ev = event_queue.get(timeout=0.05)
  if access_history_exists(ev.event_id): skip (dedup before verify)
  settings = settings_provider(ev.device_id)   (cached 2s)
  creds, users_by_am, users_by_card = _load_local_state()  (TTL 2s)
  vr = verify_totp(ev.card_no, settings, creds, ...)
  if allowed:
    rowcount = insert_access_history(...) [INSERT OR IGNORE — atomic claim]
    if rowcount == 1:
      DeviceCommandBus.open_door(device_id, door_id, pulse_ms)
    else:
      continue  (race-condition dedup: another worker already claimed)
  NotificationGate.allow(key) → enqueue to notify_q and popup_q

[History upload — same DeviceAttendanceMaintenance as DEVICE]
  uploads PENDING rows from access_history table (all sources including AGENT)
```

---

## End-to-end flow: ULTRA mode

```
[UltraEngine.start() — triggered from sync_tick when ULTRA devices appear]
  normalize_device_settings(d) → _settings per device
  UltraSyncScheduler.start(devices)
  for each ULTRA device: UltraDeviceWorker.start()  — daemon thread
  HistoryService.start() consuming history_q

[Per-device polling loop — UltraDeviceWorker.run()]
  PullSDK.connect() (5s retry on failure)
  _poll_with_watchdog() — 15s watchdog; returns RTLog events
  _pre_populate_seen() — loads last 200 event IDs from DB at startup

  for each event not in _seen deque (maxlen=10000):
    parse event_type (0 = ALLOW, non-0 = firmware-denied)

    if event_type == 0:
      _handle_allow()  [passive]
        lookup user in local cache by card
        insert_access_history(history_source="ULTRA")
        history_q.put(record) only if INSERT succeeded

    elif _is_totp_format(card_no):
      _handle_totp_rescue()  [active]
        verify_totp(code, settings, creds, users_by_am, users_by_card)
        if allowed:
          _open_door_with_retry(door_id=event_door or configured_default)
          retry once on failure (100ms delay between attempts)
        insert_access_history(history_source="ULTRA")
        history_q.put(record) only if INSERT succeeded

    else:
      _handle_deny()  [passive]
        insert_access_history(history_source="ULTRA")

[UltraSyncScheduler — 15-min interval]
  _sync_device(device):
    load_sync_cache()
    compute coarse payload hash (activeMembershipId + cards + fingerprintsHash)
    if hash unchanged: skip
    device_copy["accessDataMode"] = "DEVICE"  ← trick DeviceSyncEngine
    DeviceSyncEngine.run_blocking(filtered_cache)

[HistoryService for ULTRA — effectively only runs pruning]
  dequeue from history_q
  insert_access_history() with NO history_source → OR IGNORE (no-op, row already exists)
  every 200 items: prune_access_history() + prune_offline_creation_queue()

[History upload — same DeviceAttendanceMaintenance]
  uploads PENDING rows from access_history (includes ULTRA rows)
```

---

## Architectural contradictions found

### 1. ULTRA devices double-processed by DeviceSyncEngine (NEW — unfixed)

`DeviceSyncEngine._normalize_device()` at `app/core/device_sync.py:206-210`:
```python
if adm not in ("DEVICE", "AGENT"):
    adm = "DEVICE"    # "ULTRA" silently becomes "DEVICE"
```
After normalization, `_sync_all_devices()` doesn't skip ULTRA devices because their mode is now "DEVICE". When a DEVICE+ULTRA mixed setup exists, `sync_tick` passes the DEVICE guard check and calls `DeviceSyncEngine.run_blocking()` with the full cache. Both `DeviceSyncEngine` and `UltraSyncScheduler` now independently connect to and push data to ULTRA devices.

### 2. UltraEngine.start() is not incremental (NEW — unfixed)

`UltraEngine.start()` returns early if `self._running`. New ULTRA devices added at runtime are silently ignored until all existing ULTRA devices go away (triggering `_ultra_engine.stop()`) and then reappear (triggering a fresh `_ultra_engine.start()`).

### 3. HistoryService for ULTRA is architecturally misleading (not a safety issue)

ULTRA workers insert history directly before enqueuing. HistoryService's second `insert_access_history()` call is a no-op (INSERT OR IGNORE). The architecture implies HistoryService is responsible for ULTRA history writes, but it isn't. The only effective contribution of HistoryService for ULTRA is the pruning side effect every 200 items.

### 4. `_sync_work_running` set inside thread (race window — minor)

`self._sync_work_running = True` is set inside the thread body rather than before `threading.Thread(...).start()`. In the window between thread start and flag set, a second `_sync_tick` can pass the guard. In practice the 60s interval makes this extremely unlikely, but it is architecturally incorrect.

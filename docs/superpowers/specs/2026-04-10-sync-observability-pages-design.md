# Sync Observability Pages — Design Spec
**Date**: 2026-04-10
**Status**: Revised for implementation

---

## Overview

The original proposal mixed three repos and a few generated assumptions that do not match the live code. This revised spec keeps the same product goal, but splits delivery into an Access-first phase that fits the current MonClub Access architecture cleanly.

**Phase 1 in this session**
- MonClub Access SQLite observability tables
- MonClub Access sync trigger/run history
- MonClub Access device push batch + pin history
- MonClub Access Tauri pages for Sync History and Push History
- MonClub Access device detail "Contenu" tab, reusing the existing live device table endpoints

**Phase 2 after Access stabilizes**
- Spring Boot paginated `access_sync_event` endpoint
- Dashboard Access Sync Events page

This lets us land the highest-value observability inside MonClub Access without forcing parallel backend/dashboard changes before the data model is proven locally.

---

## Codebases Involved

| Codebase | Role in this phase | Path |
|----------|--------------------|------|
| MonClub Access (Python backend) | Phase 1 implementation | `C:\Users\mohaa\Desktop\monclub_access_python` |
| MonClub Access (Tauri frontend) | Phase 1 implementation | `C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui` |
| MonClub Backend | Phase 2 only | `D:\projects\MonClub\monclub_backend` |
| MonClub Dashboard | Phase 2 only | `C:\Users\mohaa\Desktop\mon_club_dashboard` |

---

## Phase 1 — Access: Sync Run History

### Purpose

Record each Access sync execution with enough metadata to answer:
- what triggered it
- whether it was a startup/timer/manual/hard-reset flow
- whether backend fetch/device push succeeded
- how many members/devices were involved
- what compact backend response summary came back

### SQLite table

**File**: `app/core/db.py`

```sql
CREATE TABLE IF NOT EXISTS sync_run_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_type        TEXT NOT NULL,   -- PERIODIC | TRIGGERED | HARD_RESET
    trigger_source  TEXT NOT NULL,   -- TIMER | STARTUP | SYNC_NOW_API | CHANGE_DETECTOR
    trigger_hint    TEXT,            -- JSON string, optional
    status          TEXT NOT NULL,   -- IN_PROGRESS | SUCCESS | PARTIAL | FAILED | SKIPPED
    members_total   INTEGER DEFAULT 0,
    members_changed INTEGER DEFAULT 0,
    devices_synced  INTEGER DEFAULT 0,
    duration_ms     INTEGER DEFAULT 0,
    error_message   TEXT,
    raw_response    TEXT,            -- compact JSON summary, not full payload
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sync_run_history_created_at ON sync_run_history(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sync_run_history_status ON sync_run_history(status);
CREATE INDEX IF NOT EXISTS idx_sync_run_history_trigger_source ON sync_run_history(trigger_source);
```

### Trigger context plumbing

The current code collapses all manual/change-detector syncs into `request_sync_now() -> _sync_tick()` with no metadata, so observability would be wrong unless we add context propagation.

**Files**
- `app/ui/app.py`
- `app/core/change_detector.py`
- `app/api/local_access_api_v2.py`

**Required behavior**
- `request_sync_now()` must accept trigger metadata instead of being no-arg only.
- `MainApp` stores one pending sync context for the next `_sync_tick()`.
- The first sync after app startup is recorded as:
  - `run_type=PERIODIC`
  - `trigger_source=STARTUP`
- Timer-driven background syncs are recorded as:
  - `run_type=PERIODIC`
  - `trigger_source=TIMER`
- `POST /api/v2/sync/now` records:
  - `run_type=TRIGGERED`
  - `trigger_source=SYNC_NOW_API`
- hard reset records:
  - `run_type=HARD_RESET`
  - `trigger_source=SYNC_NOW_API`
  - `trigger_hint={"hardReset": true}`
- change detector records:
  - `run_type=TRIGGERED`
  - `trigger_source=CHANGE_DETECTOR`

### `_sync_tick()` integration

**File**: `app/ui/app.py`

Inside `_sync_tick()`:
1. Resolve the effective trigger context.
2. Insert an `IN_PROGRESS` row before the backend sync work starts.
3. Store a compact response summary after `getSyncData`.
4. Run device sync with the same run id.
5. Update the row at the end with final status, duration, counters, and any error text.

### Compact `raw_response` shape

We should not store the full backend response payload because it can be large and redundant with the local cache. Store a compact JSON summary instead:

```json
{
  "refresh": {
    "members": true,
    "devices": false,
    "credentials": true,
    "settings": false
  },
  "membersDeltaMode": true,
  "usersCount": 3,
  "devicesCount": 12,
  "validMemberIdsCount": 318,
  "newTokens": {
    "membersVersion": "...",
    "devicesVersion": "..."
  }
}
```

### Local API

**Files**
- `access/local_api_routes.py`
- `app/api/local_access_api_v2.py`

Add:

```http
GET /api/v2/sync-history?page=0&size=25&run_type=TRIGGERED&status=FAILED
GET /api/v2/sync-history/{id}
```

List response excludes `raw_response` for table performance. Detail response includes everything.

### Access UI page

**New page**: `tauri-ui/src/pages/SyncHistoryPage.tsx`

Table columns:
- `created_at`
- `run_type`
- `trigger_source`
- `status`
- `members_changed / members_total`
- `devices_synced`
- `duration_ms`

Filters:
- status
- run type

Row click opens a detail dialog with:
- trigger metadata
- error message
- pretty-printed `trigger_hint`
- pretty-printed `raw_response`

---

## Phase 1 — Access: Device Push History

### Purpose

Expose device-level and pin-level push outcomes for DEVICE-mode syncs so operators can see which device ran, how many pins were attempted, and which members failed.

### SQLite tables

**File**: `app/core/db.py`

```sql
CREATE TABLE IF NOT EXISTS push_batch_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sync_run_id     INTEGER REFERENCES sync_run_history(id) ON DELETE SET NULL,
    device_id       INTEGER NOT NULL,
    device_name     TEXT NOT NULL,
    policy          TEXT NOT NULL,
    pins_attempted  INTEGER DEFAULT 0,
    pins_success    INTEGER DEFAULT 0,
    pins_failed     INTEGER DEFAULT 0,
    status          TEXT NOT NULL,   -- IN_PROGRESS | SUCCESS | PARTIAL | FAILED
    duration_ms     INTEGER DEFAULT 0,
    error_message   TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_push_batch_history_created_at ON push_batch_history(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_push_batch_history_device_id ON push_batch_history(device_id);

CREATE TABLE IF NOT EXISTS push_pin_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id      INTEGER NOT NULL REFERENCES push_batch_history(id) ON DELETE CASCADE,
    pin           TEXT NOT NULL,
    full_name     TEXT,
    operation     TEXT NOT NULL,     -- UPSERT
    status        TEXT NOT NULL,     -- SUCCESS | FAILED
    error_message TEXT,
    duration_ms   INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_push_pin_history_batch_id ON push_pin_history(batch_id);
```

`get_conn()` must enable:

```python
conn.execute("PRAGMA foreign_keys = ON")
```

### Integration point

The previous draft pointed at `DeviceWorker._execute()`, but the actual sync work happens in `DeviceSyncEngine._sync_one_device()`.

**Files**
- `app/core/device_worker.py`
- `app/core/device_sync.py`

**Required behavior**
- Add `sync_run_id` to `SyncJob`.
- Pass it through `DeviceWorker._execute()`.
- Extend `_sync_one_device(..., sync_run_id: int | None = None)`.
- Create a `push_batch_history` row once per device sync execution.
- Record one `push_pin_history` row per attempted pin push.
- Finalize the batch row with counts and status.

### Pin-level semantics

For the first phase, the pin history should answer "did this member push succeed overall?" instead of trying to represent every low-level SDK sub-step separately.

Use:
- `operation=UPSERT`
- `status=SUCCESS` when the user row + authorization step complete successfully
- `status=FAILED` otherwise

Template warnings can remain in logs for now and contribute to batch-level partial status if needed, but do not need a separate per-template history table in this phase.

### Local API

Add:

```http
GET /api/v2/push-history?page=0&size=25&device_id=3&status=PARTIAL
GET /api/v2/push-history/{batchId}/pins
```

### Access UI page

**New page**: `tauri-ui/src/pages/PushHistoryPage.tsx`

Batch table columns:
- `created_at`
- `device_name`
- `policy`
- `pins_attempted`
- `pins_success`
- `pins_failed`
- `status`
- `duration_ms`

Filters:
- device
- status

Row click opens a pins dialog with:
- `pin`
- `full_name`
- `operation`
- `status`
- `error_message`
- `duration_ms`

---

## Phase 1 — Access: Device Content Viewer

### Purpose

Let operators inspect live device tables from the existing device detail dialog without introducing a second overlapping backend API.

### Reuse existing endpoints

The Access app already exposes:

```http
GET /api/v2/devices/{deviceId}/info
GET /api/v2/devices/{deviceId}/table/{tableName}
```

So this phase will **not** add a new aggregate `device-content/read` endpoint.

Instead, the Tauri device dialog will:
1. add a new `Contenu` tab
2. read selected live tables on demand using the existing `/devices/{deviceId}/table/{tableName}` route
3. keep per-table error state in the UI

### UI behavior

**File**: `tauri-ui/src/pages/DevicesPage.tsx`

Inside the existing info dialog:
- keep the current `Cache`, `Presets portes`, and `Live (PullSDK)` tabs
- add a `Contenu` tab
- offer sub-tabs for:
  - `users`
  - `userauthorize`
  - `templatev10`
  - `transactions`
- fetch table data lazily when the user clicks `Lire le contenu`
- display partial failures inline per table without collapsing the whole dialog

This keeps the design aligned with the code that already exists.

---

## Retention

The repo already has pruning helpers and real cleanup callers.

**Files**
- `app/core/db.py`
- `app/core/device_attendance.py`
- `app/core/realtime_agent.py`

Add:
- `prune_sync_run_history(retention_days: int = 30) -> int`
- `prune_push_batch_history(retention_days: int = 30) -> int`

Wire them into the existing cleanup paths alongside `prune_access_history()` and `prune_offline_creation_queue()`.

Deleting old batches automatically removes old pin rows because of `ON DELETE CASCADE`.

---

## Phase 2 — Dashboard Access Sync Events Page

This remains valid, but is intentionally deferred until the Access-side data model and UI settle.

When resumed:
- backend endpoint must follow existing Spring/JPA patterns
- dashboard route/nav/prefetch/title wiring must match the real dashboard file structure
- `GymService.ts` must follow the existing axios client pattern, not a standalone `fetch` helper

---

## Files Changed Summary

### MonClub Access — Python
- `app/core/db.py`
- `app/ui/app.py`
- `app/core/change_detector.py`
- `app/core/device_worker.py`
- `app/core/device_sync.py`
- `access/local_api_routes.py`
- `app/api/local_access_api_v2.py`
- `tests/test_sync_observability.py`

### MonClub Access — Tauri UI
- `tauri-ui/src/App.tsx`
- `tauri-ui/src/layouts/MainLayout.tsx`
- `tauri-ui/src/api/hooks.ts`
- `tauri-ui/src/pages/DevicesPage.tsx`
- `tauri-ui/src/pages/SyncHistoryPage.tsx`
- `tauri-ui/src/pages/PushHistoryPage.tsx`

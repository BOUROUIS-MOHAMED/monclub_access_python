# Sync Observability Pages — Design Spec
**Date**: 2026-04-10
**Status**: Approved

---

## Overview

Four new UI pages across two codebases (MonClub Dashboard and MonClub Access) that expose full visibility into the sync pipeline: backend CDC events, sync run history, per-device push history, and live device content inspection.

---

## Codebases Involved

| Codebase | Tech | Path |
|----------|------|------|
| MonClub Dashboard | React + MUI + TypeScript | `C:\Users\mohaa\Desktop\mon_club_dashboard` |
| MonClub Access (Python backend) | Python + SQLite | `C:\Users\mohaa\Desktop\monclub_access_python` |
| MonClub Access (Tauri frontend) | React + TypeScript (inside Tauri) | `C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui` |
| MonClub Backend | Spring Boot | `D:\projects\MonClub\monclub_backend` |

---

## Feature 1 — Dashboard: Access Sync Events Page

### Purpose
A standalone dashboard page for gym managers to inspect all `access_sync_event` rows — the CDC events fired by the backend when members or devices change.

### Backend — New Endpoint

**File**: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Controllers\GymAccessController.java`

```
GET /api/v1/manager/gym/access/v1/events
    ?page=0&size=25&entityType=ACTIVE_MEMBERSHIP&operation=UPDATE&priority=HIGH
```

- Response: `PageResult<AccessSyncEventDto>` sorted by `id DESC`
- `AccessSyncEventDto` fields: `id`, `gymId`, `entityType`, `entityId`, `operation`, `priority`, `membershipId`, `createdAt`
- Filters are optional; all combine with AND
- New `@Query` or `Specification` method added to `AccessSyncEventRepository`

### Dashboard — New Section

**New files** (follow exact pattern of `src/sections/GymAccessDoorHistory/`):
```
src/sections/AccessSyncEvents/
  view/
    access-sync-events-view.tsx       ← main page component
    index.ts
  access-sync-events-table-head.tsx
  access-sync-events-table-row.tsx
  access-sync-events-table-toolbar.tsx
  access-sync-events-table-empty-rows.tsx
  table-no-data.tsx
  utils.ts
```

**New model**: `src/models/AccessSyncEvent.ts`
```typescript
export interface AccessSyncEvent {
  id: number;
  gymId: number;
  entityType: 'ACTIVE_MEMBERSHIP' | 'GYM_DEVICE';
  entityId: number;
  operation: 'CREATE' | 'UPDATE' | 'DELETE';
  priority: 'HIGH' | 'NORMAL' | 'LOW';
  membershipId: number | null;
  createdAt: string;
}
```

**New page file**: `src/pages/GymAccessSyncEvents.tsx`

**Route**: add to `src/routes/` and navigation sidebar

**Table columns**: `id`, `entityType`, `entityId`, `operation`, `priority` (colored badge), `membershipId`, `createdAt`

**Toolbar filters**: entityType (dropdown), operation (dropdown), priority (dropdown)

**Row click**: opens a detail dialog showing all fields with `createdAt` formatted as readable datetime

**API call**: `GET /api/v1/manager/gym/access/v1/events` via existing `GymService.ts` pattern

---

## Feature 2 — Access: Sync Run History Page

### Purpose
Records every sync execution in the Access app so users can see what happened, when, why, and with what result.

### New SQLite Table

**File**: `app/core/db.py` — add to `init_db()`

```sql
CREATE TABLE IF NOT EXISTS sync_run_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_type        TEXT NOT NULL,   -- PERIODIC | TRIGGERED | HARD_RESET
    trigger_source  TEXT NOT NULL,   -- TIMER | SYNC_NOW_API | CHANGE_DETECTOR | STARTUP
    trigger_hint    TEXT,            -- JSON of SyncHint if triggered, else NULL
    status          TEXT NOT NULL,   -- SUCCESS | PARTIAL | FAILED | SKIPPED
    members_total   INTEGER DEFAULT 0,
    members_changed INTEGER DEFAULT 0,
    devices_synced  INTEGER DEFAULT 0,
    duration_ms     INTEGER DEFAULT 0,
    error_message   TEXT,
    raw_response    TEXT,            -- JSON summary of getSyncData response
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_srh_created ON sync_run_history(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_srh_status  ON sync_run_history(status);
```

**db.py helpers to add**:
- `insert_sync_run(run_type, trigger_source, ...) -> int` — returns new id
- `update_sync_run(id, status, members_total, members_changed, devices_synced, duration_ms, error_message, raw_response)`
- `list_sync_runs(*, page, size, run_type=None, status=None) -> dict` — returns `{items, total}`
- `get_sync_run(id) -> dict | None`

**Retention**: prune rows older than 30 days in the existing daily cleanup routine.

### Integration Points in `app/ui/app.py`

In `_sync_tick()`:
1. Before sync: `run_id = insert_sync_run(run_type, trigger_source, trigger_hint, status="IN_PROGRESS", created_at=now)`
2. After sync completes (success or failure): `update_sync_run(run_id, status=..., members_total=..., members_changed=..., devices_synced=..., duration_ms=..., error_message=..., raw_response=...)`

`trigger_source` is determined by what initiated the tick:
- `TIMER` — normal periodic tick
- `SYNC_NOW_API` — triggered by `POST /api/v2/sync/now`
- `CHANGE_DETECTOR` — triggered by the ChangeDetectorService event
- `STARTUP` — first tick after login

### New Local API Endpoints

**File**: `app/api/local_access_api_v2.py`

```
GET /api/v2/sync-history
    ?page=0&size=25&run_type=TRIGGERED&status=FAILED
    → { items: [...], page, size, total }
    (excludes raw_response from list for performance)

GET /api/v2/sync-history/{id}
    → full row including raw_response and trigger_hint
```

### Access Tauri UI

**New page**: Sync History — accessible from main navigation

**Table columns**:
| Column | Notes |
|--------|-------|
| `created_at` | formatted datetime |
| `run_type` | badge |
| `trigger_source` | |
| `status` | colored badge (green=SUCCESS, yellow=PARTIAL, red=FAILED, grey=SKIPPED) |
| `members_changed / members_total` | e.g. "3 / 2000" |
| `devices_synced` | |
| `duration_ms` | formatted as "1.2s" |

**Filters**: status dropdown, run_type dropdown

**Row click** → detail dialog:
- All fields
- `trigger_hint` JSON — pretty-printed (collapsible)
- `raw_response` JSON — pretty-printed (collapsible)
- `error_message` — shown in red if present

---

## Feature 3 — Access: Device Push History Page

### Purpose
Records every sync batch dispatched to a ZKTeco device, with per-pin detail inside each batch.

### New SQLite Tables

**File**: `app/core/db.py`

```sql
CREATE TABLE IF NOT EXISTS push_batch_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sync_run_id     INTEGER,         -- FK → sync_run_history.id (nullable)
    device_id       INTEGER NOT NULL,
    device_name     TEXT NOT NULL,
    policy          TEXT NOT NULL,   -- INCREMENTAL | FULL_REPLACE | ADDITIVE_ONLY
    pins_attempted  INTEGER DEFAULT 0,
    pins_success    INTEGER DEFAULT 0,
    pins_failed     INTEGER DEFAULT 0,
    status          TEXT NOT NULL,   -- SUCCESS | PARTIAL | FAILED
    duration_ms     INTEGER DEFAULT 0,
    error_message   TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pbh_device  ON push_batch_history(device_id);
CREATE INDEX IF NOT EXISTS idx_pbh_created ON push_batch_history(created_at DESC);

CREATE TABLE IF NOT EXISTS push_pin_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id      INTEGER NOT NULL,  -- FK → push_batch_history.id
    pin           TEXT NOT NULL,
    full_name     TEXT,
    operation     TEXT NOT NULL,     -- INSERT | UPDATE | DELETE
    status        TEXT NOT NULL,     -- SUCCESS | FAILED
    error_message TEXT,
    duration_ms   INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_pph_batch ON push_pin_history(batch_id);
```

**db.py helpers to add**:
- `insert_push_batch(sync_run_id, device_id, device_name, policy, ...) -> int`
- `update_push_batch(id, pins_attempted, pins_success, pins_failed, status, duration_ms, error_message)`
- `insert_push_pin(batch_id, pin, full_name, operation, status, error_message, duration_ms)`
- `list_push_batches(*, page, size, device_id=None, status=None) -> dict`
- `get_push_batch_pins(batch_id) -> list`

**Retention**: prune rows older than 30 days in the daily cleanup routine (cascade: delete pins when batch deleted).

### Integration Points in `app/core/device_sync.py`

In `DeviceWorker._execute()` (inside the per-device sync loop):
1. Before push: `batch_id = insert_push_batch(sync_run_id, device_id, device_name, policy, ...)`
2. Per pin push result: `insert_push_pin(batch_id, pin, full_name, operation, status, error_message, duration_ms)`
3. After batch complete: `update_push_batch(batch_id, pins_attempted, pins_success, pins_failed, status, duration_ms, error_message)`

`sync_run_id` is passed down from `_sync_tick()` through `SyncJob` so batches can be linked to their parent sync run.

### New Local API Endpoints

```
GET /api/v2/push-history
    ?page=0&size=25&device_id=3&status=PARTIAL
    → { items: [...], page, size, total }

GET /api/v2/push-history/{batch_id}/pins
    → { batch_id, device_name, pins: [...] }
```

### Access Tauri UI

**New page**: Push History — accessible from main navigation

**Top filters**: device dropdown (populated from cached devices), status dropdown

**Batch table columns**:
| Column | Notes |
|--------|-------|
| `created_at` | formatted datetime |
| `device_name` | |
| `policy` | badge |
| `pins_attempted` | |
| `pins_success` | green |
| `pins_failed` | red |
| `status` | colored badge |
| `duration_ms` | formatted |

**Row click** → opens inline expanded section or dialog showing pin-level table:
| Column | Notes |
|--------|-------|
| `pin` | |
| `full_name` | |
| `operation` | badge (INSERT=blue, UPDATE=orange, DELETE=red) |
| `status` | badge |
| `error_message` | shown if present |
| `duration_ms` | |

---

## Feature 4 — Access: Device Content Viewer

### Purpose
On-demand live inspection of what is actually stored on a ZKTeco device (users, userauthorize, templates, transactions). Read-only. Only reads when explicitly requested.

### New Local API Endpoint

```
POST /api/v2/device-content/read
     Content-Type: application/json
     body: {
       "device_id": 3,
       "tables": ["users", "userauthorize", "templates", "transactions"]
     }

     Success → 200:
     {
       "device_id": 3,
       "device_name": "Entrée principale",
       "read_at": "2026-04-10T14:32:00",
       "tables": {
         "users":        [ { "pin", "name", "card_no", ... } ],
         "userauthorize": [ { "pin", "door_id", "tz_id", ... } ],
         "templates":    [ { "pin", "finger_index", ... } ],
         "transactions": [ { "pin", "time", "verified", ... } ]
       }
     }

     Device unreachable → 503:
     { "error": "Could not connect to device: <message>" }
```

**Implementation** (`local_access_api_v2.py`):
- Looks up device config from cached devices by `device_id`
- Creates a temporary SDK connection (same pattern as `DeviceWorker._execute`)
- Calls the appropriate SDK read methods for each requested table
- Disconnects and returns data
- All within the request — no background thread

### Access Tauri UI

**Location**: existing device detail modal/panel in the Appareils page — add a new `"Contenu"` tab

**Tab layout**:
- Sub-tab bar: `Utilisateurs` | `Autorisations` | `Templates` | `Transactions`
- `"Lire le contenu"` button — triggers the POST
- While loading: centered spinner
- Last read timestamp displayed after first read
- On success: data grid for the selected sub-tab (columns auto-detected from response keys)
- On error: red error message + `"Réessayer"` button
- Data persists in component state until page closes or re-read

---

## Prompt Structure (for Implementation)

The single implementation prompt will be structured as:

```
[CONTEXT SECTION]
  - Project paths
  - Key existing files and patterns to follow
  - Existing db.py helper pattern example
  - Existing local API route registration example
  - Existing dashboard section pattern (GymAccessDoorHistory)

[FEATURE 1] Dashboard — Access Sync Events Page
  - Backend endpoint to add
  - Dashboard files to create
  - Route registration

[FEATURE 2] Access — Sync Run History
  - SQLite schema
  - db.py helpers
  - app.py integration points
  - API endpoints
  - Tauri UI page

[FEATURE 3] Access — Device Push History
  - SQLite schema (2 tables)
  - db.py helpers
  - device_sync.py integration points (SyncJob carries sync_run_id)
  - API endpoints
  - Tauri UI page

[FEATURE 4] Access — Device Content Viewer
  - API endpoint implementation
  - Tauri UI tab addition in Appareils page

[VERIFICATION CHECKLIST]
  - Per-feature checklist the model must confirm before finishing
```

---

## Files Changed Summary

### Spring Boot Backend
| File | Change |
|------|--------|
| `Controllers/GymAccessController.java` | Add `getEvents` paginated endpoint |
| `Repositories/AccessSyncEventRepository.java` | Add paginated query with optional filters |

### MonClub Dashboard
| File | Change |
|------|--------|
| `src/models/AccessSyncEvent.ts` | NEW — DTO interface |
| `src/sections/AccessSyncEvents/view/access-sync-events-view.tsx` | NEW — main page |
| `src/sections/AccessSyncEvents/access-sync-events-table-*.tsx` | NEW — table components |
| `src/pages/GymAccessSyncEvents.tsx` | NEW — page entry |
| `src/routes/` | Add route |
| `src/sections/services/GymService.ts` | Add `getAccessSyncEventsPaged` function |

### MonClub Access — Python
| File | Change |
|------|--------|
| `app/core/db.py` | Add 3 tables + helpers |
| `app/ui/app.py` | Record sync run start/end in `_sync_tick` |
| `app/core/device_sync.py` | Record push batch + per-pin results; pass `sync_run_id` through `SyncJob` |
| `app/api/local_access_api_v2.py` | Add 5 new endpoints |

### MonClub Access — Tauri UI
| File | Change |
|------|--------|
| Sync History page | NEW |
| Push History page | NEW |
| Appareils device detail | Add `"Contenu"` tab |

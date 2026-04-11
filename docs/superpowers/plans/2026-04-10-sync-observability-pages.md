# Sync Observability Pages — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the Access-side observability rollout first: sync run history, push history, and a live device-content viewer inside the existing Tauri device modal.

**Architecture:** Reuse the current Access app seams instead of introducing parallel abstractions. Sync trigger metadata is carried through `MainApp._sync_tick()`, persisted in SQLite, then surfaced through lightweight local API endpoints and Tauri pages. The device content viewer reuses the existing device table route instead of adding a new aggregate backend endpoint.

**Tech Stack:** Python 3.11, SQLite, Tkinter app shell, local `http.server` API, React + TypeScript + shadcn/ui inside Tauri

**Spec:** `docs/superpowers/specs/2026-04-10-sync-observability-pages-design.md`

---

## Scope

This plan intentionally implements **MonClub Access only** in the first pass.

Included:
- SQLite schema + helpers for sync runs and push history
- sync trigger plumbing and run recording
- device push batch + pin recording
- local API endpoints for sync/push history
- Tauri Sync History page
- Tauri Push History page
- device info dialog `Contenu` tab using existing device table endpoints
- retention hooks for the new history tables
- Spring Boot paginated `access_sync_event` endpoint
- Dashboard Access Sync Events page (standalone, following GymAccessDoorHistory pattern)

Deferred:
- none

---

## File Map

### Modify (Access backend + Tauri UI)
- `app/core/db.py`
- `app/ui/app.py`
- `app/core/change_detector.py`
- `app/core/device_worker.py`
- `app/core/device_sync.py`
- `access/local_api_routes.py`
- `app/api/local_access_api_v2.py`
- `tauri-ui/src/App.tsx`
- `tauri-ui/src/layouts/MainLayout.tsx`
- `tauri-ui/src/api/hooks.ts`
- `tauri-ui/src/pages/DevicesPage.tsx`

### Create (Access backend + Tauri UI)
- `tests/test_sync_observability.py`
- `tauri-ui/src/pages/SyncHistoryPage.tsx`
- `tauri-ui/src/pages/PushHistoryPage.tsx`

### Modify (Spring Boot backend — `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\`)
- `Helper/ApiConstants.java`
- `Repositories/AccessSyncEventRepository.java`
- `Controllers/GymAccessController.java`
- `Models/DTO/PageResponse.java` (add `of(Page<T>)` factory if missing)

### Create (Dashboard — `C:\Users\mohaa\Desktop\mon_club_dashboard\src\`)
- `models/AccessSyncEvent.ts`
- `sections/AccessSyncEvents/view/access-sync-events-view.tsx`
- `sections/AccessSyncEvents/view/index.ts`
- `sections/AccessSyncEvents/access-sync-events-table-head.tsx`
- `sections/AccessSyncEvents/access-sync-events-table-row.tsx`
- `sections/AccessSyncEvents/access-sync-events-table-toolbar.tsx`
- `sections/AccessSyncEvents/access-sync-events-table-empty-rows.tsx`
- `sections/AccessSyncEvents/table-no-data.tsx`
- `sections/AccessSyncEvents/utils.ts`
- `pages/GymAccessSyncEvents.tsx`

### Modify (Dashboard)
- `sections/services/GymService.ts`
- `routes/` (add route entry matching existing pattern)

---

## Task 1: Schema + DB Helpers

**Files:**
- Modify: `app/core/db.py`
- Create: `tests/test_sync_observability.py`

- [ ] Write failing tests for:
  - `sync_run_history` schema
  - `push_batch_history` schema
  - `push_pin_history` schema
  - FK cascade from batch to pins
  - sync run insert/update/list/detail helpers
  - push batch insert/update/list/detail helpers

- [ ] Run the focused pytest file and confirm the new tests fail for missing tables/helpers.

- [ ] Implement in `app/core/db.py`:
  - `PRAGMA foreign_keys = ON`
  - `sync_run_history`
  - `push_batch_history`
  - `push_pin_history`
  - `insert_sync_run`
  - `update_sync_run`
  - `list_sync_runs`
  - `get_sync_run`
  - `insert_push_batch`
  - `update_push_batch`
  - `insert_push_pin`
  - `list_push_batches`
  - `get_push_batch_pins`
  - `prune_sync_run_history`
  - `prune_push_batch_history`

- [ ] Re-run the focused pytest file and confirm those tests pass.

---

## Task 2: Sync Trigger Context + Run Recording

**Files:**
- Modify: `app/ui/app.py`
- Modify: `app/core/change_detector.py`
- Modify: `app/api/local_access_api_v2.py`
- Test: `tests/test_sync_observability.py`

- [ ] Write failing tests for the trigger-context rules:
  - first tick resolves to `STARTUP`
  - timer tick resolves to `TIMER`
  - manual sync keeps `SYNC_NOW_API`
  - hard reset sets `run_type=HARD_RESET`
  - change detector uses `CHANGE_DETECTOR`

- [ ] Run those tests and confirm they fail before production changes.

- [ ] Implement trigger metadata plumbing:
  - `request_sync_now(...)` accepts trigger metadata
  - `MainApp` stores pending sync context
  - `_sync_tick()` resolves startup vs timer vs pending trigger
  - `_handle_sync_now()` schedules `SYNC_NOW_API`
  - `_handle_sync_hard_reset()` schedules `HARD_RESET`
  - `ChangeDetectorService` schedules `CHANGE_DETECTOR`

- [ ] Persist sync run rows inside `_sync_tick()`:
  - insert `IN_PROGRESS`
  - store compact response summary
  - finalize status/counters/duration

- [ ] Re-run the focused tests and add one integration-style test proving a sync run row can be recorded with the expected metadata.

---

## Task 3: Device Push History Recording

**Files:**
- Modify: `app/core/device_worker.py`
- Modify: `app/core/device_sync.py`
- Test: `tests/test_sync_observability.py`
- Reuse: `tests/test_batch_device_push.py`

- [ ] Write a failing test that runs `_sync_one_device(..., sync_run_id=...)` against a mocked SDK and asserts:
  - one batch row is created
  - pin rows are created
  - counts/status are updated at the end

- [ ] Run the targeted test and confirm it fails first.

- [ ] Implement:
  - `sync_run_id` on `SyncJob`
  - pass-through in `DeviceWorker._execute()`
  - `_sync_one_device(..., sync_run_id=None)`
  - batch start/finalization
  - per-pin success/failure recording

- [ ] Keep pin history semantics simple in phase 1:
  - one row per attempted pin
  - `operation=UPSERT`
  - `SUCCESS` / `FAILED`

- [ ] Re-run the new targeted push-history test plus existing `tests/test_batch_device_push.py`.

---

## Task 4: Local API Endpoints

**Files:**
- Modify: `access/local_api_routes.py`
- Modify: `app/api/local_access_api_v2.py`
- Test: `tests/test_sync_observability.py`

- [ ] Write failing tests for:
  - `GET /api/v2/sync-history`
  - `GET /api/v2/sync-history/{id}`
  - `GET /api/v2/push-history`
  - `GET /api/v2/push-history/{batchId}/pins`

- [ ] Run the targeted tests and confirm they fail before handler changes.

- [ ] Implement route registration and handler functions.

- [ ] Re-run the targeted tests and confirm the payload shape matches the plan.

---

## Task 5: Tauri Pages

**Files:**
- Create: `tauri-ui/src/pages/SyncHistoryPage.tsx`
- Create: `tauri-ui/src/pages/PushHistoryPage.tsx`
- Modify: `tauri-ui/src/App.tsx`
- Modify: `tauri-ui/src/layouts/MainLayout.tsx`

- [ ] Build the two pages with the current house style:
  - filter toolbar
  - refresh action
  - batch table
  - row detail dialog

- [ ] Add routes:
  - `/sync-history`
  - `/push-history`

- [ ] Add nav items to `MainLayout.tsx`.

- [ ] Run the Tauri build and fix any TypeScript issues.

---

## Task 6: Device Content Tab

**Files:**
- Modify: `tauri-ui/src/api/hooks.ts`
- Modify: `tauri-ui/src/pages/DevicesPage.tsx`

- [ ] Extend `usePullSdk()` with a helper for reading a device table through the existing local API route.

- [ ] Add a `Contenu` tab to the existing device info dialog.

- [ ] Reuse existing endpoints:
  - `/devices/{deviceId}/info`
  - `/devices/{deviceId}/table/{tableName}`

- [ ] Show:
  - per-table loading
  - per-table errors
  - auto-detected columns
  - retained content until dialog close

- [ ] Run the Tauri build and confirm the page compiles.

---

## Task 7: Retention Integration

**Files:**
- Modify: `app/core/device_attendance.py`
- Modify: `app/core/realtime_agent.py`
- Modify: `app/core/db.py`

- [ ] Add prune helpers for the new tables in `db.py`.

- [ ] Wire them into the existing cleanup flows next to `prune_access_history()` and `prune_offline_creation_queue()`.

- [ ] Add a focused test that old batch rows are removed and pin rows cascade-delete with them.

---

## Task 8: Spring Boot — Paginated Access Sync Events Endpoint

**Files (Spring Boot backend):**
- Modify: `Helper/ApiConstants.java`
- Modify: `Repositories/AccessSyncEventRepository.java`
- Modify: `Controllers/GymAccessController.java`
- Modify: `Models/DTO/PageResponse.java` (if needed)

- [ ] **Step 1: Add API constant** in `ApiConstants.java` near `getGymAccessChanges`:

```java
public static final String getGymAccessEvents = "/manager/gym/access/v1/events";
```

- [ ] **Step 2: Add paginated query** to `AccessSyncEventRepository`:

```java
@Query("""
    SELECT e FROM AccessSyncEvent e
    WHERE e.gymId = :gymId
      AND (:entityType IS NULL OR e.entityType = :entityType)
      AND (:operation  IS NULL OR e.operation  = :operation)
      AND (:priority   IS NULL OR e.priority   = :priority)
    ORDER BY e.id DESC
    """)
Page<AccessSyncEvent> findByGymIdFiltered(
    @Param("gymId")      Long gymId,
    @Param("entityType") String entityType,
    @Param("operation")  String operation,
    @Param("priority")   String priority,
    Pageable pageable
);
```

- [ ] **Step 3: Verify `PageResponse.of(Page<T>)` factory exists** in `Models/DTO/PageResponse.java`. If missing, add:

```java
public static <T> PageResponse<T> of(Page<T> page) {
    PageResponse<T> r = new PageResponse<>();
    r.setItems(page.getContent());
    r.setPage(page.getNumber());
    r.setSize(page.getSize());
    r.setTotal(page.getTotalElements());
    r.setTotalPages(page.getTotalPages());
    r.setHasNext(page.hasNext());
    return r;
}
```

- [ ] **Step 4: Add endpoint** to `GymAccessController` after `getGymAccessChanges`:

```java
@GetMapping(ApiConstants.getGymAccessEvents)
@Transactional(readOnly = true)
public ResponseEntity<PageResponse<AccessSyncEvent>> getGymAccessEvents(
    @RequestParam(defaultValue = "0")  int page,
    @RequestParam(defaultValue = "25") int size,
    @RequestParam(required = false)    String entityType,
    @RequestParam(required = false)    String operation,
    @RequestParam(required = false)    String priority,
    HttpServletRequest httpRequest
) {
    MainAccountModel sender = Utils.resolveAccount(httpRequest, jwtService, mainAccountRepository);
    if (sender.getGym() == null) {
        throw new DontHavePermissionException("Only gym accounts can access sync events.");
    }
    Long gymId = sender.getGym().getId();
    Pageable pageable = PageRequest.of(page, Math.min(size, 100), Sort.by("id").descending());
    Page<AccessSyncEvent> result = accessSyncEventRepository.findByGymIdFiltered(
        gymId, entityType, operation, priority, pageable
    );
    return ResponseEntity.ok(PageResponse.of(result));
}
```

`accessSyncEventRepository` must already be injected (it's used by `getGymAccessChanges`). If not, add it to the `@RequiredArgsConstructor` field list.

- [ ] **Step 5: Build** — `cd D:/projects/MonClub/monclub_backend && mvn compile -q` — expected: BUILD SUCCESS.

- [ ] **Step 6: Commit** — `feat: add paginated access sync events endpoint for dashboard`

---

## Task 9: Dashboard — Access Sync Events Section

**Files (all under `C:\Users\mohaa\Desktop\mon_club_dashboard\src\`):**

**Pattern to follow exactly:** `src/sections/GymAccessDoorHistory/` — read every file in that folder as your template. Component names, imports, MUI patterns, and service call style must match.

- [ ] **Step 1: Create `models/AccessSyncEvent.ts`**

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

export interface AccessSyncEventFilters {
  entityType?: 'ACTIVE_MEMBERSHIP' | 'GYM_DEVICE';
  operation?: 'CREATE' | 'UPDATE' | 'DELETE';
  priority?: 'HIGH' | 'NORMAL' | 'LOW';
}
```

- [ ] **Step 2: Add `getAccessSyncEventsPaged` to `sections/services/GymService.ts`**

> **IMPORTANT:** Open `GymService.ts` and read an existing paginated function (e.g. `getGymAccessDoorHistory`). Match its base URL, fetch vs axios, auth header, and `PageResult<T>` type exactly. Replace the URL below with whatever the existing pattern uses.

```typescript
import { AccessSyncEvent, AccessSyncEventFilters } from 'src/models/AccessSyncEvent';

export async function getAccessSyncEventsPaged(
  gymId: number,
  page: number,
  size: number,
  filters: AccessSyncEventFilters,
  token: string
): Promise<PageResult<AccessSyncEvent>> {
  const params = new URLSearchParams({ page: String(page), size: String(size) });
  if (filters.entityType) params.set('entityType', filters.entityType);
  if (filters.operation)  params.set('operation',  filters.operation);
  if (filters.priority)   params.set('priority',   filters.priority);
  // Use SAME base URL / http client as existing paginated functions in this file:
  const res = await fetch(`<BASE_URL>/manager/gym/access/v1/events?${params}`,
    { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}
```

- [ ] **Step 3: Create section files** — use `GymAccessDoorHistory` files as templates, substituting `AccessSyncEvent` data:

  - `sections/AccessSyncEvents/utils.ts` — copy utils from door-history, no changes needed
  - `sections/AccessSyncEvents/table-no-data.tsx` — copy + rename component
  - `sections/AccessSyncEvents/access-sync-events-table-empty-rows.tsx` — copy + rename
  - `sections/AccessSyncEvents/access-sync-events-table-head.tsx` — columns: ID, Type entité, Entité ID, Opération, Priorité, Membership, Date
  - `sections/AccessSyncEvents/access-sync-events-table-row.tsx` — render each `AccessSyncEvent` row; clicking opens a detail dialog showing all fields; use MUI `Chip` for `operation` (success/warning/error) and `priority` (error/warning/default)
  - `sections/AccessSyncEvents/access-sync-events-table-toolbar.tsx` — filter dropdowns for `entityType`, `operation`, `priority`
  - `sections/AccessSyncEvents/view/access-sync-events-view.tsx` — main view component calling `getAccessSyncEventsPaged`, pagination, filter state
  - `sections/AccessSyncEvents/view/index.ts` — re-export the view

- [ ] **Step 4: Create `pages/GymAccessSyncEvents.tsx`** — follow same pattern as other gym pages (lazy-load the view, wrap in auth guard if used).

- [ ] **Step 5: Register the route** — find the existing routes file (check `src/routes/`) and add the new page following the same pattern as `GymAccessDoorHistory`.

- [ ] **Step 6: Build** — `npm run build` in the dashboard project root — expected: no TypeScript errors.

- [ ] **Step 7: Commit** — `feat: add Access Sync Events dashboard page`

---

## Verification

- [ ] `python -m pytest tests/test_sync_observability.py -v`
- [ ] `python -m pytest tests/test_batch_device_push.py -v`
- [ ] `python -m pytest tests/test_sync_scope.py -v`
- [ ] `npm run build` in `C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui`

Manual spot-checks after build:
- [ ] Trigger `POST /api/v2/sync/now` and verify a sync history row appears with `trigger_source=SYNC_NOW_API`
- [ ] Trigger hard reset and verify `run_type=HARD_RESET`
- [ ] Run a device sync and verify push batch + pin rows appear
- [ ] Open the Tauri device modal and verify the `Contenu` tab can read `users` / `userauthorize` live
- [ ] Call `GET /manager/gym/access/v1/events?page=0&size=5` from Postman and verify paginated JSON response
- [ ] Open the Dashboard, navigate to the new Access Sync Events page, and verify the table loads with filter controls

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

Deferred:
- Spring Boot paginated sync events endpoint
- dashboard Access Sync Events page

---

## File Map

### Modify
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

### Create
- `tests/test_sync_observability.py`
- `tauri-ui/src/pages/SyncHistoryPage.tsx`
- `tauri-ui/src/pages/PushHistoryPage.tsx`

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

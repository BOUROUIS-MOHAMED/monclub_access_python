# Dashboard Feedback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add celebratory sound and animation feedback for successful device pushes and successful sync completion, including tray-mode playback and operator-visible settings.

**Architecture:** The Python app emits precise feedback events through a dedicated SSE stream, stores optional custom audio in the Access data folder, and persists operator preferences in Access config. The React shell listens globally for feedback events, plays the correct sound even while hidden to tray, and exposes a compact dashboard beacon plus a normal settings card.

**Tech Stack:** Python 3.11, local `http.server` API, SQLite-backed Access runtime, React 19, TypeScript, Tauri, `lottie-react`

**Spec:** `docs/superpowers/specs/2026-04-12-dashboard-feedback-design.md`

---

## File Map

### Modify
- `app/core/config.py`
- `shared/config.py`
- `access/local_api_routes.py`
- `app/api/local_access_api_v2.py`
- `app/core/device_sync.py`
- `app/ui/app.py`
- `tests/test_status_stream.py`
- `tests/test_sync_observability.py`
- `tauri-ui/src/App.tsx`
- `tauri-ui/src/api/client.ts`
- `tauri-ui/src/api/types.ts`
- `tauri-ui/src/pages/DashboardPage.tsx`
- `tauri-ui/src/pages/ConfigPage.tsx`

### Create
- `tests/test_feedback_api.py`
- `tauri-ui/src/components/AccessFeedbackProvider.tsx`
- `tauri-ui/src/components/DashboardSuccessBeacon.tsx`
- `tauri-ui/src/lib/feedback.ts`

### Copy default assets
- `tauri-ui/public/sounds/device-push-success.mp3`
- `tauri-ui/public/sounds/sync-complete-success.mp3`
- `tauri-ui/public/animations/device-push-celebration.json`
- `tauri-ui/public/animations/sync-complete-confetti.json`

---

## Task 1: Persist Feedback Config

**Files:**
- Modify: `app/core/config.py`
- Modify: `shared/config.py`
- Test: `tests/test_feedback_api.py`

- [ ] Write failing tests that serialize Access config and assert the new feedback fields are present with normalized defaults.
- [ ] Run `pytest tests/test_feedback_api.py -k config -v` and confirm the new test fails.
- [ ] Add the feedback fields to `AppConfig`, normalize them in `from_dict()`, and include them in split Access config serialization.
- [ ] Re-run `pytest tests/test_feedback_api.py -k config -v` and confirm it passes.

## Task 2: Add Feedback SSE And Sound Routes

**Files:**
- Modify: `access/local_api_routes.py`
- Modify: `app/api/local_access_api_v2.py`
- Modify: `app/ui/app.py`
- Test: `tests/test_feedback_api.py`

- [ ] Write failing tests for:
  - route registration
  - `GET /api/v2/feedback/events`
  - custom sound upload
  - custom sound reset
  - custom sound download
- [ ] Run `pytest tests/test_feedback_api.py -v` and confirm the new tests fail first.
- [ ] Implement:
  - in-memory feedback event buffer on `MainApp`
  - SSE handler for `/feedback/events`
  - bytes response helper for audio streaming
  - JSON base64 upload handlers
  - reset handlers
  - Access feedback storage folder helpers
- [ ] Re-run `pytest tests/test_feedback_api.py -v` and confirm the route and storage tests pass.

## Task 3: Emit Exact Success Events

**Files:**
- Modify: `app/core/device_sync.py`
- Modify: `app/ui/app.py`
- Modify: `tests/test_sync_observability.py`
- Modify: `tests/test_status_stream.py`

- [ ] Write failing tests that prove:
  - a successful device push batch emits `device_push_success`
  - a successful sync run emits `sync_completed_success`
- [ ] Run the focused tests and confirm they fail before implementation.
- [ ] Add an optional feedback callback to `DeviceSyncEngine` and emit device-push success after batch finalization.
- [ ] Emit sync-complete success from `MainApp._sync_tick()` only when the sync run finishes with `SUCCESS`.
- [ ] Re-run the focused backend tests and confirm they pass.

## Task 4: Build The React Feedback Runtime

**Files:**
- Create: `tauri-ui/src/components/AccessFeedbackProvider.tsx`
- Create: `tauri-ui/src/lib/feedback.ts`
- Modify: `tauri-ui/src/api/client.ts`
- Modify: `tauri-ui/src/api/types.ts`
- Modify: `tauri-ui/src/App.tsx`

- [ ] Add the new feedback event types and config fields to TypeScript types.
- [ ] Extend `openSSE()` to subscribe to feedback event names.
- [ ] Build a global provider that:
  - loads feedback config
  - listens to `/feedback/events`
  - decides per-device vs per-run behavior
  - plays bundled or custom audio
  - exposes the latest dashboard beacon event
- [ ] Run `npm run build` in `tauri-ui` and fix TypeScript issues.

## Task 5: Dashboard Beacon And Settings UI

**Files:**
- Create: `tauri-ui/src/components/DashboardSuccessBeacon.tsx`
- Modify: `tauri-ui/src/pages/DashboardPage.tsx`
- Modify: `tauri-ui/src/pages/ConfigPage.tsx`

- [ ] Add the dashboard beacon to the right of `Hard Reset`.
- [ ] Add the always-visible `Feedback` settings card with per-event toggles, repeat-mode select, source select, choose file, replace, and reset actions.
- [ ] Make the feedback controls patch config immediately instead of relying on the advanced settings save button.
- [ ] Run `npm run build` in `tauri-ui` and confirm the UI compiles.

## Task 6: Default Assets And End-To-End Verification

**Files:**
- Copy: `tauri-ui/public/sounds/*`
- Copy: `tauri-ui/public/animations/*`

- [ ] Copy temporary default assets into the new bundled filenames so the feature works immediately.
- [ ] Run `pytest tests/test_feedback_api.py tests/test_status_stream.py tests/test_sync_observability.py -v`.
- [ ] Run `npm run build` in `tauri-ui`.
- [ ] Manually verify:
  - success sound plays while the app is hidden to tray
  - dashboard beacon appears next to `Hard Reset`
  - each sound and animation can be disabled independently
  - custom sound upload and reset work

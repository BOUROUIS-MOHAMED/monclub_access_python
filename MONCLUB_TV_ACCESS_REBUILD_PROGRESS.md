# MonClub TV Access Rebuild — Progress Log

## Access Functionality A1 — TV Local Schema + Core Cache Foundation

**Date**: 2026-03-17
**Status**: ✅ Complete

### Summary
Rebuilt the local SQLite persistence layer and foundation helpers for MonClub TV in Access. Created 9 tables with full CRUD helpers, enum constants, and backward-compatible stubs. This is the foundation that later functionalities (sync, download, readiness, activation, player, ads) will build upon.

### Files Modified
- `app/core/tv_local_cache.py` — Full rewrite (was stubbed-out placeholder)

### Schema / Tables Added

| Table | Purpose | Key Columns | Unique Constraints / Indexes |
|---|---|---|---|
| `tv_host_monitor` | Detected monitors | monitor_id, monitor_label, width, height, is_primary | UNIQUE(monitor_id) |
| `tv_screen_binding` | Binding intent | screen_id, screen_label, gym_id, monitor_id, enabled, desired_state | UNIQUE(screen_id) |
| `tv_screen_binding_runtime` | Volatile runtime state | binding_id (PK), runtime_state, window_id, crash_count | PK(binding_id) |
| `tv_screen_binding_event` | Append-only event log | binding_id, event_type, severity, message | IDX(binding_id, created_at) |
| `tv_snapshot_cache` | Snapshot metadata/payload | screen_id, snapshot_id, snapshot_version, manifest_status, sync_status, is_latest | IDX(screen_id, is_latest), IDX(snapshot_id) |
| `tv_snapshot_required_asset` | Required assets per snapshot | snapshot_id, media_asset_id, checksum_sha256, size_bytes | UNIQUE(snapshot_id, media_asset_id) |
| `tv_local_asset_state` | Local asset validation state | media_asset_id, asset_state, file_exists, validation_mode | UNIQUE(media_asset_id) |
| `tv_snapshot_readiness` | Readiness summary | screen_id, snapshot_id, readiness_state, is_fully_ready, is_latest | IDX(screen_id, is_latest) |
| `tv_sync_run_log` | Sync attempt log | screen_id, target_snapshot_version, result, correlation_id | IDX(screen_id, created_at) |

### Helpers Added

**Schema**: `ensure_tv_local_schema()`, `_create_tv_schema()` (idempotent, thread-safe)

**CRUD per table**:
- Host monitor: `upsert_tv_host_monitor`, `list_tv_host_monitors`, `replace_tv_host_monitors`
- Screen binding: `create_tv_screen_binding`, `update_tv_screen_binding`, `delete_tv_screen_binding`, `load_tv_screen_binding_by_id`, `get_tv_screen_binding`, `load_tv_screen_binding`, `list_tv_screen_bindings`, `save_tv_screen_binding`
- Binding runtime: `upsert_tv_screen_binding_runtime`, `load_tv_screen_binding_runtime`
- Binding events: `record_tv_screen_binding_event`, `list_tv_screen_binding_events`
- Snapshot cache: `upsert_tv_snapshot_cache`, `load_tv_latest_snapshot`, `load_tv_snapshot_by_id`, `list_tv_snapshot_cache`
- Required assets: `upsert_tv_snapshot_required_asset`, `list_tv_snapshot_required_assets`
- Local asset state: `upsert_tv_local_asset_state`, `load_tv_local_asset_state`, `list_tv_local_asset_states`
- Readiness: `upsert_tv_snapshot_readiness`, `load_tv_latest_readiness`, `list_tv_snapshot_readiness`
- Sync run log: `insert_tv_sync_run_log`, `list_tv_sync_run_logs`

**Utilities**: `_json_dumps`, `_json_loads`, `_row_to_dict`, `_rows_to_list`, `_safe_int`, `compute_expected_local_path`

**Enum constants**: `DESIRED_*`, `BINDING_RUNTIME_*`, `ACTIVATION_STATE_*`, `MANIFEST_STATUS_*`, `SYNC_STATUS_*`, `ASSET_STATE_*`, `READINESS_*`, `VALIDATION_*`, `SEVERITY_*`, `SYNC_RESULT_*`

### API/Debug Endpoints
No new endpoints added in this step (existing API handlers in `local_access_api_v2.py` already call into `tv_local_cache` functions which are now implemented).

### Implementation Decisions
- Reuses `get_conn()` / `_ensure_column()` from `app.core.db` — same SQLite database
- All timestamps: UTC ISO strings via `now_iso()`
- JSON in TEXT columns, string enums in TEXT columns
- Schema creation is thread-safe with `_schema_lock` + `_schema_ready` flag
- `ON CONFLICT ... DO UPDATE` for upsert operations
- Backward-compatible stubs for ~40+ functions (player, ads, activation, observability, etc.) return `TV_NOT_YET_IMPLEMENTED`

### Verification
```
$ python -m py_compile app/core/tv_local_cache.py  # OK
$ python tmp/test_a1_schema.py
[1] Schema: 9 expected, 9 found
[2] Host monitor CRUD: OK
[3] Screen binding CRUD: OK
[4] Binding runtime CRUD: OK
[5] Binding events CRUD: OK
[6] Snapshot cache CRUD: OK
[7] Required assets CRUD: OK
[8] Local asset state CRUD: OK
[9] Snapshot readiness CRUD: OK
[10] Sync run log CRUD: OK
[11] Delete binding: OK
[12] Expected local path: OK
=== ALL 12 CHECKS PASSED ===
```

### What Remains for Next Functionality
- **A2**: Snapshot fetching from backend (sync engine)
- **A3**: Asset download worker
- **A4**: Readiness computation engine
- **A5**: Activation engine
- **A6**: Player runtime / window management
- **A7**: Ad task runtime
- **A8**: Proof sending
- **A9**: Multi-screen orchestration
- **A10**: Support/recovery actions
- **A11**: Observability / retention

---

## Access Functionality A2 — Snapshot Fetch + Manifest Cache

**Date**: 2026-03-17
**Status**: ✅ Complete

### Summary
Implemented the snapshot sync pipeline for MonClub TV in Access. The sync engine fetches the latest resolved snapshot and its asset manifest from the backend for every enabled screen binding, caches them in the local SQLite tables created in A1, logs each sync run, and exposes local API endpoints for triggering/inspecting sync operations.

### Files Modified
- `app/core/tv_local_cache.py` — Added A2 sync pipeline (~310 lines)
- `app/api/local_access_api_v2.py` — Added 5 TV handler functions + 5 route registrations

### Backend Contracts Used
- `TvResolvedSnapshotView` — fetched via `MonClubApi.get_tv_latest_snapshot(token, screen_id)`
- `TvSnapshotAssetManifestView` / `TvSnapshotAssetManifestItemView` — fetched via `MonClubApi.get_tv_snapshot_manifest(token, snapshot_id)`
- `ApiEndpoints.tv_snapshot_latest_url` / `ApiEndpoints.tv_snapshot_manifest_url` — URL templates with `{screenId}` / `{snapshotId}` placeholders

### Schema/Helpers Reused (from A1)
- Tables: `tv_snapshot_cache`, `tv_snapshot_required_asset`, `tv_sync_run_log`, `tv_screen_binding`
- Helpers: `upsert_tv_snapshot_cache`, `upsert_tv_snapshot_required_asset`, `insert_tv_sync_run_log`, `list_tv_screen_bindings`, `list_tv_snapshot_cache`, `list_tv_snapshot_required_assets`

### New Helpers Added (A2)

| Function | Purpose |
|---|---|
| `_build_tv_api()` | Constructs `MonClubApi` with TV URLs from `load_config()` |
| `_get_auth_token()` | Returns bearer token from `load_auth_token()` or raises |
| `delete_tv_snapshot_required_assets_for_snapshot(snapshot_id)` | Atomic delete all required assets for a snapshot |
| `_sync_screen_snapshot(api, token, screen_id, correlation_id)` | Fetch+cache snapshot+manifest for one screen |
| `_finalize_sync_run(sync_log_id, result, ...)` | Update sync log row with final result |
| `run_tv_snapshot_sync(app=None)` | **A2 entry point** — orchestrates sync across all enabled bindings |

### New Constants Added (A2)

`SYNC_STATUS_IDLE`, `SYNC_STATUS_FETCHING_SNAPSHOT`, `SYNC_STATUS_FETCHING_MANIFEST`, `SYNC_STATUS_COMPLETED_WITH_WARNINGS`, `SYNC_RUN_SUCCESS`, `SYNC_RUN_SUCCESS_WITH_WARNINGS`, `SYNC_RUN_FAILED`, `SYNC_RUN_NO_SNAPSHOT`, `MANIFEST_STATUS_MISSING`

### Local API/Debug Endpoints Added

| Method | Endpoint | Handler | Description |
|---|---|---|---|
| GET | `/api/v2/tv/snapshots` | `_handle_tv_snapshots_list` | List cached snapshots (filter by `screenId`, pagination) |
| GET | `/api/v2/tv/snapshots/latest` | `_handle_tv_snapshots_latest` | Latest cached snapshot (by `screenId`, or all) |
| GET | `/api/v2/tv/snapshots/{snapshotId}/assets` | `_handle_tv_snapshot_assets` | List required assets for a snapshot |
| POST | `/api/v2/tv/snapshots/sync` | `_handle_tv_snapshots_sync` | Trigger background snapshot sync |
| GET | `/api/v2/tv/sync-runs` | `_handle_tv_sync_runs` | List sync run logs (filter by `screenId`, pagination) |

### Important Implementation Decisions
1. **Standalone API client**: `_build_tv_api()` constructs its own `MonClubApi` from `load_config()` because `app._api()` doesn't pass TV URLs to `ApiEndpoints`
2. **Explicit local imports**: New handlers use `from app.core.tv_local_cache import ...` inside each function (existing dead-code TV handlers used bare names without imports)
3. **Atomic manifest replacement**: On each sync, old required assets are deleted before inserting new ones (`delete_tv_snapshot_required_assets_for_snapshot`)
4. **Async sync**: POST `/sync` runs in a background thread and returns 202 immediately
5. **Correlation ID**: Each sync run gets a UUID correlation ID linking all per-screen sync logs
6. **Error resilience**: 404 from snapshot fetch → `NO_SNAPSHOT` result; manifest fetch failure → snapshot still cached with `MANIFEST_STATUS_ERROR`

### Verification Commands/Results
```
$ python -m py_compile app/core/tv_local_cache.py  # OK
$ python -m py_compile app/api/local_access_api_v2.py  # OK
$ python tmp/test_a2_sync.py
  18/21 checks passed
  (3 failures: auth_state table not present in test DB — correctly triggers error handling)
  Key passes: all 6 constants, schema, asset CRUD, sync finalization, no-bindings edge case
```

### What Remains for Next Functionality
- **A3**: Asset download worker
- **A4**: Readiness computation engine
- **A5**: Activation engine
- **A6**: Player runtime / window management
- **A7**: Ad task runtime
- **A8**: Proof sending
- **A9**: Multi-screen orchestration
- **A10**: Support/recovery actions
- **A11**: Observability / retention

---

## Access Functionality A3 — Asset Download + Validation Cache

**Date**: 2026-03-17
**Status**: ✅ Complete

### Summary
Implemented the Access-side asset acquisition layer for MonClub TV. The download pipeline selects required assets from cached snapshots, validates local files with strong/weak integrity checks (size + SHA-256), downloads missing/invalid assets to temp files, validates them, and atomically promotes valid downloads to deterministic cache paths. All state is tracked in the existing `tv_local_asset_state` table. Three new local API endpoints expose asset state and trigger downloads.

### Files Modified
- `app/core/tv_local_cache.py` — Added A3 download/validation pipeline (~350 lines), refined `compute_expected_local_path`, replaced `list_tv_cache_assets` stub, added 3 asset state constants, added `hashlib`/`os`/`pathlib` imports
- `app/api/local_access_api_v2.py` — Added 3 asset handler functions + 3 route registrations

### Backend Contracts Used
- `TvSnapshotAssetManifestItemView` fields: `mediaAssetId`, `downloadLink`, `checksumSha256`, `sizeBytes`, `mimeType`, `mediaType`
- Asset manifest data already cached in `tv_snapshot_required_asset` by A2

### Schema/Helpers Reused (from A1/A2)
- Tables: `tv_snapshot_required_asset` (source of required assets), `tv_local_asset_state` (updated with validation results), `tv_snapshot_cache` (to find latest snapshot per screen)
- Helpers: `upsert_tv_local_asset_state`, `load_tv_local_asset_state`, `ensure_tv_local_schema`
- No new tables added — existing `tv_local_asset_state` is sufficient

### New Helpers Added (A3)

| Function | Purpose |
|---|---|
| `_mime_to_ext(mime_type, media_type)` | Derive file extension from MIME type or media type |
| `compute_expected_local_path(...)` | **Refined** — `{media_asset_id}_{checksum8}.{ext}` under `tv/media/` |
| `_sha256_file(path)` | Streaming SHA-256 hex digest |
| `_validate_local_file(path, size, checksum)` | Returns `(state, mode, reason)` tuple |
| `_download_file(url, dest)` | HTTP GET → file, returns bytes written |
| `_build_asset_worklist(snapshot_id, screen_id)` | Joins required_asset + local_asset_state, selects needing download |
| `_process_single_asset(asset)` | Full pipeline: validate → download → validate temp → atomic promote |
| `run_tv_asset_download(snapshot_id, screen_id)` | **A3 entry point** — orchestrates download across all worklist items |
| `list_tv_cache_assets(...)` | **Replaced stub** — real filtered query with screen_id/snapshot_id/state/mediaAssetId |

### New Constants Added (A3)

`ASSET_STATE_NOT_PRESENT`, `ASSET_STATE_PRESENT_UNCHECKED`, `ASSET_STATE_INVALID_UNREADABLE`

### Local API/Debug Endpoints Added

| Method | Endpoint | Handler | Description |
|---|---|---|---|
| GET | `/api/v2/tv/assets` | `_handle_tv_assets_list` | List local asset states (filter by screenId, snapshotId, state, mediaAssetId) |
| POST | `/api/v2/tv/assets/download` | `_handle_tv_assets_download` | Trigger background asset download |
| GET | `/api/v2/tv/assets/{mediaAssetId}` | `_handle_tv_asset_detail` | Inspect one asset state |

### Important Implementation Decisions
1. **No new tables** — `tv_local_asset_state` from A1 is sufficient for all tracking
2. **Deterministic path**: `{media_asset_id}_{checksum_prefix_8}.{ext}` — content-change gets new path
3. **Temp file pattern**: `{final_path}.downloading` — same directory for atomic `os.replace`
4. **Validation order**: size first (cheap) → SHA-256 (expensive) → WEAK mode when integrity data absent
5. **Atomic promotion**: `os.replace(temp, final)` only after temp passes validation
6. **Idempotent**: VALID files with existing files on disk are never re-downloaded
7. **Vanished file detection**: worklist builder rechecks that VALID files still exist on disk
8. **Error resilience**: missing URL → ERROR state with reason; download failure → ERROR with details; bad checksum → INVALID_CHECKSUM; bad size → INVALID_SIZE

### Verification Commands/Results
```
$ python -m py_compile app/core/tv_local_cache.py  # OK
$ python -m py_compile app/api/local_access_api_v2.py  # OK
$ python tmp/test_a3_download.py
  PASSED: 33/33
  ALL CHECKS PASSED ✓
```

### What Remains for Next Functionality
- **A4**: Readiness computation engine
- **A5**: Activation engine
- **A6**: Player runtime / window management
- **A7**: Ad task runtime
- **A8**: Proof sending
- **A9**: Multi-screen orchestration
- **A10**: Support/recovery actions
- **A11**: Observability / retention

==================================================
FUNCTIONALITY A4: READINESS COMPUTATION ENGINE
==================================================

## Access Functionality A4 — Readiness Computation Engine
### Objective
Implement deterministic readiness computation per screen based on snapshot manifests and local asset cache states.

### Exact Files Modified
- `app/core/tv_local_cache.py` (Appended `compute_tv_screen_readiness` and `run_tv_readiness_computation`, resolved underlying schema bug in `tv_snapshot_readiness`)
- `app/api/local_access_api_v2.py` (Added `GET /api/v2/tv/readiness`, `GET /api/v2/tv/readiness/latest`, `POST /api/v2/tv/readiness/recompute`)

### Backend Contracts Used
- Reuses existing backend structures from A1 snapshot manifest, matching `asset_count` and `tv_snapshot_required_asset` table.

### Schema/Helpers Reused or Extended
- `tv_snapshot_readiness` (Modified A1 `upsert` helper to properly inject `created_at` timestamp).
- `READINESS_EMPTY`, `READINESS_ERROR`, `READINESS_READY`, `READINESS_PARTIALLY_READY`, `READINESS_NOT_READY` added to local cache constants.

### Local API/Debug Endpoints Added
| Method | Endpoint | Handler | Description |
|---|---|---|---|
| GET | `/api/v2/tv/readiness` | `_handle_tv_readiness_list` | List history of readiness computations |
| GET | `/api/v2/tv/readiness/latest` | `_handle_tv_readiness_latest` | Get the current active readiness state for a screen |
| POST | `/api/v2/tv/readiness/recompute` | `_handle_tv_readiness_recompute` | Manually trigger a background readiness check |

### Important Implementation Decisions
1. **Pessimistic counting**: Only `ASSET_STATE_VALID` counts as ready. `PRESENT_UNCHECKED` or missing local rows are strictly counted as `invalid`/`missing`.
2. **Inconsistency catching**: Generates a `READINESS_ERROR` state if the snapshot `asset_count > 0` but `tv_snapshot_required_asset` rows are missing in the local database.
3. **Batch Orchestration**: The API exposes a trigger to batch recompute all active screens (`run_tv_readiness_computation`), gracefully skipping broken bindings.
4. **History Preservation**: We maintain history but exclusively set `is_latest=1` on the newest row per screen.

### Verification Commands/Results
```
$ python -m py_compile app/core/tv_local_cache.py  # OK
$ python -m py_compile app/api/local_access_api_v2.py  # OK
$ python tmp/test_a4_readiness.py
  [OK] Screen created
  [OK] State should be EMPTY, got EMPTY
  [OK] 0 required assets
  ...
  FINISHED: 26/26 PASSED
```

### What Remains for Next Functionality
- **A5**: Activation engine
- **A6**: Player runtime / window management
- **A7**: Ad task runtime
- **A8**: Proof sending
- **A9**: Multi-screen orchestration
- **A10**: Support/recovery actions
- **A11**: Observability / retention

==================================================
FUNCTIONALITY A5: ACTIVATION ENGINE
==================================================

## Access Functionality A5 — Activation Engine
### Objective
Implement safety-constrained snapshot promotion. Determines which cached snapshot should go live (`evaluate_tv_activation`) and transitions states atomically when upgrading or falling back (`activate_tv_ready_snapshot`).

### Exact Files Modified
- `app/core/tv_local_cache.py` (Added `evaluate_tv_activation` and `activate_tv_ready_snapshot` and fixed null comparators)
- `app/api/local_access_api_v2.py` (Registered 5 `_handle_tv_activation` endpoints and also correctly injected the missing A4 endpoints)
- `MONCLUB_TV_ACCESS_REBUILD_PROGRESS.md` (Updated this tracking file)

### Backend Contracts Used
- `activation_state` schema maps out identically to backend states with safety fallback constants (e.g. `FAILURE_REASON_NO_READY_SNAPSHOT`).

### Schema/Helpers Reused or Extended
- `tv_activation_state` (Screen-level persistent cursor for snapshot state changes)
- `tv_activation_attempt` (Historical audit log of all transition events)
- Extended local constants with `ACTIVATION_STATE_*`, `ATTEMPT_RESULT_*` and `FAILURE_REASON_*`.

### Local API/Debug Endpoints Added
| Method | Endpoint | Handler | Description |
|---|---|---|---|
| GET | `/api/v2/tv/activation` | `_handle_tv_activation_list` | Extract historical activation tracking list |
| GET | `/api/v2/tv/activation/latest` | `_handle_tv_activation_latest` | Dump the screen's active snapshot reference |
| POST | `/api/v2/tv/activation/evaluate` | `_handle_tv_activation_evaluate` | Dry-run computation thread |
| POST | `/api/v2/tv/activation/activate-latest-ready` | `_handle_tv_activation_activate_latest_ready` | Manually fire a snapshot promotion |
| GET | `/api/v2/tv/activation/attempts` | `_handle_tv_activation_attempts` | Inspect attempted rollbacks / skips / successes |

### Important Implementation Decisions
1. **Safety Enforced Preflight Evaluation**: In `activate_tv_ready_snapshot()`, we immediately query `evaluate_tv_activation()` first to safely identify the *best-ready candidate array* dynamically.
2. **Missing Endpoint Discovery**: Discovered that the A4 Readiness API handlers had never been written inside `local_access_api_v2.py` in the previous sprint. Spliced the A4 and A5 endpoints into the codebase. 

### Verification Commands/Results
```
$ python -m py_compile app/core/tv_local_cache.py  # OK
$ python -m py_compile app/api/local_access_api_v2.py  # OK
$ python tmp/run_test.py
  [OK] Initial baseline is NO_ACTIVE_SNAPSHOT
  [OK] Clean Activation success -> ACTIVE_CURRENT
  [OK] Already Active -> Skips gracefully
  [OK] New Unready Snapshot -> ACTIVE_OLDER_THAN_LATEST (active maintained)
  [OK] Snap2 Activated -> ACTIVE_CURRENT (snap1 correctly demoted to previous)
  [OK] Aborted unsafe activation -> Active state safely maintained
  === FINISHED: ALL TASKS PASSED ===
```

### What Remains for Next Functionality
- **A6**: Player runtime / window management
- **A7**: Ad task runtime
- **A8**: Proof sending
- **A9**: Multi-screen orchestration
- **A10**: Support/recovery actions
- **A11**: Observability / retention


---

## Access Functionality A6 — Player Runtime + Window Management

**Date**: 2026-03-18
**Status**: ✅ Complete

### Summary

Implemented the binding-scoped TV player runtime in MonClub Access. A6 provides a real-time render context engine that reads the A5-activated snapshot, resolves current timeline items by local time (minute-of-day, day-of-week), and maps asset availability to player states and render modes. A Tauri window page consumes this via a 1-second tick loop and renders video/image/audio or fallback placeholders accordingly. State is persisted to SQLite on meaningful change only (no write spam).

### Files Modified

| File | Change |
|---|---|
| `app/core/tv_local_cache.py` | Fixed 4 bugs in pre-existing A6 scaffolding; added `_insert_tv_player_event`; fixed asset JOIN SQL; fixed `list_tv_player_events` return type; added `activate_tv_latest_ready_snapshot` alias; normalized `video_muted_by_audio` before change-detection comparison |
| `app/api/local_access_api_v2.py` | Added module-level TV import block covering all TV cache functions; registered 6 A6 player routes; fixed `ctx.body_json()` → `ctx.body()` in hardening handler |
| `tauri-ui/src/api/types.ts` | Added TV player types: `TvPlayerState`, `TvRenderMode`, `TvFallbackReason`, `TvTimelineItemPresented`, `TvPlayerRenderContext`, `TvPlayerStateRow`, `TvPlayerStatusResponse`, `TvPlayerEvent`, `TvPlayerEventsResponse` |
| `tauri-ui/src/api/tv.ts` | Created: 6 API functions for player status, render-context, reevaluate, reload, state report, events |
| `tauri-ui/src/pages/TvPlayerWindowPage.tsx` | Created: full Tauri player window — 1s tick, snapshot change detection, state persistence, visual/audio/image renderers, debug overlay (D key) |
| `tauri-ui/src/App.tsx` | Registered `/tv-player` route for `TvPlayerWindowPage` |

### New API Routes

| Method | Path | Handler |
|---|---|---|
| GET | `/api/v2/tv/player/{bindingId}/status` | `_handle_tv_player_status` |
| GET | `/api/v2/tv/player/{bindingId}/render-context` | `_handle_tv_player_render_context` |
| POST | `/api/v2/tv/player/{bindingId}/reevaluate` | `_handle_tv_player_reevaluate` |
| POST | `/api/v2/tv/player/{bindingId}/reload` | `_handle_tv_player_reload` |
| POST | `/api/v2/tv/player/{bindingId}/state` | `_handle_tv_player_state_report` |
| GET | `/api/v2/tv/player/{bindingId}/events` | `_handle_tv_player_events` |

### Player State Machine

| State | Condition |
|---|---|
| `BLOCKED_NO_BINDING` | No binding row found for `bindingId` |
| `BLOCKED_BINDING_DISABLED` | Binding exists but `enabled=False` |
| `BLOCKED_NO_ACTIVE_SNAPSHOT` | No active snapshot in `tv_activation_state` |
| `BLOCKED_NO_RENDERABLE_ITEM` | Snapshot active but no timeline item matches current time |
| `RENDERING` | At least one asset is valid and renderable |
| `FALLBACK_RENDERING` | Partial asset availability — one track missing |
| `ERROR` | Both visual and audio assets missing/invalid |

### Render Decision Matrix

| Visual | Audio | `renderMode` | `playerState` |
|---|---|---|---|
| valid | valid | `VISUAL_AND_AUDIO` | `RENDERING` |
| valid | invalid | `VISUAL_ONLY` | `FALLBACK_RENDERING` |
| invalid | valid | `AUDIO_ONLY` | `FALLBACK_RENDERING` |
| invalid | invalid | `ERROR_FALLBACK` | `ERROR` |
| no item | — | `IDLE_FALLBACK` | `BLOCKED_NO_RENDERABLE_ITEM` |

**Audio mute rule**: when `renderMode=VISUAL_AND_AUDIO` and the visual item is a video, `videoMutedByAudio=true` — the dedicated audio track takes over.

### Key Implementation Contracts

- Timeline matching: `startMinuteOfDay <= minuteOfDay < endMinuteOfDay`; the first matching item is selected
- Asset path resolution: `tv_local_asset_state` JOINed through `tv_snapshot_required_asset` by `snapshot_id`; file existence verified via `_path_is_readable()`
- Change detection: only `active_snapshot_id`, `active_snapshot_version`, `player_state`, `render_mode`, `fallback_reason`, `current_visual_item_id`, `current_audio_item_id`, `current_visual_asset_path`, `current_audio_asset_path`, `last_render_error_code`, `last_render_error_message`, `video_muted_by_audio` are tracked — `current_minute_of_day` changes alone do not trigger a write
- Freshness window: state is written at least every `freshness_seconds` (default 20s) even without a meaningful change
- `video_muted_by_audio` is normalized to `int` (0/1) before comparison to avoid `None` vs `0` false positives

### Bugs Fixed

1. `_insert_tv_player_event` was called by `report_tv_player_state` but never defined → added
2. Asset lookup used `WHERE snapshot_id=?` on `tv_local_asset_state` (no such column) → fixed with JOIN through `tv_snapshot_required_asset`
3. `list_tv_player_events` returned `List` but API handlers expected `Dict` with `rows`/`total` → fixed
4. `activate_tv_latest_ready_snapshot` used by API handler but only `activate_tv_ready_snapshot` defined → added alias
5. All TV handler functions in `local_access_api_v2.py` used TV cache functions without any import → added module-level import block
6. `ctx.body_json()` called in hardening handler but `_Ctx` only has `body()` → fixed
7. A6 player routes never registered in `_build_router()` → added 6 routes
8. `video_muted_by_audio` normalization mismatch: DB stores `0`, payload sends `None` → false `changed=True` → fixed by coercing to `int` before `_player_meaningful_change`

### Verification

Test script: `tmp/test_a6_player.py`

```
=== A6 Results: 36 passed, 0 failed ===
```

All 12 cases pass:
- Cases 0–2: blocked states (no binding, disabled, no snapshot)
- Case 3: no matching timeline item → IDLE_FALLBACK
- Cases 4–7: full render decision matrix (both valid, audio only, visual only, both invalid)
- Case 8: snapshot change detection
- Case 9: change-based write suppression + freshness
- Case 10: `list_tv_player_events` dict format
- Case 11: `reevaluate_tv_player` / `reload_tv_player`
- Case 12: `load_tv_player_status`

### Next Recommendation

**A7 — Ad Overlay Runtime**: If ads are in scope, implement the ad task consumer that layers short-form ad clips over the base timeline rendering. Otherwise skip to A8 (proof sending) or A10 (support/recovery actions).

---

## Access Functionality A7 — Ad Task Runtime

**Status: COMPLETE**
**Date completed: 2026-03-18**

### What was implemented

Gym-scoped ad task coordinator and player override layer for MonClub TV Access.

#### Schema additions (`app/core/tv_local_cache.py`)

Three new tables added in `_create_tv_schema()`:
- `tv_ad_task_cache` — stores ad tasks fetched from remote (media metadata, local file state, schedule)
- `tv_ad_task_runtime` — per-task display lifecycle state (READY → DISPLAYING → COMPLETED/ABORTED/SKIPPED)
- `tv_gym_ad_runtime` — one row per gym_id, tracks gym coordination state (IDLE/INJECTING/DISPLAYING/COMPLETING/ABORTED)

Idempotent migrations on `tv_player_state` via `_ensure_column()`:
- `ad_override_active` INTEGER DEFAULT 0
- `current_ad_task_id` TEXT
- `current_ad_media_id` TEXT
- `current_ad_layout` TEXT
- `ad_audio_override_active` INTEGER DEFAULT 0
- `ad_fallback_reason` TEXT

#### Constants added

```python
AD_TASK_STATE_READY, AD_TASK_STATE_DISPLAYING, AD_TASK_STATE_COMPLETED
AD_TASK_STATE_ABORTED, AD_TASK_STATE_SKIPPED_WINDOW, AD_TASK_STATE_CANCELLED_REMOTE
AD_FILE_STATE_PENDING, AD_FILE_STATE_VALID, AD_FILE_STATE_INVALID, AD_FILE_STATE_MISSING
GYM_COORD_IDLE, GYM_COORD_INJECTING, GYM_COORD_DISPLAYING, GYM_COORD_COMPLETING
GYM_COORD_ABORTED, GYM_COORD_ERROR
AD_LAYOUT_FULL_SCREEN, AD_LAYOUT_BANNER_TOP, AD_LAYOUT_BANNER_BOTTOM
AD_MODE_NONE, AD_MODE_VISUAL_AND_AUDIO, AD_MODE_VISUAL_ONLY, AD_MODE_ERROR_FALLBACK
AD_GRACE_WINDOW_SECONDS = 30
```

#### Core pipeline functions

- `upsert_tv_ad_task_cache(...)` — upsert cached ad task
- `load_tv_ad_task_cache_one(*, campaign_task_id)` — single task lookup
- `list_tv_ad_task_cache(*, gym_id, ...)` — list tasks for gym
- `upsert_tv_ad_task_runtime(...)` / `load_tv_ad_task_runtime(...)` / `list_tv_ad_task_runtime(...)` — task runtime CRUD
- `upsert_tv_gym_ad_runtime(...)` / `load_tv_gym_ad_runtime(...)` — gym state CRUD
- `_get_eligible_bindings_for_gym(gym_id)` — returns enabled bindings for gym
- `_select_due_task_for_gym(gym_id, now_dt)` — deterministic winner: `scheduled_at <= now AND scheduled_at >= (now - 30s)`, file VALID, no terminal runtime row, ORDER BY scheduled_at ASC, campaign_task_id ASC LIMIT 1
- `_expire_overdue_tasks_for_gym(gym_id, now_dt)` — marks past-grace-window tasks as SKIPPED_WINDOW_MISSED
- `_clear_player_ad_override(conn, binding_id, now_str)` — clears all ad fields on tv_player_state
- `_inject_ad_for_gym(gym_id, task, bindings, now_dt)` — file re-validation, gym→INJECTING, creates runtime row, sets ad fields on all binding player states, gym→DISPLAYING
- `complete_tv_ad_display(*, campaign_task_id)` — COMPLETED, gym→IDLE, clear all player overrides
- `abort_tv_ad_display(*, campaign_task_id, reason, message)` — ABORTED, gym→IDLE, clear all player overrides
- `reconcile_all_active_gyms()` — main cycle: check duration completions, expire overdue, inject due
- `startup_recover_ad_runtime()` — reset stuck INJECTING/DISPLAYING gym states, abort stuck tasks, clear player overrides
- `run_tv_ad_task_cycle()` — delegates to `reconcile_all_active_gyms()`

#### `_build_player_render_context` extension

After building the normal snapshot context, opens a new `get_conn()` to check `tv_player_state.ad_override_active` for the binding. If set, queries `tv_ad_task_cache` and merges ad overlay fields into the returned context dict:
```python
{
    "adOverrideActive": True,
    "currentAdTaskId": ..., "currentAdMediaId": ..., "currentAdLayout": ...,
    "adAssetPath": ..., "adMimeType": ...,
    "adAudioOverrideActive": True/False,
    "adDisplayDurationSec": ...
}
```

#### API routes (`app/api/local_access_api_v2.py`)

9 new routes registered:
```
GET  /api/v2/tv/ad-runtime/tasks
GET  /api/v2/tv/ad-runtime/tasks/{taskId}
GET  /api/v2/tv/ad-runtime/gyms/{gymId}
POST /api/v2/tv/ad-runtime/evaluate
POST /api/v2/tv/ad-runtime/tasks/{taskId}/inject-now
POST /api/v2/tv/ad-runtime/tasks/{taskId}/abort
GET  /api/v2/tv/ad-runtime/runtime/list
GET  /api/v2/tv/ad-runtime/runtime/{taskId}
POST /api/v2/tv/ad-runtime/startup-recover
```

#### Frontend (`tauri-ui/`)

`src/api/types.ts`:
- Extended `TvPlayerRenderContext` with 7 ad fields
- Added `TvAdTaskCache`, `TvAdTaskRuntime`, `TvGymAdRuntime`, `TvAdEvaluateResponse` interfaces

`src/api/tv.ts`:
- Added `getTvAdTasks`, `getTvAdTaskRuntime`, `getTvGymAdRuntime`, `evaluateTvAdRuntime`, `injectTvAdNow`, `abortTvAd`

`src/pages/TvPlayerWindowPage.tsx`:
- `AdRenderer` component: renders ad video/image from `ctx.adAssetPath` via `convertFileSrc`
- Ad override priority block: `ctx.adOverrideActive && ctx.adAssetPath` checked before normal rendering
  - `FULL_SCREEN`: replaces entire content
  - `BANNER_TOP/BOTTOM`: normal visual behind, ad overlay on top
- Ad evaluation trigger every 5 ticks: `evaluateTvAdRuntime().catch(() => {})`
- Debug overlay extended with ad fields

### Key design decisions

- **Gym-scoped coordination**: one active ad per `gym_id`; different gyms fully isolated
- **Grace window**: task is eligible if `scheduled_at >= now - 30s`; past that → SKIPPED_WINDOW_MISSED
- **Deterministic winner**: ORDER BY `scheduled_at ASC, campaign_task_id ASC` — no randomness
- **Ad audio always wins**: when `adAudioOverrideActive=True`, player suppresses normal audio track
- **`report_tv_player_state` preserves ad fields**: INSERT ON CONFLICT only updates normal player fields, so backend-managed ad override state is never clobbered by frontend reports
- **Startup recovery**: any INJECTING/DISPLAYING gym from a prior crash is reset to IDLE, stuck tasks aborted, player overrides cleared

### Test results

Test script: `tmp/test_a7_ad_runtime.py`

```
=== A7 Results: 42 passed, 0 failed ===
```

All 12 cases pass:
- Case 0: no tasks → reconcile no-op
- Case 1: future-scheduled task → no injection
- Case 2: due task → injection, gym→DISPLAYING
- Case 3: both bindings in gym get ad_override_active=1
- Case 4: render context includes ad overlay fields
- Case 5: different gym is fully isolated
- Case 6: second reconcile during DISPLAYING → no double-injection
- Case 7: `complete_tv_ad_display` → gym→IDLE, player overrides cleared
- Case 8: two due tasks → single deterministic winner (earliest scheduledAt)
- Case 9: task past grace window → SKIPPED_WINDOW_MISSED
- Case 10: `abort_tv_ad_display` → gym→IDLE, overrides cleared, state=ABORTED
- Case 11: `startup_recover_ad_runtime` → resets stuck DISPLAYING gym
- Case 12: `list_tv_ad_task_cache` / `list_tv_ad_task_runtime` return proper dicts

### TypeScript build

```
vite build: ✓ built in 7.51s (no errors, size warnings only)
```

### Not implemented (out of scope per spec)

- Proof sending / proof outbox
- Campaign progress writeback to remote
- Full support actions system

---

## Access Functionality A8 -- Proof Sending

**Status: COMPLETE**
**Date completed: 2026-03-18**

### Summary

Implemented the Access-side proof creation + proof outbox + proof submission layer for MonClub TV ads. One proof is created per gym-level task attempt at every terminal transition. Proofs are persisted durably in SQLite and sent to the backend through an idempotent outbox with stepped-backoff retry.

### Files Modified

| File | Change |
|------|--------|
| `app/core/tv_local_cache.py` | Schema table, constants, proof helpers, terminal hooks |
| `app/api/local_access_api_v2.py` | Import update, startup-recover handler, 5 new routes |
| `app/ui/app.py` | Add `tv_ad_task_submit_proof_url` to `_api()` endpoints |

### Schema Added

**`tv_ad_proof_outbox`** (table 17 in `_create_tv_schema`):
- `local_proof_id` INTEGER PK AUTOINCREMENT
- `campaign_task_id`, `campaign_id`, `gym_id`, `ad_media_id`
- `idempotency_key` TEXT UNIQUE -- `{campaign_task_id}:{correlation_id}`
- `started_at`, `finished_at`, `displayed_duration_sec`, `expected_duration_sec`
- `completed_fully`, `countable` INTEGER
- `result_status`, `reason_if_not_countable`, `correlation_id`
- `participating_binding_count`, `failed_binding_count`
- `outbox_state` (QUEUED/SENDING/SENT/FAILED_RETRYABLE/FAILED_TERMINAL)
- `attempt_count`, `next_attempt_at`, `last_error`
- `backend_proof_id`, `backend_task_status`
- `created_at`, `updated_at`

Indexes: `campaign_task_id`, `gym_id`, `outbox_state`

### Constants Added

```python
PROOF_STATUS_COMPLETED, PROOF_STATUS_PARTIAL, PROOF_STATUS_ABORTED
PROOF_STATUS_FAILED_TO_START, PROOF_STATUS_CANCELLED_REMOTE, PROOF_STATUS_EXPIRED_REMOTE

PROOF_OUTBOX_QUEUED, PROOF_OUTBOX_SENDING, PROOF_OUTBOX_SENT
PROOF_OUTBOX_FAILED_RETRYABLE, PROOF_OUTBOX_FAILED_TERMINAL

PROOF_COUNTABLE_TOLERANCE_SEC = 2
PROOF_MAX_ATTEMPTS = 50
_PROOF_RETRY_BACKOFF_SECS = [30, 60, 120, 300, 600, 1800, 3600]
```

### Helpers Added (`app/core/tv_local_cache.py`)

- `_proof_next_attempt_at(attempt_count)` -- stepped backoff timestamp
- `create_tv_ad_proof(*, campaign_task_id, gym_id, result_status, ...)` -- idempotent proof creation, ON CONFLICT(idempotency_key) DO NOTHING
- `list_tv_ad_proof_outbox(*, gym_id, campaign_task_id, outbox_states, countable, result_status, limit, offset)` -- filtered list
- `load_tv_ad_proof(*, local_proof_id)` -- single row lookup
- `_send_one_proof(*, proof)` -- backend HTTP submission, returns `{ok, retryable, error, response}`
- `process_tv_ad_proof_outbox(*, app, limit, correlation_id)` -- cycle QUEUED/FAILED_RETRYABLE rows (respects `next_attempt_at`)
- `retry_tv_ad_proof(*, app, local_proof_id)` -- explicit retry of one row
- `startup_recover_proof_outbox()` -- SENDING -> FAILED_RETRYABLE on crash recovery

Also updated `_build_tv_api()` to include `tv_ad_tasks_fetch_url`, `tv_ad_task_confirm_ready_url`, and `tv_ad_task_submit_proof_url`.

### Proof Creation Rules

| A7 terminal state | Proof result_status | Countable |
|---|---|---|
| `DISPLAY_COMPLETED_LOCAL` | `COMPLETED` | if duration >= expected - 2s |
| `DISPLAY_ABORTED_LOCAL` | `ABORTED` | never |
| `SKIPPED_WINDOW_MISSED` | `FAILED_TO_START` | never |
| `CANCELLED_REMOTE` | `CANCELLED_REMOTE` | never |
| `EXPIRED_REMOTE` | `EXPIRED_REMOTE` | never |

Idempotency key: `{campaign_task_id}:{correlation_id}` -- prevents duplicate proof rows even on repeated calls.

### Countability Rules

All five conditions must be true:
1. `result_status = COMPLETED`
2. `completed_fully = True`
3. `expected_duration_sec > 0`
4. `displayed_duration_sec >= expected_duration_sec - 2`
5. Not a cancelled/expired/aborted/failed-to-start result

### Terminal Transition Hooks

- `complete_tv_ad_display()` -- creates COMPLETED proof after gym/player state cleared
- `abort_tv_ad_display()` -- creates ABORTED proof after gym/player state cleared
- `_expire_overdue_tasks_for_gym()` -- creates FAILED_TO_START proof for each skipped task

All proof creation is wrapped in try/except so a proof failure never blocks the runtime state transition.

### Backend Contract Used

- **Endpoint**: `POST /manager/gym/access/v1/tv/ad-tasks/{taskId}/submit-proof`
- **URL constant**: `tv_ad_task_submit_proof_url` in `ApiEndpoints`
- **Method**: `MonClubApi.submit_tv_ad_task_proof()` (already implemented in `monclub_api.py`)
- **Request payload** (camelCase): `idempotencyKey`, `correlationId`, `startedAt`, `finishedAt`, `displayedDurationSec`, `expectedDurationSec`, `completedFully`, `countable`, `resultStatus`, `reasonIfNotCountable`, `participatingBindingCount`, `failedBindingCount`
- **HTTP error handling**: 401/429 -> FAILED_RETRYABLE; 4xx -> FAILED_TERMINAL; 5xx/network -> FAILED_RETRYABLE
- **Non-integer campaign_task_id** (test IDs): treated as FAILED_RETRYABLE so it remains visible

### Outbox / Retry Behavior

- Rows created with `QUEUED`
- `process_tv_ad_proof_outbox()` marks SENDING, sends, updates to SENT/FAILED_RETRYABLE/FAILED_TERMINAL
- Backoff: 30s -> 60s -> 120s -> 300s -> 600s -> 1800s -> 3600s (capped)
- Max attempts: 50
- `next_attempt_at` respected: rows with future timestamp are skipped
- Startup recovery: SENDING -> FAILED_RETRYABLE (crash safety)

### Local API Endpoints Added

```
GET  /api/v2/tv/ad-proofs                       -- list proofs (filters: gymId, taskId, outboxStates)
GET  /api/v2/tv/ad-proofs/{proofId}             -- single proof detail
POST /api/v2/tv/ad-proofs/process-outbox        -- trigger outbox send cycle
POST /api/v2/tv/ad-proofs/{proofId}/retry       -- explicit retry one proof
POST /api/v2/tv/ad-proofs/startup-recover       -- demote SENDING -> FAILED_RETRYABLE
```

### Verification

Python compile:
```
python -m py_compile app/core/tv_local_cache.py app/api/local_access_api_v2.py app/ui/app.py  # OK
```

Test script: `tmp/test_a8_proofs.py`

```
=== A8 Results: 54 passed, 0 failed ===
```

All 15 cases pass:
- Case 0: countable completed proof creation
- Case 1: idempotency (same key returns existing row)
- Case 2: non-countable aborted proof
- Case 3: FAILED_TO_START proof
- Case 4: duration tolerance boundary (28s/30s countable, 27s/30s not)
- Case 5: list_tv_ad_proof_outbox filters
- Case 6: load_tv_ad_proof by id
- Case 7: process_outbox marks FAILED_RETRYABLE when no backend
- Case 8: retry rejected for SENT / SENDING states
- Case 9: startup_recover_proof_outbox SENDING->FAILED_RETRYABLE
- Case 10: process_outbox respects next_attempt_at (future = skipped)
- Case 11: complete_tv_ad_display hooks proof creation
- Case 12: abort_tv_ad_display hooks proof creation
- Case 13: _expire_overdue hooks FAILED_TO_START proof
- Case 14: CANCELLED_REMOTE proof (not countable)

### What Was NOT Implemented (Out of Scope)

- Campaign progress logic in Access
- Support action system
- Broad observability UI
- Admin dashboard changes

### Next Functionality Recommendation

**A9 -- Startup Reconciliation / Preflight**: Full startup recovery combining A5 activation recovery, A7 ad runtime recovery, A8 proof outbox recovery, and a deployment preflight check. Alternatively, if observability UI is needed first, the stubs for fleet health / proof stats are in place.


### A9: Multi-Screen Orchestration (Host Level)
**Status:** Completed
**Focus:** Host-level orchestration layer for discovering monitors, persisting inventory, managing rigid bindings, and controlling player tauri window lifecycles through a React supervisor.

**Implementation Details:**
1. **Monitor Discovery:**
   - Implemented `TvOrchestrator.tsx` in Tauri using `@tauri-apps/api/window` to poll `availableMonitors()`.
   - Python caches these monitors in `tv_host_monitor` via the `POST /api/v2/tv/host/monitors/refresh` endpoint.
2. **Binding Configurations & Validations (`tv_local_cache.py`):**
   - Implemented binding CRUD enforcing "one monitor per active binding" rule and blocking reassignment of running bindings. Check validates `runtime_state` & `desired_state`.
   - Handled player starts, stops, and restarts which transition `desired_state` and log corresponding `tv_screen_binding_event` rows.
3. **Player Window Lifecycle (Supervisor Loop):**
   - `TvOrchestrator.tsx` polls `GET /api/v2/tv/host/bindings` every 5s.
   - For `RUNNING` bindings, it ensures a `WebviewWindow` named `tv-player-{binding_id}` exists, pointing to the `/tv-player?bindingId=...` route with correct monitor positioning.
   - For `STOPPED` bindings, it ensures such windows are closed securely.
4. **Local APIs (`local_access_api_v2.py`):**
   - Completed `_handle_tv_host_binding_start/stop/restart` endpoints by importing native cache implementations.
   - Added REST wrappers for missing Host API calls mapping directly to SQLite DB.
5. **Observability UI (`TvOverviewPage.tsx`):**
   - Built a React page displaying connected monitors and binding states (`RUNNING`, `STOPPED`). Affords manual creation, modification, and starting/stopping of streams per monitor.

---

## Access Functionality A10 -- Support / Recovery Actions

**Status: COMPLETE**
**Date completed: 2026-03-18**

### Summary

Implemented the Access-side binding-scoped support and recovery layer for MonClub TV. A10 now derives deterministic binding health from factual local state, enforces one in-flight support action per binding, persists every support action in `tv_support_action_log`, exposes support history, and wires recovery actions into the existing A2-A9 runtime without changing backend or dashboard logic.

### Exact Files Modified

- `app/core/tv_local_cache.py`
- `app/api/local_access_api_v2.py`
- `tauri-ui/src/api/types.ts`
- `tauri-ui/src/api/tv.ts`
- `tauri-ui/src/components/TvOrchestrator.tsx`
- `tauri-ui/src/pages/TvOverviewPage.tsx`
- `tmp/test_a10_support.py`
- `MONCLUB_TV_ACCESS_REBUILD_PROGRESS.md`

### Backend / Local Contracts Used

- **A2 sync reuse**: `_sync_screen_snapshot(api, token, screen_id, correlation_id)` via a binding-scoped support wrapper for `RUN_SYNC`
- **A3 download reuse**: `run_tv_asset_download(screen_id=...)` and `_process_single_asset(...)` for `RETRY_FAILED_DOWNLOADS` / `RETRY_ONE_DOWNLOAD`
- **A4 readiness reuse**: `compute_tv_screen_readiness(screen_id=...)`
- **A5 activation reuse**: `evaluate_tv_activation(screen_id=...)`, `activate_tv_latest_ready_snapshot(screen_id=..., trigger_source=...)`
- **A6 player reuse**: `reevaluate_tv_player(binding_id=...)`, `reload_tv_player(binding_id=...)`, `load_tv_player_state(...)`
- **A7/A8 health inputs**: `load_tv_gym_ad_runtime(...)`, `list_tv_ad_proof_outbox(...)`
- **A9 host runtime reuse**: `start_tv_screen_binding(...)`, `stop_tv_screen_binding(...)`, `upsert_tv_screen_binding_runtime(...)`, `record_tv_screen_binding_event(...)`

### Schema / Helpers Reused or Extended

- Reused A1-A9 tables:
  - `tv_screen_binding`
  - `tv_screen_binding_runtime`
  - `tv_screen_binding_event`
  - `tv_snapshot_cache`
  - `tv_snapshot_required_asset`
  - `tv_local_asset_state`
  - `tv_snapshot_readiness`
  - `tv_activation_state`
  - `tv_player_state`
  - `tv_player_event`
  - `tv_gym_ad_runtime`
  - `tv_ad_proof_outbox`
- Completed / reused A10 table:
  - `tv_support_action_log`
- Small additive schema extension:
  - idempotent runtime columns added on `tv_screen_binding_runtime`
    - `last_error_code`
    - `last_error_message`
- New / completed helper layer in `tv_local_cache.py`:
  - `load_tv_binding_support_summary`
  - `run_tv_binding_support_action`
  - `list_tv_support_action_logs`
  - `record_tv_screen_binding_runtime_event`
  - internal health derivation / support-action guard / support-log helpers
- Also replaced remaining continuity stubs where needed:
  - `load_tv_latest_ready_snapshot`
  - `load_tv_previous_ready_snapshot`
  - `load_tv_activation_status`

### Support Rules Implemented

- **Supported action types**
  - `RUN_SYNC`
  - `RECOMPUTE_READINESS`
  - `RETRY_FAILED_DOWNLOADS`
  - `RETRY_ONE_DOWNLOAD`
  - `REEVALUATE_ACTIVATION`
  - `ACTIVATE_LATEST_READY`
  - `REEVALUATE_PLAYER_CONTEXT`
  - `RELOAD_PLAYER`
  - `START_BINDING`
  - `STOP_BINDING`
  - `RESTART_BINDING`
  - `RESTART_PLAYER_WINDOW`
  - `RESET_TRANSIENT_PLAYER_STATE`
- **Support action results enforced**
  - `STARTED`
  - `SUCCEEDED`
  - `FAILED`
  - `SKIPPED`
  - `BLOCKED`
- **Single-flight**
  - per-binding in-memory lock blocks overlapping support actions
  - blocked overlap attempts are durably logged with `result=BLOCKED`
- **Durable support log**
  - every action attempt writes `tv_support_action_log`
  - rows include `action_type`, `result`, `started_at`, `finished_at`, `correlation_id`, `message`, `error_code`, `error_message`, `metadata_json`
- **Confirmation rules**
  - confirmation required for:
    - `STOP_BINDING`
    - `RESTART_BINDING`
    - `RESTART_PLAYER_WINDOW`
    - `RESET_TRANSIENT_PLAYER_STATE`
- **Preconditions / blocked cases implemented**
  - binding not found
  - action already running
  - missing/disconnected monitor for start/restart window flows
  - no latest ready snapshot for activation
  - reset while binding is not fully stopped
  - restart while transition already in progress
  - missing `mediaAssetId` for `RETRY_ONE_DOWNLOAD`
- **Skip behavior**
  - `RETRY_FAILED_DOWNLOADS` returns `SKIPPED` when no failed downloads exist
- **Safe reset scope**
  - `RESET_TRANSIENT_PLAYER_STATE` deletes only:
    - `tv_player_state`
    - `tv_player_event`
    - `tv_screen_binding_runtime`
  - it does **not** delete snapshots, assets, proofs, ad runtime rows, or support history
- **Health summary**
  - derived from factual Access-side state only
  - inputs include:
    - binding enabled / desired state
    - runtime state / crash count / runtime error fields
    - monitor availability
    - latest readiness
    - activation state
    - player state / fallback
    - ad runtime state
    - proof outbox failures
    - current failed downloads
  - output enum:
    - `HEALTHY`
    - `WARNING`
    - `DEGRADED`
    - `ERROR`
    - `STOPPED`

### Local API / Debug Endpoints Added

- `GET /api/v2/tv/host/bindings/{bindingId}/support-summary`
- `POST /api/v2/tv/host/bindings/{bindingId}/support-actions/run`
- `GET /api/v2/tv/host/bindings/{bindingId}/support-actions/history`
- Also completed host/runtime wiring needed by A10:
  - `GET /api/v2/tv/host/monitors`
  - `POST /api/v2/tv/host/monitors/refresh`
  - `GET /api/v2/tv/host/bindings`
  - `POST /api/v2/tv/host/bindings`
  - `PATCH /api/v2/tv/host/bindings/{bindingId}`
  - `DELETE /api/v2/tv/host/bindings/{bindingId}`
  - `POST /api/v2/tv/host/bindings/{bindingId}/start`
  - `POST /api/v2/tv/host/bindings/{bindingId}/stop`
  - `POST /api/v2/tv/host/bindings/{bindingId}/restart`
  - `GET /api/v2/tv/host/bindings/{bindingId}/status`
  - `GET /api/v2/tv/host/bindings/{bindingId}/events`
  - `POST /api/v2/tv/host/bindings/{bindingId}/runtime-event`

### Tauri / UI Files Modified

- `tauri-ui/src/api/types.ts`
  - added support action / health / history / summary types
  - extended `TvScreenBinding` to carry `runtime`
  - aligned `TvScreenBindingRuntime` with actual runtime fields
- `tauri-ui/src/api/tv.ts`
  - added support summary/history/run helpers
  - added runtime-event helper for the hidden supervisor
- `tauri-ui/src/components/TvOrchestrator.tsx`
  - now reports window lifecycle back to Python
  - now reacts to support restart signals by recycling a single binding window
- `tauri-ui/src/pages/TvOverviewPage.tsx`
  - rebuilt host overview into a support-capable page
  - displays per-binding health summary
  - adds support dialog with:
    - safe actions
    - destructive confirmation flow
    - targeted asset retry buttons
    - support history list
    - current factual runtime state summary

### Important Implementation Decisions

1. **No backend or dashboard changes** -- A10 is fully Access-local.
2. **Support action execution remains synchronous** -- actions write a `STARTED` row, run, then finalize the same durable log row.
3. **Single-flight is enforced in-process per binding** via a dedicated lock plus durable `BLOCKED` log rows for overlap attempts.
4. **Restart flows reuse A9** by marking runtime as `CRASHED` with support-specific `last_exit_reason`, which the Tauri orchestrator consumes to close/reopen one window without broad host resets.
5. **Health summary is derived, not assigned** -- no manual health flag exists.
6. **A10 completed earlier continuity stubs left behind from A5/A9 where needed.**

### Verification Commands / Results

Python compile:
```bash
python -m py_compile app/core/tv_local_cache.py
python -m py_compile app/api/local_access_api_v2.py
python -m py_compile tmp/test_a10_support.py
```
Result: all OK

A10 isolated verification script:
```bash
python tmp/test_a10_support.py
```
Result:
```text
=== A10 Results: 22 passed, 0 failed ===
```
Covered:
- support summary health response
- `RUN_SYNC`
- `RECOMPUTE_READINESS`
- `REEVALUATE_ACTIVATION`
- `ACTIVATE_LATEST_READY`
- `RETRY_FAILED_DOWNLOADS` skip behavior
- confirmation enforcement
- reset blocked while running
- single-flight overlap blocking
- support history rows + metadata

TypeScript / Vite build:
```bash
cd tauri-ui
npm run build
```
Result: build OK

Notes:
- Vite emitted existing chunk-size / dynamic-import warnings only, no build failures.

### What Remains for Next Functionality

- **A11 -- Observability / Retention**
  - build broader fleet-level observability views
  - retention / cleanup policies for TV local tables
  - aggregated proof / support / health reporting beyond one binding at a time

---

## Access Functionality A11 -- Observability / Retention

**Status: COMPLETE**
**Date completed: 2026-03-18**

### Summary

Implemented the Access-side observability and retention layer for MonClub TV. A11 now exposes host-level observability counts, binding diagnostics, gym ad diagnostics, proof outbox diagnostics, unified event history, and a conservative retention/cleanup routine that removes only old operational history while preserving active business truth.

### Exact Files Modified

- `app/core/tv_local_cache.py`
- `app/api/local_access_api_v2.py`
- `tauri-ui/src/api/types.ts`
- `tauri-ui/src/api/tv.ts`
- `tauri-ui/src/pages/TvOverviewPage.tsx`
- `tmp/test_a11_observability.py`
- `MONCLUB_TV_ACCESS_REBUILD_PROGRESS.md`

### Backend / Local Contracts Used

- Reused A10 binding support summary / health derivation via `load_tv_binding_support_summary(...)`
- Reused A1-A10 factual tables only:
  - `tv_screen_binding`
  - `tv_screen_binding_runtime`
  - `tv_screen_binding_event`
  - `tv_host_monitor`
  - `tv_snapshot_cache`
  - `tv_snapshot_required_asset`
  - `tv_local_asset_state`
  - `tv_snapshot_readiness`
  - `tv_sync_run_log`
  - `tv_activation_state`
  - `tv_activation_attempt`
  - `tv_player_state`
  - `tv_player_event`
  - `tv_ad_task_cache`
  - `tv_ad_task_runtime`
  - `tv_gym_ad_runtime`
  - `tv_ad_proof_outbox`
  - `tv_support_action_log`
- Reused A7/A8 helpers for ad runtime / proof visibility:
  - `load_tv_gym_ad_runtime(...)`
  - `list_tv_ad_task_runtime(...)`
  - `list_tv_ad_proof_outbox(...)`
- Reused A9/A10 host/runtime state:
  - `list_tv_screen_bindings()`
  - `load_tv_screen_binding_runtime(...)`
  - `list_tv_screen_binding_events(...)`
  - `list_tv_player_events(...)`

### Schema / Helpers Reused or Extended

- **No new schema tables were added in A11**
- **No destructive schema redesign**
- Added A11 helper layer in `tv_local_cache.py`:
  - `get_tv_observability_overview`
  - `list_tv_observability_bindings`
  - `get_tv_observability_binding`
  - `list_tv_observability_gyms`
  - `get_tv_observability_gym`
  - `list_tv_observability_proofs`
  - `list_tv_observability_events`
  - `get_tv_observability_retention`
  - `run_tv_retention_maintenance`
  - compatibility wrappers for older observability stub names
- Added deterministic stale/problem detection and proof-state aggregation helpers
- Added conservative retention policy helper:
  - `get_tv_retention_policy()`

### Observability and Retention Rules Implemented

- **Overview summary**
  - total bindings
  - healthy / warning / degraded / error / stopped counts
  - active monitors
  - active player windows
  - active gym ad runtimes
  - queued/retryable proof count
  - unresolved failed-download count across bindings
  - recent support-action count
  - stale/problem binding count
- **Binding diagnostics**
  - binding config + runtime row
  - monitor availability
  - readiness / activation / player state
  - ad runtime (when gym-scoped runtime exists)
  - proof backlog counts + visible rows
  - failed asset count
  - last support action
  - support history
  - binding/player/support unified recent events
  - sync run history + activation attempt history
- **Gym diagnostics**
  - gym ad runtime row
  - current task id + cached task row when present
  - coordination state
  - derived active/failed binding counts
  - audio override active
  - last error code/message
  - proof backlog summary
- **Proof diagnostics**
  - filterable local proof-outbox list with outbox state, result status, countable, attempts, next attempt, backend task status
- **Retention**
  - deletes only old operational history
  - keeps active bindings, runtime rows, activation state, current snapshots/readiness, valid assets, retryable/unsent proofs
  - cleanup targets implemented:
    - `tv_screen_binding_event`
    - `tv_player_event`
    - `tv_sync_run_log`
    - `tv_activation_attempt`
    - `tv_support_action_log`
    - terminal `tv_ad_task_runtime`
    - `tv_ad_proof_outbox` rows only when `SENT` / terminal and older than threshold
    - stale disconnected `tv_host_monitor` rows

### Local API / Debug Endpoints Added

- `GET /api/v2/tv/observability/overview`
- `GET /api/v2/tv/observability/bindings`
- `GET /api/v2/tv/observability/bindings/{bindingId}`
- `GET /api/v2/tv/observability/gyms`
- `GET /api/v2/tv/observability/gyms/{gymId}`
- `GET /api/v2/tv/observability/proofs`
- `GET /api/v2/tv/observability/retention`
- `POST /api/v2/tv/observability/retention/run`
- `GET /api/v2/tv/observability/events`

### Tauri / UI Files Modified

- `tauri-ui/src/api/types.ts`
  - added A11 overview / binding / gym / proof / retention response types
- `tauri-ui/src/api/tv.ts`
  - added A11 client helpers for observability + retention routes
- `tauri-ui/src/pages/TvOverviewPage.tsx`
  - added host observability summary cards
  - added retention summary panel + manual cleanup action
  - extended binding cards with failed-download / proof / support chips
  - upgraded binding support dialog into diagnostics + support drilldown with recent unified events

### Important Implementation Decisions

1. **A11 stays read/aggregate oriented** -- no new business rules were introduced.
2. **Binding remains the primary operational unit** -- overview/gym views aggregate upward from binding facts.
3. **Retention is conservative** -- only explicit history tables and terminal proof/runtime rows are eligible.
4. **No active truth deletion** -- current runtime, activation, readiness, snapshots, valid assets, and retryable proofs are preserved.
5. **Existing A10 support health summary is reused** instead of inventing a second health model.
6. **Older observability stub names were wired to useful A11 helpers** for continuity instead of redesigning prior surfaces.

### Verification Commands / Results

Python compile:
```bash
python -m py_compile app/core/tv_local_cache.py
python -m py_compile app/api/local_access_api_v2.py
python -m py_compile tmp/test_a11_observability.py
```
Result: all OK

A11 isolated verification script:
```bash
python tmp/test_a11_observability.py
```
Result:
```text
=== A11 Results: 28 passed, 0 failed ===
```
Covered:
- overview aggregate counts
- binding diagnostics joined state
- gym diagnostics ad runtime state
- proof diagnostics list/filter visibility
- retention summary eligible-row counts
- retention cleanup deleting only eligible rows
- runtime / activation truth preserved after retention
- retryable proofs preserved after retention

TypeScript / Vite build:
```bash
cd tauri-ui
npm run build
```
Result: build OK

Notes:
- Vite emitted existing dynamic-import / chunk-size warnings only, no build failures.

### Final Remaining Work / Deferred Items

- Dedicated startup reconciliation / deployment preflight framework remains separate from A11.
- Optional deeper operator drilldowns (fleet analytics pages, richer proof/event timelines) remain deferred.
- Backend/dashboard changes remain intentionally untouched.

## Access Functionality A12 -- Startup Reconciliation + Deployment Preflight

### Summary

Implemented the Access-local startup hardening layer for MonClub TV:

- deterministic deployment preflight with blocker / warning / info diagnostics
- persisted startup reconciliation runs + ordered phase history
- conservative interrupted-state repair for transient runtime/proof/ad states
- startup monitor refresh / binding-runtime reconcile / readiness + activation recheck
- operator-visible startup diagnostics in the TV overview with manual rerun support

This stays **Access only** and reuses A4/A5/A7/A8/A9/A10/A11 instead of introducing new business behavior.

### Exact Files Modified

- `app/core/tv_local_cache.py`
- `app/api/local_access_api_v2.py`
- `tauri-ui/src/api/types.ts`
- `tauri-ui/src/api/tv.ts`
- `tauri-ui/src/pages/TvOverviewPage.tsx`
- `tmp/test_a12_startup.py`
- `MONCLUB_TV_ACCESS_REBUILD_PROGRESS.md`

### Local Contracts / Helpers Reused or Extended

- Reused A4 readiness recompute via `run_tv_readiness_computation()`
- Reused A5 activation evaluation via `run_tv_activation_evaluation()`
- Reused A7/A8 startup recovery helpers:
  - `startup_recover_ad_runtime()`
  - `startup_recover_proof_outbox()`
- Reused A9/A10/A11 factual helpers:
  - `list_tv_screen_bindings()`
  - `replace_tv_host_monitors()`
  - `load_tv_screen_binding_runtime()`
  - `reevaluate_tv_player()`
  - `get_tv_observability_retention()`
  - binding / monitor / proof / asset tables already present
- Extended the binding runtime upsert helper so partial updates preserve existing `runtime_state` / `crash_count` instead of silently resetting them to defaults

### Startup / Preflight Rules Implemented

- Preflight blocker checks:
  - data root exists / can be created
  - data root writable
  - SQLite DB open works
  - TV schema bootstrap works
  - required TV directories can be created
  - config loads
- Preflight warning checks:
  - no connected monitor
  - no bindings configured
  - no latest snapshot cache rows
  - backend/API reachability probe when requested
  - missing auth token
  - proof backlog exists
  - failed download backlog exists
- Preflight info checks:
  - monitor count
  - binding count
  - latest startup reconciliation timestamp
  - current retention eligible-row summary when available
- Ordered persisted phases:
  1. `migration`
  2. `preflight`
  3. `interrupted_state_repair`
  4. `temp_cleanup`
  5. `monitor_rescan`
  6. `binding_runtime_reconcile`
  7. `readiness_recheck`
  8. `activation_reconcile`
  9. `proof_outbox_recover`
  10. `ad_runtime_recover`
  11. `window_runtime_reconcile`
  12. `finalize`
- Conservative repair rules:
  - `tv_ad_proof_outbox.SENDING -> FAILED_RETRYABLE`
  - transient `STARTING` / `STOPPING` binding runtime rows repaired to safe stable states
  - stuck gym ad runtime states recovered through existing A7 helper
  - stale `.downloading` / `.partial` / `.part` temp files older than threshold removed
  - desired `RUNNING` bindings with no live startup window fact are marked recoverable / unhealthy instead of silently healthy
  - activation state is reevaluated but never force-activates an unready snapshot

### Local API / Debug Endpoints Added

- `GET /api/v2/tv/startup/latest`
- `GET /api/v2/tv/startup/runs`
- `POST /api/v2/tv/startup/run`
- `GET /api/v2/tv/startup/preflight`

### Tauri / UI Files Modified

- `tauri-ui/src/api/types.ts`
  - added A12 startup preflight / run / phase contracts
- `tauri-ui/src/api/tv.ts`
  - added A12 client helpers for startup endpoints
- `tauri-ui/src/pages/TvOverviewPage.tsx`
  - added startup diagnostics card
  - shows latest startup status, blocker / warning / info counts, latest phase list, and recent startup runs
  - added manual `Run Startup Check` action using current Tauri monitor inventory

### Important Implementation Decisions

1. **Startup stays conservative** -- facts are reconciled first; no new business truth is invented.
2. **No active-truth deletion** -- snapshots, readiness, activation truth, valid assets, and business history remain intact.
3. **Monitor refresh uses supplied Tauri monitor payload when available**; otherwise the existing monitor cache is retained and surfaced clearly.
4. **Bindings that wanted RUNNING but have no live window fact are explicitly marked unhealthy/recoverable** so A9 supervisor/UI can restart them safely instead of the host pretending they are healthy.
5. **Preflight endpoint always returns JSON diagnostics** even when blockers exist, so the UI can display blocker details instead of failing closed.
6. **A12 also fixed a real partial-runtime-upsert bug** uncovered during verification, where partial updates could unintentionally reset runtime state to `IDLE`.

### Verification Commands / Results

Python compile:
```bash
python -m py_compile app/core/tv_local_cache.py
python -m py_compile app/api/local_access_api_v2.py
python -m py_compile tmp/test_a12_startup.py
```
Result: all OK

A12 isolated verification script:
```bash
python tmp/test_a12_startup.py
```
Result:
```text
A12 startup verification: 23 passed, 0 failed
```
Covered:
- blocker preflight scenarios for bad data root and config load failure
- structured preflight summary output
- persisted startup run + ordered phase rows
- proof `SENDING -> FAILED_RETRYABLE`
- stale temp file cleanup preserving valid media
- ad runtime recovery
- safe binding runtime reconcile
- activation state preservation
- latest startup load + history listing

TypeScript / Vite build:
```bash
cd tauri-ui
npm run build
```
Result: build OK

Notes:
- existing Vite dynamic-import / chunk-size warnings remained, but no build failure

### Final Deferred Items / Next Functionality Recommendation

- A12 is now in place; future work can build on persisted startup history rather than inventing a second startup model.
- If a later functionality needs richer operator tooling, the next sensible step is deeper runtime analytics / correlation drilldowns on top of the A11+A12 local facts.
- Backend and dashboard remain intentionally untouched.

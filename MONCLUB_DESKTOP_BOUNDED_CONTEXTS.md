# MonClub Desktop Bounded Contexts

## Purpose

This document defines the actual MonClub desktop bounded contexts using the current repository as the baseline.

## Context Map

### Access Context

Primary ownership:

- door authorization
- ZKTeco device control and RTLog polling
- sync cache for users/memberships/devices
- access-side settings derived from backend
- offline member/account creation queue
- access notifications, popups, and history
- access operator UI

Repository surfaces currently inside this context:

- `app/core/db.py`
- `app/core/device_sync.py`
- `app/core/realtime_agent.py`
- `app/core/settings_reader.py`
- `app/sdk/pullsdk.py`
- `app/sdk/zkfinger.py`
- `app/ui/app.py` as current composition root
- `tauri-ui/src/pages/DashboardPage.tsx`
- `tauri-ui/src/pages/DevicesPage.tsx`
- `tauri-ui/src/pages/UsersPage.tsx`
- `tauri-ui/src/pages/EnrollPage.tsx`
- `tauri-ui/src/pages/AgentPage.tsx`
- `tauri-ui/src/pages/ConfigPage.tsx`
- `tauri-ui/src/pages/LogsPage.tsx`
- `tauri-ui/src/pages/LocalDbPage.tsx`
- `tauri-ui/src/pages/LoginPage.tsx`
- `tauri-ui/src/pages/RestrictedPage.tsx`
- `tauri-ui/src/pages/PopupWindow.tsx`

What Access may consume from shared:

- backend API client base
- config envelopes
- logger/correlation helpers
- updater/install metadata
- shared desktop path layout

What Access must not depend on directly in the target state:

- TV binding runtime rows
- TV player runtime state
- TV readiness/activation/ad/proof tables
- TV operator workflows

## TV Context

Primary ownership:

- monitor discovery and binding orchestration
- snapshot fetch/cache and manifest cache
- asset download and validation state
- readiness and activation logic
- player render context and player events
- ad runtime and proof outbox
- TV support/recovery/observability/startup hardening
- TV operator UI

Repository surfaces currently inside this context:

- `app/core/tv_local_cache.py`
- TV route cluster in `app/api/local_access_api_v2.py`
- `tauri-ui/src/pages/TvOverviewPage.tsx`
- `tauri-ui/src/pages/TvPlayerWindowPage.tsx`
- `tauri-ui/src/components/TvOrchestrator.tsx`
- `tauri-ui/src/api/tv.ts`

What TV may consume from shared:

- backend API client base
- config envelopes
- logger/correlation helpers
- updater/install metadata
- shared desktop path layout

What TV must not depend on directly in the target state:

- PullSDK/RTLog/device workers
- offline access-member creation queue
- access authorization history
- scanner enrollment
- access-only device pages and flows

## Shared Core/Common Context

Primary ownership:

- backend API contract/client base
- bootstrap descriptors
- shared path metadata for install/data roots
- config model wrappers used by both apps
- logging, buffering, correlation helpers
- platform/runtime descriptors

Repository surfaces that should become shared or are already split-ready candidates:

- `app/api/monclub_api.py`
- `app/core/arch.py`
- `app/core/logger.py`
- `app/core/log_buffer.py`
- path/layout logic in `app/core/utils.py`
- updater/install path conventions from `app/core/update_manager.py`, `installer/MonClubAccess.iss`, and `updater/MonClubAccessUpdater/*`

Shared is explicitly not allowed to own:

- mutable device runtime state
- mutable TV runtime state
- a shared operational SQLite database
- business workflows that belong to Access or TV

## Cross-Context Rules

### Access -> TV

Allowed in Phase 1:

- Access may host the TV local API surface temporarily
- Access may launch the current Tauri UI bundle that contains TV pages
- Access may keep using current TV modules through an anti-corruption boundary

Forbidden in the target state:

- Access runtime logic using TV runtime tables for correctness
- Access process availability depending on TV window/player health

### TV -> Access

Allowed in Phase 1:

- TV may reuse shared config/auth/API infrastructure through wrappers
- TV may still coexist in the current combined process while boundaries are introduced

Forbidden in the target state:

- TV runtime depending on access-control workers or access history tables
- TV failures propagating into access-control scheduling or device operations

### Shared -> Access / TV

Shared may expose:

- immutable contracts
- helpers
- base infrastructure

Shared may not become:

- a third business runtime
- a shared mutable datastore

## Context Boundaries by Data

### Access-owned data

- `auth_state`
- `sync_cache`, `sync_meta`
- `sync_users`, `sync_memberships`, `sync_devices`, `sync_infrastructures`, `sync_gym_access_credentials`, `sync_access_software_settings`, `sync_device_door_presets`
- `device_door_presets`
- `fingerprints`
- `access_history`
- `device_sync_state`
- `agent_rtlog_state`
- `offline_creation_queue`

### TV-owned data

- `tv_host_monitor`
- `tv_screen_binding`
- `tv_screen_binding_runtime`
- `tv_screen_binding_event`
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
- `tv_startup_reconciliation_run`
- `tv_startup_reconciliation_phase`

### Shared install metadata only

- installer component metadata
- updater channel/version metadata
- stable path configuration

## Context Boundaries by UI

### Access UI

- dashboard
- devices
- users
- enrollment
- agent
- logs
- config
- local DB
- login/restricted
- popup access notifications

### TV UI

- TV overview
- TV player window
- TV orchestration window lifecycle

### Shared UI building blocks

- generic layout/theme/components
- API client wrapper
- common type definitions that are not business-runtime specific

## Phase 1 Boundary Decision

Phase 1 should not perform a full code move of critical modules.

Phase 1 should:

- add explicit `access/`, `tv/`, and `shared/` boundaries
- route new composition-root imports through those boundaries
- keep legacy implementation modules in place behind wrappers
- prepare split-ready storage/bootstrap metadata

That is the lowest-risk direction that moves the repository toward the locked architecture without destabilizing the working system.

# MonClub Desktop Separation Plan

## Locked Target

This repository is moving to the locked target architecture:

- `MonClub Access` = critical access-control desktop agent
- `MonClub TV` = separate signage/player desktop app/runtime
- `Shared Core/Common` = contracts, DTOs, config models, API client base, logging/correlation helpers, updater/install plumbing
- separate SQLite databases
- backend remains source of truth
- no shared mutable runtime DB between Access and TV
- TV failures must never degrade access control

This document is based on the current repository state in `C:\Users\mohaa\Desktop\monclub_access_python`.

## Current-State Audit

### Current desktop/bootstrap shape

- Python entrypoint: `app/main.py`
- Main composition root: `app/ui/app.py`
- Tauri shell: `tauri-ui/src/App.tsx`
- Tauri Rust host: `tauri-ui/src-tauri/src/lib.rs`
- Local API server: `app/api/local_access_api_v2.py`
- PyInstaller entry: `MonClubAccess.spec`
- Release packaging: `build_release.ps1`, `generate_installer.ps1`
- Installer: `installer/MonClubAccess.iss`
- Updater: `updater/MonClubAccessUpdater/*`

### Where Access responsibilities currently live

Access-control responsibilities are concentrated in:

- `app/core/db.py`
  - auth token storage
  - sync cache normalization
  - device sync state
  - access history
  - offline creation queue
  - fingerprint cache
  - local door presets
- `app/core/device_sync.py`
  - PushSDK synchronization for `DEVICE` mode devices
- `app/core/realtime_agent.py`
  - `AGENT` mode device workers
  - RTLog polling
  - access decisioning
  - notifications/popups/history writing
- `app/sdk/*`
  - ZKTeco DLL bindings and device/scanner integration
- `app/core/settings_reader.py`
  - backend-driven access settings normalization from SQLite cache
- `app/ui/app.py`
  - auth/session handling
  - local API startup
  - device sync scheduling
  - realtime agent lifecycle
  - offline creation retry flow
- Tauri access pages:
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

### Where TV responsibilities currently live

TV responsibilities are concentrated in:

- `app/core/tv_local_cache.py`
  - monitor inventory
  - screen bindings and runtime state
  - snapshot cache and manifest cache
  - asset download/cache state
  - readiness and activation
  - player runtime state/events
  - ad runtime/task/proof state
  - support/recovery actions
  - observability/retention
  - startup reconciliation and preflight
- `app/api/local_access_api_v2.py`
  - TV host orchestration endpoints
  - TV sync/readiness/activation/player endpoints
  - TV ad/proof/support/observability/startup endpoints
- Tauri TV surfaces:
  - `tauri-ui/src/pages/TvOverviewPage.tsx`
  - `tauri-ui/src/pages/TvPlayerWindowPage.tsx`
  - `tauri-ui/src/components/TvOrchestrator.tsx`
  - `tauri-ui/src/api/tv.ts`
  - TV DTOs inside `tauri-ui/src/api/types.ts`

### Mixed/coupled modules today

The main coupling points are:

- `app/ui/app.py`
  - launches Tauri UI while also owning access-control runtime
  - owns both update manager and local API server
  - composes access and TV concerns in one application object
- `app/api/local_access_api_v2.py`
  - one local API surface for access + TV + updater + DB tools
- `app/core/config.py`
  - same config model stores access endpoints and TV endpoints
- `app/core/utils.py`
  - one data root and one active SQLite path (`app.db`)
- `tauri-ui/src/App.tsx`
  - one Tauri shell routes both access and TV features
- `tauri-ui/src/layouts/MainLayout.tsx`
  - one navigation tree contains both access and TV pages
- packaging
  - `MonClubAccess.spec`, `build_release.ps1`, and `installer/MonClubAccess.iss` bundle Python runtime + Tauri UI as one product named MonClub Access

### Runtime/storage/config coupling today

- one active SQLite file: `app/core/utils.py` exposes `DB_PATH = DATA_DIR / "app.db"`
- both `app/core/db.py` and `app/core/tv_local_cache.py` use the same SQLite database
- one config file: `app/core/utils.py` exposes `CONFIG_PATH = DATA_DIR / "config.json"`
- one local API port and process: `LocalAccessApiServerV2` serves both Access and TV
- one Python composition root: `MainApp` in `app/ui/app.py`
- one Tauri process launched by Access
- installer/updater are Access-branded and currently update the whole bundle together

## File Ownership Classification

### Clearly Access-only

- `app/core/db.py`
- `app/core/device_sync.py`
- `app/core/realtime_agent.py`
- `app/core/settings_reader.py`
- `app/sdk/*`
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

### Clearly TV-only

- `app/core/tv_local_cache.py`
- `tauri-ui/src/components/TvOrchestrator.tsx`
- `tauri-ui/src/pages/TvOverviewPage.tsx`
- `tauri-ui/src/pages/TvPlayerWindowPage.tsx`
- `tauri-ui/src/api/tv.ts`

### Should move to Shared/Core

- `app/api/monclub_api.py`
- `app/core/arch.py`
- `app/core/logger.py`
- `app/core/log_buffer.py`
- shared desktop path/layout metadata currently spread through `app/core/utils.py`
- updater/install metadata and path helpers currently spread through `app/core/update_manager.py`, `build_release.ps1`, `installer/MonClubAccess.iss`

### Should remain composition roots, but split later

- `app/ui/app.py`
- `app/api/local_access_api_v2.py`
- `tauri-ui/src/App.tsx`
- `tauri-ui/src/layouts/MainLayout.tsx`
- `tauri-ui/src-tauri/src/lib.rs`

## Target Bounded Contexts

### MonClub Access

Access owns:

- device connectivity and driver integration
- RTLog polling and access decisions
- offline user/account creation queue
- access history and local door authorization support
- scanner/enrollment tools
- access-specific UI and operator workflows
- access updater channel and access runtime health

Access must not own:

- TV bindings/windows/monitors
- snapshot cache/readiness/activation
- TV player runtime
- TV ad runtime/proofs/support/observability

### MonClub TV

TV owns:

- monitor inventory and screen bindings
- one player window per screen
- snapshot fetch/cache
- asset download/cache
- readiness and activation evaluation
- player window lifecycle and support/recovery
- ad runtime/proof tracking
- TV observability, retention, startup reconciliation

TV must not own:

- ZKTeco device access logic
- RTLog polling and access authorization
- offline access-member creation
- access notifications and popup screen

### Shared Core/Common

Shared owns only stable cross-app building blocks:

- backend API client base and DTO contracts
- config model envelopes and split path layout metadata
- logging/correlation helpers
- installer/updater manifest/path plumbing
- stable enums/descriptors for bootstrap and packaging

Shared must not own mutable runtime state or operational SQLite tables.

## Storage Split

### Target databases

`access.db` should contain:

- auth/session state if stored locally
- sync cache normalized tables
- device sync state
- access history
- offline creation queue
- local fingerprint cache
- access-only settings/cache derived from backend

`tv.db` should contain:

- monitor inventory
- screen binding and binding runtime state
- snapshot cache and required assets
- local asset validation state
- readiness and activation tables
- player state and event logs
- ad task/runtime/proof state
- support logs
- observability history
- startup reconciliation runs/phases

### Tiny shared install config

Shared install config may contain only:

- install/component metadata
- updater channel/platform metadata
- backend base URLs that both apps need
- optional launcher-discovery metadata

It must not contain mutable operational state. If auth must be shared later, use OS secure storage or explicit token replication, not a shared SQLite runtime database.

### Current-to-target migration

Current state is one SQLite file (`app.db`) with access and TV tables together.

Migration target:

1. keep `app.db` as the live runtime DB during Phase 1
2. introduce split-ready path scaffolding for `access.db` and `tv.db`
3. move repositories/service imports behind `access/`, `tv/`, and `shared/` boundaries
4. later migrate data table-by-table into separate DBs
5. stop any cross-context table access before the actual DB cutover

## Process Model

### Target Access process

- own Python service/runtime for access control
- own access local API or access-specific IPC surface
- own access tray/shell and access operator UI
- continue operating even if TV is absent or broken

### Target TV process

- own TV orchestration/runtime and player windows
- own TV local API or TV-specific IPC surface
- own TV operator UI
- may be installed without Access

### Optional shared shell/tray

Only justified if a future installer/launcher needs a lightweight selector/tray. It must not become a shared business runtime.

### Failure isolation

- Access crash must not take down TV if both are installed
- TV crash must not take down access control
- updater/install actions must be component-aware
- no live TV processing inside the critical access-control process after later phases

## Communication Model

### Through backend only

These should converge on backend-mediated coordination:

- auth/session identity
- gym/screen/device/source-of-truth configuration
- snapshots and manifests
- ad task fetch and proof submission
- access sync payloads
- release/update metadata

### Optional local IPC

Allowed only for narrow host-local coordination later, for example:

- launcher asking each app for health/version
- optional command handoff between Access shell and TV shell
- optional local “open screen details” action

### Must never use shared DB communication

- Access must not read/write TV runtime state through a shared mutable SQLite file as a final architecture
- TV must not depend on access tables for its runtime decisions
- no “shared operational database” once the split is complete

## Packaging / Installer Model

### Current packaging state

- Python release payload is built as `MonClubAccess`
- Tauri UI executable is bundled into the same release payload
- Inno Setup installer installs one `MonClubAccess` product
- updater is `MonClubAccessUpdater.exe`

### Target packaging state

- one desktop ecosystem / installer family
- separate installable components:
  - Access
  - TV
  - shared prerequisites/launcher only if needed
- separate executable/process identities
- updater/component boundaries per app, even if distributed by one installer

## Phase Structure

### Phase 1

- create `access/`, `tv/`, and `shared/` package boundaries
- add split-ready storage path scaffolding for `access.db` and `tv.db`
- add future Access and TV bootstrap descriptors/entry modules
- route new composition-root imports through those boundaries
- keep current runtime behavior unchanged

### Phase 2

- move more access and TV implementation modules behind repository/service facades
- reduce direct imports from `app.core.tv_local_cache` and `app.core.db`
- split config namespaces

### Phase 3

- separate TV runtime into its own process/app bootstrap
- give TV its own local API/service host
- keep Access process free of TV runtime responsibility

### Phase 4

- migrate from `app.db` to `access.db` + `tv.db`
- implement data migration tooling and cutover

### Phase 5

- split installer/update channels into component-aware delivery
- optional lightweight ecosystem launcher if still justified

# MonClub Desktop Bounded Contexts

## Final Bounded Contexts

### MonClub Access

Owns:

- ZKTeco device connectivity
- realtime agent / door authorization decisions
- offline account/member creation queue
- access history
- access operator workflows
- access-specific local API routes
- Access packaging, installer identity, and Access runtime update flow
- Access persisted config in `access/config.json`

Primary code boundaries:

- [access](C:\Users\mohaa\Desktop\monclub_access_python\access)
- [app/core/db.py](C:\Users\mohaa\Desktop\monclub_access_python\app\core\db.py)
- [access/update_runtime.py](C:\Users\mohaa\Desktop\monclub_access_python\access\update_runtime.py)
- [access/config.py](C:\Users\mohaa\Desktop\monclub_access_python\access\config.py)
- [app/ui/app.py](C:\Users\mohaa\Desktop\monclub_access_python\app\ui\app.py)

Primary data store:

- `access.db`

Primary persisted config:

- `access/config.json`

### MonClub TV

Owns:

- host monitor inventory
- screen bindings and window/runtime state
- snapshot/asset cache
- readiness and activation
- player lifecycle
- support/recovery
- ad runtime / proof outbox
- TV observability, retention, startup reconciliation
- TV-specific local API routes
- TV packaging and installer identity
- TV persisted config in `tv/config.json`
- TV runtime update flow

Primary code boundaries:

- [tv](C:\Users\mohaa\Desktop\monclub_access_python\tv)
- [app/core/tv_local_cache.py](C:\Users\mohaa\Desktop\monclub_access_python\app\core\tv_local_cache.py)
- [tv/auth_bridge.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\auth_bridge.py)
- [tv/update_runtime.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\update_runtime.py)
- [tv/config.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\config.py)
- [tauri-ui/src/tv](C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui\src\tv)

Primary data store:

- `tv.db`

Primary persisted config:

- `tv/config.json`

### Shared

Owns only stable cross-app infrastructure:

- tiny install metadata + config migration helpers
- platform/bootstrap helpers
- logging/correlation helpers
- DTO-style contracts/metadata
- Tauri launch helpers
- migration helpers that move data between owned stores but do not become runtime truth
- shared packaging metadata and generic updater infrastructure

Primary code boundaries:

- [shared](C:\Users\mohaa\Desktop\monclub_access_python\shared)
- [packaging/desktop_components.ps1](C:\Users\mohaa\Desktop\monclub_access_python\packaging\desktop_components.ps1)
- [updater/MonClubAccessUpdater](C:\Users\mohaa\Desktop\monclub_access_python\updater\MonClubAccessUpdater)

Shared must not own:

- access business tables
- TV business tables
- cross-component mutable runtime state
- cross-component operational config semantics

## Concrete Storage Ownership

### Access-owned tables in `access.db`

- `fingerprints`
- `auth_state`
- `sync_cache`
- `sync_meta`
- `sync_users`
- `sync_memberships`
- `sync_access_software_settings`
- `sync_devices`
- `sync_device_door_presets`
- `sync_infrastructures`
- `sync_gym_access_credentials`
- `device_door_presets`
- `agent_rtlog_state`
- `access_history`
- `device_sync_state`
- `offline_creation_queue`

### TV-owned tables in `tv.db`

- `tv_backend_auth_state`
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

### Legacy compatibility

- `app.db` is migration source / compatibility artifact only
- it is no longer the intended live runtime DB for either component

## Concrete Config Ownership

### Access-owned persisted config

- live file: `access/config.json`
- owned by [access/config.py](C:\Users\mohaa\Desktop\monclub_access_python\access\config.py)
- includes:
  - device/runtime tuning
  - Access local API bind
  - Access update settings
  - Access backend API URLs
  - Access logging/tray/runtime preferences

### TV-owned persisted config

- live file: `tv/config.json`
- owned by [tv/config.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\config.py)
- includes:
  - TV local API bind
  - TV update settings
  - TV snapshot/ad/proof API URLs
  - TV logging/runtime preferences

### Tiny shared install metadata

- live file: `shared/install.json`
- owned by [shared/config.py](C:\Users\mohaa\Desktop\monclub_access_python\shared\config.py)
- includes only:
  - split-config mode/version
  - legacy config migration timestamp/source
  - installed component presence
  - updater runtime mode metadata
  - `ipc_mode`

The shared file is install/ecosystem metadata only. It is not a business-runtime config file.

## Concrete Packaging Ownership

### Access delivery surface

- spec: [MonClubAccess.spec](C:\Users\mohaa\Desktop\monclub_access_python\MonClubAccess.spec)
- installer: [MonClubAccess.iss](C:\Users\mohaa\Desktop\monclub_access_python\installer\MonClubAccess.iss)
- release artifact family:
  - `MonClubAccess.exe`
  - `MonClubAccess-<releaseId>.zip`
  - `MonClubAccess-<releaseId>.manifest.json`
  - `MonClubAccessSetup-<releaseId>.exe`

### TV delivery surface

- spec: [MonClubTV.spec](C:\Users\mohaa\Desktop\monclub_access_python\MonClubTV.spec)
- installer: [MonClubTV.iss](C:\Users\mohaa\Desktop\monclub_access_python\installer\MonClubTV.iss)
- release artifact family:
  - `MonClubTV.exe`
  - `MonClubTV-<releaseId>.zip`
  - `MonClubTV-<releaseId>.manifest.json`
  - `MonClubTVSetup-<releaseId>.exe`

### Shared ecosystem delivery

- component metadata source: [desktop_components.ps1](C:\Users\mohaa\Desktop\monclub_access_python\packaging\desktop_components.ps1)
- ecosystem build entry: [generate_installer.ps1](C:\Users\mohaa\Desktop\monclub_access_python\generate_installer.ps1)
- ecosystem bundle manifest: `MonClubDesktopEcosystem-<releaseId>.bundle.json`

## Code Ownership Rules Going Forward

### Access rules

- Access code must not depend on TV runtime health for correctness
- Access packaging can ship shared infrastructure, but Access remains a complete installable artifact on its own
- Access update runtime is owned by [access/update_runtime.py](C:\Users\mohaa\Desktop\monclub_access_python\access\update_runtime.py)
- Access config routes must only mutate Access-owned config fields

### TV rules

- TV code must not depend on access-control workers or access-history behavior
- TV packaging can reuse shared updater infrastructure, but TV artifact identity must stay `MonClubTV`
- TV update runtime is owned by [tv/update_runtime.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\update_runtime.py)
- TV config routes must only mutate TV-owned config fields
- TV backend auth is now read from `tv_backend_auth_state` in `tv.db`, not from Access live storage
- TV may perform a one-time compatibility import from Access/legacy auth state only when its own auth row is still absent, and that compatibility behavior is isolated in [tv/auth_bridge.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\auth_bridge.py)

### Shared rules

- Shared may provide generic updater infrastructure, but not component business behavior
- Shared may provide config migration helpers and install metadata, but not one monolithic operational config blob
- Shared may provide build metadata, but not component-specific release logic hidden in opaque defaults
- Shared must not become a third operational runtime with its own business DB
- Shared updater code may remain one project, but its code-level naming must stay component-neutral

## IPC Decision

- Phase 7 re-confirmed that local IPC is still unnecessary.
- Reason:
  - Access and TV are already separated in process, DB, config, and packaging.
  - no inspected runtime, update, or operator flow required sibling-process RPC to stay correct.
  - adding IPC now would create another operational coupling surface without solving a current blocker.

## Temporary Exceptions Still Present

- Access still mirrors backend auth into TV storage on a best-effort basis so TV can bootstrap without prompting for a separate login
- TV can still import legacy auth state once from Access/legacy storage if its own auth row is empty, and that import path is isolated in [tv/auth_bridge.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\auth_bridge.py)
- one shared Tauri source tree still exists, but TV-owned implementations now live under [tauri-ui/src/tv](C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui\src\tv)
- one shared updater implementation project still exists
- legacy `data/config.json` can still exist as migration input from pre-split installs

These are known temporary seams, not target-state ownership decisions.

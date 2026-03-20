# MonClub Desktop Separation Plan

## Locked Target

MonClub desktop is being split using the locked target model:

- `MonClub Access` = critical access-control desktop agent
- `MonClub TV` = separate signage/player desktop app
- `Shared` = stable contracts/infrastructure only
- separate processes
- separate live SQLite databases
- backend remains source of truth
- no shared mutable runtime DB

Phase 8 retires low-value transitional debt after process, storage, packaging, config, and update separation were already completed in Phases 3 through 7.

## Current State After Phase 8

### Runtime/process state

- Access starts independently through [access/main.py](C:\Users\mohaa\Desktop\monclub_access_python\access\main.py)
- TV starts independently through [tv/main.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\main.py)
- the shared Tauri shell is still one codebase, but it is launched in explicit `access` or `tv` mode
- Access no longer hosts TV by default

### Storage state

- Access uses `access.db`
- TV uses `tv.db`
- legacy `app.db` remains migration-only / compatibility-only

### Config/update state

- Access now persists runtime config in `access/config.json`
- TV now persists runtime config in `tv/config.json`
- shared install metadata is reduced to `shared/install.json`
- Access now owns an Access update-runtime wrapper: [access/update_runtime.py](C:\Users\mohaa\Desktop\monclub_access_python\access\update_runtime.py)
- TV now owns a TV update-runtime wrapper: [tv/update_runtime.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\update_runtime.py)
- both wrappers use one shared generic engine in [shared/update_runtime.py](C:\Users\mohaa\Desktop\monclub_access_python\shared\update_runtime.py), but runtime state is component-local
- TV now exposes TV-owned config/update routes from [tv/local_api_routes.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\local_api_routes.py)
- TV now persists its own backend auth row in `tv.db`
- the remaining auth compatibility seam is isolated in [tv/auth_bridge.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\auth_bridge.py)
- Access login/logout still mirror backend auth into the TV-owned auth row on a best-effort basis; Access correctness does not depend on TV mirroring succeeding
- TV may still perform a one-time compatibility import from Access/legacy auth state if its own auth row does not exist yet
- local IPC is still intentionally not implemented; shared install metadata records `ipc_mode = NONE`

### Frontend / Tauri state

- shared Tauri infrastructure still lives in one source tree
- TV-owned implementations now live directly under [tauri-ui/src/tv](C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui\src\tv)
- low-value generic TV wrapper files under `src/pages`, `src/components`, and `src/api` were removed in Phase 8 because all live imports already resolved through `src/tv/*`

### Packaging/delivery state

- Access now has a dedicated PyInstaller spec: [MonClubAccess.spec](C:\Users\mohaa\Desktop\monclub_access_python\MonClubAccess.spec)
- TV now has a dedicated PyInstaller spec: [MonClubTV.spec](C:\Users\mohaa\Desktop\monclub_access_python\MonClubTV.spec)
- Access now has a dedicated installer script: [MonClubAccess.iss](C:\Users\mohaa\Desktop\monclub_access_python\installer\MonClubAccess.iss)
- TV now has a dedicated installer script: [MonClubTV.iss](C:\Users\mohaa\Desktop\monclub_access_python\installer\MonClubTV.iss)
- release/installer scripts are now component-aware through [desktop_components.ps1](C:\Users\mohaa\Desktop\monclub_access_python\packaging\desktop_components.ps1)
- the repo now supports packaging:
  - Access only
  - TV only
  - both, via one ecosystem build invocation that produces both installers and an ecosystem bundle manifest

## Current-State Audit

### Access-owned code

- Access bootstrap/runtime: [access/bootstrap.py](C:\Users\mohaa\Desktop\monclub_access_python\access\bootstrap.py), [access/main.py](C:\Users\mohaa\Desktop\monclub_access_python\access\main.py), [access/runtime.py](C:\Users\mohaa\Desktop\monclub_access_python\access\runtime.py)
- Access storage: [access/store.py](C:\Users\mohaa\Desktop\monclub_access_python\access\store.py), [access/storage.py](C:\Users\mohaa\Desktop\monclub_access_python\access\storage.py), [app/core/db.py](C:\Users\mohaa\Desktop\monclub_access_python\app\core\db.py)
- Access config/update ownership: [access/config.py](C:\Users\mohaa\Desktop\monclub_access_python\access\config.py), [access/update_runtime.py](C:\Users\mohaa\Desktop\monclub_access_python\access\update_runtime.py)
- Access local API ownership: [access/api.py](C:\Users\mohaa\Desktop\monclub_access_python\access\api.py), [access/local_api_routes.py](C:\Users\mohaa\Desktop\monclub_access_python\access\local_api_routes.py)
- the unused legacy updater shim `app/core/update_manager.py` was removed in Phase 8

### TV-owned code

- TV bootstrap/runtime: [tv/bootstrap.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\bootstrap.py), [tv/main.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\main.py), [tv/app.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\app.py), [tv/runtime.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\runtime.py)
- TV storage: [tv/store.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\store.py), [tv/storage.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\storage.py), [app/core/tv_local_cache.py](C:\Users\mohaa\Desktop\monclub_access_python\app\core\tv_local_cache.py)
- TV config/update ownership: [tv/config.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\config.py), [tv/update_runtime.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\update_runtime.py)
- TV local API ownership: [tv/api.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\api.py), [tv/local_api_routes.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\local_api_routes.py)
- TV UI ownership seam: [tauri-ui/src/tv](C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui\src\tv)

### Shared/common code

- config split helpers + install metadata: [shared/config.py](C:\Users\mohaa\Desktop\monclub_access_python\shared\config.py)
- logging/runtime helpers: [shared/logging.py](C:\Users\mohaa\Desktop\monclub_access_python\shared\logging.py), [shared/runtime_support.py](C:\Users\mohaa\Desktop\monclub_access_python\shared\runtime_support.py)
- Tauri launch bridge: [shared/tauri_launcher.py](C:\Users\mohaa\Desktop\monclub_access_python\shared\tauri_launcher.py)
- desktop descriptors/contracts: [shared/contracts.py](C:\Users\mohaa\Desktop\monclub_access_python\shared\contracts.py)
- storage migration helper: [shared/storage_migration.py](C:\Users\mohaa\Desktop\monclub_access_python\shared\storage_migration.py)
- component identity + generic update engine: [shared/component_identity.py](C:\Users\mohaa\Desktop\monclub_access_python\shared\component_identity.py), [shared/update_runtime.py](C:\Users\mohaa\Desktop\monclub_access_python\shared\update_runtime.py)

### Packaging coupling that existed before Phase 5

- only one PyInstaller target existed: `MonClubAccess.spec`
- only one installer existed: `installer/MonClubAccess.iss`
- release scripts assumed only `MonClubAccess-*` outputs
- publishing and verification scripts assumed only Access filenames
- updater build/output identity was Access-specific
- Tauri shell was role-aware at runtime, but packaging still treated it as only an Access payload

## Target Packaging Model Now Implemented

### Access package

- Python app artifact name: `MonClubAccess`
- main executable: `MonClubAccess.exe`
- staged UI executable: `monclub-access-ui.exe`
- installer executable: `MonClubAccessSetup-<releaseId>.exe`
- updater installed name: `MonClubAccessUpdater.exe`

### TV package

- Python app artifact name: `MonClubTV`
- main executable: `MonClubTV.exe`
- staged UI executable: `monclub-tv-ui.exe`
- installer executable: `MonClubTVSetup-<releaseId>.exe`
- updater installed name: `MonClubTVUpdater.exe`

### Shared ecosystem delivery

- both components can still be built from the same repository
- [generate_installer.ps1](C:\Users\mohaa\Desktop\monclub_access_python\generate_installer.ps1) now supports `access`, `tv`, or `both`
- `both` produces both component installers plus `MonClubDesktopEcosystem-<releaseId>.bundle.json`
- the updater implementation is still one shared infrastructure project, but installers rename/package it per component

## Packaging / Release File Map

- component metadata: [desktop_components.ps1](C:\Users\mohaa\Desktop\monclub_access_python\packaging\desktop_components.ps1)
- Access PyInstaller target: [MonClubAccess.spec](C:\Users\mohaa\Desktop\monclub_access_python\MonClubAccess.spec)
- TV PyInstaller target: [MonClubTV.spec](C:\Users\mohaa\Desktop\monclub_access_python\MonClubTV.spec)
- component-aware Tauri shell staging: [build_tauri_shell.ps1](C:\Users\mohaa\Desktop\monclub_access_python\build_tauri_shell.ps1)
- component-aware release packaging: [build_release.ps1](C:\Users\mohaa\Desktop\monclub_access_python\build_release.ps1)
- component-aware installer packaging: [build_installer.ps1](C:\Users\mohaa\Desktop\monclub_access_python\build_installer.ps1)
- ecosystem build entry: [generate_installer.ps1](C:\Users\mohaa\Desktop\monclub_access_python\generate_installer.ps1)
- component-aware release publishing: [publish_github_release.ps1](C:\Users\mohaa\Desktop\monclub_access_python\publish_github_release.ps1)
- component-aware release verification: [verify_release.ps1](C:\Users\mohaa\Desktop\monclub_access_python\verify_release.ps1)
- shared updater project: [MonClubAccessUpdater.csproj](C:\Users\mohaa\Desktop\monclub_access_python\updater\MonClubAccessUpdater\MonClubAccessUpdater.csproj)
- shared updater runtime now uses the generic `MonClubDesktopUpdater` namespace internally while keeping packaging continuity

## What Remains Temporarily Shared

- one repository
- one shared Tauri source tree
- one shared updater implementation project
- one tiny shared install metadata file on disk: `shared/install.json`
- one installer asset set (icons/bitmaps)
- one best-effort Access -> TV auth mirror plus one-time TV compatibility import path for old auth state
- legacy `data/config.json` may still exist as a migration source, but it is no longer the intended live runtime config

These are explicitly temporary/shared delivery concerns, not shared mutable runtime state.

## Final Assessment After Phase 8

The separation work is functionally complete after Phase 8. Any future work is optional polish only:

- further reduce legacy `app/*` implementation modules if they stop providing value
- decide whether the shared Tauri source tree should remain shared permanently or be physically split into separate UI packages
- polish the combined ecosystem installer/update UX beyond the current component-correct foundation
- keep local IPC out unless a later concrete operational need appears; Phase 8 still found no blocker that justified it

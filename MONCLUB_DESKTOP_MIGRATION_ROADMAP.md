# MonClub Desktop Migration Roadmap

## Target End State

- `MonClub Access` and `MonClub TV` are separate desktop apps/processes
- each has its own live SQLite database
- each has its own persisted runtime config
- each is packageable/installable and updateable on its own path
- shared code remains infrastructure/contracts only
- backend remains source of truth
- local IPC stays optional and out of the architecture unless a later concrete need appears

## Phase Status Summary

### Phase 1 â€” Foundations

Completed.

Delivered:

- `access/`, `tv/`, and `shared/` scaffolding
- architecture docs
- split-ready path/bootstrap wrappers

### Phase 2 â€” Internal Ownership Seams

Completed.

Delivered:

- Access-owned and TV-owned local API registration seams
- cleaner bootstrap/runtime composition
- access/store and tv/store ownership boundaries
- initial TV frontend ownership seam under `tauri-ui/src/tv`

### Phase 3 â€” Real Process Extraction

Completed.

Delivered:

- real standalone TV startup path
- Access and TV independently startable
- shared Tauri shell made role-aware

### Phase 4 â€” Live DB Split

Completed.

Delivered:

- `access.db` as live Access DB
- `tv.db` as live TV DB
- migration from legacy `app.db`
- explicit table ownership

### Phase 5 â€” Packaging / Delivery Split

Completed.

Delivered:

- separate PyInstaller specs:
  - [MonClubAccess.spec](C:\Users\mohaa\Desktop\monclub_access_python\MonClubAccess.spec)
  - [MonClubTV.spec](C:\Users\mohaa\Desktop\monclub_access_python\MonClubTV.spec)
- separate installers:
  - [MonClubAccess.iss](C:\Users\mohaa\Desktop\monclub_access_python\installer\MonClubAccess.iss)
  - [MonClubTV.iss](C:\Users\mohaa\Desktop\monclub_access_python\installer\MonClubTV.iss)
- component-aware release/install/publish/verify scripts
- component-aware Tauri shell staging
- ecosystem build mode that can package:
  - Access only
  - TV only
  - both

### Phase 6 â€” Config / Update Runtime Separation

Completed.

Delivered:

- `access/config.json` as live Access persisted config
- `tv/config.json` as live TV persisted config
- `shared/install.json` as tiny install/ecosystem metadata only
- safe split-config migration from legacy `data/config.json`
- Access-owned update wrapper: [access/update_runtime.py](C:\Users\mohaa\Desktop\monclub_access_python\access\update_runtime.py)
- TV-owned update wrapper: [tv/update_runtime.py](C:\Users\mohaa\Desktop\monclub_access_python\tv\update_runtime.py)
- shared generic update engine with separate component runtime state: [shared/update_runtime.py](C:\Users\mohaa\Desktop\monclub_access_python\shared\update_runtime.py)
- TV-owned config/update local API routes
- explicit `ipc_mode = NONE` decision

### Phase 7 â€” Near-Final Seam Cleanup / Polish

Completed.

Delivered:

- TV now owns its own backend auth persistence in `tv.db` through `tv_backend_auth_state`
- TV no longer reads live Access auth state through `access.store`
- Access login/logout mirrors auth into TV storage on a best-effort basis so Access reliability stays primary
- update status payloads now expose component-specific identity/install metadata
- TV now surfaces TV-owned update state in the TV overview UI
- TV implementations now live directly under `tauri-ui/src/tv`, while old generic TV paths act as compatibility wrappers
- IPC decision re-confirmed: still not needed

### Phase 8 â€” Debt Retirement / Final Cleanup

Completed.

Delivered:

- deleted unused generic TV wrapper files under `tauri-ui/src/api`, `tauri-ui/src/components`, and `tauri-ui/src/pages`
- deleted the unused legacy Access updater shim `app/core/update_manager.py`
- isolated the remaining auth compatibility seam in `tv/auth_bridge.py`
- kept TV storage TV-owned by moving compatibility behavior out of `tv/store.py`
- cleaned shared updater code naming to the generic `MonClubDesktopUpdater` namespace
- confirmed the architecture is complete and remaining work is optional polish only

## Concrete Build / Delivery Commands After Phase 8

### Run locally

- Access: `run_access_app.bat`
- TV: `run_tv_app.bat`

### Build staged Tauri shell

- Access: `powershell -ExecutionPolicy Bypass -File .\build_tauri_shell.ps1 -Component access`
- TV: `powershell -ExecutionPolicy Bypass -File .\build_tauri_shell.ps1 -Component tv`

### Build release payload

- Access: `powershell -ExecutionPolicy Bypass -File .\build_release.ps1 -Component access`
- TV: `powershell -ExecutionPolicy Bypass -File .\build_release.ps1 -Component tv`

### Build shared updater

- shared updater: `powershell -ExecutionPolicy Bypass -File .\build_updater.ps1`

### Build installer

- Access: `powershell -ExecutionPolicy Bypass -File .\build_installer.ps1 -Component access`
- TV: `powershell -ExecutionPolicy Bypass -File .\build_installer.ps1 -Component tv`

### Build ecosystem outputs

- both: `powershell -ExecutionPolicy Bypass -File .\generate_installer.ps1 -Component both`

## Temporary Compatibility Left After Phase 8

- Access still performs a best-effort auth mirror into TV storage
- TV can still perform a one-time compatibility import from Access/legacy auth storage when its own auth row is missing
- updater implementation is still one shared infrastructure project
- Tauri source is still one shared codebase even though packaged outputs and runtime ownership are separate
- legacy `data/config.json` may still exist as a migration source from pre-Phase-6 installs

## Separation Completion Status

The separation work is complete after Phase 8.

### Future work, if any

- optional installer/update UX polish
- decide whether the shared Tauri source tree should remain shared permanently or be physically split into separate UI projects
- continue pruning legacy `app/*` implementation modules only when there is clear value
- keep IPC out unless a later concrete operational need appears; Phase 8 still found no blocker that justified it

## Release / Delivery Strategy Going Forward

### Stable artifact families

- Access release family:
  - `MonClubAccess-<releaseId>.zip`
  - `MonClubAccess-<releaseId>.manifest.json`
  - `MonClubAccessSetup-<releaseId>.exe`

- TV release family:
  - `MonClubTV-<releaseId>.zip`
  - `MonClubTV-<releaseId>.manifest.json`
  - `MonClubTVSetup-<releaseId>.exe`

### Shared ecosystem family

- `MonClubDesktopEcosystem-<releaseId>.bundle.json`

This bundle manifest remains the delivery bridge for both components without forcing a final all-in-one installer design yet.

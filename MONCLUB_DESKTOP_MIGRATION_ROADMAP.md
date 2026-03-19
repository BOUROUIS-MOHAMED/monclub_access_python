# MonClub Desktop Migration Roadmap

## Goal

Reach the locked target architecture:

- `MonClub Access` and `MonClub TV` as separate desktop apps/processes
- shared/common code only for contracts and infrastructure
- separate `access.db` and `tv.db`
- no shared mutable runtime DB
- backend as source of truth

## Current Starting Point

The repository is still a single desktop product:

- one Python runtime composition root in `app/ui/app.py`
- one local API server in `app/api/local_access_api_v2.py`
- one live SQLite file `app.db`
- one Tauri app routing access and TV pages together
- one installer/updater identity: `MonClubAccess`

## Migration Phases

### Phase 1 — Structural Foundations

Goal:

- create architecture boundaries without changing working behavior

Scope:

- add `access/`, `tv/`, and `shared/` packages
- add future Access and TV bootstrap descriptors/entry modules
- wrap shared modules through `shared/*`
- wrap TV entrypoints through `tv/*`
- wrap Access runtime composition dependencies through `access/*`
- add split-ready storage path scaffolding for `access.db` and `tv.db`
- keep current runtime on the legacy combined DB

Exit criteria:

- current app still runs
- build entry points resolve through the new Access bootstrap
- repository clearly reflects the target bounded contexts

### Phase 2 — Access/TV Internal Decoupling

Goal:

- reduce direct cross-context imports and isolate repositories/services

Scope:

- move TV route handlers behind a TV service module
- move access route handlers behind an Access service module
- split config model into Access/TV/shared sections
- stop new code from importing `app.core.tv_local_cache` directly outside the TV boundary
- stop new code from importing `app.core.db` directly outside the Access boundary unless explicitly shared

Exit criteria:

- composition roots depend on boundaries, not legacy implementation modules
- import graph clearly shows Access and TV separated by wrappers/facades

### Phase 3 — Separate TV Runtime Process

Goal:

- stop hosting TV runtime inside the critical Access process

Scope:

- create a standalone TV bootstrap/runtime
- move TV startup reconciliation/orchestration/player supervision into TV app
- give TV its own local API/service host
- keep Access-only deployments possible
- keep TV-only deployments possible

Exit criteria:

- TV windows/player runtime run without the Access process
- Access can start without loading TV runtime modules

### Phase 4 — Database Split

Goal:

- move from the combined `app.db` to `access.db` + `tv.db`

Scope:

- build migration scripts
- copy/transform Access-owned and TV-owned tables into separate databases
- cut reads/writes over to context-owned repositories
- preserve backward-compatible migration path from the existing installed base

Exit criteria:

- Access reads/writes only `access.db`
- TV reads/writes only `tv.db`
- no shared mutable operational SQLite file remains

### Phase 5 — Packaging / Installer Separation

Goal:

- distribute Access and TV as separate components inside one ecosystem

Scope:

- create distinct build targets
- create installer component selection or separate installers from the same pipeline
- split updater channels/component manifests
- keep shared prerequisites optional and minimal

Exit criteria:

- Access can be installed/updated independently
- TV can be installed/updated independently
- shared installer metadata does not re-couple runtime state

## Risks to Manage

### Highest-risk areas

- `app/ui/app.py` because it is the current composition root
- `app/api/local_access_api_v2.py` because it exposes both contexts in one server
- `app/core/utils.py` and `app/core/db.py` because one DB path currently feeds both contexts
- `tauri-ui/src/App.tsx` and `tauri-ui/src/layouts/MainLayout.tsx` because the operator shell still mixes both contexts
- packaging scripts because the current installer treats the bundle as a single app

### Non-goals until later phases

- no backend changes
- no dashboard changes
- no immediate DB migration
- no immediate TV standalone runtime cutover
- no broad IPC framework
- no rewrite of business logic

## Recommended Order After Phase 1

1. carve the local API into access-owned and tv-owned registration modules while preserving the current server shell
2. isolate TV orchestration startup from Access `MainApp`
3. split config/state path ownership
4. create a real TV runtime/service bootstrap
5. perform the DB migration only after the import/runtime boundaries are stable

## Phase 1 Deliverables In This Repository

Phase 1 should leave the repo with:

- concrete architecture documents
- visible `access/`, `tv/`, and `shared/` boundaries
- Access bootstrap entry as the build/run entry
- future TV bootstrap entry scaffolded
- split-ready storage metadata for `access.db` and `tv.db`
- legacy functionality preserved

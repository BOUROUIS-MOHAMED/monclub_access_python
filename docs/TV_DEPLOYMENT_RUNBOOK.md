# MonClub TV Deployment Runbook (Functionality 18)

## Scope
This runbook covers pre-deployment cleanup, startup/runtime readiness checks, deployment smoke tests, operator SOPs, and rollback for the current MonClub TV stack.

## Deployment Decision Table

### Must Fix Before First Deployment
- SQLite connection lifecycle must close all opened connections (`get_conn` context manager pattern).
- TV deployment preflight must pass with no blockers.
  - Data root writable
  - DB parent writable
  - DB openable
  - TV media root writable
  - TV schema/bootstrap valid
  - Required config URLs valid
  - Local API port valid
- Startup reconciliation must complete with explicit phase logging.

### Strongly Recommended Before Deployment
- Run query responsiveness checks and retention dry-run.
- Ensure startup/hardening visibility is available in Access TV Overview.
- Confirm support actions and diagnostics are available for each binding.

### Can Be Deferred With Documentation
- Frontend bundle chunk-size warning from Vite build output.
  - Non-blocking for first deployment.
  - Track as optimization follow-up.

## Startup Phase Reference
Expected startup reconciliation phase sequence:
1. `migration`
2. `interrupted-state repair`
3. `temp cleanup`
4. `monitor rescan`
5. `state reconciliation`
6. `readiness recompute`
7. `activation heal`
8. `autostart`

## First Installation SOP
1. Install app build and ensure writable data root.
2. Start app once and confirm local API is reachable.
3. Open Access TV Overview.
4. Verify Deployment Preflight card:
   - status is `PASS` or `WARN` (no blockers)
5. Verify startup reconciliation run appears with phase details.
6. Refresh host monitors.
7. Create at least one binding.
8. Trigger sync, download missing assets, evaluate activation, start player window.
9. Confirm overview/fleet diagnostics show expected status.

## Normal Startup SOP
1. Launch app.
2. Check startup log for preflight summary and startup run summary.
3. In TV Overview verify:
   - latest startup run status
   - phase outcomes
   - preflight blockers = 0
4. If autostart bindings exist, verify each binding runtime state and player state.

## Configuration Validation Rules
Preflight validates:
- Data root writable
- DB parent writable
- DB file openable
- TV media root writable
- TV schema/bootstrap success
- Config file presence
- Required URLs are valid HTTP/HTTPS:
  - `api_login_url`
  - `api_tv_snapshot_latest_url`
  - `api_tv_snapshot_manifest_url`
- TV URL template placeholders:
  - latest URL should include `{screenId}`
  - manifest URL should include `{snapshotId}`
- `local_api_port` in `1..65535`

## Pre-Deployment Checklist
- Python compile checks pass
- Unit/integration hardening tests pass
- Frontend build passes
- No preflight blockers
- Startup reconciliation succeeds locally
- Correlation propagation audit endpoint returns expected core path coverage
- Retention policy and query checks executed and reviewed

## Smoke Test Matrix (Minimum)

### Single-Screen Path
1. Create one binding
2. Sync snapshot
3. Download missing assets
4. Readiness becomes `READY`
5. Activation evaluates and active snapshot updates
6. Player window renders

### Multi-Screen Path
1. Create two or more bindings with different monitors
2. Start all bindings
3. Confirm per-binding isolation and independent state
4. Stop/restart one binding and verify others remain unaffected

### Failure/Recovery Sanity
1. Run support action `RUN_SYNC`
2. Run `RETRY_FAILED_DOWNLOADS` when failures exist
3. Run `REEVALUATE_ACTIVATION`
4. Run `RELOAD_PLAYER`
5. Run confirmed action `RESTART_PLAYER_WINDOW`
6. Verify support history and correlation IDs are visible

## Troubleshooting Quick Guide

### No Monitor Detected
- Refresh monitors from TV Overview.
- Check OS monitor availability.
- Verify preflight warning `TV_PREFLIGHT_NO_MONITOR`.

### Binding Not Starting
- Check binding runtime state, blocked reason, and monitor availability.
- Run `START_BINDING` or `RESTART_BINDING` via support actions.

### Snapshot Not Ready
- Run sync now.
- Inspect readiness counts (missing/invalid assets).
- Run download missing / retry failed downloads.

### Downloads Failing
- Check download job failure reason.
- Only retriable failures auto-retry (timeout/network/HTTP 5xx).
- For non-retriable failures, correct source and manually retry.

### Player Fallback/Error
- Inspect player state, render mode, fallback reason.
- Use `RELOAD_PLAYER` then `REEVALUATE_PLAYER_CONTEXT`.
- Use `RESTART_PLAYER_WINDOW` if needed.

### Startup Reconciliation Failed
- Open startup run details and failed phases.
- Resolve blockers from preflight output.
- Re-run startup reconciliation.

## Recovery Action Safety Rules
- Confirmed actions required:
  - `STOP_BINDING`
  - `RESTART_BINDING`
  - `RESTART_PLAYER_WINDOW`
  - `RESET_TRANSIENT_PLAYER_STATE`
- `RESET_TRANSIENT_PLAYER_STATE` must only reset transient per-binding player state; no deletion of snapshots/manifests/download/readiness/activation history.

## Rollback / Recovery Procedure
1. Stop the app.
2. Preserve current data root backup.
3. Reinstall previous known-good build.
4. Restart app and run preflight.
5. Run startup reconciliation manually.
6. Validate at least one full single-screen smoke path.
7. If DB migration fails:
   - restore DB backup
   - relaunch previous build
   - escalate migration issue with logs and startup phase details.

## Operator Visibility Minimum (Go-Live)
- TV Overview hardening section showing:
  - preflight status
  - startup run status
  - startup phases
  - query check timings
- Binding support summary with:
  - health, readiness, activation, player state, failed downloads
- Support action history with correlation ID visibility

## Useful Local API Endpoints
- `GET /api/v2/tv/hardening/preflight`
- `GET /api/v2/tv/hardening/startup/latest`
- `GET /api/v2/tv/hardening/startup/runs`
- `POST /api/v2/tv/hardening/startup/run`
- `GET /api/v2/tv/hardening/retention-policy`
- `POST /api/v2/tv/hardening/retention/run`
- `GET /api/v2/tv/hardening/query-checks`
- `GET /api/v2/tv/hardening/correlation-audit?correlationId=<id>`

## Known Limitations (Documented)
- Frontend build can show chunk-size warning from Vite. This is currently non-blocking and deferred.

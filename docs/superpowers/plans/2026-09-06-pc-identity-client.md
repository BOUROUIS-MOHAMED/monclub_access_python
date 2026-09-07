# Per-PC Identity Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add fail-closed per-PC credentials, post-login registration/adoption, and isolated heartbeat telemetry without affecting access control.

**Architecture:** A focused Access-owned module contains storage, backend calls, token state, payload construction, and a daemon worker. New Access-owned loopback handlers expose that service to a French React setup flow; existing sync and door modules do not depend on it.

**Tech Stack:** Python 3, requests, Windows DPAPI, pytest, React 19, TypeScript, Node test runner, Vite/Tauri.

---

### Task 1: Fail-closed secure credential storage

**Files:**
- Modify: `app/core/secure_store.py`
- Create: `access/pc_identity.py`
- Create: `tests/test_pc_identity.py`

- [ ] Write tests that use a temporary `pc_identity.dat`, assert a returned register credential round-trips, assert replacement credentials overwrite the pair, and assert missing/corrupt/unprotectable content returns no credentials.
- [ ] Run `python -m pytest tests/test_pc_identity.py -q` and confirm failures because the store/service do not exist and secure-store errors are swallowed into raw bytes.
- [ ] Add `SecureStoreError`, make protection fail closed, and implement atomic `PcCredentialStore.save/load` with JSON bytes protected as one blob.
- [ ] Re-run the targeted tests and confirm they pass.

### Task 2: API contract and token lifecycle

**Files:**
- Modify: `access/pc_identity.py`
- Modify: `tests/test_pc_identity.py`
- Modify: `app/core/app_const.py`

- [ ] Add failing tests for list/register/adopt payloads, backend error parsing, first-token minting, one-hour proactive refresh, credential replacement on adoption, and cap details.
- [ ] Run the targeted tests and confirm expected failures.
- [ ] Implement endpoint constants, `PcIdentityApiError`, `PcIdentityApiClient`, and the locked service state machine.
- [ ] Re-run targeted tests and confirm they pass.

### Task 3: Dedicated heartbeat worker and access-path isolation

**Files:**
- Modify: `access/pc_identity.py`
- Modify: `access/runtime.py`
- Modify: `tests/test_pc_identity.py`
- Create: `tests/test_pc_identity_access_isolation.py`

- [ ] Add failing tests for expiry refresh, 429 backoff, revoked shutdown, two-invalid-token shutdown, five-minute daemon-thread configuration, payload fields, and unchanged sync/card results across all identity states.
- [ ] Run the two targeted files and confirm expected failures.
- [ ] Implement `build_heartbeat_payload`, `PcHeartbeatWorker`, lazy app service construction, and best-effort startup from `access/runtime.py`.
- [ ] Re-run targeted tests and confirm they pass.

### Task 4: Access-owned loopback routes

**Files:**
- Create: `access/pc_identity_routes.py`
- Modify: `access/local_api_routes.py`
- Create: `tests/test_pc_identity_routes.py`

- [ ] Add failing fake-context tests for status/list/register/adopt, especially 409 cap mapping to `takeoverRequired: true`.
- [ ] Run the route tests and confirm missing routes/handlers fail.
- [ ] Implement handlers and register them without changing `app/api/local_access_api_v2.py`.
- [ ] Re-run route tests and confirm they pass.

### Task 5: French first-run and visible status UI

**Files:**
- Modify: `tauri-ui/src/api/client.ts`
- Modify: `tauri-ui/src/api/types.ts`
- Create: `tauri-ui/src/lib/pcIdentityState.ts`
- Create: `tauri-ui/src/lib/pcIdentityState.test.ts`
- Create: `tauri-ui/src/context/PcIdentityContext.tsx`
- Create: `tauri-ui/src/pages/PcSetupPage.tsx`
- Create: `tauri-ui/src/components/PcIdentityBanner.tsx`
- Modify: `tauri-ui/src/App.tsx`
- Modify: `tauri-ui/src/layouts/MainLayout.tsx`
- Modify: `tauri-ui/package.json`

- [ ] Add a Node TypeScript test proving a cap-coded API error changes new-PC mode to takeover mode and preserves `cap/activeCount`.
- [ ] Run `npm test --prefix tauri-ui` and confirm failure because the reducer is missing.
- [ ] Implement typed error payloads, identity context, first-run page, non-blocking bypass, and degraded-state banner using existing UI components and French copy.
- [ ] Run the UI test and `npm run build --prefix tauri-ui`; fix type/build errors until both pass.

### Task 6: Full verification and commits

**Files:**
- Review every changed file; do not stage `.claude/settings.local.json` or `tools/mb2000_scripts.rar`.

- [ ] Run `python -m pytest tests/ -q --ignore=tests/_pydeps` and record the real count against the 1112-test baseline.
- [ ] Run `python tools/check_sql_arity.py` and record checked counts.
- [ ] Run `npm test --prefix tauri-ui` and `npm run build --prefix tauri-ui`.
- [ ] Confirm `git diff -- app/core/access_verification.py app/sdk app/core/device_* app/core/ultra_engine.py app/core/realtime_agent.py app/api/local_access_api_v2.py` is empty.
- [ ] Commit the implementation in focused commits on `codex/pc-identity-client`; do not push or merge.

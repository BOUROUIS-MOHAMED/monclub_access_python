# MonClub Access — Tauri UI Localhost API Contract (Revised)

**Generated:** 2026-03-03  
**Audience:** Backend/core developer implementing `LocalAccessApiServer` + Tauri/React UI developer  
**Goal:** Replace the Tkinter UI entirely with a **Tauri + React (MUI)** UI that talks to a **localhost API** provided by the existing Python core.

> Key baseline (Mar 2026): **`accessDataMode` is per-device** (DEVICE/AGENT) from SQLite sync cache, not a global config mode.

---

## 1) Scope and assumptions

- The Python process becomes a **headless core** (no Tkinter ownership of windows).
- Tauri/React becomes the only UI.
- The local API **binds to 127.0.0.1 only** on a configurable port (default `8788`).
- The API contract below covers what the Tkinter pages previously did:
  - login/logout + restriction state
  - sync + cache browsing
  - DEVICE-mode (PullSDK + device sync) operations
  - AGENT-mode realtime engine operations
  - enrollment workflows (local save + backend save + “dashboard → PC” remote enroll)
  - updates (check/download/install via existing Python UpdateManager)
  - diagnostics + logs

---

## 2) Security model (recommended)

### 2.1 Bind rules
- Always bind to `127.0.0.1` (never `0.0.0.0`).
- If the backend settings propose a different host, **ignore it** for security.

### 2.2 Local UI authentication
- Use a local UI token:
  - Header: `X-Local-Auth: <token>`
  - Required for **all endpoints** except: `GET /api/v1/access/health` (and optionally the legacy dashboard enroll endpoint).
- Token is generated at core startup and stored locally (file/SQLite/config) in a way that the Tauri app can read (sidecar bootstrap, IPC, or known file under app data).

### 2.3 CORS rules
- **Do not ship** `Access-Control-Allow-Origin: *`.
- Options:
  1) **Tauri HTTP plugin** (preferred): avoids browser CORS entirely.
  2) If browser access is required (e.g., dashboard triggering enroll on localhost), use a strict allowlist:
     - Dev: `http://localhost:1420` (Tauri dev)  
     - Prod Tauri: `tauri://localhost` (or none if plugin)  
     - Dashboard: `https://<your-dashboard-domain>` only

### 2.4 SSE authentication
- If using `EventSource` (no custom headers), allow `?token=<localToken>` query param **only for SSE** endpoints.
- If using Tauri’s HTTP client with streaming support, use `X-Local-Auth` header instead.

---

## 3) Versioning and conventions

- All endpoints are prefixed with: `/api/v1/access`
- JSON responses use:
  - success: `{ "ok": true, ... }`
  - error: `{ "ok": false, "status": 400, "code": "BAD_REQUEST", "error": "..." }`

### 3.1 Common error shape
```json
{
  "ok": false,
  "status": 400,
  "code": "BAD_REQUEST",
  "error": "Human readable message",
  "details": {}
}
```

### 3.2 Time format
- Use ISO 8601 strings (UTC or local) consistently: `2026-03-03T10:05:00`

---

## 4) Endpoint groups (full parity)

### A) Health, session, status

#### A1) Health (no auth)
**GET** `/api/v1/access/health`  
Purpose: quick liveness + bind info; safe for “is core up?” checks.  
Response `200`:
```json
{
  "ok": true,
  "appName": "MonClub Access",
  "uptimeSec": 1234,
  "localApi": { "host": "127.0.0.1", "port": 8788 },
  "platform": { "os": "Windows", "arch": "x86", "python": "3.11.x" }
}
```

#### A2) Session (auth + restrictions)
**GET** `/api/v1/access/session`  
Purpose: logged-in state + restriction reasons + contract status.  
Response `200`:
```json
{
  "ok": true,
  "loggedIn": true,
  "email": "gym@example.com",
  "lastLoginAt": "2026-03-03T10:00:00",
  "restricted": false,
  "reasons": [],
  "contractStatus": true,
  "contractEndDate": "2027-01-01"
}
```
Errors: `401` if not logged in (or return `loggedIn:false` depending on your preference; pick one and keep consistent).

#### A3) Global mode summary (per-device accessDataMode)
**GET** `/api/v1/access/mode`  
Response `200`:
```json
{
  "ok": true,
  "globalMode": "MIXED",
  "summary": { "DEVICE": 2, "AGENT": 1, "UNKNOWN": 0 }
}
```

#### A4) Unified runtime status snapshot (recommended)
**GET** `/api/v1/access/status`  
Purpose: one-call dashboard for Tauri UI.  
Response `200`:
```json
{
  "ok": true,
  "session": { "...": "..." },
  "mode": { "...": "..." },
  "sync": { "running": false, "lastSyncAt": "2026-03-03T10:05:00", "lastOk": true, "lastError": null },
  "deviceSync": { "lastRunAt": "2026-03-03T10:05:02", "lastOk": true, "lastError": null },
  "pullsdk": { "connected": false, "deviceId": null, "ip": null, "since": null, "lastError": null },
  "agent": { "running": true, "eventQueueDepth": 12, "avgDecisionMs": 3.5 },
  "updates": { "updateAvailable": true, "downloaded": false, "downloading": false, "progress": null }
}
```

Optional: `GET /api/v1/access/status/events` (SSE) to push changes.

---

### B) Auth

#### B1) Login
**POST** `/api/v1/access/auth/login`  
Body:
```json
{ "email": "gym@example.com", "password": "secret" }
```
Response `200`:
```json
{ "ok": true, "loggedIn": true, "email": "gym@example.com" }
```

#### B2) Logout
**POST** `/api/v1/access/auth/logout`  
Response `200`:
```json
{ "ok": true, "message": "Logged out. Token cleared." }
```

---

### C) Config

> Note: **Do not** rely on any global “dataMode” for behavior. If present in config, treat as legacy.

#### C1) Read config
**GET** `/api/v1/access/config`  
Response `200`: returns the full config object.

#### C2) Patch config (partial update)
**PATCH** `/api/v1/access/config`  
Body: send only fields to change.
```json
{ "syncIntervalSec": 120, "agentRealtimeEnabled": false, "logLevel": "INFO" }
```
Response `200`:
```json
{ "ok": true, "message": "Config saved." }
```

#### C3) Unlock advanced settings (if still needed)
**POST** `/api/v1/access/config/unlock-advanced`  
Body:
```json
{ "password": "..." }
```
Response `200`: `{ "ok": true, "unlocked": true }`  
Error `403`: wrong password

---

### D) Sync and cache

#### D1) Trigger sync now (async)
**POST** `/api/v1/access/sync/trigger`  
Response `202`:
```json
{ "ok": true, "message": "Sync started." }
```

#### D2) Sync status
**GET** `/api/v1/access/sync/status`  
Response `200`:
```json
{ "ok": true, "running": false, "lastSyncAt": "2026-03-03T10:05:00", "lastOk": true, "lastError": null }
```

#### D3) Cache endpoints (read-only)
- **GET** `/api/v1/access/cache/all`
- **GET** `/api/v1/access/cache/meta`
- **GET** `/api/v1/access/cache/users?limit=...&q=...`
- **GET** `/api/v1/access/cache/memberships`
- **GET** `/api/v1/access/cache/infrastructures`
- **GET** `/api/v1/access/cache/gym-access-credentials`
- **GET** `/api/v1/access/cache/access-history?limit=...&deviceId=...`
- **GET** `/api/v1/access/cache/device-sync-state?deviceId=...`
- **GET** `/api/v1/access/cache/rtlog-state`
- **GET** `/api/v1/access/cache/stats`
- **GET** `/api/v1/access/cache/export` (optional “download all JSON”)

---

### E) Devices (cached) and door presets (local editable)

#### E1) List devices
**GET** `/api/v1/access/devices`  
Must include `accessDataMode` per device.

#### E2) Get device (optional convenience)
**GET** `/api/v1/access/devices/{deviceId}`

#### E3) Read per-device settings (backend-driven, read-only)
**GET** `/api/v1/access/devices/{deviceId}/settings`

#### E4) Door presets CRUD (local table)
- **GET** `/api/v1/access/devices/{deviceId}/door-presets`
- **POST** `/api/v1/access/devices/{deviceId}/door-presets`
- **PUT** `/api/v1/access/door-presets/{presetId}`
- **DELETE** `/api/v1/access/door-presets/{presetId}`

---

### F) PullSDK (DEVICE-mode operations)

#### F0) PullSDK connection status (IMPORTANT)
**GET** `/api/v1/access/pullsdk/status`  
Response `200`:
```json
{ "ok": true, "connected": true, "deviceId": 10, "ip": "192.168.0.4", "since": "2026-03-03T10:10:00", "lastError": null }
```

#### F1) Connect
**POST** `/api/v1/access/pullsdk/connect`  
Body: `{ "deviceId": 10 }` (or `{ip,port,password,timeoutMs}`)  
Response: `{ "ok": true }`

#### F2) Disconnect
**POST** `/api/v1/access/pullsdk/disconnect`

#### F3) Fetch table data
**POST** `/api/v1/access/pullsdk/fetch`  
Body: `{ "deviceId": 10, "table": "user", "fields": "*", "filter": "", "maxRows": 10000 }`

#### F4) Device info / params
**POST** `/api/v1/access/pullsdk/device-info`  
Body: `{ "deviceId": 10, "items": "DeviceName,SerialNumber,..." }`

#### F5) Open door (pulse)
**POST** `/api/v1/access/pullsdk/door-open`  
Body: `{ "deviceId": 10, "door": 1, "pulseSeconds": 3 }`

#### F6) Push user (card + authorize + optional templates)
**POST** `/api/v1/access/pullsdk/push-user`

#### F7) List users on device
**POST** `/api/v1/access/pullsdk/device-users`

#### F8) Check pushed (bulk)
**POST** `/api/v1/access/pullsdk/check-pushed`

#### F9) Delete user from device
**POST** `/api/v1/access/pullsdk/delete-user`

---

### G) Device Sync (DEVICE-mode engine)

#### G1) Run device sync now (async or blocking—choose one and document)
**POST** `/api/v1/access/device-sync/run`  
Response `202`: `{ "ok": true, "message": "Device sync started." }`

#### G2) Device sync status
**GET** `/api/v1/access/device-sync/status`  
Response `200`:
```json
{ "ok": true, "running": false, "lastRunAt": "2026-03-03T10:05:02", "lastOk": true, "lastError": null, "lastCounts": { "devices": 2, "pinsPushed": 40, "pinsFailed": 1 } }
```

---

### H) Realtime Agent (AGENT-mode engine)

#### H1) Agent global settings (backend-driven, read-only)
**GET** `/api/v1/access/agent/settings`

#### H2) Agent status snapshot
**GET** `/api/v1/access/agent/status`

#### H3) Per-device agent status
**GET** `/api/v1/access/agent/devices`

#### H4) Start/Stop agent
- **POST** `/api/v1/access/agent/start`
- **POST** `/api/v1/access/agent/stop`

#### H5) Refresh agent device list
**POST** `/api/v1/access/agent/refresh-devices`

#### H6) Enable/disable a device inside agent engine (temporary override)
**POST** `/api/v1/access/agent/devices/{deviceId}/enable`  
Body: `{ "enabled": true }`

#### H7) Test notification
**POST** `/api/v1/access/agent/test-notification`

#### H8) Agent events stream (SSE)
**GET** `/api/v1/access/agent/events?token=...`  
Event types: `status`, `device-status`, `access-event`, `notification`, `error`

---

### I) Enrollment (job-based, recommended)

> **Fix applied:** enrollment is unified into one job API. This reduces UI complexity and duplicated server logic.

#### I0) Scanner status (optional but useful)
**GET** `/api/v1/access/scanner/status`

#### I1) Scanner open/close (optional; enroll can auto-open)
- **POST** `/api/v1/access/scanner/open`
- **POST** `/api/v1/access/scanner/close`

#### I2) Start enrollment job (ONE endpoint)
**POST** `/api/v1/access/enroll/start`  
Body includes a `type`:
- `LOCAL_SQLITE` → enroll and store in local `fingerprints` table
- `BACKEND` → enroll and call MonClub backend `create_user_fingerprint`
- `REMOTE` → dashboard-triggered enroll (same core job path)

Examples:

**LOCAL_SQLITE**
```json
{ "type": "LOCAL_SQLITE", "label": "member", "pin": "123", "cardNo": "12345678", "fingerId": 0 }
```

**BACKEND**
```json
{ "type": "BACKEND", "userId": 1, "activeMembershipId": 123, "fingerId": 0, "label": "member", "enabled": true }
```

**REMOTE**
```json
{ "type": "REMOTE", "userId": 1, "fingerId": 0, "fullName": "Mohamed Amine", "device": "zk9500" }
```

Response `202`:
```json
{ "ok": true, "jobId": "enroll_8f2f2a1b", "message": "Enrollment started." }
```

#### I3) Cancel enrollment job
**POST** `/api/v1/access/enroll/cancel`  
Body:
```json
{ "jobId": "enroll_8f2f2a1b" }
```

#### I4) Poll enrollment job status (optional)
**GET** `/api/v1/access/enroll/jobs/{jobId}`  
Response `200`:
```json
{ "ok": true, "jobId": "enroll_...", "state": "RUNNING", "startedAt": "...", "endedAt": null, "result": null, "error": null }
```

#### I5) Enrollment events stream (SSE)
**GET** `/api/v1/access/enroll/events?jobId=enroll_...&token=...`  
Event types: `step`, `log`, `progress`, `success`, `error`, `cancelled`

#### I6) Legacy dashboard compatibility (optional, deprecated)
If you must keep the old endpoint temporarily:
- **GET** `/api/v1/access/enroll?id=...&fingerId=...&fullName=...&device=zk9500`
Return `202` with `{jobId}` and log: `"DEPRECATED endpoint used"`.

---

### J) Fingerprints (local DB)

- **GET** `/api/v1/access/fingerprints`
- **DELETE** `/api/v1/access/fingerprints/{id}`

(If you want editing labels, add `PATCH /fingerprints/{id}` later.)

---

### K) Logs and diagnostics

#### K1) Buffered logs
**GET** `/api/v1/access/logs?limit=1000&level=ALL`

#### K2) Live logs (SSE)
**GET** `/api/v1/access/logs/events?token=...`  
Event: `log`

#### K3) Clear buffer
**POST** `/api/v1/access/logs/clear`

#### K4) Platform/DB diagnostics
- **GET** `/api/v1/access/diagnostics/platform`
- **GET** `/api/v1/access/diagnostics/db-info`
- **POST** `/api/v1/access/diagnostics/check-pullsdk`
- **POST** `/api/v1/access/diagnostics/check-zkfinger`

> Note: “Open log directory” should be handled by Tauri directly; the API can return the log dir path if needed.

---

### L) Updates (Python UpdateManager)

#### L1) Update status
**GET** `/api/v1/access/updates/status`

#### L2) Force check now
**POST** `/api/v1/access/updates/check`

#### L3) Trigger download
**POST** `/api/v1/access/updates/download`

#### L4) Install (launch updater and exit core)
**POST** `/api/v1/access/updates/install`

#### L5) Update events (SSE, optional but recommended)
**GET** `/api/v1/access/updates/events?token=...`  
Events: `status`, `ready`, `error`

---

### M) Core lifecycle (headless)

> **Fix applied:** no “minimize/restore” endpoints (UI owns windows now).

#### M1) Graceful quit
**POST** `/api/v1/access/core/quit`  
Response `200`: `{ "ok": true }` (core exits after responding)

Optional:
- **GET** `/api/v1/access/core/uptime`

---

## 5) Minimum viable subset vs full parity

### 5.1 Minimum viable UI API (ship first)
1. `GET  /api/v1/access/health`
2. `GET  /api/v1/access/status`
3. `POST /api/v1/access/auth/login`
4. `POST /api/v1/access/auth/logout`
5. `GET  /api/v1/access/config`
6. `PATCH /api/v1/access/config`
7. `POST /api/v1/access/sync/trigger`
8. `GET  /api/v1/access/sync/status`
9. `GET  /api/v1/access/devices`
10. `GET /api/v1/access/cache/users`
11. `GET /api/v1/access/logs/events` (SSE)
12. `GET /api/v1/access/pullsdk/status`
13. `POST /api/v1/access/pullsdk/connect`
14. `POST /api/v1/access/pullsdk/door-open`
15. `GET /api/v1/access/agent/status`
16. `POST /api/v1/access/enroll/start`
17. `GET /api/v1/access/enroll/events` (SSE)
18. `POST /api/v1/access/enroll/cancel`
19. `GET /api/v1/access/updates/status`
20. `POST /api/v1/access/updates/check`

### 5.2 Full parity
Everything in sections A–M.

---

## 6) Notes and implementation hints (non-binding)

- Prefer **POST for actions** (connect, door open, start/stop engines, enroll).
- Keep “one PullSDK connection at a time” as a server-side invariant.
- Always include `accessDataMode` in device responses; UI should filter features by it:
  - DEVICE → PullSDK + device sync features
  - AGENT → agent realtime features
- Consider returning **camelCase** everywhere (align with your db.py coercion helpers).

---

## 7) Quick endpoint inventory (cheat sheet)

**Core:** health, status, session, mode, core/quit  
**Auth:** login, logout  
**Config:** get, patch, unlock-advanced  
**Sync:** trigger, status, cache/*, export, stats  
**Devices:** devices, device settings, door presets CRUD  
**PullSDK:** status, connect, disconnect, fetch, device-info, door-open, push-user, device-users, check-pushed, delete-user  
**Device Sync:** run, status  
**Agent:** settings, status, devices, start, stop, refresh-devices, enable, test-notification, events(SSE)  
**Enroll:** scanner status/open/close, enroll/start, enroll/cancel, enroll/jobs/{id}, enroll/events(SSE), legacy GET enroll (optional)  
**Logs:** logs, logs/events(SSE), logs/clear, diagnostics/*  
**Updates:** updates/status, check, download, install, updates/events(SSE optional)


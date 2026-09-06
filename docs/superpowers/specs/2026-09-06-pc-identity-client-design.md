# Per-PC Identity Client Design

## Goal

Add installation identity and best-effort heartbeat telemetry to MonClub Access without changing, delaying, or authorizing member sync, card verification, or any door-open path.

## Boundaries

- The existing gym JWT remains the only credential used for login, member sync, and current backend operations.
- A new PC JWT is held in memory and used only for `/public/access/v1/pc/heartbeat`.
- No new module is imported by `app/core/access_verification.py`, the device drivers, the live workers, or the door command path.
- Registration is a post-login operator flow, but the UI always offers a way to continue without registering so door controls remain usable.
- The protected legacy local API module is not modified. Access-owned route registration points at new handlers in `access/pc_identity_routes.py`.

## Components

### Credential store

`app/core/secure_store.py` will become fail-closed: DPAPI protection or unprotection failure raises a dedicated error instead of returning input bytes. This is necessary because the current executable code silently returns plaintext on every DPAPI failure. DPAPI remains user-scoped because `CryptProtectData`/`CryptUnprotectData` are called without optional entropy and without `CRYPTPROTECT_LOCAL_MACHINE`.

`access/pc_identity.py::PcCredentialStore` serializes `pcUuid` and `pcSecret` together, protects the serialized bytes with `secure_store.protect_bytes`, and atomically replaces `pc_identity.dat` in the Access data directory. Missing, malformed, or undecryptable data loads as no credentials and therefore produces the first-run state. Failed protection writes nothing.

### Backend client and service

`PcIdentityApiClient` owns the five backend calls and a request timeout. It parses backend error code, details, and `Retry-After` into a typed exception.

`PcIdentityService` owns credentials, the in-memory PC token, expiry, public status, registration/adoption, and one heartbeat attempt. Register and adopt persist the returned credential pair before minting the first token; adopt overwrites the complete local pair atomically. Token minting is proactive one hour before the backend-provided expiry.

Two consecutive `ACCESS_PC_TOKEN_INVALID` heartbeat responses disable further heartbeat attempts until registration/adoption changes the credentials. `ACCESS_PC_REVOKED`, invalid credentials, or adopt-revoked also disable heartbeat and remain visible through local status. HTTP 429 sets a private retry deadline based on `Retry-After`. Other failures are logged and swallowed.

### Worker and payload

One daemon thread named `pc-heartbeat` runs independently of Tk scheduling, Tauri, device workers, and sync workers. It waits on its own event for five minutes between attempts. Network calls have a ten-second timeout and no lock shared with access control.

The heartbeat payload reads the updater's installed version source, the app's existing `_last_sync_at` and `_last_sync_ok` observations, and non-blocking snapshots already published by AGENT/ULTRA engines. Synced devices without an affirmative live snapshot are reported `reachable: false`; this telemetry value is not consumed anywhere locally.

### Local API and Tauri UI

New authenticated loopback routes expose status, list PCs, register, and adopt. A cap response remains HTTP 409 and includes `code`, `cap`, `activeCount`, and `takeoverRequired: true`.

After gym login, `PcIdentityGate` checks local identity. Missing/unreadable/revoked/invalid state opens a French `PcSetupPage`; operators can register a named new PC, adopt an existing row, retry loading, or continue into the app without registration. Adoption copy explicitly says identity/history are retained and the old machine's secret is rotated. A compact banner in the normal layout keeps degraded/revoked state visible after bypass.

## Testing

- Python unit tests use temporary credential files and injected transports/clocks/providers.
- Any test that touches the application database monkeypatches `app.core.db._DB_PATH` to `tmp_path` before initialization.
- Node's built-in test runner executes a pure TypeScript state reducer proving `ACCESS_PC_CAP_REACHED` selects takeover mode.
- Route tests use a fake context and service.
- Invariance tests exercise the existing sync and card-verification entry points with missing, unreadable, revoked, and offline identity services, proving the identity module is neither imported nor consulted.
- Final gates are the full pytest command, the UI TypeScript test, the Vite build, and SQL arity check.

## Scope left to the dashboard session

The client only sends the backend contract. Fleet presentation, history visualization, remote revoke controls, and persistence/readback of `turnstiles[]` remain backend/dashboard work.

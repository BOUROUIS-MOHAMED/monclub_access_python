# SCR100 Scan Flow Design (Direct Dashboard -> Access)

## Summary

Implement a direct dashboard-to-Access scan flow for the SCR100 card reader using
ZKEMKeeper COM (32-bit). The dashboard opens a modal, triggers a single-card scan
session on the Access local API, listens via SSE for exactly one card value, then
auto-fills the field and closes the modal. Access stores scanner settings
(IP-based only) with a visible Save button and no auto-reset to USB.

## Goals

- Single-card scan via SCR100 with ZKEMKeeper (IP-based only).
- Dashboard calls Access local API directly (no backend proxy for now).
- Modal UX: connect -> prompt to scan -> success/failure -> close.
- Persist scanner mode/IP/port in Access config with an always-visible Save button.
- Avoid multi-card or continuous scanning; capture exactly one card.

## Non-Goals

- USB mode support for SCR100.
- Backend proxy or remote scan control.
- Access-side Tauri modal for scanning (dashboard owns the UI).

## Architecture

- **Dashboard** opens a modal and calls Access local API:
  - `POST /api/v2/scan/start`
  - `GET /api/v2/scan/stream` (SSE)
- **Access** runs a **scan session manager**:
  - One active session at a time.
  - Background worker uses `ZkemkeeperScanner` to read a single card.
  - Emits SSE event with status and card number, then ends session.

## Components

### Access (Python)

1. **ZkemkeeperScanner**
   - COM wrapper around `zkemkeeper.CZKEM`.
   - `Connect_Net(ip, port)` then read once:
     - Try `GetHIDEventCardNumAsStr` first.
     - Fallback to `GetStrCardNumber`.
   - Disconnect after reading or timeout.

2. **ScanSessionManager**
   - Holds current session state (idle, running, done, error).
   - Starts a worker thread for the scan.
   - Pushes events to SSE clients.
   - Rejects concurrent sessions with HTTP 409.

3. **Config persistence**
   - Persist:
     - `scanner_mode` (ip-based `zkemkeeper`)
     - `scanner_network_ip`
     - `scanner_network_port`
     - `scanner_network_timeout_ms`
   - Remove auto-reset to USB in config normalization.

### Dashboard (Web)

1. **Scan button** next to Card ID field:
   - Opens modal and calls `/api/v2/scan/start`.
2. **Modal**:
   - States: Connecting -> Scan now -> Success/Error.
3. **SSE listener**:
   - On success, fill the Card ID field and close modal.

## API

- `POST /api/v2/scan/start`
  - Starts a single scan session.
  - Returns `{ status: "started" }` or 409 if already running.

- `GET /api/v2/scan/stream`
  - SSE events:
    - `{ status: "ready" }`
    - `{ status: "done", card: "..." }`
    - `{ status: "timeout" }`
    - `{ status: "error", message: "..." }`

## Error Handling

- If COM connect fails: emit `error` and end session.
- If no card within timeout: emit `timeout`.
- If scanner returns invalid/empty card: emit `error`.
- SSE always completes after a terminal status.

## UI/UX Notes

- Save button always visible on Access settings page.
- IP-based mode only; USB option removed for SCR100 settings.
- Dashboard modal UI is clean and guides user action step-by-step.

## Security & Scope

- Access local API is on `127.0.0.1:8788` only.
- Dashboard runs on the same machine.
- No remote access in this phase.

## Testing

- Unit tests for `ZkemkeeperScanner` (mock COM object).
- Config persistence test ensures scanner mode/IP stays saved.
- API test for `/scan/start` and `/scan/stream`:
  - Only one card returned.
  - 409 on concurrent start.

## Rollout

- Ship Access changes first (scanner + config persistence).
- Add dashboard modal + API integration.
- Validate on gym machine with SCR100 (single scan).

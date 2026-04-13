# SCR100 Card Scan (ZKEMKeeper) Design

## Summary
Add a dedicated `zkemkeeper` scan mode for SCR100 card readers, keep existing `network` (pyzk) and `usb` modes as fallbacks, and wire a dashboard "Scan" button to the Access local API so a popup connects, waits for a card, then auto-fills the card ID field. Update the installer to register the bundled 32-bit `zkemkeeper.dll` during install.

## Goals
- SCR100 scanning uses ZKEMKeeper COM instead of PullSDK.
- Dashboard shows a clean scan modal, closes on success, and auto-fills the card ID.
- Installer registers `zkemkeeper.dll` reliably on both 32-bit and 64-bit Windows.
- Keep existing scan modes working with no regressions.

## Non-Goals
- Replacing existing `network` or `usb` scan paths.
- Building a new scanner UI outside the existing modal pattern.

## Architecture & Components
- **Card scanner engine** (`app/core/card_scanner.py`):
  - Add `ScannerMode.ZKEMKEEPER = "zkemkeeper"`.
  - Implement `_zkemkeeper_scan_loop(ip, port, timeout_ms)` using COM class `zkemkeeper`.
  - Behavior: connect, read a single card event, call `on_card`, then stop.
- **Local API** (`app/api/local_access_api_v2.py`):
  - Reuse existing `/api/v2/scanner/start|status|stop`.
  - Accept `mode="zkemkeeper"` and forward to scanner.
- **UI / dashboard**:
  - Add "Scan" button to card ID fields in create/edit member/user.
  - Use the same polling model as `useScanCard` to show a modal and auto-fill the card.

## Data Flow
1. Dashboard user clicks **Scan** in a card ID field.
2. Dashboard calls `POST /api/v2/scanner/start` with `{ mode: "zkemkeeper" }`.
3. Dashboard shows scan modal, polling `GET /api/v2/scanner/status`.
4. When `lastResult.cardNumber` appears, modal closes and field is auto-filled.
5. On cancel, dashboard calls `POST /api/v2/scanner/stop`.

## Installer Changes
- In `installer/MonClubAccess.iss`, add a post-install registration step:
  - 64-bit Windows: run `SysWOW64\regsvr32.exe /s "{app}\current\sdk\zkemkeeper.dll"`.
  - 32-bit Windows: run `System32\regsvr32.exe /s "{app}\current\sdk\zkemkeeper.dll"`.
- Log registration outcome and surface a warning in runtime checks if registration fails.

## Error Handling
- COM not registered: show explicit error in modal.
- Device connection failure: show "failed to connect" with retry suggestion.
- Scanner already active: return 409 with error message (already implemented).

## Testing Plan (Manual)
- Installer registers COM and can instantiate ZKEMKeeper.
- Scan modal connects and reads a card once, then stops.
- Cancel stops the scanner and releases the device session.
- `network` and `usb` modes still work.

## Open Questions
- None. Proceed with implementation.

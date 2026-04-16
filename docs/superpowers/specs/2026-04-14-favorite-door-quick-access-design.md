# Favorite Door Quick Access Design

## Goal

Make favorite door presets reachable faster without changing the current tray open-door menu or the existing tray panel.

## Repositories

- `C:\Users\mohaa\Desktop\monclub_access_python`
  Desktop Access app, local sync cache, local API, tray, overlay, global shortcut consumption
- `C:\Users\mohaa\Desktop\mon_club_dashboard`
  Gym-facing preset management UI
- `D:\projects\MonClub\monclub_backend`
  Preset persistence, validation, DTOs, and sync payload contract

## Approved Scope

### Keep existing behavior

- The current tray `Ouvrir porte` menu keeps showing all presets exactly as before.
- The current tray panel stays available and keeps its existing device/preset explorer behavior.
- No existing tray feature is replaced by the new favorite quick-access feature.

### Add new behavior

- Add a separate favorites overlay in Access.
- Add a separate tray item for this overlay, for example `Panneau favoris`.
- Add dashboard controls to mark up to 16 presets as favorites and assign each favorite an independent shortcut.
- Sync that favorite metadata from backend to Access and use it for:
  - the new overlay
  - global Windows shortcuts while Access is running

## Domain Model

Favorite metadata lives directly on each door preset.

New preset fields:

- `favoriteEnabled: boolean`
- `favoriteOrder: number | null`
  Display number in the overlay, unique across the gym, `1..16`
- `favoriteShortcut: string | null`
  One of:
  - `CTRL_0`
  - `CTRL_1`
  - `CTRL_2`
  - `CTRL_3`
  - `CTRL_4`
  - `CTRL_5`
  - `CTRL_6`
  - `CTRL_7`
  - `CTRL_8`
  - `CTRL_9`
  - `CTRL_F1`
  - `CTRL_F2`
  - `CTRL_F3`
  - `CTRL_F4`
  - `CTRL_F5`
  - `CTRL_F6`
  - `null`

Rules:

- A gym can have at most 16 favorite presets total.
- `favoriteOrder` is required when `favoriteEnabled = true`.
- `favoriteOrder` must be unique within the gym.
- `favoriteShortcut`, when present, must be unique within the gym.
- `favoriteShortcut` is independent from `favoriteOrder`.
- When `favoriteEnabled = false`, both `favoriteOrder` and `favoriteShortcut` must be cleared.

## Dashboard UX

Use the existing `GymDeviceDoorPresetsDialog` in the dashboard.

For each preset:

- keep the current door number, pulse, and door name editing flow
- add a favorite toggle
- add a favorite order selector `1..16`
- add a shortcut selector independent from order

Behavior:

- the dialog stays explicit-save, matching the current pattern
- used orders and shortcuts should be visible in the UI when possible
- backend validation remains the source of truth

## Backend Responsibilities

- Persist the new favorite fields on `GymDeviceDoorPreset`
- Return them from all preset CRUD responses
- Include them in access sync payloads and patch bundles
- Enforce gym-level uniqueness and max-16 rules

## Access Responsibilities

### Local config

Local PC settings stay local to Access:

- `quick_access_enabled: bool`
  Enables the feature on this PC, including global shortcuts
- `quick_access_panel_enabled: bool`
  Enables the overlay panel on this PC
- `quick_access_panel_edge: str`
  One of `left`, `right`, `top`

There is no local shortcut-profile selector in the corrected design. Shortcut assignment comes from the dashboard.

### Overlay

- The new overlay is a separate window from the existing tray panel.
- It stays hidden by default.
- A small half-circle handle stays attached to the chosen screen edge.
- V1 positions:
  - left center
  - right center
  - top center
- Hovering the handle expands the overlay into a compact Windows-11-style quick bar.
- Leaving the overlay collapses it back to the half-circle after a short delay.
- The expanded bar shows only the favorite order numbers.
- Clicking a number opens the assigned preset immediately.
- Tooltip text can show the preset name, door name, device name, and shortcut.

### Tray

- Restore the existing tray panel entry behavior.
- Restore the existing tray `Ouvrir porte` device/preset list behavior.
- Add a new tray item dedicated to the favorites overlay.

### Shortcuts

- Access registers only the dashboard-assigned shortcuts for synced favorites.
- Shortcuts work globally across Windows while Access is running.
- If one shortcut registration fails, the others still register.

## Failure Handling

- No synced favorites:
  - keep the existing tray behavior unchanged
  - the favorites overlay stays hidden or disabled
- Sync not ready:
  - favorites overlay stays unavailable until favorite metadata is present
- Shortcut registration conflict:
  - log the failure locally
  - keep overlay and remaining shortcuts working
- Door open failure:
  - show lightweight error feedback
  - keep the overlay responsive

## Testing

### Backend

- entity/DTO/controller tests for favorite fields
- validation tests for:
  - max 16 favorites
  - unique favorite order
  - unique favorite shortcut
  - clearing favorite metadata when favorite is off
- patch bundle tests proving preset favorite metadata reaches Access payloads

### Dashboard

- model/service tests for favorite field round-tripping
- dialog behavior tests for:
  - favorite toggle
  - order selector
  - shortcut selector

### Access

- restore tests for the old tray open-door menu and the old tray panel
- sync/cache/API tests for the corrected favorite fields
- shell verification for global shortcut mapping
- overlay behavior verification for:
  - collapsed handle
  - hover expand
  - click-to-open
  - edge placement

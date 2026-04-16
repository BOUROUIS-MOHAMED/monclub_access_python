# Favorite Door Quick Access Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add gym-configured favorite door quick access across backend, dashboard, and Access while preserving the existing tray open-door list and the existing tray panel.

**Architecture:** The backend becomes the source of truth for preset favorite metadata and validates gym-level uniqueness for order and shortcut assignment. The dashboard extends the existing door preset dialog to edit those fields. Access restores the old tray and old panel behavior, consumes synced favorite metadata, and adds a new separate hover overlay plus global shortcut registration.

**Tech Stack:** Spring Boot 3 / Java 17, React 19 / TypeScript / MUI, Python 3.11 / SQLite / React / Tauri 2 / Rust

---

### Task 1: Rewrite the backend preset contract for favorites

**Files:**
- Modify: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Models\GymDeviceDoorPreset.java`
- Modify: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Models\DTO\GymDeviceDoorPresetDto.java`
- Modify: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Controllers\GymDeviceDoorPresetController.java`
- Modify: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Controllers\GymAccessController.java`
- Modify: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Services\AccessPatchBundleService.java`
- Modify: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Repositories\GymDeviceDoorPresetRepository.java`
- Create: `D:\projects\MonClub\monclub_backend\src\main\resources\db\migration\V22__add_gym_device_door_preset_favorites.sql`
- Test: `D:\projects\MonClub\monclub_backend\src\test\java\com\tpjava\tpjava\Services\AccessPatchBundleServiceTest.java`

- [ ] Add `favoriteEnabled`, `favoriteOrder`, and `favoriteShortcut` to the preset entity and DTO.
- [ ] Add repository queries needed to count and detect conflicts at gym scope.
- [ ] Validate create and update requests so a gym can have at most 16 favorites, unique orders, and unique shortcuts.
- [ ] Clear order and shortcut automatically when a preset is saved as non-favorite.
- [ ] Include the new fields in Access sync and fast patch payload generation.
- [ ] Add a Flyway migration for the new columns.
- [ ] Extend patch-bundle tests to prove favorite metadata reaches Access payloads.

### Task 2: Extend dashboard preset editing with favorite controls

**Files:**
- Modify: `C:\Users\mohaa\Desktop\mon_club_dashboard\src\models\GymDeviceDoorPresetModel.ts`
- Modify: `C:\Users\mohaa\Desktop\mon_club_dashboard\src\models\GymDeviceModel.ts`
- Modify: `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\services\GymDeviceService.ts`
- Modify: `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\GymDevices\view\GymDeviceDoorPresetsDialog.tsx`
- Test: `C:\Users\mohaa\Desktop\mon_club_dashboard\tests\access-patch-dispatch-service.test.ts`

- [ ] Update the dashboard preset model and service layer to round-trip the favorite fields.
- [ ] Extend the existing preset dialog with:
  - favorite toggle
  - favorite order selector `1..16`
  - shortcut selector independent from order
- [ ] Keep the dialog on an explicit save flow.
- [ ] Surface backend validation failures clearly in the dialog.
- [ ] Add or extend a lightweight dashboard test for model/service serialization of the new fields.

### Task 3: Restore the original Access tray and panel behavior

**Files:**
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui\src\pages\TrayPanelPage.tsx`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui\src\pages\ConfigPage.tsx`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui\src-tauri\src\lib.rs`

- [ ] Restore `TrayPanelPage` to the original device/preset explorer behavior from `HEAD`.
- [ ] Restore the tray `Ouvrir porte` submenu to the original all-devices/all-presets behavior from `HEAD`.
- [ ] Restore the original tray panel entry behavior.
- [ ] Remove the incorrect local shortcut-profile UI and instant-save quick-access behavior from Config.

### Task 4: Correct Access sync/cache/API favorite metadata

**Files:**
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\db.py`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\api\local_access_api_v2.py`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\config.py`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\shared\config.py`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\access\local_api_routes.py`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui\src\api\types.ts`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui\src\api\hooks.ts`
- Test: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_local_api_device_paths.py`
- Test: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_feedback_api.py`

- [ ] Replace the old slot/label-only favorite metadata shape with:
  - `favoriteEnabled`
  - `favoriteOrder`
  - `favoriteShortcut`
- [ ] Preserve those fields through synced preset storage, cache snapshots, direct preset payloads, and device payloads.
- [ ] Keep a dedicated local quick-access endpoint, but make it return the corrected favorite metadata and order by `favoriteOrder`.
- [ ] Reduce local config fields to the corrected Access-owned settings:
  - enable
  - overlay enable
  - overlay edge
- [ ] Update Python tests for the corrected payload and config shape.

### Task 5: Add the new separate favorites overlay in Access

**Files:**
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui\src\App.tsx`
- Create: `C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui\src\pages\FavoritesOverlayPage.tsx`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui\src-tauri\src\lib.rs`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui\src\pages\ConfigPage.tsx`

- [ ] Add a new overlay route and separate Tauri window for favorites.
- [ ] Add a tray item dedicated to opening/toggling the favorites overlay.
- [ ] Implement the half-circle handle and hover-expand behavior for `left`, `right`, and `top`.
- [ ] Render only favorite order numbers in the expanded bar.
- [ ] Open the corresponding preset immediately on click.
- [ ] Keep the existing tray panel untouched.
- [ ] Update Config to use the normal save flow for local overlay enablement and edge selection.

### Task 6: Register global shortcuts from dashboard-assigned favorite shortcuts

**Files:**
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui\src-tauri\Cargo.toml`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui\src-tauri\capabilities\default.json`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui\src-tauri\src\lib.rs`

- [ ] Keep the global shortcut plugin.
- [ ] Change shortcut mapping to consume explicit `favoriteShortcut` values from synced favorites instead of deriving shortcuts from slots or local profiles.
- [ ] Respect the local Access enable switch when registering shortcuts.
- [ ] Keep individual registration failures non-fatal.

### Task 7: Verify all three repos

**Files:**
- Test: `D:\projects\MonClub\monclub_backend\src\test\java\com\tpjava\tpjava\Services\AccessPatchBundleServiceTest.java`
- Test: `C:\Users\mohaa\Desktop\mon_club_dashboard\tests\access-patch-dispatch-service.test.ts`
- Test: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_local_api_device_paths.py`
- Test: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_feedback_api.py`

- [ ] Run targeted backend tests for favorite metadata in Access patch payloads.
- [ ] Run the dashboard TypeScript test/build verification covering the updated preset dialog/model path.
- [ ] Run Access Python tests for preset and config payloads.
- [ ] Run Access frontend build and Tauri `cargo check`.
- [ ] If possible, manually sanity-check:
  - old tray open-door menu still shows all presets
  - old tray panel still works
  - new favorites overlay expands from the chosen edge
  - clicking a favorite opens the door
  - assigned shortcuts work globally

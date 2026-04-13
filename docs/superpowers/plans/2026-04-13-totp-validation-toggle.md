# TOTP Validation Toggle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a gym-controlled `totpValidation` setting that can disable TOTP QR validation and make QR access fall back to card IDs, while also refreshing mobile account state from membership and main-tab refresh flows.

**Architecture:** Extend the existing gym access software settings model in the backend and dashboard so the new boolean is the single source of truth. Propagate the same field through the backend payloads consumed by the access software and mobile app, then update the Python and Flutter runtimes to branch between TOTP and card-style QR handling from that one flag.

**Tech Stack:** Spring Boot, TypeScript/React, Flutter/Dart, Python 3.11, SQLite

---

### Task 1: Backend settings contract

**Files:**
- Modify: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Models\GymAccessSoftwareSettings.java`
- Modify: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Models\DTO\GymAccessSoftwareSettingsDto.java`
- Modify: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Controllers\GymAccessSoftwareSettingsController.java`
- Modify: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Controllers\GymAccessController.java`
- Modify: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Services\AccessPatchBundleService.java`

- [ ] Add `totpValidation` with a default of `true` to the entity and DTO.
- [ ] Map the field in settings CRUD and in every access sync DTO builder.
- [ ] Include the field in any settings-version/hash calculation so clients refresh when it changes.

### Task 2: Dashboard settings screen

**Files:**
- Modify: `C:\Users\mohaa\Desktop\mon_club_dashboard\src\models\GymAccessSoftwareSettingsModel.ts`
- Modify: `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\UserAccount\GymAccessSoftwareSettingsView.tsx`

- [ ] Extend the model JSON mapping with `totpValidation`, defaulting to `true`.
- [ ] Add a toggle in the access settings form that clearly explains the behavior switch between TOTP QR and card-style QR.

### Task 3: Mobile QR behavior and refresh

**Files:**
- Modify: `C:\Users\mohaa\Desktop\wigo\lib\data\models\GymAccessCredential.dart`
- Modify: `C:\Users\mohaa\Desktop\wigo\lib\screens\QrCode\GymMembershipAccessTotpQrCodeScreen.dart`
- Modify: `C:\Users\mohaa\Desktop\wigo\lib\core\auth\global_auth_service.dart`
- Modify: `C:\Users\mohaa\Desktop\wigo\lib\screens\Dashboard\mainTabScreen.dart`
- Modify: `C:\Users\mohaa\Desktop\wigo\lib\screens\subscriptions\subscription_management_screen.dart`

- [ ] Add the backend-provided setting to the mobile data model that feeds the QR screen.
- [ ] Make QR payload selection branch on `totpValidation`: TOTP when enabled, otherwise `cardId` then `secondCardId`.
- [ ] Relax the QR rendering assumptions so non-TOTP payloads still display.
- [ ] Force an account refresh from the relevant membership and main-tab refresh paths.

### Task 4: Access software sync and verification

**Files:**
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\db.py`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\settings_reader.py`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\access_verification.py`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\ultra_engine.py`
- Test: `C:\Users\mohaa\Desktop\monclub_access_python\tests\...`

- [ ] Persist `totpValidation` in the sync cache table and payload coercion.
- [ ] Normalize the new setting into the runtime settings map.
- [ ] Disable TOTP interpretation when the setting is off so QR scans are treated like RFID/card input.
- [ ] Add or extend tests around the new fallback behavior.

### Task 5: Verification

**Files:**
- Test: `D:\projects\MonClub\monclub_backend`
- Test: `C:\Users\mohaa\Desktop\mon_club_dashboard`
- Test: `C:\Users\mohaa\Desktop\wigo`
- Test: `C:\Users\mohaa\Desktop\monclub_access_python`

- [ ] Run targeted verification commands for each repo after the edits.
- [ ] Record any gaps where the repository does not have practical automated coverage for the touched path.

# Silent Update Design — MonClub Access & TV

**Date:** 2026-04-05
**Applies to:** MonClub Access + MonClub TV (Windows)
**Status:** Approved

---

## Problem

When an update is available and downloaded, clicking "Install now" opens the NSIS/Inno Setup installer GUI. The user must click through the wizard before the app restarts. The goal is a Telegram-style experience: update downloads silently in the background, a banner appears saying "Restart to update", and clicking it installs silently with no installer window.

---

## Chosen Approach

**Silent Inno Setup flags + copy change.** Pass `/VERYSILENT /SUPPRESSMSGBOXES` when launching the `.exe` installer, fix the `[Run]` section in both `.iss` files to relaunch the app after silent install, flip the auto-download default to `True`, and rename the UI button.

---

## Architecture

```
Update downloaded (background) → Banner: "Restart to update" → User clicks
  → Python: _launch_installer_exe(/VERYSILENT /SUPPRESSMSGBOXES)
  → App exits
  → Installer runs silently (no window)
  → Installer [Run] section launches new version automatically
```

---

## Changes

### 1. `shared/update_runtime.py`

**Function:** `_launch_installer_exe()`

Add `/VERYSILENT` and `/SUPPRESSMSGBOXES` flags when launching the `.exe` installer. Add a `silent: bool = True` parameter so the behavior can be overridden if ever needed.

```python
# Before
def _launch_installer_exe(exe_path: Path) -> None:
    subprocess.Popen([str(exe_path)], ...)

# After
def _launch_installer_exe(exe_path: Path, *, silent: bool = True) -> None:
    cmd = [str(exe_path)]
    if silent:
        cmd += ["/VERYSILENT", "/SUPPRESSMSGBOXES"]
    subprocess.Popen(cmd, ...)
```

- `/VERYSILENT` — suppresses all Inno Setup UI
- `/SUPPRESSMSGBOXES` — suppresses error dialogs (e.g. "another version is running")
- Applies to both Access and TV since they share `shared/update_runtime.py`

**Config default:** `update_auto_download_zip` changes default from `False` to `True` so the installer is already downloaded before the user opens the Update page.

---

### 2. `installer/MonClubAccess.iss` + `installer/MonClubTV.iss`

**Root cause:** Both files have `skipifsilent` in the `[Run]` entry, which tells Inno Setup to skip relaunching the app when running silently.

```ini
; Before (both files)
Filename: "{app}\current\{#MainExe}"; Flags: nowait postinstall skipifsilent

; After (both files)
Filename: "{app}\current\{#MainExe}"; Flags: nowait postinstall
```

**Effect:**
- Normal (GUI) install: unchanged — still shows the "Launch app" checkbox at the end
- Silent install (`/VERYSILENT`): app launches automatically after install completes

---

### 3. Tauri React UI

**Files:** `tauri-ui/src/pages/UpdatePage.tsx`, `tauri-ui/src/tv/pages/TvUpdatePage.tsx`, `tauri-ui/src/components/SidebarUpdateCard.tsx`

Copy-only changes — no structural or logic changes:

| Location | Before | After |
|---|---|---|
| Action button label | `Install now` | `Restart to update` |
| Loading state label | `Installing...` | `Restarting...` |
| `SidebarUpdateCard` sub-label | `Install now` | `Restart to update` |

The `handleInstall` function, API calls, progress bar, cancel button, and all other logic remain unchanged.

---

## Flow After Implementation

1. App starts → update check runs in background (every 3 hours by default)
2. Update found → installer `.exe` downloads silently in background (auto-download = true)
3. Download complete → `SidebarUpdateCard` animates in: "Update Ready · v1.x.x · Restart to update"
4. User navigates to Update page → sees `[Restart to update]` button
5. User clicks → `installAccessUpdate()` / `installTvUpdate()` API call
6. Python: `_launch_installer_exe(path, silent=True)` → spawns installer with `/VERYSILENT /SUPPRESSMSGBOXES`
7. App process exits (Tauri window closes)
8. Inno Setup installer runs silently in background
9. `[Run]` section (without `skipifsilent`) launches the new version automatically

---

## What Does Not Change

- Download logic and progress reporting
- C# `MonClubDesktopUpdater.exe` (only used for `.zip` path, not involved)
- Update check interval configuration
- Backend API
- Rollback logic
- All other UI components

---

## Edge Cases

| Scenario | Handling |
|---|---|
| Installer fails silently | Inno Setup logs to `%TEMP%`; app does not restart; user can retry |
| Auto-download disabled by operator | "Download" button still shown; user downloads manually, then restarts |
| User ignores the banner | Nothing happens; update waits until next restart |
| TV running unattended | Same flow — banner shows, update waits for a human to click Restart |

---

## Files Changed Summary

| File | Change type |
|---|---|
| `shared/update_runtime.py` | Add `/VERYSILENT /SUPPRESSMSGBOXES` to `_launch_installer_exe()`; flip auto-download default |
| `installer/MonClubAccess.iss` | Remove `skipifsilent` from `[Run]` flags |
| `installer/MonClubTV.iss` | Remove `skipifsilent` from `[Run]` flags |
| `tauri-ui/src/pages/UpdatePage.tsx` | Rename button copy |
| `tauri-ui/src/tv/pages/TvUpdatePage.tsx` | Rename button copy |
| `tauri-ui/src/components/SidebarUpdateCard.tsx` | Rename sub-label copy |

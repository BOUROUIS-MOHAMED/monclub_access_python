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
Update found → .exe downloads silently in background
  → SidebarUpdateCard: "Restart to update" (shown only when downloaded=true)
  → User clicks → UpdatePage → [Restart to update] button
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

- `/VERYSILENT` — suppresses all Inno Setup wizard UI
- `/SUPPRESSMSGBOXES` — suppresses `MsgBox()` calls in the `[Code]` section (e.g. the "same version already installed" dialog in `InitializeSetup()`, and the WebView2/ZKTeco warning dialog in `NextButtonClick`)
- Applies to both Access and TV since they share `shared/update_runtime.py`

**Also in `shared/update_runtime.py` — `_auto_download()` fallback:**

```python
# Before
return bool(getattr(self.cfg, "update_auto_download_zip", False))

# After
return bool(getattr(self.cfg, "update_auto_download_zip", True))
```

This fallback fires if `cfg` ever lacks the attribute entirely (e.g. test harnesses). It must match the `app/core/config.py` default to be consistent.

---

### 2. `app/core/config.py`

**Two places** must be changed — both enforce `False` independently:

**a) Field declaration (line ~140):**
```python
# Before
update_auto_download_zip: bool = False

# After
update_auto_download_zip: bool = True
```

**b) `from_dict()` deserialization coercion (line ~463):**
```python
# Before
cfg.update_auto_download_zip = _ensure_bool(getattr(cfg, "update_auto_download_zip", False), False)

# After
cfg.update_auto_download_zip = _ensure_bool(getattr(cfg, "update_auto_download_zip", True), True)
```

If only the field declaration is changed, the `from_dict()` coercion overrides it back to `False` for any user whose config file does not explicitly set this key. Both must be `True`.

Note: `shared/config.py` already uses `True` as the fallback in the normalization layer for both `AccessConfigSection` and `TvConfigSection` — no change needed there.

Both Access and TV share `AppConfig`, so this change applies to both. Operators can still disable auto-download by explicitly setting `update_auto_download_zip = false` in their config file.

---

### 3. `installer/MonClubAccess.iss` + `installer/MonClubTV.iss`

**Root cause:** Both files have `skipifsilent` in the `[Run]` entry, which tells Inno Setup to skip relaunching the app when running silently.

```ini
; Before (both files)
Filename: "{app}\current\{#MainExe}"; Description: "Launch MonClub Access/TV"; Flags: nowait postinstall skipifsilent

; After (both files)
Filename: "{app}\current\{#MainExe}"; Description: "Launch MonClub Access/TV"; Flags: nowait postinstall
```

**Effect:**
- Normal (GUI) install: unchanged — still shows the "Launch app" checkbox at the end
- Silent install (`/VERYSILENT`): app launches automatically after install completes

---

### 4. Tauri React UI

**Files:** `tauri-ui/src/pages/UpdatePage.tsx`, `tauri-ui/src/tv/pages/TvUpdatePage.tsx`, `tauri-ui/src/components/SidebarUpdateCard.tsx`

#### `UpdatePage.tsx` + `TvUpdatePage.tsx` — button copy only

| Location | Before | After |
|---|---|---|
| Action button label | `Install now` | `Restart to update` |

Note: there is no separate "Installing..." text label in the current code — the loading state is already shown via a `Loader2` spinner on the button. No additional label change is needed.

The `handleInstall` function, API calls, progress bar, cancel button, and all other logic remain unchanged.

#### `SidebarUpdateCard.tsx` — add `downloaded` + `downloading` props

Currently the card only receives `updateAvailable` and shows "Install now" as soon as an update is detected — before the download completes. This is misleading when auto-download is enabled. The card needs to reflect the download state.

**Visibility gate:** unchanged — the card still shows whenever `updateAvailable=true`. The new props only change the copy and icon.

**Sub-label and icon by state:**

| State | Expanded sub-label | Collapsed icon |
|---|---|---|
| `downloading=true` | `Downloading... (XX%)` | `Loader2` (spinning) |
| `downloaded=true` | `Restart to update` | `Download` (existing) with ping dot |
| neither (auto-download off, not started) | `Download update` | `Download` (existing) with ping dot |

**Props to add:**
```tsx
interface SidebarUpdateCardProps {
  // existing
  updateAvailable: boolean;
  latestVersion?: string | null;
  latestCodename?: string | null;
  sidebarOpen: boolean;
  onClick: () => void;
  // new
  downloaded: boolean;
  downloading: boolean;
  progressPercent?: number | null;
}
```

The parent component (`MainLayout.tsx`) already has access to the full update status object and passes props to `SidebarUpdateCard` — it just needs to pass the new ones through.

---

## Flow After Implementation

1. App starts → update check runs in background (every 3 hours by default)
2. Update found → installer `.exe` downloads silently in background (`update_auto_download_zip = True`)
3. Sidebar card shows: "Downloading..." with progress while in progress
4. Download complete → sidebar card switches to: "Update Ready · v1.x.x · Restart to update"
5. User navigates to Update page → sees `[Restart to update]` button
6. User clicks → `installAccessUpdate()` / `installTvUpdate()` API call
7. Python: `_launch_installer_exe(path, silent=True)` → spawns installer with `/VERYSILENT /SUPPRESSMSGBOXES`
8. App process exits (Tauri window closes)
9. Inno Setup installer runs silently in background
10. `[Run]` section (without `skipifsilent`) launches the new version automatically

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
| Installer fails silently | Inno Setup logs to `%TEMP%`; app does not restart; user can retry from Update page |
| Auto-download disabled by operator | "Download" button still shown; user downloads manually, then sees "Restart to update" |
| User ignores the banner | Nothing happens; update waits indefinitely |
| TV running unattended | Banner shows, update waits for a human to click Restart (no auto-restart) |
| Same version already installed silently | `InitializeSetup()` in the `.iss` file returns `False` and exits; `/SUPPRESSMSGBOXES` suppresses the dialog; installer exits silently, app does not relaunch; user sees nothing after clicking Restart — this is acceptable behaviour since nothing actually needed updating |
| Missing WebView2 / ZKTeco driver on target machine | The WebView2/ZKTeco warning `MsgBox` in `NextButtonClick` is suppressed by `/SUPPRESSMSGBOXES`; install continues silently; the app may not function correctly on launch. This is an existing risk (same as today's GUI install if the user clicks through the warning) |

---

## Files Changed Summary

| File | Change type |
|---|---|
| `shared/update_runtime.py` | Add `/VERYSILENT /SUPPRESSMSGBOXES` to `_launch_installer_exe()` |
| `app/core/config.py` | Flip `update_auto_download_zip` default from `False` to `True` |
| `installer/MonClubAccess.iss` | Remove `skipifsilent` from `[Run]` flags |
| `installer/MonClubTV.iss` | Remove `skipifsilent` from `[Run]` flags |
| `tauri-ui/src/pages/UpdatePage.tsx` | Rename "Install now" button to "Restart to update" |
| `tauri-ui/src/tv/pages/TvUpdatePage.tsx` | Rename "Install now" button to "Restart to update" |
| `tauri-ui/src/components/SidebarUpdateCard.tsx` | Add `downloaded`/`downloading`/`progressPercent` props; update sub-label copy |
| `tauri-ui/src/layouts/MainLayout.tsx` | Pass new props to `SidebarUpdateCard` |
